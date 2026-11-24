#!/usr/bin/env python3
"""
Self-hosted Health Connect webhook receiver.

- Listens on configurable host/port.
- Accepts POST /health-connect/<person>.
- Auth via X-Webhook-Token header or ?token= query parameter.
- Stores raw JSON payloads and normalized sleep/vitals/activity into SQLite.
- No cloud calls, no LLM calls.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DEFAULT_DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "hcwebhook-receiver"
DEFAULT_DB = Path(os.environ.get("HCWEBHOOK_DB", str(DEFAULT_DATA_DIR / "health_connect.sqlite"))).expanduser()
DEFAULT_TOKEN_FILE = Path(os.environ.get("HCWEBHOOK_TOKEN_FILE", str(DEFAULT_DATA_DIR / "webhook_token"))).expanduser()
DEFAULT_LOG = Path(os.environ.get("HCWEBHOOK_LOG", str(DEFAULT_DATA_DIR / "receiver.log"))).expanduser()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log(msg: str) -> None:
    DEFAULT_LOG.parent.mkdir(parents=True, exist_ok=True)
    line = f"{utc_now()} {msg}\n"
    with DEFAULT_LOG.open("a", encoding="utf-8") as f:
        f.write(line)


def load_token() -> str:
    env = os.environ.get("HCWEBHOOK_TOKEN") or os.environ.get("HEALTH_CONNECT_WEBHOOK_TOKEN")
    if env:
        return env.strip()
    if DEFAULT_TOKEN_FILE.exists():
        return DEFAULT_TOKEN_FILE.read_text(encoding="utf-8").strip()
    raise RuntimeError(f"Missing token: set HCWEBHOOK_TOKEN or create {DEFAULT_TOKEN_FILE}")


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path, timeout=30.0) as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                person TEXT NOT NULL,
                source_ip TEXT,
                user_agent TEXT,
                payload_sha256 TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE(person, payload_sha256)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS sleep_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_event_id INTEGER NOT NULL,
                person TEXT NOT NULL,
                session_start TEXT,
                session_end TEXT,
                duration_seconds REAL,
                stage_count INTEGER,
                stages_json TEXT,
                UNIQUE(person, session_start, session_end),
                FOREIGN KEY(raw_event_id) REFERENCES raw_events(id)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS vitals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_event_id INTEGER NOT NULL,
                person TEXT NOT NULL,
                metric TEXT NOT NULL,
                time TEXT,
                value REAL,
                unit TEXT,
                raw_json TEXT,
                UNIQUE(person, metric, time, value),
                FOREIGN KEY(raw_event_id) REFERENCES raw_events(id)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_event_id INTEGER NOT NULL,
                person TEXT NOT NULL,
                metric TEXT NOT NULL,
                date TEXT NOT NULL,
                start_time TEXT,
                end_time TEXT,
                value REAL NOT NULL,
                unit TEXT,
                raw_json TEXT,
                UNIQUE(person, metric, date),
                FOREIGN KEY(raw_event_id) REFERENCES raw_events(id)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_intervals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_event_id INTEGER NOT NULL,
                person TEXT NOT NULL,
                metric TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT,
                record_id TEXT,
                raw_json TEXT,
                UNIQUE(person, metric, start_time, end_time),
                FOREIGN KEY(raw_event_id) REFERENCES raw_events(id)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                person TEXT NOT NULL,
                raw_event_id INTEGER,
                status TEXT NOT NULL,
                message TEXT
            )
            """
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_vitals_person_metric_time ON vitals(person, metric, time)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_sleep_person_end ON sleep_sessions(person, session_end)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_daily_activity_person_metric_date ON daily_activity(person, metric, date)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_activity_intervals_person_metric_start ON activity_intervals(person, metric, start_time)")


def as_float(x):
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def _normalize_payload(con: sqlite3.Connection, raw_event_id: int, person: str, payload: dict) -> dict:
    sleep_seen = 0
    sleep_inserted = 0
    vitals_seen = 0
    vitals_inserted = 0
    daily_seen = 0
    daily_upserted = 0
    intervals_seen = 0
    intervals_inserted = 0

    for sleep in payload.get("sleep") or []:
        if not isinstance(sleep, dict):
            continue
        stages = sleep.get("stages") or []
        session_start = sleep.get("session_start_time") or sleep.get("start_time")
        session_end = sleep.get("session_end_time") or sleep.get("end_time")
        if not session_start and isinstance(stages, list) and stages:
            starts = [s.get("start_time") for s in stages if isinstance(s, dict) and s.get("start_time")]
            if starts:
                session_start = min(starts)
        if not session_start and session_end and sleep.get("duration_seconds") is not None:
            try:
                end_dt = datetime.fromisoformat(session_end.replace("Z", "+00:00"))
                session_start = end_dt.timestamp() - float(sleep.get("duration_seconds"))
                session_start = datetime.fromtimestamp(session_start, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            except Exception:
                pass
        cur = con.execute(
            """
            INSERT OR IGNORE INTO sleep_sessions
              (raw_event_id, person, session_start, session_end, duration_seconds, stage_count, stages_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                raw_event_id,
                person,
                session_start,
                session_end,
                as_float(sleep.get("duration_seconds")),
                len(stages) if isinstance(stages, list) else None,
                json.dumps(stages, ensure_ascii=False),
            ),
        )
        sleep_seen += 1
        sleep_inserted += cur.rowcount

    vital_specs = {
        "heart_rate": ("bpm", ["bpm", "beats_per_minute", "value"]),
        "resting_heart_rate": ("bpm", ["bpm", "beats_per_minute", "value"]),
        "heart_rate_variability": ("ms", ["heart_rate_variability_millis", "rmssd_millis", "value"]),
        "oxygen_saturation": ("percent", ["percentage", "value"]),
        "respiratory_rate": ("rpm", ["rate", "value"]),
    }
    for metric, (unit, keys) in vital_specs.items():
        for rec in payload.get(metric) or []:
            if not isinstance(rec, dict):
                continue
            value = None
            for k in keys:
                if k in rec:
                    value = as_float(rec.get(k))
                    break
            t = rec.get("time") or rec.get("start_time") or rec.get("end_time")
            cur = con.execute(
                """
                INSERT OR IGNORE INTO vitals
                  (raw_event_id, person, metric, time, value, unit, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (raw_event_id, person, metric, t, value, unit, json.dumps(rec, ensure_ascii=False)),
            )
            vitals_seen += 1
            vitals_inserted += cur.rowcount

    daily_specs = {
        "steps": ("count", ["count", "steps", "value"]),
        "distance": ("meters", ["meters", "distance_meters", "value"]),
        "active_calories": ("kcal", ["calories", "kcal", "value"]),
    }
    for metric, (unit, keys) in daily_specs.items():
        for rec in payload.get(metric) or []:
            if not isinstance(rec, dict):
                continue
            value = None
            for k in keys:
                if k in rec:
                    value = as_float(rec.get(k))
                    break
            start_time = rec.get("start_time") or rec.get("time")
            end_time = rec.get("end_time") or rec.get("time")
            date_src = start_time or end_time
            if value is None or not date_src or len(str(date_src)) < 10:
                continue
            day = str(date_src)[:10]
            cur = con.execute(
                """
                INSERT INTO daily_activity
                  (raw_event_id, person, metric, date, start_time, end_time, value, unit, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(person, metric, date) DO UPDATE SET
                  raw_event_id = excluded.raw_event_id,
                  start_time = COALESCE(excluded.start_time, daily_activity.start_time),
                  end_time = excluded.end_time,
                  value = excluded.value,
                  raw_json = excluded.raw_json
                WHERE excluded.value > daily_activity.value
                   OR (
                     excluded.value = daily_activity.value
                     AND COALESCE(excluded.end_time, '') > COALESCE(daily_activity.end_time, '')
                   )
                """,
                (raw_event_id, person, metric, day, start_time, end_time, value, unit, json.dumps(rec, ensure_ascii=False)),
            )
            daily_seen += 1
            daily_upserted += cur.rowcount

    interval_specs = {
        "total_calories": ("kcal", ["calories", "kcal", "value"]),
    }
    for metric, (unit, keys) in interval_specs.items():
        for rec in payload.get(metric) or []:
            if not isinstance(rec, dict):
                continue
            value = None
            for k in keys:
                if k in rec:
                    value = as_float(rec.get(k))
                    break
            start_time = rec.get("start_time") or rec.get("time") or rec.get("end_time")
            end_time = rec.get("end_time") or rec.get("time") or start_time
            if value is None or not start_time:
                continue
            meta = rec.get("metadata") if isinstance(rec.get("metadata"), dict) else {}
            record_id = meta.get("id") or meta.get("client_record_id")
            cur = con.execute(
                """
                INSERT OR IGNORE INTO activity_intervals
                  (raw_event_id, person, metric, start_time, end_time, value, unit, record_id, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    raw_event_id,
                    person,
                    metric,
                    start_time,
                    end_time,
                    value,
                    unit,
                    record_id,
                    json.dumps(rec, ensure_ascii=False),
                ),
            )
            intervals_seen += 1
            intervals_inserted += cur.rowcount

    return {
        "sleep_seen": sleep_seen,
        "sleep_inserted": sleep_inserted,
        "vitals_seen": vitals_seen,
        "vitals_inserted": vitals_inserted,
        "daily_seen": daily_seen,
        "daily_upserted": daily_upserted,
        "intervals_seen": intervals_seen,
        "intervals_inserted": intervals_inserted,
    }


def insert_payload(db_path: Path, person: str, payload: dict, source_ip: str | None, user_agent: str | None) -> dict:
    received_at = utc_now()
    payload_text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()

    init_db(db_path)
    with sqlite3.connect(db_path, timeout=30.0) as con:
        con.execute("PRAGMA journal_mode=WAL")
        cur = con.execute(
            """
            INSERT OR IGNORE INTO raw_events
              (received_at, person, source_ip, user_agent, payload_sha256, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (received_at, person, source_ip, user_agent, digest, payload_text),
        )
        inserted = cur.rowcount == 1
        if inserted:
            raw_event_id = cur.lastrowid
            counts = _normalize_payload(con, raw_event_id, person, payload)
        else:
            raw_event_id = con.execute(
                "SELECT id FROM raw_events WHERE person=? AND payload_sha256=?",
                (person, digest),
            ).fetchone()[0]
            counts = {
                "sleep_seen": 0,
                "sleep_inserted": 0,
                "vitals_seen": 0,
                "vitals_inserted": 0,
                "daily_seen": 0,
                "daily_upserted": 0,
                "intervals_seen": 0,
                "intervals_inserted": 0,
            }

        status = "inserted" if inserted else "duplicate_raw"
        msg = (
            f"{status}: raw_event_id={raw_event_id} "
            f"sleep_seen={counts['sleep_seen']} sleep_inserted={counts['sleep_inserted']} "
            f"vitals_seen={counts['vitals_seen']} vitals_inserted={counts['vitals_inserted']} "
            f"daily_seen={counts['daily_seen']} daily_upserted={counts['daily_upserted']} "
            f"intervals_seen={counts['intervals_seen']} intervals_inserted={counts['intervals_inserted']} "
            f"sha={digest[:12]}"
        )
        con.execute(
            "INSERT INTO sync_log(received_at, person, raw_event_id, status, message) VALUES (?, ?, ?, ?, ?)",
            (received_at, person, raw_event_id, status, msg),
        )
        return {
            "ok": True,
            "status": status,
            "raw_event_id": raw_event_id,
            "person": person,
            "sleep_sessions_seen": counts["sleep_seen"],
            "sleep_sessions_inserted": counts["sleep_inserted"],
            "vitals_seen": counts["vitals_seen"],
            "vitals_inserted": counts["vitals_inserted"],
            "daily_activity_seen": counts["daily_seen"],
            "daily_activity_upserted": counts["daily_upserted"],
            "activity_intervals_seen": counts["intervals_seen"],
            "activity_intervals_inserted": counts["intervals_inserted"],
            "sha256": digest,
        }


def backfill_db(db_path: Path) -> dict:
    init_db(db_path)
    totals = {
        "raw_events": 0,
        "sleep_sessions_inserted": 0,
        "vitals_inserted": 0,
        "daily_activity_upserted": 0,
        "activity_intervals_inserted": 0,
    }
    with sqlite3.connect(db_path, timeout=30.0) as con:
        con.execute("PRAGMA journal_mode=WAL")
        rows = con.execute("SELECT id, person, payload_json FROM raw_events ORDER BY id ASC").fetchall()
        for raw_event_id, person, payload_json in rows:
            payload = json.loads(payload_json)
            if not isinstance(payload, dict):
                continue
            counts = _normalize_payload(con, raw_event_id, person, payload)
            totals["raw_events"] += 1
            totals["sleep_sessions_inserted"] += counts["sleep_inserted"]
            totals["vitals_inserted"] += counts["vitals_inserted"]
            totals["daily_activity_upserted"] += counts["daily_upserted"]
            totals["activity_intervals_inserted"] += counts["intervals_inserted"]
    return totals


class Handler(BaseHTTPRequestHandler):
    server_version = "HealthConnectReceiver/1.0"

    def _send_json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        log(f"{self.client_address[0]} {fmt % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/health", "/healthz", "/"):
            self._send_json(200, {"ok": True, "service": "health-connect-receiver", "time": utc_now()})
            return
        self._send_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            if len(parts) != 2 or parts[0] != "health-connect":
                self._send_json(404, {"ok": False, "error": "expected /health-connect/<person>"})
                return
            person = parts[1].strip().lower()
            if not person or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in person):
                self._send_json(400, {"ok": False, "error": "invalid person"})
                return

            token = self.headers.get("X-Webhook-Token") or (parse_qs(parsed.query).get("token") or [None])[0]
            expected = self.server.auth_token  # type: ignore[attr-defined]
            if not token or not hmac.compare_digest(token, expected):
                self._send_json(401, {"ok": False, "error": "unauthorized"})
                return

            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                self._send_json(400, {"ok": False, "error": "empty body"})
                return
            max_body_mb = float(os.environ.get("HCWEBHOOK_MAX_BODY_MB", "25"))
            if length > max_body_mb * 1024 * 1024:
                self._send_json(413, {"ok": False, "error": "payload too large"})
                return
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception as e:
                self._send_json(400, {"ok": False, "error": f"invalid json: {e}"})
                return
            if not isinstance(payload, dict):
                self._send_json(400, {"ok": False, "error": "json must be object"})
                return

            result = insert_payload(
                self.server.db_path,  # type: ignore[attr-defined]
                person,
                payload,
                self.client_address[0] if self.client_address else None,
                self.headers.get("User-Agent"),
            )
            log(
                f"POST person={person} status={result['status']} "
                f"sleep_seen={result['sleep_sessions_seen']} sleep_inserted={result['sleep_sessions_inserted']} "
                f"vitals_seen={result['vitals_seen']} vitals_inserted={result['vitals_inserted']} "
                f"daily_seen={result['daily_activity_seen']} daily_upserted={result['daily_activity_upserted']} "
                f"intervals_seen={result['activity_intervals_seen']} intervals_inserted={result['activity_intervals_inserted']} "
                f"id={result['raw_event_id']}"
            )
            self._send_json(200, result)
        except Exception as e:
            log("ERROR " + repr(e) + "\n" + traceback.format_exc())
            self._send_json(500, {"ok": False, "error": "internal_error", "message": str(e)})


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("HCWEBHOOK_HOST", os.environ.get("HEALTH_CONNECT_RECEIVER_HOST", "0.0.0.0")))
    parser.add_argument("--port", type=int, default=int(os.environ.get("HCWEBHOOK_PORT", os.environ.get("HEALTH_CONNECT_RECEIVER_PORT", "8787"))))
    parser.add_argument("--db", default=os.environ.get("HCWEBHOOK_DB", os.environ.get("HEALTH_CONNECT_DB", str(DEFAULT_DB))))
    parser.add_argument("--backfill", action="store_true", help="Re-parse all raw_events into normalized tables and exit")
    args = parser.parse_args(argv)

    db_path = Path(args.db).expanduser()
    if args.backfill:
        summary = backfill_db(db_path)
        print(json.dumps(summary))
        return

    init_db(db_path)
    token = load_token()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.auth_token = token  # type: ignore[attr-defined]
    httpd.db_path = db_path  # type: ignore[attr-defined]
    log(f"START host={args.host} port={args.port} db={db_path}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log("STOP")


if __name__ == "__main__":
    main()
