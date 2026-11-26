import json
import os
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from hcwebhook_receiver.server import backfill_db, insert_payload


@pytest.fixture
def sample_payload():
    return {
        "sleep": [
            {
                "session_end_time": "2026-01-02T23:00:00Z",
                "duration_seconds": 28800,
                "stages": [
                    {"stage": "4", "start_time": "2026-01-02T15:00:00Z", "end_time": "2026-01-02T18:00:00Z"},
                    {"stage": "5", "start_time": "2026-01-02T18:00:00Z", "end_time": "2026-01-02T23:00:00Z"},
                ],
            }
        ],
        "heart_rate": [{"time": "2026-01-02T15:05:00Z", "bpm": 62}],
        "heart_rate_variability": [{"time": "2026-01-02T15:05:00Z", "rmssd_millis": 42.5}],
        "oxygen_saturation": [{"time": "2026-01-02T20:00:00Z", "percentage": 97.0}],
        "resting_heart_rate": [{"time": "2026-01-02T00:00:00Z", "bpm": 58}],
        "respiratory_rate": [{"time": "2026-01-02T20:00:00Z", "rate": 14.2}],
    }


def test_insert_payload_normalizes_sleep_and_vitals(tmp_path, sample_payload):
    db = tmp_path / "health.sqlite"
    result = insert_payload(db, "alice", sample_payload, "127.0.0.1", "pytest")

    assert result["status"] == "inserted"
    assert result["sleep_sessions_seen"] == 1
    assert result["sleep_sessions_inserted"] == 1
    assert result["vitals_seen"] == 5
    assert result["vitals_inserted"] == 5

    con = sqlite3.connect(db)
    sleep = con.execute("select session_start, session_end, duration_seconds, stage_count from sleep_sessions").fetchone()
    assert sleep == ("2026-01-02T15:00:00Z", "2026-01-02T23:00:00Z", 28800.0, 2)

    metrics = dict(con.execute("select metric, count(*) from vitals group by metric").fetchall())
    assert metrics == {
        "heart_rate": 1,
        "heart_rate_variability": 1,
        "oxygen_saturation": 1,
        "resting_heart_rate": 1,
        "respiratory_rate": 1,
    }


def test_duplicate_raw_event_is_detected(tmp_path, sample_payload):
    db = tmp_path / "health.sqlite"
    first = insert_payload(db, "alice", sample_payload, None, None)
    second = insert_payload(db, "alice", sample_payload, None, None)

    assert first["status"] == "inserted"
    assert second["status"] == "duplicate_raw"
    assert second["sleep_sessions_seen"] == 0
    assert second["vitals_seen"] == 0

    con = sqlite3.connect(db)
    assert con.execute("select count(*) from raw_events").fetchone()[0] == 1
    assert con.execute("select count(*) from sync_log").fetchone()[0] == 2


def test_sleep_start_falls_back_to_duration(tmp_path):
    db = tmp_path / "health.sqlite"
    payload = {
        "sleep": [{"session_end_time": "2026-01-02T23:00:00Z", "duration_seconds": 3600, "stages": []}]
    }
    insert_payload(db, "alice", payload, None, None)
    con = sqlite3.connect(db)
    start = con.execute("select session_start from sleep_sessions").fetchone()[0]
    assert start == "2026-01-02T22:00:00Z"


def test_sleep_updates_in_place_by_record_id(tmp_path):
    db = tmp_path / "health.sqlite"
    partial = {
        "sleep": [
            {
                "session_end_time": "2026-11-25T07:45:00+06:00",
                "duration_seconds": 17580,
                "stages": [
                    {"stage": "4", "start_time": "2026-11-25T02:52:00+06:00", "end_time": "2026-11-25T07:45:00+06:00"}
                ],
                "metadata": {
                    "id": "b7929db7-494f-3915-89e5-699c6062bb9f",
                    "last_modified_time": "2026-11-25T07:45:00.45+06:00",
                },
            }
        ]
    }
    finalized = {
        "sleep": [
            {
                "session_end_time": "2026-11-25T10:02:00+06:00",
                "duration_seconds": 25800,
                "stages": [
                    {"stage": "4", "start_time": "2026-11-25T02:52:00+06:00", "end_time": "2026-11-25T07:45:00+06:00"},
                    {"stage": "6", "start_time": "2026-11-25T07:45:00+06:00", "end_time": "2026-11-25T10:02:00+06:00"},
                ],
                "metadata": {
                    "id": "b7929db7-494f-3915-89e5-699c6062bb9f",
                    "last_modified_time": "2026-11-25T10:05:06.247+06:00",
                },
            }
        ]
    }
    insert_payload(db, "alice", partial, None, None)
    insert_payload(db, "alice", finalized, None, None)

    # Re-sending an older modification for the same record_id must not downgrade it
    stale_copy = dict(partial, timestamp="2026-11-25T11:00:00+06:00")
    insert_payload(db, "alice", stale_copy, None, None)

    con = sqlite3.connect(db)
    rows = con.execute(
        "SELECT session_start, session_end, duration_seconds, stage_count, record_id, last_modified_time FROM sleep_sessions"
    ).fetchall()
    assert rows == [
        (
            "2026-11-25T02:52:00+06:00",
            "2026-11-25T10:02:00+06:00",
            25800.0,
            2,
            "b7929db7-494f-3915-89e5-699c6062bb9f",
            "2026-11-25T10:05:06.247+06:00",
        )
    ]


def test_sleep_record_id_allows_shorter_finalized_update(tmp_path):
    db = tmp_path / "health.sqlite"
    initial = {
        "sleep": [
            {
                "session_end_time": "2026-11-25T10:12:00+06:00",
                "duration_seconds": 26400,
                "stages": [{"stage": "4", "start_time": "2026-11-25T02:52:00+06:00", "end_time": "2026-11-25T10:12:00+06:00"}],
                "metadata": {"id": "rec-trim", "last_modified_time": "2026-11-25T10:12:00+06:00"},
            }
        ]
    }
    trimmed = {
        "sleep": [
            {
                "session_end_time": "2026-11-25T10:02:00+06:00",
                "duration_seconds": 25800,
                "stages": [{"stage": "4", "start_time": "2026-11-25T02:52:00+06:00", "end_time": "2026-11-25T10:02:00+06:00"}],
                "metadata": {"id": "rec-trim", "last_modified_time": "2026-11-25T10:15:00+06:00"},
            }
        ]
    }
    insert_payload(db, "alice", initial, None, None)
    insert_payload(db, "alice", trimmed, None, None)

    con = sqlite3.connect(db)
    rows = con.execute("SELECT session_end, duration_seconds FROM sleep_sessions").fetchall()
    assert rows == [("2026-11-25T10:02:00+06:00", 25800.0)]


def test_sleep_overlap_fallback_replaces_drifted_partial_and_keeps_nap(tmp_path):
    db = tmp_path / "health.sqlite"
    partial = {
        "sleep": [
            {
                "session_end_time": "2026-11-25T08:00:00+06:00",
                "duration_seconds": 21600,
                "stages": [{"stage": "4", "start_time": "2026-11-25T02:00:00+06:00", "end_time": "2026-11-25T08:00:00+06:00"}],
                "metadata": {"id": "rec-a", "last_modified_time": "2026-11-25T08:00:00+06:00"},
            }
        ]
    }
    drifted_final_plus_nap = {
        "sleep": [
            {
                "session_end_time": "2026-11-25T10:00:00+06:00",
                "duration_seconds": 28680,
                "stages": [{"stage": "4", "start_time": "2026-11-25T02:02:00+06:00", "end_time": "2026-11-25T10:00:00+06:00"}],
                "metadata": {"id": "rec-b", "last_modified_time": "2026-11-25T10:05:00+06:00"},
            },
            {
                "session_end_time": "2026-11-25T16:30:00+06:00",
                "duration_seconds": 3600,
                "stages": [{"stage": "4", "start_time": "2026-11-25T15:30:00+06:00", "end_time": "2026-11-25T16:30:00+06:00"}],
                "metadata": {"id": "rec-nap", "last_modified_time": "2026-11-25T16:35:00+06:00"},
            },
        ]
    }
    insert_payload(db, "alice", partial, None, None)
    insert_payload(db, "alice", drifted_final_plus_nap, None, None)

    con = sqlite3.connect(db)
    rows = con.execute("SELECT record_id, duration_seconds FROM sleep_sessions ORDER BY session_start ASC").fetchall()
    assert rows == [("rec-b", 28680.0), ("rec-nap", 3600.0)]


def test_backfill_migrates_legacy_rows_idempotently(tmp_path):
    db = tmp_path / "health.sqlite"
    partial = {
        "sleep": [
            {
                "session_end_time": "2026-11-25T07:45:00+06:00",
                "duration_seconds": 17580,
                "stages": [{"stage": "4", "start_time": "2026-11-25T02:52:00+06:00", "end_time": "2026-11-25T07:45:00+06:00"}],
                "metadata": {"id": "rec-1", "last_modified_time": "2026-11-25T07:45:00.45+06:00"},
            }
        ]
    }
    finalized = {
        "sleep": [
            {
                "session_end_time": "2026-11-25T10:02:00+06:00",
                "duration_seconds": 25800,
                "stages": [{"stage": "4", "start_time": "2026-11-25T02:52:00+06:00", "end_time": "2026-11-25T10:02:00+06:00"}],
                "metadata": {"id": "rec-1", "last_modified_time": "2026-11-25T10:05:06.247+06:00"},
            }
        ]
    }
    insert_payload(db, "alice", partial, None, None)
    insert_payload(db, "alice", finalized, None, None)

    # Simulate legacy rows created before record_id existed (two overlapping rows with NULL record_id)
    with sqlite3.connect(db) as con:
        con.execute("UPDATE sleep_sessions SET record_id = NULL, last_modified_time = NULL")
        con.execute(
            "INSERT INTO sleep_sessions (raw_event_id, person, session_start, session_end, duration_seconds, stage_count, stages_json) "
            "VALUES (1, 'alice', '2026-11-25T02:52:00+06:00', '2026-11-25T07:45:00+06:00', 17580.0, 1, '[]')"
        )

    first = backfill_db(db)
    second = backfill_db(db)
    assert first["sleep_sessions_inserted"] == 1
    assert second["sleep_sessions_inserted"] == 0

    con = sqlite3.connect(db)
    rows = con.execute("SELECT session_end, duration_seconds, record_id FROM sleep_sessions").fetchall()
    assert rows == [("2026-11-25T10:02:00+06:00", 25800.0, "rec-1")]
