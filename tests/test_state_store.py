"""Scan-state store tests (P3-17).

The store persists one bounded JSON object per line under the resolved
data directory (``SENTINELCLAW_DATA_DIR``). These tests exercise the
record id scheme, ordering, corruption tolerance, and the bounded
record built from a ``run_scan`` report.
"""

import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinelclaw.config.constants import REPORT_SCHEMA_VERSION
from sentinelclaw.state import store
from sentinelclaw.state.store import (
    append_scan_record,
    latest_record,
    list_records,
    read_record,
    record_from_report,
    records_since,
    store_path,
)


@pytest.fixture
def data_dir(
    monkeypatch,
    tmp_path,
) -> Path:
    directory = tmp_path / "data"
    monkeypatch.setenv(
        "SENTINELCLAW_DATA_DIR",
        str(directory),
    )
    return directory


def make_record(
    record_id: str,
    timestamp: str,
    findings: list[dict] | None = None,
    incidents: list[dict] | None = None,
    risk: dict | None = None,
    windows_events: list[dict] | None = None,
    hostname: str = "test-host",
) -> dict:
    findings = findings or []
    record = {
        "record_id": record_id,
        "schema_version": REPORT_SCHEMA_VERSION,
        "hostname": hostname,
        "timestamp": timestamp,
        "scan": {
            "application": "SentinelClaw",
            "timestamp": timestamp,
        },
        "summary": {
            "total_findings": len(findings),
        },
        "risk": risk
        or {
            "score": 0,
            "level": "informational",
        },
        "findings": findings,
        "incidents": incidents or [],
    }

    if windows_events:
        record["windows_events"] = windows_events

    return record


def make_finding(
    rule_id: str,
    title: str,
    severity: str = "medium",
    category: str = "process",
    pid: int | None = None,
    mitre: dict | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": category,
        "pid": pid,
        "mitre": mitre,
        "evidence": {},
    }


def test_append_creates_data_directory_and_file(
    data_dir,
) -> None:
    record = make_record(
        "sc-first",
        "2026-09-09T10:00:00+00:00",
    )

    record_id = append_scan_record(record)

    assert record_id == "sc-first"

    assert data_dir.is_dir()
    assert store_path().is_file()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits",
)
def test_append_creates_owner_only_directory_and_file(
    data_dir,
) -> None:
    append_scan_record(
        make_record(
            "sc-perms",
            "2026-09-09T10:00:00+00:00",
        )
    )

    assert (
        stat.S_IMODE(
            data_dir.stat().st_mode
        )
        == 0o700
    )

    assert (
        stat.S_IMODE(
            store_path().stat().st_mode
        )
        == 0o600
    )


def test_append_and_list_newest_first(
    data_dir,
) -> None:
    append_scan_record(
        make_record(
            "sc-old",
            "2026-09-08T10:00:00+00:00",
            findings=[make_finding("A", "Old finding")],
        )
    )

    append_scan_record(
        make_record(
            "sc-new",
            "2026-09-09T10:00:00+00:00",
            findings=[make_finding("B", "New finding")],
        )
    )

    records = list_records()

    assert len(records) == 2

    assert records[0]["record_id"] == "sc-new"
    assert records[1]["record_id"] == "sc-old"


def test_record_id_derived_from_scan_timestamp(
    data_dir,
) -> None:
    record = make_record(
        "",
        "2026-09-09T15:45:30.123456+02:00",
    )

    record.pop("record_id")

    record_id = append_scan_record(record)

    assert record_id == "sc-20260909T154530123456"


def test_record_id_deduplicated_for_identical_timestamps(
    data_dir,
) -> None:
    record = make_record(
        "",
        "2026-09-09T15:45:30.123456+02:00",
    )

    record.pop("record_id")

    first = append_scan_record(record)

    second = append_scan_record(record)

    assert first == "sc-20260909T154530123456"
    assert second == "sc-20260909T154530123456-2"


def test_record_defaults_schema_version_and_hostname(
    data_dir,
) -> None:
    record_id = append_scan_record(
        {
            "timestamp": "2026-09-09T10:00:00+00:00",
        }
    )

    stored = read_record(record_id)

    assert stored is not None

    assert stored["schema_version"] == "1.0.0"
    assert stored["hostname"]
    assert stored["findings"] == []
    assert stored["incidents"] == []


def test_read_record_returns_none_for_unknown_id(
    data_dir,
) -> None:
    assert read_record("sc-missing") is None


def test_latest_record_returns_newest(
    data_dir,
) -> None:
    assert latest_record() is None

    append_scan_record(
        make_record(
            "sc-a",
            "2026-09-08T10:00:00+00:00",
        )
    )

    append_scan_record(
        make_record(
            "sc-b",
            "2026-09-09T10:00:00+00:00",
        )
    )

    latest = latest_record()

    assert latest is not None
    assert latest["record_id"] == "sc-b"


def test_records_since_filters_by_cutoff(
    data_dir,
) -> None:
    append_scan_record(
        make_record(
            "sc-a",
            "2026-09-08T10:00:00+00:00",
        )
    )

    append_scan_record(
        make_record(
            "sc-b",
            "2026-09-09T10:00:00+00:00",
        )
    )

    cutoff = datetime(
        2026,
        9,
        9,
        0,
        0,
        tzinfo=timezone.utc,
    )

    results = records_since(cutoff)

    assert [record["record_id"] for record in results] == ["sc-b"]


def test_records_since_accepts_naive_cutoff(
    data_dir,
) -> None:
    append_scan_record(
        make_record(
            "sc-b",
            "2026-09-09T10:00:00+00:00",
        )
    )

    naive = datetime(
        2026,
        9,
        9,
        0,
        0,
    )

    assert len(records_since(naive)) == 1


def test_corrupt_line_is_skipped_with_warning(
    data_dir,
    caplog,
) -> None:
    append_scan_record(
        make_record(
            "sc-good",
            "2026-09-09T10:00:00+00:00",
        )
    )

    with store_path().open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write("{ this is not valid json\n")

    records = list_records()

    assert [record["record_id"] for record in records] == ["sc-good"]

    assert any("corrupt scan-state" in message for message in caplog.messages)


def test_missing_store_file_lists_empty(
    data_dir,
) -> None:
    assert list_records() == []
    assert latest_record() is None


def test_record_from_report_flattens_findings(
    data_dir,
) -> None:
    findings = [
        make_finding("A", "One"),
        make_finding("B", "Two"),
    ]

    report = {
        "scan": {
            "application": "SentinelClaw",
            "timestamp": "2026-09-09T10:00:00+00:00",
        },
        "summary": {},
        "risk": {
            "score": 0,
            "level": "informational",
        },
        "findings": {
            "processes": findings,
            "all": findings,
        },
        "incidents": [],
        "system": {
            "hostname": "REPORT-HOST",
        },
    }

    record = record_from_report(report)

    assert record["hostname"] == "REPORT-HOST"
    assert record["schema_version"] == "1.0.0"
    assert record["findings"] == findings
    assert "windows_events" not in record


def test_record_from_report_bounds_windows_events(
    data_dir,
) -> None:
    many_events = [
        {
            "event_id": 4625,
            "event_name": "Failed logon",
        }
        for _ in range(store.MAX_WINDOW_EVENTS_PER_RECORD + 10)
    ]

    report = {
        "scan": {
            "timestamp": "2026-09-09T10:00:00+00:00",
        },
        "summary": {},
        "risk": {},
        "findings": [],
        "incidents": [],
        "windows_events": many_events,
    }

    record = record_from_report(report)

    assert len(record["windows_events"]) == store.MAX_WINDOW_EVENTS_PER_RECORD


def test_append_preserves_caller_supplied_id(
    data_dir,
) -> None:
    record = make_record(
        "sc-custom",
        "2026-09-09T10:00:00+00:00",
    )

    record_id = append_scan_record(record)

    assert record_id == "sc-custom"

    stored = read_record("sc-custom")

    assert stored is not None
    assert stored["record_id"] == "sc-custom"


def test_jsonl_lines_are_json(
    data_dir,
) -> None:
    append_scan_record(
        make_record(
            "sc-a",
            "2026-09-09T10:00:00+00:00",
        )
    )

    for line in store_path().read_text(encoding="utf-8").splitlines():
        assert isinstance(
            json.loads(line),
            dict,
        )
