"""
Scan-state JSONL store (P3-17).

SentinelClaw persists a bounded, machine-readable record of every CLI
scan as one JSON object per line in ``scans.jsonl`` inside the resolved
data directory (``SENTINELCLAW_DATA_DIR`` or ``./data``) -- the first
consumer of :func:`sentinelclaw.config.paths.get_data_directory`.

A record deliberately excludes the bulky raw collector dumps that
``run_scan`` only attaches with ``include_raw=True``. It keeps the
fields stateful hunting needs:

.. code-block:: python

    {
        "record_id": "sc-20260909T154530123456",
        "schema_version": "1.0.0",
        "hostname": "workstation-01",
        "timestamp": "2026-09-09T15:45:30.123456+02:00",
        "scan": {"application": "SentinelClaw", "timestamp": "..."},
        "summary": {"total_findings": 3, ...},
        "risk": {"score": 40, "level": "high", ...},
        "findings": [<finding>, ...],
        "incidents": [<incident>, ...],
        "windows_events": [<event>, ...],   # only when the report
                                            # carried them; capped
    }

``record_id`` is timestamp-based (``sc-<YYYYmmddTHHMMSSffffff>`` of
the scan timestamp) and falls back to ``sc-<UTC now>`` for records
without a parseable scan timestamp. A caller-supplied ``record_id`` is
honored unchanged; ``append_scan_record`` guarantees uniqueness by
suffixing ``-2``, ``-3``, ... when the id already exists in the file.

Reads never raise on corrupt content: unparseable lines are skipped
with a warning so ``history`` and friends stay usable.
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelclaw.config.constants import REPORT_SCHEMA_VERSION
from sentinelclaw.config.paths import (
    ensure_private_directory,
    open_private_append,
)
from sentinelclaw.config.settings import get_settings
from sentinelclaw.engine.timeline_engine import parse_timestamp

logger = logging.getLogger(
    __name__
)

STORE_FILENAME = "scans.jsonl"

# Cap on windows events persisted inside one record. Windows event
# objects are bounded and the collector already caps collection, but
# the cap keeps hand-built records (and --json-raw scans) from writing
# unbounded state files.
MAX_WINDOW_EVENTS_PER_RECORD = 1000


def store_path() -> Path:
    """Return the path to the scan-state JSONL file."""
    return (
        get_settings().resolved_data_dir
        / STORE_FILENAME
    )


def _flatten_findings(
    findings: Any,
) -> list[dict]:
    if isinstance(
        findings,
        dict,
    ):
        result = findings.get(
            "all",
            [],
        )

        return (
            result
            if isinstance(
                result,
                list,
            )
            else []
        )

    if isinstance(
        findings,
        list,
    ):
        return [
            item
            for item in findings
            if isinstance(
                item,
                dict,
            )
        ]

    return []


def record_from_report(
    report: dict,
    hostname: str | None = None,
) -> dict:
    """Build a bounded state record from a ``run_scan`` report.

    The record flattens ``findings.all`` and keeps incidents, risk,
    summary and scan metadata. Windows events are kept only when the
    report already carried them (``--json-raw`` scans), capped at
    :data:`MAX_WINDOW_EVENTS_PER_RECORD`.
    """
    system = report.get(
        "system",
        {},
    )

    if not isinstance(
        system,
        dict,
    ):
        system = {}

    resolved_hostname = (
        hostname
        or (
            str(system.get("hostname"))
            if system.get("hostname")
            else None
        )
        or socket.gethostname()
    )

    scan_meta = report.get(
        "scan",
        {},
    )

    if not isinstance(
        scan_meta,
        dict,
    ):
        scan_meta = {}

    timestamp = scan_meta.get(
        "timestamp"
    )

    record = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "hostname": resolved_hostname,
        "timestamp": (
            str(timestamp)
            if timestamp
            else (
                datetime.now()
                .astimezone()
                .isoformat()
            )
        ),
        "scan": scan_meta,
        "summary": report.get(
            "summary",
            {},
        ),
        "risk": report.get(
            "risk",
            {},
        ),
        "findings": _flatten_findings(
            report.get(
                "findings",
                [],
            )
        ),
        "incidents": report.get(
            "incidents",
            [],
        ),
    }

    windows_events = report.get(
        "windows_events",
        [],
    )

    if (
        isinstance(
            windows_events,
            list,
        )
        and windows_events
    ):
        record["windows_events"] = (
            windows_events[
                :MAX_WINDOW_EVENTS_PER_RECORD
            ]
        )

    return record


def _timestamp_iso(
    record: dict,
) -> str:
    """Return the record's scan timestamp (falling back to now)."""
    raw = record.get(
        "timestamp"
    )

    if raw:
        return str(raw)

    return (
        datetime.now()
        .astimezone()
        .isoformat()
    )


def _base_record_id(
    record: dict,
) -> str:
    """Derive the timestamp-based record id for a record."""
    parsed = parse_timestamp(
        record.get(
            "timestamp"
        )
    )

    if parsed is None:
        parsed = datetime.now(
            tz=timezone.utc
        )

    return "sc-" + parsed.strftime(
        "%Y%m%dT%H%M%S%f"
    )


def _existing_record_ids(
    path: Path,
) -> set[str]:
    if not path.exists():
        return set()

    ids = set()

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    parsed = json.loads(
                        line
                    )
                except json.JSONDecodeError:
                    continue

                if not isinstance(
                    parsed,
                    dict,
                ):
                    continue

                record_id = parsed.get(
                    "record_id"
                )

                if record_id:
                    ids.add(
                        str(record_id)
                    )
    except OSError:
        return set()

    return ids


def _unique_record_id(
    path: Path,
    base: str,
) -> str:
    existing = _existing_record_ids(
        path
    )

    if base not in existing:
        return base

    suffix = 2

    while (
        f"{base}-{suffix}"
        in existing
    ):
        suffix += 1

    return f"{base}-{suffix}"


def append_scan_record(
    record: dict,
) -> str:
    """Append one scan record as a JSONL line and return its id.

    The data directory is created on demand. A missing ``record_id``
    is derived from the record's scan timestamp; a caller-supplied id
    is honored. Corrupt trailing content in the file is left in place
    (reads skip it) and the new record is appended after it.
    """
    path = store_path()

    ensure_private_directory(
        path.parent
    )

    record_id = record.get(
        "record_id"
    )

    if not record_id:
        record_id = _unique_record_id(
            path,
            _base_record_id(record),
        )

    resolved = dict(record)
    resolved["record_id"] = str(
        record_id
    )
    resolved.setdefault(
        "schema_version",
        REPORT_SCHEMA_VERSION,
    )
    resolved.setdefault(
        "timestamp",
        _timestamp_iso(record),
    )
    resolved.setdefault(
        "findings",
        [],
    )
    resolved.setdefault(
        "incidents",
        [],
    )
    resolved.setdefault(
        "risk",
        {},
    )

    if "hostname" not in resolved:
        resolved["hostname"] = (
            socket.gethostname()
        )

    with open_private_append(
        path
    ) as file:
        file.write(
            json.dumps(
                resolved,
                ensure_ascii=False,
                default=str,
            )
        )

        file.write(
            "\n"
        )

    return str(
        record_id
    )


def _read_records(
    path: Path,
) -> list[
    tuple[
        str | None,
        dict,
        int,
    ]
]:
    """Return (timestamp, record, file line index) for every valid line.

    Corrupt or non-object lines are skipped with a warning instead of
    raising so history/analytics survive a torn write.
    """
    if not path.exists():
        return []

    records: list[
        tuple[
            str | None,
            dict,
            int,
        ]
    ] = []

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            for index, line in enumerate(
                file
            ):
                line = line.strip()

                if not line:
                    continue

                try:
                    parsed = json.loads(
                        line
                    )
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Skipping corrupt scan-state "
                        "line %d in %s: %s",
                        index + 1,
                        path,
                        exc,
                    )

                    continue

                if not isinstance(
                    parsed,
                    dict,
                ):
                    logger.warning(
                        "Skipping non-object scan-state "
                        "line %d in %s",
                        index + 1,
                        path,
                    )

                    continue

                records.append(
                    (
                        parsed.get(
                            "timestamp"
                        ),
                        parsed,
                        index,
                    )
                )
    except OSError as exc:
        logger.warning(
            "Unable to read scan state %s: %s",
            path,
            exc,
        )

        return []

    return records


def list_records() -> list[dict]:
    """Return every stored record, newest first.

    Records are ordered by their scan timestamp (descending); records
    sharing a timestamp keep file order reversed so the most recently
    appended record sorts first.
    """
    path = store_path()

    raw = _read_records(
        path
    )

    def sort_key(
        item: tuple[
            str | None,
            dict,
            int,
        ],
    ) -> tuple[
        datetime,
        int,
    ]:
        timestamp = parse_timestamp(
            item[0]
        )

        return (
            (
                timestamp
                if timestamp is not None
                else datetime.min.replace(
                    tzinfo=timezone.utc
                )
            ),
            item[2],
        )

    ordered = sorted(
        raw,
        key=sort_key,
        reverse=True,
    )

    return [
        record
        for _, record, _ in ordered
    ]


def read_record(
    record_id: str,
) -> dict | None:
    """Return the record with the given id, or ``None``."""
    for record in list_records():
        if str(
            record.get(
                "record_id"
            )
        ) == str(
            record_id
        ):
            return record

    return None


def records_since(
    since: datetime,
) -> list[dict]:
    """Return records whose scan timestamp is at or after ``since``."""
    if since.tzinfo is None:
        since = since.replace(
            tzinfo=timezone.utc
        )

    results = []

    for record in list_records():
        timestamp = parse_timestamp(
            record.get(
                "timestamp"
            )
        )

        if timestamp is None:
            continue

        if timestamp >= since:
            results.append(
                record
            )

    return results


def latest_record() -> dict | None:
    """Return the newest stored record, or ``None`` for an empty store."""
    records = list_records()

    if not records:
        return None

    return records[0]
