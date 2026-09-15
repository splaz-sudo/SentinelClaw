"""Security-hardening regression tests (findings 1-4).

Covers terminal-control-character sanitization of untrusted rendered
output (rule text, file names, AI output), CSV formula-injection
neutralization (CWE-1236), owner-only permissions for state/report
files, and the offline threat-intel bundle size cap.
"""

import csv
import io
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from sentinelclaw.commands import investigate
from sentinelclaw.config.settings import Settings
from sentinelclaw.reporting.report_generator import (
    generate_csv_report,
    save_report_formats,
)
from sentinelclaw.tools.intel_loader import (
    check_collected_values,
    load_intel_bundle,
)
from sentinelclaw.ui import console


# ---------------------------------------------------------------------------
# Finding 1: terminal escape injection
# ---------------------------------------------------------------------------


def test_sanitize_strips_escape_sequences_and_preserves_text() -> None:
    raw = (
        "\x1b]0;pwnd\x07normal"
        "\x1b[2Jclear"
        "\x9b31mc1"
        "caf\u00e9\nline\ttab"
    )

    cleaned = console.sanitize_terminal_text(raw)

    assert "\x1b" not in cleaned
    assert "\x07" not in cleaned
    assert "\x9b" not in cleaned
    assert "normal" in cleaned
    assert "clear" in cleaned
    assert "caf\u00e9" in cleaned
    assert "\n" in cleaned
    assert "\t" in cleaned


def test_sanitize_preserves_plain_unicode() -> None:
    text = "h\u00e9llo \u4e16\u754c \u2705"

    assert console.sanitize_terminal_text(text) == text


def test_sanitize_strips_del_and_c1_but_keeps_high_unicode() -> None:
    cleaned = console.sanitize_terminal_text("\x7f\x9dok\u00ff")

    assert cleaned == "ok\u00ff"


def test_status_strips_escape_sequence(capsys) -> None:
    console.status(
        "Name",
        "evil\x1b]52;c;cGF3bmVk\x07.log",
    )

    output = capsys.readouterr().out

    assert "\x1b" not in output
    assert "\x07" not in output
    assert "evil" in output


def test_file_dashboard_sanitizes_name_and_path(capsys) -> None:
    console.print_file_dashboard(
        {
            "file": {
                "name": "\x1b]0;pwnd\x07evil.exe",
                "path": "/tmp/\x1b[31mevil.exe",
                "sha256": "0" * 64,
                "entropy": 1.0,
            },
            "risk": {
                "score": 0,
                "level": "informational",
            },
            "findings": [],
        }
    )

    output = capsys.readouterr().out

    assert "\x1b" not in output
    assert "\x07" not in output
    assert "evil.exe" in output


def test_directory_dashboard_sanitizes_file_names(capsys) -> None:
    console.print_directory_dashboard(
        {
            "directory": "\x1b]0;pwnd\x07/tmp",
            "analysis": {
                "files_scanned": 1,
                "files_error_count": 0,
                "files_truncated": False,
            },
            "risk": {
                "score": 0,
                "level": "informational",
            },
            "files": [
                {
                    "file": {
                        "name": "bad\x1b[2Jfile.bin",
                    },
                    "findings": [],
                }
            ],
            "findings": [],
        }
    )

    output = capsys.readouterr().out

    assert "\x1b" not in output
    assert "bad" in output
    assert "file.bin" in output


def test_compact_finding_strips_escape_sequence(capsys) -> None:
    console.compact_finding(
        {
            "severity": "high",
            "rule_id": "RULE-\x1b[31m1",
            "title": "bad\x1b]0;pwnd\x07title",
            "description": "desc\x1b[2Jription",
            "confidence": "high\x1b[1m",
            "process_name": "proc\x1b]52;c;cGF3bmVk\x07.exe",
            "source_ip": "10.0.0.1\x1b[2J",
            "mitre": {
                "technique": "T1059\x1b[31m",
                "name": "Scripting\x1b]0;x\x07",
                "tactic": "Execution\x1b[2J",
            },
        },
        verbose=True,
    )

    output = capsys.readouterr().out

    assert "\x1b" not in output
    assert "\x07" not in output
    assert "title" in output
    assert "Scripting" in output


def test_compact_incident_strips_escape_sequence(capsys) -> None:
    console.compact_incident(
        {
            "severity": "high",
            "incident_id": "INC-\x1b[31m1",
            "title": "incident\x1b]0;pwnd\x07 title",
            "description": "why\x1b[2J",
            "confidence": "high\x1b[1m",
            "finding_count": 1,
            "related_rule_ids": ["A\x1b[31m", "B"],
        },
        verbose=True,
    )

    output = capsys.readouterr().out

    assert "\x1b" not in output
    assert "incident" in output


def test_investigate_sanitizes_ai_output(monkeypatch, capsys) -> None:
    report = {
        "summary": {
            "total_findings": 0,
            "incidents": 0,
        },
        "risk": {
            "score": 0,
            "level": "informational",
        },
    }

    monkeypatch.setattr(
        investigate,
        "analyze_report_with_qwen",
        lambda report, model: {
            "model": "qwen\x1b[31m",
            "analysis": (
                "AI summary\x1b]52;c;cGF3bmVk\x07"
            ),
        },
    )

    investigate.print_ai_investigation(
        report,
        model="qwen",
    )

    output = capsys.readouterr().out

    assert "\x1b" not in output
    assert "\x07" not in output
    assert "AI summary" in output


# ---------------------------------------------------------------------------
# Finding 2: CSV formula injection (CWE-1236)
# ---------------------------------------------------------------------------


def make_csv_report(title: str) -> dict:
    return {
        "findings": {
            "all": [
                {
                    "rule_id": "R-1",
                    "severity": "high",
                    "title": title,
                    "category": "process",
                    "source": "test-rule",
                    "timestamp": "2026-09-09T10:00:00+00:00",
                }
            ]
        },
        "incidents": [],
    }


@pytest.mark.parametrize(
    "payload",
    (
        "=cmd|'/C calc'!A0",
        "+cmd|'/C calc'!A0",
        "-cmd|'/C calc'!A0",
        "@cmd|'/C calc'!A0",
        "\tcmd|'/C calc'!A0",
        "\rcmd|'/C calc'!A0",
    ),
)
def test_csv_formula_payloads_are_prefixed(payload: str) -> None:
    csv_text = generate_csv_report(
        make_csv_report(payload)
    )

    rows = list(
        csv.reader(
            io.StringIO(csv_text)
        )
    )

    title_cell = rows[1][2]

    assert title_cell == "'" + payload


def test_csv_normal_title_is_unchanged() -> None:
    csv_text = generate_csv_report(
        make_csv_report("Encoded PowerShell detected")
    )

    rows = list(
        csv.reader(
            io.StringIO(csv_text)
        )
    )

    assert rows[1][2] == "Encoded PowerShell detected"


def test_csv_incident_title_is_prefixed() -> None:
    report = make_csv_report("clean")

    report["incidents"] = [
        {
            "incident_id": "INC-1",
            "severity": "high",
            "title": "=HYPERLINK(\"http://evil\")",
            "confidence": "high",
            "finding_count": 1,
            "related_rule_ids": ["R-1"],
        }
    ]

    csv_text = generate_csv_report(report)

    assert "'=HYPERLINK" in csv_text


# ---------------------------------------------------------------------------
# Finding 3: owner-only state and report files
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits",
)
def test_report_files_are_owner_only(tmp_path) -> None:
    reports_dir = tmp_path / "reports"

    created = save_report_formats(
        make_csv_report("clean"),
        output_directory=reports_dir,
        formats=("csv",),
    )

    assert (
        stat.S_IMODE(
            reports_dir.stat().st_mode
        )
        == 0o700
    )

    assert (
        stat.S_IMODE(
            created["csv"].stat().st_mode
        )
        == 0o600
    )


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX permission bits",
)
def test_existing_report_directory_is_not_chmod_ed(tmp_path) -> None:
    reports_dir = tmp_path / "reports"

    reports_dir.mkdir()
    os.chmod(reports_dir, 0o755)

    save_report_formats(
        make_csv_report("clean"),
        output_directory=reports_dir,
        formats=("csv",),
    )

    assert (
        stat.S_IMODE(
            reports_dir.stat().st_mode
        )
        == 0o755
    )


# ---------------------------------------------------------------------------
# Finding 4: intel bundle size cap and fd handling
# ---------------------------------------------------------------------------

STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--11111111-1111-1111-1111-111111111111",
            "name": "C2 sinkhole",
            "pattern": "[ipv4-addr:value = '10.0.0.5']",
        }
    ],
}


def write_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "intel.json"

    bundle.write_text(
        json.dumps(STIX_BUNDLE),
        encoding="utf-8",
    )

    return bundle


def test_oversized_intel_bundle_is_skipped_not_found(
    monkeypatch,
    tmp_path,
) -> None:
    bundle = write_bundle(tmp_path)

    monkeypatch.setattr(
        "sentinelclaw.tools.intel_loader.get_settings",
        lambda: Settings(
            max_intel_bundle_size_bytes=8,
        ),
    )

    result = load_intel_bundle(str(bundle))

    assert "error" in result
    assert "size limit" in result["error"]

    assert check_collected_values(
        result,
        ips=["10.0.0.5"],
    ) == []


def test_normal_intel_bundle_still_parses(
    monkeypatch,
    tmp_path,
) -> None:
    bundle = write_bundle(tmp_path)

    monkeypatch.setattr(
        "sentinelclaw.tools.intel_loader.get_settings",
        lambda: Settings(),
    )

    result = load_intel_bundle(str(bundle))

    assert "error" not in result
    assert result["ip"][0]["value"] == "10.0.0.5"


@pytest.mark.skipif(
    not Path("/proc/self/fd").is_dir(),
    reason="requires procfs to count open file descriptors",
)
def test_format_sniff_fallback_does_not_leak_fds(tmp_path) -> None:
    bundle = tmp_path / "intel.txt"

    bundle.write_text(
        "garbage",
        encoding="utf-8",
    )

    before = len(os.listdir("/proc/self/fd"))

    for _ in range(25):
        assert "error" in load_intel_bundle(str(bundle))

    after = len(os.listdir("/proc/self/fd"))

    assert after <= before + 2
