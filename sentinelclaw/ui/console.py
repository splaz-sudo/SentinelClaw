from __future__ import annotations

import json
import os
import sys
from typing import Any

from sentinelclaw.config.constants import (
    SEVERITY_RANK,
    SEVERITY_ORDER as _SEVERITY_ORDER,
)


WIDTH = 72

SEVERITY_ORDER = tuple(
    reversed(_SEVERITY_ORDER)
)


def supports_color() -> bool:
    if not sys.stdout.isatty():
        return False

    if os.environ.get("NO_COLOR"):
        return False

    return True


COLOR_ENABLED = supports_color()


COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "white": "\033[97m",
}


def sanitize_terminal_text(
    value: Any,
) -> str:
    """Return ``value`` as text with terminal control characters removed.

    C0 control characters (0x00-0x1f) are stripped except newline and
    tab; DEL (0x7f) and the C1 range (0x80-0x9f) are stripped as well.
    Untrusted strings (rule text, file names, AI output) are rendered
    through this helper before printing so escape sequences cannot spoof
    the terminal or write the clipboard.
    """
    return "".join(
        character
        for character in str(value)
        if (
            character in "\n\t"
            or 0x20 <= ord(character) <= 0x7E
            or ord(character) >= 0xA0
        )
    )


class _StyledText(str):
    """Text built by :func:`colorize`; its content is already sanitized."""


def colorize(
    text: str,
    color: str,
) -> str:
    clean = sanitize_terminal_text(
        text
    )

    if not COLOR_ENABLED:
        return _StyledText(clean)

    return _StyledText(
        COLORS.get(color, "")
        + clean
        + COLORS["reset"]
    )


def _display_text(
    value: Any,
) -> str:
    """Sanitize untrusted text while preserving colorized output."""
    if isinstance(value, _StyledText):
        return str(value)

    return sanitize_terminal_text(value)


def severity_color(
    severity: str,
) -> str:
    severity = str(
        severity
    ).lower()

    if severity == "critical":
        return "magenta"

    if severity == "high":
        return "red"

    if severity == "medium":
        return "yellow"

    if severity == "low":
        return "cyan"

    return "white"


def banner(
    title: str,
) -> None:
    print()
    print("=" * WIDTH)

    print(
        colorize(
            title.center(WIDTH),
            "bold",
        )
    )

    print("=" * WIDTH)


def section(
    title: str,
) -> None:
    print()

    print(
        colorize(
            title.upper(),
            "bold",
        )
    )

    print("-" * WIDTH)


def status(
    label: str,
    value: Any,
    width: int = 22,
) -> None:
    print(
        f"{_display_text(label):<{width}}"
        f"{_display_text(value)}"
    )


def severity_counts(
    findings: list[dict],
) -> dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = str(
            finding.get(
                "severity",
                "info",
            )
        ).lower()

        if severity not in counts:
            severity = "info"

        counts[
            severity
        ] += 1

    return counts


def risk_label(
    score: int,
    level: str,
) -> str:
    level = str(
        level
    ).lower()

    text = (
        f"{score}/100 "
        f"({level.upper()})"
    )

    return colorize(
        text,
        severity_color(
            level
        ),
    )


def compact_finding(
    finding: dict,
    verbose: bool = False,
) -> None:
    severity = str(
        finding.get(
            "severity",
            "info",
        )
    ).lower()

    rule_id = finding.get(
        "rule_id",
        "UNKNOWN",
    )

    title = finding.get(
        "title",
        "Unknown finding",
    )

    severity_text = colorize(
        f"{severity.upper():8}",
        severity_color(
            severity
        ),
    )

    print(
        f"{severity_text} "
        f"{sanitize_terminal_text(rule_id):<16} "
        f"{sanitize_terminal_text(title)}"
    )

    if not verbose:
        return

    description = finding.get(
        "description"
    )

    if description:
        print(
            f"    Reason      : "
            f"{sanitize_terminal_text(description)}"
        )

    confidence = finding.get(
        "confidence"
    )

    if confidence:
        print(
            f"    Confidence  : "
            f"{sanitize_terminal_text(confidence)}"
        )

    pid = finding.get(
        "pid"
    )

    if pid is not None:
        print(
            f"    PID         : "
            f"{sanitize_terminal_text(pid)}"
        )

    process_name = finding.get(
        "process_name"
    )

    if process_name:
        print(
            f"    Process     : "
            f"{sanitize_terminal_text(process_name)}"
        )

    source_ip = finding.get(
        "source_ip"
    )

    if source_ip:
        print(
            f"    Source IP   : "
            f"{sanitize_terminal_text(source_ip)}"
        )

    destination_ip = finding.get(
        "destination_ip"
    )

    if destination_ip:
        print(
            f"    Destination : "
            f"{sanitize_terminal_text(destination_ip)}"
        )

    remote_ip = finding.get(
        "remote_ip"
    )

    remote_port = finding.get(
        "remote_port"
    )

    if remote_ip:
        remote = remote_ip

        if remote_port is not None:
            remote = (
                f"{remote_ip}:"
                f"{remote_port}"
            )

        print(
            f"    Remote      : "
            f"{sanitize_terminal_text(remote)}"
        )

    mitre = finding.get(
        "mitre"
    )

    if isinstance(
        mitre,
        dict,
    ):
        technique = mitre.get(
            "technique"
        )

        name = mitre.get(
            "name"
        )

        tactic = mitre.get(
            "tactic"
        )

        if technique or name:
            print(
                f"    MITRE       : "
                f"{sanitize_terminal_text(technique or 'Unknown')}"
                f" - "
                f"{sanitize_terminal_text(name or 'Unknown')}"
            )

        if tactic:
            print(
                f"    Tactic      : "
                f"{sanitize_terminal_text(tactic)}"
            )

    evidence = finding.get(
        "evidence"
    )

    if evidence:
        print(
            "    Evidence    : "
            + json.dumps(
                evidence,
                ensure_ascii=False,
                default=str,
            )
        )


def compact_incident(
    incident: dict,
    verbose: bool = False,
) -> None:
    severity = str(
        incident.get(
            "severity",
            "info",
        )
    ).lower()

    incident_id = incident.get(
        "incident_id",
        "UNKNOWN",
    )

    title = incident.get(
        "title",
        "Unknown incident",
    )

    severity_text = colorize(
        f"{severity.upper():8}",
        severity_color(
            severity
        ),
    )

    print(
        f"{severity_text} "
        f"{sanitize_terminal_text(incident_id):<18} "
        f"{sanitize_terminal_text(title)}"
    )

    if not verbose:
        return

    description = incident.get(
        "description"
    )

    if description:
        print(
            f"    Reason      : "
            f"{sanitize_terminal_text(description)}"
        )

    confidence = incident.get(
        "confidence"
    )

    if confidence:
        print(
            f"    Confidence  : "
            f"{sanitize_terminal_text(confidence)}"
        )

    finding_count = incident.get(
        "finding_count",
        0,
    )

    print(
        f"    Findings    : "
        f"{sanitize_terminal_text(finding_count)}"
    )

    related_rule_ids = incident.get(
        "related_rule_ids",
        [],
    )

    if related_rule_ids:
        print(
            "    Rules       : "
            + ", ".join(
                sanitize_terminal_text(
                    rule_id
                )
                for rule_id in related_rule_ids
            )
        )


def print_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    findings = (
        report
        .get(
            "findings",
            {},
        )
        .get(
            "all",
            [],
        )
    )

    incidents = report.get(
        "incidents",
        [],
    )

    risk = report.get(
        "risk",
        {},
    )

    summary = report.get(
        "summary",
        {},
    )

    counts = severity_counts(
        findings
    )

    banner(
        "SENTINELCLAW SECURITY CONSOLE"
    )

    section(
        "System scan"
    )

    status(
        "Processes",
        summary.get(
            "processes_scanned",
            0,
        ),
    )

    status(
        "Connections",
        summary.get(
            "network_connections_scanned",
            0,
        ),
    )

    status(
        "Windows Events",
        summary.get(
            "windows_events_scanned",
            0,
        ),
    )

    status(
        "Detection Rules",
        summary.get(
            "rules_loaded",
            0,
        ),
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    section(
        "Findings"
    )

    for severity in SEVERITY_ORDER:
        value = counts[
            severity
        ]

        label = (
            severity.upper()
        )

        label = colorize(
            label,
            severity_color(
                severity
            ),
        )

        status(
            label,
            value,
        )

    status(
        "TOTAL",
        len(
            findings
        ),
    )

    section(
        "Incidents"
    )

    status(
        "Correlated",
        len(
            incidents
        ),
    )

    if incidents:
        print()

        for incident in incidents[
            :10
        ]:
            compact_incident(
                incident,
                verbose=verbose,
            )

    section(
        "Top findings"
    )

    if not findings:
        print(
            "[+] No findings detected."
        )

    else:
        ranked = sorted(
            findings,
            key=lambda item: SEVERITY_RANK.get(
                str(
                    item.get(
                        "severity",
                        "info",
                    )
                ).lower(),
                0,
            ),
            reverse=True,
        )

        limit = (
            len(ranked)
            if verbose
            else 10
        )

        for finding in ranked[
            :limit
        ]:
            compact_finding(
                finding,
                verbose=verbose,
            )

    section(
        "Assessment"
    )

    if not findings:
        print(
            "[+] No security indicators "
            "were detected by the current rules."
        )

    elif (
        counts["critical"]
        or counts["high"]
    ):
        print(
            "[!] High-priority indicators "
            "require investigation."
        )

    elif counts["medium"]:
        print(
            "[!] Suspicious indicators were "
            "detected. Review the findings."
        )

    else:
        print(
            "[+] Only low or informational "
            "indicators were detected."
        )

    print()
    print("=" * WIDTH)

    print(
        "SentinelClaw findings are indicators, "
        "not proof of compromise."
    )

    print("=" * WIDTH)
    print()


def print_pcap_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    if "error" in report:
        banner(
            "SENTINELCLAW PCAP ANALYSIS"
        )

        print()
        print(
            f"[ERROR] "
            f"{sanitize_terminal_text(report['error'])}"
        )
        print()
        return

    pcap = report.get(
        "pcap",
        {},
    )

    risk = report.get(
        "risk",
        {},
    )

    findings = report.get(
        "findings",
        [],
    )

    incidents = report.get(
        "incidents",
        [],
    )

    protocols = pcap.get(
        "protocols",
        {},
    )

    banner(
        "SENTINELCLAW PCAP ANALYSIS"
    )

    section(
        "Capture"
    )

    status(
        "File",
        pcap.get(
            "name",
            "Unknown",
        ),
    )

    status(
        "Packets",
        pcap.get(
            "packets_total",
            0,
        ),
    )

    status(
        "TCP",
        protocols.get(
            "tcp",
            0,
        ),
    )

    status(
        "UDP",
        protocols.get(
            "udp",
            0,
        ),
    )

    status(
        "Other",
        protocols.get(
            "other",
            0,
        ),
    )

    status(
        "Unique IPs",
        pcap.get(
            "unique_ips",
            0,
        ),
    )

    status(
        "Flows",
        pcap.get(
            "unique_flows",
            0,
        ),
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    status(
        "Findings",
        len(
            findings
        ),
    )

    status(
        "Incidents",
        len(
            incidents
        ),
    )

    section(
        "Top destination ports"
    )

    ports = pcap.get(
        "top_destination_ports",
        [],
    )

    if not ports:
        print(
            "No destination-port data."
        )

    else:
        for item in ports[
            :10
        ]:
            print(
                f"{str(item.get('port')):<10}"
                f"{item.get('packets', 0)} packets"
            )

    section(
        "Findings"
    )

    if not findings:
        print(
            "[+] No suspicious PCAP "
            "behavior detected."
        )

    else:
        for finding in findings:
            compact_finding(
                finding,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)

    print(
        "PCAP findings are indicators "
        "and require investigation."
    )

    print("=" * WIDTH)
    print()


def print_file_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    if "error" in report:
        banner(
            "SENTINELCLAW FILE ANALYSIS"
        )

        print()
        print(
            f"[ERROR] "
            f"{sanitize_terminal_text(report['error'])}"
        )
        print()
        return

    file_info = report.get(
        "file",
        {},
    )

    risk = report.get(
        "risk",
        {},
    )

    findings = report.get(
        "findings",
        [],
    )

    banner(
        "SENTINELCLAW FILE ANALYSIS"
    )

    section(
        "File"
    )

    status(
        "Name",
        file_info.get(
            "name",
            "Unknown",
        ),
    )

    status(
        "Path",
        file_info.get(
            "path",
            "Unknown",
        ),
    )

    status(
        "SHA-256",
        file_info.get(
            "sha256",
            "Unknown",
        ),
    )

    status(
        "Entropy",
        file_info.get(
            "entropy",
            "Unknown",
        ),
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    status(
        "Findings",
        len(
            findings
        ),
    )

    section(
        "Findings"
    )

    if not findings:
        print(
            "[+] No file indicators detected."
        )

    else:
        for finding in findings:
            compact_finding(
                finding,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)
    print()


def print_log_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    if "error" in report:
        banner(
            "SENTINELCLAW LOG ANALYSIS"
        )

        print()
        print(
            f"[ERROR] "
            f"{sanitize_terminal_text(report['error'])}"
        )
        print()
        return

    log_data = report.get(
        "log",
        {},
    )

    risk = report.get(
        "risk",
        {},
    )

    findings = report.get(
        "findings",
        [],
    )

    incidents = report.get(
        "incidents",
        [],
    )

    banner(
        "SENTINELCLAW LOG ANALYSIS"
    )

    section(
        "Log file"
    )

    status(
        "File",
        log_data.get(
            "file",
            "Unknown",
        ),
    )

    status(
        "Total lines",
        log_data.get(
            "total_lines",
            0,
        ),
    )

    status(
        "Suspicious matches",
        log_data.get(
            "suspicious_matches",
            0,
        ),
    )

    status(
        "Events parsed",
        len(
            log_data.get(
                "events",
                [],
            )
        ),
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    status(
        "Findings",
        len(
            findings
        ),
    )

    status(
        "Incidents",
        len(
            incidents
        ),
    )

    section(
        "Findings"
    )

    if not findings:
        print(
            "[+] No log indicators detected."
        )

    else:
        for finding in findings:
            compact_finding(
                finding,
                verbose=verbose,
            )

    section(
        "Incidents"
    )

    if not incidents:
        print(
            "[+] No correlated incidents detected."
        )

    else:
        for incident in incidents:
            compact_incident(
                incident,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)

    print(
        "Log findings are indicators "
        "and require investigation."
    )

    print("=" * WIDTH)
    print()


def print_incidents_dashboard(
    incidents: list[dict],
    verbose: bool = False,
) -> None:
    banner(
        "SENTINELCLAW INCIDENTS"
    )

    if not incidents:
        print()
        print(
            "[+] No correlated incidents detected."
        )

    else:
        section(
            "Correlated incidents"
        )

        for incident in incidents:
            compact_incident(
                incident,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)
    print()


def print_directory_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    """Render the summary dashboard for a directory scan (P4-23).

    A directory scan can touch up to ``max_dir_files`` files; the full
    per-file detail lives in the JSON output, while this dashboard
    shows the aggregate risk plus a per-file finding count table.
    """
    if "error" in report:
        banner(
            "SENTINELCLAW DIRECTORY ANALYSIS"
        )

        print()
        print(
            f"[ERROR] "
            f"{sanitize_terminal_text(report['error'])}"
        )
        print()
        return

    analysis = report.get(
        "analysis",
        {},
    )

    risk = report.get(
        "risk",
        {},
    )

    files = report.get(
        "files",
        [],
    )

    findings = report.get(
        "findings",
        [],
    )

    banner(
        "SENTINELCLAW DIRECTORY ANALYSIS"
    )

    section(
        "Directory"
    )

    status(
        "Path",
        report.get(
            "directory",
            "Unknown",
        ),
    )

    status(
        "Files scanned",
        analysis.get(
            "files_scanned",
            len(
                files
            ),
        ),
    )

    status(
        "Files with errors",
        analysis.get(
            "files_error_count",
            0,
        ),
    )

    status(
        "Truncated by cap",
        "yes"
        if analysis.get(
            "files_truncated"
        )
        else "no",
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    status(
        "Findings",
        len(
            findings
        ),
    )

    section(
        "Files"
    )

    if not files:
        print(
            "No files found in directory "
            "(or all files were skipped)."
        )

    else:
        for entry in files:
            file_info = entry.get(
                "file",
                {},
            )

            error = entry.get(
                "error"
            )

            file_findings = entry.get(
                "findings",
                [],
            )

            name = file_info.get(
                "name",
                entry.get(
                    "path",
                    "Unknown",
                ),
            )

            if error:
                print(
                    f"- {sanitize_terminal_text(name)}: "
                    f"[ERROR] {sanitize_terminal_text(error)}"
                )

            elif file_findings:
                severities = severity_counts(
                    file_findings
                )

                counts = " ".join(
                    f"{level}={count}"
                    for level, count
                    in severities.items()
                    if count
                )

                print(
                    f"- {sanitize_terminal_text(name)}: "
                    f"{len(file_findings)} finding(s) "
                    f"({counts})"
                )

            else:
                print(
                    f"- {sanitize_terminal_text(name)}: "
                    "no findings"
                )

    section(
        "Findings"
    )

    if not findings:
        print(
            "[+] No file indicators detected."
        )

    else:
        for finding in findings:
            compact_finding(
                finding,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)
    print()


def print_evtx_dashboard(
    report: dict,
    verbose: bool = False,
) -> None:
    """Render the summary dashboard for an offline EVTX analysis (P4-22)."""
    if "error" in report:
        banner(
            "SENTINELCLAW EVTX ANALYSIS"
        )

        print()
        print(
            f"[ERROR] "
            f"{sanitize_terminal_text(report['error'])}"
        )
        print()
        return

    evtx_data = report.get(
        "evtx",
        {},
    )

    risk = report.get(
        "risk",
        {},
    )

    findings = report.get(
        "findings",
        [],
    )

    incidents = report.get(
        "incidents",
        [],
    )

    banner(
        "SENTINELCLAW EVTX ANALYSIS"
    )

    section(
        "Event log"
    )

    status(
        "File",
        evtx_data.get(
            "name",
            "Unknown",
        ),
    )

    status(
        "Records",
        evtx_data.get(
            "records_total",
            0,
        ),
    )

    status(
        "Events parsed",
        evtx_data.get(
            "events_returned",
            0,
        ),
    )

    status(
        "Skipped records",
        evtx_data.get(
            "skipped_records",
            0,
        ),
    )

    truncated = evtx_data.get(
        "truncated"
    )

    status(
        "Truncated",
        (
            "yes"
            if truncated
            else "no"
        ),
    )

    section(
        "Risk"
    )

    status(
        "Overall",
        risk_label(
            risk.get(
                "score",
                0,
            ),
            risk.get(
                "level",
                "informational",
            ),
        ),
    )

    status(
        "Findings",
        len(
            findings
        ),
    )

    status(
        "Incidents",
        len(
            incidents
        ),
    )

    section(
        "Findings"
    )

    if not findings:
        print(
            "[+] No suspicious events detected."
        )

    else:
        for finding in findings:
            compact_finding(
                finding,
                verbose=verbose,
            )

    section(
        "Incidents"
    )

    if not incidents:
        print(
            "[+] No correlated incidents detected."
        )

    else:
        for incident in incidents:
            compact_incident(
                incident,
                verbose=verbose,
            )

    print()
    print("=" * WIDTH)
    print()
