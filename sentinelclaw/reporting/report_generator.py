from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinelclaw.config.constants import (
    REPORT_SCHEMA_VERSION,
    SEVERITY_RANK,
)
from sentinelclaw.config.paths import (
    ensure_private_directory,
    write_private_text,
)
from sentinelclaw.config.settings import get_settings


def _safe(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


# Characters that make spreadsheet applications treat a cell as a
# formula (CWE-1236). A leading quote forces text interpretation.
_CSV_FORMULA_PREFIXES = (
    "=",
    "+",
    "-",
    "@",
    "\t",
    "\r",
)


def _csv_safe(value: Any) -> str:
    """Return a CSV cell value that cannot be interpreted as a formula."""
    text = _safe(value)

    if text and text[0] in _CSV_FORMULA_PREFIXES:
        return "'" + text

    return text


def _severity_rank(severity: str) -> int:
    normalized = str(
        severity
    ).lower()

    if normalized == "informational":
        normalized = "info"

    return SEVERITY_RANK.get(
        normalized,
        0,
    )


def _get_findings(report: dict) -> list[dict]:
    findings = report.get("findings", {})

    if isinstance(findings, dict):
        result = findings.get("all", [])
        return result if isinstance(result, list) else []

    if isinstance(findings, list):
        return findings

    return []


def _finding_counts(findings: list[dict]) -> dict[str, int]:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "info")
        ).lower()

        if severity == "informational":
            severity = "info"

        if severity not in counts:
            severity = "info"

        counts[severity] += 1

    return counts


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda item: _severity_rank(
            item.get("severity", "info")
        ),
        reverse=True,
    )


def _get_incidents(report: dict) -> list[dict]:
    incidents = report.get("incidents", [])

    if not isinstance(
        incidents,
        list,
    ):
        return []

    return [
        incident
        for incident in incidents
        if isinstance(
            incident,
            dict,
        )
    ]


def _finding_timestamp(finding: dict) -> str:
    """Best-effort finding timestamp from the finding or its evidence."""
    value = finding.get("timestamp")

    if value:
        return str(value)

    evidence = finding.get("evidence")

    if isinstance(
        evidence,
        dict,
    ):
        value = (
            evidence.get("timestamp")
            or evidence.get("create_time")
        )

        if value:
            return str(value)

    return ""


def compute_mitre_coverage(
    findings: list[dict],
) -> dict[str, dict[str, int]]:
    """Map MITRE tactic to ``{technique: finding count}`` across findings.

    Findings carry MITRE data either as a dict (``tactic``/``technique``/
    ``name``) or, for older detectors, as a bare technique string. The
    result is ordered by first appearance so output stays deterministic.
    """
    coverage: dict[
        str,
        dict[str, int],
    ] = {}

    for finding in findings:
        mitre = finding.get("mitre")

        if isinstance(
            mitre,
            dict,
        ):
            tactic = str(
                mitre.get("tactic")
                or "Unmapped"
            )

            technique = str(
                mitre.get("technique")
                or "Unknown"
            )

        elif (
            isinstance(
                mitre,
                str,
            )
            and mitre.strip()
        ):
            tactic = "Unmapped"
            technique = mitre
        else:
            continue

        technique_counts = coverage.setdefault(
            tactic,
            {},
        )

        technique_counts[technique] = (
            technique_counts.get(
                technique,
                0,
            )
            + 1
        )

    return coverage


def build_executive_assessment(report: dict) -> dict:
    findings = _get_findings(report)
    incidents = report.get("incidents", [])
    risk = report.get("risk", {})
    collector_status = report.get("collector_status", {})

    counts = _finding_counts(findings)
    sorted_findings = _sorted_findings(findings)

    score = int(risk.get("score", 0) or 0)
    level = str(
        risk.get("level", "informational")
    ).lower()

    observations: list[str] = []
    recommendations: list[str] = []

    if counts["critical"]:
        observations.append(
            f"{counts['critical']} critical-severity "
            "finding(s) require immediate investigation."
        )

    if counts["high"]:
        observations.append(
            f"{counts['high']} high-severity finding(s) "
            "were detected."
        )

    if counts["medium"]:
        observations.append(
            f"{counts['medium']} medium-severity finding(s) "
            "require review."
        )

    if not counts["critical"] and not counts["high"]:
        observations.append(
            "No critical or high-severity findings were detected."
        )

    if incidents:
        observations.append(
            f"{len(incidents)} correlated security incident(s) "
            "were identified."
        )
    else:
        observations.append(
            "No correlated security incidents were identified."
        )

    failed_collectors = [
        name
        for name, error in collector_status.items()
        if error
    ]

    if failed_collectors:
        observations.append(
            "One or more collectors were unavailable, so scan "
            "coverage may be incomplete."
        )
    else:
        observations.append(
            "All configured collectors completed without "
            "recorded errors."
        )

    if level in {"critical", "high"}:
        assessment = (
            "SentinelClaw identified significant security "
            "indicators requiring prioritized investigation. "
            "The results should be validated against system "
            "context before any remediation decision is made."
        )

    elif level == "medium":
        assessment = (
            "SentinelClaw identified security indicators that "
            "warrant investigation. No conclusion of compromise "
            "should be made without validating the associated "
            "process, network, file, and event evidence."
        )

    elif level == "low":
        assessment = (
            "SentinelClaw identified a limited number of "
            "lower-risk security indicators. The current scan "
            "does not establish evidence of compromise, but the "
            "flagged activity should be reviewed for legitimacy."
        )

    else:
        assessment = (
            "SentinelClaw did not identify material security "
            "indicators during this scan. This does not guarantee "
            "that the system is free from malicious activity."
        )

    if sorted_findings:
        top = sorted_findings[0]

        recommendations.append(
            "Review the highest-priority finding: "
            f"{top.get('rule_id', 'Unknown')} - "
            f"{top.get('title', 'Unknown finding')}."
        )

    process_findings = [
        finding
        for finding in findings
        if str(
            finding.get("category", "")
        ).lower() == "process"
    ]

    network_findings = [
        finding
        for finding in findings
        if str(
            finding.get("category", "")
        ).lower() == "network"
    ]

    windows_findings = [
        finding
        for finding in findings
        if str(
            finding.get("category", "")
        ).lower() in {
            "windows",
            "windows_event",
            "windows_events",
        }
    ]

    file_findings = [
        finding
        for finding in findings
        if str(
            finding.get("category", "")
        ).lower() == "file"
    ]

    if process_findings:
        recommendations.append(
            "Validate flagged processes against their executable "
            "paths, command lines, parent processes, and expected "
            "user activity."
        )

    if network_findings:
        recommendations.append(
            "Review flagged network connections and verify that "
            "the destination addresses, ports, and owning "
            "processes are expected."
        )

    if windows_findings:
        recommendations.append(
            "Review the relevant Windows Security events and "
            "correlate them with user logons, process execution, "
            "and administrative activity."
        )

    if file_findings:
        recommendations.append(
            "Validate flagged files using their hashes, digital "
            "signatures, locations, metadata, and known source."
        )

    if incidents:
        recommendations.append(
            "Investigate correlated incidents before reviewing "
            "isolated findings because correlation may indicate "
            "a broader activity chain."
        )

    if failed_collectors:
        recommendations.append(
            "Restore unavailable collectors and repeat the scan "
            "before treating this assessment as complete."
        )

    recommendations.append(
        "Confirm suspicious indicators with additional evidence "
        "before containment, deletion, or other remediation."
    )

    return {
        "risk_score": score,
        "risk_level": level,
        "assessment": assessment,
        "observations": observations,
        "recommendations": recommendations,
    }


def generate_json_report(report: dict) -> str:
    export = dict(report)

    # P3-18/P3-20: the on-disk JSON report carries the schema version
    # and the MITRE coverage summary alongside the scan itself. The
    # ``run_scan`` dict is left untouched (its key set is frozen).
    export.setdefault(
        "schema_version",
        REPORT_SCHEMA_VERSION,
    )

    export["mitre_coverage"] = compute_mitre_coverage(
        _get_findings(report)
    )

    return json.dumps(
        export,
        indent=2,
        default=str,
    )


def _scan_metadata_line(report: dict) -> dict:
    """Build the first JSONL line: scan metadata + schema version."""
    return {
        "type": "scan",
        "schema_version": REPORT_SCHEMA_VERSION,
        "scan": report.get(
            "scan",
            {},
        ),
        "summary": report.get(
            "summary",
            {},
        ),
        "risk": report.get(
            "risk",
            {},
        ),
        "collector_status": report.get(
            "collector_status",
            {},
        ),
        "system": report.get(
            "system",
            {},
        ),
        "mitre_coverage": compute_mitre_coverage(
            _get_findings(report)
        ),
    }


def generate_jsonl_report(report: dict) -> str:
    """Emit one JSON object per line: scan, then findings, then incidents.

    Findings and incidents are top-level entities (one object per line)
    rather than nested under the scan metadata, so downstream parsers
    can stream them line by line.
    """
    lines = [
        json.dumps(
            _scan_metadata_line(report),
            ensure_ascii=False,
            default=str,
        )
    ]

    for finding in _get_findings(report):
        item = dict(finding)
        item["type"] = "finding"

        lines.append(
            json.dumps(
                item,
                ensure_ascii=False,
                default=str,
            )
        )

    for incident in _get_incidents(report):
        item = dict(incident)
        item["type"] = "incident"

        lines.append(
            json.dumps(
                item,
                ensure_ascii=False,
                default=str,
            )
        )

    return "\n".join(lines) + "\n"


FINDING_CSV_COLUMNS = (
    "id",
    "severity",
    "title",
    "category",
    "source",
    "mitre",
    "timestamp",
)

INCIDENT_CSV_COLUMNS = (
    "incident_id",
    "severity",
    "title",
    "confidence",
    "finding_count",
    "related_rule_ids",
)


def _finding_csv_id(finding: dict) -> str:
    return str(
        finding.get("rule_id")
        or finding.get("id")
        or ""
    )


def _finding_source(finding: dict) -> str:
    source = finding.get("source")

    if isinstance(
        source,
        list,
    ):
        return " ".join(
            str(item)
            for item in source
        )

    return _safe(source)


def _mitre_text(finding: dict) -> str:
    mitre = finding.get("mitre")

    if isinstance(
        mitre,
        dict,
    ):
        technique = mitre.get("technique")
        name = mitre.get("name")

        if technique and name:
            return f"{technique} {name}"

        if technique:
            return str(technique)

        return json.dumps(
            mitre,
            ensure_ascii=False,
            default=str,
        )

    return _safe(mitre)


def generate_csv_report(report: dict) -> str:
    """Render findings and incidents as two CSV tables in one document."""
    output = io.StringIO()

    findings_writer = csv.DictWriter(
        output,
        fieldnames=FINDING_CSV_COLUMNS,
    )

    findings_writer.writeheader()

    for finding in _sorted_findings(
        _get_findings(report)
    ):
        findings_writer.writerow(
            {
                "id": _csv_safe(
                    _finding_csv_id(finding)
                ),
                "severity": _csv_safe(
                    finding.get("severity")
                ),
                "title": _csv_safe(
                    finding.get("title")
                ),
                "category": _csv_safe(
                    finding.get("category")
                ),
                "source": _csv_safe(
                    _finding_source(finding)
                ),
                "mitre": _csv_safe(
                    _mitre_text(finding)
                ),
                "timestamp": _csv_safe(
                    _finding_timestamp(
                        finding
                    )
                ),
            }
        )

    output.write("\n")

    incidents_writer = csv.DictWriter(
        output,
        fieldnames=INCIDENT_CSV_COLUMNS,
    )

    incidents_writer.writeheader()

    for incident in _get_incidents(report):
        incidents_writer.writerow(
            {
                "incident_id": _csv_safe(
                    incident.get("incident_id")
                ),
                "severity": _csv_safe(
                    incident.get("severity")
                ),
                "title": _csv_safe(
                    incident.get("title")
                ),
                "confidence": _csv_safe(
                    incident.get("confidence")
                ),
                "finding_count": _csv_safe(
                    incident.get("finding_count")
                ),
                "related_rule_ids": _csv_safe(
                    " ".join(
                        str(item)
                        for item in (
                            incident.get("related_rule_ids")
                            or []
                        )
                    )
                ),
            }
        )

    return output.getvalue()


def generate_text_report(report: dict) -> str:
    findings = _get_findings(report)
    findings = _sorted_findings(findings)

    max_findings = max(
        1,
        int(get_settings().report_max_findings),
    )

    mitre_coverage = compute_mitre_coverage(
        findings
    )

    incidents = report.get("incidents", [])
    timeline = report.get("timeline", [])
    summary = report.get("summary", {})
    risk = report.get("risk", {})
    system = report.get("system", {})
    collector_status = report.get("collector_status", {})

    counts = _finding_counts(findings)
    executive = build_executive_assessment(report)

    lines: list[str] = []

    lines.append("=" * 80)
    lines.append("SENTINELCLAW SECURITY ASSESSMENT")
    lines.append("=" * 80)
    lines.append("")

    lines.append("SCAN OVERVIEW")
    lines.append("-" * 80)

    lines.append(
        "Application       : "
        + _safe(
            report.get(
                "scan", {}
            ).get(
                "application",
                "SentinelClaw",
            )
        )
    )

    lines.append(
        "Scan Timestamp    : "
        + _safe(
            report.get(
                "scan", {}
            ).get(
                "timestamp",
                "Unknown",
            )
        )
    )

    lines.append(
        f"Risk Score        : {risk.get('score', 0)}/100"
    )

    lines.append(
        "Risk Level        : "
        + str(
            risk.get(
                "level",
                "informational",
            )
        ).upper()
    )

    lines.append(
        f"Rules Loaded      : {summary.get('rules_loaded', 0)}"
    )

    lines.append(
        "Processes Scanned : "
        f"{summary.get('processes_scanned', 0)}"
    )

    lines.append(
        "Connections       : "
        f"{summary.get('network_connections_scanned', 0)}"
    )

    lines.append(
        "Windows Events    : "
        f"{summary.get('windows_events_scanned', 0)}"
    )

    lines.append("")
    lines.append("EXECUTIVE ASSESSMENT")
    lines.append("-" * 80)
    lines.append(executive["assessment"])

    lines.append("")
    lines.append("Key Observations")

    for observation in executive["observations"]:
        lines.append(
            f"- {observation}"
        )

    lines.append("")
    lines.append("Prioritized Investigation")

    for index, recommendation in enumerate(
        executive["recommendations"],
        start=1,
    ):
        lines.append(
            f"{index}. {recommendation}"
        )

    lines.append("")
    lines.append("FINDING STATISTICS")
    lines.append("-" * 80)

    lines.append(
        f"Total Findings    : {len(findings)}"
    )

    lines.append(
        f"Critical          : {counts['critical']}"
    )

    lines.append(
        f"High              : {counts['high']}"
    )

    lines.append(
        f"Medium            : {counts['medium']}"
    )

    lines.append(
        f"Low               : {counts['low']}"
    )

    lines.append(
        f"Informational     : {counts['info']}"
    )

    lines.append(
        f"Incidents         : {len(incidents)}"
    )

    lines.append("")
    lines.append("MITRE ATT&CK COVERAGE")
    lines.append("-" * 80)

    if not mitre_coverage:
        lines.append(
            "No MITRE mappings in findings."
        )
    else:
        for tactic in mitre_coverage:
            lines.append(
                f"Tactic: {tactic}"
            )

            for technique, count in sorted(
                mitre_coverage[tactic].items()
            ):
                lines.append(
                    f"  {technique}: {count} finding(s)"
                )

    lines.append("")
    lines.append("SYSTEM INFORMATION")
    lines.append("-" * 80)

    if system:
        for key, value in system.items():
            lines.append(
                f"{key:<22}: {_safe(value)}"
            )
    else:
        lines.append(
            "System information unavailable."
        )

    lines.append("")
    lines.append("SECURITY FINDINGS")
    lines.append("-" * 80)

    if not findings:
        lines.append(
            "No findings detected."
        )

    for index, finding in enumerate(
        findings[:max_findings],
        start=1,
    ):
        lines.append("")

        lines.append(
            f"[{index}] "
            f"{finding.get('title', 'Unknown Finding')}"
        )

        lines.append(
            "Severity   : "
            + str(
                finding.get(
                    "severity",
                    "info",
                )
            ).upper()
        )

        lines.append(
            "Rule ID    : "
            + _safe(
                finding.get(
                    "rule_id",
                    "Unknown",
                )
            )
        )

        lines.append(
            "Category   : "
            + _safe(
                finding.get(
                    "category",
                    "Unknown",
                )
            )
        )

        lines.append(
            "Confidence : "
            + _safe(
                finding.get(
                    "confidence",
                    "Unknown",
                )
            )
        )

        rule_source = finding.get(
            "rule_source"
        )

        if rule_source:
            lines.append(
                "Rule Source : "
                + _safe(rule_source)
            )

        rule_status = finding.get(
            "rule_status"
        )

        if rule_status:
            lines.append(
                "Rule Status : "
                + _safe(rule_status)
            )

        description = (
            finding.get("description")
            or finding.get("reason")
        )

        if description:
            lines.append(
                "Description: "
                + _safe(description)
            )

        mitre = finding.get("mitre")

        if mitre:
            lines.append(
                "MITRE      : "
                + _safe(mitre)
            )

        evidence = finding.get("evidence")

        if evidence:
            lines.append(
                "Evidence    : "
                + json.dumps(
                    evidence,
                    ensure_ascii=False,
                    default=str,
                )
            )

    if len(findings) > max_findings:
        lines.append("")

        lines.append(
            f"... {len(findings) - max_findings} more "
            "finding(s) not shown "
            "(report_max_findings cap)."
        )

    lines.append("")
    lines.append("CORRELATED INCIDENTS")
    lines.append("-" * 80)

    if not incidents:
        lines.append(
            "No correlated incidents detected."
        )

    for index, incident in enumerate(
        incidents[:max_findings],
        start=1,
    ):
        lines.append("")

        lines.append(
            f"[{index}] "
            f"{incident.get('title', 'Unknown Incident')}"
        )

        lines.append(
            "Incident ID : "
            + _safe(
                incident.get(
                    "incident_id",
                    "Unknown",
                )
            )
        )

        lines.append(
            "Severity    : "
            + str(
                incident.get(
                    "severity",
                    "info",
                )
            ).upper()
        )

        lines.append(
            "Confidence  : "
            + _safe(
                incident.get(
                    "confidence",
                    "Unknown",
                )
            )
        )

    if len(incidents) > max_findings:
        lines.append("")

        lines.append(
            f"... {len(incidents) - max_findings} more "
            "incident(s) not shown "
            "(report_max_findings cap)."
        )

    lines.append("")
    lines.append("INVESTIGATION TIMELINE")
    lines.append("-" * 80)

    if not timeline:
        lines.append(
            "No timeline events available."
        )

    for event in timeline:
        lines.append(
            f"{event.get('timestamp', 'TIME UNKNOWN')} | "
            f"{str(event.get('severity', 'info')).upper()} | "
            f"{event.get('title', 'Unknown Event')}"
        )

    lines.append("")
    lines.append("COLLECTOR STATUS")
    lines.append("-" * 80)

    collector_errors = False

    for key, value in collector_status.items():
        if value:
            collector_errors = True
            lines.append(
                f"{key}: {value}"
            )

    if not collector_errors:
        lines.append(
            "All collectors completed without recorded errors."
        )

    lines.append("")
    lines.append("METHODOLOGY AND LIMITATIONS")
    lines.append("-" * 80)

    lines.append(
        "SentinelClaw uses local deterministic collection, "
        "rule-based detection, normalization, correlation, "
        "risk scoring, and timeline analysis."
    )

    lines.append(
        "A finding represents a security indicator and does "
        "not by itself prove malware infection or compromise."
    )

    lines.append(
        "Optional local AI analysis is advisory and is not "
        "required for SentinelClaw detection."
    )

    lines.append("")
    lines.append("=" * 80)

    return "\n".join(lines)


def generate_html_report(report: dict) -> str:
    findings = _sorted_findings(
        _get_findings(report)
    )

    incidents = report.get("incidents", [])
    timeline = report.get("timeline", [])
    summary = report.get("summary", {})
    risk = report.get("risk", {})
    system = report.get("system", {})
    collector_status = report.get("collector_status", {})

    counts = _finding_counts(findings)
    executive = build_executive_assessment(report)

    mitre_coverage = compute_mitre_coverage(
        findings
    )

    def esc(value: Any) -> str:
        return html.escape(
            _safe(value)
        )

    observation_html = "".join(
        f"<li>{esc(item)}</li>"
        for item in executive["observations"]
    )

    recommendation_html = "".join(
        f"<li>{esc(item)}</li>"
        for item in executive["recommendations"]
    )

    finding_rows: list[str] = []

    for finding in findings:
        evidence = finding.get("evidence")

        evidence_text = (
            json.dumps(
                evidence,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
            if evidence
            else ""
        )

        provenance = ""

        rule_source = finding.get(
            "rule_source"
        )

        if rule_source:
            provenance += (
                '<div class="small">'
                + esc(rule_source)
                + "</div>"
            )

        rule_status = finding.get(
            "rule_status"
        )

        if rule_status:
            provenance += (
                '<div class="small">status: '
                + esc(rule_status)
                + "</div>"
            )

        finding_rows.append(
            f"""
            <tr>
                <td>
                    {esc(finding.get("rule_id", "Unknown"))}
                    {provenance}
                </td>
                <td>
                    <span class="severity {esc(str(finding.get("severity", "info")).lower())}">
                        {esc(str(finding.get("severity", "info")).upper())}
                    </span>
                </td>
                <td>{esc(finding.get("title", "Unknown Finding"))}</td>
                <td>{esc(finding.get("confidence", "Unknown"))}</td>
                <td>{esc(finding.get("mitre", ""))}</td>
                <td><pre>{esc(evidence_text)}</pre></td>
            </tr>
            """
        )

    incident_drilldown: list[str] = []

    for incident in incidents:
        incident_id = esc(
            incident.get(
                "incident_id",
                "Unknown",
            )
        )

        member_rows = "".join(
            (
                "<tr>"
                f"<td>{esc(finding.get('rule_id', 'Unknown'))}</td>"
                f"<td>{esc(str(finding.get('severity', 'info')).upper())}</td>"
                f"<td>{esc(finding.get('title', 'Unknown'))}</td>"
                f"<td>{esc(finding.get('rule_status', ''))}</td>"
                "</tr>"
            )
            for finding in incident.get(
                "findings",
                [],
            )
            if isinstance(
                finding,
                dict,
            )
        )

        incident_events = [
            event
            for event in timeline
            if str(
                event.get("incident_id")
            ) == str(
                incident.get("incident_id")
            )
        ]

        event_rows = "".join(
            (
                "<tr>"
                f"<td>{esc(event.get('timestamp', ''))}</td>"
                f"<td>{esc(event.get('title', ''))}</td>"
                "</tr>"
            )
            for event in incident_events
        )

        incident_drilldown.append(
            f"""
            <details class="incident">
                <summary>
                    {esc(incident.get('title', 'Unknown Incident'))}
                    <span class="severity {esc(str(incident.get('severity', 'info')).lower())}">
                        {esc(str(incident.get('severity', 'info')).upper())}
                    </span>
                </summary>
                <div class="small">
                    Incident {incident_id} |
                    Confidence: {esc(incident.get('confidence', 'Unknown'))}
                </div>
                <table>
                    <tr><th>Rule</th><th>Severity</th><th>Finding</th><th>Status</th></tr>
                    {member_rows or '<tr><td colspan="4">No member findings recorded.</td></tr>'}
                </table>
                <h4>Timeline events for this incident</h4>
                <table>
                    <tr><th>Timestamp</th><th>Event</th></tr>
                    {event_rows or '<tr><td colspan="2">No timeline events recorded.</td></tr>'}
                </table>
            </details>
            """
        )

    mitre_rows = "".join(
        (
            "<tr>"
            f"<td>{esc(tactic)}</td>"
            f"<td>{esc(technique)}</td>"
            f"<td>{count}</td>"
            "</tr>"
        )
        for tactic, techniques in mitre_coverage.items()
        for technique, count in sorted(
            techniques.items()
        )
    )

    timeline_rows: list[str] = []

    for event in timeline:
        timeline_rows.append(
            f"""
            <tr>
                <td>{esc(event.get("timestamp", "TIME UNKNOWN"))}</td>
                <td>{esc(str(event.get("severity", "info")).upper())}</td>
                <td>{esc(event.get("event_type", "event"))}</td>
                <td>{esc(event.get("title", "Unknown Event"))}</td>
            </tr>
            """
        )

    system_rows = "".join(
        f"<tr><td>{esc(key)}</td><td>{esc(value)}</td></tr>"
        for key, value in system.items()
    )

    collector_rows = "".join(
        (
            f"<tr><td>{esc(key)}</td>"
            f"<td>{esc(value or 'OK')}</td></tr>"
        )
        for key, value in collector_status.items()
    )

    scan_timestamp = (
        report.get(
            "scan",
            {},
        ).get(
            "timestamp",
            "Unknown",
        )
    )

    generated_timestamp = (
        datetime.now()
        .astimezone()
        .isoformat()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelClaw Security Assessment</title>

<style>
body {{
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #0b1020;
    color: #e5e7eb;
}}

.container {{
    width: 92%;
    max-width: 1400px;
    margin: 30px auto;
}}

.card {{
    background: #111827;
    border: 1px solid #263244;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 18px;
}}

h1, h2, h3 {{
    margin-top: 0;
}}

.small {{
    color: #9ca3af;
    font-size: 0.9rem;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(
        auto-fit,
        minmax(160px, 1fr)
    );
    gap: 12px;
}}

.metric {{
    background: #182235;
    border-radius: 8px;
    padding: 15px;
}}

.metric strong {{
    display: block;
    margin-top: 6px;
    font-size: 1.5rem;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}}

th,
td {{
    border-bottom: 1px solid #2d3748;
    padding: 10px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #182235;
}}

pre {{
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
    font-size: 0.82rem;
}}

.severity {{
    font-weight: bold;
}}

.critical {{
    color: #ff6b6b;
}}

.high {{
    color: #ff9f43;
}}

.medium {{
    color: #feca57;
}}

.low {{
    color: #54a0ff;
}}

.info,
.informational {{
    color: #c8d6e5;
}}

.assessment {{
    font-size: 1.05rem;
    line-height: 1.6;
}}

li {{
    margin-bottom: 8px;
}}

.footer {{
    color: #9ca3af;
    font-size: 0.85rem;
    margin: 25px 0;
}}
</style>
</head>

<body>

<div class="container">

<div class="card">
    <h1>SentinelClaw Security Assessment</h1>

    <div class="small">
        Scan: {esc(scan_timestamp)}
        <br>
        Report generated: {esc(generated_timestamp)}
    </div>
</div>

<div class="card">
    <h2>Risk Overview</h2>

    <div class="grid">
        <div class="metric">
            Risk Score
            <strong>{esc(risk.get("score", 0))}/100</strong>
        </div>

        <div class="metric">
            Risk Level
            <strong>{esc(str(risk.get("level", "informational")).upper())}</strong>
        </div>

        <div class="metric">
            Findings
            <strong>{len(findings)}</strong>
        </div>

        <div class="metric">
            Incidents
            <strong>{len(incidents)}</strong>
        </div>
    </div>
</div>

<div class="card">
    <h2>Executive Assessment</h2>

    <p class="assessment">
        {esc(executive["assessment"])}
    </p>

    <h3>Key Observations</h3>
    <ul>
        {observation_html}
    </ul>

    <h3>Prioritized Investigation</h3>
    <ol>
        {recommendation_html}
    </ol>
</div>

<div class="card">
    <h2>Finding Statistics</h2>

    <div class="grid">
        <div class="metric">
            Critical
            <strong>{counts["critical"]}</strong>
        </div>

        <div class="metric">
            High
            <strong>{counts["high"]}</strong>
        </div>

        <div class="metric">
            Medium
            <strong>{counts["medium"]}</strong>
        </div>

        <div class="metric">
            Low
            <strong>{counts["low"]}</strong>
        </div>

        <div class="metric">
            Informational
            <strong>{counts["info"]}</strong>
        </div>
    </div>
</div>

<div class="card">
    <h2>MITRE ATT&amp;CK Coverage</h2>

    <table>
        <tr>
            <th>Tactic</th>
            <th>Technique</th>
            <th>Findings</th>
        </tr>

        {
            mitre_rows
            if mitre_rows
            else '<tr><td colspan="3">No MITRE mappings in findings.</td></tr>'
        }
    </table>
</div>

<div class="card">
    <h2>Scan Statistics</h2>

    <table>
        <tr>
            <th>Metric</th>
            <th>Value</th>
        </tr>

        <tr>
            <td>Rules Loaded</td>
            <td>{summary.get("rules_loaded", 0)}</td>
        </tr>

        <tr>
            <td>Processes Scanned</td>
            <td>{summary.get("processes_scanned", 0)}</td>
        </tr>

        <tr>
            <td>Network Connections</td>
            <td>{summary.get("network_connections_scanned", 0)}</td>
        </tr>

        <tr>
            <td>Windows Events</td>
            <td>{summary.get("windows_events_scanned", 0)}</td>
        </tr>

        <tr>
            <td>Timeline Events</td>
            <td>{summary.get("timeline_events", 0)}</td>
        </tr>
    </table>
</div>

<div class="card">
    <h2>System Information</h2>

    <table>
        <tr>
            <th>Field</th>
            <th>Value</th>
        </tr>

        {system_rows}
    </table>
</div>

<div class="card">
    <h2>Security Findings</h2>

    <table>
        <tr>
            <th>Rule</th>
            <th>Severity</th>
            <th>Finding</th>
            <th>Confidence</th>
            <th>MITRE ATT&amp;CK</th>
            <th>Evidence</th>
        </tr>

        {
            "".join(finding_rows)
            if finding_rows
            else '<tr><td colspan="6">No findings detected.</td></tr>'
        }
    </table>
</div>

<div class="card">
    <h2>Incident Drill-down</h2>

    {
        "".join(incident_drilldown)
        if incident_drilldown
        else '<p class="small">No correlated incidents detected.</p>'
    }
</div>

<div class="card">
    <h2>Investigation Timeline</h2>

    <table>
        <tr>
            <th>Timestamp</th>
            <th>Severity</th>
            <th>Type</th>
            <th>Event</th>
        </tr>

        {
            "".join(timeline_rows)
            if timeline_rows
            else '<tr><td colspan="4">No timeline events available.</td></tr>'
        }
    </table>
</div>

<div class="card">
    <h2>Collector Status</h2>

    <table>
        <tr>
            <th>Collector</th>
            <th>Status</th>
        </tr>

        {collector_rows}
    </table>
</div>

<div class="card">
    <h2>Methodology &amp; Limitations</h2>

    <p>
        SentinelClaw performs local deterministic security
        collection, rule-based detection, normalization,
        correlation, risk scoring, and timeline construction.
    </p>

    <p>
        Findings represent security indicators requiring
        investigation and do not independently prove compromise.
    </p>

    <p>
        Optional local AI analysis is advisory and is not required
        for SentinelClaw detection.
    </p>
</div>

<div class="footer">
    Generated locally by SentinelClaw.
</div>

</div>

</body>
</html>
"""


def save_report_formats(
    report: dict,
    output_directory: str | Path = "reports",
    formats: tuple[str, ...] = (
        "json",
        "text",
        "html",
    ),
) -> dict[str, Path]:
    output_path = Path(
        output_directory
    )

    ensure_private_directory(
        output_path
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    created: dict[str, Path] = {}

    if "json" in formats:
        path = (
            output_path
            / f"sentinelclaw_{timestamp}.json"
        )

        write_private_text(
            path,
            generate_json_report(report),
        )

        created["json"] = path

    if "text" in formats:
        path = (
            output_path
            / f"sentinelclaw_{timestamp}.txt"
        )

        write_private_text(
            path,
            generate_text_report(report),
        )

        created["text"] = path

    if "html" in formats:
        path = (
            output_path
            / f"sentinelclaw_{timestamp}.html"
        )

        write_private_text(
            path,
            generate_html_report(report),
        )

        created["html"] = path

    if "csv" in formats:
        path = (
            output_path
            / f"sentinelclaw_{timestamp}.csv"
        )

        write_private_text(
            path,
            generate_csv_report(report),
        )

        created["csv"] = path

    if "jsonl" in formats:
        path = (
            output_path
            / f"sentinelclaw_{timestamp}.jsonl"
        )

        write_private_text(
            path,
            generate_jsonl_report(report),
        )

        created["jsonl"] = path

    return created
