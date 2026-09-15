"""Shared scan-pipeline machinery for the command modules (P6-30).

Holds the ``run_*`` scan entry points (host scan, file, directory,
EVTX, PCAP, log) plus their per-file helpers. Collectors and the
process detector are resolved through the ``sentinelclaw.main``
namespace at call time so runtime overrides applied there (e.g. test
monkeypatching) keep working after the P6-30 extraction.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

from sentinelclaw.config.settings import get_settings

from sentinelclaw.commands.rules import get_rules

from sentinelclaw.detectors.auth_detector import analyze_auth_events
from sentinelclaw.detectors.file_detector import analyze_file_findings
from sentinelclaw.detectors.log_detector import (
    analyze_log_events,
    analyze_windows_events,
)
from sentinelclaw.detectors.network_detector import analyze_network
from sentinelclaw.detectors.pcap_detector import analyze_pcap_findings
from sentinelclaw.detectors.persistence_detector import (
    analyze_persistence_records,
)

from sentinelclaw.engine.correlation_engine import correlate_findings
from sentinelclaw.engine.finding_processor import process_findings
from sentinelclaw.engine.rule_engine import (
    run_rules,
)
from sentinelclaw.engine.timeline_engine import build_timeline

from sentinelclaw.models.risk import (
    calculate_overall_risk,
    calculate_risk_score,
)

from sentinelclaw.tools.evtx_analyzer import analyze_evtx
from sentinelclaw.tools.file_analyzer import analyze_file
from sentinelclaw.tools.intel_loader import (
    check_collected_values,
    connection_remote_ips,
    load_intel_bundle,
)
from sentinelclaw.tools.log_analyzer import analyze_log_file

from sentinelclaw.ui.progress import ScanProgress


logger = logging.getLogger(__name__)


def add_source(
    findings: list[dict],
    source: str,
) -> list[dict]:
    result = []

    for finding in findings:
        item = dict(finding)
        item["source"] = source
        result.append(item)

    return result


def run_scan(
    show_progress: bool = False,
    include_raw: bool = False,
) -> dict:
    from sentinelclaw import main as cli

    progress = ScanProgress(
        enabled=show_progress,
        total_steps=6,
    )

    scan_timestamp = datetime.now().astimezone().isoformat()

    collector_status: dict[str, str | None] = {
        "process_error": None,
        "network_error": None,
        "windows_event_error": None,
        "system_info_error": None,
    }

    progress.step("Collecting running processes...")

    try:
        processes = cli.get_processes()
    except Exception as exc:
        processes = []
        collector_status["process_error"] = str(exc)

        logger.warning(
            "Process collection failed: %s",
            exc,
        )

        progress.warning("Process collection failed. Continuing with remaining collectors.")

    progress.step("Collecting network connections...")

    try:
        network = cli.get_network_connections()
    except Exception as exc:
        network = []
        collector_status["network_error"] = str(exc)

        logger.warning(
            "Network collection failed: %s",
            exc,
        )

        progress.warning("Network collection failed. Continuing with remaining collectors.")

    progress.step("Reading Windows Security events...")

    try:
        windows_events = cli.get_windows_events(
            log_name="Security",
            max_events=get_settings().max_windows_events,
        )
    except Exception as exc:
        windows_events = []
        collector_status["windows_event_error"] = str(exc)

        logger.warning(
            "Windows Security event collection failed: %s",
            exc,
        )

        progress.warning(
            "Windows Security events are unavailable. "
            "Run the terminal as Administrator "
            "for Security log access."
        )

    auth_events: list[dict] = []
    persistence_records: list[dict] = []

    if sys.platform.startswith("linux"):
        try:
            auth_events = cli.get_auth_events()
        except Exception as exc:
            auth_events = []

            logger.warning(
                "Auth log collection failed: %s",
                exc,
            )

        try:
            persistence_records = cli.get_persistence_records()
        except Exception as exc:
            persistence_records = []

            logger.warning(
                "Persistence collection failed: %s",
                exc,
            )

    progress.step("Running detection rules...")

    rules = get_rules()

    built_in_process_findings = add_source(
        cli.analyze_processes(processes),
        "builtin",
    )

    built_in_network_findings = add_source(
        analyze_network(network),
        "builtin",
    )

    built_in_windows_findings = add_source(
        analyze_windows_events(windows_events),
        "builtin",
    )

    built_in_auth_findings = add_source(
        analyze_auth_events(auth_events),
        "builtin",
    )

    built_in_persistence_findings = add_source(
        analyze_persistence_records(persistence_records),
        "builtin",
    )

    yaml_process_findings = add_source(
        run_rules(
            rules,
            processes,
            category="process",
        ),
        "yaml",
    )

    yaml_windows_findings = add_source(
        run_rules(
            rules,
            windows_events,
            category="windows_event",
        ),
        "yaml",
    )

    yaml_auth_findings = add_source(
        run_rules(
            rules,
            auth_events,
            category="auth",
        ),
        "yaml",
    )

    yaml_persistence_findings = add_source(
        run_rules(
            rules,
            persistence_records,
            category="persistence",
        ),
        "yaml",
    )

    process_results = process_findings(built_in_process_findings + yaml_process_findings)

    network_results = process_findings(built_in_network_findings)

    windows_results = process_findings(built_in_windows_findings + yaml_windows_findings)

    auth_results = process_findings(built_in_auth_findings + yaml_auth_findings)

    persistence_results = process_findings(
        built_in_persistence_findings + yaml_persistence_findings
    )

    # P4-25: offline threat-intel matching. Only runs when the
    # ``intel_bundle_path`` setting names a local STIX/OpenIOC
    # bundle; the scan data available here is network connections
    # (IPs only -- no file hashes or DNS names are collected by
    # ``run_scan``), so only IP indicators can fire. A malformed
    # bundle is an operational warning, never a scan failure.
    intel_results: list[dict] = []

    intel_bundle_path = get_settings().intel_bundle_path

    if intel_bundle_path is not None:
        intel_bundle = load_intel_bundle(str(intel_bundle_path))

        if "error" in intel_bundle:
            logger.warning(
                "Threat-intel bundle skipped: %s",
                intel_bundle["error"],
            )
        else:
            intel_results = add_source(
                check_collected_values(
                    intel_bundle,
                    ips=connection_remote_ips(network),
                ),
                "intel",
            )

    all_findings = process_findings(
        process_results
        + network_results
        + windows_results
        + auth_results
        + persistence_results
        + intel_results
    )

    progress.step("Correlating security incidents...")

    incidents = correlate_findings(all_findings)

    progress.step("Building investigation timeline...")

    timeline = build_timeline(
        findings=all_findings,
        incidents=incidents,
        scan_timestamp=scan_timestamp,
    )

    risk = calculate_overall_risk(
        all_findings,
        incidents,
    )

    try:
        system_info = cli.get_system_info()
    except Exception as exc:
        system_info = {}
        collector_status["system_info_error"] = str(exc)

        logger.warning(
            "System information collection failed: %s",
            exc,
        )

        progress.warning("System information collection failed.")

    progress.complete()

    result = {
        "scan": {
            "application": "SentinelClaw",
            "timestamp": scan_timestamp,
        },
        "risk": risk,
        "summary": {
            "rules_loaded": len(rules),
            "processes_scanned": len(processes),
            "network_connections_scanned": len(network),
            "windows_events_scanned": len(windows_events),
            "auth_events_scanned": len(auth_events),
            "persistence_records_scanned": len(persistence_records),
            "process_findings": len(process_results),
            "network_findings": len(network_results),
            "windows_findings": len(windows_results),
            "auth_findings": len(auth_results),
            "persistence_findings": len(persistence_results),
            "total_findings": len(all_findings),
            "incidents": len(incidents),
            "timeline_events": len(timeline),
        },
        "findings": {
            "processes": process_results,
            "network": network_results,
            "windows_events": windows_results,
            "auth": auth_results,
            "persistence": persistence_results,
            "all": all_findings,
        },
        "incidents": incidents,
        "timeline": timeline,
        "collector_status": collector_status,
        "system": system_info,
    }

    if include_raw:
        result["processes"] = processes
        result["network"] = network
        result["windows_events"] = windows_events

    return result


def yara_findings_for_file(
    file_path: str,
) -> tuple[list[dict], dict]:
    """Run the optional YARA scan for one file.

    Returns ``(findings, result)`` where ``result`` is the operational
    scanner result (see ``sentinelclaw.tools.yara_scanner``). Each
    matched rule becomes one ``YARA-001`` finding whose severity comes
    from the rule's metadata (medium default). Missing yara-python or
    an empty rules directory yields an operational note, never a
    finding and never an error.
    """
    from sentinelclaw.tools.yara_scanner import (
        scan_file_result,
    )

    result = scan_file_result(file_path)

    findings = []

    for match in result.get(
        "matches",
        [],
    ):
        findings.append(
            {
                "severity": match.get(
                    "severity",
                    "medium",
                ),
                "rule_id": "YARA-001",
                "title": (f"YARA rule matched: {match.get('rule')}"),
                "description": ("The file content matched a configured YARA rule."),
                "category": "file",
                "confidence": "medium",
                "evidence": {
                    "rule": match.get("rule"),
                    "namespace": match.get("namespace"),
                    "severity": match.get(
                        "severity",
                        "medium",
                    ),
                    "path": result.get("path"),
                },
                "mitre": {
                    "technique": "T1204.002",
                    "name": "Malicious File",
                    "tactic": "Execution",
                },
            }
        )

    return (
        findings,
        result,
    )


def analyze_file_with_detections(
    path: Path,
    rules: list[dict],
) -> dict:
    """Run the full per-file pipeline (P4-23).

    File analysis plus built-in/YAML/YARA detections for one file.
    Returns an entry dict consumed by the single-file and
    directory-scan report builders; failures are captured per entry
    instead of aborting the batch.
    """
    entry: dict = {
        "path": str(path),
    }

    try:
        file_info = analyze_file(str(path))
    except PermissionError as exc:
        entry["error"] = f"Permission denied while reading file: {exc}"

        return entry
    except Exception as exc:
        entry["error"] = f"Unable to analyze file: {exc}"

        return entry

    entry["file"] = file_info

    if "error" in file_info:
        entry["error"] = file_info["error"]

        return entry

    try:
        built_in_findings = add_source(
            analyze_file_findings(file_info),
            "builtin",
        )

        yaml_findings = add_source(
            run_rules(
                rules,
                [file_info],
                category="file",
            ),
            "yaml",
        )

        yara_findings, yara_result = yara_findings_for_file(str(path))

        yara_sourced = add_source(
            yara_findings,
            "yara",
        )

        findings = process_findings(built_in_findings + yaml_findings + yara_sourced)
    except Exception as exc:
        entry["error"] = f"File detection failed: {exc}"

        entry["findings"] = []

        return entry

    entry["findings"] = findings
    entry["yara"] = yara_result
    entry["yara_matches"] = [
        match.get("rule")
        for match in yara_result.get(
            "matches",
            [],
        )
    ]

    return entry


def run_file_scan(
    file_path: str,
) -> dict:
    path = Path(file_path)

    if not path.exists():
        return {"error": (f"File does not exist: {path}")}

    if path.is_dir():
        return run_directory_scan(file_path)

    if not path.is_file():
        return {"error": (f"Path is not a file: {path}")}

    try:
        rules = get_rules()
    except Exception as exc:
        return {"error": (f"Unable to load detection rules: {exc}")}

    entry = analyze_file_with_detections(
        path,
        rules,
    )

    if "error" in entry:
        return {"error": entry["error"]}

    findings = entry.get(
        "findings",
        [],
    )

    return {
        "analysis": {
            "application": "SentinelClaw",
            "timestamp": (datetime.now().astimezone().isoformat()),
            "type": "file",
        },
        "rules_loaded": len(rules),
        "risk": calculate_risk_score(findings),
        "file": entry["file"],
        "yara": entry.get(
            "yara",
            {},
        ),
        "findings": findings,
    }


def run_directory_scan(
    directory_path: str,
) -> dict:
    """Scan up to ``max_dir_files`` files inside a directory.

    P4-23: each regular file (sorted by name for determinism) is
    analyzed and scored with the same built-in/YAML/YARA detection
    pipeline as the single-file command. Files past the cap are
    reported via ``files_truncated``; per-file failures are collected
    in the ``files`` entries instead of aborting the scan.
    """
    directory = Path(directory_path)

    try:
        candidates = sorted(item for item in directory.iterdir() if item.is_file())
    except PermissionError:
        return {"error": (f"Permission denied while listing directory: {directory}")}
    except OSError as exc:
        return {"error": (f"Unable to list directory: {exc}")}

    try:
        rules = get_rules()
    except Exception as exc:
        return {"error": (f"Unable to load detection rules: {exc}")}

    max_files = get_settings().max_dir_files

    truncated = len(candidates) > max_files

    targets = candidates[:max_files]

    from sentinelclaw.tools.yara_scanner import (
        directory_status,
    )

    yara_status = directory_status()

    entries: list[dict] = []
    all_findings: list[dict] = []
    error_count = 0

    for target in targets:
        entry = analyze_file_with_detections(
            target,
            rules,
        )

        if "error" in entry:
            error_count += 1
        else:
            all_findings.extend(
                entry.get(
                    "findings",
                    [],
                )
            )

        entries.append(entry)

    processed = process_findings(all_findings)

    return {
        "analysis": {
            "application": "SentinelClaw",
            "timestamp": (datetime.now().astimezone().isoformat()),
            "type": "directory",
            "total_files_found": len(candidates),
            "files_scanned": len(targets),
            "files_truncated": truncated,
            "files_error_count": error_count,
        },
        "directory": str(directory.resolve()),
        "rules_loaded": len(rules),
        "risk": calculate_risk_score(processed),
        "yara": yara_status,
        "files": entries,
        "findings": processed,
    }


def run_evtx_scan(
    file_path: str,
) -> dict:
    """Offline Windows Event Log analysis (P4-22).

    ``windows-events <path.evtx>`` parses an ``.evtx`` file into the
    same event records the live Security-log collector produces and
    then runs the standard Windows-event detector, correlation, and
    timeline pipeline. Missing python-evtx yields an operational note
    via the analyzer's error dict.
    """
    path = Path(file_path)

    if not path.exists():
        return {"error": (f"EVTX file does not exist: {path}")}

    if not path.is_file():
        return {"error": (f"EVTX path is not a file: {path}")}

    try:
        evtx_data = analyze_evtx(str(path))
    except PermissionError:
        return {"error": (f"Permission denied while reading evtx: {path}")}
    except Exception as exc:
        return {"error": (f"Unable to analyze evtx file: {exc}")}

    if "error" in evtx_data:
        return evtx_data

    try:
        findings = process_findings(
            add_source(
                analyze_windows_events(
                    evtx_data.get(
                        "events",
                        [],
                    )
                ),
                "builtin",
            )
        )

        incidents = correlate_findings(findings)

        scan_timestamp = datetime.now().astimezone().isoformat()

        timeline = build_timeline(
            findings=findings,
            incidents=incidents,
            scan_timestamp=scan_timestamp,
        )

        risk = calculate_overall_risk(
            findings,
            incidents,
        )
    except Exception as exc:
        return {"error": (f"EVTX detection pipeline failed: {exc}")}

    return {
        "analysis": {
            "application": "SentinelClaw",
            "timestamp": scan_timestamp,
            "type": "evtx",
        },
        "risk": risk,
        "evtx": evtx_data,
        "findings": findings,
        "incidents": incidents,
        "timeline": timeline,
    }


def run_pcap_scan(
    file_path: str,
) -> dict:
    try:
        from sentinelclaw.tools.pcap_analyzer import analyze_pcap
    except ImportError:
        return {"error": ("PCAP support is not installed. Install it with: pip install -e .[pcap]")}

    path = Path(file_path)

    if not path.exists():
        return {"error": (f"Capture file does not exist: {path}")}

    if not path.is_file():
        return {"error": (f"Capture path is not a file: {path}")}

    try:
        pcap_data = analyze_pcap(str(path))
    except PermissionError:
        return {"error": (f"Permission denied while reading capture: {path}")}
    except Exception as exc:
        return {"error": (f"Unable to analyze capture: {exc}")}

    if "error" in pcap_data:
        return pcap_data

    try:
        findings = process_findings(
            add_source(
                analyze_pcap_findings(pcap_data),
                "builtin",
            )
        )

        incidents = correlate_findings(findings)

        scan_timestamp = datetime.now().astimezone().isoformat()

        timeline = build_timeline(
            findings=findings,
            incidents=incidents,
            scan_timestamp=scan_timestamp,
        )

        risk = calculate_overall_risk(
            findings,
            incidents,
        )
    except Exception as exc:
        return {"error": (f"PCAP detection pipeline failed: {exc}")}

    return {
        "analysis": {
            "application": "SentinelClaw",
            "timestamp": scan_timestamp,
            "type": "pcap",
        },
        "risk": risk,
        "pcap": pcap_data,
        "findings": findings,
        "incidents": incidents,
        "timeline": timeline,
    }


def run_log_scan(
    file_path: str,
) -> dict:
    path = Path(file_path)

    if not path.exists():
        return {"error": (f"Log file does not exist: {path}")}

    if not path.is_file():
        return {"error": (f"Log path is not a file: {path}")}

    try:
        log_data = analyze_log_file(str(path))
    except PermissionError:
        return {"error": (f"Permission denied while reading log: {path}")}
    except Exception as exc:
        return {"error": (f"Unable to analyze log file: {exc}")}

    if "error" in log_data:
        return log_data

    if log_data.get("skipped"):
        logger.info(
            "Log analysis skipped for %s: %s",
            path,
            log_data.get(
                "skipped_reason",
                "unknown reason",
            ),
        )

    try:
        findings = process_findings(
            add_source(
                analyze_log_events(
                    log_data.get(
                        "events",
                        [],
                    )
                ),
                "builtin",
            )
        )

        incidents = correlate_findings(findings)

        scan_timestamp = datetime.now().astimezone().isoformat()

        timeline = build_timeline(
            findings=findings,
            incidents=incidents,
            scan_timestamp=scan_timestamp,
        )

        risk = calculate_overall_risk(
            findings,
            incidents,
        )
    except Exception as exc:
        return {"error": (f"Log detection pipeline failed: {exc}")}

    return {
        "analysis": {
            "application": "SentinelClaw",
            "timestamp": scan_timestamp,
            "type": "log",
        },
        "risk": risk,
        "log": log_data,
        "findings": findings,
        "incidents": incidents,
        "timeline": timeline,
    }
