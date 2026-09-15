import argparse
import json
import logging
import re
from pathlib import Path

from sentinelclaw.config.settings import get_settings

logger = logging.getLogger(
    __name__
)

# DoS guard: keyword matching runs on (and retains) at most this many
# characters of each line, so a single hostile multi-GB line cannot
# force an unbounded match record.
MAX_LOG_LINE_CHARS = 8192

# DoS guard: cap the retained suspicious matches/events. Once the cap
# is reached the scan stops early and reports the truncation (mirroring
# the pcap packet/flow caps) instead of growing memory without bound.
MAX_LOG_MATCHES = 5000

KEYWORD_CLASSES: dict[
    str,
    tuple[str, str, str],
] = {
    "failed login": (
        "authentication",
        "failed_login",
        "low",
    ),
    "failed password": (
        "authentication",
        "failed_login",
        "low",
    ),
    "authentication failed": (
        "authentication",
        "failed_login",
        "low",
    ),
    "unauthorized": (
        "authentication",
        "unauthorized_access",
        "low",
    ),
    "access denied": (
        "authentication",
        "access_denied",
        "info",
    ),
    "malware": (
        "generic",
        "malware_indicator",
        "info",
    ),
    "ransomware": (
        "generic",
        "malware_indicator",
        "info",
    ),
    "powershell": (
        "execution",
        "script_execution",
        "medium",
    ),
    "encodedcommand": (
        "execution",
        "obfuscated_command",
        "high",
    ),
    "mimikatz": (
        "credential_access",
        "credential_dumping",
        "high",
    ),
    "brute force": (
        "authentication",
        "brute_force",
        "medium",
    ),
    "privilege escalation": (
        "privilege_escalation",
        "privilege_escalation",
        "medium",
    ),
    "reverse shell": (
        "command_and_control",
        "reverse_shell",
        "high",
    ),
    "port scan": (
        "reconnaissance",
        "port_scan",
        "low",
    ),
    "scheduled task": (
        "persistence",
        "scheduled_task",
        "medium",
    ),
}

SUSPICIOUS_KEYWORDS = list(
    KEYWORD_CLASSES
)

_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)

_IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

_SSH_FAILED_PATTERN = re.compile(
    r"failed\s+(?:password|login|authentication)\s+"
    r"for\s+(\S+)\s+from\s+([0-9A-Fa-f:.]+)",
    re.IGNORECASE,
)

_USER_PATTERN = re.compile(
    r"(?:user|username)\s*[=:]\s*(\S+)",
    re.IGNORECASE,
)

_HOST_PATTERN = re.compile(
    r"(?:host(?:name)?|computer)\s*[=:]\s*"
    r"([A-Za-z0-9._-]+)",
    re.IGNORECASE,
)


def detect_source(message: str) -> str:
    lower = message.lower()

    if "sshd" in lower:
        return "ssh"

    if "sudo" in lower:
        return "sudo"

    if "cron" in lower:
        return "cron"

    if "systemd" in lower:
        return "systemd"

    if "auth" in lower:
        return "auth"

    return "unknown"


def extract_timestamp(line: str) -> str | None:
    match = _TIMESTAMP_PATTERN.search(
        line
    )

    if match is None:
        return None

    timestamp = match.group(0).strip()
    timestamp = timestamp.replace(" ", "T")
    timestamp = timestamp.replace(",", ".")

    return timestamp


def build_event(
    line_number: int,
    line: str,
    matched_keywords: list[str],
) -> dict:
    message = line.strip()

    event_class, event_type, severity_hint = (
        KEYWORD_CLASSES[matched_keywords[0]]
    )

    ip = None
    username = None

    ssh_failed = _SSH_FAILED_PATTERN.search(
        line
    )

    if ssh_failed:
        username = ssh_failed.group(1)
        ip = ssh_failed.group(2)
    else:
        ip_match = _IP_PATTERN.search(
            line
        )

        if ip_match:
            ip = ip_match.group(0)

        user_match = _USER_PATTERN.search(
            line
        )

        if user_match:
            username = user_match.group(1)

    host_match = _HOST_PATTERN.search(
        line
    )

    host = (
        host_match.group(1)
        if host_match
        else None
    )

    return {
        "timestamp": extract_timestamp(
            line
        ),
        "source": detect_source(
            message
        ),
        "event_type": event_type,
        "event_class": event_class,
        "message": message,
        "severity_hint": severity_hint,
        "matched_keywords": matched_keywords,
        "ip": ip,
        "host": host,
        "username": username,
        "line_number": line_number,
    }


def _skipped_result(
    path: Path,
    size_bytes: int,
    max_size: int,
) -> dict:
    """Operational "too large" note, matching ``file_analyzer``'s shape.

    The log is never opened; the result carries the same keys as a
    normal analysis (empty collections) plus ``skipped`` /
    ``skipped_reason`` so the caller renders an operational note
    instead of a security finding.
    """
    logger.info(
        "Skipping full analysis of %s "
        "(%d bytes exceeds %d byte limit)",
        path.name,
        size_bytes,
        max_size,
    )

    return {
        "file": str(path),
        "size_bytes": size_bytes,
        "total_lines": 0,
        "suspicious_matches": 0,
        "matches": [],
        "events": [],
        "truncated": False,
        "truncation_reason": None,
        "skipped": True,
        "skipped_reason": "too large",
    }


def analyze_log_file(file_path: str) -> dict:
    path = Path(file_path)

    if not path.exists():
        return {
            "error": f"File not found: {file_path}"
        }

    if not path.is_file():
        return {
            "error": f"Not a file: {file_path}"
        }

    max_size = get_settings().max_file_analysis_size

    try:
        size_bytes = path.stat().st_size
    except OSError as exc:
        return {
            "error": str(exc)
        }

    if size_bytes > max_size:
        return _skipped_result(
            path,
            size_bytes,
            max_size,
        )

    matches: list[dict] = []
    events: list[dict] = []
    total_lines = 0

    truncated = False
    truncation_reason: str | None = None

    with path.open("r", encoding="utf-8", errors="ignore") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if len(matches) >= MAX_LOG_MATCHES:
                truncated = True
                truncation_reason = (
                    f"match limit reached "
                    f"({MAX_LOG_MATCHES})"
                )
                break

            total_lines += 1

            # Bound both the scanned text and the retained text: the
            # keyword match, the structured event and the raw match
            # record all operate on the same truncated prefix.
            line = line[:MAX_LOG_LINE_CHARS]
            lower_line = line.lower()

            matched_keywords = [
                keyword
                for keyword in SUSPICIOUS_KEYWORDS
                if keyword in lower_line
            ]

            if matched_keywords:
                matches.append(
                    {
                        "line_number": line_number,
                        "matched_keywords": matched_keywords,
                        "text": line.strip(),
                    }
                )

                events.append(
                    build_event(
                        line_number,
                        line,
                        matched_keywords,
                    )
                )

    logger.debug(
        "Analyzed log %s: %d line(s), "
        "%d suspicious match(es), "
        "%d structured event(s) "
        "(truncated: %s)",
        path.name,
        total_lines,
        len(matches),
        len(events),
        truncated,
    )

    return {
        "file": str(path),
        "size_bytes": size_bytes,
        "total_lines": total_lines,
        "suspicious_matches": len(matches),
        "matches": matches,
        "events": events,
        "truncated": truncated,
        "truncation_reason": truncation_reason,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a text log file for suspicious keywords."
    )

    parser.add_argument(
        "file",
        help="Path to the log file to analyze",
    )

    args = parser.parse_args()

    result = analyze_log_file(args.file)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
