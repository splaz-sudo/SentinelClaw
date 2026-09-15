import ipaddress
import logging
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from sentinelclaw.config.constants import VALID_SEVERITIES

try:
    import regex as _regex
except ImportError:
    _regex = None

logger = logging.getLogger(
    __name__
)

# ReDoS guard: rule-supplied regexes (raw Sigma ``|re`` patterns and
# wildcard-converted patterns) run against hostile evidence. When the
# ``regex`` package is installed its per-match timeout is authoritative;
# the searched text is ALWAYS truncated to the input cap as
# defense-in-depth, and patterns longer than the pattern cap are
# rejected at validation time. The stdlib ``re`` fallback keeps the
# truncation but cannot enforce a timeout, so it logs a one-time
# warning that timeouts are unavailable.
REGEX_TIMEOUT_SECONDS = 0.5
MAX_REGEX_INPUT_CHARS = 8192
MAX_REGEX_PATTERN_CHARS = 512

# Timeout warnings are emitted once per pattern; the tracked set is
# bounded so a hostile rule pack cannot grow it without bound.
_MAX_TRACKED_REGEX_TIMEOUT_PATTERNS = 256
_REGEX_TIMEOUT_PATTERNS: set[str] = set()

_REGEX_FALLBACK_WARNED = False

SUPPORTED_OPERATORS = frozenset(
    {
        "equals",
        "contains",
        "startswith",
        "endswith",
        "greater_than",
        "greater_or_equal",
        "less_than",
        "less_or_equal",
        "exists",
        "not_equals",
        "not_contains",
        "matches",
        "cidr",
        "fieldref",
    }
)

# P2-14: condition nodes. In addition to the flat atom form (``field`` /
# ``operator`` / ``value``), a condition entry may be a logical group:
#
#   - ``any_of: [<node>, ...]``   true when at least one child is true
#   - ``all_of: [<node>, ...]``   true when every child is true
#
# Either group key may carry ``negated: true`` to invert the group, and
# atom nodes may carry ``negated: true`` to invert a single comparison.
# Groups nest recursively, which lets the Sigma reader express arbitrary
# ``and``/``or``/``not`` detection conditions. Rules without any group
# keys keep the legacy flat semantics unchanged.
#
# P2-14 also adds two operators used by the Sigma subset:
#
#   - ``cidr``     value is a CIDR string (or list of them); the actual
#                  value is an IP string; matches when the IP is inside
#                  any listed network.
#   - ``fieldref`` value names another field on the same record; matches
#                  when the two fields hold equal values (the Sigma
#                  ``|fieldref`` modifier).
GROUP_KEYS = frozenset(
    {
        "any_of",
        "all_of",
    }
)

VALID_RULE_CATEGORIES = frozenset(
    {
        "process",
        "network",
        "file",
        "windows_event",
        "log",
        "auth",
        "persistence",
    }
)

VALID_RULE_OS_VALUES = frozenset(
    {
        "linux",
        "windows",
        "all",
    }
)

# P2-15: optional rule-quality metadata (Hayabusa-style). All of these
# fields are OPTIONAL; a rule without any of them loads unchanged.
#
#   status          provenance of the rule: ``proven`` (battle-tested
#                   detections), ``experimental`` (new, still being
#                   tuned), ``stable`` (mature), or ``deprecated``
#                   (kept for legacy reporting, no longer trusted).
#   noisy           bool; signals the rule produces frequent, mostly
#                   benign matches (used for reporting / tuning only).
#   falsepositives  human-readable guidance on expected false
#                   positives; a string or a list of strings.
#   level_override  severity in VALID_SEVERITIES that overrides the
#                   rule's ``severity`` at match time (per-rule tuning
#                   without editing the base severity).
#   enabled         bool, default true. Rules with ``enabled: false``
#                   are skipped at load time with a debug log entry so
#                   they neither fire nor appear in listings; the
#                   ``run_rules`` guard is kept as defense in depth
#                   for programmatically built rule lists.
VALID_RULE_STATUSES = frozenset(
    {
        "proven",
        "experimental",
        "stable",
        "deprecated",
    }
)

REQUIRED_RULE_FIELDS = (
    "id",
    "title",
    "description",
    "category",
    "severity",
    "confidence",
    "conditions",
)


def current_platform() -> str:
    """Return the normalized current platform: ``linux`` or ``windows``."""
    if sys.platform.startswith(
        "win"
    ):
        return "windows"

    if sys.platform.startswith(
        "linux"
    ):
        return "linux"

    return "other"


def rule_matches_current_os(
    rule: dict,
) -> bool:
    """Return whether a rule's optional ``os`` list includes the platform.

    A rule without an ``os`` field (or with ``all`` listed) applies on
    every platform. Rules whose ``os`` list excludes the current platform
    are skipped at load time so that, for example, Windows-only rules do
    not fire noise on Linux hosts.
    """
    os_values = rule.get("os")

    if not os_values:
        return True

    if not isinstance(
        os_values,
        list,
    ):
        return True

    normalized = {
        str(value)
        .lower()
        for value in os_values
    }

    if "all" in normalized:
        return True

    return current_platform() in normalized


def load_rule_file(file_path: str | Path) -> list[dict]:
    path = Path(file_path)

    if not path.exists():
        return []

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file) or {}
    except yaml.YAMLError as exc:
        logger.warning(
            "Skipping rule file %s: invalid YAML (%s)",
            path,
            exc,
        )

        return []

    rules = data.get("rules", [])

    if not isinstance(rules, list):
        logger.warning(
            "Skipping rule file %s: top-level "
            "'rules' must be a list",
            path,
        )

        return []

    validated = []

    for index, rule in enumerate(rules):
        valid, reason = validate_rule(
            rule
        )

        if not valid:
            logger.warning(
                "Skipping rule %d in %s: %s",
                index,
                path,
                reason,
            )

            continue

        if not rule_matches_current_os(
            rule
        ):
            logger.debug(
                "Skipping rule %s in %s: "
                "os %r excludes platform %r",
                rule.get("id"),
                path,
                rule.get("os"),
                current_platform(),
            )

            continue

        if not rule.get(
            "enabled",
            True,
        ):
            logger.debug(
                "Skipping disabled rule %s in %s",
                rule.get("id"),
                path,
            )

            continue

        stamped = dict(rule)

        # P3-20: rule provenance. Stamp every loaded rule with the YAML
        # file it came from so findings created from the rule (and the
        # reports that carry them) can name the exact source rule file.
        # The stamp is applied after validation so it never masks a
        # schema problem inside the rule itself.
        stamped["source_file"] = str(path)

        validated.append(stamped)

    return validated


def load_rules_from_directory(
    directory: str | Path,
) -> list[dict]:
    rule_directory = Path(directory)

    if not rule_directory.exists():
        logger.debug(
            "Rules directory %s does not exist",
            rule_directory,
        )

        return []

    rule_files = [
        *sorted(
            rule_directory.rglob("*.yaml")
        ),
        *sorted(
            rule_directory.rglob("*.yml")
        ),
    ]

    if not rule_files:
        logger.debug(
            "No rule files found in %s",
            rule_directory,
        )

        return []

    rules = []
    loaded_any = False

    for file_path in rule_files:
        file_rules = load_rule_file(
            file_path
        )

        if file_rules:
            loaded_any = True

        rules.extend(
            file_rules
        )

    if not loaded_any:
        raise RuntimeError(
            "All rule files in "
            f"{rule_directory} failed to load"
        )

    logger.debug(
        "Loaded %d rule(s) from %s",
        len(rules),
        rule_directory,
    )

    return rules


def normalize_string(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, list):
        return " ".join(
            str(item)
            for item in value
        ).lower()

    return str(value).lower()


def get_nested_value(
    data: dict,
    field_path: str,
) -> Any:
    current: Any = data

    for part in field_path.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

    return current


def match_equals(
    actual,
    expected,
) -> bool:
    if isinstance(expected, list):
        actual_normalized = normalize_string(
            actual
        )

        return any(
            actual_normalized
            == normalize_string(item)
            for item in expected
        )

    return (
        normalize_string(actual)
        == normalize_string(expected)
    )


def match_contains(
    actual,
    expected,
) -> bool:
    actual_normalized = normalize_string(
        actual
    )

    if isinstance(expected, list):
        return any(
            normalize_string(item)
            in actual_normalized
            for item in expected
        )

    return (
        normalize_string(expected)
        in actual_normalized
    )


def match_startswith(
    actual,
    expected,
) -> bool:
    actual_normalized = normalize_string(
        actual
    )

    if isinstance(expected, list):
        return any(
            actual_normalized.startswith(
                normalize_string(item)
            )
            for item in expected
        )

    return actual_normalized.startswith(
        normalize_string(expected)
    )


def match_endswith(
    actual,
    expected,
) -> bool:
    actual_normalized = normalize_string(
        actual
    )

    if isinstance(expected, list):
        return any(
            actual_normalized.endswith(
                normalize_string(item)
            )
            for item in expected
        )

    return actual_normalized.endswith(
        normalize_string(expected)
    )


def _searchable_text(value: Any) -> str:
    """Render a value as the case-preserved text regexes search on."""
    if isinstance(value, list):
        return " ".join(
            str(item)
            for item in value
        )

    if value is None:
        return ""

    return str(value)


def _warn_regex_fallback_once() -> None:
    """Warn once that the timeout-capable ``regex`` engine is absent."""
    global _REGEX_FALLBACK_WARNED

    if _REGEX_FALLBACK_WARNED:
        return

    _REGEX_FALLBACK_WARNED = True

    logger.warning(
        "regex module is unavailable; rule regexes run with the stdlib "
        "re engine and cannot be timed out (searched text is truncated "
        "to %d characters)",
        MAX_REGEX_INPUT_CHARS,
    )


def _warn_regex_timeout_once(
    pattern_text: str,
) -> None:
    """Warn once per pattern that a regex match hit the timeout."""
    if pattern_text in _REGEX_TIMEOUT_PATTERNS:
        return

    if (
        len(_REGEX_TIMEOUT_PATTERNS)
        >= _MAX_TRACKED_REGEX_TIMEOUT_PATTERNS
    ):
        return

    _REGEX_TIMEOUT_PATTERNS.add(pattern_text)

    logger.warning(
        "matches: regex timed out after %.1fs for pattern %r; "
        "treating as a non-match",
        REGEX_TIMEOUT_SECONDS,
        pattern_text,
    )


def _regex_search(
    pattern: Any,
    text: str,
) -> bool:
    pattern_text = str(pattern)

    # Defense-in-depth: the engines never see more than the input cap,
    # even when the timeout is enforced.
    search_text = text[:MAX_REGEX_INPUT_CHARS]

    if _regex is not None:
        try:
            return (
                _regex.search(
                    pattern_text,
                    search_text,
                    timeout=REGEX_TIMEOUT_SECONDS,
                )
                is not None
            )
        except TimeoutError:
            _warn_regex_timeout_once(
                pattern_text
            )

            return False
        except _regex.error as exc:
            logger.debug(
                "matches: invalid regex %r (%s)",
                pattern,
                exc,
            )

            return False

    _warn_regex_fallback_once()

    try:
        return (
            re.search(
                pattern_text,
                search_text,
            )
            is not None
        )
    except re.error as exc:
        logger.debug(
            "matches: invalid regex %r (%s)",
            pattern,
            exc,
        )

        return False


def match_matches(
    actual,
    expected,
) -> bool:
    """Return whether the actual value matches the regex pattern(s)."""
    actual_text = _searchable_text(
        actual
    )

    if isinstance(expected, list):
        return any(
            _regex_search(
                pattern,
                actual_text,
            )
            for pattern in expected
        )

    return _regex_search(
        expected,
        actual_text,
    )


def match_not_equals(
    actual,
    expected,
) -> bool:
    return not match_equals(
        actual,
        expected,
    )


def match_not_contains(
    actual,
    expected,
) -> bool:
    return not match_contains(
        actual,
        expected,
    )


def match_cidr(
    actual: Any,
    expected: Any,
) -> bool:
    """Return whether an IP address falls inside one of the CIDR blocks.

    ``actual`` is the address observed on the record (a string or an
    object str() renders as an address); ``expected`` is a CIDR string
    or a list of CIDR strings (any-of semantics, matching the engine's
    list convention). Invalid networks or unparseable addresses simply
    fail to match.
    """
    if actual is None:
        return False

    try:
        address = ipaddress.ip_address(
            str(actual).strip()
        )
    except ValueError:
        return False

    if isinstance(
        expected,
        list,
    ):
        networks = expected
    else:
        networks = [
            expected
        ]

    for item in networks:
        try:
            network = ipaddress.ip_network(
                str(item).strip(),
                strict=False,
            )
        except ValueError as exc:
            logger.debug(
                "cidr: invalid network %r (%s)",
                item,
                exc,
            )

            continue

        if address in network:
            return True

    return False


def match_fieldref(
    actual: Any,
    referenced: Any,
) -> bool:
    """Return whether a field equals the value of another field.

    Implements the Sigma ``|fieldref`` modifier: the condition's value
    names a sibling field whose resolved value is compared (with the
    usual normalized equality). A missing actual value never matches,
    which keeps absent fields from equating to one another.
    """
    if actual is None or referenced is None:
        return False

    return match_equals(
        actual,
        referenced,
    )


def evaluate_condition(
    record: dict,
    condition: dict,
) -> bool:
    field = condition.get("field")
    operator = condition.get(
        "operator",
        "equals",
    )
    expected: Any = condition.get("value")

    if not field:
        return False

    actual = get_nested_value(
        record,
        field,
    )

    if operator == "equals":
        return match_equals(
            actual,
            expected,
        )

    if operator == "contains":
        return match_contains(
            actual,
            expected,
        )

    if operator == "startswith":
        return match_startswith(
            actual,
            expected,
        )

    if operator == "endswith":
        return match_endswith(
            actual,
            expected,
        )

    if operator == "matches":
        return match_matches(
            actual,
            expected,
        )

    if operator == "not_equals":
        return match_not_equals(
            actual,
            expected,
        )

    if operator == "not_contains":
        return match_not_contains(
            actual,
            expected,
        )

    if operator == "greater_than":
        try:
            return float(actual) > float(
                expected
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

    if operator == "greater_or_equal":
        try:
            return float(actual) >= float(
                expected
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

    if operator == "less_than":
        try:
            return float(actual) < float(
                expected
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

    if operator == "less_or_equal":
        try:
            return float(actual) <= float(
                expected
            )
        except (
            TypeError,
            ValueError,
        ):
            logger.debug(
                "less_or_equal: non-numeric "
                "comparison %r vs %r",
                actual,
                expected,
            )

            return False

    if operator == "exists":
        return actual is not None

    if operator == "cidr":
        return match_cidr(
            actual,
            expected,
        )

    if operator == "fieldref":
        return match_fieldref(
            actual,
            get_nested_value(
                record,
                str(expected),
            ),
        )

    return False


def evaluate_condition_node(
    record: dict,
    node: Any,
) -> bool:
    """Evaluate one condition node (atom or any_of/all_of group).

    Group keys nest recursively; every node type honors ``negated``.
    """
    if not isinstance(
        node,
        dict,
    ):
        return False

    if "any_of" in node:
        result = any(
            evaluate_condition_node(
                record,
                child,
            )
            for child in node["any_of"]
        )
    elif "all_of" in node:
        result = all(
            evaluate_condition_node(
                record,
                child,
            )
            for child in node["all_of"]
        )
    else:
        result = evaluate_condition(
            record,
            node,
        )

    if node.get("negated"):
        return not result

    return result


def evaluate_rule(
    rule: dict,
    record: dict,
) -> bool:
    conditions = rule.get(
        "conditions",
        []
    )

    if not conditions:
        return False

    match_mode = (
        rule.get(
            "match",
            "all",
        )
        .lower()
    )

    results = [
        evaluate_condition_node(
            record,
            condition,
        )
        for condition in conditions
    ]

    if match_mode == "any":
        return any(results)

    return all(results)


def validate_condition(
    condition: Any,
) -> tuple[
    bool,
    str,
]:
    """Validate a single rule condition; return (ok, reason)."""
    if not isinstance(
        condition,
        dict,
    ):
        return (
            False,
            "condition must be a mapping",
        )

    field = condition.get("field")
    operator = condition.get(
        "operator",
        "equals",
    )

    if not field:
        return (
            False,
            "condition missing field 'field'",
        )

    if operator not in SUPPORTED_OPERATORS:
        return (
            False,
            f"unknown operator '{operator}'",
        )

    if "value" not in condition:
        return (
            False,
            "condition missing field 'value'",
        )

    if operator == "matches":
        patterns = (
            condition["value"]
            if isinstance(
                condition["value"],
                list,
            )
            else [
                condition["value"]
            ]
        )

        for pattern in patterns:
            pattern_text = str(pattern)

            if (
                len(pattern_text)
                > MAX_REGEX_PATTERN_CHARS
            ):
                return (
                    False,
                    "regex pattern too long "
                    f"({len(pattern_text)} > "
                    f"{MAX_REGEX_PATTERN_CHARS} chars)",
                )

            try:
                re.compile(
                    pattern_text
                )
            except re.error as exc:
                return (
                    False,
                    f"invalid regex {pattern!r}: {exc}",
                )

    return (
        True,
        "",
    )


def validate_condition_node(
    node: Any,
) -> tuple[
    bool,
    str,
]:
    """Validate one condition node (atom or any_of/all_of group).

    Atoms use :func:`validate_condition`; groups require exactly one of
    ``any_of`` / ``all_of`` holding a non-empty list of valid child
    nodes. Either form may carry an optional boolean ``negated``.
    """
    if not isinstance(
        node,
        dict,
    ):
        return (
            False,
            "condition must be a mapping",
        )

    negated = node.get(
        "negated",
        False,
    )

    if not isinstance(
        negated,
        bool,
    ):
        return (
            False,
            "negated must be a boolean",
        )

    has_any = "any_of" in node
    has_all = "all_of" in node

    if has_any or has_all:
        if has_any == has_all:
            return (
                False,
                "group condition needs exactly one of "
                "'any_of' or 'all_of'",
            )

        group = node["any_of"] if has_any else node["all_of"]

        if (
            not isinstance(
                group,
                list,
            )
            or not group
        ):
            return (
                False,
                "group children must be a non-empty list",
            )

        for child_index, child in enumerate(
            group
        ):
            valid, reason = validate_condition_node(
                child
            )

            if not valid:
                return (
                    False,
                    f"group child {child_index}: {reason}",
                )

        return (
            True,
            "",
        )

    return validate_condition(
        node
    )


def validate_rule(
    rule: Any,
) -> tuple[
    bool,
    str,
]:
    """Validate a rule; return (ok, reason)."""
    if not isinstance(
        rule,
        dict,
    ):
        return (
            False,
            "rule must be a mapping",
        )

    for field in REQUIRED_RULE_FIELDS:
        if field not in rule:
            return (
                False,
                f"missing required field '{field}'",
            )

    severity = str(
        rule.get("severity", "")
    ).lower()

    if severity not in VALID_SEVERITIES:
        return (
            False,
            f"invalid severity '{rule.get('severity')}'",
        )

    category = str(
        rule.get("category", "")
    ).lower()

    if category not in VALID_RULE_CATEGORIES:
        return (
            False,
            f"invalid category '{rule.get('category')}'",
        )

    if "os" in rule:
        os_values = rule.get("os")

        if not isinstance(
            os_values,
            list,
        ) or not os_values:
            return (
                False,
                "os must be a non-empty list",
            )

        normalized_os = {
            str(value)
            .lower()
            for value in os_values
        }

        unknown_os = sorted(
            normalized_os
            - VALID_RULE_OS_VALUES
        )

        if unknown_os:
            return (
                False,
                "invalid os value(s) "
                f"{unknown_os}",
            )

    if "status" in rule:
        status = str(
            rule.get("status", "")
        ).lower()

        if status not in VALID_RULE_STATUSES:
            return (
                False,
                f"invalid status '{rule.get('status')}'",
            )

    if "noisy" in rule and not isinstance(
        rule.get("noisy"),
        bool,
    ):
        return (
            False,
            "noisy must be a boolean",
        )

    if "enabled" in rule and not isinstance(
        rule.get("enabled"),
        bool,
    ):
        return (
            False,
            "enabled must be a boolean",
        )

    if "level_override" in rule:
        override = str(
            rule.get("level_override", "")
        ).lower()

        if override not in VALID_SEVERITIES:
            return (
                False,
                "invalid level_override "
                f"'{rule.get('level_override')}'",
            )

    if "falsepositives" in rule:
        false_positives = rule.get(
            "falsepositives"
        )

        valid_falsepositives = isinstance(
            false_positives,
            str,
        ) or (
            isinstance(
                false_positives,
                list,
            )
            and bool(false_positives)
            and all(
                isinstance(item, str)
                for item in false_positives
            )
        )

        if not valid_falsepositives:
            return (
                False,
                "falsepositives must be a string or a "
                "non-empty list of strings",
            )

    conditions = rule.get("conditions")

    if (
        not isinstance(
            conditions,
            list,
        )
        or not conditions
    ):
        return (
            False,
            "conditions must be a non-empty list",
        )

    for index, condition in enumerate(
        conditions
    ):
        valid, reason = validate_condition_node(
            condition
        )

        if not valid:
            return (
                False,
                f"condition {index}: {reason}",
            )

    return (
        True,
        "",
    )


PROMOTED_CONTEXT_FIELDS = (
    "pid",
    "process_name",
    "remote_ip",
    "remote_port",
    "timestamp",
)


def create_finding(
    rule: dict,
    record: dict,
) -> dict:
    severity = rule.get(
        "severity",
        "info",
    )
    level_override = rule.get(
        "level_override"
    )

    if level_override:
        severity = str(
            level_override
        ).lower()

    finding = {
        "severity": severity,
        "rule_id": rule.get(
            "id",
            "RULE-UNKNOWN",
        ),
        "title": rule.get(
            "title",
            "Rule matched",
        ),
        "description": rule.get(
            "description",
            "",
        ),
        "category": rule.get(
            "category",
            "unknown",
        ),
        "evidence": record,
    }

    # Promote entity context to the finding's top level so the
    # correlation engine can group YAML-rule findings the same way
    # it groups built-in detector findings. The full record stays
    # unchanged under "evidence" for reports and timeline fallback.
    for field in PROMOTED_CONTEXT_FIELDS:
        if field in record:
            finding[field] = record[field]

    if (
        "process_name" not in finding
        and rule.get("category") == "process"
    ):
        name = record.get("name")

        if name is not None:
            finding["process_name"] = name

    mitre = rule.get("mitre")

    if mitre:
        finding["mitre"] = mitre

    confidence = rule.get(
        "confidence"
    )

    if confidence is not None:
        finding["confidence"] = (
            confidence
        )

    # P3-20: rule provenance. Findings carry the source rule file and
    # status metadata so reports can attribute a detection to the exact
    # rule that produced it. Both are optional -- rules built inline by
    # tests carry neither.
    rule_source = rule.get(
        "source_file"
    )

    if rule_source:
        finding["rule_source"] = str(
            rule_source
        )

    rule_status = rule.get(
        "status"
    )

    if rule_status:
        finding["rule_status"] = str(
            rule_status
        )

    return finding


def run_rules(
    rules: list[dict],
    records: list[dict],
    category: str | None = None,
) -> list[dict]:
    findings = []

    for rule in rules:
        if not rule.get(
            "enabled",
            True,
        ):
            continue

        rule_category = rule.get(
            "category"
        )

        if (
            category
            and rule_category != category
        ):
            continue

        for record in records:
            if evaluate_rule(
                rule,
                record,
            ):
                findings.append(
                    create_finding(
                        rule,
                        record,
                    )
                )

    logger.debug(
        "Rule engine produced %d finding(s) "
        "from %d record(s), category=%s",
        len(findings),
        len(records),
        category,
    )

    return findings
