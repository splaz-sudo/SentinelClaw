"""
Offline threat-intel bundle loading and matching (P4-25).

SentinelClaw is local-first and read-only: this module parses a
user-supplied threat-intel bundle *from disk* and checks collected
system data against it. There is no network access and no feed
subscription; the bundle is simply a file referenced by the
``intel_bundle_path`` setting (env ``SENTINELCLAW_INTEL_BUNDLE_PATH``
or TOML ``intel_bundle_path``).

Supported bundle formats
------------------------

STIX 2.x JSON bundles (``.json``): a top-level object with ``type``
``bundle`` and an ``objects`` list, or a single indicator/SCO object.
The supported subset is intentionally small and documented:

* Indicators with a single-term STIX pattern of the form::

      [file:hashes.'SHA-256' = '<hex>']
      [ipv4-addr:value = '<ip>']      / [ipv6-addr:value = '<ip>']
      [domain-name:value = '<name>']

  Patterns containing ``AND``/``OR`` conjunctions or unsupported
  object types (``url:value``, ``x509-certificate:...``, ...) are
  skipped rather than treated as an error.
* Plain STIX 2.x SCO-style observable objects directly inside the
  ``objects`` list: ``file`` (``hashes`` dict with a ``SHA-256``
  entry), ``ipv4-addr``/``ipv6-addr`` (``value``) and ``domain-name``
  (``value``).

OpenIOC XML (``.xml``): a root ``<ioc>`` document. The supported
subset covers the common Mandiant/FireEye indicator items:

* ``FileItem/Sha256sum`` (and ``FileItem/Sha256``) hash items
* ``Network/RemoteIP``, ``PortItem/RemoteIP`` and
  ``Network/DestinationIP`` IP items
* ``Network/DNS`` and ``HostItem/DNS`` domain items

Other hash algorithms (``Md5sum``, ``Sha1sum``, ``Imphash``) and any
unmapped item type are skipped. Both ``condition="is"`` and
``condition="contains"`` items are accepted for the mapped types.

Return value
------------

``load_intel_bundle`` returns a normalized dict with one list of
entries per indicator type::

    {
        "sha256": [{"value", "source", "description"}, ...],
        "ip":     [...],
        "domain": [...],
    }

Values are normalized (hashes lower-cased hex, domains lower-cased,
IPs validated) and entries are deduplicated and sorted for
determinism. A missing/unreadable file, invalid JSON/XML, a bundle
larger than the ``max_intel_bundle_size_bytes`` setting, or a bundle
that is not an indicator collection yields an *operational error dict*
(``{"error": "..."}``) instead of raising; callers treat that as a
skip note, never as a scan failure.

Matching
--------

``check_collected_values`` matches normalized candidate values
(hashes, IPs, domains) against a loaded bundle and emits the new
findings INTEL-001 (hash, high), INTEL-002 (IP, high) and INTEL-003
(domain, high) with the matched value plus the indicator
source/description as evidence. Matching is case-insensitive for
hashes and domains. With no bundle configured no intel findings are
ever produced (the feature is off by default).
"""

import ipaddress
import json
import logging
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from sentinelclaw.config.settings import get_settings

logger = logging.getLogger(
    __name__
)

INTEL_FINDING_IDS = {
    "sha256": "INTEL-001",
    "ip": "INTEL-002",
    "domain": "INTEL-003",
}

INTEL_SEVERITY = "high"
INTEL_CONFIDENCE = "high"

_INTEL_MITRE = {
    "sha256": {
        "technique": "T1204.002",
        "name": "Malicious File",
        "tactic": "Execution",
    },
    "ip": {
        "technique": "T1071.001",
        "name": "Application Layer Protocol: Web",
        "tactic": "Command and Control",
    },
    "domain": {
        "technique": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
    },
}

_INTEL_TITLES = {
    "sha256": "File hash matched threat-intel indicator",
    "ip": "Network connection to known threat-intel IP",
    "domain": "Domain matched threat-intel indicator",
}

_INTEL_DESCRIPTIONS = {
    "sha256": (
        "The file hash matched an indicator from the "
        "configured offline threat-intel bundle."
    ),
    "ip": (
        "A network connection was observed to an IP address "
        "listed in the configured offline threat-intel bundle."
    ),
    "domain": (
        "A domain listed in the configured offline "
        "threat-intel bundle was observed in collected data."
    ),
}

_SHA256_HEX = frozenset("0123456789abcdef")


def _normalize_sha256(
    value: str,
) -> str | None:
    text = value.strip().lower()

    if len(text) != 64:
        return None

    if not set(text) <= _SHA256_HEX:
        return None

    return text


def _normalize_ip(
    value: str,
) -> str | None:
    text = value.strip()

    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None

    return text


def _normalize_domain(
    value: str,
) -> str | None:
    text = value.strip().lower().rstrip(".")

    if not text or "." not in text:
        return None

    return text


_NORMALIZERS = {
    "sha256": _normalize_sha256,
    "ip": _normalize_ip,
    "domain": _normalize_domain,
}


def _error(
    message: str,
) -> dict:
    return {
        "error": message,
    }


def _local_name(
    tag: str,
) -> str:
    if "}" in tag:
        return tag.rsplit(
            "}",
            1,
        )[1].lower()

    return tag.lower()


def _strip_quotes(
    value: str,
) -> str:
    value = value.strip()

    if (
        len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {"'", '"'}
    ):
        return value[1:-1]

    return value


def _pattern_type_and_value(
    pattern: str,
) -> tuple[
    str,
    str,
] | None:
    """Extract (type, value) from a single-term STIX pattern.

    Returns ``None`` for unsupported or compound patterns.
    """
    body = pattern.strip()

    if (
        len(body) >= 2
        and body[0] == "["
        and body[-1] == "]"
    ):
        body = body[1:-1]

    if " AND " in body or " OR " in body:
        return None

    if "=" not in body:
        return None

    left, _, right = body.partition("=")

    if ":" not in left:
        return None

    obj_type, _, prop = left.partition(":")

    value = _strip_quotes(
        right
    )

    prop_key = (
        prop.strip()
        .replace("'", "")
        .replace('"', "")
        .lower()
    )

    if obj_type.lower() == "file":
        if (
            prop_key == "hashes.sha-256"
            or prop_key == "hashes.sha256"
        ):
            return (
                "sha256",
                value,
            )

        return None

    if (
        obj_type.lower() in {
            "ipv4-addr",
            "ipv6-addr",
        }
        and prop_key == "value"
    ):
        return (
            "ip",
            value,
        )

    if (
        obj_type.lower() == "domain-name"
        and prop_key == "value"
    ):
        return (
            "domain",
            value,
        )

    return None


def _scoped_object_type(
    obj: dict,
) -> tuple[
    str,
    str,
] | None:
    """Return (type, value) for a plain STIX SCO-style observable."""
    obj_type = str(
        obj.get("type", "")
    ).lower()

    if obj_type == "file":
        hashes = obj.get("hashes")

        if isinstance(
            hashes,
            dict,
        ):
            for key, value in hashes.items():
                if str(key).lower().replace(
                    "_",
                    "-",
                ) == "sha-256":
                    return (
                        "sha256",
                        value,
                    )

        return None

    if (
        obj_type in {
            "ipv4-addr",
            "ipv6-addr",
        }
        and obj.get("value")
    ):
        return (
            "ip",
            str(obj["value"]),
        )

    if (
        obj_type == "domain-name"
        and obj.get("value")
    ):
        return (
            "domain",
            str(obj["value"]),
        )

    return None


def _add_entry(
    result: dict,
    entry_type: str,
    value: str,
    source: str,
    description: str,
) -> None:
    normalized = _NORMALIZERS[
        entry_type
    ](value)

    if normalized is None:
        return

    entry = {
        "value": normalized,
        "source": source,
        "description": description,
    }

    existing = result[entry_type]

    if entry not in existing:
        existing.append(
            entry
        )


def _sort_entries(
    result: dict,
) -> None:
    for entry_type in (
        "sha256",
        "ip",
        "domain",
    ):
        result[entry_type].sort(
            key=lambda entry: (
                entry["value"],
                entry["source"],
                entry["description"],
            )
        )


def _empty_result() -> dict:
    return {
        "sha256": [],
        "ip": [],
        "domain": [],
    }


def _load_stix_bundle(
    path: Path,
) -> dict:
    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(
                file
            )
    except json.JSONDecodeError as exc:
        return _error(
            f"Invalid JSON in intel bundle {path}: {exc}"
        )
    except OSError as exc:
        return _error(
            f"Unable to read intel bundle {path}: {exc}"
        )

    if not isinstance(
        data,
        dict,
    ):
        return _error(
            f"Intel bundle {path} must contain a JSON object"
        )

    objects = data.get(
        "objects",
        [],
    )

    if not isinstance(
        objects,
        list,
    ):
        return _error(
            f"Intel bundle {path} 'objects' must be a list"
        )

    result = _empty_result()
    filename = path.name

    for obj in objects:
        if not isinstance(
            obj,
            dict,
        ):
            continue

        source = str(
            obj.get("name")
            or obj.get("id")
            or f"intel-bundle:{filename}"
        )

        description = str(
            obj.get("description")
            or ""
        ).strip()

        pattern = obj.get(
            "pattern"
        )

        if isinstance(
            pattern,
            str,
        ) and pattern:
            parsed = _pattern_type_and_value(
                pattern
            )
        else:
            parsed = _scoped_object_type(
                obj
            )

        if parsed is None:
            continue

        entry_type, value = parsed

        _add_entry(
            result,
            entry_type,
            value,
            str(source),
            description,
        )

    _sort_entries(
        result
    )

    return result


def _openioc_items(
    root: ElementTree.Element,
) -> list[ElementTree.Element]:
    return [
        element
        for element in root.iter()
        if _local_name(
            element.tag
        )
        == "indicatoritem"
    ]


def _openioc_value(
    item: ElementTree.Element,
) -> str:
    text = (item.text or "").strip()

    if text:
        return text

    # OpenIOC values usually follow a self-closing <Context />
    # element, so they arrive as the Context child's *tail* text
    # rather than the IndicatorItem's own text node.
    for child in item:
        name = _local_name(
            child.tag
        )

        if name == "content":
            content = (
                child.text or ""
            ).strip()

            if content:
                return content

        tail = (
            child.tail or ""
        ).strip()

        if tail:
            return tail

    return ""


def _openioc_item_type(
    item: ElementTree.Element,
) -> str | None:
    # The value type is described by the nested <Context />
    # element's ``search`` attribute (e.g. "FileItem/Sha256sum");
    # the IndicatorItem itself only carries condition/id.
    search = ""

    for child in item:
        if _local_name(
            child.tag
        ) == "context":
            search = (
                child.get(
                    "search",
                    "",
                )
                .strip()
                .lower()
            )
            break

    if not search:
        search = (
            item.get(
                "search",
                "",
            )
            .strip()
            .lower()
        )

    if (
        "fileitem/sha256sum" in search
        or "fileitem/sha256" in search
    ):
        return "sha256"

    if (
        "remoteip" in search
        or "destinationip" in search
    ):
        return "ip"

    if (
        "/dns" in search
        or search.endswith("dns")
    ):
        return "domain"

    return None


def _load_openioc_bundle(
    path: Path,
) -> dict:
    try:
        tree = ElementTree.parse(
            path
        )
    except ElementTree.ParseError as exc:
        return _error(
            f"Invalid OpenIOC XML in intel bundle "
            f"{path}: {exc}"
        )
    except OSError as exc:
        return _error(
            f"Unable to read intel bundle {path}: {exc}"
        )

    root = tree.getroot()

    if _local_name(
        root.tag
    ) != "ioc":
        return _error(
            f"Intel bundle {path} is not an <ioc> document"
        )

    result = _empty_result()

    source = ""

    for element in root.iter():
        name = _local_name(
            element.tag
        )

        if (
            name == "short_description"
            or name == "description"
        ):
            text = (
                element.text or ""
            ).strip()

            if (
                text
                and not source
            ):
                source = text

    if not source:
        source = f"intel-bundle:{path.name}"

    for item in _openioc_items(
        root
    ):
        entry_type = _openioc_item_type(
            item
        )

        if entry_type is None:
            continue

        value = _openioc_value(
            item
        )

        _add_entry(
            result,
            entry_type,
            value,
            source,
            source,
        )

    _sort_entries(
        result
    )

    return result


def load_intel_bundle(
    bundle_path: str,
) -> dict:
    """Load a STIX 2.x JSON or OpenIOC XML intel bundle from disk.

    Returns the normalized ``{sha256, ip, domain}`` entry dict, or an
    operational ``{"error": "..."}`` dict for missing/unreadable/
    malformed bundles (callers skip, never crash).
    """
    path = Path(
        bundle_path
    ).expanduser()

    if not path.exists():
        return _error(
            f"Intel bundle does not exist: {path}"
        )

    if not path.is_file():
        return _error(
            f"Intel bundle is not a file: {path}"
        )

    max_size = (
        get_settings()
        .max_intel_bundle_size_bytes
    )

    try:
        size = path.stat().st_size
    except OSError as exc:
        return _error(
            f"Unable to read intel bundle {path}: {exc}"
        )

    if size > max_size:
        message = (
            f"Intel bundle {path} is {size} bytes, "
            f"which exceeds the {max_size} byte "
            "size limit"
        )

        logger.warning(
            "%s",
            message,
        )

        return _error(
            message
        )

    suffix = path.suffix.lower()

    if suffix == ".json":
        return _load_stix_bundle(
            path
        )

    if suffix == ".xml":
        return _load_openioc_bundle(
            path
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            first = file.read(1)
    except OSError as exc:
        return _error(
            f"Unable to read intel bundle {path}: {exc}"
        )

    if first == "<":
        return _load_openioc_bundle(
            path
        )

    if first == "{":
        return _load_stix_bundle(
            path
        )

    return _error(
        f"Unrecognized intel bundle format for {path}"
    )


def connection_remote_ips(
    connections: list[dict],
) -> list[str]:
    """Extract remote IPs from ``get_network_connections`` records."""
    ips = set()

    for connection in connections:
        remote = connection.get(
            "remote_address"
        )

        if not isinstance(
            remote,
            dict,
        ):
            continue

        ip = remote.get(
            "ip"
        )

        if isinstance(
            ip,
            str,
        ) and ip:
            ips.add(
                ip
            )

    return sorted(
        ips
    )


def _intel_finding(
    entry_type: str,
    matched_value: str,
    indicators: list[dict],
) -> dict:
    return {
        "severity": INTEL_SEVERITY,
        "confidence": INTEL_CONFIDENCE,
        "category": (
            "file"
            if entry_type == "sha256"
            else "network"
        ),
        "rule_id": INTEL_FINDING_IDS[
            entry_type
        ],
        "title": _INTEL_TITLES[
            entry_type
        ],
        "description": _INTEL_DESCRIPTIONS[
            entry_type
        ],
        "evidence": {
            "matched_value": matched_value,
            "indicators": indicators,
        },
        "mitre": _INTEL_MITRE[
            entry_type
        ],
    }


def check_collected_values(
    intel: dict,
    *,
    hashes: list[str] | None = None,
    ips: list[str] | None = None,
    domains: list[str] | None = None,
) -> list[dict]:
    """Check collected candidate values against a loaded intel bundle.

    Returns INTEL-001/INTEL-002/INTEL-003 findings (high severity)
    for matched values; one finding per matched candidate value with
    every matching indicator entry as evidence. Candidates that match
    nothing produce no findings.
    """
    findings = []

    candidates = {
        "sha256": hashes or [],
        "ip": ips or [],
        "domain": domains or [],
    }

    for entry_type, values in candidates.items():
        index: dict[str, list[dict]] = {}

        for entry in intel.get(
            entry_type,
            [],
        ):
            if not isinstance(
                entry,
                dict,
            ):
                continue

            value = entry.get(
                "value"
            )

            if not isinstance(
                value,
                str,
            ):
                continue

            key = value.lower()

            index.setdefault(
                key,
                [],
            ).append(
                {
                    "value": value,
                    "source": entry.get(
                        "source",
                        "",
                    ),
                    "description": entry.get(
                        "description",
                        "",
                    ),
                }
            )

        for candidate in sorted(
            set(
                str(value)
                for value in values
                if value
            )
        ):
            normalized = _NORMALIZERS[
                entry_type
            ](candidate)

            if normalized is None:
                continue

            matched = index.get(
                normalized.lower(),
                [],
            )

            if not matched:
                continue

            findings.append(
                _intel_finding(
                    entry_type,
                    normalized,
                    sorted(
                        matched,
                        key=lambda entry: (
                            entry["source"],
                            entry["value"],
                        ),
                    ),
                )
            )

    return findings
