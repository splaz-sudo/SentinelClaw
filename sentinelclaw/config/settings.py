"""
SentinelClaw runtime settings.

Settings are resolved with the following precedence (lowest to highest):

1. Built-in defaults defined on the :class:`Settings` dataclass.
2. An optional TOML configuration file.
3. ``SENTINELCLAW_*`` environment variables (environment wins).

TOML file discovery order (only the first existing file is used):

1. ``SENTINELCLAW_CONFIG`` environment variable, when set.
2. ``./sentinelclaw.toml`` in the current working directory.
3. ``~/.config/sentinelclaw/config.toml``.

A missing configuration file is not an error: built-in defaults apply.

Environment variables follow the scheme ``SENTINELCLAW_<FIELD>`` where
``<FIELD>`` is the setting name converted to upper case. Supported
variables (the first three reuse the pre-existing paths.py variables):

=======================  =====================================
Setting                  Environment variable
=======================  =====================================
rules_dir                SENTINELCLAW_RULES_DIR
report_dir               SENTINELCLAW_REPORT_DIR
data_dir                 SENTINELCLAW_DATA_DIR
yara_rules_dir           SENTINELCLAW_YARA_RULES_DIR
file_entropy_threshold   SENTINELCLAW_FILE_ENTROPY_THRESHOLD
pcap_port_scan_threshold SENTINELCLAW_PCAP_PORT_SCAN_THRESHOLD
pcap_port_scan_high_threshold
                         SENTINELCLAW_PCAP_PORT_SCAN_HIGH_THRESHOLD
pcap_flow_high_volume    SENTINELCLAW_PCAP_FLOW_HIGH_VOLUME
pcap_beacon_min_packets  SENTINELCLAW_PCAP_BEACON_MIN_PACKETS
pcap_beacon_max_cv       SENTINELCLAW_PCAP_BEACON_MAX_CV
logon_failure_threshold  SENTINELCLAW_LOGON_FAILURE_THRESHOLD
report_max_findings      SENTINELCLAW_REPORT_MAX_FINDINGS
max_windows_events       SENTINELCLAW_MAX_WINDOWS_EVENTS
max_events_print         SENTINELCLAW_MAX_EVENTS_PRINT
max_file_analysis_size   SENTINELCLAW_MAX_FILE_ANALYSIS_SIZE
max_dir_files            SENTINELCLAW_MAX_DIR_FILES
max_evtx_events          SENTINELCLAW_MAX_EVTX_EVENTS
max_pcap_packets         SENTINELCLAW_MAX_PCAP_PACKETS
max_pcap_flows           SENTINELCLAW_MAX_PCAP_FLOWS
correlation_window_hours SENTINELCLAW_CORRELATION_WINDOW_HOURS
ollama_url               SENTINELCLAW_OLLAMA_URL
ollama_model             SENTINELCLAW_OLLAMA_MODEL
ollama_timeout           SENTINELCLAW_OLLAMA_TIMEOUT
ollama_retries           SENTINELCLAW_OLLAMA_RETRIES
ollama_retry_backoff_seconds
                         SENTINELCLAW_OLLAMA_RETRY_BACKOFF_SECONDS
ollama_max_response_bytes
                         SENTINELCLAW_OLLAMA_MAX_RESPONSE_BYTES
ollama_token_budget      SENTINELCLAW_OLLAMA_TOKEN_BUDGET
ollama_evidence_max_chars
                         SENTINELCLAW_OLLAMA_EVIDENCE_MAX_CHARS
intel_bundle_path        SENTINELCLAW_INTEL_BUNDLE_PATH
max_intel_bundle_size_bytes
                         SENTINELCLAW_MAX_INTEL_BUNDLE_SIZE_BYTES
=======================  =====================================

TOML keys use the plain setting names (``file_entropy_threshold = 7.5``
etc.). The directory keys accept filesystem paths; ``intel_bundle_path``
accepts the path of a local STIX/OpenIOC intel bundle (optional);
all other keys accept their declared scalar types.

``max_intel_bundle_size_bytes`` caps the size of the optional offline
threat-intel bundle (default 256 MiB); larger bundles are skipped with
an operational warning and must be a positive integer.

``ollama_token_budget`` is an approximate prompt-token budget for the
AI evidence section; SentinelClaw converts it with a documented
4-chars-per-token heuristic and stops adding evidence once the budget
is consumed. ``ollama_evidence_max_chars`` caps each individual
evidence string. ``ollama_retries`` is the number of additional
attempts after the first request; ``ollama_retry_backoff_seconds`` is
the delay between attempts. ``ollama_max_response_bytes`` caps the
HTTP response body read from Ollama.

``get_settings()`` is the production entry point. It caches the loaded
:class:`Settings` and transparently reloads when the relevant
``SENTINELCLAW_*`` environment changes (e.g. under tests).
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sentinelclaw.config.paths import (
    get_data_directory,
    get_report_directory,
    get_rules_directory,
    get_yara_rules_directory,
)

CONFIG_ENV_VAR = "SENTINELCLAW_CONFIG"
ENV_PREFIX = "SENTINELCLAW_"
CWD_CONFIG_FILENAME = "sentinelclaw.toml"
USER_CONFIG_PATH = Path.home() / ".config" / "sentinelclaw" / "config.toml"

SCALAR_FIELDS = frozenset(
    {
        "file_entropy_threshold",
        "pcap_port_scan_threshold",
        "pcap_port_scan_high_threshold",
        "pcap_flow_high_volume",
        "pcap_beacon_min_packets",
        "pcap_beacon_max_cv",
        "logon_failure_threshold",
        "report_max_findings",
        "max_windows_events",
        "max_events_print",
        "max_file_analysis_size",
        "max_dir_files",
        "max_evtx_events",
        "max_pcap_packets",
        "max_pcap_flows",
        "correlation_window_hours",
        "ollama_url",
        "ollama_model",
        "ollama_timeout",
        "ollama_retries",
        "ollama_retry_backoff_seconds",
        "ollama_max_response_bytes",
        "ollama_token_budget",
        "ollama_evidence_max_chars",
        "max_intel_bundle_size_bytes",
    }
)

DIRECTORY_FIELDS = frozenset(
    {
        "rules_dir",
        "report_dir",
        "data_dir",
        "yara_rules_dir",
    }
)

# P4-25: file-path settings with no default (absent means the
# feature is disabled). Unlike directory settings, an empty value
# stays ``None`` instead of resolving to a package default.
FILE_FIELDS = frozenset(
    {
        "intel_bundle_path",
    }
)

_KNOWN_FIELDS = (
    SCALAR_FIELDS | DIRECTORY_FIELDS | FILE_FIELDS
)


def env_var_name(field: str) -> str:
    """Return the environment variable name for a settings field."""
    return ENV_PREFIX + field.upper()


@dataclass(frozen=True)
class Settings:
    """Resolved SentinelClaw configuration."""

    rules_dir: Path | None = None
    report_dir: Path | None = None
    data_dir: Path | None = None
    yara_rules_dir: Path | None = None
    file_entropy_threshold: float = 7.2
    pcap_port_scan_threshold: int = 20
    pcap_port_scan_high_threshold: int = 100
    pcap_flow_high_volume: int = 5000
    pcap_beacon_min_packets: int = 10
    pcap_beacon_max_cv: float = 0.5
    logon_failure_threshold: int = 5
    report_max_findings: int = 50
    max_windows_events: int = 200
    max_events_print: int = 100
    max_file_analysis_size: int = 100 * 1024 * 1024
    max_dir_files: int = 100
    max_evtx_events: int = 2000
    max_pcap_packets: int = 2000000
    max_pcap_flows: int = 100000
    correlation_window_hours: int = 24
    ollama_url: str = "http://127.0.0.1:11434/api/generate"
    ollama_model: str = "qwen3:14b"
    ollama_timeout: int = 900
    ollama_retries: int = 1
    ollama_retry_backoff_seconds: float = 2.0
    ollama_max_response_bytes: int = 200000
    ollama_token_budget: int = 8000
    ollama_evidence_max_chars: int = 2000
    intel_bundle_path: Path | None = None
    max_intel_bundle_size_bytes: int = 268435456

    @property
    def resolved_rules_dir(self) -> Path:
        """Directory containing detection rules (env or package default)."""
        if self.rules_dir is not None:
            return self.rules_dir

        return get_rules_directory()

    @property
    def resolved_report_dir(self) -> Path:
        """Directory used for generated reports (env or CWD default)."""
        if self.report_dir is not None:
            return self.report_dir

        return get_report_directory()

    @property
    def resolved_data_dir(self) -> Path:
        """Directory used for local data files (env or CWD default)."""
        if self.data_dir is not None:
            return self.data_dir

        return get_data_directory()

    @property
    def resolved_yara_rules_dir(self) -> Path:
        """Directory containing optional YARA rules (env or package default)."""
        if self.yara_rules_dir is not None:
            return self.yara_rules_dir

        return get_yara_rules_directory()


def discover_config_file() -> Path | None:
    """Locate the TOML configuration file, if any exists."""
    explicit = os.environ.get(
        CONFIG_ENV_VAR
    )

    if explicit:
        path = Path(
            explicit
        ).expanduser()

        if path.is_file():
            return path

        return None

    cwd_config = Path.cwd() / CWD_CONFIG_FILENAME

    if cwd_config.is_file():
        return cwd_config

    if USER_CONFIG_PATH.is_file():
        return USER_CONFIG_PATH

    return None


def _validate_toml_keys(
    data: dict[str, object],
    path: Path,
) -> None:
    unknown = sorted(
        set(data) - _KNOWN_FIELDS
    )

    if unknown:
        raise ValueError(
            "Unknown setting(s) in "
            f"{path}: {', '.join(unknown)}"
        )


def _invalid_toml(
    path: Path,
    field: str,
    value: object,
    expected: str,
) -> ValueError:
    return ValueError(
        f"Config file {path}: setting '{field}' "
        f"must be {expected}, got "
        f"{type(value).__name__}"
    )


def _invalid_env(
    field: str,
    value: str,
    expected: str,
) -> ValueError:
    return ValueError(
        f"Environment variable {env_var_name(field)} "
        f"must be {expected}, got {value!r}"
    )


def _env_value(
    field: str,
) -> str | None:
    return os.environ.get(
        env_var_name(field)
    )


def _resolve_int(
    field: str,
    toml_value: object,
    path: Path | None,
    default: int,
) -> int:
    env_value = _env_value(
        field
    )

    if env_value is not None:
        try:
            return int(
                env_value
            )

        except ValueError as exc:
            raise _invalid_env(
                field,
                env_value,
                "an integer",
            ) from exc

    if isinstance(
        toml_value,
        bool,
    ):
        raise _invalid_toml(
            path
            if path is not None
            else Path("<config>"),
            field,
            toml_value,
            "an integer",
        )

    if isinstance(
        toml_value,
        int,
    ):
        return toml_value

    if toml_value is not None:
        raise _invalid_toml(
            path
            if path is not None
            else Path("<config>"),
            field,
            toml_value,
            "an integer",
        )

    return default


def _resolve_positive_int(
    field: str,
    toml_value: object,
    path: Path | None,
    default: int,
) -> int:
    value = _resolve_int(
        field,
        toml_value,
        path,
        default,
    )

    if value <= 0:
        env_value = _env_value(
            field
        )

        if env_value is not None:
            raise _invalid_env(
                field,
                env_value,
                "a positive integer",
            )

        raise _invalid_toml(
            path
            if path is not None
            else Path("<config>"),
            field,
            value,
            "a positive integer",
        )

    return value


def _resolve_float(
    field: str,
    toml_value: object,
    path: Path | None,
    default: float,
) -> float:
    env_value = _env_value(
        field
    )

    if env_value is not None:
        try:
            return float(
                env_value
            )

        except ValueError as exc:
            raise _invalid_env(
                field,
                env_value,
                "a number",
            ) from exc

    if isinstance(
        toml_value,
        bool,
    ):
        raise _invalid_toml(
            path
            if path is not None
            else Path("<config>"),
            field,
            toml_value,
            "a number",
        )

    if isinstance(
        toml_value,
        (
            int,
            float,
        ),
    ):
        return float(
            toml_value
        )

    if toml_value is not None:
        raise _invalid_toml(
            path
            if path is not None
            else Path("<config>"),
            field,
            toml_value,
            "a number",
        )

    return default


def _resolve_str(
    field: str,
    toml_value: object,
    path: Path | None,
    default: str,
) -> str:
    env_value = _env_value(
        field
    )

    if env_value is not None:
        return env_value

    if isinstance(
        toml_value,
        str,
    ):
        return toml_value

    if toml_value is not None:
        raise _invalid_toml(
            path
            if path is not None
            else Path("<config>"),
            field,
            toml_value,
            "a string",
        )

    return default


def _resolve_directory(
    field: str,
    toml_value: object,
    path: Path | None,
    default_factory: Callable[[], Path],
) -> Path:
    env_value = _env_value(
        field
    )

    if env_value is not None:
        return default_factory()

    if isinstance(
        toml_value,
        str,
    ):
        return Path(
            toml_value
        ).expanduser().resolve()

    if toml_value is not None:
        raise _invalid_toml(
            path
            if path is not None
            else Path("<config>"),
            field,
            toml_value,
            "a string path",
        )

    return default_factory()


def _resolve_optional_file(
    field: str,
    toml_value: object,
    path: Path | None,
) -> Path | None:
    env_value = _env_value(
        field
    )

    if env_value is not None:
        return Path(
            env_value
        ).expanduser().resolve()

    if isinstance(
        toml_value,
        str,
    ):
        return Path(
            toml_value
        ).expanduser().resolve()

    if toml_value is not None:
        raise _invalid_toml(
            path
            if path is not None
            else Path("<config>"),
            field,
            toml_value,
            "a string path",
        )

    return None


def _read_toml(
    path: Path,
) -> dict[str, object]:
    try:
        with path.open(
            "rb"
        ) as file:
            data = tomllib.load(
                file
            )

    except OSError as exc:
        raise ValueError(
            f"Unable to read config file {path}: {exc}"
        ) from exc

    except tomllib.TOMLDecodeError as exc:
        raise ValueError(
            f"Invalid TOML in config file {path}: {exc}"
        ) from exc

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            f"Config file {path} must contain a TOML table"
        )

    _validate_toml_keys(
        data,
        path,
    )

    return data


def load_settings(
    config_file: Path | None = None,
) -> Settings:
    """
    Load settings from defaults, an optional TOML file, and env vars.

    ``config_file`` forces a specific file; when ``None`` the file is
    discovered via :func:`discover_config_file`. A missing file simply
    yields built-in defaults.
    """
    path = (
        config_file
        if config_file is not None
        else discover_config_file()
    )

    if (
        path is not None
        and not path.is_file()
    ):
        path = None

    toml_data: dict[str, object] = {}

    if path is not None:
        toml_data = _read_toml(
            path
        )

    return Settings(
        rules_dir=_resolve_directory(
            "rules_dir",
            toml_data.get(
                "rules_dir"
            ),
            path,
            get_rules_directory,
        ),
        report_dir=_resolve_directory(
            "report_dir",
            toml_data.get(
                "report_dir"
            ),
            path,
            get_report_directory,
        ),
        data_dir=_resolve_directory(
            "data_dir",
            toml_data.get(
                "data_dir"
            ),
            path,
            get_data_directory,
        ),
        yara_rules_dir=_resolve_directory(
            "yara_rules_dir",
            toml_data.get(
                "yara_rules_dir"
            ),
            path,
            get_yara_rules_directory,
        ),
        file_entropy_threshold=_resolve_float(
            "file_entropy_threshold",
            toml_data.get(
                "file_entropy_threshold"
            ),
            path,
            7.2,
        ),
        pcap_port_scan_threshold=_resolve_int(
            "pcap_port_scan_threshold",
            toml_data.get(
                "pcap_port_scan_threshold"
            ),
            path,
            20,
        ),
        pcap_port_scan_high_threshold=_resolve_int(
            "pcap_port_scan_high_threshold",
            toml_data.get(
                "pcap_port_scan_high_threshold"
            ),
            path,
            100,
        ),
        pcap_flow_high_volume=_resolve_int(
            "pcap_flow_high_volume",
            toml_data.get(
                "pcap_flow_high_volume"
            ),
            path,
            5000,
        ),
        pcap_beacon_min_packets=_resolve_int(
            "pcap_beacon_min_packets",
            toml_data.get(
                "pcap_beacon_min_packets"
            ),
            path,
            10,
        ),
        pcap_beacon_max_cv=_resolve_float(
            "pcap_beacon_max_cv",
            toml_data.get(
                "pcap_beacon_max_cv"
            ),
            path,
            0.5,
        ),
        logon_failure_threshold=_resolve_int(
            "logon_failure_threshold",
            toml_data.get(
                "logon_failure_threshold"
            ),
            path,
            5,
        ),
        report_max_findings=_resolve_int(
            "report_max_findings",
            toml_data.get(
                "report_max_findings"
            ),
            path,
            50,
        ),
        max_windows_events=_resolve_int(
            "max_windows_events",
            toml_data.get(
                "max_windows_events"
            ),
            path,
            200,
        ),
        max_events_print=_resolve_int(
            "max_events_print",
            toml_data.get(
                "max_events_print"
            ),
            path,
            100,
        ),
        max_file_analysis_size=_resolve_int(
            "max_file_analysis_size",
            toml_data.get(
                "max_file_analysis_size"
            ),
            path,
            100 * 1024 * 1024,
        ),
        max_dir_files=_resolve_int(
            "max_dir_files",
            toml_data.get(
                "max_dir_files"
            ),
            path,
            100,
        ),
        max_evtx_events=_resolve_int(
            "max_evtx_events",
            toml_data.get(
                "max_evtx_events"
            ),
            path,
            2000,
        ),
        max_pcap_packets=_resolve_int(
            "max_pcap_packets",
            toml_data.get(
                "max_pcap_packets"
            ),
            path,
            2000000,
        ),
        max_pcap_flows=_resolve_int(
            "max_pcap_flows",
            toml_data.get(
                "max_pcap_flows"
            ),
            path,
            100000,
        ),
        correlation_window_hours=_resolve_int(
            "correlation_window_hours",
            toml_data.get(
                "correlation_window_hours"
            ),
            path,
            24,
        ),
        ollama_url=_resolve_str(
            "ollama_url",
            toml_data.get(
                "ollama_url"
            ),
            path,
            "http://127.0.0.1:11434/api/generate",
        ),
        ollama_model=_resolve_str(
            "ollama_model",
            toml_data.get(
                "ollama_model"
            ),
            path,
            "qwen3:14b",
        ),
        ollama_timeout=_resolve_int(
            "ollama_timeout",
            toml_data.get(
                "ollama_timeout"
            ),
            path,
            900,
        ),
        ollama_retries=_resolve_int(
            "ollama_retries",
            toml_data.get(
                "ollama_retries"
            ),
            path,
            1,
        ),
        ollama_retry_backoff_seconds=_resolve_float(
            "ollama_retry_backoff_seconds",
            toml_data.get(
                "ollama_retry_backoff_seconds"
            ),
            path,
            2.0,
        ),
        ollama_max_response_bytes=_resolve_int(
            "ollama_max_response_bytes",
            toml_data.get(
                "ollama_max_response_bytes"
            ),
            path,
            200000,
        ),
        ollama_token_budget=_resolve_int(
            "ollama_token_budget",
            toml_data.get(
                "ollama_token_budget"
            ),
            path,
            8000,
        ),
        ollama_evidence_max_chars=_resolve_int(
            "ollama_evidence_max_chars",
            toml_data.get(
                "ollama_evidence_max_chars"
            ),
            path,
            2000,
        ),
        intel_bundle_path=_resolve_optional_file(
            "intel_bundle_path",
            toml_data.get(
                "intel_bundle_path"
            ),
            path,
        ),
        max_intel_bundle_size_bytes=_resolve_positive_int(
            "max_intel_bundle_size_bytes",
            toml_data.get(
                "max_intel_bundle_size_bytes"
            ),
            path,
            268435456,
        ),
    )


_CACHE_KEY: tuple[
    tuple[tuple[str, str], ...],
    str | None,
] | None = None
_CACHED_SETTINGS: Settings | None = None


def _env_signature() -> tuple[
    tuple[tuple[str, str], ...],
    str | None,
]:
    env_snapshot = tuple(
        sorted(
            (
                key,
                value,
            )
            for key, value in os.environ.items()
            if key.startswith(
                ENV_PREFIX
            )
        )
    )

    return (
        env_snapshot,
        str(
            discover_config_file()
        ),
    )


def get_settings() -> Settings:
    """
    Return the cached :class:`Settings`, reloading when needed.

    The cache is keyed on the ``SENTINELCLAW_*`` environment snapshot
    and the discovered config path, so environment changes made by
    tests or shells are honored on the next call.
    """
    global _CACHE_KEY, _CACHED_SETTINGS

    signature = _env_signature()

    if (
        _CACHED_SETTINGS is not None
        and _CACHE_KEY == signature
    ):
        return _CACHED_SETTINGS

    loaded = load_settings()

    _CACHE_KEY = signature
    _CACHED_SETTINGS = loaded

    return loaded
