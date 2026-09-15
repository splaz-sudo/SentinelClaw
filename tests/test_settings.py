import os
from pathlib import Path

import pytest

from sentinelclaw.config.paths import (
    get_data_directory,
    get_report_directory,
    get_rules_directory,
)
from sentinelclaw.config.settings import (
    DIRECTORY_FIELDS,
    SCALAR_FIELDS,
    Settings,
    get_settings,
    load_settings,
)


def clear_settings_env(monkeypatch) -> None:
    """Remove all SENTINELCLAW_* environment variables."""
    for key in list(os.environ):
        if key.startswith("SENTINELCLAW_"):
            monkeypatch.delenv(
                key,
                raising=False,
            )


def test_defaults_when_no_file_or_env(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    settings = load_settings(
        config_file=tmp_path / "does-not-exist.toml"
    )

    assert settings.file_entropy_threshold == 7.2
    assert settings.pcap_port_scan_threshold == 20
    assert settings.pcap_port_scan_high_threshold == 100
    assert settings.pcap_flow_high_volume == 5000
    assert settings.logon_failure_threshold == 5
    assert settings.max_windows_events == 200
    assert settings.max_events_print == 100
    assert settings.ollama_url == "http://127.0.0.1:11434/api/generate"
    assert settings.ollama_model == "qwen3:14b"
    assert settings.ollama_timeout == 900

    assert settings.resolved_rules_dir == get_rules_directory()
    assert settings.resolved_report_dir == get_report_directory()
    assert settings.resolved_data_dir == get_data_directory()


def test_toml_file_overrides_defaults(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "file_entropy_threshold = 6.5\n"
        "pcap_flow_high_volume = 2500\n"
        "ollama_model = \"qwen2:7b\"\n"
        "ollama_timeout = 120\n",
        encoding="utf-8",
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.file_entropy_threshold == 6.5
    assert settings.pcap_flow_high_volume == 2500
    assert settings.ollama_model == "qwen2:7b"
    assert settings.ollama_timeout == 120

    assert settings.pcap_port_scan_threshold == 20
    assert settings.ollama_url == "http://127.0.0.1:11434/api/generate"


def test_toml_discovery_via_env_var(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "custom.toml"

    config_file.write_text(
        "pcap_port_scan_threshold = 33\n",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_CONFIG",
        str(config_file),
    )

    settings = load_settings()

    assert settings.pcap_port_scan_threshold == 33


def test_missing_explicit_config_is_defaults(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    monkeypatch.setenv(
        "SENTINELCLAW_CONFIG",
        str(tmp_path / "missing.toml"),
    )

    settings = load_settings()

    assert settings.pcap_port_scan_threshold == 20


def test_env_var_beats_toml(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "pcap_port_scan_threshold = 30\n",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_PCAP_PORT_SCAN_THRESHOLD",
        "55",
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.pcap_port_scan_threshold == 55

    monkeypatch.delenv(
        "SENTINELCLAW_PCAP_PORT_SCAN_THRESHOLD"
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.pcap_port_scan_threshold == 30


def test_env_dir_overrides_toml(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "rules_dir = \"/toml/rules\"\n",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_RULES_DIR",
        str(tmp_path / "env-rules"),
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.resolved_rules_dir == (tmp_path / "env-rules").resolve()


def test_invalid_env_value_fails_loudly(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    monkeypatch.setenv(
        "SENTINELCLAW_OLLAMA_TIMEOUT",
        "not-a-number",
    )

    try:
        load_settings(
            config_file=tmp_path / "missing.toml"
        )
    except ValueError as exc:
        assert "SENTINELCLAW_OLLAMA_TIMEOUT" in str(exc)
    else:
        raise AssertionError(
            "expected ValueError for invalid env value"
        )


def test_unknown_toml_key_fails_loudly(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "bogus_setting = true\n",
        encoding="utf-8",
    )

    try:
        load_settings(
            config_file=config_file
        )
    except ValueError as exc:
        assert "bogus_setting" in str(exc)
    else:
        raise AssertionError(
            "expected ValueError for unknown TOML key"
        )


def test_get_settings_reloads_on_env_change(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    defaults = get_settings()

    assert defaults.ollama_model == "qwen3:14b"

    monkeypatch.setenv(
        "SENTINELCLAW_OLLAMA_MODEL",
        "llama3",
    )

    configured = get_settings()

    assert configured.ollama_model == "llama3"

    monkeypatch.delenv(
        "SENTINELCLAW_OLLAMA_MODEL"
    )

    restored = get_settings()

    assert restored.ollama_model == "qwen3:14b"


def test_pcap_detector_reads_configured_thresholds(monkeypatch) -> None:
    import sentinelclaw.detectors.pcap_detector as pcap_detector

    monkeypatch.setattr(
        pcap_detector,
        "get_settings",
        lambda: Settings(
            pcap_port_scan_threshold=5,
            pcap_port_scan_high_threshold=50,
        ),
    )

    low_candidate = {
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "unique_destination_ports": 5,
        "destination_ports": [1, 2, 3, 4, 5],
    }

    findings = pcap_detector.detect_tcp_port_scans(
        {
            "tcp_scan_candidates": [
                low_candidate
            ],
        }
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"

    high_candidate = {
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "unique_destination_ports": 60,
        "destination_ports": list(
            range(60)
        ),
    }

    findings = pcap_detector.detect_tcp_port_scans(
        {
            "tcp_scan_candidates": [
                high_candidate
            ],
        }
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_pcap_detector_respects_high_volume_setting(monkeypatch) -> None:
    import sentinelclaw.detectors.pcap_detector as pcap_detector

    monkeypatch.setattr(
        pcap_detector,
        "get_settings",
        lambda: Settings(
            pcap_flow_high_volume=50,
        ),
    )

    flow = {
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "packet_count": 50,
    }

    findings = pcap_detector.detect_high_volume_flows(
        {
            "flows": [
                flow
            ],
        }
    )

    assert len(findings) == 1

    below = {
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "packet_count": 49,
    }

    findings = pcap_detector.detect_high_volume_flows(
        {
            "flows": [
                below
            ],
        }
    )

    assert findings == []


def test_file_detector_reads_entropy_setting(monkeypatch) -> None:
    import sentinelclaw.detectors.file_detector as file_detector

    monkeypatch.setattr(
        file_detector,
        "get_settings",
        lambda: Settings(
            file_entropy_threshold=6.0,
        ),
    )

    file_info = {
        "path": "/tmp/sample.exe",
        "name": "sample.exe",
        "extension": ".exe",
        "is_pe_file": True,
        "entropy": 6.5,
    }

    findings = file_detector.analyze_file_findings(
        file_info
    )

    rule_ids = {
        finding["rule_id"]
        for finding in findings
    }

    assert "FILE-004" in rule_ids


def test_intel_bundle_path_from_env(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    bundle = tmp_path / "intel.json"

    monkeypatch.setenv(
        "SENTINELCLAW_INTEL_BUNDLE_PATH",
        str(bundle),
    )

    settings = load_settings()

    assert settings.intel_bundle_path == bundle.resolve()

    monkeypatch.delenv(
        "SENTINELCLAW_INTEL_BUNDLE_PATH"
    )

    assert load_settings().intel_bundle_path is None


def test_intel_bundle_path_from_toml(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "intel_bundle_path = \"/toml/intel.json\"\n",
        encoding="utf-8",
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.intel_bundle_path == Path("/toml/intel.json").resolve()


def test_settings_known_field_sets_are_complete() -> None:
    assert "rules_dir" in DIRECTORY_FIELDS
    assert "report_dir" in DIRECTORY_FIELDS
    assert "data_dir" in DIRECTORY_FIELDS
    assert "file_entropy_threshold" in SCALAR_FIELDS
    assert "pcap_port_scan_threshold" in SCALAR_FIELDS
    assert "ollama_timeout" in SCALAR_FIELDS
    assert "max_intel_bundle_size_bytes" in SCALAR_FIELDS


def test_max_intel_bundle_size_default(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    settings = load_settings(
        config_file=tmp_path / "missing.toml"
    )

    assert settings.max_intel_bundle_size_bytes == 268435456


def test_max_intel_bundle_size_toml_override(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "max_intel_bundle_size_bytes = 1024\n",
        encoding="utf-8",
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.max_intel_bundle_size_bytes == 1024


def test_max_intel_bundle_size_env_beats_toml(monkeypatch, tmp_path) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        "max_intel_bundle_size_bytes = 1024\n",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "SENTINELCLAW_MAX_INTEL_BUNDLE_SIZE_BYTES",
        "2048",
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.max_intel_bundle_size_bytes == 2048

    monkeypatch.delenv(
        "SENTINELCLAW_MAX_INTEL_BUNDLE_SIZE_BYTES"
    )

    settings = load_settings(
        config_file=config_file
    )

    assert settings.max_intel_bundle_size_bytes == 1024


@pytest.mark.parametrize(
    "value",
    (
        "0",
        "-1",
        "not-a-number",
    ),
)
def test_max_intel_bundle_size_invalid_env_rejected(
    monkeypatch,
    tmp_path,
    value,
) -> None:
    clear_settings_env(monkeypatch)

    monkeypatch.setenv(
        "SENTINELCLAW_MAX_INTEL_BUNDLE_SIZE_BYTES",
        value,
    )

    with pytest.raises(ValueError) as excinfo:
        load_settings(
            config_file=tmp_path / "missing.toml"
        )

    assert "SENTINELCLAW_MAX_INTEL_BUNDLE_SIZE_BYTES" in str(excinfo.value)


@pytest.mark.parametrize(
    "value",
    (
        "0",
        "-1",
        "true",
        "\"large\"",
    ),
)
def test_max_intel_bundle_size_invalid_toml_rejected(
    monkeypatch,
    tmp_path,
    value,
) -> None:
    clear_settings_env(monkeypatch)

    config_file = tmp_path / "sentinelclaw.toml"

    config_file.write_text(
        f"max_intel_bundle_size_bytes = {value}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_settings(
            config_file=config_file
        )

    assert "max_intel_bundle_size_bytes" in str(excinfo.value)
