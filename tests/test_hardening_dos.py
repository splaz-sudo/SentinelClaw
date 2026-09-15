"""DoS/ReDoS hardening tests for logs, pcap flow names, and rule regexes.

These tests cover the audit findings fixed in the security-hardening
branch:

* unbounded log analysis (file-size skip, per-line truncation, match cap)
* quadratic per-flow DNS/TLS name accumulation in the pcap analyzer
* ReDoS from rule-supplied regexes (timeout + truncation + pattern cap)
"""

import logging
import time

import pytest

from sentinelclaw.config.settings import Settings
from sentinelclaw.engine import rule_engine
from sentinelclaw.engine.rule_engine import (
    MAX_REGEX_INPUT_CHARS,
    MAX_REGEX_PATTERN_CHARS,
    match_matches,
    run_rules,
    validate_rule,
)
from sentinelclaw.tools import pcap_analyzer
from sentinelclaw.tools.log_analyzer import (
    MAX_LOG_LINE_CHARS,
    MAX_LOG_MATCHES,
    analyze_log_file,
)

# --- Finding 1: unbounded log analysis -------------------------------


def test_oversized_log_is_skipped(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "SENTINELCLAW_MAX_FILE_ANALYSIS_SIZE",
        "1024",
    )

    log_path = tmp_path / "oversized.log"

    log_path.write_text(
        "failed login\n" * 200,
        encoding="utf-8",
    )

    assert log_path.stat().st_size > 1024

    result = analyze_log_file(
        str(log_path)
    )

    assert "error" not in result
    assert result["skipped"] is True
    assert result["skipped_reason"] == "too large"
    assert result["size_bytes"] == log_path.stat().st_size
    assert result["total_lines"] == 0
    assert result["suspicious_matches"] == 0
    assert result["matches"] == []
    assert result["events"] == []
    assert result["truncated"] is False


def test_log_within_cap_is_analyzed_normally(
    tmp_path,
) -> None:
    log_path = tmp_path / "normal.log"

    log_path.write_text(
        "2026-09-08T09:10:00+00:00 sshd[1234]: "
        "Failed login for root from 10.0.0.5 port 22 ssh2\n"
        "2026-09-08T09:16:00+00:00 sshd[1234]: "
        "Accepted publickey for analyst\n",
        encoding="utf-8",
    )

    result = analyze_log_file(
        str(log_path)
    )

    assert "error" not in result
    assert "skipped" not in result
    assert result["total_lines"] == 2
    assert result["suspicious_matches"] == 1
    assert result["truncated"] is False
    assert result["truncation_reason"] is None

    event = result["events"][0]

    assert event["event_type"] == "failed_login"
    assert event["username"] == "root"
    assert event["ip"] == "10.0.0.5"


def test_long_log_line_is_truncated_for_match_and_retention(
    tmp_path,
) -> None:
    log_path = tmp_path / "longline.log"

    log_path.write_text(
        "failed login " + "A" * 100_000 + "\n"
        + "B" * 9000 + "failed login\n",
        encoding="utf-8",
    )

    result = analyze_log_file(
        str(log_path)
    )

    assert result["total_lines"] == 2
    assert result["suspicious_matches"] == 1
    assert result["truncated"] is False

    match = result["matches"][0]

    assert match["line_number"] == 1
    assert len(match["text"]) == MAX_LOG_LINE_CHARS
    assert len(result["events"][0]["message"]) == MAX_LOG_LINE_CHARS

    # The keyword past the truncation point on line 2 is not matched,
    # which proves matching itself ran on the truncated prefix.
    assert all(
        item["line_number"] != 2
        for item in result["matches"]
    )


def test_log_match_cap_truncates_and_stops(
    tmp_path,
) -> None:
    log_path = tmp_path / "spam.log"

    log_path.write_text(
        "malware detected\n" * (MAX_LOG_MATCHES + 25),
        encoding="utf-8",
    )

    result = analyze_log_file(
        str(log_path)
    )

    assert "error" not in result
    assert result["truncated"] is True
    assert result["truncation_reason"] == (
        f"match limit reached ({MAX_LOG_MATCHES})"
    )
    assert result["suspicious_matches"] == MAX_LOG_MATCHES
    assert len(result["matches"]) == MAX_LOG_MATCHES
    assert len(result["events"]) == MAX_LOG_MATCHES


# --- Finding 2: quadratic pcap per-flow name accumulation ------------


class _FakeAddress:
    def __init__(
        self,
        address: str,
    ) -> None:
        self.address = address

    def __str__(self) -> str:
        return self.address


class _FakeIPLayer:
    def __init__(
        self,
        source: str,
        destination: str,
    ) -> None:
        self.src = _FakeAddress(source)
        self.dst = _FakeAddress(destination)


class _FakeTransport:
    def __init__(
        self,
        sport: int,
        dport: int,
    ) -> None:
        self.sport = sport
        self.dport = dport
        self.flags = "S"


class _FakeIP:
    pass


class _FakeTCP:
    pass


class _FakePacket:
    def __init__(
        self,
        source: str,
        destination: str,
        qname: str | None = None,
        sni: str | None = None,
    ) -> None:
        self._ip = _FakeIPLayer(source, destination)
        self._tcp = _FakeTransport(49152, 53)
        self.qname = qname
        self.sni = sni

    def __contains__(
        self,
        key: object,
    ) -> bool:
        return key is pcap_analyzer.IP or key is pcap_analyzer.TCP

    def __getitem__(
        self,
        key: object,
    ) -> object:
        if key is pcap_analyzer.IP:
            return self._ip

        return self._tcp

    def __len__(self) -> int:
        return 64


class _FakeReader:
    def __init__(
        self,
        packets: list[_FakePacket],
    ) -> None:
        self._packets = iter(packets)

    def __enter__(self) -> "_FakeReader":
        return self

    def __exit__(
        self,
        *args: object,
    ) -> bool:
        return False

    def __iter__(self):
        return self._packets


def build_fake_capture(
    tmp_path,
    monkeypatch,
    packets: list[_FakePacket],
):
    monkeypatch.setattr(
        pcap_analyzer,
        "IP",
        _FakeIP,
    )
    monkeypatch.setattr(
        pcap_analyzer,
        "TCP",
        _FakeTCP,
    )
    monkeypatch.setattr(
        pcap_analyzer,
        "UDP",
        None,
    )
    monkeypatch.setattr(
        pcap_analyzer,
        "IPv6",
        None,
    )
    monkeypatch.setattr(
        pcap_analyzer,
        "PcapReader",
        lambda path: _FakeReader(packets),
    )
    monkeypatch.setattr(
        pcap_analyzer,
        "_packet_dns_queries",
        lambda packet: (
            [packet.qname]
            if packet.qname
            else []
        ),
    )
    monkeypatch.setattr(
        pcap_analyzer,
        "_packet_tls_sni",
        lambda packet: packet.sni,
    )
    monkeypatch.setattr(
        pcap_analyzer,
        "get_settings",
        lambda: Settings(
            max_pcap_packets=1000000,
            max_pcap_flows=100000,
        ),
    )

    capture = tmp_path / "capture.pcap"

    capture.write_bytes(b"\x00" * 64)

    return capture


def test_pcap_unique_dns_names_capped_and_ordered(
    tmp_path,
    monkeypatch,
) -> None:
    packets = [
        _FakePacket(
            "10.0.0.1",
            "8.8.8.8",
            qname=f"h{index}.example.com",
        )
        for index in range(10000)
    ]

    capture = build_fake_capture(
        tmp_path,
        monkeypatch,
        packets,
    )

    start = time.monotonic()

    result = pcap_analyzer.analyze_pcap(
        str(capture)
    )

    elapsed = time.monotonic() - start

    assert "error" not in result
    assert elapsed < 5.0
    assert result["packets_total"] == 10000
    assert result["dns_query_count"] == (
        pcap_analyzer.MAX_FLOW_DNS_NAMES
    )
    assert result["dns_names_truncated"] is True
    assert result["tls_snis_truncated"] is False
    assert result["truncated"] is True
    assert "DNS name" in str(
        result["truncation_reason"]
    )

    flow = result["flows"][0]
    queries = flow["dns_queries"]

    assert len(queries) == pcap_analyzer.MAX_FLOW_DNS_NAMES
    assert queries == [
        f"h{index}.example.com"
        for index in range(
            pcap_analyzer.MAX_FLOW_DNS_NAMES
        )
    ]


def test_pcap_duplicate_dns_names_are_deduplicated(
    tmp_path,
    monkeypatch,
) -> None:
    packets = [
        _FakePacket(
            "10.0.0.1",
            "8.8.8.8",
            qname="dup.example.com",
        )
        for _ in range(5000)
    ]

    capture = build_fake_capture(
        tmp_path,
        monkeypatch,
        packets,
    )

    result = pcap_analyzer.analyze_pcap(
        str(capture)
    )

    assert "error" not in result
    assert result["dns_query_count"] == 1
    assert result["dns_names_truncated"] is False
    assert result["truncated"] is False

    flow = result["flows"][0]

    assert flow["dns_queries"] == ["dup.example.com"]


def test_pcap_tls_sni_global_cap_truncates(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        pcap_analyzer,
        "MAX_FLOW_TLS_SNIS",
        10,
    )
    monkeypatch.setattr(
        pcap_analyzer,
        "MAX_PCAP_FLOW_NAMES",
        3,
    )

    packets = [
        _FakePacket(
            "10.0.0.1",
            "198.51.100.7",
            sni=f"sni-{index}.example.net",
        )
        for index in range(5)
    ]

    capture = build_fake_capture(
        tmp_path,
        monkeypatch,
        packets,
    )

    result = pcap_analyzer.analyze_pcap(
        str(capture)
    )

    assert "error" not in result
    assert result["tls_sni_count"] == 3
    assert result["tls_snis_truncated"] is True
    assert result["truncated"] is True
    assert "global limit reached (3)" in str(
        result["truncation_reason"]
    )

    flow = result["flows"][0]

    assert flow["tls_snis"] == [
        "sni-0.example.net",
        "sni-1.example.net",
        "sni-2.example.net",
    ]


def test_pcap_flow_record_schema_unchanged(
    tmp_path,
    monkeypatch,
) -> None:
    packets = [
        _FakePacket(
            "10.0.0.1",
            "8.8.8.8",
            qname="one.example.com",
        ),
    ]

    capture = build_fake_capture(
        tmp_path,
        monkeypatch,
        packets,
    )

    result = pcap_analyzer.analyze_pcap(
        str(capture)
    )

    assert set(
        result["flows"][0]
    ) == {
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "protocol",
        "packet_count",
        "first_seen",
        "last_seen",
        "iat_mean_seconds",
        "iat_cv",
        "syn_only_count",
        "tcp_flags_seen",
        "dns_queries",
        "tls_snis",
    }

    assert isinstance(
        result["flows"][0]["dns_queries"],
        list,
    )

    for key in (
        "packets_total",
        "unique_flows",
        "dns_query_count",
        "tls_sni_count",
        "truncated",
        "truncation_reason",
    ):
        assert key in result


# --- Finding 3: ReDoS from rule-supplied regexes ---------------------


def regex_matches_rule(
    value: object,
) -> dict:
    return {
        "id": "REGEX-DOS-001",
        "title": "Regex hardening test rule",
        "description": "Synthetic regex test rule.",
        "category": "process",
        "severity": "medium",
        "confidence": "medium",
        "conditions": [
            {
                "field": "command_line",
                "operator": "matches",
                "value": value,
            }
        ],
    }


def test_catastrophic_regex_times_out_as_non_match(
    caplog,
) -> None:
    if rule_engine._regex is None:
        pytest.skip(
            "regex module is not installed"
        )

    # The hostile suffix sits within the truncation cap so the
    # catastrophic pattern still receives its dangerous shape.
    text = "a" * 8000 + "b" + "a" * 42000

    with caplog.at_level(
        logging.WARNING,
        logger="sentinelclaw.engine.rule_engine",
    ):
        start = time.monotonic()

        matched = match_matches(
            text,
            "(a+)+$",
        )

        elapsed = time.monotonic() - start

    assert matched is False
    assert elapsed < 1.0
    assert any(
        "timed out" in record.message
        for record in caplog.records
    )


def test_regex_timeout_warns_once_per_pattern(
    monkeypatch,
    caplog,
) -> None:
    if rule_engine._regex is None:
        pytest.skip(
            "regex module is not installed"
        )

    monkeypatch.setattr(
        rule_engine,
        "_REGEX_TIMEOUT_PATTERNS",
        set(),
    )

    text = "a" * 8000 + "b" + "a" * 42000

    with caplog.at_level(
        logging.WARNING,
        logger="sentinelclaw.engine.rule_engine",
    ):
        assert match_matches(text, "(a+)+$") is False
        assert match_matches(text, "(a+)+$") is False

    timeout_warnings = [
        record
        for record in caplog.records
        if "timed out" in record.message
    ]

    assert len(timeout_warnings) == 1


def test_regex_input_is_truncated_to_cap() -> None:
    assert MAX_REGEX_INPUT_CHARS == 8192

    assert (
        match_matches(
            "x" * MAX_REGEX_INPUT_CHARS + "NEEDLE",
            "NEEDLE",
        )
        is False
    )

    assert match_matches(
        "x" * (MAX_REGEX_INPUT_CHARS - 10) + "NEEDLE",
        "NEEDLE",
    )

    assert match_matches(
        "ordinary powershell -enc AAA",
        "powershell",
    )


def test_overlong_regex_pattern_rejected_at_validation() -> None:
    overlong = "a" * (
        MAX_REGEX_PATTERN_CHARS + 1
    )

    ok, reason = validate_rule(
        regex_matches_rule(overlong)
    )

    assert not ok
    assert "too long" in reason

    boundary = "a" * MAX_REGEX_PATTERN_CHARS

    ok, reason = validate_rule(
        regex_matches_rule(boundary)
    )

    assert ok, reason


def test_normal_matches_rule_still_fires() -> None:
    rule = regex_matches_rule(
        r"powershell.*encoded"
    )

    findings = run_rules(
        [rule],
        [
            {
                "command_line": (
                    "powershell -encodedCommand x"
                )
            }
        ],
        category="process",
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "REGEX-DOS-001"


def test_stdlib_fallback_still_truncates_and_warns_once(
    monkeypatch,
    caplog,
) -> None:
    monkeypatch.setattr(
        rule_engine,
        "_regex",
        None,
    )
    monkeypatch.setattr(
        rule_engine,
        "_REGEX_FALLBACK_WARNED",
        False,
    )

    with caplog.at_level(
        logging.WARNING,
        logger="sentinelclaw.engine.rule_engine",
    ):
        assert match_matches("foo", "fo+") is True
        assert match_matches("bar", "fo+") is False

        assert (
            match_matches(
                "x" * MAX_REGEX_INPUT_CHARS + "NEEDLE",
                "NEEDLE",
            )
            is False
        )

    fallback_warnings = [
        record
        for record in caplog.records
        if "regex module is unavailable"
        in record.message
    ]

    assert len(fallback_warnings) == 1
