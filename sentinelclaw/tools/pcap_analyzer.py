from __future__ import annotations

import logging
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelclaw.config.settings import get_settings
from sentinelclaw.tools.tls_parse import (
    decode_dns_qname,
    extract_sni_from_client_hello,
)

logger = logging.getLogger(
    __name__
)

# DoS guard: per-flow DNS/TLS name accumulation uses insertion-ordered
# dict-as-set membership (O(1) instead of the previous O(n) list scan)
# and is capped per flow and globally, so a crafted capture with a
# constant 5-tuple and ever-changing names cannot force quadratic
# membership scans or unbounded memory. Output order is the insertion
# order of the first occurrence of each unique name.
MAX_FLOW_DNS_NAMES = 64
MAX_FLOW_TLS_SNIS = 64
MAX_PCAP_FLOW_NAMES = 10000

# scapy classes are resolved lazily so that (a) module import never
# depends on scapy's dynamic ``scapy.all`` exports (which also keeps
# static type checks clean), (b) installs without scapy still import,
# and (c) the layered stand-ins used in tests keep working through the
# ``scapy.all`` fallback. Resolution is re-attempted on first use when
# the initial import-time attempt found no scapy (a later import may
# have installed the package or a test may have installed a stand-in).
IP: Any = None
IPv6: Any = None
TCP: Any = None
UDP: Any = None
PcapReader: Any = None


def _resolve_scapy_layers() -> None:
    global IP, IPv6, TCP, UDP, PcapReader

    if (
        TCP is not None
        and IP is not None
        and PcapReader is not None
    ):
        return

    try:
        import scapy.layers.inet as _scapy_inet_module

        IP = _scapy_inet_module.IP
        TCP = _scapy_inet_module.TCP
        UDP = _scapy_inet_module.UDP
    except Exception:
        pass

    try:
        import scapy.layers.inet6 as _scapy_inet6_module

        IPv6 = _scapy_inet6_module.IPv6
    except Exception:
        pass

    try:
        import scapy.utils as _scapy_utils_module

        PcapReader = _scapy_utils_module.PcapReader
    except Exception:
        pass

    if (
        IP is None
        or TCP is None
        or PcapReader is None
    ):
        # Fallback for environments that only expose the aggregated
        # ``scapy.all`` namespace (older scapy layouts and the layered
        # stand-ins used in tests).
        try:
            import scapy.all as _scapy_all_fallback

            if IP is None:
                IP = getattr(
                    _scapy_all_fallback,
                    "IP",
                    None,
                )

            if IPv6 is None:
                IPv6 = getattr(
                    _scapy_all_fallback,
                    "IPv6",
                    None,
                )

            if TCP is None:
                TCP = getattr(
                    _scapy_all_fallback,
                    "TCP",
                    None,
                )

            if UDP is None:
                UDP = getattr(
                    _scapy_all_fallback,
                    "UDP",
                    None,
                )

            if PcapReader is None:
                PcapReader = getattr(
                    _scapy_all_fallback,
                    "PcapReader",
                    None,
                )
        except Exception:
            pass


_resolve_scapy_layers()

# P4-21: DNS and TLS payload extraction is layered on scapy but must
# never break capture analysis when the optional layers are absent.
# ``haslayer`` is checked on each packet, so capture-only installs (and
# the scapy stand-ins used in tests) simply skip payload extraction.
_SCAPY_DNS: Any = None
_SCAPY_RAW: Any = None

try:
    import scapy.layers.dns as _scapy_dns_module

    _SCAPY_DNS = _scapy_dns_module.DNS
except Exception:
    pass

try:
    import scapy.packet as _scapy_packet_module

    _SCAPY_RAW = _scapy_packet_module.Raw
except Exception:
    pass


def _packet_epoch(packet) -> float | None:
    """Return the packet capture timestamp as epoch seconds, if any."""
    value = getattr(
        packet,
        "time",
        None,
    )

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _packet_dns_queries(packet) -> list[str]:
    """Return normalized query names carried by a DNS query packet."""
    if _SCAPY_DNS is None:
        return []

    if not hasattr(
        packet,
        "haslayer",
    ):
        return []

    try:
        if not packet.haslayer(_SCAPY_DNS):
            return []

        dns_layer = packet[_SCAPY_DNS]

        if int(
            getattr(
                dns_layer,
                "qr",
                1,
            )
        ) != 0:
            return []

        question = getattr(
            dns_layer,
            "qd",
            None,
        )

        if question is None:
            return []

        qname = getattr(
            question,
            "qname",
            None,
        )

        if not isinstance(
            qname,
            bytes,
        ):
            return []

        decoded = decode_dns_qname(qname)

        if decoded is None:
            return []

        return [decoded]
    except Exception:
        return []


def _packet_tls_sni(packet) -> str | None:
    """Return the SNI hostname from a TLS ClientHello, if present."""
    if _SCAPY_RAW is None:
        return None

    if not hasattr(
        packet,
        "haslayer",
    ):
        return None

    try:
        if not packet.haslayer(_SCAPY_RAW):
            return None

        raw_layer = packet[_SCAPY_RAW]

        load = getattr(
            raw_layer,
            "load",
            None,
        )

        if not isinstance(
            load,
            bytes,
        ):
            return None
    except Exception:
        return None

    return extract_sni_from_client_hello(load)


def _epoch_to_iso(
    epoch: float,
) -> str:
    return datetime.fromtimestamp(
        epoch,
        tz=timezone.utc,
    ).isoformat()


def _iat_variation(
    count: int,
    mean: float,
    m2: float,
) -> tuple[float | None, float | None]:
    """Return (mean seconds, coefficient of variation) of inter-arrival
    times for a flow, from streaming (Welford) accumulator values.

    The coefficient of variation needs at least two inter-arrival
    samples and a positive mean; otherwise ``None`` is returned so the
    beacon detector treats the flow as unmeasurable.
    """
    if count < 2 or mean <= 0:
        return None, None

    variance = m2 / (count - 1)

    if variance < 0:
        return None, None

    stddev = math.sqrt(variance)
    cv = stddev / mean

    return (
        round(mean, 6),
        round(cv, 4),
    )


def _syn_only_flags(
    flags_text: str,
) -> bool:
    """True when a TCP packet carries SYN without ACK/RST/FIN.

    ``str(packet[TCP].flags)`` renders set flags as sorted letters
    (e.g. ``S``, ``SA``, ``A``), so a bare ``S`` means a connection
    attempt that never reached the handshake-completion stage.
    """
    return flags_text == "S"


class _CappedNameStore:
    """Insertion-ordered, capped set of DNS qnames or TLS SNIs per flow.

    Membership and insertion both use ``dict[str, None]`` so each lookup
    is O(1); names are capped per flow and globally. On overflow the
    offending name is dropped and the store records a truncation reason
    (surfaced through the analyzer's ``truncated`` / ``truncation_reason``
    metadata) while the packet loop keeps running normally.
    """

    def __init__(
        self,
        per_flow_cap: int,
        global_cap: int,
    ) -> None:
        self.per_flow_cap = per_flow_cap
        self.global_cap = global_cap

        self.names: dict[tuple, dict[str, None]] = defaultdict(dict)

        self.total = 0
        self.truncated = False
        self.truncation_reason: str | None = None

    def add(
        self,
        flow_key: tuple,
        name: str,
    ) -> None:
        known = self.names[flow_key]

        if name in known:
            return

        if len(known) >= self.per_flow_cap:
            self._mark_truncated(
                f"per-flow limit reached ({self.per_flow_cap})"
            )

            return

        if self.total >= self.global_cap:
            self._mark_truncated(
                f"global limit reached ({self.global_cap})"
            )

            return

        known[name] = None
        self.total += 1

    def for_flow(
        self,
        flow_key: tuple,
    ) -> list[str]:
        return list(
            self.names.get(
                flow_key,
                {},
            )
        )

    def _mark_truncated(
        self,
        reason: str,
    ) -> None:
        if self.truncated:
            return

        self.truncated = True
        self.truncation_reason = reason


def normalize_ip(packet) -> tuple[str | None, str | None]:
    if IP in packet:
        return str(packet[IP].src), str(packet[IP].dst)

    if IPv6 in packet:
        return str(packet[IPv6].src), str(packet[IPv6].dst)

    return None, None


def analyze_pcap(file_path: str) -> dict[str, Any]:
    path = Path(file_path)

    if not path.exists():
        return {
            "error": f"PCAP file not found: {file_path}"
        }

    if not path.is_file():
        return {
            "error": f"Not a file: {file_path}"
        }

    if path.suffix.lower() not in {
        ".pcap",
        ".pcapng",
        ".cap",
    }:
        return {
            "error": (
                "Unsupported capture type. "
                "Use .pcap, .pcapng, or .cap"
            )
        }

    if (
        TCP is None
        or IP is None
        or PcapReader is None
    ):
        _resolve_scapy_layers()

    if PcapReader is None:
        return {
            "error": (
                "PCAP support is not installed. "
                "Install it with: pip install -e .[pcap]"
            )
        }

    settings = get_settings()

    max_packets = settings.max_pcap_packets
    max_flows = settings.max_pcap_flows

    protocol_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    destination_port_counts: Counter[int] = Counter()

    tcp_port_targets = defaultdict(set)
    udp_port_targets = defaultdict(set)

    flows: Counter[tuple[str, int | None, str, int | None, str]] = Counter()

    # P4-21: per-flow state collected alongside the packet counts.
    # Timestamps arrive as epoch seconds; inter-arrival-time statistics
    # are accumulated with Welford's online algorithm so beacon
    # regularity can be scored without retaining per-packet data.
    flow_first_seen: dict[tuple, float] = {}
    flow_last_seen: dict[tuple, float] = {}
    flow_iat_count: dict[tuple, int] = {}
    flow_iat_mean: dict[tuple, float] = {}
    flow_iat_m2: dict[tuple, float] = {}
    flow_flag_counts: dict[tuple, Counter[str]] = defaultdict(Counter)
    flow_dns_queries = _CappedNameStore(
        per_flow_cap=MAX_FLOW_DNS_NAMES,
        global_cap=MAX_PCAP_FLOW_NAMES,
    )
    flow_tls_snis = _CappedNameStore(
        per_flow_cap=MAX_FLOW_TLS_SNIS,
        global_cap=MAX_PCAP_FLOW_NAMES,
    )

    packets_total = 0
    tcp_packets = 0
    udp_packets = 0
    other_packets = 0

    packet_samples: list[dict] = []

    truncated = False
    truncation_reason: str | None = None

    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if packets_total >= max_packets:
                    truncated = True
                    truncation_reason = (
                        f"packet limit reached "
                        f"({max_packets})"
                    )
                    break

                packets_total += 1

                source_ip, destination_ip = normalize_ip(
                    packet
                )

                if source_ip:
                    ip_counts[source_ip] += 1
                    source_counts[source_ip] += 1

                if destination_ip:
                    ip_counts[destination_ip] += 1
                    destination_counts[
                        destination_ip
                    ] += 1

                protocol = "OTHER"
                source_port = None
                destination_port = None
                tcp_flags = None

                epoch = _packet_epoch(packet)

                if TCP in packet:
                    protocol = "TCP"
                    tcp_packets += 1

                    source_port = int(
                        packet[TCP].sport
                    )

                    destination_port = int(
                        packet[TCP].dport
                    )

                    tcp_flags = str(
                        packet[TCP].flags
                    )

                    if (
                        source_ip
                        and destination_ip
                    ):
                        tcp_port_targets[
                            (
                                source_ip,
                                destination_ip,
                            )
                        ].add(
                            destination_port
                        )

                elif UDP in packet:
                    protocol = "UDP"
                    udp_packets += 1

                    source_port = int(
                        packet[UDP].sport
                    )

                    destination_port = int(
                        packet[UDP].dport
                    )

                    if (
                        source_ip
                        and destination_ip
                    ):
                        udp_port_targets[
                            (
                                source_ip,
                                destination_ip,
                            )
                        ].add(
                            destination_port
                        )

                else:
                    other_packets += 1

                protocol_counts[
                    protocol
                ] += 1

                if destination_port is not None:
                    destination_port_counts[
                        destination_port
                    ] += 1

                if (
                    source_ip
                    and destination_ip
                ):
                    flow_key = (
                        source_ip,
                        source_port,
                        destination_ip,
                        destination_port,
                        protocol,
                    )

                    if (
                        flow_key not in flows
                        and len(flows) >= max_flows
                    ):
                        truncated = True
                        truncation_reason = (
                            f"flow limit reached "
                            f"({max_flows})"
                        )
                        break

                    flows[
                        flow_key
                    ] += 1

                    if epoch is not None:
                        if (
                            flow_key
                            not in flow_first_seen
                        ):
                            flow_first_seen[
                                flow_key
                            ] = epoch

                        previous = flow_last_seen.get(
                            flow_key
                        )

                        if (
                            previous is not None
                            and epoch > previous
                        ):
                            delta = epoch - previous
                            sample = (
                                flow_iat_count.get(
                                    flow_key,
                                    0,
                                )
                                + 1
                            )

                            flow_iat_count[
                                flow_key
                            ] = sample

                            previous_mean = (
                                flow_iat_mean.get(
                                    flow_key,
                                    0.0,
                                )
                            )

                            updated_mean = (
                                previous_mean
                                + (
                                    delta
                                    - previous_mean
                                )
                                / sample
                            )

                            flow_iat_mean[
                                flow_key
                            ] = updated_mean

                            flow_iat_m2[
                                flow_key
                            ] = (
                                flow_iat_m2.get(
                                    flow_key,
                                    0.0,
                                )
                                + (
                                    delta
                                    - previous_mean
                                )
                                * (
                                    delta
                                    - updated_mean
                                )
                            )

                        flow_last_seen[
                            flow_key
                        ] = max(
                            flow_last_seen.get(
                                flow_key,
                                epoch,
                            ),
                            epoch,
                        )

                    if tcp_flags is not None:
                        flow_flag_counts[
                            flow_key
                        ][tcp_flags] += 1

                    for qname in _packet_dns_queries(
                        packet
                    ):
                        flow_dns_queries.add(
                            flow_key,
                            qname,
                        )

                    sni = _packet_tls_sni(
                        packet
                    )

                    if sni:
                        flow_tls_snis.add(
                            flow_key,
                            sni,
                        )

                if len(
                    packet_samples
                ) < 100:
                    packet_samples.append(
                        {
                            "source_ip": source_ip,
                            "source_port": source_port,
                            "destination_ip": destination_ip,
                            "destination_port": destination_port,
                            "protocol": protocol,
                            "tcp_flags": tcp_flags,
                            "length": len(packet),
                        }
                    )

    except Exception as exc:
        return {
            "error": (
                "Could not parse PCAP file: "
                f"{exc}"
            )
        }

    flow_records = []

    for (
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
    ), count in flows.most_common():
        flow_key = (
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
        )

        first_epoch = flow_first_seen.get(
            flow_key
        )

        last_epoch = flow_last_seen.get(
            flow_key
        )

        iat_mean, iat_cv = _iat_variation(
            flow_iat_count.get(
                flow_key,
                0,
            ),
            flow_iat_mean.get(
                flow_key,
                0.0,
            ),
            flow_iat_m2.get(
                flow_key,
                0.0,
            ),
        )

        flag_counts = flow_flag_counts.get(
            flow_key,
        )

        flow_record = {
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "packet_count": count,
            "first_seen": (
                _epoch_to_iso(first_epoch)
                if first_epoch is not None
                else None
            ),
            "last_seen": (
                _epoch_to_iso(last_epoch)
                if last_epoch is not None
                else None
            ),
            "iat_mean_seconds": iat_mean,
            "iat_cv": iat_cv,
            "syn_only_count": (
                flag_counts.get(
                    "S",
                    0,
                )
                if flag_counts is not None
                else 0
            ),
            "tcp_flags_seen": sorted(
                flag_counts.keys()
            )
            if flag_counts is not None
            else [],
            "dns_queries": flow_dns_queries.for_flow(
                flow_key
            ),
            "tls_snis": flow_tls_snis.for_flow(
                flow_key
            ),
        }

        flow_records.append(
            flow_record
        )

    tcp_scan_candidates = []

    for (
        source_ip,
        destination_ip,
    ), ports in tcp_port_targets.items():
        tcp_scan_candidates.append(
            {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "unique_destination_ports": len(
                    ports
                ),
                "destination_ports": sorted(
                    ports
                ),
            }
        )

    udp_scan_candidates = []

    for (
        source_ip,
        destination_ip,
    ), ports in udp_port_targets.items():
        udp_scan_candidates.append(
            {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "unique_destination_ports": len(
                    ports
                ),
                "destination_ports": sorted(
                    ports
                ),
            }
        )

    top_source_ips = [
        {
            "ip": ip,
            "packets": count,
        }
        for ip, count in source_counts.most_common(
            20
        )
    ]

    top_destination_ips = [
        {
            "ip": ip,
            "packets": count,
        }
        for ip, count in destination_counts.most_common(
            20
        )
    ]

    top_destination_ports = [
        {
            "port": port,
            "packets": count,
        }
        for port, count in destination_port_counts.most_common(
            20
        )
    ]

    dns_query_count = flow_dns_queries.total
    tls_sni_count = flow_tls_snis.total

    if flow_dns_queries.truncated and not truncated:
        truncated = True
        truncation_reason = (
            "DNS name "
            + str(
                flow_dns_queries.truncation_reason
            )
        )

    if flow_tls_snis.truncated and not truncated:
        truncated = True
        truncation_reason = (
            "TLS SNI "
            + str(
                flow_tls_snis.truncation_reason
            )
        )

    logger.debug(
        "Parsed %d packet(s), %d unique flow(s) "
        "from %s (truncated: %s)",
        packets_total,
        len(flows),
        path.name,
        truncated,
    )

    return {
        "path": str(
            path.resolve()
        ),
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "packets_total": packets_total,
        "protocols": {
            "tcp": tcp_packets,
            "udp": udp_packets,
            "other": other_packets,
        },
        "protocol_counts": dict(
            protocol_counts
        ),
        "unique_ips": len(
            ip_counts
        ),
        "unique_flows": len(
            flows
        ),
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips,
        "top_destination_ports": top_destination_ports,
        "dns_query_count": dns_query_count,
        "tls_sni_count": tls_sni_count,
        "dns_names_truncated": flow_dns_queries.truncated,
        "tls_snis_truncated": flow_tls_snis.truncated,
        "flows": flow_records,
        "tcp_scan_candidates": tcp_scan_candidates,
        "udp_scan_candidates": udp_scan_candidates,
        "packet_samples": packet_samples,
        "truncated": truncated,
        "truncation_reason": truncation_reason,
    }
