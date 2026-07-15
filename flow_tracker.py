"""Flow aggregation layer.

Turns individual packets into bidirectional flows so the classifier can score
connection-level behaviour (the model is trained on CIC-IDS-2017 flow features,
not single packets). Live sniffing and pcap replay share ONE code path: both
convert a packet into a `PacketMeta` via `meta_from_scapy()` and feed it to
`FlowTracker.update()`.

A flow is keyed by the *canonicalised* 5-tuple so that A->B and B->A packets
land in the same flow; the endpoint that sent the first packet is treated as the
initiator ("forward" direction).

Feature semantics are aligned to CICFlowMeter / CIC-IDS-2017 so that the values
this tracker emits at inference time match the values the model was trained on.
Where a definition is only an approximation of CICFlowMeter's, it is noted.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

import config

# IP protocol numbers, kept consistent with the trainer's protocol encoding
# (see train_flow_model.py: tcp->6, udp->17, other->0).
PROTO_TCP = 6
PROTO_UDP = 17


@dataclass
class PacketMeta:
    """Protocol-agnostic view of one packet. Built by `meta_from_scapy()` for
    live/replay traffic, or directly in tests. Keeping this separate from scapy
    means flow_tracker is testable without crafting real packets."""
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int          # 6=TCP, 17=UDP, else raw IP proto number
    payload_len: int    # transport payload bytes (excludes IP/TCP/UDP headers)
    syn: bool = False
    rst: bool = False
    fin: bool = False
    ack: bool = False


@dataclass
class Flow:
    """Accumulated bidirectional flow state. `to_features()` projects it onto the
    canonical FEATURE_ORDER the model expects."""
    src_ip: str          # initiator (forward direction source)
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    first_ts: float
    last_ts: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    syn_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    ack_count: int = 0
    _fin_fwd: bool = field(default=False, repr=False)
    _fin_bwd: bool = field(default=False, repr=False)
    closed: bool = field(default=False, repr=False)

    @property
    def duration_s(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def to_features(self) -> dict:
        """Raw (unscaled) feature dict keyed by config.FEATURE_ORDER names.
        cnn_engine applies the saved scaler + ordering on top of this."""
        return {
            "duration_s": self.duration_s,
            "protocol": float(self.proto),
            "fwd_packets": float(self.fwd_packets),
            "bwd_packets": float(self.bwd_packets),
            "fwd_bytes": float(self.fwd_bytes),
            "bwd_bytes": float(self.bwd_bytes),
            # IMPORTANT: CIC-IDS-2017's CICFlowMeter flag columns are BINARY
            # presence indicators (0/1), NOT occurrence counts -- verified: every
            # flag column has max==1 across all 2.8M rows. A real bidirectional
            # TCP flow carries many ACKs (and a SYN + SYN-ACK), so emitting the
            # true packet count here (e.g. ack=16-32) would be far out of the
            # training distribution and wreck classification. We therefore emit
            # PRESENCE to match the training feature definition. The raw counts
            # are still tracked on the Flow for TCP-close logic and display.
            "syn_count": 1.0 if self.syn_count else 0.0,
            "rst_count": 1.0 if self.rst_count else 0.0,
            "fin_count": 1.0 if self.fin_count else 0.0,
            "ack_count": 1.0 if self.ack_count else 0.0,
        }

    def key_tuple(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)


def _canonical_key(m: PacketMeta) -> tuple:
    """Direction-independent flow key: the two endpoints are sorted so both
    directions hash to the same flow."""
    a = (m.src_ip, m.src_port)
    b = (m.dst_ip, m.dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo, hi, m.proto)


class FlowTracker:
    def __init__(self,
                 idle_timeout: float = config.FLOW_IDLE_TIMEOUT_S,
                 active_timeout: float = config.FLOW_ACTIVE_TIMEOUT_S):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self._flows: dict[tuple, Flow] = {}

    def update(self, m: PacketMeta) -> list[Flow]:
        """Ingest one packet. Returns any flows completed as a result of this
        packet (TCP close) or of idle/active timeouts that expired alongside it."""
        completed: list[Flow] = []
        key = _canonical_key(m)
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(src_ip=m.src_ip, dst_ip=m.dst_ip,
                        src_port=m.src_port, dst_port=m.dst_port,
                        proto=m.proto, first_ts=m.ts, last_ts=m.ts)
            self._flows[key] = flow

        forward = (m.src_ip, m.src_port) == (flow.src_ip, flow.src_port)
        if forward:
            flow.fwd_packets += 1
            flow.fwd_bytes += m.payload_len
        else:
            flow.bwd_packets += 1
            flow.bwd_bytes += m.payload_len

        if m.syn:
            flow.syn_count += 1
        if m.rst:
            flow.rst_count += 1
        if m.ack:
            flow.ack_count += 1
        if m.fin:
            flow.fin_count += 1
            if forward:
                flow._fin_fwd = True
            else:
                flow._fin_bwd = True
        flow.last_ts = max(flow.last_ts, m.ts)

        # TCP teardown: RST from either side, or FIN seen in both directions.
        if flow.proto == PROTO_TCP and (flow.rst_count > 0 or (flow._fin_fwd and flow._fin_bwd)):
            flow.closed = True
            completed.append(self._flows.pop(key))

        completed.extend(self.expire(now=m.ts))
        return completed

    def expire(self, now: Optional[float] = None) -> list[Flow]:
        """Emit flows that have gone idle or exceeded the active timeout."""
        if now is None:
            now = time.time()
        expired: list[Flow] = []
        for key, flow in list(self._flows.items()):
            if (now - flow.last_ts) >= self.idle_timeout or \
               (now - flow.first_ts) >= self.active_timeout:
                expired.append(self._flows.pop(key))
        return expired

    def flush(self) -> list[Flow]:
        """Emit every remaining flow. Used at end of a pcap replay."""
        remaining = list(self._flows.values())
        self._flows.clear()
        return remaining

    def __len__(self) -> int:
        return len(self._flows)


def meta_from_scapy(packet) -> Optional[PacketMeta]:
    """Convert a scapy packet into a PacketMeta, or None if it is not an
    IPv4 TCP/UDP packet we can turn into a flow. Imported lazily so tests and
    the trainer don't require scapy."""
    from scapy.layers.inet import IP, TCP, UDP

    if not packet.haslayer(IP):
        return None
    ip = packet[IP]
    if packet.haslayer(TCP):
        l4 = packet[TCP]
        proto = PROTO_TCP
        flags = int(l4.flags)
        syn = bool(flags & 0x02)
        rst = bool(flags & 0x04)
        fin = bool(flags & 0x01)
        ack = bool(flags & 0x10)
    elif packet.haslayer(UDP):
        l4 = packet[UDP]
        proto = PROTO_UDP
        syn = rst = fin = ack = False
    else:
        return None

    payload_len = len(l4.payload) if l4.payload else 0
    ts = float(getattr(packet, "time", None) or time.time())
    return PacketMeta(
        ts=ts,
        src_ip=ip.src, dst_ip=ip.dst,
        src_port=int(l4.sport), dst_port=int(l4.dport),
        proto=proto, payload_len=payload_len,
        syn=syn, rst=rst, fin=fin, ack=ack,
    )
