"""
capture/flow_table.py: Stateful network flow aggregation table.

Aggregates raw packet records into canonical 5-tuple bidirectional flows
(src_ip, src_port, dst_ip, dst_port, protocol), tracks packet timing, lengths,
and TCP flags, and handles flow termination and expiration triggers (FIN/RST,
idle timeout, active timeout).
"""

import os
from typing import Any, Dict, List, Optional, Set, Tuple


def _extract_tcp_flags(flags: Any) -> Dict[str, bool]:
    """
    Normalizes various TCP flag formats (dict, int bitmask, str, or set) into
    a standard boolean dictionary: {'SYN': bool, 'ACK': bool, 'FIN': bool, 'RST': bool, 'PSH': bool}.
    """
    result = {"SYN": False, "ACK": False, "FIN": False, "RST": False, "PSH": False}
    if flags is None:
        return result

    if isinstance(flags, dict):
        for k in result:
            result[k] = bool(flags.get(k) or flags.get(k.lower()))
        return result

    if isinstance(flags, int):
        # Standard TCP flag bit positions:
        # FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10
        result["FIN"] = bool(flags & 0x01)
        result["SYN"] = bool(flags & 0x02)
        result["RST"] = bool(flags & 0x04)
        result["PSH"] = bool(flags & 0x08)
        result["ACK"] = bool(flags & 0x10)
        return result

    if isinstance(flags, (set, list, tuple)):
        flags_upper = {str(f).upper() for f in flags}
        result["FIN"] = "FIN" in flags_upper or "F" in flags_upper
        result["SYN"] = "SYN" in flags_upper or "S" in flags_upper
        result["RST"] = "RST" in flags_upper or "R" in flags_upper
        result["PSH"] = "PSH" in flags_upper or "P" in flags_upper
        result["ACK"] = "ACK" in flags_upper or "A" in flags_upper
        return result

    if isinstance(flags, str):
        flags_upper = flags.upper()
        result["FIN"] = "F" in flags_upper or "FIN" in flags_upper
        result["SYN"] = "S" in flags_upper or "SYN" in flags_upper
        result["RST"] = "RST" in flags_upper or "R" in flags_upper
        result["PSH"] = "PSH" in flags_upper or "P" in flags_upper
        result["ACK"] = "ACK" in flags_upper or "A" in flags_upper
        return result

    return result


class Flow:
    """
    Represents an ongoing or completed bidirectional network flow.
    """

    def __init__(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        first_packet: Dict[str, Any],
    ):
        # The direction of the first seen packet establishes forward (fwd) vs backward (bwd)
        self.fwd_src_ip = src_ip
        self.fwd_src_port = src_port
        self.fwd_dst_ip = dst_ip
        self.fwd_dst_port = dst_port
        self.protocol = str(protocol).upper()

        self.start_time = float(first_packet.get("timestamp", 0.0))
        self.last_seen_time = self.start_time

        self.packets: List[Dict[str, Any]] = []
        self.has_fin_or_rst = False

        self.add_packet(first_packet)

    def is_forward(self, src_ip: str, src_port: int) -> bool:
        """Determines if a packet matches the forward direction of this flow."""
        return src_ip == self.fwd_src_ip and src_port == self.fwd_src_port

    def add_packet(self, packet_info: Dict[str, Any]) -> None:
        """
        Appends a packet record and updates timestamps and state flags.
        """
        ts = float(packet_info.get("timestamp", self.last_seen_time))
        size = int(packet_info.get("size", 0))
        src_ip = packet_info.get("src_ip", self.fwd_src_ip)
        src_port = int(packet_info.get("src_port", self.fwd_src_port))

        direction = "fwd" if self.is_forward(src_ip, src_port) else "bwd"
        flags = _extract_tcp_flags(packet_info.get("tcp_flags"))

        record = {
            "timestamp": ts,
            "size": size,
            "direction": direction,
            "tcp_flags": flags,
        }
        self.packets.append(record)

        if ts > self.last_seen_time:
            self.last_seen_time = ts
        if ts < self.start_time:
            self.start_time = ts

        if flags["FIN"] or flags["RST"]:
            self.has_fin_or_rst = True


def canonical_flow_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str
) -> Tuple[str, str, int, str, int]:
    """
    Computes a canonical key for a 5-tuple regardless of packet direction.
    """
    proto = str(protocol).upper()
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    if ep1 <= ep2:
        return (proto, ep1[0], ep1[1], ep2[0], ep2[1])
    else:
        return (proto, ep2[0], ep2[1], ep1[0], ep1[1])


class FlowTable:
    """
    Maintains active flows and enforces idle, active, and TCP teardown expiration policies.
    """

    def __init__(
        self,
        idle_timeout: Optional[float] = None,
        active_timeout: Optional[float] = None,
    ):
        # Default timeouts from environment or constants
        self.idle_timeout = (
            idle_timeout
            if idle_timeout is not None
            else float(os.getenv("FLOW_IDLE_TIMEOUT", "5.0"))
        )
        self.active_timeout = (
            active_timeout
            if active_timeout is not None
            else float(os.getenv("FLOW_ACTIVE_TIMEOUT", "30.0"))
        )
        self.flows: Dict[Tuple[str, str, int, str, int], Flow] = {}

    def add_packet(self, packet_info: Dict[str, Any]) -> Flow:
        """
        Ingests a packet record, adding it to an existing flow or initializing a new flow.
        """
        src_ip = str(packet_info.get("src_ip", "0.0.0.0"))
        src_port = int(packet_info.get("src_port", 0))
        dst_ip = str(packet_info.get("dst_ip", "0.0.0.0"))
        dst_port = int(packet_info.get("dst_port", 0))
        protocol = str(packet_info.get("protocol", "TCP"))

        key = canonical_flow_key(src_ip, src_port, dst_ip, dst_port, protocol)

        if key in self.flows:
            flow = self.flows[key]
            flow.add_packet(packet_info)
        else:
            flow = Flow(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                first_packet=packet_info,
            )
            self.flows[key] = flow

        return flow

    def expire_flows(self, now: float) -> List[Flow]:
        """
        Checks active flows and returns (and removes) all expired flows based on:
        1. TCP FIN or RST flag received.
        2. Idle timeout (no packet seen for >= idle_timeout).
        3. Active timeout (flow duration >= active_timeout).
        """
        expired: List[Flow] = []
        keys_to_remove = []

        for key, flow in self.flows.items():
            duration = now - flow.start_time
            idle_time = now - flow.last_seen_time

            is_expired = False
            if flow.has_fin_or_rst:
                is_expired = True
            elif idle_time >= self.idle_timeout:
                is_expired = True
            elif duration >= self.active_timeout:
                is_expired = True

            if is_expired:
                expired.append(flow)
                keys_to_remove.append(key)

        for k in keys_to_remove:
            del self.flows[k]

        return expired

    def __len__(self) -> int:
        return len(self.flows)
