"""
capture/sniffer.py: Live packet capture engine and feature extraction pipeline.

Captures live network packets via Scapy AsyncSniffer (or testable packet dictionaries),
aggregates packets into canonical flows in FlowTable, computes 19-feature vectors upon
flow expiration, and streams them to the NIDS API.
"""

import argparse
import logging
import sys
import time
from typing import Any, Dict, Optional

from capture.client import FlowClient
from capture.features import compute_features
from capture.flow_table import FlowTable

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sniffer")


def packet_to_dict(packet: Any) -> Optional[Dict[str, Any]]:
    """
    Converts a Scapy packet object or structured dict into a plain packet dictionary:
    {timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, tcp_flags}.

    Safely inspects layers without hard dependency failures.
    """
    if isinstance(packet, dict):
        return packet

    # Process Scapy packet object
    try:
        # Check IP layer
        if not hasattr(packet, "haslayer"):
            return None

        # Determine IP protocol and addresses
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        protocol = "IP"

        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
        elif packet.haslayer("IPv6"):
            ip_layer = packet["IPv6"]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
        else:
            return None  # Non-IP packet

        src_port = 0
        dst_port = 0
        tcp_flags = {"SYN": False, "ACK": False, "FIN": False, "RST": False, "PSH": False}

        if packet.haslayer("TCP"):
            tcp_layer = packet["TCP"]
            protocol = "TCP"
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            flags_val = tcp_layer.flags
            # Scapy flag conversion (flags could be FlagValue or int or str)
            flags_str = str(flags_val)
            tcp_flags = {
                "SYN": "S" in flags_str,
                "ACK": "A" in flags_str,
                "FIN": "F" in flags_str,
                "RST": "R" in flags_str,
                "PSH": "P" in flags_str,
            }
        elif packet.haslayer("UDP"):
            udp_layer = packet["UDP"]
            protocol = "UDP"
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)

        ts = float(getattr(packet, "time", time.time()))
        size = int(len(packet))

        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "size": size,
            "tcp_flags": tcp_flags,
        }
    except Exception as e:
        logger.debug("Error converting packet to dict: %s", e)
        return None


class PacketSniffer:
    """
    Orchestrates live capture, flow table maintenance, expiration checks,
    and asynchronous telemetry dispatch.
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        bpf_filter: str = "ip",
        api_url: str = "http://localhost:8000",
        idle_timeout: float = 5.0,
        active_timeout: float = 30.0,
    ):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.flow_table = FlowTable(idle_timeout=idle_timeout, active_timeout=active_timeout)
        self.client = FlowClient(api_url=api_url)
        self._is_running = False
        self._async_sniffer = None

    def process_packet(self, packet: Any) -> None:
        """Handler called for each captured packet."""
        p_dict = packet_to_dict(packet)
        if p_dict is not None:
            self.flow_table.add_packet(p_dict)

    def flush_expired(self, now: Optional[float] = None) -> int:
        """
        Expires inactive flows, computes 19-feature vectors, and sends them to API.
        """
        current_time = now if now is not None else time.time()
        expired_flows = self.flow_table.expire_flows(current_time)

        for flow in expired_flows:
            features = compute_features(flow)
            self.client.send_flow(
                src_ip=flow.fwd_src_ip,
                dst_ip=flow.fwd_dst_ip,
                dst_port=flow.fwd_dst_port,
                features=features,
            )

        return len(expired_flows)

    def start(self) -> None:
        """
        Starts Scapy AsyncSniffer and enters the periodic expiration loop.
        Note: Requires Npcap (on Windows) or root/promiscuous privileges (on Linux).
        """
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            logger.error(
                "Scapy is not installed. To run live sniffing, install scapy (pip install scapy) "
                "and ensure Npcap/libpcap is installed on the system."
            )
            return

        print_legal_warning()
        logger.info(
            "Starting live packet sniffer on iface='%s' with filter='%s'",
            self.iface or "default",
            self.bpf_filter,
        )

        self._is_running = True
        self._async_sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self.process_packet,
            store=False,
        )
        self._async_sniffer.start()

        try:
            while self._is_running:
                time.sleep(1.0)
                expired_count = self.flush_expired()
                if expired_count > 0:
                    logger.info("Flushed and dispatched %d expired flows.", expired_count)
        except KeyboardInterrupt:
            logger.info("Stopping sniffer...")
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully stops sniffer and closes HTTP connections."""
        self._is_running = False
        if self._async_sniffer is not None and self._async_sniffer.running:
            self._async_sniffer.stop()
        self.flush_expired()
        self.client.close()
        logger.info("Sniffer stopped successfully.")


def print_legal_warning():
    warning_text = """
===============================================================================
[SECURITY / ETHICAL WARNING]
Only run live packet sniffing on network interfaces and subnets you own, manage,
or have explicit authorization to monitor. Unauthorized packet capture may
violate organizational policies and applicable privacy laws.
===============================================================================
"""
    print(warning_text)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Live packet capture and flow feature extraction engine."
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Network interface name to sniff on (default: auto/default)",
    )
    parser.add_argument(
        "--bpf-filter",
        type=str,
        default="ip",
        help="BPF capture filter (default: 'ip')",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default="http://localhost:8000",
        help="FastAPI ingestion endpoint URL (default: http://localhost:8000)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    sniffer = PacketSniffer(
        iface=args.iface,
        bpf_filter=args.bpf_filter,
        api_url=args.api_url,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
