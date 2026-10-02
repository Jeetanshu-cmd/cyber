"""
capture/features.py: 19-Feature extraction engine for network flows.

Transforms stateful Flow objects into a standardized 19-feature vector matching
the exact contract specified in AGENTS.md §3 and ml/artifacts/features.json:

Features (in strict contract order):
 1. dst_port
 2. flow_duration_s
 3. fwd_packets
 4. bwd_packets
 5. fwd_bytes
 6. bwd_bytes
 7. bytes_per_sec
 8. packets_per_sec
 9. pkt_len_mean
10. pkt_len_std
11. pkt_len_max
12. pkt_len_min
13. syn_count
14. ack_count
15. fin_count
16. rst_count
17. psh_count
18. iat_mean
19. iat_max

-------------------------------------------------------------------------------
HAND-TRACE OF 5 RAW PACKETS:
-------------------------------------------------------------------------------
Assume a HTTP flow between Initiator (192.168.1.50:54321) and Web Server (10.0.0.1:80):

  P1 (t=0.00s): 192.168.1.50:54321 -> 10.0.0.1:80   | Size:   64B | Flags: [SYN]      | Direction: fwd
  P2 (t=0.01s): 10.0.0.1:80   -> 192.168.1.50:54321 | Size:   64B | Flags: [SYN, ACK] | Direction: bwd
  P3 (t=0.02s): 192.168.1.50:54321 -> 10.0.0.1:80   | Size:   54B | Flags: [ACK]      | Direction: fwd
  P4 (t=0.05s): 192.168.1.50:54321 -> 10.0.0.1:80   | Size:  554B | Flags: [PSH, ACK] | Direction: fwd
  P5 (t=0.10s): 10.0.0.1:80   -> 192.168.1.50:54321 | Size: 1514B | Flags: [ACK]      | Direction: bwd

Step-by-Step Hand Calculations:
1.  dst_port        = 80.0
2.  flow_duration_s = 0.10 - 0.00 = 0.10s
3.  fwd_packets     = 3.0 (P1, P3, P4)
4.  bwd_packets     = 2.0 (P2, P5)
5.  fwd_bytes       = 64 + 54 + 554 = 672.0B
6.  bwd_bytes       = 64 + 1514 = 1578.0B
7.  bytes_per_sec   = (672 + 1578) / 0.10 = 22500.0 B/s
8.  packets_per_sec = (3 + 2) / 0.10 = 50.0 pkts/s
9.  pkt_len_mean    = (64 + 64 + 54 + 554 + 1514) / 5 = 2250 / 5 = 450.0B
10. pkt_len_std     = Sample std dev: sqrt(((64-450)^2 + (64-450)^2 + (54-450)^2 + (554-450)^2 + (1514-450)^2) / 4)
                    = sqrt((149000 + 149000 + 156816 + 10816 + 1132096) / 4)
                    = sqrt(1597728 / 4) = sqrt(399432) ~= 631.9968
11. pkt_len_max     = 1514.0B
12. pkt_len_min     = 54.0B
13. syn_count       = 2.0 (P1, P2)
14. ack_count       = 4.0 (P2, P3, P4, P5)
15. fin_count       = 0.0
16. rst_count       = 0.0
17. psh_count       = 1.0 (P4)
18. iat_mean        = IATs: [0.01, 0.01, 0.03, 0.05] -> sum=0.10, mean = 0.10 / 4 = 0.025s
19. iat_max         = max(0.01, 0.01, 0.03, 0.05) = 0.05s

-------------------------------------------------------------------------------
TIME & SPACE COMPLEXITY ANALYSIS:
-------------------------------------------------------------------------------
Let N be the total number of packet records in the flow:
- Direction & Byte Counts : O(N) single linear scan.
- Packet Length Stats     : O(N) linear scan for sum, min, max, and variance/std.
- TCP Flag Counts         : O(N) linear scan through packet headers.
- IAT Computation         : O(N log N) for sorting timestamps (or O(N) when arrivals are monotonic).
- Total Time Complexity   : O(N) linear in the number of packets per flow.
- Space Complexity        : O(N) auxiliary space to store intermediate packet length and IAT arrays.
"""

import math
from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:
    from capture.flow_table import Flow


FEATURE_KEYS: List[str] = [
    "dst_port",
    "flow_duration_s",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "bytes_per_sec",
    "packets_per_sec",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_max",
    "pkt_len_min",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "iat_mean",
    "iat_max",
]


def compute_features(flow: "Flow") -> Dict[str, float]:
    """
    Computes all 19 standardized network flow features from a Flow object.

    Guarantees:
    - Exactly 19 keys in identical contract order.
    - Zero divisions safely guarded (returns 0.0, never NaN or Inf).
    - Packet lengths and flag counts aggregated across both directions.
    """
    total_packets = len(flow.packets)

    # 1. Destination Port
    dst_port = float(flow.fwd_dst_port)

    # 2. Flow Duration (seconds)
    flow_duration_s = max(0.0, float(flow.last_seen_time - flow.start_time))

    # 3-6. Forward/Backward packet counts and payload bytes
    fwd_packets = 0.0
    bwd_packets = 0.0
    fwd_bytes = 0.0
    bwd_bytes = 0.0

    # 9-12. Packet length stats (across all packets)
    packet_lengths: List[float] = []

    # 13-17. TCP flag counts
    syn_count = 0.0
    ack_count = 0.0
    fin_count = 0.0
    rst_count = 0.0
    psh_count = 0.0

    # 18-19. Timestamps for Inter-Arrival Times (IAT)
    timestamps: List[float] = []

    for pkt in flow.packets:
        size = float(pkt.get("size", 0))
        direction = pkt.get("direction", "fwd")
        flags = pkt.get("tcp_flags", {})
        ts = float(pkt.get("timestamp", 0.0))

        if direction == "fwd":
            fwd_packets += 1.0
            fwd_bytes += size
        else:
            bwd_packets += 1.0
            bwd_bytes += size

        packet_lengths.append(size)
        timestamps.append(ts)

        if flags.get("SYN"):
            syn_count += 1.0
        if flags.get("ACK"):
            ack_count += 1.0
        if flags.get("FIN"):
            fin_count += 1.0
        if flags.get("RST"):
            rst_count += 1.0
        if flags.get("PSH"):
            psh_count += 1.0

    # 7-8. Throughput rates
    total_bytes = fwd_bytes + bwd_bytes
    if flow_duration_s > 0.0:
        bytes_per_sec = total_bytes / flow_duration_s
        packets_per_sec = float(total_packets) / flow_duration_s
    else:
        bytes_per_sec = 0.0
        packets_per_sec = 0.0

    # Packet length metrics
    if total_packets > 0:
        pkt_len_mean = total_bytes / float(total_packets)
        pkt_len_max = float(max(packet_lengths))
        pkt_len_min = float(min(packet_lengths))

        if total_packets > 1:
            # Sample standard deviation (Bessel's correction ddof=1)
            variance = sum((x - pkt_len_mean) ** 2 for x in packet_lengths) / (total_packets - 1)
            pkt_len_std = math.sqrt(variance)
        else:
            pkt_len_std = 0.0
    else:
        pkt_len_mean = 0.0
        pkt_len_std = 0.0
        pkt_len_max = 0.0
        pkt_len_min = 0.0

    # Inter-Arrival Times (IAT)
    if total_packets > 1:
        timestamps.sort()
        iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        iat_mean = sum(iats) / float(len(iats))
        iat_max = float(max(iats))
    else:
        iat_mean = 0.0
        iat_max = 0.0

    # Construct the dictionary maintaining strict contract ordering
    features: Dict[str, float] = {
        "dst_port": dst_port,
        "flow_duration_s": flow_duration_s,
        "fwd_packets": fwd_packets,
        "bwd_packets": bwd_packets,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "bytes_per_sec": bytes_per_sec,
        "packets_per_sec": packets_per_sec,
        "pkt_len_mean": pkt_len_mean,
        "pkt_len_std": pkt_len_std,
        "pkt_len_max": pkt_len_max,
        "pkt_len_min": pkt_len_min,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "iat_mean": iat_mean,
        "iat_max": iat_max,
    }

    return features
