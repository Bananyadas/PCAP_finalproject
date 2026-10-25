#!/usr/bin/env python3
"""
generate_pcap.py — Synthetic PCAP generator using Scapy.

Usage:
    python3 scripts/generate_pcap.py \
        --output data/synthetic_even.pcap \
        --flows 100 \
        --packets-per-flow 10 \
        --skew even \
        --seed 42

    python3 scripts/generate_pcap.py \
        --output data/synthetic_high.pcap \
        --flows 50 \
        --packets-per-flow 20 \
        --skew high \
        --seed 7 \
        --pattern "ATTACK"

Flow-size distributions (--skew):
    even     — all flows get roughly the same payload size.
    moderate — sizes drawn from an exponential distribution,
               giving some large and many medium flows.
    high     — a Pareto (heavy-tail) distribution: a few large
               flows dominate, many tiny ones.

Payload sizes:
    --min-payload and --max-payload control per-PACKET application
    payload bytes.  The skew distribution scales these per flow.
    The total bytes in a flow = (packets in flow) × (per-packet payload).

Sequence numbers:
    Each flow starts from a random ISN (initial sequence number).
    Subsequent packets advance the sequence number by the payload length
    of the previous packet, producing a coherent TCP stream.

Test patterns (--pattern):
    Supply one or more comma-separated ASCII strings.
    Each pattern is inserted at a random position in the first packet
    of every flow, so the full system can later validate signature hits.
    If the payload is shorter than the pattern, the pattern is prepended.

Dependencies:
    pip install scapy
"""

import argparse
import random
import sys
from dataclasses import dataclass, field
from typing import List

try:
    from scapy.all import (Ether, IP, TCP, Raw, wrpcap, conf)
    conf.verb = 0          # suppress Scapy output
except ImportError:
    print("ERROR: Scapy is not installed.  Run:  pip install scapy", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FlowSpec:
    """Describes one synthetic TCP flow."""
    flow_idx:   int
    src_ip:     str
    dst_ip:     str
    src_port:   int
    dst_port:   int
    num_pkts:   int           # number of TCP data packets in this flow
    pkt_payload_sizes: List[int] = field(default_factory=list)
    isn:        int = 0       # initial sequence number


# ---------------------------------------------------------------------------
# Skew distributions
# ---------------------------------------------------------------------------

def generate_payload_sizes(num_pkts: int, skew: str, rng: random.Random,
                           min_payload: int, max_payload: int) -> List[int]:
    """
    Return a list of `num_pkts` payload sizes shaped by the skew distribution.

    even     — uniform random in [min_payload, max_payload]
    moderate — exponential, clamped to [min_payload, max_payload]
    high     — Pareto (alpha=1.5), heavy-tailed, clamped
    """
    sizes = []
    for _ in range(num_pkts):
        if skew == "even":
            sz = rng.randint(min_payload, max_payload)

        elif skew == "moderate":
            # Exponential with mean = (min+max)/2
            mean = (min_payload + max_payload) / 2.0
            sz = int(rng.expovariate(1.0 / mean))
            sz = max(min_payload, min(max_payload, sz))

        elif skew == "high":
            # Pareto: most packets are small, a few are huge
            alpha = 1.5
            sz = int(rng.paretovariate(alpha) * min_payload)
            sz = max(min_payload, min(max_payload, sz))

        else:
            raise ValueError(f"Unknown skew: {skew!r}")

        sizes.append(sz)
    return sizes


# ---------------------------------------------------------------------------
# IP address helpers
# ---------------------------------------------------------------------------

def random_private_ip(rng: random.Random) -> str:
    """Return a random 10.x.x.x address."""
    return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def random_port(rng: random.Random, low: int = 1024, high: int = 65535) -> int:
    return rng.randint(low, high)


# ---------------------------------------------------------------------------
# Flow spec generation
# ---------------------------------------------------------------------------

def build_flow_specs(num_flows: int, pkts_per_flow: int, skew: str,
                     rng: random.Random,
                     min_payload: int, max_payload: int) -> List[FlowSpec]:
    specs = []
    used_tuples = set()

    for i in range(num_flows):
        # Generate a unique 5-tuple
        for _ in range(1000):
            sip  = random_private_ip(rng)
            dip  = random_private_ip(rng)
            sp   = random_port(rng)
            dp   = random_port(rng, 1, 1023)   # server port in well-known range
            key  = (sip, dip, sp, dp)
            if key not in used_tuples:
                used_tuples.add(key)
                break

        isn    = rng.randint(0, 0xFFFFFFFF)
        sizes  = generate_payload_sizes(pkts_per_flow, skew, rng,
                                        min_payload, max_payload)

        specs.append(FlowSpec(
            flow_idx=i,
            src_ip=sip, dst_ip=dip,
            src_port=sp, dst_port=dp,
            num_pkts=pkts_per_flow,
            pkt_payload_sizes=sizes,
            isn=isn,
        ))

    return specs


# ---------------------------------------------------------------------------
# Packet building
# ---------------------------------------------------------------------------

def build_packets_for_flow(spec: FlowSpec,
                            patterns: List[bytes]) -> list:
    """
    Build Scapy packet objects for one flow.

    Sequence numbers are coherent: each packet's SEQ advances by the
    payload length of the previous packet.

    The first packet carries a SYN (flags="S") with no payload.
    Data packets follow with flags="PA" (PSH+ACK).
    The last packet is a FIN+ACK.
    """
    packets = []
    seq = spec.isn

    # --- SYN ---
    syn = (
        Ether() /
        IP(src=spec.src_ip, dst=spec.dst_ip) /
        TCP(sport=spec.src_port, dport=spec.dst_port,
            seq=seq, flags="S")
    )
    packets.append(syn)
    seq = (seq + 1) & 0xFFFFFFFF   # SYN consumes one seq number

    # --- Data packets ---
    for pkt_idx, payload_sz in enumerate(spec.pkt_payload_sizes):
        payload = bytes(range(payload_sz % 256)) * (payload_sz // 256 + 1)
        payload = payload[:payload_sz]

        # Insert test pattern into the first data packet
        if pkt_idx == 0 and patterns:
            pat = random.choice(patterns)
            if len(payload) >= len(pat):
                insert_at = 0  # deterministic: always at offset 0
                payload = bytearray(payload)
                payload[insert_at: insert_at + len(pat)] = pat
                payload = bytes(payload)
            else:
                payload = pat + payload  # prepend if payload shorter than pattern

        pkt = (
            Ether() /
            IP(src=spec.src_ip, dst=spec.dst_ip) /
            TCP(sport=spec.src_port, dport=spec.dst_port,
                seq=seq, flags="PA") /
            Raw(load=payload)
        )
        packets.append(pkt)
        seq = (seq + len(payload)) & 0xFFFFFFFF

    # --- FIN+ACK ---
    fin = (
        Ether() /
        IP(src=spec.src_ip, dst=spec.dst_ip) /
        TCP(sport=spec.src_port, dport=spec.dst_port,
            seq=seq, flags="FA")
    )
    packets.append(fin)

    return packets


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(specs: List[FlowSpec], output: str, skew: str):
    total_pkts    = sum(s.num_pkts for s in specs) + 2 * len(specs)  # +SYN+FIN
    total_payload = sum(sum(s.pkt_payload_sizes) for s in specs)
    sizes_flat    = [sz for s in specs for sz in s.pkt_payload_sizes]
    avg_payload   = total_payload / max(len(sizes_flat), 1)

    print("\n=== Synthetic PCAP Summary ===")
    print(f"  Output file      : {output}")
    print(f"  Skew             : {skew}")
    print(f"  Unique flows     : {len(specs)}")
    print(f"  Total packets    : {total_pkts}  (includes SYN + FIN per flow)")
    print(f"  Total app payload: {total_payload} bytes")
    print(f"  Avg per-pkt size : {avg_payload:.1f} bytes")
    if sizes_flat:
        print(f"  Min payload      : {min(sizes_flat)} bytes")
        print(f"  Max payload      : {max(sizes_flat)} bytes")
    print("==============================\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a synthetic PCAP with configurable flow-size skew.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--output", default="data/synthetic.pcap",
                        help="Output PCAP file path.")
    parser.add_argument("--flows", type=int, default=50,
                        help="Number of unique TCP flows.")
    parser.add_argument("--packets-per-flow", type=int, default=10,
                        help="Number of DATA packets per flow (excludes SYN/FIN).")
    parser.add_argument("--skew", choices=["even", "moderate", "high"],
                        default="even",
                        help="Flow-size distribution shape.")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility.")
    parser.add_argument("--min-payload", type=int, default=20,
                        help="Minimum per-packet application payload bytes.")
    parser.add_argument("--max-payload", type=int, default=1400,
                        help="Maximum per-packet application payload bytes.")
    parser.add_argument("--pattern", type=str, default="",
                        help="Comma-separated ASCII test patterns to embed "
                             "(e.g. 'TESTSIG,ATTACK'). Leave empty for none.")

    args = parser.parse_args()

    # Validate
    if args.flows < 1:
        print("ERROR: --flows must be >= 1", file=sys.stderr); sys.exit(1)
    if args.packets_per_flow < 1:
        print("ERROR: --packets-per-flow must be >= 1", file=sys.stderr); sys.exit(1)
    if args.min_payload < 1:
        print("ERROR: --min-payload must be >= 1", file=sys.stderr); sys.exit(1)
    if args.max_payload < args.min_payload:
        print("ERROR: --max-payload must be >= --min-payload", file=sys.stderr)
        sys.exit(1)

    # Parse test patterns
    patterns: List[bytes] = []
    if args.pattern.strip():
        patterns = [p.encode("ascii") for p in args.pattern.split(",") if p.strip()]

    rng = random.Random(args.seed)

    print(f"[generate_pcap] seed={args.seed}, flows={args.flows}, "
          f"pkts/flow={args.packets_per_flow}, skew={args.skew}")

    # Build flow specs
    specs = build_flow_specs(
        num_flows=args.flows,
        pkts_per_flow=args.packets_per_flow,
        skew=args.skew,
        rng=rng,
        min_payload=args.min_payload,
        max_payload=args.max_payload,
    )

    # Build packets (interleave flows to simulate realistic capture order)
    all_packets = []
    per_flow_pkts = [build_packets_for_flow(s, patterns) for s in specs]

    # Round-robin interleave packets across flows
    max_len = max(len(p) for p in per_flow_pkts)
    for i in range(max_len):
        for fp in per_flow_pkts:
            if i < len(fp):
                all_packets.append(fp[i])

    # Write PCAP
    wrpcap(args.output, all_packets)
    print(f"[generate_pcap] Written {len(all_packets)} packets to {args.output!r}")

    print_summary(specs, args.output, args.skew)


if __name__ == "__main__":
    main()
