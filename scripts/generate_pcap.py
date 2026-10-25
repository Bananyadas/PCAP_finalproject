#!/usr/bin/env python3
"""
generate_pcap.py - Synthetic TCP PCAP generator for testing the flow manager.

Each flow:  SYN  ->  N data packets (PSH|ACK)  ->  FIN|ACK
  * random ISN per flow; seq advances by payload length (SYN uses 1)
  * flows are interleaved round-robin, like real concurrent traffic
  * --skew controls how unequal flow sizes are:
        even     : every flow gets --packets-per-flow packets
        moderate : sizes vary roughly 0.25x .. 2x
        high     : a few "elephant" flows, many "mice" (Pareto-like)

Example:
    python3 scripts/generate_pcap.py --output data/synth_high.pcap \
        --flows 1000 --packets-per-flow 50 --skew high --seed 1
"""
import argparse
import random

from scapy.all import Ether, IP, TCP, Raw, wrpcap  # pip install scapy


def flow_sizes(n_flows, ppf, skew, rng):
    if skew == "even":
        return [ppf] * n_flows
    if skew == "moderate":
        return [max(1, int(ppf * rng.uniform(0.25, 2.0))) for _ in range(n_flows)]
    # high: Pareto distribution, normalised so the mean is about ppf
    raw = [rng.paretovariate(1.2) for _ in range(n_flows)]
    mean = sum(raw) / n_flows
    return [max(1, int(ppf * r / mean)) for r in raw]


def make_payload(rng, lo, hi, pattern):
    n = rng.randint(lo, hi)
    if pattern and rng.random() < 0.1:  # sometimes embed a "signature"
        p = pattern.encode()
        if n >= len(p):
            pos = rng.randint(0, n - len(p))
            body = bytearray(rng.getrandbits(8) for _ in range(n))
            body[pos:pos + len(p)] = p
            return bytes(body)
    return bytes(rng.getrandbits(8) for _ in range(n))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output", required=True)
    ap.add_argument("--flows", type=int, default=100)
    ap.add_argument("--packets-per-flow", type=int, default=20)
    ap.add_argument("--skew", choices=["even", "moderate", "high"], default="even")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--min-payload", type=int, default=64)
    ap.add_argument("--max-payload", type=int, default=1400)
    ap.add_argument("--pattern", default="", help="optional byte string to embed in ~10%% of payloads")
    a = ap.parse_args()

    rng = random.Random(a.seed)
    sizes = flow_sizes(a.flows, a.packets_per_flow, a.skew, rng)

    # Build each flow's packet list.
    flows = []
    for i in range(a.flows):
        src = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        dst = "192.168.100.1"
        sport, dport = 1024 + (i % 60000), 80
        isn = rng.getrandbits(32)
        base = Ether() / IP(src=src, dst=dst)
        pkts = [base / TCP(sport=sport, dport=dport, flags="S", seq=isn)]
        seq = (isn + 1) & 0xFFFFFFFF
        for _ in range(sizes[i]):
            pl = make_payload(rng, a.min_payload, a.max_payload, a.pattern)
            pkts.append(base / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / Raw(pl))
            seq = (seq + len(pl)) & 0xFFFFFFFF
        pkts.append(base / TCP(sport=sport, dport=dport, flags="FA", seq=seq))
        flows.append(pkts)

    # Round-robin interleave.
    out, idx, t = [], [0] * a.flows, 0.0
    remaining = sum(len(f) for f in flows)
    while remaining:
        for i, f in enumerate(flows):
            if idx[i] < len(f):
                p = f[idx[i]]
                p.time = t
                t += 0.00001
                out.append(p)
                idx[i] += 1
                remaining -= 1

    wrpcap(a.output, out)
    payload = sum(len(p[Raw].load) for p in out if Raw in p)
    print(f"wrote {a.output}: {len(out)} packets, {a.flows} flows, skew={a.skew}, "
          f"payload={payload} bytes, largest flow={max(sizes)} pkts, smallest={min(sizes)} pkts")


if __name__ == "__main__":
    main()
