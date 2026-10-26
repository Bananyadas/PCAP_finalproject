#!/usr/bin/env bash
# bench.sh - generate synthetic PCAPs (even/moderate/high skew) and compare 1 vs 4 threads.
# Usage: bash scripts/bench.sh
set -e
cd "$(dirname "$0")/.."
make -s pcap_flow
mkdir -p synth
for s in even moderate high; do
  [ -f synth/$s.pcap ] || python3 scripts/generate_pcap.py --output synth/$s.pcap \
      --flows 2000 --packets-per-flow 40 --skew $s --seed 1 --min-payload 64 --max-payload 512
done
for s in even moderate high; do
  for t in 1 4; do
    echo "== skew=$s threads=$t"
    ./pcap_flow synth/$s.pcap $t | grep -E '^packets|flows \(|reassembled|gaps|checksum|verify|I/O|parse \(|flows\+|processing'
  done
done
