#!/usr/bin/env bash
# run_bench.sh - run pcap_flow on every synth/*.pcap with 1 and 4 threads.
cd "$(dirname "$0")/.."
for f in synth/*.pcap; do
  for t in 1 4; do
    echo "== $f threads=$t"
    ./pcap_flow "$f" "$t" | grep -E '^packets|flows \(|reassembled|gaps|checksum|verify|I/O|parse \(|flows\+|processing'
  done
done
