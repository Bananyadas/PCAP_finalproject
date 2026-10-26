# PCAP Input & Flow Management (C11 + OpenMP + libpcap)

This is my component of **Adaptive Parallel Packet Grouping for GPU-Based Network Attack Detection**.
It reads an offline PCAP, rebuilds every TCP byte stream, and exports them in a GPU-friendly layout
(`include/shared.h`) for the batcher, the cost predictor and the CUDA matcher.

## Build & run (Linux / WSL)
```bash
sudo apt-get install -y build-essential libpcap-dev
make              # builds pcap_flow + 4 test programs
make run_tests    # runs every test suite
./pcap_flow data/netmetria-focused-scenario.pcap 4   # 4 = OpenMP threads
```
Synthetic captures (needs `pip install scapy`):
```bash
python3 scripts/generate_pcap.py --output synth.pcap --flows 1000 --packets-per-flow 50 --skew high
```

## Layout
| File | Role |
|---|---|
| [shared.h](include/shared.h) | Team structs `Segment`, `Match`, `FlowRec` (layout fixed, static-asserted) |
| [packet_parser.c](src/packet_parser.c) | libpcap loading, Ethernet/VLAN/IPv4/TCP parsing, OpenMP `parse_all` |
| [flow_table.c](src/flow_table.c) | FNV-1a hash table, linear probing, sequential packet processing |
| [tcp_reassembly.c](src/tcp_reassembly.c) | In-order stream rebuild, OOO list, first-wins, gaps |
| [flow_export.c](src/flow_export.c) | Byte arena + `Segment[]` + `FlowRec[]`, `export_verify`, checksum |
| [main.c](src/main.c) | Driver: timing + statistics |
| `tests/` | 40 unit tests (parser 12, flow table 10, reassembly 10, export 8) |

## Pipeline
```
PCAP file --(libpcap, I/O timed separately)--> PacketList (all in RAM)
        --(OpenMP parallel for)-->             ParsedPacket[]   (one per packet)
        --(sequential, file order)-->          FlowTable + TcpStream per flow
        --> export: arena | Segment[] (sorted by flow_id) | FlowRec[]
```

## Design decisions (viva notes)
- **Why load everything first?** Disk I/O would dominate timing; loading first lets us measure
  processing separately and gives OpenMP an array to split.
- **Why is parsing parallel?** Each packet is independent: thread *i* only writes `out[i]` → no locks,
  no races. `schedule(dynamic,64)` balances uneven packet sizes.
- **Why is the flow stage sequential?** TCP reassembly depends on packet order. Doing it in file order
  guarantees identical flow_ids and bytes for any thread count (test `e08` checks 1/2/4/8 threads give
  the same checksum).
- **Header lengths:** IPv4 header = `IHL × 4`, TCP header = `data offset × 4`, so options are skipped
  correctly. Payload ends at IP *total length* (ignores Ethernet padding).
- **Byte-wise reads** (`rd16/rd32`) avoid unaligned pointer casts and convert big-endian in one step.
- **Flow key:** directional 5-tuple (A→B and B→A are different flows). Hash = FNV-1a 64 over the fields
  in fixed byte order, so struct padding never matters.
- **Hash table:** open addressing + linear probing, power-of-two size, doubles at 70% load. On equal
  hashes the full tuple is compared, so collisions are harmless (test `f09` forces one).
- **Eviction policy:** none. Offline input is finite; all flows are finalised together at EOF.
- **Sequence numbers wrap at 2³²**, so we compare with `(int32_t)(a-b) < 0`.
- **SYN** consumes one sequence number → data starts at ISN+1. No SYN captured → stream starts at the
  first seen packet.
- **First-wins overlap:** bytes we already hold are never replaced by a later retransmission.
- **Out-of-order:** buffered in a sorted, non-overlapping linked list; capped at 64 MiB per flow
  (excess dropped and counted).
- **Gaps:** data after a missing hole is never glued onto the stream; it is counted as *stranded*.
- **Export:** one `Segment` per flow, `carry = 0`, empty flows keep a `len = 0` segment; totals above
  `UINT32_MAX` are refused (no silent truncation). `FlowRec.key` = flow hash, `cost_est = 0`.

## Observed result on the provided capture
`data/netmetria-focused-scenario.pcap`: 1592 packets (1276 TCP, 316 non-TCP), 204 directional flows,
95,774 payload bytes reassembled, 0 gaps, `export verify: OK`, same checksum with 1 and 4 threads.
(Capture is tiny, so timings are not meaningful as a benchmark.)

## Measured results on synthetic captures
Generated with `generate_pcap.py --flows 2000 --packets-per-flow 40 --seed 1 --min-payload 64 --max-payload 512`,
run in WSL2 (Ubuntu 24.04) on files under `/mnt/c`. Single run each, so treat timings as rough.

| Skew | Packets | Bytes reassembled | Threads | Parse (s) | Flows+reasm (s) | Processing (s) | Checksum |
|---|---|---|---|---|---|---|---|
| even | 84,000 | 22,984,990 | 1 | 0.0086 | 0.0751 | 0.1176 | c9ed3be51d692ee0 |
| even | 84,000 | 22,984,990 | 4 | 0.0042 | 0.0770 | 0.1110 | c9ed3be51d692ee0 |
| moderate | 93,327 | 25,749,484 | 1 | 0.0069 | 0.0693 | 0.1064 | 79cb889c97dd3b79 |
| moderate | 93,327 | 25,749,484 | 4 | 0.0129 | 0.1065 | 0.1630 | 79cb889c97dd3b79 |
| high | 83,002 | 22,765,498 | 1 | 0.0085 | 0.0706 | 0.1117 | 8e080d3dc6e868fe |
| high | 83,002 | 22,765,498 | 4 | 0.0105 | 0.1047 | 0.1553 | 8e080d3dc6e868fe |

**What this shows (honestly):**
- **Correctness:** every run has 2000 flows, 0 gaps, `export verify: OK`, and the checksum is identical
  for 1 and 4 threads → the output is deterministic.
- **Speed-up is small/noisy.** Parsing is only ~7% of processing time; the sequential flow/reassembly
  stage (~65%) dominates, so by Amdahl's law parallel parsing cannot give a large overall speed-up.
  Parse halved on `even` (0.0086 → 0.0042 s) but other runs were slower at 4 threads — at ~10 ms the
  OpenMP thread start-up and WSL timing noise are as large as the work itself.
- **I/O (2.6–18 s) dwarfs processing** because WSL reads `/mnt/c` (Windows disk) slowly; this is why
  I/O is timed separately. Copying the PCAP into the Linux filesystem (e.g. `~/`) is much faster.

Reproduce: `bash scripts/run_bench.sh` (after generating `synth/*.pcap`).

## Limitations
- IPv4 + TCP only (no IPv6, UDP streams, IP fragment reassembly — fragments are counted and skipped).
- One VLAN tag supported; Ethernet link type only.
- Mid-stream capture without SYN: an early out-of-order first packet becomes the stream start.
- Flow stage is single-threaded by design (determinism); whole capture must fit in RAM.
- RST is not specially handled; no flow timeouts (offline only).
