# PCAP Flow Manager

**Component**: PCAP Input and Flow Management
**Project**: Adaptive Parallel Packet Grouping for GPU-Based Network Attack Detection
**Language**: C++17 · OpenMP · Python 3 / Scapy
**Platform**: Linux / Ubuntu (including WSL on Windows)

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Directory Layout](#2-directory-layout)
3. [Installation](#3-installation)
4. [Build](#4-build)
5. [Running](#5-running)
6. [Synthetic PCAP Generator](#6-synthetic-pcap-generator)
7. [Testing](#7-testing)
8. [Performance Benchmarking](#8-performance-benchmarking)
9. [Shared Interface](#9-shared-interface)
10. [Design Decisions (Viva Notes)](#10-design-decisions-viva-notes)
11. [Implemented Features](#11-implemented-features)
12. [Known Limitations](#12-known-limitations)

---

## 1. Architecture Overview

```
PCAP file
    │
    ▼
┌─────────────────────────────────┐
│  pcap_load()                    │  libpcap offline read
│  Read ALL packets into memory   │  File I/O timed separately
└──────────────┬──────────────────┘
               │  vector<RawPacket>
               ▼
┌─────────────────────────────────┐
│  parse_all_packets()            │  OpenMP parallel_for
│  Ethernet → IPv4 → TCP parsing  │  Each packet independent
│  Extract 5-tuple + seq info     │  No shared writes
└──────────────┬──────────────────┘
               │  vector<ParsedPacket>
               ▼
┌─────────────────────────────────┐
│  FlowTable                      │  Sequential (shared state)
│  FNV-1a hash + linear probing   │
│  Assigns stable flow_id         │
└──────────────┬──────────────────┘
               │  map<flow_id, ReassemblyBuffer>
               ▼
┌─────────────────────────────────┐
│  TCP Reassembly (per flow)      │  One buffer per flow
│  Sequence-ordered buffering     │  First-wins overlap policy
│  Gap detection                  │
└──────────────┬──────────────────┘
               │  vector<ReassemblyBuffer>
               ▼
┌─────────────────────────────────┐
│  export_flows()                 │  Builds byte arena
│  Fills Segment array            │  Segment.carry = 0
└──────────────┬──────────────────┘
               │
        ┌──────┴──────┐
        │  byte arena │   shared with GPU matcher (downstream)
        │  Segment[]  │
        └─────────────┘
```

---

## 2. Directory Layout

```
PCAP_finalproject/
├── include/
│   ├── shared.h           # Fixed team contract (Segment, Match, FlowRec)
│   ├── packet_parser.h    # PCAP read + header parsing API
│   ├── flow_table.h       # 5-tuple hash table API
│   ├── tcp_reassembly.h   # Per-flow TCP sequence reassembly API
│   └── flow_export.h      # Byte-arena + Segment array export API
├── src/
│   ├── main.cpp           # CLI driver, timing, stats
│   ├── packet_parser.cpp  # libpcap offline read, Eth/IP/TCP parsing
│   ├── flow_table.cpp     # Hash table, flow ID assignment, FlowRec
│   ├── tcp_reassembly.cpp # Sequence-ordered TCP payload reassembly
│   └── flow_export.cpp    # Arena builder, Segment array filler
├── tests/
│   ├── test_parser.cpp    # 8 unit tests for header parsing
│   ├── test_flow_table.cpp# 10 unit tests for hash table
│   ├── test_reassembly.cpp# 8 unit tests for TCP reassembly
│   └── test_export.cpp    # 8 unit tests for Segment export
├── scripts/
│   └── generate_pcap.py   # Scapy synthetic PCAP generator
├── data/
│   └── netmetria-focused-scenario.pcap   # bundled smoke-test capture
├── build/                 # (created by make)
├── Makefile
└── README.md
```

---

## 3. Installation

### On Ubuntu / WSL Ubuntu

```bash
# C++ build tools + libpcap
sudo apt update
sudo apt install -y build-essential libpcap-dev

# Python + Scapy (for the generator)
pip install scapy
```

Verify:
```bash
dpkg -l libpcap-dev   # should show ii
python3 -c "import scapy; print('Scapy OK')"
```

---

## 4. Build

```bash
# Build main binary + all unit-test binaries
make

# Build only the main binary
make pcap_flow

# Build only unit tests
make tests

# Clean everything
make clean
```

---

## 5. Running

```bash
# Basic run on the bundled PCAP
./pcap_flow data/netmetria-focused-scenario.pcap

# Specify number of OpenMP threads explicitly
./pcap_flow data/netmetria-focused-scenario.pcap 4

# Use environment variable instead
OMP_NUM_THREADS=1 ./pcap_flow data/netmetria-focused-scenario.pcap
OMP_NUM_THREADS=8 ./pcap_flow data/netmetria-focused-scenario.pcap
```

### Sample output

```
[pcap_load] Opened 'data/netmetria-focused-scenario.pcap' (link-layer: Ethernet)
[pcap_load] Read 1842 packets into memory.
[main] File I/O time: 3.21 ms (1842 packets)

=== Packet Parsing Statistics ===
  Total packets read      : 1842
  Valid TCP (with payload): 1234
  Skipped — not TCP       : 456
  Skipped — no payload    : 152
  ...

=== Flow Table Statistics ===
  Unique flows    : 87
  Load factor     : 33.98%

=== Export Statistics ===
  Arena size (bytes)    : 524288
  Segments exported     : 87
  Incomplete flows      : 3

=== Performance Summary ===
  Processing time : 12.40 ms (excludes file I/O)
  Throughput      : 148548 packets/sec
  OpenMP threads  : 4
```

---

## 6. Synthetic PCAP Generator

```bash
# Even distribution — 100 flows, 10 packets each
python3 scripts/generate_pcap.py \
    --output data/synthetic_even.pcap \
    --flows 100 \
    --packets-per-flow 10 \
    --skew even \
    --seed 42

# Moderate skew
python3 scripts/generate_pcap.py \
    --output data/synthetic_moderate.pcap \
    --flows 100 --packets-per-flow 10 \
    --skew moderate --seed 42

# High skew (few large flows, many tiny)
python3 scripts/generate_pcap.py \
    --output data/synthetic_high.pcap \
    --flows 100 --packets-per-flow 10 \
    --skew high --seed 42

# With embedded test pattern
python3 scripts/generate_pcap.py \
    --output data/synthetic_pattern.pcap \
    --flows 20 --packets-per-flow 5 \
    --skew even --seed 99 \
    --pattern "TESTSIG,ATTACK"

# Show all options
python3 scripts/generate_pcap.py --help
```

**Payload sizes** refer to **application (TCP) payload bytes** per packet, not total frame bytes.

**Sequence numbers** start from a random ISN and advance coherently by payload length.

**Packet order** in the PCAP: packets from different flows are interleaved in round-robin order, simulating realistic capture order.

---

## 7. Testing

### Run all unit tests

```bash
make run_tests
```

### Run individual test binaries

```bash
./test_parser        # 8 tests: Ethernet/IPv4/TCP parsing
./test_flow_table    # 10 tests: hash table correctness
./test_reassembly    # 8 tests: TCP sequence reassembly
./test_export        # 8 tests: Segment offset/len correctness
```

### Smoke test on real PCAP

```bash
make smoke
```

### Test the generator

```bash
python3 scripts/generate_pcap.py --output /tmp/test.pcap \
    --flows 10 --packets-per-flow 5 --skew even --seed 1
./pcap_flow /tmp/test.pcap
```

### Single-thread vs multi-thread reproducibility check

```bash
OMP_NUM_THREADS=1 ./pcap_flow data/synthetic_even.pcap > /tmp/out1.txt
OMP_NUM_THREADS=4 ./pcap_flow data/synthetic_even.pcap > /tmp/out4.txt
# The "unique flows" and "arena size" lines must match
diff /tmp/out1.txt /tmp/out4.txt
```

---

## 8. Performance Benchmarking

```bash
# 1 thread
OMP_NUM_THREADS=1 ./pcap_flow data/netmetria-focused-scenario.pcap 1

# N threads (replace N with your core count)
OMP_NUM_THREADS=4 ./pcap_flow data/netmetria-focused-scenario.pcap 4

# Time is printed in the "Performance Summary" section.
# File I/O time is excluded from the processing time.
```

The reported **processing time** covers:
- Parallel packet parsing (OpenMP)
- Flow table insertion
- TCP reassembly
- Segment export

File I/O time is printed separately as per project spec.

---

## 9. Shared Interface

These structures are fixed team contracts. **Do not change them.**

```c
typedef struct {
    uint32_t flow_id;  // which flow
    uint32_t offset;   // byte offset into the arena
    uint32_t len;      // valid bytes from that offset
    uint32_t carry;    // always 0 from this component
} Segment;

typedef struct {
    uint32_t seg_idx;  // index into Segment array
    uint32_t pos;      // byte position inside the segment
    uint32_t sig_id;   // matched signature ID
} Match;

typedef struct {
    uint64_t key;      // 64-bit FNV-1a hash of the 5-tuple
    uint64_t bytes;    // total captured bytes for the flow
    float    cost_est; // 0.0f from this component
} FlowRec;
```

**Arena ownership**: The `ExportResult` object owns both the arena and the
segment array. The GPU matcher must keep `ExportResult` alive for as long as
it reads from the arena. Do not free the arena before the matcher finishes.

---

## 10. Design Decisions (Viva Notes)

### Why FNV-1a for hashing?
FNV-1a is fast (no division, no lookup tables), produces well-distributed
64-bit output, and is simple enough to explain in one line:
`hash = (hash XOR byte) * prime`. We still do a full 5-tuple comparison
on collision because a 64-bit hash is not collision-proof.

### Why open addressing with linear probing?
- Cache-friendly: collision resolution stays on nearby cache lines.
- Simple to implement correctly.
- Automatically resizes at 70% load factor to keep expected probe length short.

### Why directional flows?
`(A→B)` and `(B→A)` are different flows by default. This is the correct
approach for detecting attacks: a client sending data and a server responding
are two different traffic streams. The team can later add canonical-key logic
if bidirectional analysis is needed.

### Why first-wins for TCP overlap?
In real captures, retransmissions usually carry identical data. When they
carry different data it normally means a forged or corrupted packet.
First-wins (accept earlier data, reject later contradiction) is safe,
documented, and simple to explain.

### Why sequential flow table updates?
The hash table uses shared mutable state. Locking every insert with a mutex
would add overhead and complexity. Since packet *parsing* is the
computationally heavy step, parallelising that (OpenMP `parallel for`) and
keeping the table updates sequential gives most of the speedup with zero
risk of data races.

### Sequence-number wrap-around
TCP sequence numbers are 32-bit unsigned. After `0xFFFFFFFF` they wrap to `0`.
We use signed subtraction (`(int32_t)(a - b) < 0`) to compare sequence numbers
correctly across the wrap boundary.

### What is `carry` and why is it always 0?
`carry` is a cross-batch tail field owned by the downstream batch composer.
This component does not know how the GPU processes batches, so we always write
0 and document that the batch composer must fill the real value.

---

## 11. Implemented Features

| Feature | Status |
|---------|--------|
| Offline PCAP reading (libpcap) | ✅ |
| Ethernet header parsing | ✅ |
| IPv4 header parsing (with options) | ✅ |
| TCP header parsing (with options) | ✅ |
| 5-tuple extraction | ✅ |
| Directional flow table (FNV-1a + linear probing) | ✅ |
| Auto-resize at 70% load | ✅ |
| FlowRec export | ✅ |
| TCP sequence reassembly (in-order) | ✅ |
| TCP out-of-order buffering | ✅ |
| Retransmission handling (first-wins) | ✅ |
| Sequence-number wrap-around | ✅ |
| Gap detection and reporting | ✅ |
| OOO buffer cap (64 MiB/flow) | ✅ |
| OpenMP parallel parsing | ✅ |
| Byte arena construction | ✅ |
| Segment array with overflow check | ✅ |
| export_verify() sanity check | ✅ |
| Synthetic PCAP generator (3 skew modes) | ✅ |
| Test-pattern embedding | ✅ |
| Unit tests (34 cases across 4 files) | ✅ |
| Separate I/O and processing timers | ✅ |
| Throughput reporting (pkt/sec) | ✅ |

---

## 12. Known Limitations

| Limitation | Notes |
|------------|-------|
| Ethernet only | Packets on non-Ethernet link layers are rejected cleanly with an error message. |
| IPv4 only | IPv6 is not parsed; packets are counted as "not IPv4". |
| TCP only | UDP, ICMP, etc. are counted as "not TCP". |
| No IP fragmentation reassembly | Fragmented IPv4 packets are parsed as-is; if the TCP header lands in a later fragment it will be missed. |
| Directional flows only | (A→B) and (B→A) are separate flows. Bidirectional flow merging not implemented. |
| No live capture | Only offline PCAP files are supported (libpcap offline mode). |
| `carry` always 0 | The downstream batch composer must write the real cross-batch carry value. |
| No batch splitting | The entire reassembled payload of each flow is one Segment; batch composition is the downstream component's job. |
| OOO buffer capped at 64 MiB/flow | Very large out-of-order windows cause drops, which are counted and reported. |
| No PCAP-ng support | Only classic `.pcap` format is read. |
