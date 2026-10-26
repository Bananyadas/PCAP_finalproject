# Running everything

Everything is plain C (C11) plus two CUDA files; the only Python is the trace generator.
Ananyaraj's repo is never modified - it is only compiled from. His code is C now, and
`pcap_bridge.c` is the one file that talks to it.

## A. On Kaggle (the GPU run) - needs only this zip
See the step-by-step in the chat message. In short: upload this zip as a Dataset, open a notebook with a
GPU, copy the folder to /kaggle/working, run `bash kaggle_run.sh`.

## B. On a laptop / WSL (optional: rebuild traces, CPU model)
```
sudo apt update && sudo apt install -y build-essential libpcap-dev python3-pip && pip install scapy
mkdir work && cd work
git clone https://github.com/Bananyadas/pcap_finalproject ananya_orig     # his repo, untouched
unzip final.zip && cd final
make                  # ./bench          CPU build, reads PCAPs through his code
make nopcap           # ./bench_nopcap   CPU build, reads traces/*.flows (no libpcap)
./bench --skew 1.0                                       # self-test: PASS PASS IDENTICAL
python3 tools/gen_traces.py --output t.pcap --flows 300 --packets-per-flow 30 --zipf 1.0 \
        --content mixed --straddle --reorder 0.1 --pattern ATTACKSIG --seed 4
./bench --pcap t.pcap --sig-text ATTACKSIG --slice-kb 8                         # CPU model + correctness
./bench --pcap t.pcap --sig-text ATTACKSIG --dump-flows traces/mine.flows --dump-only   # for Kaggle
./bench --pcap ../ananya_orig/synth/high.pcap --sig-text ATTACKSIG              # his own captures work too
```
Flags: `--mode static|adaptive|both`, `--skew S` (built-in synthetic traces), `--batch-kb`, `--chunk`,
`--slice-kb`, `--alpha`, `--sigs file` (hex, one pattern per line), `--sig-text a,b`, `--gpu` (GPU build only).

## What the output means
* `PASS` = that mode's alerts equal the oracle (every flow scanned whole, no cuts): nothing missed, nothing extra.
* `IDENTICAL` = static and adaptive found exactly the same alerts. Must always hold.
* GPU build: `measured speedup` is real wall-clock. CPU build: `modelled GPU speedup` is a model, not a measurement.
