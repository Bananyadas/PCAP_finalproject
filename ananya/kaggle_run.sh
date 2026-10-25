#!/bin/bash
# One command that shows everything on a Kaggle GPU:  bash kaggle_run.sh
# Needs no internet, no libpcap, and none of Ananyaraj's code (his stage was already run on your laptop;
# its output is in traces/*.flows). Saves the full log to results_<gpu>.txt for you to download.
set -o pipefail
cd "$(dirname "$0")"
GPU=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1 | tr ' ' '_')
OUT=results_${GPU:-gpu}.txt
CAP=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | tr -d .); CAP=${CAP:-75}
SIGS=${SIGS:-ATTACKSIG}
{
echo "################ 1. ENVIRONMENT"
nvidia-smi --query-gpu=name,compute_cap,driver_version --format=csv
nvcc --version | tail -2
echo; echo "################ 2. BUILD (CUDA, arch sm_$CAP)"
make clean >/dev/null; make gpu-nopcap ARCH=sm_$CAP 2>&1 | tail -15
[ -x ./bench_gpu_nopcap ] || { echo "BUILD FAILED - send the lines above to Ananya Das"; exit 1; }
echo; echo "################ 3. CORRECTNESS ON THE GPU (every line must say PASS / IDENTICAL)"
./bench_gpu_nopcap --gpu --skew 1.0 --total-mb 16
echo; echo "################ 4. SPEEDUP vs SKEW, synthetic traces (same GPU for every run)"
for s in 0 0.5 1.0 1.5 2.0; do
  ./bench_gpu_nopcap --gpu --skew $s --total-mb 64 | grep -E "^trace|^static|^adaptive|measured|IDENTICAL|DIFFER"
  echo
done
echo "################ 5. TRACES made from PCAPs through Ananyaraj's ingest (traces/*.flows)"
for f in traces/*.flows; do
  echo "--- $f"
  ./bench_gpu_nopcap --gpu --flows-file "$f" --sig-text "$SIGS" --slice-kb 8 | grep -E "^trace|^static|^adaptive|measured|PASS|FAIL|IDENTICAL|DIFFER"
  echo
done
echo "################ DONE. Log saved as $OUT"
} 2>&1 | tee "$OUT"
