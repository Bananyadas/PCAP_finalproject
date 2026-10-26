# Everything of ours lives in this folder. Ananyaraj's repo is NEVER modified: it is compiled from
# wherever ANANYA points (a plain `git clone` of his repo).
#
#   make                 CPU build with PCAP input   -> ./bench        (laptop: needs libpcap-dev, ANANYA)
#   make nopcap          CPU build, flows-file input -> ./bench_nopcap (no libpcap, no ANANYA needed)
#   make gpu-nopcap      CUDA build                  -> ./bench_gpu_nopcap  (Kaggle)
#   make fakegpu         GPU code path tested on the CPU
ANANYA ?= ../ananya_orig
CC  ?= gcc
CFLAGS   ?= -O2 -std=c11 -Wall -Wextra
HISFLAGS ?= -O2 -std=c11 -Wall -Wextra -fopenmp -D_DEFAULT_SOURCE -I$(ANANYA)/include

CORE   = composer.c predictor.c scanner_cpu.c pipeline.c bench.c
HIS    = $(ANANYA)/src/packet_parser.c $(ANANYA)/src/flow_table.c $(ANANYA)/src/tcp_reassembly.c $(ANANYA)/src/flow_export.c
HDRS   = contracts.h predictor.h composer.h scanner_cpu.h pipeline.h gpu_scan.h pcap_bridge.h
OBJS   = $(CORE:.c=.o)
HISOBJ = packet_parser.o flow_table.o tcp_reassembly.o flow_export.o pcap_bridge.o

NVCC ?= nvcc
ARCH ?= native
CUDA_INC ?= /usr/local/cuda/include

all: bench
bench: $(CORE) $(HDRS) pcap_bridge.c
	$(CC) $(CFLAGS) -DWITH_PCAP -c $(CORE)
	$(CC) $(HISFLAGS) -c $(HIS) pcap_bridge.c
	$(CC) -o $@ $(OBJS) $(HISOBJ) -lpcap -fopenmp -lm -lpthread

nopcap: bench_nopcap
bench_nopcap: $(CORE) $(HDRS)
	$(CC) -O2 -std=c11 -Wall -Wextra -o $@ $(CORE) -lm -lpthread

gpu-nopcap: bench_gpu_nopcap
bench_gpu_nopcap: $(CORE) $(HDRS) gpu_scan.cu kernel_standin.cu
	$(CC) -O2 -std=c11 -Wall -Wextra -DUSE_GPU -I$(CUDA_INC) -c $(CORE)
	$(NVCC) -O2 -arch=$(ARCH) -c gpu_scan.cu kernel_standin.cu
	$(NVCC) -arch=$(ARCH) -o $@ $(OBJS) gpu_scan.o kernel_standin.o -lm -lpthread

fakegpu: $(CORE) $(HDRS) gpu_fake.c
	$(CC) -O2 -std=c11 -Wall -Wextra -DUSE_GPU -o bench_fakegpu $(CORE) gpu_fake.c -lm -lpthread

clean:
	rm -f *.o bench bench_nopcap bench_gpu_nopcap bench_fakegpu
.PHONY: all nopcap gpu-nopcap fakegpu clean

# --- Asmita's kernel, built as a second binary so the two can be compared ---
#   make gpu-asmita ARCH=sm_75   ->  ./bench_gpu_asmita
gpu-asmita: bench_gpu_asmita
bench_gpu_asmita: $(CORE) $(HDRS) gpu_scan.cu kernel_asmita.cu
	$(CC) -O2 -std=c11 -Wall -Wextra -DUSE_GPU -I$(CUDA_INC) -c $(CORE)
	$(NVCC) -O2 -arch=$(ARCH) -c gpu_scan.cu kernel_asmita.cu
	$(NVCC) -arch=$(ARCH) -o $@ $(OBJS) gpu_scan.o kernel_asmita.o -lm -lpthread
