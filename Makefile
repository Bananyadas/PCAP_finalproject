# Makefile — host-only build works anywhere; GPU targets need nvcc.
#
#   make test        CPU reference tests (no GPU needed)
#   make gputest     CPU-vs-GPU diff      (needs nvcc + a GPU)

CXX      ?= g++
NVCC     ?= nvcc
CXXFLAGS := -O2 -std=c++17 -Iinclude -Wall -Wextra
NVFLAGS  := -O3 -std=c++17 -Iinclude -lineinfo

HOST_SRC := src/rules.cpp src/pfac.cpp src/cpu_match.cpp

.PHONY: all test gputest dump clean

all: test

test: test_cpu
	./test_cpu

test_cpu: tests/test_cpu.cpp $(HOST_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

gputest: test_gpu
	./test_gpu

test_gpu: tests/test_gpu.cu src/gpu_match.cu $(HOST_SRC)
	$(NVCC) $(NVFLAGS) -o $@ $^

# Profiling: warp execution efficiency is the metric that shows WHY the
# adaptive composer helps. Run this once the composer is wired in.
profile: test_gpu
	ncu --metrics smsp__thread_inst_executed_per_inst_executed.ratio,\
sm__warps_active.avg.pct_of_peak_sustained_active ./test_gpu

clean:
	rm -f test_cpu test_gpu dump_patterns

# Inspect what the parser pulls out of a .rules file:
#   make dump RULES=rules/et.rules
dump: dump_patterns
	./dump_patterns $(RULES) | head -40

dump_patterns: tools/dump_patterns.cpp src/rules.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^
