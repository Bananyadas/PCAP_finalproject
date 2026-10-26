# Makefile - PCAP Input & Flow Management (C11 + OpenMP + libpcap)

CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -O2 -fopenmp -Iinclude -D_DEFAULT_SOURCE
LDLIBS  := -lpcap -fopenmp

LIB_SRC := src/packet_parser.c src/flow_table.c src/tcp_reassembly.c src/flow_export.c
LIB_OBJ := $(LIB_SRC:src/%.c=build/%.o)
TESTS   := test_parser test_flow_table test_reassembly test_export
PCAP    := data/netmetria-focused-scenario.pcap

.PHONY: all tests run_tests smoke smoke1 clean

all: pcap_flow tests

build:
	mkdir -p build

build/%.o: src/%.c include/*.h | build
	$(CC) $(CFLAGS) -c $< -o $@

pcap_flow: build/main.o $(LIB_OBJ)
	$(CC) $^ -o $@ $(LDLIBS)

tests: $(TESTS)

test_%: tests/test_%.c tests/test_util.h $(LIB_OBJ)
	$(CC) $(CFLAGS) $< $(LIB_OBJ) -o $@ $(LDLIBS)

run_tests: tests
	@fail=0; for t in $(TESTS); do ./$$t || fail=1; done; \
	if [ $$fail -eq 0 ]; then echo "ALL TEST SUITES PASSED"; else echo "SOME TESTS FAILED"; exit 1; fi

smoke: pcap_flow
	./pcap_flow $(PCAP) 4

smoke1: pcap_flow
	./pcap_flow $(PCAP) 1

clean:
	rm -rf build pcap_flow $(TESTS) *.pcap

# ---------------------------------------------------------------------------
# Matcher (Asmita) - C++17 and CUDA
# nvcc only compiles C++, so this half stays C++ while Ananyaraj's stays C.
# Linking is done by g++ or nvcc, never gcc, so the C++ runtime is included.
# ---------------------------------------------------------------------------

CXX       ?= g++
NVCC      ?= nvcc
CXXFLAGS  := -O2 -std=c++17 -Iinclude -Wall -Wextra
NVFLAGS   := -O3 -std=c++17 -Iinclude -lineinfo

MATCH_SRC := src/rules.cpp src/pfac.cpp src/cpu_match.cpp

.PHONY: matcher_test gputest dump matcher_clean

matcher_test: test_cpu
	./test_cpu

test_cpu: tests/test_cpu.cpp $(MATCH_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

gputest: test_gpu
	./test_gpu

test_gpu: tests/test_gpu.cu src/gpu_match.cu $(MATCH_SRC)
	$(NVCC) $(NVFLAGS) -o $@ $^

dump: dump_patterns
	./dump_patterns $(RULES) | head -40

dump_patterns: tools/dump_patterns.cpp src/rules.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

matcher_clean:
	rm -f test_cpu test_gpu dump_patterns
