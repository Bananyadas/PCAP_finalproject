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
