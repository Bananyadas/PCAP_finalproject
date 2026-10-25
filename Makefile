# =============================================================================
# Makefile — PCAP Flow Manager
#
# Usage (inside WSL/Ubuntu):
#   make              — build the main binary and all tests
#   make pcap_flow    — build only the main binary
#   make tests        — build all unit-test binaries
#   make run_tests    — build and run all unit tests
#   make clean        — remove all build artefacts
#
# Dependencies:
#   sudo apt install build-essential libpcap-dev
# =============================================================================

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -fopenmp -Iinclude
LDFLAGS  := -lpcap -fopenmp

SRC_DIR   := src
TEST_DIR  := tests
BUILD_DIR := build

# Source files shared between main and tests
COMMON_SRCS := $(SRC_DIR)/packet_parser.cpp \
               $(SRC_DIR)/flow_table.cpp     \
               $(SRC_DIR)/tcp_reassembly.cpp \
               $(SRC_DIR)/flow_export.cpp

COMMON_OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(COMMON_SRCS))

# -----------------------------------------------------------------------
# Default target — build everything
# -----------------------------------------------------------------------
.PHONY: all
all: pcap_flow tests

# -----------------------------------------------------------------------
# Main binary
# -----------------------------------------------------------------------
pcap_flow: $(BUILD_DIR)/main.o $(COMMON_OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@
	@echo "[make] Built: pcap_flow"

# -----------------------------------------------------------------------
# Unit-test binaries
# -----------------------------------------------------------------------
TEST_BINS := test_parser test_flow_table test_reassembly test_export

.PHONY: tests
tests: $(TEST_BINS)

test_parser: $(BUILD_DIR)/test_parser.o $(COMMON_OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@

test_flow_table: $(BUILD_DIR)/test_flow_table.o $(COMMON_OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@

test_reassembly: $(BUILD_DIR)/test_reassembly.o $(COMMON_OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@

test_export: $(BUILD_DIR)/test_export.o $(COMMON_OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@

# -----------------------------------------------------------------------
# Compile rules
# -----------------------------------------------------------------------
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# -----------------------------------------------------------------------
# Run all unit tests
# -----------------------------------------------------------------------
.PHONY: run_tests
run_tests: tests
	@echo "\n===== test_parser ====="
	./test_parser
	@echo "\n===== test_flow_table ====="
	./test_flow_table
	@echo "\n===== test_reassembly ====="
	./test_reassembly
	@echo "\n===== test_export ====="
	./test_export
	@echo "\n===== All tests completed ====="

# -----------------------------------------------------------------------
# Convenience: run main on the bundled NetMetria capture
# -----------------------------------------------------------------------
.PHONY: smoke
smoke: pcap_flow
	./pcap_flow data/netmetria-focused-scenario.pcap

.PHONY: smoke1
smoke1: pcap_flow
	OMP_NUM_THREADS=1 ./pcap_flow data/netmetria-focused-scenario.pcap 1

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) pcap_flow $(TEST_BINS)
	@echo "[make] Cleaned."
