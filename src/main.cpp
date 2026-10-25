/**
 * main.cpp — PCAP Flow Manager driver.
 *
 * Usage:
 *   ./pcap_flow <pcap_file> [num_threads]
 *
 * Stages:
 *   1. Read the entire PCAP into memory (I/O time is measured separately).
 *   2. Parse packets in parallel (OpenMP).
 *   3. Build the flow table (sequential — not thread-safe).
 *   4. TCP reassembly per flow (sequential per flow).
 *   5. Export byte arena and Segment array.
 *   6. Print performance statistics.
 */

#include "packet_parser.h"
#include "flow_table.h"
#include "tcp_reassembly.h"
#include "flow_export.h"
#include "shared.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <omp.h>

/* Simple wall-clock timer */
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

static double elapsed_ms(TimePoint start, TimePoint end)
{
    return std::chrono::duration<double, std::milli>(end - start).count();
}

int main(int argc, char* argv[])
{
    /* ------------------------------------------------------------------ */
    /* 0. Parse command-line arguments                                     */
    /* ------------------------------------------------------------------ */
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <pcap_file> [num_threads]\n"
                "  pcap_file   — path to a .pcap file\n"
                "  num_threads — number of OpenMP threads (default: system)\n",
                argv[0]);
        return 1;
    }

    const char* pcap_file   = argv[1];
    int         num_threads = (argc >= 3) ? atoi(argv[2]) : 0;

    if (num_threads > 0) {
        omp_set_num_threads(num_threads);
        printf("[main] Using %d OpenMP thread(s).\n", num_threads);
    } else {
        printf("[main] Using default OpenMP thread count (%d available).\n",
               omp_get_max_threads());
    }

    /* ------------------------------------------------------------------ */
    /* 1. Load PCAP into memory (file I/O — timed separately)             */
    /* ------------------------------------------------------------------ */
    printf("[main] Loading PCAP: %s\n", pcap_file);
    auto t_io_start = Clock::now();

    std::vector<RawPacket> raw_packets;
    if (!pcap_load(pcap_file, raw_packets)) {
        return 1;
    }

    auto t_io_end = Clock::now();
    printf("[main] File I/O time: %.2f ms (%zu packets)\n",
           elapsed_ms(t_io_start, t_io_end), raw_packets.size());

    if (raw_packets.empty()) {
        fprintf(stderr, "[main] No packets in file. Exiting.\n");
        return 0;
    }

    /* ------------------------------------------------------------------ */
    /* 2. Parse packets in parallel (OpenMP)                               */
    /* ------------------------------------------------------------------ */
    printf("[main] Parsing packets...\n");
    auto t_parse_start = Clock::now();

    ParseStats    parse_stats;
    auto parsed = parse_all_packets(raw_packets, parse_stats);

    auto t_parse_end = Clock::now();
    pcap_stats_print(parse_stats);
    printf("[main] Parsing time: %.2f ms\n",
           elapsed_ms(t_parse_start, t_parse_end));

    /* ------------------------------------------------------------------ */
    /* 3. Build flow table (sequential)                                    */
    /*                                                                     */
    /* Why sequential? The hash table uses shared mutable state.           */
    /* We parallelised the CPU-heavy parsing step above. Grouping by flow  */
    /* is cheaper and must be deterministic.                               */
    /* ------------------------------------------------------------------ */
    printf("[main] Building flow table...\n");
    auto t_flow_start = Clock::now();

    FlowTable flow_table = flow_table_init(1024);

    for (uint32_t i = 0; i < static_cast<uint32_t>(parsed.size()); ++i) {
        const ParsedPacket& pkt = parsed[i];
        if (!pkt.valid) continue;

        /* Count the raw packet bytes for the flow's byte_count */
        flow_table_insert(flow_table, pkt.tuple,
                          raw_packets[pkt.raw_idx].caplen);
    }

    auto t_flow_end = Clock::now();
    flow_table_print_stats(flow_table);
    printf("[main] Flow table time: %.2f ms\n",
           elapsed_ms(t_flow_start, t_flow_end));

    /* ------------------------------------------------------------------ */
    /* 4. TCP Reassembly                                                   */
    /*                                                                     */
    /* Group parsed packets by flow_id, then process each flow's packets  */
    /* in sequence-number order (not capture order).                       */
    /* ------------------------------------------------------------------ */
    printf("[main] Reassembling TCP flows...\n");
    auto t_reassembly_start = Clock::now();

    /* Map from flow_id → ReassemblyBuffer */
    std::unordered_map<uint32_t, ReassemblyBuffer> reassembly_map;
    reassembly_map.reserve(flow_table.count);

    /* First pass: create a buffer for every known flow */
    for (const auto& slot : flow_table.slots) {
        if (!slot.occupied) continue;
        reassembly_map[slot.flow_id] = reassembly_buffer_init(slot.flow_id);
    }

    /* Second pass: feed segments to their flow's buffer.
     * We process packets in their original capture order here.
     * The reassembly engine sorts them internally by sequence number. */
    for (uint32_t i = 0; i < static_cast<uint32_t>(parsed.size()); ++i) {
        const ParsedPacket& pkt = parsed[i];
        if (!pkt.valid) continue;

        /* Look up the flow_id */
        FlowEntry* entry = flow_table_lookup(flow_table, pkt.tuple);
        if (!entry) continue; /* should never happen */

        /* Retrieve the payload bytes from the raw packet */
        const RawPacket& raw = raw_packets[pkt.raw_idx];
        const uint8_t*   payload_ptr = raw.data.data() + pkt.payload_offset;

        reassembly_add_segment(reassembly_map[entry->flow_id],
                               pkt.seq,
                               payload_ptr,
                               pkt.tcp_payload_len);
    }

    /* Finalise all buffers (detect gaps) */
    uint32_t total_gaps = 0;
    for (auto& kv : reassembly_map) {
        reassembly_finalize(kv.second);
        if (kv.second.has_gaps) total_gaps++;
    }

    auto t_reassembly_end = Clock::now();
    printf("[main] Reassembly time: %.2f ms\n",
           elapsed_ms(t_reassembly_start, t_reassembly_end));

    /* ------------------------------------------------------------------ */
    /* 5. Export byte arena + Segment array                                */
    /* ------------------------------------------------------------------ */
    printf("[main] Exporting segments...\n");

    /* Flatten the map into a vector for export_flows() */
    std::vector<ReassemblyBuffer> buffers;
    buffers.reserve(reassembly_map.size());
    for (auto& kv : reassembly_map) buffers.push_back(std::move(kv.second));

    ExportResult export_result;
    if (!export_flows(buffers, export_result)) {
        fprintf(stderr, "[main] Export failed (overflow). Exiting.\n");
        return 1;
    }

    if (!export_verify(export_result)) {
        fprintf(stderr, "[main] Export verification FAILED.\n");
        return 1;
    }

    export_print_stats(export_result);

    /* ------------------------------------------------------------------ */
    /* 6. Performance summary                                              */
    /* ------------------------------------------------------------------ */
    double total_processing_ms =
        elapsed_ms(t_parse_start, t_reassembly_end);

    printf("=== Performance Summary ===\n");
    printf("  PCAP file             : %s\n",  pcap_file);
    printf("  Total packets read    : %u\n",  parse_stats.total);
    printf("  Valid TCP packets     : %u\n",  parse_stats.valid_tcp);
    printf("  Unique flows          : %u\n",  flow_table.count);
    printf("  Arena size (bytes)    : %zu\n", export_result.arena.size());
    printf("  Incomplete flows      : %u\n",  export_result.incomplete_flows);
    printf("  Sequence gaps found   : %u\n",  total_gaps);
    printf("  Processing time       : %.2f ms (excludes file I/O)\n",
           total_processing_ms);
    if (total_processing_ms > 0 && parse_stats.total > 0) {
        double pps = parse_stats.total / (total_processing_ms / 1000.0);
        printf("  Throughput            : %.0f packets/sec\n", pps);
    }
    printf("  OpenMP threads        : %d\n",  omp_get_max_threads());
    printf("===========================\n");

    return 0;
}
