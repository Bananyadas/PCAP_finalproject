/**
 * flow_table.h — 5-tuple hash table for flow tracking.
 *
 * Key design decisions:
 *   • Directional: (srcIP, srcPort, dstIP, dstPort, proto) ≠ its reverse.
 *   • Open addressing with linear probing; load-factor cap 0.70.
 *   • FlowRec.key stores the 64-bit FNV-1a hash of the 5-tuple.
 *     On hash collision the full FiveTuple is compared for correctness.
 *   • Eviction policy: NONE for offline PCAP analysis.
 *     All flows are kept in memory until the program exits.
 *     Call flow_table_finalize() to flush statistics.
 *   • NOT thread-safe for concurrent insertion/lookup.
 *     The caller must serialise flow-table operations
 *     (parse in parallel, then update the table sequentially).
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "shared.h"
#include "packet_parser.h"  /* FiveTuple */
#include <vector>
#include <cstdint>

/* -----------------------------------------------------------------------
 * FlowEntry — one slot in the open-addressing hash table.
 * --------------------------------------------------------------------- */
struct FlowEntry {
    bool      occupied;    /* true if this slot holds a live flow        */
    FiveTuple tuple;       /* full 5-tuple for collision disambiguation  */
    uint64_t  hash;        /* 64-bit FNV-1a hash of the tuple            */
    uint32_t  flow_id;     /* stable, sequential ID assigned at insert   */
    uint64_t  pkt_count;   /* number of packets seen for this flow       */
    uint64_t  byte_count;  /* total captured bytes (headers + payload)   */
};

/* -----------------------------------------------------------------------
 * FlowTable — the hash table itself.
 * --------------------------------------------------------------------- */
struct FlowTable {
    std::vector<FlowEntry> slots;
    uint32_t capacity;     /* current slot count (always a power of two) */
    uint32_t count;        /* number of occupied slots                   */
    uint32_t next_flow_id; /* monotonically increasing flow ID           */
};

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

/**
 * flow_table_init — allocate a FlowTable with `initial_capacity` slots.
 * `initial_capacity` is rounded up to the next power of two.
 */
FlowTable flow_table_init(uint32_t initial_capacity = 1024);

/**
 * flow_table_lookup — find the FlowEntry for a given 5-tuple.
 *
 * Returns a pointer to the entry if found, nullptr if not present.
 * Read-only; does not modify the table.
 */
FlowEntry* flow_table_lookup(FlowTable& table, const FiveTuple& tuple);

/**
 * flow_table_insert — insert or update an entry for `tuple`.
 *
 * If the flow does not exist a new entry is created and a new flow_id
 * is assigned. `pkt_bytes` is added to byte_count.
 * Returns a pointer to the (possibly new) FlowEntry.
 * Resizes the table if load factor exceeds 0.70.
 */
FlowEntry* flow_table_insert(FlowTable& table,
                             const FiveTuple& tuple,
                             uint64_t pkt_bytes);

/**
 * flow_table_to_flow_recs — convert the table to the shared FlowRec vector.
 *
 * FlowRec.key      = FlowEntry.hash  (64-bit FNV-1a hash)
 * FlowRec.bytes    = FlowEntry.byte_count
 * FlowRec.cost_est = 0.0f  (filled by cost predictor downstream)
 *
 * The output vector is sorted by flow_id for deterministic ordering.
 */
std::vector<FlowRec> flow_table_to_flow_recs(const FlowTable& table);

/**
 * flow_table_print_stats — print a summary to stdout.
 */
void flow_table_print_stats(const FlowTable& table);

/**
 * fnv1a_64 — 64-bit FNV-1a hash of arbitrary bytes.
 * Exposed here so packet_parser and tests can use the same function.
 */
uint64_t fnv1a_64(const void* data, size_t len);

/**
 * tuple_hash — hash a FiveTuple with FNV-1a.
 */
uint64_t tuple_hash(const FiveTuple& t);

#endif /* FLOW_TABLE_H */
