/*
 * flow_table.h - Hash table mapping a directional 5-tuple to a Flow.
 *
 * Design:
 *  - FNV-1a 64-bit hash of the 5-tuple fields.
 *  - Open addressing + linear probing; slots store (flow index + 1), 0 = empty.
 *  - Table doubles when load factor would exceed 70%.
 *  - On equal hashes we still compare the full tuple (collisions are safe).
 *  - Flows live in a separate array in insertion order, so
 *    flow_id = order of first appearance (deterministic).
 *  - Eviction policy: NONE. Offline input is finite, so every flow stays
 *    until end-of-file, where all flows are finalised together.
 */
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stddef.h>
#include <stdint.h>
#include "packet_parser.h"
#include "tcp_reassembly.h"

#define FLOW_NOT_FOUND UINT32_MAX

typedef struct {
    FiveTuple tuple;
    uint64_t  key;        /* FNV-1a hash of tuple */
    uint32_t  flow_id;
    uint64_t  packets;
    TcpStream stream;
} Flow;

typedef struct {
    uint32_t *slots;      /* size slot_cap, power of two */
    size_t    slot_cap;
    Flow     *flows;      /* insertion-ordered */
    size_t    nflows;
    size_t    flows_cap;
} FlowTable;

/* Statistics from flow_process_packets(). */
typedef struct {
    uint64_t status_count[PARSE_STATUS_COUNT];
    uint64_t tcp_packets;
    uint64_t payload_bytes;
} FlowStats;

uint64_t fivetuple_hash (const FiveTuple *t);
int      fivetuple_equal(const FiveTuple *a, const FiveTuple *b);

int      flow_table_init(FlowTable *ft, size_t initial_slots);
void     flow_table_free(FlowTable *ft);

uint32_t flow_table_find(const FlowTable *ft, const FiveTuple *t);
/* Returns flow_id, or FLOW_NOT_FOUND on out-of-memory. *created set to 1 if new. */
uint32_t flow_table_get_or_insert(FlowTable *ft, const FiveTuple *t, int *created);
/* Same, but with a caller-supplied hash (lets tests force collisions). */
uint32_t flow_table_get_or_insert_hashed(FlowTable *ft, const FiveTuple *t,
                                         uint64_t hash, int *created);
/* Pointer is valid until the next insert (the flows array may move). */
Flow    *flow_table_get(FlowTable *ft, uint32_t flow_id);

/* Sequential stage: feed every parsed packet (in file order) into the
 * flow table + reassembler, then finalise all flows (EOF).
 * Returns 0 on success, -1 on out-of-memory. */
int flow_process_packets(FlowTable *ft, const PacketList *pl,
                         const ParsedPacket *pp, FlowStats *stats);

#endif /* FLOW_TABLE_H */
