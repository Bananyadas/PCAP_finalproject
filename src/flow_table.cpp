/**
 * flow_table.cpp
 *
 * Implements the 5-tuple hash table.
 *
 * Key ideas (beginner-friendly):
 *   • We hash the 5-tuple (srcIP, dstIP, srcPort, dstPort, proto)
 *     into a 64-bit number using FNV-1a — a fast, well-distributed
 *     hash function.
 *   • The hash is used to pick a starting slot in the table.
 *   • If that slot is taken (collision), we try the next slot, then
 *     the next — this is called linear probing.
 *   • When the table fills up to 70% we double its size and rehash
 *     everything — this is called resizing.
 *
 * Thread-safety: NOT thread-safe for concurrent writes.
 * Flow-table updates must be done from one thread.
 */

#include "flow_table.h"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <cassert>

/* -----------------------------------------------------------------------
 * FNV-1a 64-bit hash
 *
 * FNV-1a is simple and fast.
 * For each byte b: hash = (hash XOR b) * FNV_PRIME
 * --------------------------------------------------------------------- */
static constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
static constexpr uint64_t FNV_PRIME        = 1099511628211ULL;

uint64_t fnv1a_64(const void* data, size_t len)
{
    const uint8_t* ptr  = static_cast<const uint8_t*>(data);
    uint64_t       hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; ++i) {
        hash ^= ptr[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

/* Hash a FiveTuple by treating it as a flat byte array. */
uint64_t tuple_hash(const FiveTuple& t)
{
    return fnv1a_64(&t, sizeof(FiveTuple));
}

/* -----------------------------------------------------------------------
 * Helper — are two FiveTuples identical?
 * --------------------------------------------------------------------- */
static bool tuple_equal(const FiveTuple& a, const FiveTuple& b)
{
    return a.src_ip   == b.src_ip   &&
           a.dst_ip   == b.dst_ip   &&
           a.src_port == b.src_port &&
           a.dst_port == b.dst_port &&
           a.proto    == b.proto;
}

/* -----------------------------------------------------------------------
 * Helper — round n up to the next power of two (minimum 8).
 * --------------------------------------------------------------------- */
static uint32_t next_pow2(uint32_t n)
{
    if (n < 8) return 8;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n + 1;
}

/* -----------------------------------------------------------------------
 * flow_table_init
 * --------------------------------------------------------------------- */
FlowTable flow_table_init(uint32_t initial_capacity)
{
    FlowTable table;
    table.capacity    = next_pow2(initial_capacity);
    table.count       = 0;
    table.next_flow_id = 0;
    table.slots.assign(table.capacity, FlowEntry{});
    return table;
}

/* -----------------------------------------------------------------------
 * Internal probe — find the slot index for a given (hash, tuple) pair.
 *
 * Returns:
 *   • Index of a matching occupied slot, OR
 *   • Index of the first empty slot (for insertion).
 * --------------------------------------------------------------------- */
static uint32_t probe(const FlowTable& table,
                      uint64_t hash,
                      const FiveTuple& tuple)
{
    /* Mask to keep the index within [0, capacity-1].
     * Works because capacity is a power of two: x & (cap-1) == x % cap */
    uint32_t mask = table.capacity - 1;
    uint32_t idx  = static_cast<uint32_t>(hash & mask);

    for (uint32_t i = 0; i < table.capacity; ++i) {
        const FlowEntry& slot = table.slots[idx];
        if (!slot.occupied) {
            return idx; /* empty slot → use for insertion */
        }
        /* Slot is occupied: is it our tuple? */
        if (slot.hash == hash && tuple_equal(slot.tuple, tuple)) {
            return idx; /* found existing entry */
        }
        /* Linear probe: try next slot */
        idx = (idx + 1) & mask;
    }
    /* Table is full — should never reach here if resize works correctly */
    assert(false && "flow_table: table is full (resize bug)");
    return 0;
}

/* -----------------------------------------------------------------------
 * Resize — double the table and rehash everything.
 * Called internally when load factor > 0.70.
 * --------------------------------------------------------------------- */
static void resize(FlowTable& table)
{
    uint32_t new_cap = table.capacity * 2;
    FlowTable new_table;
    new_table.capacity     = new_cap;
    new_table.count        = 0;
    new_table.next_flow_id = table.next_flow_id;
    new_table.slots.assign(new_cap, FlowEntry{});

    /* Re-insert every occupied slot */
    for (const auto& slot : table.slots) {
        if (!slot.occupied) continue;
        uint32_t idx = probe(new_table, slot.hash, slot.tuple);
        new_table.slots[idx] = slot;
        new_table.count++;
    }

    table = std::move(new_table);
}

/* -----------------------------------------------------------------------
 * flow_table_lookup
 * --------------------------------------------------------------------- */
FlowEntry* flow_table_lookup(FlowTable& table, const FiveTuple& tuple)
{
    uint64_t hash = tuple_hash(tuple);
    uint32_t idx  = probe(table, hash, tuple);
    FlowEntry& slot = table.slots[idx];
    if (slot.occupied && slot.hash == hash && tuple_equal(slot.tuple, tuple)) {
        return &slot;
    }
    return nullptr;
}

/* -----------------------------------------------------------------------
 * flow_table_insert
 * --------------------------------------------------------------------- */
FlowEntry* flow_table_insert(FlowTable& table,
                             const FiveTuple& tuple,
                             uint64_t pkt_bytes)
{
    /* Resize before inserting if we are at 70% load */
    if ((table.count + 1) * 10 > table.capacity * 7) {
        resize(table);
    }

    uint64_t hash = tuple_hash(tuple);
    uint32_t idx  = probe(table, hash, tuple);
    FlowEntry& slot = table.slots[idx];

    if (!slot.occupied) {
        /* New flow */
        slot.occupied   = true;
        slot.tuple      = tuple;
        slot.hash       = hash;
        slot.flow_id    = table.next_flow_id++;
        slot.pkt_count  = 1;
        slot.byte_count = pkt_bytes;
        table.count++;
    } else {
        /* Existing flow — update counters */
        slot.pkt_count++;
        slot.byte_count += pkt_bytes;
    }

    return &slot;
}

/* -----------------------------------------------------------------------
 * flow_table_to_flow_recs
 * --------------------------------------------------------------------- */
std::vector<FlowRec> flow_table_to_flow_recs(const FlowTable& table)
{
    std::vector<FlowRec> recs;
    recs.reserve(table.count);

    for (const auto& slot : table.slots) {
        if (!slot.occupied) continue;
        FlowRec rec;
        rec.key      = slot.hash;       /* 64-bit FNV-1a hash of 5-tuple   */
        rec.bytes    = slot.byte_count; /* total captured bytes for flow   */
        rec.cost_est = 0.0f;            /* filled by cost predictor later  */
        recs.push_back(rec);
    }

    /* Sort by flow_id for deterministic ordering */
    std::sort(recs.begin(), recs.end(),
        [&](const FlowRec& a, const FlowRec& b) {
            /* We don't have flow_id in FlowRec, but we can use key
             * as a proxy since it's unique per flow.
             * For proper sort by flow_id we build a temp sorted list. */
            return a.bytes > b.bytes; /* fallback: sort by size descending */
        });

    /* Better: rebuild with flow_id sorting */
    /* Collect (flow_id, rec) pairs, sort, strip flow_id */
    struct FR2 { uint32_t flow_id; FlowRec rec; };
    std::vector<FR2> tmp;
    tmp.reserve(table.count);
    for (const auto& slot : table.slots) {
        if (!slot.occupied) continue;
        FR2 fr;
        fr.flow_id   = slot.flow_id;
        fr.rec.key      = slot.hash;
        fr.rec.bytes    = slot.byte_count;
        fr.rec.cost_est = 0.0f;
        tmp.push_back(fr);
    }
    std::sort(tmp.begin(), tmp.end(),
        [](const FR2& a, const FR2& b){ return a.flow_id < b.flow_id; });

    recs.clear();
    for (const auto& fr : tmp) recs.push_back(fr.rec);
    return recs;
}

/* -----------------------------------------------------------------------
 * flow_table_print_stats
 * --------------------------------------------------------------------- */
void flow_table_print_stats(const FlowTable& table)
{
    printf("\n=== Flow Table Statistics ===\n");
    printf("  Unique flows    : %u\n",  table.count);
    printf("  Table capacity  : %u\n",  table.capacity);
    printf("  Load factor     : %.2f%%\n",
           100.0 * table.count / table.capacity);
    printf("  Next flow ID    : %u\n",  table.next_flow_id);
    printf("=============================\n\n");
}
