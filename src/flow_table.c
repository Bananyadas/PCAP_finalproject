/*
 * flow_table.c - Open-addressing hash table of flows.
 */
#include "flow_table.h"

#include <stdlib.h>
#include <string.h>

#define FNV_OFFSET 1469598103934665603ull
#define FNV_PRIME  1099511628211ull

static uint64_t fnv_bytes(uint64_t h, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= FNV_PRIME; }
    return h;
}

/* Hash the fields one by one in a fixed (big-endian) byte order, so the
 * result never depends on struct padding or CPU endianness. */
uint64_t fivetuple_hash(const FiveTuple *t)
{
    uint8_t b[13] = {
        (uint8_t)(t->src_ip >> 24), (uint8_t)(t->src_ip >> 16), (uint8_t)(t->src_ip >> 8), (uint8_t)t->src_ip,
        (uint8_t)(t->dst_ip >> 24), (uint8_t)(t->dst_ip >> 16), (uint8_t)(t->dst_ip >> 8), (uint8_t)t->dst_ip,
        (uint8_t)(t->src_port >> 8), (uint8_t)t->src_port,
        (uint8_t)(t->dst_port >> 8), (uint8_t)t->dst_port,
        t->protocol
    };
    return fnv_bytes(FNV_OFFSET, b, sizeof b);
}

int fivetuple_equal(const FiveTuple *a, const FiveTuple *b)
{
    return a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port && a->dst_port == b->dst_port &&
           a->protocol == b->protocol;
}

int flow_table_init(FlowTable *ft, size_t initial_slots)
{
    memset(ft, 0, sizeof *ft);
    size_t cap = 16;
    while (cap < initial_slots) cap *= 2;      /* power of two -> mask */
    ft->slots = calloc(cap, sizeof *ft->slots);
    if (!ft->slots) return -1;
    ft->slot_cap = cap;
    return 0;
}

void flow_table_free(FlowTable *ft)
{
    for (size_t i = 0; i < ft->nflows; i++) stream_free(&ft->flows[i].stream);
    free(ft->flows);
    free(ft->slots);
    memset(ft, 0, sizeof *ft);
}

/* Double the slot array and re-place every flow (keys are cached). */
static int resize(FlowTable *ft)
{
    size_t ncap = ft->slot_cap * 2;
    uint32_t *ns = calloc(ncap, sizeof *ns);
    if (!ns) return -1;
    size_t mask = ncap - 1;
    for (size_t i = 0; i < ft->nflows; i++) {
        size_t idx = (size_t)ft->flows[i].key & mask;
        while (ns[idx]) idx = (idx + 1) & mask;
        ns[idx] = (uint32_t)(i + 1);
    }
    free(ft->slots);
    ft->slots = ns;
    ft->slot_cap = ncap;
    return 0;
}

uint32_t flow_table_find(const FlowTable *ft, const FiveTuple *t)
{
    uint64_t h = fivetuple_hash(t);
    size_t mask = ft->slot_cap - 1;
    size_t idx = (size_t)h & mask;
    for (;;) {
        uint32_t s = ft->slots[idx];
        if (s == 0) return FLOW_NOT_FOUND;
        const Flow *f = &ft->flows[s - 1];
        if (f->key == h && fivetuple_equal(&f->tuple, t)) return s - 1;
        idx = (idx + 1) & mask;               /* linear probing */
    }
}

uint32_t flow_table_get_or_insert_hashed(FlowTable *ft, const FiveTuple *t,
                                         uint64_t h, int *created)
{
    if (created) *created = 0;
    /* Keep load factor <= 70% so probe chains stay short. */
    if ((ft->nflows + 1) * 10 > ft->slot_cap * 7)
        if (resize(ft) != 0) return FLOW_NOT_FOUND;

    size_t mask = ft->slot_cap - 1;
    size_t idx = (size_t)h & mask;
    for (;;) {
        uint32_t s = ft->slots[idx];
        if (s == 0) break;                    /* empty: insert here */
        Flow *f = &ft->flows[s - 1];
        if (f->key == h && fivetuple_equal(&f->tuple, t)) return s - 1;
        idx = (idx + 1) & mask;
    }

    if (ft->nflows >= FLOW_NOT_FOUND - 1) return FLOW_NOT_FOUND;
    if (ft->nflows == ft->flows_cap) {
        size_t nc = ft->flows_cap ? ft->flows_cap * 2 : 64;
        Flow *nf = realloc(ft->flows, nc * sizeof *nf);
        if (!nf) return FLOW_NOT_FOUND;
        ft->flows = nf;
        ft->flows_cap = nc;
    }
    uint32_t id = (uint32_t)ft->nflows;
    Flow *f = &ft->flows[id];
    memset(f, 0, sizeof *f);
    f->tuple = *t;
    memset(f->tuple.pad, 0, sizeof f->tuple.pad);
    f->key = h;
    f->flow_id = id;
    stream_init(&f->stream);
    ft->nflows++;
    ft->slots[idx] = id + 1;
    if (created) *created = 1;
    return id;
}

uint32_t flow_table_get_or_insert(FlowTable *ft, const FiveTuple *t, int *created)
{
    return flow_table_get_or_insert_hashed(ft, t, fivetuple_hash(t), created);
}

Flow *flow_table_get(FlowTable *ft, uint32_t flow_id)
{
    return flow_id < ft->nflows ? &ft->flows[flow_id] : NULL;
}

int flow_process_packets(FlowTable *ft, const PacketList *pl,
                         const ParsedPacket *pp, FlowStats *stats)
{
    FlowStats local;
    if (!stats) stats = &local;
    memset(stats, 0, sizeof *stats);

    /* SEQUENTIAL, in file order: this is what makes flow_ids and
     * reassembled bytes identical no matter how many threads parsed. */
    for (size_t i = 0; i < pl->count; i++) {
        const ParsedPacket *p = &pp[i];
        stats->status_count[p->status]++;
        if (p->status != PARSE_OK) continue;
        stats->tcp_packets++;
        stats->payload_bytes += p->payload_len;

        uint32_t id = flow_table_get_or_insert(ft, &p->tuple, NULL);
        if (id == FLOW_NOT_FOUND) return -1;
        Flow *f = &ft->flows[id];
        f->packets++;
        if (stream_add(&f->stream, p->seq, p->tcp_flags,
                       pl->pkts[i].data + p->payload_off, p->payload_len) != 0)
            return -1;
    }
    /* End of file: no eviction policy, so finalise every flow now. */
    for (size_t i = 0; i < ft->nflows; i++) stream_finish(&ft->flows[i].stream);
    return 0;
}
