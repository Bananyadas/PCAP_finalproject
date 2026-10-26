/* contracts.h -- the ONLY things the three parts know about each other.
 * The three structs Segment / Match / FlowRec are FIXED (Developer Guide). Do not edit. */
#ifndef CONTRACTS_H
#define CONTRACTS_H
#include <stdint.h>
#include <stddef.h>

/* one piece of payload for the GPU to scan */
typedef struct {
    uint32_t flow_id;  /* which flow it came from */
    uint32_t offset;   /* where it starts in the byte arena */
    uint32_t len;      /* how many bytes (INCLUDING the carried bytes at the front) */
    uint32_t carry;    /* bytes at the front copied from the previous segment */
} Segment;

/* one signature hit, reported by the GPU */
typedef struct {
    uint32_t seg_idx;  /* which segment */
    uint32_t pos;      /* byte offset within that segment (where the match STARTS) */
    uint32_t sig_id;   /* which signature matched */
} Match;

/* what we remember about a flow */
typedef struct {
    uint64_t key;      /* hashed 5-tuple */
    uint64_t bytes;    /* bytes seen so far */
    float cost_est;    /* predicted scan cost (steps per byte) */
} FlowRec;

/* ---- helper types on Ananya Das's side (not part of the three contracts) ---- */

/* A composed batch. arena + segs is the handover to Asmita's kernel.
 * flow_pos is a side table for the harness (NOT sent to the GPU): stream offset,
 * within the flow, of the first byte the segment OWNS (i.e. after the carry). */
typedef struct {
    uint8_t* arena;   size_t arena_len, arena_cap;
    Segment* segs;    uint64_t* flow_pos;  size_t nsegs, segs_cap;
    double predicted_cost;
} Batch;

typedef struct { Batch* v; size_t n, cap; } BatchList;

/* What Ananyaraj hands over per flow: the reassembled stream, and the range
 * [begin,end) of it that is new in this window. Bytes before `begin` stay readable
 * (needed for the tail-carry). */
typedef struct {
    uint32_t flow_id;
    uint8_t  proto;       /* 6 = TCP, 17 = UDP */
    uint16_t dst_port;
    const uint8_t* data;  /* whole reassembled flow */
    uint64_t size, begin, end;
} FlowInput;

/* All reassembled flows (Ananyaraj's output). flow_id == index. */
typedef struct {
    uint8_t** data;  uint64_t* size;
    uint8_t* proto;  uint16_t* port;  uint64_t* key;
    size_t n;
} Flows;

void batch_init(Batch* b);
void batch_free(Batch* b);
void batchlist_push(BatchList* l, Batch* b);   /* moves *b into the list, re-inits *b */
void batchlist_free(BatchList* l);
#endif
