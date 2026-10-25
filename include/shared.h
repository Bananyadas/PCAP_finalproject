/*
 * shared.h - Data structures SHARED with the rest of the team
 * (batcher, cost predictor, CUDA Aho-Corasick kernel).
 *
 * DO NOT CHANGE THE LAYOUT OF THESE STRUCTS without agreeing with the team:
 * the GPU code copies arrays of them byte-for-byte.
 */
#ifndef SHARED_H
#define SHARED_H

#include <stdint.h>

/* One contiguous run of reassembled payload bytes inside the byte arena. */
typedef struct {
    uint32_t flow_id;   /* which flow these bytes belong to              */
    uint32_t offset;    /* start position inside the byte arena          */
    uint32_t len;       /* number of bytes                               */
    uint32_t carry;     /* overlap bytes from previous segment (0 here)  */
} Segment;

/* A signature match reported by the GPU matcher (not produced by us). */
typedef struct {
    uint32_t seg_idx;
    uint32_t pos;
    uint32_t sig_id;
} Match;

/* Per-flow record handed to the batcher / cost predictor. */
typedef struct {
    uint64_t key;       /* FNV-1a 64-bit hash of the 5-tuple             */
    uint64_t bytes;     /* reassembled payload bytes of this flow        */
    float    cost_est;  /* filled by the cost predictor (we write 0.0f)  */
} FlowRec;

/* Compile-time guards so an accidental layout change breaks the build. */
_Static_assert(sizeof(Segment) == 16, "Segment layout changed");
_Static_assert(sizeof(Match)   == 12, "Match layout changed");
_Static_assert(sizeof(FlowRec) == 24, "FlowRec layout changed");

#endif /* SHARED_H */
