/**
 * shared.h — Team-agreed shared data structures.
 *
 * These structures are a fixed contract between team members.
 * DO NOT change field names, types, or layout.
 *
 *  • Segment   — produced by this (flow-management) component.
 *                Consumed by the GPU matcher.
 *  • Match     — produced by the GPU/Aho-Corasick component.
 *  • FlowRec   — produced by the flow-table component; may be
 *                read by the cost predictor / adaptive batcher.
 */

#ifndef SHARED_H
#define SHARED_H

#include <stdint.h>

/* ------------------------------------------------------------------
 * Segment
 * Describes one reconstructed TCP flow payload inside the shared byte arena.
 *
 * flow_id  — identifies which flow this segment belongs to.
 * offset   — byte offset into the arena where this flow's payload starts.
 * len      — number of valid bytes from `offset`.
 * carry    — cross-batch tail-carry value.
 *            This component always writes 0; the downstream batch
 *            composer owns the final carry value.
 * ------------------------------------------------------------------ */
typedef struct {
    uint32_t flow_id;
    uint32_t offset;
    uint32_t len;
    uint32_t carry;
} Segment;

/* ------------------------------------------------------------------
 * Match
 * Produced by the GPU Aho-Corasick matcher.
 * Not used by this component; included for completeness.
 * ------------------------------------------------------------------ */
typedef struct {
    uint32_t seg_idx;   /* index into the Segment array */
    uint32_t pos;       /* byte position inside the segment */
    uint32_t sig_id;    /* matched signature / pattern ID */
} Match;

/* ------------------------------------------------------------------
 * FlowRec
 * Summary record for a single network flow.
 *
 * key       — 64-bit hash of the 5-tuple used as the fast-lookup key.
 *             A full tuple comparison is still required on collision.
 * bytes     — total reconstructed payload bytes for this flow.
 * cost_est  — estimated processing cost (filled by cost predictor;
 *             this component initialises it to 0.0f).
 * ------------------------------------------------------------------ */
typedef struct {
    uint64_t key;
    uint64_t bytes;
    float    cost_est;
} FlowRec;

#endif /* SHARED_H */
