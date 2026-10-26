/* scanner_cpu.h -- single-threaded CPU stand-in for Asmita's kernel.
 * Same shape as the GPU algorithm (failure-less Aho-Corasick / PFAC: every byte position
 * starts its own walk, which stops at the first mismatch). Used to
 *   (a) let the pipeline run before the real kernel exists, and
 *   (b) be the reference the GPU output is checked against.
 * Also holds the de-dup rule and a simple model of GPU time. */
#ifndef SCANNER_CPU_H
#define SCANNER_CPU_H
#include "contracts.h"

typedef struct { const uint8_t* p; size_t len; } Pat;

typedef struct {
    int32_t* next;     /* node*256 + byte -> node, or -1 */
    int32_t* term;     /* node -> sig_id, or -1 */
    size_t nnodes;
    size_t* lens;      /* sig_id -> length */
    size_t nsigs, maxlen;
} Pfac;

void pfac_build(Pfac* s, const Pat* pats, size_t n);   /* duplicates/empties are dropped */
void pfac_free(Pfac* s);

typedef struct { Match* v; size_t n, cap; } MatchVec;
void matchvec_push(MatchVec* m, Match x);

/* One walk per arena byte. Walks never cross the end of their segment (otherwise they
 * would read the NEXT flow's bytes). pos_steps[i] (arena_len entries) gets the number of
 * bytes examined by the walk starting at arena position i. */
void pfac_scan(const Pfac* s, const Batch* b, MatchVec* out, uint32_t* pos_steps);

/* Per-segment cost = total steps of the walks that started in the segment: the number the
 * kernel must hand back to the predictor. seg_cost has b->nsegs entries. */
void segment_costs(const Batch* b, const uint32_t* pos_steps, uint32_t* seg_cost);

/* DE-DUP RULE for carried bytes. A segment re-scans `carry` bytes the previous segment
 * already scanned. Drop a match only if it lies ENTIRELY inside the carry (the previous
 * segment reported it). A match that starts in the carry but runs past it is the
 * straddling one -- only this segment can see it, so keep it.
 *     keep  <=>  pos + len(sig) > carry                                              */
void dedupe(const Batch* b, MatchVec* m, const Pfac* s);   /* in place */

/* A final alert, independent of how the flow was cut up. */
typedef struct { uint32_t flow_id; uint64_t stream_pos; uint32_t sig_id; } Alert;
typedef struct { Alert* v; size_t n, cap; } AlertVec;
void append_alerts(const Batch* b, const MatchVec* deduped, AlertVec* out);
void alerts_sort(AlertVec* a);
int  alert_cmp(const Alert* a, const Alert* b);

/* Model of GPU time for one batch (NOT a measurement -- real numbers come from the GPU):
 * 32-thread warps run in lockstep, so a warp costs the max steps of its threads; a block
 * costs the sum of its warps; blocks go in index order to whichever of `sms` workers is
 * free first. makespan is in warp-steps. */
typedef struct { uint64_t sum_steps, sum_warp_max; double makespan; } GpuModel;
GpuModel model_batch(const uint32_t* pos_steps, size_t n, int block, int sms);
#endif
