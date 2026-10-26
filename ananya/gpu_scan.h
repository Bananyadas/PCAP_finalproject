/* gpu_scan.h -- host-side GPU scanner API (plain C; implemented in gpu_scan.cu).
 * Two slots, each with its own stream and pinned buffers: while one slot's kernel runs,
 * the host fills/reads the other. */
#ifndef GPU_SCAN_H
#define GPU_SCAN_H
#include "contracts.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct GpuScanner GpuScanner;

/* next/term = the flattened automaton (Pfac.next / Pfac.term) uploaded once to the GPU */
GpuScanner* gpu_create(const int32_t* next, const int32_t* term, size_t nnodes,
                       size_t max_arena, size_t max_segs, uint32_t max_matches);
void gpu_destroy(GpuScanner* g);
uint32_t gpu_max_matches(const GpuScanner* g);

/* Queue a batch (async: copy in, kernel, copy out). Returns the slot to collect from.
 * A slot must be collected before it is submitted to again (alternate 2 slots). */
int  gpu_submit(GpuScanner* g, const Batch* b);
/* Wait for that slot only. out_matches holds gpu_max_matches() entries; seg_cost holds
 * one entry per segment of the batch that was submitted. */
void gpu_collect(GpuScanner* g, int slot, Match* out_matches, uint32_t* n_matches, uint32_t* seg_cost);
#ifdef __cplusplus
}
#endif
#endif
