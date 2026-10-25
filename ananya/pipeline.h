/* pipeline.h -- windowed compose/scan pipeline with feedback.
 *
 * The trace is processed in windows: window k holds the next `slice` bytes of every flow
 * that still has data, so long (expensive) flows reappear and the predictor's feedback has
 * something to improve.
 *
 * Overlap: while window k is scanned, window k+1 is composed on another thread. That
 * thread gets a SNAPSHOT of the predictor taken at launch, so feedback from window k
 * reaches the composer for window k+2 (one window of lag). */
#ifndef PIPELINE_H
#define PIPELINE_H
#include <time.h>
#include "composer.h"
#include "scanner_cpu.h"

struct GpuScanner;   /* NULL => use the CPU stand-in scanner */

typedef struct {
    size_t windows, batches, segments;
    uint64_t arena_bytes;      /* bytes scanned, carry included */
    uint64_t payload_bytes;    /* bytes owned by segments (== trace size) */
    double compose_ms;         /* time composing (overlapped with scan) */
    double scan_ms;            /* time scanning */
    double wall_ms;            /* whole pipeline */
    uint64_t steps, warp_steps;/* CPU mode only (the model needs per-byte steps) */
    double model_makespan;     /* CPU mode only: modelled GPU time, warp-steps */
    double worst_batch_ratio;  /* CPU mode only: heaviest batch / mean batch, by steps */
} RunStats;

static inline double now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

void run_pipeline(ComposeFn compose, const Flows* flows, CostPredictor* pred, const Pfac* sc,
                  const ComposeCfg* cfg, size_t slice, int sms, int block,
                  struct GpuScanner* gpu, AlertVec* alerts, RunStats* st);
#endif
