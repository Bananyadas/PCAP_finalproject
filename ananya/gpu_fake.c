/* gpu_fake.c -- test double for gpu_scan.cu: implements the gpu_* API on the CPU so the
 * GPU code path in pipeline.c / bench.c can be exercised on a laptop (`make fakegpu`).
 * Mimics the kernel exactly: per-byte walks, bounded by the segment, atomics replaced by
 * plain adds, seg_cost summed per segment. Not part of the GPU build. */
#include <stdlib.h>
#include <string.h>
#include "gpu_scan.h"

typedef struct { Match* m; uint32_t nm; uint32_t* cost; uint32_t nsegs; } FSlot;
struct GpuScanner {
    const int32_t *next, *term; uint32_t max_matches; FSlot s[2]; int cur;
};

GpuScanner* gpu_create(const int32_t* next, const int32_t* term, size_t nnodes, size_t max_arena,
                       size_t max_segs, uint32_t max_matches) {
    (void)nnodes; (void)max_arena;
    GpuScanner* g = (GpuScanner*)calloc(1, sizeof *g);
    g->next = next; g->term = term; g->max_matches = max_matches;
    for (int i = 0; i < 2; i++) { g->s[i].m = (Match*)malloc(max_matches * sizeof(Match)); g->s[i].cost = (uint32_t*)malloc(max_segs * sizeof(uint32_t)); }
    return g;
}
void gpu_destroy(GpuScanner* g) { for (int i = 0; i < 2; i++) { free(g->s[i].m); free(g->s[i].cost); } free(g); }
uint32_t gpu_max_matches(const GpuScanner* g) { return g->max_matches; }

int gpu_submit(GpuScanner* g, const Batch* b) {
    int i = g->cur; g->cur ^= 1;
    FSlot* s = &g->s[i];
    s->nm = 0; s->nsegs = (uint32_t)b->nsegs;
    memset(s->cost, 0, b->nsegs * sizeof(uint32_t));
    for (uint32_t si = 0; si < b->nsegs; si++) {
        const Segment* sg = &b->segs[si];
        for (uint32_t p = 0; p < sg->len; p++) {
            int32_t node = 0; uint32_t steps = 0;
            for (uint32_t k = p; k < sg->len; k++) {
                steps++;
                int32_t nx = g->next[(size_t)node * 256 + b->arena[sg->offset + k]];
                if (nx < 0) break;
                node = nx;
                if (g->term[node] >= 0) { if (s->nm < g->max_matches) { Match m = { si, p, (uint32_t)g->term[node] }; s->m[s->nm] = m; } s->nm++; }
            }
            s->cost[si] += steps;
        }
    }
    return i;
}
void gpu_collect(GpuScanner* g, int slot, Match* out, uint32_t* n, uint32_t* cost) {
    FSlot* s = &g->s[slot];
    memcpy(out, s->m, s->nm * sizeof(Match)); *n = s->nm;
    memcpy(cost, s->cost, s->nsegs * sizeof(uint32_t));
}
