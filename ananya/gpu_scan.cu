/* gpu_scan.cu -- pinned memory + two CUDA streams (double buffering). Plain-C style.
 * UNTESTED here (no nvcc in the authoring sandbox): run `make gpu` on Kaggle.
 *
 * While slot A's kernel runs on stream A, the host composes the next window and fills
 * slot B. pipeline.c does: submit(b0); submit(b1); collect(b0); submit(b2); collect(b1)... */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>
#include "gpu_scan.h"

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); exit(1); } } while (0)

/* provided by kernel_standin.cu now, by Asmita's kernel later */
extern "C" void kernel_init(const int32_t* next, const int32_t* term, size_t nnodes);
extern "C" void kernel_free(void);
extern "C" void launch_scan(const uint8_t* d_arena, const Segment* d_segs, uint32_t nsegs, uint32_t arena_len,
                            Match* d_matches, uint32_t* d_n_matches, uint32_t max_matches,
                            uint32_t* d_seg_cost, cudaStream_t stream);

typedef struct {
    uint8_t* h_arena; Segment* h_segs; Match* h_matches; uint32_t* h_nm; uint32_t* h_cost;   /* pinned host */
    uint8_t* d_arena; Segment* d_segs; Match* d_matches; uint32_t* d_nm; uint32_t* d_cost;   /* device */
    cudaStream_t stream; cudaEvent_t done;
    uint32_t nsegs, arena_len;
} Slot;

struct GpuScanner {
    Slot slot[2];
    int next_slot;
    size_t max_arena, max_segs;
    uint32_t max_matches;
};

extern "C" GpuScanner* gpu_create(const int32_t* next, const int32_t* term, size_t nnodes,
                                  size_t max_arena, size_t max_segs, uint32_t max_matches) {
    GpuScanner* g = (GpuScanner*)calloc(1, sizeof(GpuScanner));
    g->max_arena = max_arena; g->max_segs = max_segs; g->max_matches = max_matches;
    kernel_init(next, term, nnodes);
    for (int i = 0; i < 2; i++) {
        Slot* s = &g->slot[i];
        CK(cudaMallocHost((void**)&s->h_arena, max_arena));          /* pinned: needed for truly async copies */
        CK(cudaMallocHost((void**)&s->h_segs, max_segs * sizeof(Segment)));
        CK(cudaMallocHost((void**)&s->h_matches, (size_t)max_matches * sizeof(Match)));
        CK(cudaMallocHost((void**)&s->h_nm, sizeof(uint32_t)));
        CK(cudaMallocHost((void**)&s->h_cost, max_segs * sizeof(uint32_t)));
        CK(cudaMalloc((void**)&s->d_arena, max_arena));
        CK(cudaMalloc((void**)&s->d_segs, max_segs * sizeof(Segment)));
        CK(cudaMalloc((void**)&s->d_matches, (size_t)max_matches * sizeof(Match)));
        CK(cudaMalloc((void**)&s->d_nm, sizeof(uint32_t)));
        CK(cudaMalloc((void**)&s->d_cost, max_segs * sizeof(uint32_t)));
        CK(cudaStreamCreate(&s->stream));
        CK(cudaEventCreate(&s->done));
    }
    return g;
}

extern "C" void gpu_destroy(GpuScanner* g) {
    for (int i = 0; i < 2; i++) {
        Slot* s = &g->slot[i];
        cudaFreeHost(s->h_arena); cudaFreeHost(s->h_segs); cudaFreeHost(s->h_matches);
        cudaFreeHost(s->h_nm); cudaFreeHost(s->h_cost);
        cudaFree(s->d_arena); cudaFree(s->d_segs); cudaFree(s->d_matches); cudaFree(s->d_nm); cudaFree(s->d_cost);
        cudaStreamDestroy(s->stream); cudaEventDestroy(s->done);
    }
    kernel_free();
    free(g);
}

extern "C" uint32_t gpu_max_matches(const GpuScanner* g) { return g->max_matches; }

extern "C" int gpu_submit(GpuScanner* g, const Batch* b) {
    if (b->arena_len > g->max_arena || b->nsegs > g->max_segs) { fprintf(stderr, "batch too large for GpuScanner buffers\n"); exit(1); }
    int i = g->next_slot; g->next_slot ^= 1;
    Slot* s = &g->slot[i];
    s->nsegs = (uint32_t)b->nsegs; s->arena_len = (uint32_t)b->arena_len;
    memcpy(s->h_arena, b->arena, b->arena_len);
    memcpy(s->h_segs, b->segs, b->nsegs * sizeof(Segment));
    CK(cudaMemcpyAsync(s->d_arena, s->h_arena, s->arena_len, cudaMemcpyHostToDevice, s->stream));
    CK(cudaMemcpyAsync(s->d_segs, s->h_segs, s->nsegs * sizeof(Segment), cudaMemcpyHostToDevice, s->stream));
    CK(cudaMemsetAsync(s->d_nm, 0, sizeof(uint32_t), s->stream));
    CK(cudaMemsetAsync(s->d_cost, 0, s->nsegs * sizeof(uint32_t), s->stream));
    launch_scan(s->d_arena, s->d_segs, s->nsegs, s->arena_len, s->d_matches, s->d_nm, g->max_matches, s->d_cost, s->stream);
    CK(cudaMemcpyAsync(s->h_nm, s->d_nm, sizeof(uint32_t), cudaMemcpyDeviceToHost, s->stream));
    CK(cudaMemcpyAsync(s->h_matches, s->d_matches, (size_t)g->max_matches * sizeof(Match), cudaMemcpyDeviceToHost, s->stream));
    CK(cudaMemcpyAsync(s->h_cost, s->d_cost, s->nsegs * sizeof(uint32_t), cudaMemcpyDeviceToHost, s->stream));
    CK(cudaEventRecord(s->done, s->stream));
    return i;
}

extern "C" void gpu_collect(GpuScanner* g, int slot, Match* out_matches, uint32_t* n_matches, uint32_t* seg_cost) {
    Slot* s = &g->slot[slot];
    CK(cudaEventSynchronize(s->done));                               /* waits for this slot only */
    if (*s->h_nm > g->max_matches) {                                  /* never silently drop alerts */
        fprintf(stderr, "match buffer overflow (%u > %u): raise max_matches in bench.c\n", *s->h_nm, g->max_matches);
        exit(1);
    }
    memcpy(out_matches, s->h_matches, (size_t)*s->h_nm * sizeof(Match));
    *n_matches = *s->h_nm;
    memcpy(seg_cost, s->h_cost, s->nsegs * sizeof(uint32_t));
}
