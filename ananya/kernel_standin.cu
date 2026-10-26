/* kernel_standin.cu -- STAND-IN for Asmita's kernel, so the pipeline runs on a GPU today.
 * Replace this file with her kernel; the three entry points below are the interface.
 * Same algorithm as the CPU reference: one thread per arena byte, walk the failure-less
 * automaton until mismatch, bounded by the end of the thread's own segment.
 * Writes matches (bumping *n_matches; never writing past max_matches -- the host checks
 * for overflow) and the steps taken per segment into seg_cost.
 * UNTESTED here (no nvcc in the authoring sandbox): run `make gpu` on Kaggle. */
#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>
#include "contracts.h"

static int32_t *d_next = NULL, *d_term = NULL;

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(e_)); exit(1); } } while (0)

__global__ void scan_kernel(const uint8_t* arena, const Segment* segs, uint32_t nsegs, uint32_t arena_len,
                            const int32_t* next, const int32_t* term, Match* out, uint32_t* n_matches,
                            uint32_t max_matches, uint32_t* seg_cost) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= arena_len) return;
    uint32_t lo = 0, hi = nsegs - 1;                       /* segment containing byte i */
    while (lo < hi) {
        uint32_t mid = (lo + hi + 1) / 2;
        if (segs[mid].offset <= i) lo = mid; else hi = mid - 1;
    }
    Segment s = segs[lo];
    uint32_t p = i - s.offset, steps = 0;
    int32_t node = 0;
    for (uint32_t k = p; k < s.len; k++) {                  /* bounded by the segment end */
        steps++;
        int32_t nx = next[(size_t)node * 256 + arena[s.offset + k]];
        if (nx < 0) break;
        node = nx;
        int32_t t = term[node];
        if (t >= 0) {
            uint32_t idx = atomicAdd(n_matches, 1u);
            if (idx < max_matches) { Match m; m.seg_idx = lo; m.pos = p; m.sig_id = (uint32_t)t; out[idx] = m; }
        }
    }
    atomicAdd(&seg_cost[lo], steps);
}

extern "C" void kernel_init(const int32_t* next, const int32_t* term, size_t nnodes) {
    CK(cudaMalloc(&d_next, nnodes * 256 * sizeof(int32_t)));
    CK(cudaMalloc(&d_term, nnodes * sizeof(int32_t)));
    CK(cudaMemcpy(d_next, next, nnodes * 256 * sizeof(int32_t), cudaMemcpyHostToDevice));
    CK(cudaMemcpy(d_term, term, nnodes * sizeof(int32_t), cudaMemcpyHostToDevice));
}
extern "C" void kernel_free(void) { cudaFree(d_next); cudaFree(d_term); d_next = d_term = NULL; }

extern "C" void launch_scan(const uint8_t* d_arena, const Segment* d_segs, uint32_t nsegs, uint32_t arena_len,
                            Match* d_matches, uint32_t* d_n_matches, uint32_t max_matches,
                            uint32_t* d_seg_cost, cudaStream_t stream) {
    if (!arena_len || !nsegs) return;
    uint32_t threads = 256, blocks = (arena_len + threads - 1) / threads;
    scan_kernel<<<blocks, threads, 0, stream>>>(d_arena, d_segs, nsegs, arena_len, d_next, d_term,
                                                d_matches, d_n_matches, max_matches, d_seg_cost);
    CK(cudaGetLastError());
}
