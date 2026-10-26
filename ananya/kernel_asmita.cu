/* kernel_asmita.cu -- replaces kernel_standin.cu behind the same three entry
 * points (kernel_init / kernel_free / launch_scan), so gpu_scan.cu is unchanged.
 *
 * Same algorithm as the stand-in: one thread per arena byte, failure-less
 * Aho-Corasick walk bounded by the thread's own segment, every match reported
 * (the carry de-dup stays a host pass in scanner_cpu.c -- the kernel must NOT
 * apply it, or the alert sets stop matching).
 *
 * Two mechanical differences, both aimed at the same thing: fewer global
 * atomics and less redundant work per thread.
 *
 *   1. PER-SEGMENT COST, WARP-AGGREGATED.
 *      The stand-in does one atomicAdd per thread onto seg_cost[]. With ~1M
 *      threads a batch and only a few dozen segments, that is ~1M atomics
 *      contending on a few dozen addresses. Here the 32 lanes of a warp sum
 *      their step counts among themselves first (__shfl_down_sync, no memory
 *      traffic) and one lane does a single atomicAdd. That is 32x fewer
 *      atomics whenever a warp sits inside one segment, which is almost
 *      always true because a warp covers 32 adjacent arena bytes.
 *      Warps that straddle a segment boundary fall back to per-thread
 *      atomics, so the totals stay exact.
 *
 *   2. SEGMENT LOOKUP, ONCE PER WARP.
 *      The stand-in runs a binary search over segs[] in every thread. Since a
 *      warp's 32 bytes are adjacent and segs[] is sorted by offset, the whole
 *      warp is in one segment unless it straddles a boundary. So lanes 0 and 1
 *      probe the warp's first and last byte; if both land in the same segment,
 *      every lane takes that answer by broadcast. Two searches per warp
 *      instead of thirty-two.
 *
 * Nothing about the matching itself changes: same table, same walk, same
 * bound, same matches. The alert sets must come out identical to the
 * stand-in's -- if they do not, this file is wrong, not the stand-in.
 */

#include <stdio.h>
#include <stdlib.h>
#include <cuda_runtime.h>
#include "contracts.h"

static int32_t *d_next = NULL, *d_term = NULL;

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) {                 \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(e_));   \
    exit(1); } } while (0)

#define FULL_MASK 0xffffffffu

/* segs[] is sorted by offset: find the segment containing arena byte i. */
__device__ __forceinline__
uint32_t seg_of(const Segment* __restrict__ segs, uint32_t nsegs, uint32_t i)
{
    uint32_t lo = 0, hi = nsegs - 1;
    while (lo < hi) {
        uint32_t mid = (lo + hi + 1) >> 1;
        if (segs[mid].offset <= i) lo = mid; else hi = mid - 1;
    }
    return lo;
}

__global__ void scan_kernel(const uint8_t*  __restrict__ arena,
                            const Segment*  __restrict__ segs,
                            uint32_t nsegs, uint32_t arena_len,
                            const int32_t*  __restrict__ next,
                            const int32_t*  __restrict__ term,
                            Match*          __restrict__ out,
                            uint32_t*       __restrict__ n_matches,
                            uint32_t max_matches,
                            uint32_t*       __restrict__ seg_cost)
{
    const uint32_t i    = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t lane = threadIdx.x & 31u;
    const uint32_t base = i - lane;              /* first arena byte of this warp */
    const bool     live = (i < arena_len);

    /* NOTE: no early return. Every lane must reach the __shfl_sync calls below,
     * so out-of-range lanes stay in the warp and simply do no work. */

    /* ---- which segment am I in? Two probes per warp, then broadcast. ---- */
    uint32_t last = base + 31u;
    if (last >= arena_len) last = arena_len ? arena_len - 1u : 0u;
    uint32_t first = base < arena_len ? base : last;

    uint32_t probe = (lane == 1u) ? last : first;
    uint32_t s_probe = (lane < 2u) ? seg_of(segs, nsegs, probe) : 0u;

    const uint32_t segA = __shfl_sync(FULL_MASK, s_probe, 0);
    const uint32_t segB = __shfl_sync(FULL_MASK, s_probe, 1);
    const bool uniform  = (segA == segB);

    uint32_t my_seg = segA;
    if (!uniform && live) my_seg = seg_of(segs, nsegs, i);

    /* ---- the walk ---- */
    uint32_t steps = 0;
    if (live) {
        const Segment s = segs[my_seg];
        const uint32_t p = i - s.offset;
        int32_t node = 0;

        for (uint32_t k = p; k < s.len; ++k) {
            ++steps;
            const int32_t nx = next[(size_t)node * 256 + arena[s.offset + k]];
            if (nx < 0) break;
            node = nx;
            const int32_t t = term[node];
            if (t >= 0) {
                const uint32_t idx = atomicAdd(n_matches, 1u);
                if (idx < max_matches) {
                    Match m;
                    m.seg_idx = my_seg;
                    m.pos     = p;
                    m.sig_id  = (uint32_t)t;
                    out[idx]  = m;
                }
            }
        }
    }

    /* ---- per-segment cost ---- */
    if (uniform) {
        uint32_t sum = steps;
        for (int off = 16; off > 0; off >>= 1)
            sum += __shfl_down_sync(FULL_MASK, sum, off);
        if (lane == 0u && sum) atomicAdd(&seg_cost[segA], sum);
    } else if (live && steps) {
        atomicAdd(&seg_cost[my_seg], steps);
    }
}

extern "C" void kernel_init(const int32_t* next, const int32_t* term, size_t nnodes)
{
    CK(cudaMalloc(&d_next, nnodes * 256 * sizeof(int32_t)));
    CK(cudaMalloc(&d_term, nnodes * sizeof(int32_t)));
    CK(cudaMemcpy(d_next, next, nnodes * 256 * sizeof(int32_t), cudaMemcpyHostToDevice));
    CK(cudaMemcpy(d_term, term, nnodes * sizeof(int32_t), cudaMemcpyHostToDevice));
}

extern "C" void kernel_free(void)
{
    cudaFree(d_next); cudaFree(d_term); d_next = d_term = NULL;
}

extern "C" void launch_scan(const uint8_t* d_arena, const Segment* d_segs,
                            uint32_t nsegs, uint32_t arena_len,
                            Match* d_matches, uint32_t* d_n_matches,
                            uint32_t max_matches, uint32_t* d_seg_cost,
                            cudaStream_t stream)
{
    if (!arena_len || !nsegs) return;
    const uint32_t threads = 256;                       /* multiple of 32 */
    const uint32_t blocks  = (arena_len + threads - 1) / threads;
    scan_kernel<<<blocks, threads, 0, stream>>>(d_arena, d_segs, nsegs, arena_len,
                                                d_next, d_term, d_matches,
                                                d_n_matches, max_matches, d_seg_cost);
    CK(cudaGetLastError());
}
