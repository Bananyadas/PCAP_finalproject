// gpu_match.cu — PFAC matching kernel.
//
// One thread per byte position of the batch. Each thread starts at the root
// of the goto trie at its own byte and walks forward until a transition is
// missing, then exits. No failure links: a thread that mismatches is done.
//
// This is where the project's problem lives. Threads run in warps of 32 in
// lockstep, and the warp does not retire until its slowest thread does. Most
// threads mismatch within a byte or two; a few walk deep. The idle time that
// creates is exactly what Ananya Das's batch composer is trying to reduce.
//
// Two things this kernel owes the rest of the system:
//   1. Matches identical to the CPU reference, including the carry rule.
//   2. A per-segment step count, which is the cost signal the predictor uses.

#include "ids_types.h"
#include <cstdio>
#include <new>

#define THREADS_PER_BLOCK 256

// ---------------------------------------------------------------------------
// Device-side copy of the carry rule from cpu_match.cpp. These two must agree;
// if you change one, change the other, or the alert-set diff will fail.
// ---------------------------------------------------------------------------
__device__ __forceinline__
bool d_carry_keeps_match(uint32_t pos, uint32_t pat_len, uint32_t carry)
{
    if (pos >= carry) return true;
    return pos + pat_len > carry;
}

// ---------------------------------------------------------------------------
// Thread -> (segment, byte) mapping.
//
// We launch one thread per byte of the whole batch and give each thread its
// segment via a prefix-sum lookup table built on the host (seg_of_byte).
// That costs one extra load but keeps the launch flat and fully coalesced,
// which matters more. The alternative — one block per segment — wastes whole
// blocks on short segments, which is the very imbalance we are studying.
// ---------------------------------------------------------------------------

__global__ void pfac_kernel(const int32_t  *__restrict__ table,
                            const int32_t  *__restrict__ output,
                            const uint32_t *__restrict__ pat_len,
                            const uint8_t  *__restrict__ arena,
                            const Segment  *__restrict__ segs,
                            const uint32_t *__restrict__ seg_of_byte,
                            const uint32_t *__restrict__ seg_base,  // prefix sums
                            uint32_t        total_bytes,
                            Match          *__restrict__ matches,
                            uint32_t       *__restrict__ match_count,
                            uint32_t        match_capacity,
                            unsigned long long *__restrict__ seg_cost)
{
    uint32_t gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= total_bytes) return;

    uint32_t seg_idx = seg_of_byte[gid];
    Segment  seg     = segs[seg_idx];

    // position of this thread's starting byte within its own segment
    uint32_t start = gid - seg_base[seg_idx];

    const uint8_t *text = arena + seg.offset;

    int32_t  state = PFAC_ROOT;
    uint32_t i     = start;
    uint32_t steps = 0;

    while (i < seg.len) {
        int32_t next = table[(size_t)state * PFAC_ALPHABET + text[i]];
        ++steps;
        if (next == PFAC_NO_STATE) break;

        state = next;
        ++i;

        int32_t sig = output[state];
        if (sig >= 0) {
            uint32_t plen = pat_len[sig];
            if (d_carry_keeps_match(start, plen, seg.carry)) {
                uint32_t slot = atomicAdd(match_count, 1u);
                if (slot < match_capacity) {
                    matches[slot].seg_idx = seg_idx;
                    matches[slot].pos     = start;
                    matches[slot].sig_id  = (uint32_t)sig;
                }
                // slot >= capacity: counter still increments, so the host can
                // see the overflow and re-run with a bigger buffer.
            }
        }
    }

    // Per-segment cost. One atomic per thread is heavy; warp-aggregate first
    // so only one atomic per warp reaches memory.
    unsigned mask = __activemask();
    unsigned long long warp_sum = steps;
    for (int off = 16; off > 0; off >>= 1)
        warp_sum += __shfl_down_sync(mask, warp_sum, off);

    // Only valid when the whole warp is in the same segment, which holds for
    // all but the warps straddling a segment boundary. Those fall back to
    // per-thread atomics so the total stays exact.
    uint32_t first_seg = __shfl_sync(mask, seg_idx, 0);
    bool uniform = __all_sync(mask, seg_idx == first_seg);

    if (uniform) {
        if ((threadIdx.x & 31) == 0)
            atomicAdd(&seg_cost[seg_idx], warp_sum);
    } else {
        atomicAdd(&seg_cost[seg_idx], (unsigned long long)steps);
    }
}

// ---------------------------------------------------------------------------
// Host wrapper
// ---------------------------------------------------------------------------

#define CUDA_CHECK(call)                                                      \
    do {                                                                      \
        cudaError_t e = (call);                                               \
        if (e != cudaSuccess) {                                               \
            fprintf(stderr, "CUDA error %s at %s:%d\n",                       \
                    cudaGetErrorString(e), __FILE__, __LINE__);               \
            return -1;                                                        \
        }                                                                     \
    } while (0)

// Everything the device needs, allocated once and reused across batches.
struct GpuCtx {
    int32_t  *d_table   = nullptr;
    int32_t  *d_output  = nullptr;
    uint32_t *d_pat_len = nullptr;
    uint8_t  *d_arena   = nullptr;
    Segment  *d_segs    = nullptr;
    uint32_t *d_seg_of_byte = nullptr;
    uint32_t *d_seg_base    = nullptr;
    Match    *d_matches     = nullptr;
    uint32_t *d_match_count = nullptr;
    unsigned long long *d_seg_cost = nullptr;
    size_t arena_cap = 0, seg_cap = 0, byte_cap = 0, match_cap = 0;
};

// GpuCtx stays private to this file so the host code never pokes at device
// pointers. Callers allocate the right number of bytes and hand it back.
extern "C" size_t gpu_ctx_size() { return sizeof(GpuCtx); }
extern "C" void   gpu_ctx_init(void *mem) { new (mem) GpuCtx(); }

extern "C" int gpu_upload_table(GpuCtx *ctx, const PfacTable *t)
{
    size_t cells = (size_t)t->num_states * PFAC_ALPHABET;
    CUDA_CHECK(cudaMalloc(&ctx->d_table,   cells * sizeof(int32_t)));
    CUDA_CHECK(cudaMalloc(&ctx->d_output,  t->num_states * sizeof(int32_t)));
    CUDA_CHECK(cudaMalloc(&ctx->d_pat_len, t->num_patterns * sizeof(uint32_t)));

    CUDA_CHECK(cudaMemcpy(ctx->d_table,   t->table,   cells * sizeof(int32_t),
                          cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(ctx->d_output,  t->output,  t->num_states * sizeof(int32_t),
                          cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(ctx->d_pat_len, t->pat_len, t->num_patterns * sizeof(uint32_t),
                          cudaMemcpyHostToDevice));
    return 0;
}

// Scan one batch. Returns the number of matches found, or -1 on error.
// `matches_out` must have room for match_capacity entries.
extern "C" int gpu_match_batch(GpuCtx          *ctx,
                               const uint8_t   *arena,    size_t arena_len,
                               const Segment   *segs,     uint32_t num_segs,
                               const uint32_t  *seg_of_byte,
                               const uint32_t  *seg_base,
                               uint32_t         total_bytes,
                               Match           *matches_out,
                               uint32_t         match_capacity,
                               unsigned long long *seg_cost_out,
                               cudaStream_t     stream)
{
    // (Re)allocate if this batch is bigger than anything seen so far.
    if (arena_len > ctx->arena_cap) {
        cudaFree(ctx->d_arena);
        CUDA_CHECK(cudaMalloc(&ctx->d_arena, arena_len));
        ctx->arena_cap = arena_len;
    }
    if (num_segs > ctx->seg_cap) {
        cudaFree(ctx->d_segs); cudaFree(ctx->d_seg_base); cudaFree(ctx->d_seg_cost);
        CUDA_CHECK(cudaMalloc(&ctx->d_segs,     num_segs * sizeof(Segment)));
        CUDA_CHECK(cudaMalloc(&ctx->d_seg_base, num_segs * sizeof(uint32_t)));
        CUDA_CHECK(cudaMalloc(&ctx->d_seg_cost, num_segs * sizeof(unsigned long long)));
        ctx->seg_cap = num_segs;
    }
    if (total_bytes > ctx->byte_cap) {
        cudaFree(ctx->d_seg_of_byte);
        CUDA_CHECK(cudaMalloc(&ctx->d_seg_of_byte, total_bytes * sizeof(uint32_t)));
        ctx->byte_cap = total_bytes;
    }
    if (match_capacity > ctx->match_cap) {
        cudaFree(ctx->d_matches);
        CUDA_CHECK(cudaMalloc(&ctx->d_matches, match_capacity * sizeof(Match)));
        ctx->match_cap = match_capacity;
    }
    if (!ctx->d_match_count)
        CUDA_CHECK(cudaMalloc(&ctx->d_match_count, sizeof(uint32_t)));

    CUDA_CHECK(cudaMemcpyAsync(ctx->d_arena, arena, arena_len,
                               cudaMemcpyHostToDevice, stream));
    CUDA_CHECK(cudaMemcpyAsync(ctx->d_segs, segs, num_segs * sizeof(Segment),
                               cudaMemcpyHostToDevice, stream));
    CUDA_CHECK(cudaMemcpyAsync(ctx->d_seg_of_byte, seg_of_byte,
                               total_bytes * sizeof(uint32_t),
                               cudaMemcpyHostToDevice, stream));
    CUDA_CHECK(cudaMemcpyAsync(ctx->d_seg_base, seg_base,
                               num_segs * sizeof(uint32_t),
                               cudaMemcpyHostToDevice, stream));
    CUDA_CHECK(cudaMemsetAsync(ctx->d_match_count, 0, sizeof(uint32_t), stream));
    CUDA_CHECK(cudaMemsetAsync(ctx->d_seg_cost, 0,
                               num_segs * sizeof(unsigned long long), stream));

    uint32_t blocks = (total_bytes + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;
    pfac_kernel<<<blocks, THREADS_PER_BLOCK, 0, stream>>>(
        ctx->d_table, ctx->d_output, ctx->d_pat_len,
        ctx->d_arena, ctx->d_segs, ctx->d_seg_of_byte, ctx->d_seg_base,
        total_bytes, ctx->d_matches, ctx->d_match_count, match_capacity,
        ctx->d_seg_cost);

    uint32_t found = 0;
    CUDA_CHECK(cudaMemcpyAsync(&found, ctx->d_match_count, sizeof(uint32_t),
                               cudaMemcpyDeviceToHost, stream));
    CUDA_CHECK(cudaStreamSynchronize(stream));

    uint32_t copy_n = found < match_capacity ? found : match_capacity;
    if (copy_n) {
        CUDA_CHECK(cudaMemcpyAsync(matches_out, ctx->d_matches,
                                   copy_n * sizeof(Match),
                                   cudaMemcpyDeviceToHost, stream));
    }
    if (seg_cost_out) {
        CUDA_CHECK(cudaMemcpyAsync(seg_cost_out, ctx->d_seg_cost,
                                   num_segs * sizeof(unsigned long long),
                                   cudaMemcpyDeviceToHost, stream));
    }
    CUDA_CHECK(cudaStreamSynchronize(stream));

    if (found > match_capacity) {
        fprintf(stderr, "gpu_match_batch: match buffer overflow (%u > %u)\n",
                found, match_capacity);
        return -1;
    }
    return (int)found;
}
