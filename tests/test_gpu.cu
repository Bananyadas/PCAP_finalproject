// test_gpu.cu — run the same inputs through the CUDA kernel and diff the
// result against the CPU reference. Needs a GPU; use the Colab notebook.
//
// The diff is the whole point. If a single match differs, the kernel is wrong,
// and no speedup number from it is worth reporting.

#include "cpu_match.h"
#include "pfac.h"
#include "ids_types.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <cuda_runtime.h>

struct GpuCtx;
extern "C" int gpu_upload_table(GpuCtx *ctx, const PfacTable *t);
extern "C" int gpu_match_batch(GpuCtx *ctx,
                               const uint8_t *arena, size_t arena_len,
                               const Segment *segs, uint32_t num_segs,
                               const uint32_t *seg_of_byte,
                               const uint32_t *seg_base,
                               uint32_t total_bytes,
                               Match *matches_out, uint32_t match_capacity,
                               unsigned long long *seg_cost_out,
                               cudaStream_t stream);
// GpuCtx is defined in gpu_match.cu; we only need storage of the right size.
extern "C" size_t gpu_ctx_size();
extern "C" void   gpu_ctx_init(void *mem);

// --------------------------------------------------------------------------

static std::vector<std::string> make_patterns() {
    return { "/admin.php?cmd=", "/admin", "SELECT * FROM",
             "\x90\x90\x90", "evilbot", "../../etc/passwd",
             "cmd.exe", "UNION SELECT" };
}

// Build a batch of segments with deliberately uneven content: a few payloads
// stuffed with near-misses and real signatures, many payloads of filler.
static void make_batch(std::vector<uint8_t> &arena,
                       std::vector<Segment> &segs,
                       int num_cheap, int num_pricey)
{
    auto append = [&](const std::string &s, uint32_t carry) {
        Segment seg;
        seg.flow_id = (uint32_t)segs.size();
        seg.offset  = (uint32_t)arena.size();
        seg.len     = (uint32_t)s.size();
        seg.carry   = carry;
        arena.insert(arena.end(), s.begin(), s.end());
        segs.push_back(seg);
    };

    srand(1234);  // fixed seed: the test must be reproducible

    for (int i = 0; i < num_cheap; ++i) {
        std::string s;
        int n = 400 + rand() % 800;
        for (int j = 0; j < n; ++j) s.push_back((char)('a' + rand() % 26));
        append(s, 0);
    }
    for (int i = 0; i < num_pricey; ++i) {
        std::string s;
        int n = 20 + rand() % 40;
        for (int j = 0; j < n; ++j) {
            s += "/admin.php?cmd=id&x=";     // real hit
            s += "/admin.ph";                // near miss: deep walk, no match
            s += "SELECT * FROM users;";     // real hit
        }
        append(s, i % 3 == 0 ? 12u : 0u);    // some carry a boundary prefix
    }
}

int main() {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, 0) != cudaSuccess) {
        fprintf(stderr, "no CUDA device\n");
        return 1;
    }
    printf("GPU: %s, %d SMs, %.1f GB\n\n", prop.name, prop.multiProcessorCount,
           prop.totalGlobalMem / 1e9);

    PfacTable t = pfac_build(make_patterns());
    printf("automaton: %u states, L_max %u, table %.1f KB\n",
           t.num_states, t.max_pat_len, pfac_table_bytes(t) / 1024.0);

    std::vector<uint8_t> arena;
    std::vector<Segment> segs;
    make_batch(arena, segs, 200, 20);

    // thread -> segment lookup
    std::vector<uint32_t> seg_base(segs.size()), seg_of_byte;
    uint32_t running = 0;
    for (size_t i = 0; i < segs.size(); ++i) {
        seg_base[i] = running;
        for (uint32_t b = 0; b < segs[i].len; ++b) seg_of_byte.push_back((uint32_t)i);
        running += segs[i].len;
    }
    uint32_t total_bytes = running;
    printf("batch: %zu segments, %u bytes\n\n", segs.size(), total_bytes);

    // ---- CPU reference ----
    std::vector<Match>    cpu_m;
    std::vector<uint64_t> cpu_cost;
    cudaEvent_t e0, e1; cudaEventCreate(&e0); cudaEventCreate(&e1);

    cudaEventRecord(e0);
    cpu_match_batch(t, arena.data(), segs.data(), (uint32_t)segs.size(),
                    cpu_m, cpu_cost);
    cudaEventRecord(e1); cudaEventSynchronize(e1);
    float cpu_ms = 0; cudaEventElapsedTime(&cpu_ms, e0, e1);
    sort_matches(cpu_m);
    printf("CPU reference: %zu matches in %.2f ms\n", cpu_m.size(), cpu_ms);

    // ---- GPU ----
    void *ctx_mem = calloc(1, gpu_ctx_size());
    gpu_ctx_init(ctx_mem);
    GpuCtx *ctx = (GpuCtx *)ctx_mem;
    if (gpu_upload_table(ctx, &t) != 0) return 1;

    uint32_t cap = (uint32_t)cpu_m.size() * 2 + 1024;
    std::vector<Match> gpu_m(cap);
    std::vector<unsigned long long> gpu_cost(segs.size());

    // warm-up, then timed run
    gpu_match_batch(ctx, arena.data(), arena.size(), segs.data(),
                    (uint32_t)segs.size(), seg_of_byte.data(), seg_base.data(),
                    total_bytes, gpu_m.data(), cap, gpu_cost.data(), 0);

    cudaEventRecord(e0);
    int found = gpu_match_batch(ctx, arena.data(), arena.size(), segs.data(),
                                (uint32_t)segs.size(), seg_of_byte.data(),
                                seg_base.data(), total_bytes,
                                gpu_m.data(), cap, gpu_cost.data(), 0);
    cudaEventRecord(e1); cudaEventSynchronize(e1);
    float gpu_ms = 0; cudaEventElapsedTime(&gpu_ms, e0, e1);
    if (found < 0) return 1;

    gpu_m.resize(found);
    sort_matches(gpu_m);
    printf("GPU kernel:    %d matches in %.2f ms  (%.1fx)\n\n",
           found, gpu_ms, cpu_ms / gpu_ms);

    // ---- the diff ----
    int diffs = 0;
    if (cpu_m.size() != gpu_m.size()) {
        printf("MISMATCH: %zu CPU matches vs %zu GPU matches\n",
               cpu_m.size(), gpu_m.size());
        ++diffs;
    } else {
        for (size_t i = 0; i < cpu_m.size(); ++i) {
            if (cpu_m[i].seg_idx != gpu_m[i].seg_idx ||
                cpu_m[i].pos     != gpu_m[i].pos     ||
                cpu_m[i].sig_id  != gpu_m[i].sig_id) {
                if (diffs < 5)
                    printf("MISMATCH at %zu: cpu(seg %u pos %u sig %u) "
                           "gpu(seg %u pos %u sig %u)\n", i,
                           cpu_m[i].seg_idx, cpu_m[i].pos, cpu_m[i].sig_id,
                           gpu_m[i].seg_idx, gpu_m[i].pos, gpu_m[i].sig_id);
                ++diffs;
            }
        }
    }
    printf("match sets %s\n", diffs ? "DIFFER  <-- kernel is wrong" : "are IDENTICAL");

    // ---- cost agreement ----
    int cost_diffs = 0;
    for (size_t i = 0; i < segs.size(); ++i)
        if (cpu_cost[i] != gpu_cost[i]) ++cost_diffs;
    printf("per-segment step counts %s (%d of %zu differ)\n",
           cost_diffs ? "DIFFER" : "agree", cost_diffs, segs.size());

    // ---- the skew Ananya Das needs ----
    unsigned long long lo = ~0ull, hi = 0, sum = 0;
    for (size_t i = 0; i < segs.size(); ++i) {
        unsigned long long c = gpu_cost[i];
        if (c < lo) lo = c;
        if (c > hi) hi = c;
        sum += c;
    }
    printf("\nsegment cost: min %llu, max %llu, mean %.0f  -> max/mean = %.1fx\n",
           lo, hi, (double)sum / segs.size(), (double)hi / ((double)sum / segs.size()));
    printf("A batch is only as fast as its most expensive warp, so that\n"
           "max/mean ratio is roughly what the adaptive composer can win back.\n");

    pfac_free(&t);
    free(ctx_mem);
    return (diffs || cost_diffs) ? 1 : 0;
}
