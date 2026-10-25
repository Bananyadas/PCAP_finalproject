// cpu_match.cpp — single-threaded reference matcher.
//
// This is ground truth. The CUDA kernel must produce exactly the same set of
// matches on the same input, every time. When the two disagree, the GPU is
// wrong until proven otherwise.
//
// It walks the same flattened table with the same failure-less rule, so it is
// also a fair sequential baseline for the speedup numbers.

#include "cpu_match.h"
#include <algorithm>

// --------------------------------------------------------------------------
// Carry de-duplication
// --------------------------------------------------------------------------
// A segment may begin with `carry` bytes copied from the tail of the previous
// segment, so that a signature straddling the cut is still visible.
//
// A match starting at position p with length L inside that carry region was
// ALREADY reported by the previous segment if it ended there too:
//
//      p + L <= carry   ->  lies entirely in the previous segment  -> drop
//      p + L >  carry   ->  crosses the boundary, genuinely new    -> keep
//
// Anything starting at p >= carry is in this segment's own bytes -> keep.
bool carry_keeps_match(uint32_t pos, uint32_t pat_len, uint32_t carry) {
    if (pos >= carry) return true;
    return pos + pat_len > carry;
}

void cpu_match_segment(const PfacTable &t,
                       const uint8_t   *arena,
                       const Segment   &seg,
                       uint32_t         seg_idx,
                       std::vector<Match> &out,
                       uint64_t        *steps_out)
{
    uint64_t steps = 0;
    const uint8_t *text = arena + seg.offset;

    for (uint32_t start = 0; start < seg.len; ++start) {
        int32_t  state = PFAC_ROOT;
        uint32_t i     = start;

        while (i < seg.len) {
            int32_t next = t.table[(size_t)state * PFAC_ALPHABET + text[i]];
            ++steps;                        // one transition lookup = one step
            if (next == PFAC_NO_STATE) break;

            state = next;
            ++i;

            int32_t sig = t.output[state];
            if (sig >= 0) {
                uint32_t plen = t.pat_len[sig];
                if (carry_keeps_match(start, plen, seg.carry)) {
                    Match m;
                    m.seg_idx = seg_idx;
                    m.pos     = start;
                    m.sig_id  = (uint32_t)sig;
                    out.push_back(m);
                }
                // keep walking: a longer pattern may share this prefix
            }
        }
    }

    if (steps_out) *steps_out = steps;
}

void cpu_match_batch(const PfacTable &t,
                     const uint8_t   *arena,
                     const Segment   *segs,
                     uint32_t         num_segs,
                     std::vector<Match> &out,
                     std::vector<uint64_t> &costs)
{
    costs.assign(num_segs, 0);
    for (uint32_t s = 0; s < num_segs; ++s)
        cpu_match_segment(t, arena, segs[s], s, out, &costs[s]);
}

void sort_matches(std::vector<Match> &v) {
    std::sort(v.begin(), v.end(), [](const Match &a, const Match &b) {
        if (a.seg_idx != b.seg_idx) return a.seg_idx < b.seg_idx;
        if (a.pos     != b.pos)     return a.pos     < b.pos;
        return a.sig_id < b.sig_id;
    });
}
