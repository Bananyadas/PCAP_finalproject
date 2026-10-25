#ifndef IDS_CPU_MATCH_H
#define IDS_CPU_MATCH_H

#include "ids_types.h"
#include <vector>

// True when a match at `pos` of length `pat_len` should be reported, given
// that the segment starts with `carry` bytes copied from the previous one.
// Shared rule: the CUDA kernel applies the identical test on the device.
bool carry_keeps_match(uint32_t pos, uint32_t pat_len, uint32_t carry);

// Scan one segment. steps_out receives the transition count (the cost metric
// Ananya Das's predictor learns from). Pass nullptr if not needed.
void cpu_match_segment(const PfacTable &t, const uint8_t *arena,
                       const Segment &seg, uint32_t seg_idx,
                       std::vector<Match> &out, uint64_t *steps_out);

// Scan a whole batch; costs[i] is the step count for segment i.
void cpu_match_batch(const PfacTable &t, const uint8_t *arena,
                     const Segment *segs, uint32_t num_segs,
                     std::vector<Match> &out, std::vector<uint64_t> &costs);

// Canonical ordering, so CPU and GPU output can be compared directly.
void sort_matches(std::vector<Match> &v);

#endif
