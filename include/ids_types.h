// ids_types.h — shared contracts for the whole team.
// AGREED INTERFACE: do not change without telling Ananyaraj and Ananya Das.
#ifndef IDS_TYPES_H
#define IDS_TYPES_H

#include <stdint.h>

// ---------------------------------------------------------------------------
// Team contracts (identical on host and device)
// ---------------------------------------------------------------------------

// One piece of payload for the GPU to scan.
// Points into a shared byte arena; carries no bytes of its own.
typedef struct {
    uint32_t flow_id;  // which flow it came from
    uint32_t offset;   // start position in the byte arena
    uint32_t len;      // number of bytes, including any carry prefix
    uint32_t carry;    // bytes at the front copied from the previous segment
} Segment;

// One signature hit, reported by the matcher.
typedef struct {
    uint32_t seg_idx;  // index into the Segment array
    uint32_t pos;      // byte offset of the match START within that segment
    uint32_t sig_id;   // which pattern matched
} Match;

// Per-flow state owned by Ananyaraj, read by Ananya Das.
typedef struct {
    uint64_t key;       // hashed 5-tuple
    uint64_t bytes;     // bytes seen so far
    float    cost_est;  // predicted scan cost
} FlowRec;

// ---------------------------------------------------------------------------
// Automaton (Asmita's half)
// ---------------------------------------------------------------------------
//
// Parallel Failure-less Aho-Corasick (PFAC): the goto trie only, no failure
// links. Every thread starts at the root at its own byte and walks forward
// until a transition is missing, then stops. Lin et al. (2013).
//
// Flattened layout: a dense row-major table of (num_states * 256) int32.
//   next_state = table[state * 256 + byte]
//   PFAC_NO_STATE (-1) means no transition -> this thread is done.
// Dense costs memory but gives one coalesced load per step, which is what
// makes it fast on a GPU. Bellekens et al. (2017) compress this; we do not,
// because our contribution is scheduling, not memory footprint.

#define PFAC_ROOT        0
#define PFAC_NO_STATE   (-1)
#define PFAC_ALPHABET    256

typedef struct {
    int32_t  *table;       // num_states * 256 transitions
    int32_t  *output;      // output[s] = sig_id if s is terminal, else -1
    uint32_t *pat_len;     // pat_len[sig_id] = pattern length in bytes
    uint32_t  num_states;
    uint32_t  num_patterns;
    uint32_t  max_pat_len; // L_max: Ananya Das needs this for the tail-carry
} PfacTable;

#endif // IDS_TYPES_H
