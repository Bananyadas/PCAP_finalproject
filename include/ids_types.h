// ids_types.h — the matcher's own types.
//
// Segment, Match and FlowRec live in shared.h, which Ananyaraj's ingest code
// also uses. Defining them once means they cannot drift apart.

#ifndef IDS_TYPES_H
#define IDS_TYPES_H

#include <stdint.h>
#include "shared.h"

// ---------------------------------------------------------------------------
// PFAC automaton — Parallel Failure-less Aho-Corasick (Lin et al., 2013).
// Goto trie only, no failure links: every thread starts at the root at its own
// byte and exits on the first missing transition.
//
// Flattened layout:  next_state = table[state * 256 + byte]
//                    PFAC_NO_STATE (-1) means this thread is done.
// ---------------------------------------------------------------------------

#define PFAC_ROOT        0
#define PFAC_NO_STATE   (-1)
#define PFAC_ALPHABET    256

typedef struct {
    int32_t  *table;       // num_states * 256 transitions
    int32_t  *output;      // output[s] = sig_id if terminal, else -1
    uint32_t *pat_len;     // pattern length per sig_id
    uint32_t  num_states;
    uint32_t  num_patterns;
    uint32_t  max_pat_len; // L_max — sets the tail-carry length
} PfacTable;

#endif // IDS_TYPES_H
