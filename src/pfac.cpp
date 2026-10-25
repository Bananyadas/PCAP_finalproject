// pfac.cpp — build the goto trie over all patterns, then flatten it.
//
// PFAC uses the goto function only. Classic Aho-Corasick adds failure links so
// one pass over the text finds every match; PFAC drops them because every byte
// position gets its own thread, so a thread that mismatches has nothing left to
// do and simply exits. That exit is what frees the GPU slot early — and also
// what creates the warp divergence our project is about.

#include "pfac.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

struct TrieNode {
    int32_t next[PFAC_ALPHABET];
    int32_t out;                 // sig_id if a pattern ends here, else -1
    TrieNode() { for (int i = 0; i < PFAC_ALPHABET; ++i) next[i] = PFAC_NO_STATE; out = -1; }
};

} // namespace

PfacTable pfac_build(const std::vector<std::string> &patterns) {
    std::vector<TrieNode> trie(1);           // state 0 = root

    uint32_t max_len = 0;
    std::vector<uint32_t> lens(patterns.size(), 0);

    for (size_t p = 0; p < patterns.size(); ++p) {
        const std::string &pat = patterns[p];
        int32_t s = PFAC_ROOT;

        for (unsigned char c : pat) {
            if (trie[s].next[c] == PFAC_NO_STATE) {
                trie.push_back(TrieNode());
                trie[s].next[c] = (int32_t)(trie.size() - 1);
            }
            s = trie[s].next[c];
        }

        // Two identical patterns land on the same state. Keep the first
        // sig_id; the duplicate is harmless but worth knowing about.
        if (trie[s].out == -1) trie[s].out = (int32_t)p;

        lens[p] = (uint32_t)pat.size();
        if (pat.size() > max_len) max_len = (uint32_t)pat.size();
    }

    PfacTable t;
    t.num_states   = (uint32_t)trie.size();
    t.num_patterns = (uint32_t)patterns.size();
    t.max_pat_len  = max_len;

    size_t cells = (size_t)t.num_states * PFAC_ALPHABET;
    t.table   = (int32_t  *)malloc(cells * sizeof(int32_t));
    t.output  = (int32_t  *)malloc(t.num_states * sizeof(int32_t));
    t.pat_len = (uint32_t *)malloc((patterns.empty() ? 1 : patterns.size()) * sizeof(uint32_t));

    for (uint32_t s = 0; s < t.num_states; ++s) {
        memcpy(&t.table[(size_t)s * PFAC_ALPHABET], trie[s].next,
               PFAC_ALPHABET * sizeof(int32_t));
        t.output[s] = trie[s].out;
    }
    for (size_t p = 0; p < patterns.size(); ++p) t.pat_len[p] = lens[p];

    return t;
}

void pfac_free(PfacTable *t) {
    free(t->table);   t->table = nullptr;
    free(t->output);  t->output = nullptr;
    free(t->pat_len); t->pat_len = nullptr;
    t->num_states = t->num_patterns = t->max_pat_len = 0;
}

size_t pfac_table_bytes(const PfacTable &t) {
    return (size_t)t.num_states * PFAC_ALPHABET * sizeof(int32_t);
}
