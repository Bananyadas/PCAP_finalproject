#include "scanner_cpu.h"
#include <stdlib.h>
#include <string.h>

void pfac_build(Pfac* s, const Pat* pats, size_t n) {
    memset(s, 0, sizeof *s);
    size_t cap = 1024;
    s->next = (int32_t*)malloc(cap * 256 * sizeof(int32_t));
    s->term = (int32_t*)malloc(cap * sizeof(int32_t));
    s->lens = (size_t*)malloc((n ? n : 1) * sizeof(size_t));
    for (int c = 0; c < 256; c++) s->next[c] = -1;
    s->term[0] = -1; s->nnodes = 1;
    for (size_t i = 0; i < n; i++) {
        if (pats[i].len == 0) continue;
        int dup = 0;   /* O(n^2), fine for ~2000 patterns */
        for (size_t j = 0; j < i && !dup; j++)
            dup = pats[j].len == pats[i].len && !memcmp(pats[j].p, pats[i].p, pats[i].len);
        if (dup) continue;
        int32_t node = 0;
        for (size_t k = 0; k < pats[i].len; k++) {
            int32_t* slot = &s->next[(size_t)node * 256 + pats[i].p[k]];
            if (*slot < 0) {
                if (s->nnodes == cap) {
                    cap *= 2;
                    s->next = (int32_t*)realloc(s->next, cap * 256 * sizeof(int32_t));
                    s->term = (int32_t*)realloc(s->term, cap * sizeof(int32_t));
                    slot = &s->next[(size_t)node * 256 + pats[i].p[k]];
                }
                *slot = (int32_t)s->nnodes;
                s->term[s->nnodes] = -1;
                for (int c = 0; c < 256; c++) s->next[s->nnodes * 256 + c] = -1;
                s->nnodes++;
            }
            node = *slot;
        }
        s->term[node] = (int32_t)s->nsigs;
        s->lens[s->nsigs++] = pats[i].len;
        if (pats[i].len > s->maxlen) s->maxlen = pats[i].len;
    }
}
void pfac_free(Pfac* s) { free(s->next); free(s->term); free(s->lens); memset(s, 0, sizeof *s); }

void matchvec_push(MatchVec* m, Match x) {
    if (m->n == m->cap) { m->cap = m->cap ? m->cap * 2 : 1024; m->v = (Match*)realloc(m->v, m->cap * sizeof(Match)); }
    m->v[m->n++] = x;
}

void pfac_scan(const Pfac* s, const Batch* b, MatchVec* out, uint32_t* pos_steps) {
    out->n = 0;
    for (uint32_t si = 0; si < b->nsegs; si++) {
        const Segment* sg = &b->segs[si];
        const uint8_t* base = b->arena + sg->offset;
        for (uint32_t p = 0; p < sg->len; p++) {
            int32_t node = 0; uint32_t steps = 0;
            for (uint32_t k = p; k < sg->len; k++) {      /* bounded by the segment end */
                steps++;
                int32_t nx = s->next[(size_t)node * 256 + base[k]];
                if (nx < 0) break;
                node = nx;
                if (s->term[node] >= 0) { Match m = { si, p, (uint32_t)s->term[node] }; matchvec_push(out, m); }
            }
            pos_steps[sg->offset + p] = steps;
        }
    }
}

void segment_costs(const Batch* b, const uint32_t* pos_steps, uint32_t* seg_cost) {
    for (size_t i = 0; i < b->nsegs; i++) {
        uint64_t sum = 0;
        for (uint32_t p = 0; p < b->segs[i].len; p++) sum += pos_steps[b->segs[i].offset + p];
        seg_cost[i] = sum > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)sum;
    }
}

void dedupe(const Batch* b, MatchVec* m, const Pfac* s) {
    size_t w = 0;
    for (size_t i = 0; i < m->n; i++)
        if (m->v[i].pos + s->lens[m->v[i].sig_id] > b->segs[m->v[i].seg_idx].carry) m->v[w++] = m->v[i];
    m->n = w;
}

void append_alerts(const Batch* b, const MatchVec* d, AlertVec* out) {
    for (size_t i = 0; i < d->n; i++) {
        const Match* x = &d->v[i];
        const Segment* s = &b->segs[x->seg_idx];
        if (out->n == out->cap) { out->cap = out->cap ? out->cap * 2 : 4096; out->v = (Alert*)realloc(out->v, out->cap * sizeof(Alert)); }
        /* flow_pos = where the owned bytes start; the segment begins `carry` bytes earlier */
        Alert a = { s->flow_id, b->flow_pos[x->seg_idx] - s->carry + x->pos, x->sig_id };
        out->v[out->n++] = a;
    }
}
int alert_cmp(const Alert* a, const Alert* b) {
    if (a->flow_id != b->flow_id) return a->flow_id < b->flow_id ? -1 : 1;
    if (a->stream_pos != b->stream_pos) return a->stream_pos < b->stream_pos ? -1 : 1;
    if (a->sig_id != b->sig_id) return a->sig_id < b->sig_id ? -1 : 1;
    return 0;
}
static int alert_qcmp(const void* a, const void* b) { return alert_cmp((const Alert*)a, (const Alert*)b); }
void alerts_sort(AlertVec* a) { if (a->n) qsort(a->v, a->n, sizeof(Alert), alert_qcmp); }

GpuModel model_batch(const uint32_t* st, size_t n, int block, int sms) {
    GpuModel g = {0, 0, 0};
    size_t nwarps = (n + 31) / 32, wpb = (size_t)block / 32;
    double* free_at = (double*)calloc((size_t)sms, sizeof(double));
    uint64_t cur = 0;
    for (size_t w = 0; w < nwarps; w++) {
        uint32_t mx = 0;
        size_t end = (w + 1) * 32 < n ? (w + 1) * 32 : n;
        for (size_t i = w * 32; i < end; i++) { if (st[i] > mx) mx = st[i]; g.sum_steps += st[i]; }
        g.sum_warp_max += mx; cur += mx;
        if ((w + 1) % wpb == 0 || w + 1 == nwarps) {       /* block finished: hand to earliest-free SM */
            int m = 0;
            for (int i = 1; i < sms; i++) if (free_at[i] < free_at[m]) m = i;
            free_at[m] += (double)cur; cur = 0;
        }
    }
    for (int i = 0; i < sms; i++) if (free_at[i] > g.makespan) g.makespan = free_at[i];
    free(free_at);
    return g;
}
