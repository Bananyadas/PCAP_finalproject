#include "composer.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static void* xrealloc(void* p, size_t n) {
    void* q = realloc(p, n);
    if (!q) { fprintf(stderr, "out of memory\n"); exit(1); }
    return q;
}

void batch_init(Batch* b) { memset(b, 0, sizeof *b); }
void batch_free(Batch* b) { free(b->arena); free(b->segs); free(b->flow_pos); batch_init(b); }
void batchlist_push(BatchList* l, Batch* b) {
    if (l->n == l->cap) { l->cap = l->cap ? l->cap * 2 : 16; l->v = (Batch*)xrealloc(l->v, l->cap * sizeof(Batch)); }
    l->v[l->n++] = *b;
    batch_init(b);
}
void batchlist_free(BatchList* l) {
    for (size_t i = 0; i < l->n; i++) batch_free(&l->v[i]);
    free(l->v); l->v = NULL; l->n = l->cap = 0;
}

/* Append one segment: [carry bytes][n new bytes], both copied from the flow.
 * TAIL-CARRY: any segment that does not start at byte 0 of its flow gets the previous
 * (lmax-1) bytes of the flow in front of it. A signature of <= lmax bytes straddling
 * the cut starts inside those carried bytes, so the scanner sees it whole. The carry
 * is the run of bytes immediately before `pos`, so carry+payload is ONE contiguous
 * slice of the flow. */
static void emit_segment(Batch* b, const FlowInput* f, uint64_t pos, uint64_t n, size_t lmax) {
    uint64_t carry = pos > 0 ? MIN((uint64_t)(lmax - 1), pos) : 0;
    size_t need = b->arena_len + (size_t)(carry + n);
    if (need > b->arena_cap) {
        size_t c = b->arena_cap ? b->arena_cap * 2 : 4096;
        while (c < need) c *= 2;
        b->arena = (uint8_t*)xrealloc(b->arena, c);
        b->arena_cap = c;
    }
    if (b->nsegs == b->segs_cap) {
        b->segs_cap = b->segs_cap ? b->segs_cap * 2 : 64;
        b->segs = (Segment*)xrealloc(b->segs, b->segs_cap * sizeof(Segment));
        b->flow_pos = (uint64_t*)xrealloc(b->flow_pos, b->segs_cap * sizeof(uint64_t));
    }
    Segment s = { f->flow_id, (uint32_t)b->arena_len, (uint32_t)(carry + n), (uint32_t)carry };
    memcpy(b->arena + b->arena_len, f->data + (pos - carry), (size_t)(carry + n));
    b->arena_len += (size_t)(carry + n);
    b->segs[b->nsegs] = s;
    b->flow_pos[b->nsegs] = pos;
    b->nsegs++;
}

/* ------------------------------- baseline ------------------------------- */
void static_compose(const FlowInput* flows, size_t nflows, const CostPredictor* pred,
                    const ComposeCfg* cfg, BatchList* out) {
    assert(cfg->batch_bytes > cfg->lmax);
    Batch cur; batch_init(&cur);
    for (size_t i = 0; i < nflows; i++) {
        const FlowInput* f = &flows[i];
        uint64_t pos = f->begin;
        while (pos < f->end) {
            uint64_t carry = pos > 0 ? MIN((uint64_t)(cfg->lmax - 1), pos) : 0;
            size_t room = cfg->batch_bytes - cur.arena_len;
            if (room <= carry) { batchlist_push(out, &cur); continue; } /* no room for even 1 new byte */
            uint64_t n = MIN(f->end - pos, (uint64_t)(room - carry));
            emit_segment(&cur, f, pos, n, cfg->lmax);
            cur.predicted_cost += (double)pred_cost_per_byte(pred, f->flow_id) * (double)(carry + n);
            pos += n;
        }
    }
    if (cur.nsegs) batchlist_push(out, &cur); else batch_free(&cur);
}

/* ------------------------------- adaptive ------------------------------- */
typedef struct {
    uint32_t fi;        /* index into flows[] */
    uint64_t pos, n, bytes;   /* bytes = n + carry: what it occupies in the arena */
    float cpb;          /* predicted cost per byte */
    double cost;        /* cpb * bytes */
    size_t seq;         /* creation order, makes the sorts deterministic */
} Chunk;
typedef struct { size_t used; double cost; Chunk* ch; size_t n, cap; } Bin;

static int cmp_cost_desc(const void* a, const void* b) {
    const Chunk *x = (const Chunk*)a, *y = (const Chunk*)b;
    if (x->cost != y->cost) return x->cost < y->cost ? 1 : -1;
    return x->seq < y->seq ? -1 : 1;
}
static int cmp_cpb_desc(const void* a, const void* b) {
    const Chunk *x = (const Chunk*)a, *y = (const Chunk*)b;
    if (x->cpb != y->cpb) return x->cpb < y->cpb ? 1 : -1;
    if (x->fi != y->fi) return x->fi < y->fi ? -1 : 1;
    return x->pos < y->pos ? -1 : 1;
}

void adaptive_compose(const FlowInput* flows, size_t nflows, const CostPredictor* pred,
                      const ComposeCfg* cfg, BatchList* out) {
    assert(cfg->chunk_bytes + cfg->lmax <= cfg->batch_bytes);

    /* 1. cut every flow into chunks of at most chunk_bytes */
    size_t nch = 0;
    for (size_t i = 0; i < nflows; i++)
        if (flows[i].end > flows[i].begin) nch += (size_t)((flows[i].end - flows[i].begin + cfg->chunk_bytes - 1) / cfg->chunk_bytes);
    if (nch == 0) return;
    Chunk* ch = (Chunk*)xrealloc(NULL, nch * sizeof(Chunk));
    size_t k = 0; uint64_t total = 0;
    for (size_t i = 0; i < nflows; i++) {
        const FlowInput* f = &flows[i];
        float cpb = pred_cost_per_byte(pred, f->flow_id);
        for (uint64_t pos = f->begin; pos < f->end;) {
            uint64_t n = MIN((uint64_t)cfg->chunk_bytes, f->end - pos);
            uint64_t carry = pos > 0 ? MIN((uint64_t)(cfg->lmax - 1), pos) : 0;
            Chunk c = { (uint32_t)i, pos, n, n + carry, cpb, (double)cpb * (double)(n + carry), k };
            ch[k++] = c; total += n + carry; pos += n;
        }
    }

    /* 2. deal chunks, most expensive first, into the currently cheapest batch that still
     *    has room (longest-processing-time-first). Same batch count as the baseline would
     *    use; a new one opens only if everything is full. */
    qsort(ch, nch, sizeof(Chunk), cmp_cost_desc);
    size_t nb = (size_t)((total + cfg->batch_bytes - 1) / cfg->batch_bytes);
    if (nb == 0) nb = 1;
    size_t nbins = nb, bcap = nb;
    Bin* bins = (Bin*)calloc(bcap, sizeof(Bin));
    for (size_t i = 0; i < nch; i++) {
        long best = -1;
        for (size_t b = 0; b < nbins; b++) {
            if (bins[b].used + ch[i].bytes > cfg->batch_bytes) continue;
            if (best < 0 || bins[b].cost < bins[best].cost) best = (long)b;
        }
        if (best < 0) {
            if (nbins == bcap) {
                bcap *= 2;
                bins = (Bin*)xrealloc(bins, bcap * sizeof(Bin));
                memset(bins + nbins, 0, (bcap - nbins) * sizeof(Bin));
            }
            best = (long)nbins++;
        }
        Bin* B = &bins[best];
        if (B->n == B->cap) { B->cap = B->cap ? B->cap * 2 : 32; B->ch = (Chunk*)xrealloc(B->ch, B->cap * sizeof(Chunk)); }
        B->ch[B->n++] = ch[i];
        B->used += (size_t)ch[i].bytes;
        B->cost += ch[i].cost;
    }

    /* 3. inside a batch, expensive chunks first: the GPU hands out thread blocks in order,
     *    so heavy blocks start early and none is left to run alone at the tail. */
    for (size_t b = 0; b < nbins; b++) {
        Bin* B = &bins[b];
        if (B->n) {
            qsort(B->ch, B->n, sizeof(Chunk), cmp_cpb_desc);
            Batch batch; batch_init(&batch);
            for (size_t i = 0; i < B->n; i++)
                emit_segment(&batch, &flows[B->ch[i].fi], B->ch[i].pos, B->ch[i].n, cfg->lmax);
            batch.predicted_cost = B->cost;
            batchlist_push(out, &batch);
        }
        free(B->ch);
    }
    free(bins);
    free(ch);
}
