/*
 * flow_export.c - Builds arena + Segment[] + FlowRec[] for the GPU stage.
 *
 * One Segment per flow (whole reassembled stream), in flow_id order.
 * carry = 0 (splitting/overlap is the batcher's job, not ours).
 * Empty flows still get a Segment with len = 0 so indices line up.
 */
#include "flow_export.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int export_build(const FlowTable *ft, ExportData *ex, char *err, size_t errlen)
{
    memset(ex, 0, sizeof *ex);
    uint64_t total = 0;
    for (size_t i = 0; i < ft->nflows; i++) total += ft->flows[i].stream.out.len;

    /* Segment.offset/len are uint32: refuse instead of silently truncating. */
    if (total > UINT32_MAX) {
        snprintf(err, errlen, "arena %llu bytes exceeds uint32 offsets",
                 (unsigned long long)total);
        return -1;
    }
    if (ft->nflows > UINT32_MAX) {
        snprintf(err, errlen, "too many flows for uint32 flow_id");
        return -1;
    }

    size_t n = ft->nflows;
    ex->arena = malloc(total ? (size_t)total : 1);
    ex->segs  = malloc((n ? n : 1) * sizeof *ex->segs);
    ex->recs  = malloc((n ? n : 1) * sizeof *ex->recs);
    if (!ex->arena || !ex->segs || !ex->recs) {
        snprintf(err, errlen, "out of memory building export");
        export_free(ex);
        return -1;
    }

    uint32_t off = 0;
    for (size_t i = 0; i < n; i++) {
        const Flow *f = &ft->flows[i];
        uint32_t len = (uint32_t)f->stream.out.len;
        if (len) memcpy(ex->arena + off, f->stream.out.data, len);
        ex->segs[i].flow_id = f->flow_id;
        ex->segs[i].offset  = off;
        ex->segs[i].len     = len;
        ex->segs[i].carry   = 0;
        ex->recs[i].key      = f->key;
        ex->recs[i].bytes    = len;
        ex->recs[i].cost_est = 0.0f;
        off += len;
    }
    ex->arena_len = (size_t)total;
    ex->nsegs = ex->nrecs = n;
    return 0;
}

int export_verify(const ExportData *ex, const FlowTable *ft, char *err, size_t errlen)
{
    if (ex->nsegs != ft->nflows || ex->nrecs != ft->nflows) {
        snprintf(err, errlen, "count mismatch: %zu segs, %zu flows", ex->nsegs, ft->nflows);
        return -1;
    }
    uint64_t expect_off = 0;
    for (size_t i = 0; i < ex->nsegs; i++) {
        const Segment *s = &ex->segs[i];
        const Flow *f = &ft->flows[i];
        if (s->flow_id != i)        { snprintf(err, errlen, "seg %zu: flow_id %u not sorted", i, s->flow_id); return -1; }
        if (s->offset != expect_off){ snprintf(err, errlen, "seg %zu: offset not contiguous", i); return -1; }
        if (s->carry != 0)          { snprintf(err, errlen, "seg %zu: carry != 0", i); return -1; }
        if (s->len != f->stream.out.len) { snprintf(err, errlen, "seg %zu: length mismatch", i); return -1; }
        if ((uint64_t)s->offset + s->len > ex->arena_len) { snprintf(err, errlen, "seg %zu: out of arena", i); return -1; }
        if (s->len && memcmp(ex->arena + s->offset, f->stream.out.data, s->len) != 0) {
            snprintf(err, errlen, "seg %zu: bytes differ from stream", i); return -1;
        }
        if (ex->recs[i].key != f->key || ex->recs[i].bytes != s->len) {
            snprintf(err, errlen, "rec %zu: key/bytes mismatch", i); return -1;
        }
        expect_off += s->len;
    }
    if (expect_off != ex->arena_len) {
        snprintf(err, errlen, "arena length mismatch");
        return -1;
    }
    return 0;
}

uint64_t export_checksum(const ExportData *ex)
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < ex->arena_len; i++) { h ^= ex->arena[i]; h *= 1099511628211ull; }
    const uint8_t *p = (const uint8_t *)ex->segs;
    for (size_t i = 0; i < ex->nsegs * sizeof(Segment); i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

void export_free(ExportData *ex)
{
    free(ex->arena);
    free(ex->segs);
    free(ex->recs);
    memset(ex, 0, sizeof *ex);
}
