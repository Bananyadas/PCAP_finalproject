/*
 * flow_export.h - Packs reassembled streams into the GPU-friendly format:
 *   one contiguous byte arena + Segment[] (sorted by flow_id) + FlowRec[].
 */
#ifndef FLOW_EXPORT_H
#define FLOW_EXPORT_H

#include <stddef.h>
#include <stdint.h>
#include "shared.h"
#include "flow_table.h"

typedef struct {
    uint8_t *arena;
    size_t   arena_len;
    Segment *segs;
    size_t   nsegs;
    FlowRec *recs;
    size_t   nrecs;
} ExportData;

/* Returns 0 on success, -1 on error (overflow / out-of-memory). */
int      export_build (const FlowTable *ft, ExportData *ex, char *err, size_t errlen);
/* Cross-checks the export against the flow table. 0 = OK, -1 = mismatch. */
int      export_verify(const ExportData *ex, const FlowTable *ft, char *err, size_t errlen);
/* FNV-1a over arena + segments: used to prove determinism across threads. */
uint64_t export_checksum(const ExportData *ex);
void     export_free  (ExportData *ex);

#endif /* FLOW_EXPORT_H */
