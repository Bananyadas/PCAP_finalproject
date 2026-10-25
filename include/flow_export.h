/**
 * flow_export.h — Build the shared byte arena and Segment array.
 *
 * The byte arena is one large contiguous buffer.
 * Every reconstructed flow payload is appended in order of flow_id.
 * Each flow gets exactly one Segment entry.
 *
 * Segment.carry is always set to 0 by this component.
 * The downstream batch composer writes the final carry value.
 *
 * Overflow check: if total arena bytes would exceed UINT32_MAX the
 * function aborts with an error rather than silently truncating.
 */

#ifndef FLOW_EXPORT_H
#define FLOW_EXPORT_H

#include "shared.h"
#include "tcp_reassembly.h"
#include <vector>
#include <cstdint>

/* -----------------------------------------------------------------------
 * ExportResult — output of the export step.
 *
 * Ownership:
 *   Both vectors are owned by the caller after export_flows() returns.
 *   The arena must remain valid for as long as any Segment is in use,
 *   because Segment.offset points into the arena.
 * --------------------------------------------------------------------- */
struct ExportResult {
    std::vector<uint8_t> arena;    /* byte arena — all payloads packed    */
    std::vector<Segment> segments; /* one entry per exported flow         */
    uint32_t             incomplete_flows; /* flows with reassembly gaps  */
};

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

/**
 * export_flows — build the arena and Segment array from a list of
 * fully-reassembled (or partially-reassembled) ReassemblyBuffers.
 *
 * Buffers are processed in ascending flow_id order for determinism.
 * Empty flows (no contiguous_data) are still represented; they get a
 * Segment with len == 0 so the downstream consumer can detect them.
 *
 * Returns false and prints an error if an overflow is detected.
 */
bool export_flows(const std::vector<ReassemblyBuffer>& buffers,
                  ExportResult& out);

/**
 * export_verify — sanity-check that every Segment's offset and len
 * are within bounds of the arena.
 *
 * Returns true if all segments are consistent.
 * Prints a detailed error for any inconsistency.
 */
bool export_verify(const ExportResult& result);

/**
 * export_print_stats — print arena size, segment count, and incomplete flows.
 */
void export_print_stats(const ExportResult& result);

#endif /* FLOW_EXPORT_H */
