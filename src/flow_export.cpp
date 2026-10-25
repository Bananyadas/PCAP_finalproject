/**
 * flow_export.cpp
 *
 * Packs all reconstructed flow payloads into one contiguous byte arena
 * and fills the fixed Segment array.
 *
 * Beginner guide:
 *   • The GPU matcher expects all payload data in one big buffer (arena).
 *   • Each flow's data is placed at a specific offset in that buffer.
 *   • A Segment record says "flow X's data starts at byte Y and is Z bytes".
 *   • We process flows in ascending flow_id order so the output is the
 *     same regardless of how many threads were used.
 */

#include "flow_export.h"
#include <cstdio>
#include <algorithm>
#include <limits>
#include <cassert>

/* -----------------------------------------------------------------------
 * export_flows
 * --------------------------------------------------------------------- */
bool export_flows(const std::vector<ReassemblyBuffer>& buffers,
                  ExportResult& out)
{
    out.arena.clear();
    out.segments.clear();
    out.incomplete_flows = 0;

    /* Sort by flow_id for deterministic output */
    std::vector<const ReassemblyBuffer*> sorted;
    sorted.reserve(buffers.size());
    for (const auto& b : buffers) sorted.push_back(&b);
    std::sort(sorted.begin(), sorted.end(),
        [](const ReassemblyBuffer* a, const ReassemblyBuffer* b){
            return a->flow_id < b->flow_id;
        });

    for (const ReassemblyBuffer* buf : sorted) {
        const size_t payload_size = buf->contiguous_data.size();

        /* Overflow check: offset and len must fit in uint32_t */
        if (out.arena.size() > std::numeric_limits<uint32_t>::max()) {
            fprintf(stderr,
                    "[export_flows] Arena offset overflow at flow_id %u. "
                    "Total arena size exceeds UINT32_MAX.\n",
                    buf->flow_id);
            return false;
        }
        if (payload_size > std::numeric_limits<uint32_t>::max()) {
            fprintf(stderr,
                    "[export_flows] Payload length overflow at flow_id %u "
                    "(%zu bytes > UINT32_MAX).\n",
                    buf->flow_id, payload_size);
            return false;
        }

        Segment seg;
        seg.flow_id = buf->flow_id;
        seg.offset  = static_cast<uint32_t>(out.arena.size());
        seg.len     = static_cast<uint32_t>(payload_size);
        seg.carry   = 0; /* always 0; downstream batch composer owns carry */

        /* Append payload bytes to the arena */
        out.arena.insert(out.arena.end(),
                         buf->contiguous_data.begin(),
                         buf->contiguous_data.end());

        out.segments.push_back(seg);

        if (buf->has_gaps) out.incomplete_flows++;
    }

    return true;
}

/* -----------------------------------------------------------------------
 * export_verify
 * --------------------------------------------------------------------- */
bool export_verify(const ExportResult& result)
{
    bool ok = true;
    const size_t arena_size = result.arena.size();

    for (size_t i = 0; i < result.segments.size(); ++i) {
        const Segment& seg = result.segments[i];

        /* Check that offset is within the arena */
        if (seg.offset > arena_size) {
            fprintf(stderr,
                    "[export_verify] Segment %zu (flow %u): offset %u "
                    "exceeds arena size %zu\n",
                    i, seg.flow_id, seg.offset, arena_size);
            ok = false;
        }

        /* Check that offset + len doesn't run past the end */
        if (static_cast<size_t>(seg.offset) + seg.len > arena_size) {
            fprintf(stderr,
                    "[export_verify] Segment %zu (flow %u): "
                    "offset %u + len %u = %llu exceeds arena size %zu\n",
                    i, seg.flow_id, seg.offset, seg.len,
                    (unsigned long long)seg.offset + seg.len,
                    arena_size);
            ok = false;
        }

        /* carry must be zero (our component's contract) */
        if (seg.carry != 0) {
            fprintf(stderr,
                    "[export_verify] Segment %zu (flow %u): "
                    "carry is %u, expected 0\n",
                    i, seg.flow_id, seg.carry);
            ok = false;
        }
    }
    return ok;
}

/* -----------------------------------------------------------------------
 * export_print_stats
 * --------------------------------------------------------------------- */
void export_print_stats(const ExportResult& result)
{
    printf("\n=== Export Statistics ===\n");
    printf("  Arena size (bytes)    : %zu\n", result.arena.size());
    printf("  Segments exported     : %zu\n", result.segments.size());
    printf("  Incomplete flows      : %u\n",  result.incomplete_flows);
    if (!result.segments.empty()) {
        uint32_t max_len = 0;
        uint32_t min_len = std::numeric_limits<uint32_t>::max();
        for (const auto& seg : result.segments) {
            if (seg.len > max_len) max_len = seg.len;
            if (seg.len < min_len) min_len = seg.len;
        }
        printf("  Largest flow payload  : %u bytes\n", max_len);
        printf("  Smallest flow payload : %u bytes\n", min_len);
    }
    printf("=========================\n\n");
}
