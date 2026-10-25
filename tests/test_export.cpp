/**
 * test_export.cpp — Unit tests for flow_export.cpp
 *
 * Tests:
 *   T01 — Empty buffer list produces empty arena and segment array.
 *   T02 — Single flow: Segment offset=0, len=payload_size, carry=0.
 *   T03 — Two flows: offsets are contiguous, lengths are correct.
 *   T04 — Segment bytes in arena match the expected payload bytes.
 *   T05 — Flow with no contiguous data gets Segment with len=0.
 *   T06 — export_verify() passes on valid output.
 *   T07 — Incomplete flow (has_gaps=true) increments incomplete_flows.
 *   T08 — Segments are ordered by flow_id (ascending).
 */

#include "flow_export.h"
#include "tcp_reassembly.h"
#include "shared.h"
#include <cstdio>
#include <cassert>
#include <cstring>
#include <vector>
#include <numeric>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                           \
    do {                                                           \
        if (cond) {                                                \
            printf("  PASS: %s\n", msg); g_pass++;                \
        } else {                                                   \
            printf("  FAIL: %s  (line %d)\n", msg, __LINE__);     \
            g_fail++;                                              \
        }                                                          \
    } while (0)

/* Helper: make a ReassemblyBuffer with known payload */
static ReassemblyBuffer make_buf(uint32_t flow_id,
                                 const std::vector<uint8_t>& data,
                                 bool has_gaps = false)
{
    ReassemblyBuffer buf = reassembly_buffer_init(flow_id);
    buf.contiguous_data  = data;
    buf.has_gaps         = has_gaps;
    buf.initialized      = true;
    return buf;
}

int main()
{
    printf("=== test_export ===\n");

    /* T01 — Empty input */
    {
        std::vector<ReassemblyBuffer> buffers;
        ExportResult result;
        bool ok = export_flows(buffers, result);
        CHECK(ok,                       "T01a: export_flows returns true");
        CHECK(result.arena.empty(),     "T01b: arena is empty");
        CHECK(result.segments.empty(),  "T01c: no segments");
        CHECK(export_verify(result),    "T01d: verify passes");
    }

    /* T02 — Single flow */
    {
        std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05};
        std::vector<ReassemblyBuffer> buffers = {make_buf(0, payload)};

        ExportResult result;
        bool ok = export_flows(buffers, result);
        CHECK(ok,                              "T02a: export ok");
        CHECK(result.segments.size() == 1,     "T02b: one segment");
        CHECK(result.segments[0].flow_id == 0, "T02c: flow_id = 0");
        CHECK(result.segments[0].offset  == 0, "T02d: offset = 0");
        CHECK(result.segments[0].len     == 5, "T02e: len = 5");
        CHECK(result.segments[0].carry   == 0, "T02f: carry = 0");
        CHECK(result.arena.size()        == 5, "T02g: arena size = 5");
        CHECK(export_verify(result),           "T02h: verify passes");
    }

    /* T03 — Two flows: check contiguous offsets */
    {
        std::vector<uint8_t> p1 = {0xAA, 0xBB, 0xCC};           /* len 3 */
        std::vector<uint8_t> p2 = {0x11, 0x22, 0x33, 0x44};     /* len 4 */
        std::vector<ReassemblyBuffer> buffers = {
            make_buf(0, p1),
            make_buf(1, p2)
        };

        ExportResult result;
        bool ok = export_flows(buffers, result);
        CHECK(ok,                              "T03a: export ok");
        CHECK(result.segments.size() == 2,     "T03b: two segments");
        CHECK(result.segments[0].offset == 0,  "T03c: flow 0 offset = 0");
        CHECK(result.segments[0].len    == 3,  "T03d: flow 0 len = 3");
        CHECK(result.segments[1].offset == 3,  "T03e: flow 1 offset = 3");
        CHECK(result.segments[1].len    == 4,  "T03f: flow 1 len = 4");
        CHECK(result.arena.size()       == 7,  "T03g: arena total = 7 bytes");
        CHECK(export_verify(result),           "T03h: verify passes");
    }

    /* T04 — Bytes in the arena match expected payload */
    {
        std::vector<uint8_t> payload(256);
        std::iota(payload.begin(), payload.end(), 0); /* 0x00..0xFF */
        std::vector<ReassemblyBuffer> buffers = {make_buf(0, payload)};

        ExportResult result;
        export_flows(buffers, result);
        const Segment& seg = result.segments[0];

        bool bytes_match = true;
        for (uint32_t i = 0; i < seg.len; ++i) {
            if (result.arena[seg.offset + i] != static_cast<uint8_t>(i)) {
                bytes_match = false;
                break;
            }
        }
        CHECK(bytes_match, "T04: arena bytes match expected payload");
    }

    /* T05 — Flow with empty contiguous data */
    {
        std::vector<ReassemblyBuffer> buffers = {
            make_buf(0, {})   /* no bytes */
        };
        ExportResult result;
        bool ok = export_flows(buffers, result);
        CHECK(ok,                              "T05a: export ok");
        CHECK(result.segments.size() == 1,     "T05b: segment still present");
        CHECK(result.segments[0].len == 0,     "T05c: len = 0 for empty flow");
        CHECK(result.arena.empty(),            "T05d: arena is empty");
        CHECK(export_verify(result),           "T05e: verify passes");
    }

    /* T06 — export_verify catches bad offset */
    {
        ExportResult result;
        result.arena.resize(10, 0xAB);
        Segment bad;
        bad.flow_id = 0;
        bad.offset  = 20; /* way out of bounds */
        bad.len     = 5;
        bad.carry   = 0;
        result.segments.push_back(bad);
        CHECK(!export_verify(result), "T06: verify fails on bad offset");
    }

    /* T07 — Incomplete flow increments counter */
    {
        std::vector<ReassemblyBuffer> buffers = {
            make_buf(0, {0x01, 0x02}, false),  /* complete   */
            make_buf(1, {0x03, 0x04}, true),   /* incomplete */
            make_buf(2, {0x05, 0x06}, true),   /* incomplete */
        };
        ExportResult result;
        export_flows(buffers, result);
        CHECK(result.incomplete_flows == 2, "T07: two incomplete flows counted");
    }

    /* T08 — Segments are ordered by flow_id even if buffers given out of order */
    {
        /* Insert buffers in reverse order */
        std::vector<ReassemblyBuffer> buffers = {
            make_buf(2, {0xCC}),
            make_buf(0, {0xAA}),
            make_buf(1, {0xBB}),
        };
        ExportResult result;
        export_flows(buffers, result);
        CHECK(result.segments.size() == 3,        "T08a: three segments");
        CHECK(result.segments[0].flow_id == 0,    "T08b: sorted: flow 0 first");
        CHECK(result.segments[1].flow_id == 1,    "T08c: sorted: flow 1 second");
        CHECK(result.segments[2].flow_id == 2,    "T08d: sorted: flow 2 third");
        /* Arena order follows flow_id sort order */
        CHECK(result.arena[0] == 0xAA, "T08e: flow 0 byte correct in arena");
        CHECK(result.arena[1] == 0xBB, "T08f: flow 1 byte correct in arena");
        CHECK(result.arena[2] == 0xCC, "T08g: flow 2 byte correct in arena");
    }

    printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
