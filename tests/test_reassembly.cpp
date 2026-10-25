/**
 * test_reassembly.cpp — Unit tests for tcp_reassembly.cpp
 *
 * Tests:
 *   T01 — In-order segments reassemble to the exact bytes.
 *   T02 — Out-of-order segments (3, 1, 2) reassemble correctly.
 *   T03 — Duplicate retransmission does not duplicate bytes.
 *   T04 — A retransmission with different data is discarded (first-wins).
 *   T05 — Missing middle segment creates a gap.
 *   T06 — Sequence-number wraparound handled correctly.
 *   T07 — OOO buffer cap rejects data beyond the limit.
 *   T08 — Partial retransmission (overlapping tail) trimmed correctly.
 */

#include "tcp_reassembly.h"
#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>

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

/* Helper: feed a vector<uint8_t> as a segment */
static void add(ReassemblyBuffer& buf, uint32_t seq,
                const std::vector<uint8_t>& data)
{
    reassembly_add_segment(buf, seq,
                           data.data(),
                           static_cast<uint16_t>(data.size()));
}

/* Helper: compare contiguous_data to expected bytes */
static bool data_equals(const ReassemblyBuffer& buf,
                        const std::vector<uint8_t>& expected)
{
    return buf.contiguous_data == expected;
}

int main()
{
    printf("=== test_reassembly ===\n");

    /* T01 — In-order segments */
    {
        ReassemblyBuffer buf = reassembly_buffer_init(0);
        add(buf, 0, {0x01, 0x02, 0x03});
        add(buf, 3, {0x04, 0x05});
        add(buf, 5, {0x06});
        reassembly_finalize(buf);

        std::vector<uint8_t> expected = {0x01,0x02,0x03,0x04,0x05,0x06};
        CHECK(data_equals(buf, expected), "T01: in-order reassembly correct");
        CHECK(!buf.has_gaps,             "T01b: no gaps");
    }

    /* T02 — Out-of-order: segments arrive as 3rd, 1st, 2nd */
    {
        ReassemblyBuffer buf = reassembly_buffer_init(1);
        /* Seg 1: seq=0, data=AA BB CC */
        /* Seg 2: seq=3, data=DD EE    */
        /* Seg 3: seq=5, data=FF       */
        /* Arrive order: seg3, seg1, seg2 */
        add(buf, 5, {0xFF});           /* arrives first, but seq=5, buffered  */
        add(buf, 0, {0xAA, 0xBB, 0xCC}); /* initialises next_seq=0, drains   */
        add(buf, 3, {0xDD, 0xEE});    /* fills gap → drains 0xFF too         */
        reassembly_finalize(buf);

        std::vector<uint8_t> expected = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
        CHECK(data_equals(buf, expected), "T02: out-of-order reassembly correct");
        CHECK(!buf.has_gaps,             "T02b: no gaps after OOO resolved");
    }

    /* T03 — Duplicate retransmission: same seq, same data */
    {
        ReassemblyBuffer buf = reassembly_buffer_init(2);
        add(buf, 0, {0x01, 0x02, 0x03});
        add(buf, 0, {0x01, 0x02, 0x03}); /* exact duplicate */
        reassembly_finalize(buf);

        std::vector<uint8_t> expected = {0x01, 0x02, 0x03};
        CHECK(data_equals(buf, expected),       "T03a: no duplicate bytes");
        CHECK(buf.retransmit_count >= 1,        "T03b: retransmit counted");
    }

    /* T04 — Retransmission with conflicting data: first-wins */
    {
        ReassemblyBuffer buf = reassembly_buffer_init(3);
        add(buf, 0, {0xAA, 0xBB});     /* accepted first */
        add(buf, 0, {0xFF, 0xFF});     /* retransmission with different data */
        reassembly_finalize(buf);

        /* First-wins: original 0xAA 0xBB must be kept */
        std::vector<uint8_t> expected = {0xAA, 0xBB};
        CHECK(data_equals(buf, expected), "T04: first-wins policy respected");
    }

    /* T05 — Missing middle segment creates a gap */
    {
        ReassemblyBuffer buf = reassembly_buffer_init(4);
        add(buf, 0, {0x01, 0x02});     /* bytes 0-1 */
        /* bytes 2-4 are missing */
        add(buf, 5, {0x06, 0x07});     /* bytes 5-6 — buffered, gap 2-4 */
        reassembly_finalize(buf);

        /* Only bytes 0-1 are contiguous; 5-6 remain in OOO with a gap */
        std::vector<uint8_t> expected = {0x01, 0x02};
        CHECK(data_equals(buf, expected), "T05a: only contiguous bytes present");
        CHECK(buf.has_gaps,               "T05b: gap detected");
        CHECK(!buf.gaps.empty(),          "T05c: gap recorded");
        CHECK(buf.gaps[0].start_seq == 2, "T05d: gap starts at seq 2");
        CHECK(buf.gaps[0].end_seq   == 5, "T05e: gap ends at seq 5");
    }

    /* T06 — Sequence-number wraparound */
    {
        ReassemblyBuffer buf = reassembly_buffer_init(5);
        /* Last two bytes before wrap */
        uint32_t near_wrap = 0xFFFFFFFE;
        add(buf, near_wrap, {0xAA, 0xBB}); /* occupies seq 0xFFFFFFFE and 0xFFFFFFFF */
        /* Wrap: next byte is seq 0x00000000 */
        add(buf, 0x00000000, {0xCC, 0xDD});
        reassembly_finalize(buf);

        std::vector<uint8_t> expected = {0xAA, 0xBB, 0xCC, 0xDD};
        CHECK(data_equals(buf, expected), "T06: wraparound reassembly correct");
        CHECK(!buf.has_gaps,             "T06b: no gap across wraparound");
    }

    /* T07 — OOO buffer cap */
    {
        /* Set up a buffer and manually shrink the cap by adding enough
         * data before the "needed" seq to fill the cap.
         * We use a small indirect test: add a segment far ahead (seq=1e9)
         * and many segments at intermediate positions. */

        /* We can't easily override OOO_BUFFER_LIMIT in a unit test without
         * changing the header, so we test the behaviour with large data.
         * Instead, we verify drop_count increments when the buffer is full. */

        ReassemblyBuffer buf = reassembly_buffer_init(6);
        buf.ooo_bytes = OOO_BUFFER_LIMIT; /* simulate full buffer */

        /* This segment should be dropped because the buffer is "full" */
        add(buf, 1000, {0xDE, 0xAD});
        CHECK(buf.ooo_drop_count >= 1, "T07: OOO drop recorded when buffer full");
    }

    /* T08 — Partial retransmission: segment overlaps accepted data on the left */
    {
        ReassemblyBuffer buf = reassembly_buffer_init(7);
        add(buf, 0, {0x01, 0x02, 0x03, 0x04}); /* seq 0-3 accepted */
        /* Retransmission that starts at seq=2, extends into new territory */
        add(buf, 2, {0xFF, 0xFF, 0x07, 0x08}); /* overlap at 2-3, new at 4-5 */
        reassembly_finalize(buf);

        /* Bytes 0-3 were accepted first.
         * The overlap portion (seq 2-3) is trimmed (first-wins).
         * The new portion (seq 4-5) = 0x07 0x08 is appended. */
        std::vector<uint8_t> expected = {0x01,0x02,0x03,0x04,0x07,0x08};
        CHECK(data_equals(buf, expected), "T08a: partial retransmission trimmed");
        CHECK(buf.retransmit_count >= 1,  "T08b: retransmit counted");
    }

    printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
