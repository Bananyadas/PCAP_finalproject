/**
 * test_flow_table.cpp — Unit tests for flow_table.cpp
 *
 * Tests:
 *   T01 — Lookup on an empty table returns nullptr.
 *   T02 — Inserting a tuple once creates a flow with flow_id = 0.
 *   T03 — Looking up the same tuple returns the same entry.
 *   T04 — Two different tuples map to two different flow_ids.
 *   T05 — Inserting the same tuple twice does NOT create a new flow.
 *   T06 — Reversed tuple (B→A vs A→B) creates a different flow (directional).
 *   T07 — Byte and packet counters update correctly.
 *   T08 — Table resizes correctly when load factor exceeds 0.70.
 *   T09 — flow_table_to_flow_recs() returns one FlowRec per unique flow.
 *   T10 — FlowRec.key matches the FNV-1a hash of the tuple.
 */

#include "flow_table.h"
#include <cstdio>
#include <cassert>
#include <cstring>

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

/* Helper: build a FiveTuple quickly */
static FiveTuple make_tuple(uint32_t sip, uint32_t dip,
                            uint16_t sp, uint16_t dp, uint8_t proto = 6)
{
    FiveTuple t{};
    t.src_ip   = sip; t.dst_ip   = dip;
    t.src_port = sp;  t.dst_port = dp;
    t.proto    = proto;
    return t;
}

int main()
{
    printf("=== test_flow_table ===\n");

    /* T01 — Lookup on empty table */
    {
        FlowTable ft = flow_table_init(16);
        FiveTuple t  = make_tuple(1, 2, 100, 200);
        CHECK(flow_table_lookup(ft, t) == nullptr,
              "T01: lookup empty table → nullptr");
    }

    /* T02 — First insert creates flow_id 0 */
    {
        FlowTable ft  = flow_table_init(16);
        FiveTuple t   = make_tuple(10, 20, 1000, 2000);
        FlowEntry* e  = flow_table_insert(ft, t, 100);
        CHECK(e != nullptr,       "T02a: insert returns non-null");
        CHECK(e->flow_id == 0,    "T02b: first flow_id is 0");
        CHECK(ft.count   == 1,    "T02c: table count is 1");
    }

    /* T03 — Lookup after insert returns the same entry */
    {
        FlowTable  ft = flow_table_init(16);
        FiveTuple  t  = make_tuple(1, 2, 10, 20);
        FlowEntry* e1 = flow_table_insert(ft, t, 50);
        FlowEntry* e2 = flow_table_lookup(ft, t);
        CHECK(e2 != nullptr,           "T03a: lookup finds entry");
        CHECK(e1->flow_id == e2->flow_id, "T03b: same flow_id");
    }

    /* T04 — Two different tuples → two different flows */
    {
        FlowTable  ft = flow_table_init(16);
        FiveTuple  t1 = make_tuple(1, 2, 10, 20);
        FiveTuple  t2 = make_tuple(3, 4, 30, 40);
        FlowEntry* e1 = flow_table_insert(ft, t1, 100);
        FlowEntry* e2 = flow_table_insert(ft, t2, 200);
        CHECK(ft.count == 2,               "T04a: two flows in table");
        CHECK(e1->flow_id != e2->flow_id,  "T04b: different flow_ids");
    }

    /* T05 — Inserting same tuple twice does NOT duplicate */
    {
        FlowTable  ft = flow_table_init(16);
        FiveTuple  t  = make_tuple(5, 6, 50, 60);
        flow_table_insert(ft, t, 100);
        flow_table_insert(ft, t, 200);
        CHECK(ft.count == 1, "T05a: no duplicate entry");
        FlowEntry* e = flow_table_lookup(ft, t);
        CHECK(e != nullptr,          "T05b: entry exists");
        CHECK(e->pkt_count  == 2,    "T05c: packet count = 2");
        CHECK(e->byte_count == 300,  "T05d: byte count = 300");
    }

    /* T06 — Directional: reversed tuple is a different flow */
    {
        FlowTable  ft = flow_table_init(16);
        FiveTuple  t_ab = make_tuple(1, 2, 100, 200);
        FiveTuple  t_ba = make_tuple(2, 1, 200, 100); /* reversed */
        FlowEntry* e_ab = flow_table_insert(ft, t_ab, 50);
        FlowEntry* e_ba = flow_table_insert(ft, t_ba, 50);
        CHECK(ft.count == 2,                  "T06a: two directional flows");
        CHECK(e_ab->flow_id != e_ba->flow_id, "T06b: different flow_ids");
    }

    /* T07 — Byte and packet counter update */
    {
        FlowTable ft = flow_table_init(16);
        FiveTuple t  = make_tuple(7, 8, 70, 80);
        flow_table_insert(ft, t, 1000);
        flow_table_insert(ft, t, 500);
        flow_table_insert(ft, t, 250);
        FlowEntry* e = flow_table_lookup(ft, t);
        CHECK(e->pkt_count  == 3,    "T07a: three packets counted");
        CHECK(e->byte_count == 1750, "T07b: byte total correct");
    }

    /* T08 — Resize: insert enough entries to trigger resize */
    {
        FlowTable ft = flow_table_init(8); /* tiny initial size */
        /* Insert 10 unique flows — this should trigger at least one resize */
        for (int i = 0; i < 10; ++i) {
            FiveTuple t = make_tuple(
                static_cast<uint32_t>(i),
                static_cast<uint32_t>(i + 100),
                static_cast<uint16_t>(i * 10 + 1),
                static_cast<uint16_t>(i * 10 + 2)
            );
            flow_table_insert(ft, t, 64);
        }
        CHECK(ft.count == 10, "T08a: all 10 flows survive resize");

        /* Verify every entry can still be found */
        int found = 0;
        for (int i = 0; i < 10; ++i) {
            FiveTuple t = make_tuple(
                static_cast<uint32_t>(i),
                static_cast<uint32_t>(i + 100),
                static_cast<uint16_t>(i * 10 + 1),
                static_cast<uint16_t>(i * 10 + 2)
            );
            if (flow_table_lookup(ft, t) != nullptr) found++;
        }
        CHECK(found == 10, "T08b: all 10 flows found after resize");
    }

    /* T09 — flow_table_to_flow_recs returns one entry per flow */
    {
        FlowTable ft = flow_table_init(16);
        for (int i = 0; i < 5; ++i) {
            FiveTuple t = make_tuple(
                static_cast<uint32_t>(i), static_cast<uint32_t>(i + 50),
                static_cast<uint16_t>(i + 1000), static_cast<uint16_t>(i + 2000)
            );
            flow_table_insert(ft, t, 100);
        }
        auto recs = flow_table_to_flow_recs(ft);
        CHECK(recs.size() == 5, "T09: five FlowRec entries");
        /* cost_est must be 0 */
        bool all_zero = true;
        for (const auto& r : recs) if (r.cost_est != 0.0f) all_zero = false;
        CHECK(all_zero, "T09b: all cost_est initialised to 0");
    }

    /* T10 — FlowRec.key matches tuple_hash() */
    {
        FlowTable  ft = flow_table_init(16);
        FiveTuple  t  = make_tuple(0xDEADBEEF, 0xCAFEBABE, 12345, 80);
        flow_table_insert(ft, t, 1);

        auto recs = flow_table_to_flow_recs(ft);
        uint64_t expected_hash = tuple_hash(t);
        CHECK(!recs.empty() && recs[0].key == expected_hash,
              "T10: FlowRec.key matches tuple_hash()");
    }

    printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
