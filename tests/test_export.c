/* test_export.c - Export format tests + 1-vs-N thread determinism. */
#include <stdlib.h>
#include "test_util.h"
#include "flow_export.h"

/* Build a table with 3 flows: "abc", "" (SYN only), "defgh". */
static void build_small(FlowTable *ft)
{
    flow_table_init(ft, 16);
    FiveTuple a = {1, 2, 3, 4, 6, {0}}, b = {5, 6, 7, 8, 6, {0}}, c = {9, 9, 9, 9, 6, {0}};
    uint32_t ia = flow_table_get_or_insert(ft, &a, NULL);
    uint32_t ib = flow_table_get_or_insert(ft, &b, NULL);
    uint32_t ic = flow_table_get_or_insert(ft, &c, NULL);
    stream_add(&ft->flows[ia].stream, 0, TCP_ACK, (const uint8_t *)"abc", 3);
    stream_add(&ft->flows[ib].stream, 0, TCP_SYN, NULL, 0);
    stream_add(&ft->flows[ic].stream, 0, TCP_ACK, (const uint8_t *)"defgh", 5);
    for (size_t i = 0; i < ft->nflows; i++) stream_finish(&ft->flows[i].stream);
}

static void e01_struct_sizes(void)
{
    CHECK(sizeof(Segment) == 16 && sizeof(Match) == 12 && sizeof(FlowRec) == 24);
}

static void e02_empty_table(void)
{
    FlowTable ft; flow_table_init(&ft, 16); ExportData ex; char err[256];
    CHECK(export_build(&ft, &ex, err, sizeof err) == 0);
    CHECK(ex.nsegs == 0 && ex.arena_len == 0);
    CHECK(export_verify(&ex, &ft, err, sizeof err) == 0);
    export_free(&ex); flow_table_free(&ft);
}

static void e03_layout(void)
{
    FlowTable ft; build_small(&ft); ExportData ex; char err[256];
    CHECK(export_build(&ft, &ex, err, sizeof err) == 0);
    CHECK(ex.nsegs == 3 && ex.arena_len == 8);
    CHECK(ex.segs[0].offset == 0 && ex.segs[0].len == 3);
    CHECK(ex.segs[1].offset == 3 && ex.segs[1].len == 0);   /* empty flow kept */
    CHECK(ex.segs[2].offset == 3 && ex.segs[2].len == 5);
    CHECK(memcmp(ex.arena, "abcdefgh", 8) == 0);
    export_free(&ex); flow_table_free(&ft);
}

static void e04_sorted_carry_zero(void)
{
    FlowTable ft; build_small(&ft); ExportData ex; char err[256];
    export_build(&ft, &ex, err, sizeof err);
    int ok = 1;
    for (size_t i = 0; i < ex.nsegs; i++)
        if (ex.segs[i].flow_id != i || ex.segs[i].carry != 0) ok = 0;
    CHECK(ok);
    export_free(&ex); flow_table_free(&ft);
}

static void e05_flowrec(void)
{
    FlowTable ft; build_small(&ft); ExportData ex; char err[256];
    export_build(&ft, &ex, err, sizeof err);
    CHECK(ex.recs[0].key == fivetuple_hash(&ft.flows[0].tuple));
    CHECK(ex.recs[2].bytes == 5 && ex.recs[1].bytes == 0);
    CHECK(ex.recs[0].cost_est == 0.0f);
    export_free(&ex); flow_table_free(&ft);
}

static void e06_verify_ok(void)
{
    FlowTable ft; build_small(&ft); ExportData ex; char err[256];
    export_build(&ft, &ex, err, sizeof err);
    CHECK(export_verify(&ex, &ft, err, sizeof err) == 0);
    export_free(&ex); flow_table_free(&ft);
}

static void e07_verify_detects_corruption(void)
{
    FlowTable ft; build_small(&ft); ExportData ex; char err[256];
    export_build(&ft, &ex, err, sizeof err);
    ex.arena[1] ^= 0xFF;
    CHECK(export_verify(&ex, &ft, err, sizeof err) == -1);
    ex.arena[1] ^= 0xFF;
    ex.segs[2].offset = 4;
    CHECK(export_verify(&ex, &ft, err, sizeof err) == -1);
    export_free(&ex); flow_table_free(&ft);
}

/* Full pipeline on a synthetic, shuffled multi-flow capture:
 * the export checksum must be identical for 1, 2, 4 and 8 threads. */
static uint64_t run_pipeline(const PacketList *pl, int threads, size_t *nflows)
{
    ParsedPacket *pp = malloc(pl->count * sizeof *pp);
    parse_all(pl, pp, threads);
    FlowTable ft; flow_table_init(&ft, 16);
    flow_process_packets(&ft, pl, pp, NULL);
    ExportData ex; char err[256];
    export_build(&ft, &ex, err, sizeof err);
    uint64_t h = export_checksum(&ex);
    *nflows = ft.nflows;
    export_free(&ex); flow_table_free(&ft); free(pp);
    return h;
}

static void e08_thread_determinism(void)
{
    PacketList pl; memset(&pl, 0, sizeof pl);
    uint8_t f[256], pay[100];
    srand(12345);
    for (uint32_t flow = 0; flow < 200; flow++) {
        uint32_t isn = (uint32_t)rand();
        size_t l = build_tcp_frame(f, IP4(10,0,0,1), IP4(10,1,0,0) + flow, (uint16_t)(1000 + flow), 80,
                                   isn, TCP_SYN, NULL, 0, 5, 5);
        packet_list_push(&pl, f, (uint32_t)l, (uint32_t)l, 0);
        uint32_t seq = isn + 1;
        for (int k = 0; k < 20; k++) {
            uint32_t n = 1 + (uint32_t)(rand() % 100);
            for (uint32_t j = 0; j < n; j++) pay[j] = (uint8_t)rand();
            l = build_tcp_frame(f, IP4(10,0,0,1), IP4(10,1,0,0) + flow, (uint16_t)(1000 + flow), 80,
                                seq, TCP_ACK | TCP_PSH, pay, n, 5, 5);
            packet_list_push(&pl, f, (uint32_t)l, (uint32_t)l, 0);
            seq += n;
        }
    }
    /* Shuffle to create out-of-order delivery across flows and within flows. */
    for (size_t i = pl.count - 1; i > 0; i--) {
        size_t j = (size_t)rand() % (i + 1);
        RawPacket t = pl.pkts[i]; pl.pkts[i] = pl.pkts[j]; pl.pkts[j] = t;
    }
    size_t n1, n2, n4, n8;
    uint64_t h1 = run_pipeline(&pl, 1, &n1);
    uint64_t h2 = run_pipeline(&pl, 2, &n2);
    uint64_t h4 = run_pipeline(&pl, 4, &n4);
    uint64_t h8 = run_pipeline(&pl, 8, &n8);
    CHECK(n1 == 200);
    CHECK(h1 == h2 && h1 == h4 && h1 == h8);
    pcap_free_packets(&pl);
}

int main(void)
{
    printf("test_export\n");
    RUN(e01_struct_sizes);
    RUN(e02_empty_table);
    RUN(e03_layout);
    RUN(e04_sorted_carry_zero);
    RUN(e05_flowrec);
    RUN(e06_verify_ok);
    RUN(e07_verify_detects_corruption);
    RUN(e08_thread_determinism);
    return SUMMARY("test_export");
}
