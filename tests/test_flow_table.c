/* test_flow_table.c - Hash flow table tests. */
#include <stdlib.h>
#include "test_util.h"
#include "flow_table.h"

static FiveTuple mk(uint32_t s, uint32_t d, uint16_t sp, uint16_t dp)
{
    FiveTuple t; memset(&t, 0, sizeof t);
    t.src_ip = s; t.dst_ip = d; t.src_port = sp; t.dst_port = dp; t.protocol = 6;
    return t;
}

static void f01_hash_deterministic(void)
{
    FiveTuple a = mk(1, 2, 3, 4), b = mk(1, 2, 3, 4), c = mk(1, 2, 3, 5);
    CHECK(fivetuple_hash(&a) == fivetuple_hash(&b));
    CHECK(fivetuple_hash(&a) != fivetuple_hash(&c));
}

static void f02_padding_ignored(void)
{
    FiveTuple a = mk(1, 2, 3, 4), b = mk(1, 2, 3, 4);
    b.pad[0] = 0xAA; b.pad[2] = 0x55;
    CHECK(fivetuple_hash(&a) == fivetuple_hash(&b));
    CHECK(fivetuple_equal(&a, &b));
}

static void f03_same_tuple_same_flow(void)
{
    FlowTable ft; flow_table_init(&ft, 16);
    FiveTuple a = mk(1, 2, 3, 4); int c1, c2;
    uint32_t i1 = flow_table_get_or_insert(&ft, &a, &c1);
    uint32_t i2 = flow_table_get_or_insert(&ft, &a, &c2);
    CHECK(i1 == i2 && c1 == 1 && c2 == 0 && ft.nflows == 1);
    flow_table_free(&ft);
}

static void f04_directional(void)
{
    FlowTable ft; flow_table_init(&ft, 16);
    FiveTuple a = mk(1, 2, 3, 4), r = mk(2, 1, 4, 3);
    CHECK(flow_table_get_or_insert(&ft, &a, NULL) != flow_table_get_or_insert(&ft, &r, NULL));
    CHECK(ft.nflows == 2);
    flow_table_free(&ft);
}

static void f05_lookup_missing(void)
{
    FlowTable ft; flow_table_init(&ft, 16);
    FiveTuple a = mk(1, 2, 3, 4), b = mk(9, 9, 9, 9);
    flow_table_get_or_insert(&ft, &a, NULL);
    CHECK(flow_table_find(&ft, &b) == FLOW_NOT_FOUND);
    CHECK(flow_table_find(&ft, &a) == 0);
    flow_table_free(&ft);
}

static void f06_sequential_ids(void)
{
    FlowTable ft; flow_table_init(&ft, 16);
    int ok = 1;
    for (uint32_t i = 0; i < 100; i++) {
        FiveTuple t = mk(i, 0, 0, 0);
        if (flow_table_get_or_insert(&ft, &t, NULL) != i) ok = 0;
    }
    CHECK(ok);
    flow_table_free(&ft);
}

static void f07_resize_keeps_all(void)
{
    FlowTable ft; flow_table_init(&ft, 16);
    const uint32_t N = 50000;
    for (uint32_t i = 0; i < N; i++) { FiveTuple t = mk(i, i * 31, (uint16_t)i, 80); flow_table_get_or_insert(&ft, &t, NULL); }
    int ok = 1;
    for (uint32_t i = 0; i < N; i++) { FiveTuple t = mk(i, i * 31, (uint16_t)i, 80); if (flow_table_find(&ft, &t) != i) ok = 0; }
    CHECK(ok);
    CHECK(ft.nflows == N);
    flow_table_free(&ft);
}

static void f08_load_factor(void)
{
    FlowTable ft; flow_table_init(&ft, 16);
    int ok = 1;
    for (uint32_t i = 0; i < 10000; i++) {
        FiveTuple t = mk(i, 7, 7, 7); flow_table_get_or_insert(&ft, &t, NULL);
        if (ft.nflows * 10 > ft.slot_cap * 7) ok = 0;
    }
    CHECK(ok);
    flow_table_free(&ft);
}

/* Force identical hashes: full-tuple comparison must keep flows apart. */
static void f09_forced_collision(void)
{
    FlowTable ft; flow_table_init(&ft, 16);
    FiveTuple a = mk(1, 2, 3, 4), b = mk(5, 6, 7, 8);
    uint32_t ia = flow_table_get_or_insert_hashed(&ft, &a, 42, NULL);
    uint32_t ib = flow_table_get_or_insert_hashed(&ft, &b, 42, NULL);
    CHECK(ia != ib);
    CHECK(flow_table_get_or_insert_hashed(&ft, &a, 42, NULL) == ia);
    CHECK(flow_table_get_or_insert_hashed(&ft, &b, 42, NULL) == ib);
    flow_table_free(&ft);
}

/* flow_process_packets: skips non-OK packets and reassembles payload. */
static void f10_process_packets(void)
{
    PacketList pl; memset(&pl, 0, sizeof pl);
    uint8_t f[128];
    size_t l1 = build_tcp_frame(f, 1, 2, 3, 4, 100, TCP_SYN, NULL, 0, 5, 5);
    packet_list_push(&pl, f, (uint32_t)l1, (uint32_t)l1, 0);
    size_t l2 = build_tcp_frame(f, 1, 2, 3, 4, 101, TCP_ACK, (const uint8_t *)"abc", 3, 5, 5);
    packet_list_push(&pl, f, (uint32_t)l2, (uint32_t)l2, 1);
    packet_list_push(&pl, f, 10, 10, 2);                 /* truncated */
    ParsedPacket pp[3];
    parse_all(&pl, pp, 2);
    FlowTable ft; FlowStats st; flow_table_init(&ft, 16);
    CHECK(flow_process_packets(&ft, &pl, pp, &st) == 0);
    CHECK(ft.nflows == 1);
    CHECK(st.tcp_packets == 2 && st.status_count[PARSE_TRUNCATED] == 1);
    CHECK(ft.flows[0].stream.out.len == 3 && memcmp(ft.flows[0].stream.out.data, "abc", 3) == 0);
    flow_table_free(&ft);
    pcap_free_packets(&pl);
}

int main(void)
{
    printf("test_flow_table\n");
    RUN(f01_hash_deterministic);
    RUN(f02_padding_ignored);
    RUN(f03_same_tuple_same_flow);
    RUN(f04_directional);
    RUN(f05_lookup_missing);
    RUN(f06_sequential_ids);
    RUN(f07_resize_keeps_all);
    RUN(f08_load_factor);
    RUN(f09_forced_collision);
    RUN(f10_process_packets);
    return SUMMARY("test_flow_table");
}
