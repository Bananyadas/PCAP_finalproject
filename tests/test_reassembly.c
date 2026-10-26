/* test_reassembly.c - TCP reassembly tests. */
#include <stdlib.h>
#include "test_util.h"
#include "tcp_reassembly.h"
#include "packet_parser.h"

#define ADD(s, seq, str) stream_add(&(s), (seq), TCP_ACK, (const uint8_t *)(str), (uint32_t)strlen(str))
#define OUT_IS(s, str) ((s).out.len == strlen(str) && memcmp((s).out.data, (str), strlen(str)) == 0)

static void r01_in_order(void)
{
    TcpStream s; stream_init(&s);
    ADD(s, 1000, "Hello, "); ADD(s, 1007, "world");
    stream_finish(&s);
    CHECK(OUT_IS(s, "Hello, world"));
    CHECK(s.gaps == 0 && s.dup_bytes == 0);
    stream_free(&s);
}

static void r02_out_of_order(void)
{
    TcpStream s; stream_init(&s);
    stream_add(&s, 999, TCP_SYN, NULL, 0);
    ADD(s, 1006, "CCC"); ADD(s, 1003, "BBB"); ADD(s, 1000, "AAA");
    stream_finish(&s);
    CHECK(OUT_IS(s, "AAABBBCCC"));
    CHECK(s.ooo_packets == 2);
    stream_free(&s);
}

static void r03_duplicate(void)
{
    TcpStream s; stream_init(&s);
    ADD(s, 1, "abcd"); ADD(s, 1, "abcd"); ADD(s, 5, "efgh");
    stream_finish(&s);
    CHECK(OUT_IS(s, "abcdefgh"));
    CHECK(s.retransmits == 1 && s.dup_bytes == 4);
    stream_free(&s);
}

/* Conflicting retransmission: first data wins (both delivered and buffered). */
static void r04_first_wins(void)
{
    TcpStream s; stream_init(&s);
    ADD(s, 1, "AAAA"); ADD(s, 1, "XXXX");
    ADD(s, 9, "CCCC"); ADD(s, 9, "YYYY");    /* buffered, then conflict */
    ADD(s, 5, "BBBB");
    stream_finish(&s);
    CHECK(OUT_IS(s, "AAAABBBBCCCC"));
    stream_free(&s);
}

/* Packets 1,3,4,5 of 5 (packet 2 missing): only packet 1 is output. */
static void r05_gap(void)
{
    TcpStream s; stream_init(&s);
    ADD(s, 0, "11111"); ADD(s, 10, "33333"); ADD(s, 15, "44444"); ADD(s, 20, "55555");
    stream_finish(&s);
    CHECK(OUT_IS(s, "11111"));
    CHECK(s.gaps == 1 && s.stranded_bytes == 15);
    stream_free(&s);
}

static void r06_wraparound(void)
{
    TcpStream s; stream_init(&s);
    stream_add(&s, 0xFFFFFFFDu, TCP_SYN, NULL, 0);      /* data at 0xFFFFFFFE */
    ADD(s, 0x00000002u, "WXYZ");                          /* arrives early */
    ADD(s, 0xFFFFFFFEu, "abcd");                          /* crosses 2^32 */
    stream_finish(&s);
    CHECK(OUT_IS(s, "abcdWXYZ"));
    CHECK(s.gaps == 0);
    CHECK(seq_lt(0xFFFFFFF0u, 5u) && !seq_lt(5u, 0xFFFFFFF0u));
    stream_free(&s);
}

static void r07_ooo_cap(void)
{
    TcpStream s; stream_init(&s);
    s.ooo_cap = 8;
    ADD(s, 0, "a");
    ADD(s, 10, "12345"); ADD(s, 20, "67890");             /* 2nd exceeds cap */
    CHECK(s.ooo_bytes == 5 && s.ooo_dropped_bytes == 5);
    stream_finish(&s);
    CHECK(OUT_IS(s, "a"));
    stream_free(&s);
}

static void r08_partial_overlap(void)
{
    TcpStream s; stream_init(&s);
    ADD(s, 0, "ABCDEF");
    ADD(s, 4, "EFGHIJ");                                  /* 2 bytes old */
    ADD(s, 14, "OPQR");
    ADD(s, 12, "MNOPQRST");                               /* overlaps buffered */
    ADD(s, 10, "KLMN");
    stream_finish(&s);
    CHECK(OUT_IS(s, "ABCDEFGHIJKLMNOPQRST"));
    stream_free(&s);
}

static void r09_syn_fin(void)
{
    TcpStream s; stream_init(&s);
    stream_add(&s, 5000, TCP_SYN, NULL, 0);
    ADD(s, 5001, "data");
    stream_add(&s, 5005, TCP_FIN | TCP_ACK, NULL, 0);
    stream_add(&s, 5000, TCP_SYN, NULL, 0);               /* SYN retransmit */
    stream_finish(&s);
    CHECK(OUT_IS(s, "data"));
    CHECK(s.syn_seen && s.fin_seen);
    stream_free(&s);
}

static void r10_no_syn_midstream(void)
{
    TcpStream s; stream_init(&s);
    ADD(s, 777, "mid"); ADD(s, 780, "stream");
    stream_finish(&s);
    CHECK(OUT_IS(s, "midstream"));
    CHECK(!s.syn_seen);
    stream_free(&s);
}

int main(void)
{
    printf("test_reassembly\n");
    RUN(r01_in_order);
    RUN(r02_out_of_order);
    RUN(r03_duplicate);
    RUN(r04_first_wins);
    RUN(r05_gap);
    RUN(r06_wraparound);
    RUN(r07_ooo_cap);
    RUN(r08_partial_overlap);
    RUN(r09_syn_fin);
    RUN(r10_no_syn_midstream);
    return SUMMARY("test_reassembly");
}
