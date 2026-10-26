/* test_parser.c - PCAP loading and header parsing tests (T01-T11). */
#include <stdlib.h>
#include "test_util.h"
#include "packet_parser.h"

static const uint8_t PAY[] = "HELLO";

/* T01: open a valid PCAP, read all packets. */
static void t01_open_pcap(void)
{
    uint8_t f[128];
    size_t len = build_tcp_frame(f, IP4(10,0,0,1), IP4(10,0,0,2), 1234, 80, 1, TCP_ACK, PAY, 5, 5, 5);
    const uint8_t *fr[2] = { f, f };
    size_t ln[2] = { len, len };
    CHECK(write_pcap("t01.pcap", 1, fr, ln, 2) == 0);
    PacketList pl; char err[256];
    CHECK(pcap_load_file("t01.pcap", &pl, err, sizeof err) == 0);
    CHECK(pl.count == 2);
    CHECK(pl.count == 2 && pl.pkts[0].caplen == len && memcmp(pl.pkts[0].data, f, len) == 0);
    pcap_free_packets(&pl);
    remove("t01.pcap");
}

/* T02: normal frame -> correct 5-tuple, seq, flags, payload. */
static void t02_normal_frame(void)
{
    uint8_t f[128]; ParsedPacket p;
    size_t len = build_tcp_frame(f, IP4(192,168,1,10), IP4(8,8,8,8), 40000, 443, 0xDEADBEEF,
                                 TCP_ACK | TCP_PSH, PAY, 5, 5, 5);
    CHECK(parse_packet(f, (uint32_t)len, &p) == PARSE_OK);
    CHECK(p.tuple.src_ip == IP4(192,168,1,10));
    CHECK(p.tuple.dst_ip == IP4(8,8,8,8));
    CHECK(p.tuple.src_port == 40000 && p.tuple.dst_port == 443);
    CHECK(p.tuple.protocol == 6);
    CHECK(p.seq == 0xDEADBEEF);
    CHECK(p.tcp_flags == (TCP_ACK | TCP_PSH));
    CHECK(p.payload_len == 5 && memcmp(f + p.payload_off, "HELLO", 5) == 0);
}

/* T03: truncated at every possible length -> never OK, never crashes. */
static void t03_truncated(void)
{
    uint8_t f[128]; ParsedPacket p;
    size_t len = build_tcp_frame(f, 1, 2, 3, 4, 5, TCP_ACK, PAY, 5, 5, 5);
    int all_trunc = 1;
    for (uint32_t cut = 0; cut < len; cut++)
        if (parse_packet(f, cut, &p) != PARSE_TRUNCATED) all_trunc = 0;
    CHECK(all_trunc);
}

/* T04: ARP frame -> NOT_IPV4. */
static void t04_arp(void)
{
    uint8_t f[60] = {0}; ParsedPacket p;
    f[12] = 0x08; f[13] = 0x06;
    CHECK(parse_packet(f, sizeof f, &p) == PARSE_NOT_IPV4);
}

/* T05: UDP -> NOT_TCP. */
static void t05_udp(void)
{
    uint8_t f[128]; ParsedPacket p;
    size_t len = build_tcp_frame(f, 1, 2, 3, 4, 5, 0, PAY, 5, 5, 5);
    f[14 + 9] = 17;
    CHECK(parse_packet(f, (uint32_t)len, &p) == PARSE_NOT_TCP);
}

/* T06: pure ACK, no payload; Ethernet padding must be ignored. */
static void t06_no_payload(void)
{
    uint8_t f[128]; ParsedPacket p;
    build_tcp_frame(f, 1, 2, 3, 4, 5, TCP_ACK, NULL, 0, 5, 5);
    CHECK(parse_packet(f, 60 /* padded min frame */, &p) == PARSE_OK);
    CHECK(p.payload_len == 0);
}

/* T07: IPv4 options (IHL = 6). */
static void t07_ip_options(void)
{
    uint8_t f[128]; ParsedPacket p;
    size_t len = build_tcp_frame(f, 1, 2, 3, 4, 5, TCP_ACK, PAY, 5, 6, 5);
    CHECK(parse_packet(f, (uint32_t)len, &p) == PARSE_OK);
    CHECK(p.payload_off == 14 + 24 + 20);
    CHECK(p.payload_len == 5 && memcmp(f + p.payload_off, "HELLO", 5) == 0);
}

/* T08: TCP options (data offset = 8). */
static void t08_tcp_options(void)
{
    uint8_t f[128]; ParsedPacket p;
    size_t len = build_tcp_frame(f, 1, 2, 3, 4, 5, TCP_ACK, PAY, 5, 5, 8);
    CHECK(parse_packet(f, (uint32_t)len, &p) == PARSE_OK);
    CHECK(p.payload_off == 14 + 20 + 32);
    CHECK(p.payload_len == 5);
}

/* T09: invalid IHL / data offset -> BAD_HEADER. */
static void t09_bad_header(void)
{
    uint8_t f[128]; ParsedPacket p;
    size_t len = build_tcp_frame(f, 1, 2, 3, 4, 5, TCP_ACK, PAY, 5, 5, 5);
    f[14] = 0x44;                                   /* IHL = 4 */
    CHECK(parse_packet(f, (uint32_t)len, &p) == PARSE_BAD_HEADER);
    build_tcp_frame(f, 1, 2, 3, 4, 5, TCP_ACK, PAY, 5, 5, 5);
    f[14 + 20 + 12] = 0x30;                         /* doff = 3 */
    CHECK(parse_packet(f, (uint32_t)len, &p) == PARSE_BAD_HEADER);
}

/* T10: non-Ethernet link type and missing file are rejected cleanly. */
static void t10_reject_files(void)
{
    uint8_t f[64] = {0};
    const uint8_t *fr[1] = { f }; size_t ln[1] = { 40 };
    write_pcap("t10.pcap", 101 /* LINKTYPE_RAW */, fr, ln, 1);
    PacketList pl; char err[256];
    CHECK(pcap_load_file("t10.pcap", &pl, err, sizeof err) == -1);
    CHECK(pcap_load_file("does_not_exist.pcap", &pl, err, sizeof err) == -1);
    remove("t10.pcap");
}

/* T11: IP fragment and VLAN-tagged frame. */
static void t11_fragment_vlan(void)
{
    uint8_t f[128], v[132]; ParsedPacket p;
    size_t len = build_tcp_frame(f, 1, 2, 3, 4, 5, TCP_ACK, PAY, 5, 5, 5);
    /* VLAN: insert 4-byte tag after MACs */
    memcpy(v, f, 12); v[12] = 0x81; v[13] = 0x00; v[14] = 0; v[15] = 1;
    memcpy(v + 16, f + 12, len - 12);
    CHECK(parse_packet(v, (uint32_t)len + 4, &p) == PARSE_OK && p.payload_len == 5);
    f[14 + 6] = 0x20;                               /* More Fragments */
    CHECK(parse_packet(f, (uint32_t)len, &p) == PARSE_FRAGMENT);
}

/* T12: parallel parse equals sequential parse. */
static void t12_parallel_parse(void)
{
    PacketList pl; memset(&pl, 0, sizeof pl);
    uint8_t f[128];
    for (uint32_t i = 0; i < 5000; i++) {
        size_t len = build_tcp_frame(f, i, i + 1, (uint16_t)i, 80, i * 7, TCP_ACK, PAY, i % 6, 5, 5);
        packet_list_push(&pl, f, (uint32_t)(i % 13 == 0 ? 20 : len), (uint32_t)len, i);
    }
    ParsedPacket *a = malloc(pl.count * sizeof *a), *b = malloc(pl.count * sizeof *b);
    parse_all(&pl, a, 1);
    parse_all(&pl, b, 4);
    CHECK(memcmp(a, b, pl.count * sizeof *a) == 0);
    free(a); free(b);
    pcap_free_packets(&pl);
}

int main(void)
{
    printf("test_parser\n");
    RUN(t01_open_pcap);
    RUN(t02_normal_frame);
    RUN(t03_truncated);
    RUN(t04_arp);
    RUN(t05_udp);
    RUN(t06_no_payload);
    RUN(t07_ip_options);
    RUN(t08_tcp_options);
    RUN(t09_bad_header);
    RUN(t10_reject_files);
    RUN(t11_fragment_vlan);
    RUN(t12_parallel_parse);
    return SUMMARY("test_parser");
}
