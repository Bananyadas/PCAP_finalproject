/**
 * test_parser.cpp — Unit tests for packet_parser.cpp
 *
 * Tests:
 *   T01 — pcap_load() opens the bundled NetMetria PCAP successfully.
 *   T02 — A hand-crafted Ethernet/IPv4/TCP frame is parsed correctly.
 *   T03 — A truncated frame is flagged SKIP_TRUNCATED.
 *   T04 — A non-IPv4 EtherType frame is flagged SKIP_NOT_IPV4.
 *   T05 — A non-TCP IP packet (UDP) is flagged SKIP_NOT_TCP.
 *   T06 — A TCP ACK-only (no payload) is flagged SKIP_NO_PAYLOAD.
 *   T07 — IPv4 header with options (IHL=6) is parsed without crashing.
 *   T08 — TCP header with options (data offset=8, i.e. 32 bytes) parsed OK.
 */

#include "packet_parser.h"
#include <cstdio>
#include <cstring>
#include <cassert>
#include <cstdlib>
#include <netinet/in.h>  /* htons, htonl */

/* -----------------------------------------------------------------------
 * Tiny test harness
 * --------------------------------------------------------------------- */
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

/* -----------------------------------------------------------------------
 * Build a minimal Ethernet/IPv4/TCP frame in a byte vector.
 *
 * src_ip, dst_ip  — in HOST byte order
 * ip_protocol     — 6 = TCP, 17 = UDP
 * tcp_payload_sz  — bytes of dummy payload to append
 * ip_ihl_words    — IP header length in 32-bit words (5 = standard, 6 = with options)
 * tcp_doff_words  — TCP data offset in 32-bit words (5 = standard, 8 = with options)
 * --------------------------------------------------------------------- */
static RawPacket make_frame(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t  ip_protocol,
    uint16_t tcp_payload_sz,
    uint8_t  ip_ihl_words = 5,
    uint8_t  tcp_doff_words = 5)
{
    /* Header sizes */
    uint16_t ip_hdr_sz  = ip_ihl_words  * 4;
    uint16_t tcp_hdr_sz = tcp_doff_words * 4;
    uint16_t ip_payload = tcp_hdr_sz + tcp_payload_sz;
    uint16_t ip_total   = ip_hdr_sz  + ip_payload;

    std::vector<uint8_t> frame;
    frame.reserve(14 + ip_total);

    /* --- Ethernet header (14 bytes) --- */
    uint8_t eth[14] = {};
    eth[12] = 0x08; eth[13] = 0x00; /* EtherType = IPv4 */
    frame.insert(frame.end(), eth, eth + 14);

    /* --- IPv4 header --- */
    uint8_t ip[60] = {};
    ip[0] = static_cast<uint8_t>((4 << 4) | (ip_ihl_words & 0x0F));
    uint16_t tlen_n = htons(ip_total);
    memcpy(&ip[2], &tlen_n, 2);
    ip[8]  = 64; /* TTL */
    ip[9]  = ip_protocol;
    uint32_t sip_n = htonl(src_ip), dip_n = htonl(dst_ip);
    memcpy(&ip[12], &sip_n, 4);
    memcpy(&ip[16], &dip_n, 4);
    frame.insert(frame.end(), ip, ip + ip_hdr_sz);

    /* --- TCP header --- */
    uint8_t tcp[60] = {};
    uint16_t sp_n = htons(src_port), dp_n = htons(dst_port);
    memcpy(&tcp[0], &sp_n, 2);
    memcpy(&tcp[2], &dp_n, 2);
    uint32_t seq_n = htonl(1000);
    memcpy(&tcp[4], &seq_n, 4);
    tcp[12] = static_cast<uint8_t>((tcp_doff_words & 0x0F) << 4);
    tcp[13] = 0x18; /* PSH + ACK */
    frame.insert(frame.end(), tcp, tcp + tcp_hdr_sz);

    /* --- TCP payload --- */
    for (uint16_t i = 0; i < tcp_payload_sz; ++i)
        frame.push_back(static_cast<uint8_t>(i & 0xFF));

    RawPacket pkt;
    pkt.data    = frame;
    pkt.caplen  = static_cast<uint32_t>(frame.size());
    pkt.wirelen = pkt.caplen;
    pkt.ts_sec  = 0;
    pkt.ts_usec = 0;
    return pkt;
}

/* -----------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------- */
int main()
{
    printf("=== test_parser ===\n");

    /* T01 — Open the bundled PCAP */
    {
        std::vector<RawPacket> pkts;
        bool ok = pcap_load("data/netmetria-focused-scenario.pcap", pkts);
        CHECK(ok,           "T01a: pcap_load returns true");
        CHECK(!pkts.empty(),"T01b: at least one packet loaded");
    }

    /* T02 — Normal TCP frame parsed correctly */
    {
        RawPacket raw = make_frame(
            0xC0A80101, 0xC0A80102,  /* 192.168.1.1 → 192.168.1.2 */
            12345, 80,
            6,   /* TCP */
            100  /* 100 bytes payload */
        );
        ParsedPacket pp = parse_packet(raw, 0);
        CHECK(pp.valid,                "T02a: valid flag set");
        CHECK(pp.tuple.src_ip == 0xC0A80101, "T02b: src_ip correct");
        CHECK(pp.tuple.dst_ip == 0xC0A80102, "T02c: dst_ip correct");
        CHECK(pp.tuple.src_port == 12345,    "T02d: src_port correct");
        CHECK(pp.tuple.dst_port == 80,       "T02e: dst_port correct");
        CHECK(pp.tuple.proto == 6,           "T02f: proto = TCP");
        CHECK(pp.seq == 1000,                "T02g: seq number correct");
        CHECK(pp.tcp_payload_len == 100,     "T02h: payload_len correct");
        CHECK(pp.skip_reason == ParsedPacket::SKIP_NONE, "T02i: no skip");
    }

    /* T03 — Truncated frame */
    {
        RawPacket raw;
        raw.data = {0x00, 0x01, 0x02}; /* far too short */
        raw.caplen = 3; raw.wirelen = 3;
        ParsedPacket pp = parse_packet(raw, 0);
        CHECK(!pp.valid, "T03a: truncated → not valid");
        CHECK(pp.skip_reason == ParsedPacket::SKIP_TRUNCATED,
              "T03b: skip = TRUNCATED");
    }

    /* T04 — Non-IPv4 EtherType (ARP = 0x0806) */
    {
        RawPacket raw;
        raw.data.resize(64, 0);
        raw.data[12] = 0x08; raw.data[13] = 0x06; /* ARP */
        raw.caplen = 64; raw.wirelen = 64;
        ParsedPacket pp = parse_packet(raw, 0);
        CHECK(!pp.valid, "T04a: ARP → not valid");
        CHECK(pp.skip_reason == ParsedPacket::SKIP_NOT_IPV4,
              "T04b: skip = NOT_IPV4");
    }

    /* T05 — UDP packet (protocol = 17) */
    {
        RawPacket raw = make_frame(
            0x01010101, 0x02020202, 53, 1024,
            17, /* UDP */
            10
        );
        ParsedPacket pp = parse_packet(raw, 0);
        CHECK(!pp.valid, "T05a: UDP → not valid");
        CHECK(pp.skip_reason == ParsedPacket::SKIP_NOT_TCP,
              "T05b: skip = NOT_TCP");
    }

    /* T06 — TCP with zero payload (pure ACK) */
    {
        RawPacket raw = make_frame(
            0x01010101, 0x02020202, 40000, 443,
            6, /* TCP */
            0  /* no payload */
        );
        ParsedPacket pp = parse_packet(raw, 0);
        CHECK(!pp.valid, "T06a: zero payload → not valid");
        CHECK(pp.skip_reason == ParsedPacket::SKIP_NO_PAYLOAD,
              "T06b: skip = NO_PAYLOAD");
    }

    /* T07 — IPv4 with options (IHL=6, 24-byte IP header) */
    {
        RawPacket raw = make_frame(
            0xACACACAC, 0xBCBCBCBC, 8888, 9999,
            6, /* TCP */
            50,
            6  /* IHL=6 → 24 byte IP header with options */
        );
        ParsedPacket pp = parse_packet(raw, 0);
        CHECK(pp.valid,                     "T07a: IPv4-with-options valid");
        CHECK(pp.tcp_payload_len == 50,     "T07b: payload correct");
        CHECK(pp.tuple.src_ip == 0xACACACAC, "T07c: src_ip after options");
    }

    /* T08 — TCP with options (data offset=8, 32-byte TCP header) */
    {
        RawPacket raw = make_frame(
            0x0A000001, 0x0A000002, 22222, 33333,
            6,  /* TCP */
            75,
            5,  /* standard IP header */
            8   /* TCP doff=8 → 32 byte header with options */
        );
        ParsedPacket pp = parse_packet(raw, 0);
        CHECK(pp.valid,                  "T08a: TCP-with-options valid");
        CHECK(pp.tcp_payload_len == 75,  "T08b: payload correct after TCP options");
    }

    /* Summary */
    printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
