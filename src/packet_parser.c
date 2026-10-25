/*
 * packet_parser.c - Offline PCAP loading and Ethernet/IPv4/TCP parsing.
 *
 * Every multi-byte header field is read BYTE BY BYTE (rd16/rd32). This
 * avoids unaligned-pointer casts and converts network byte order (big-endian)
 * to host order in one step.
 */
#include "packet_parser.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>

#define ETH_HDR_LEN   14
#define VLAN_TAG_LEN  4
#define ETHERTYPE_IP  0x0800
#define ETHERTYPE_VLAN 0x8100
#define IPPROTO_TCP_NUM 6

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

const char *parse_status_name(ParseStatus s)
{
    switch (s) {
    case PARSE_OK:         return "ok";
    case PARSE_TRUNCATED:  return "truncated";
    case PARSE_NOT_IPV4:   return "not_ipv4";
    case PARSE_NOT_TCP:    return "not_tcp";
    case PARSE_FRAGMENT:   return "ip_fragment";
    case PARSE_BAD_HEADER: return "bad_header";
    default:               return "unknown";
    }
}

/* ------------------------------------------------------------------ */
/* Loading                                                             */
/* ------------------------------------------------------------------ */

int packet_list_push(PacketList *pl, const uint8_t *data, uint32_t caplen,
                     uint32_t wirelen, uint64_t ts_us)
{
    if (pl->count == pl->cap) {
        size_t ncap = pl->cap ? pl->cap * 2 : 1024;
        RawPacket *np = realloc(pl->pkts, ncap * sizeof *np);
        if (!np) return -1;
        pl->pkts = np;
        pl->cap = ncap;
    }
    RawPacket *r = &pl->pkts[pl->count];
    r->data = malloc(caplen ? caplen : 1);
    if (!r->data) return -1;
    if (caplen) memcpy(r->data, data, caplen);
    r->caplen = caplen;
    r->wirelen = wirelen;
    r->ts_us = ts_us;
    pl->count++;
    return 0;
}

int pcap_load_file(const char *path, PacketList *out, char *err, size_t errlen)
{
    char ebuf[PCAP_ERRBUF_SIZE];
    memset(out, 0, sizeof *out);

    pcap_t *p = pcap_open_offline(path, ebuf);
    if (!p) {
        snprintf(err, errlen, "cannot open '%s': %s", path, ebuf);
        return -1;
    }
    /* We only understand Ethernet framing. Reject anything else cleanly. */
    if (pcap_datalink(p) != DLT_EN10MB) {
        snprintf(err, errlen, "unsupported link type %d (only Ethernet/DLT_EN10MB)",
                 pcap_datalink(p));
        pcap_close(p);
        return -1;
    }

    struct pcap_pkthdr *h;
    const u_char *d;
    int rc;
    while ((rc = pcap_next_ex(p, &h, &d)) == 1) {
        uint64_t ts = (uint64_t)h->ts.tv_sec * 1000000ull + (uint64_t)h->ts.tv_usec;
        if (packet_list_push(out, d, h->caplen, h->len, ts) != 0) {
            snprintf(err, errlen, "out of memory after %zu packets", out->count);
            pcap_free_packets(out);
            pcap_close(p);
            return -1;
        }
    }
    if (rc == -1) {
        snprintf(err, errlen, "read error: %s", pcap_geterr(p));
        pcap_free_packets(out);
        pcap_close(p);
        return -1;
    }
    pcap_close(p);
    return 0;
}

void pcap_free_packets(PacketList *pl)
{
    for (size_t i = 0; i < pl->count; i++) free(pl->pkts[i].data);
    free(pl->pkts);
    memset(pl, 0, sizeof *pl);
}

/* ------------------------------------------------------------------ */
/* Parsing                                                             */
/* ------------------------------------------------------------------ */

ParseStatus parse_packet(const uint8_t *data, uint32_t caplen, ParsedPacket *out)
{
    memset(out, 0, sizeof *out);   /* also zeroes tuple padding */
    out->status = PARSE_TRUNCATED;

    /* ---- Ethernet ---- */
    if (caplen < ETH_HDR_LEN) return out->status;
    uint32_t off = ETH_HDR_LEN;
    uint16_t ethertype = rd16(data + 12);
    if (ethertype == ETHERTYPE_VLAN) {            /* one 802.1Q tag */
        if (caplen < ETH_HDR_LEN + VLAN_TAG_LEN) return out->status;
        ethertype = rd16(data + 16);
        off += VLAN_TAG_LEN;
    }
    if (ethertype != ETHERTYPE_IP) return out->status = PARSE_NOT_IPV4;

    /* ---- IPv4 ---- */
    if (caplen < off + 20) return out->status = PARSE_TRUNCATED;
    const uint8_t *ip = data + off;
    uint32_t version = ip[0] >> 4;
    uint32_t ihl = (uint32_t)(ip[0] & 0x0F) * 4;  /* header length incl. options */
    if (version != 4) return out->status = PARSE_NOT_IPV4;
    if (ihl < 20) return out->status = PARSE_BAD_HEADER;
    if (caplen < off + ihl) return out->status = PARSE_TRUNCATED;

    uint32_t total_len = rd16(ip + 2);
    if (total_len < ihl) return out->status = PARSE_BAD_HEADER;

    out->tuple.src_ip = rd32(ip + 12);
    out->tuple.dst_ip = rd32(ip + 16);
    out->tuple.protocol = ip[9];

    uint16_t frag = rd16(ip + 6);
    if ((frag & 0x2000) || (frag & 0x1FFF)) return out->status = PARSE_FRAGMENT;
    if (ip[9] != IPPROTO_TCP_NUM) return out->status = PARSE_NOT_TCP;

    /* ---- TCP ---- */
    uint32_t toff = off + ihl;
    if (caplen < toff + 20) return out->status = PARSE_TRUNCATED;
    const uint8_t *tcp = data + toff;
    uint32_t doff = (uint32_t)(tcp[12] >> 4) * 4; /* header length incl. options */
    if (doff < 20) return out->status = PARSE_BAD_HEADER;
    if (total_len < ihl + doff) return out->status = PARSE_BAD_HEADER;
    if (caplen < toff + doff) return out->status = PARSE_TRUNCATED;

    /* Payload ends at the IP total length (ignores Ethernet padding).
     * If the snapshot cut the payload, we refuse the packet rather than
     * feed partial bytes into reassembly. */
    uint32_t ip_end = off + total_len;
    if (ip_end > caplen) return out->status = PARSE_TRUNCATED;

    out->tuple.src_port = rd16(tcp);
    out->tuple.dst_port = rd16(tcp + 2);
    out->seq = rd32(tcp + 4);
    out->tcp_flags = tcp[13];
    out->payload_off = toff + doff;
    out->payload_len = ip_end - out->payload_off;
    return out->status = PARSE_OK;
}

void parse_all(const PacketList *pl, ParsedPacket *out, int threads)
{
    if (threads <= 0) threads = omp_get_max_threads();
    long n = (long)pl->count;
    /* Each packet is independent, and each thread writes only out[i],
     * so no locks are needed. dynamic,64 balances uneven packet sizes. */
    #pragma omp parallel for schedule(dynamic, 64) num_threads(threads)
    for (long i = 0; i < n; i++)
        parse_packet(pl->pkts[i].data, pl->pkts[i].caplen, &out[i]);
}
