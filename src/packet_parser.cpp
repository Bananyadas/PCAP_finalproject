/**
 * packet_parser.cpp
 *
 * Responsibilities:
 *   1. Open a PCAP file with libpcap and read every frame into memory.
 *   2. Parse Ethernet → IPv4 → TCP headers for each frame.
 *   3. Extract the 5-tuple and TCP sequence metadata.
 *   4. Run parsing in parallel with OpenMP (each packet is independent).
 *
 * Beginner guide to the key ideas:
 *   • A PCAP file is just a list of captured network frames.
 *     libpcap gives us one frame at a time with a header that tells us
 *     how many bytes were captured vs. the original wire length.
 *   • Ethernet, IP, and TCP each have their own header at the start of
 *     the captured bytes. We advance a byte pointer past each header to
 *     reach the next layer.
 *   • We copy everything into our own memory so we can close libpcap
 *     immediately and process frames without holding a file handle open.
 */

#include "packet_parser.h"
#include <pcap.h>
#include <netinet/in.h>     /* ntohs, ntohl          */
#include <arpa/inet.h>      /* inet_ntoa (debugging) */
#include <cstring>
#include <cstdio>
#include <omp.h>

/* -----------------------------------------------------------------------
 * Ethernet header layout (14 bytes fixed)
 * --------------------------------------------------------------------- */
#pragma pack(push, 1)
struct EtherHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type; /* 0x0800 = IPv4, stored in network byte order */
};

/* IPv4 header layout (minimum 20 bytes; may have options)
 *
 * `ihl` is the Internet Header Length in 32-bit words.
 * Actual header size = ihl * 4. We must use this, not a fixed 20.
 */
struct IPv4Header {
    uint8_t  version_ihl;   /* top 4 bits = version, bottom 4 = IHL */
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;      /* 6 = TCP                               */
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    /* Options (variable) follow here */
};

/* TCP header layout (minimum 20 bytes; data_offset gives actual size)
 *
 * `data_offset` is the top 4 bits of the 13th byte.
 * Actual TCP header size = data_offset * 4.
 */
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset; /* top 4 bits = header length in 32-bit words */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
    /* Options (variable) follow here */
};
#pragma pack(pop)

static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
static constexpr uint8_t  IPPROTO_TCP_VAL = 6;

/* -----------------------------------------------------------------------
 * pcap_load — read the entire PCAP into memory, then close the handle.
 * --------------------------------------------------------------------- */
bool pcap_load(const std::string& filename,
               std::vector<RawPacket>& out_packets)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Open the file for offline (saved) reading */
    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle) {
        fprintf(stderr, "[pcap_load] Cannot open '%s': %s\n",
                filename.c_str(), errbuf);
        return false;
    }

    /* Check the link-layer type.
     * We only understand Ethernet (DLT_EN10MB). */
    int dlt = pcap_datalink(handle);
    if (dlt != DLT_EN10MB) {
        fprintf(stderr,
                "[pcap_load] Unsupported link-layer type %d (%s).\n"
                "            Only Ethernet (DLT_EN10MB=%d) is supported.\n",
                dlt, pcap_datalink_val_to_name(dlt), DLT_EN10MB);
        pcap_close(handle);
        return false;
    }

    fprintf(stdout, "[pcap_load] Opened '%s' (link-layer: Ethernet)\n",
            filename.c_str());

    /* Read every packet into our own memory.
     * pcap_next_ex() returns 1 on success, 0 on timeout (not used in
     * offline mode), -1 on error, -2 at end-of-file. */
    struct pcap_pkthdr* hdr;
    const uint8_t*      raw_data;
    int ret;

    while ((ret = pcap_next_ex(handle, &hdr, &raw_data)) == 1) {
        RawPacket pkt;
        pkt.caplen  = hdr->caplen;
        pkt.wirelen = hdr->len;
        pkt.ts_sec  = static_cast<uint32_t>(hdr->ts.tv_sec);
        pkt.ts_usec = static_cast<uint32_t>(hdr->ts.tv_usec);

        /* Deep-copy the frame bytes */
        pkt.data.assign(raw_data, raw_data + hdr->caplen);
        out_packets.push_back(std::move(pkt));
    }

    if (ret == -1) {
        fprintf(stderr, "[pcap_load] Read error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return false;
    }

    fprintf(stdout, "[pcap_load] Read %zu packets into memory.\n",
            out_packets.size());
    pcap_close(handle);
    return true;
}

/* -----------------------------------------------------------------------
 * parse_packet — parse one RawPacket.
 *
 * This function is pure (reads only `raw`; no global writes) so it is
 * safe to call from multiple OpenMP threads simultaneously.
 * --------------------------------------------------------------------- */
ParsedPacket parse_packet(const RawPacket& raw, uint32_t raw_idx)
{
    ParsedPacket result{};
    result.raw_idx     = raw_idx;
    result.valid       = false;
    result.skip_reason = ParsedPacket::SKIP_NONE;

    const uint8_t* buf = raw.data.data();
    uint32_t       remaining = raw.caplen;

    /* --- Ethernet header -------------------------------------------- */
    if (remaining < sizeof(EtherHeader)) {
        result.skip_reason = ParsedPacket::SKIP_TRUNCATED;
        return result;
    }
    const auto* eth = reinterpret_cast<const EtherHeader*>(buf);
    if (ntohs(eth->ether_type) != ETHERTYPE_IPV4) {
        result.skip_reason = ParsedPacket::SKIP_NOT_IPV4;
        return result;
    }
    buf       += sizeof(EtherHeader);
    remaining -= sizeof(EtherHeader);

    /* --- IPv4 header ------------------------------------------------- */
    if (remaining < sizeof(IPv4Header)) {
        result.skip_reason = ParsedPacket::SKIP_TRUNCATED;
        return result;
    }
    const auto* ip = reinterpret_cast<const IPv4Header*>(buf);

    /* Extract IP header length (IHL field = bottom 4 bits of first byte).
     * IHL is in 32-bit (4-byte) words; multiply by 4 for bytes. */
    uint8_t ip_version = (ip->version_ihl >> 4) & 0x0F;
    uint8_t ip_ihl     = (ip->version_ihl     ) & 0x0F;
    uint32_t ip_hdr_len = static_cast<uint32_t>(ip_ihl) * 4;

    if (ip_version != 4 || ip_ihl < 5) {
        /* Version must be 4; IHL < 5 means invalid (min header is 20 bytes) */
        result.skip_reason = ParsedPacket::SKIP_MALFORMED;
        return result;
    }
    if (remaining < ip_hdr_len) {
        result.skip_reason = ParsedPacket::SKIP_TRUNCATED;
        return result;
    }
    if (ip->protocol != IPPROTO_TCP_VAL) {
        result.skip_reason = ParsedPacket::SKIP_NOT_TCP;
        return result;
    }

    /* IP total length tells us how many bytes the IP datagram contains. */
    uint16_t ip_total_len = ntohs(ip->total_length);
    if (ip_total_len < ip_hdr_len) {
        result.skip_reason = ParsedPacket::SKIP_MALFORMED;
        return result;
    }

    result.tuple.src_ip  = ntohl(ip->src_ip);
    result.tuple.dst_ip  = ntohl(ip->dst_ip);
    result.tuple.proto   = ip->protocol;

    buf       += ip_hdr_len;
    remaining -= ip_hdr_len;

    /* How many bytes does the IP payload occupy? */
    uint32_t ip_payload_len = ip_total_len - ip_hdr_len;

    /* Clamp to what was actually captured */
    if (ip_payload_len > remaining) {
        ip_payload_len = remaining; /* packet was truncated on capture */
    }

    /* --- TCP header -------------------------------------------------- */
    if (remaining < sizeof(TCPHeader)) {
        result.skip_reason = ParsedPacket::SKIP_TRUNCATED;
        return result;
    }
    const auto* tcp = reinterpret_cast<const TCPHeader*>(buf);

    /* TCP data offset: top 4 bits of byte 12, value in 32-bit words */
    uint8_t  tcp_doff    = (tcp->data_offset >> 4) & 0x0F;
    uint32_t tcp_hdr_len = static_cast<uint32_t>(tcp_doff) * 4;

    if (tcp_doff < 5) {
        /* Minimum TCP header is 20 bytes = 5 words */
        result.skip_reason = ParsedPacket::SKIP_MALFORMED;
        return result;
    }
    if (tcp_hdr_len > ip_payload_len) {
        result.skip_reason = ParsedPacket::SKIP_TRUNCATED;
        return result;
    }

    result.tuple.src_port = ntohs(tcp->src_port);
    result.tuple.dst_port = ntohs(tcp->dst_port);
    result.seq            = ntohl(tcp->seq);
    result.ack            = ntohl(tcp->ack);
    result.tcp_flags      = tcp->flags;

    /* TCP payload starts after the TCP header */
    uint32_t payload_len = ip_payload_len - tcp_hdr_len;
    if (payload_len == 0) {
        result.skip_reason = ParsedPacket::SKIP_NO_PAYLOAD;
        return result;
    }

    /* payload_offset is relative to the start of the original raw buffer */
    uint32_t offset_from_raw_start =
        static_cast<uint32_t>(sizeof(EtherHeader)) + ip_hdr_len + tcp_hdr_len;

    if (offset_from_raw_start + payload_len > raw.caplen) {
        /* Payload extends beyond what was captured */
        payload_len = raw.caplen - offset_from_raw_start;
        if (payload_len == 0) {
            result.skip_reason = ParsedPacket::SKIP_NO_PAYLOAD;
            return result;
        }
    }

    if (payload_len > UINT16_MAX) {
        /* Sanity cap — TCP payload cannot exceed 65535 bytes in one segment */
        payload_len = UINT16_MAX;
    }

    result.payload_offset    = static_cast<uint16_t>(offset_from_raw_start);
    result.tcp_payload_len   = static_cast<uint16_t>(payload_len);
    result.valid             = true;
    result.skip_reason       = ParsedPacket::SKIP_NONE;

    return result;
}

/* -----------------------------------------------------------------------
 * parse_all_packets — parallel wrapper using OpenMP.
 * --------------------------------------------------------------------- */
std::vector<ParsedPacket> parse_all_packets(
    const std::vector<RawPacket>& raws,
    ParseStats& stats)
{
    const uint32_t n = static_cast<uint32_t>(raws.size());
    std::vector<ParsedPacket> results(n);

    /*
     * Each iteration reads only its own RawPacket and writes to its own
     * results[i] slot, so there are no data races — fully parallel.
     */
#pragma omp parallel for schedule(dynamic, 64)
    for (uint32_t i = 0; i < n; ++i) {
        results[i] = parse_packet(raws[i], i);
    }

    /* Aggregate stats sequentially (cheap) */
    stats = {};
    stats.total = n;
    for (const auto& p : results) {
        switch (p.skip_reason) {
            case ParsedPacket::SKIP_NONE:
                if (p.valid) stats.valid_tcp++;
                break;
            case ParsedPacket::SKIP_TRUNCATED:    stats.skipped_truncated++;    break;
            case ParsedPacket::SKIP_NOT_ETHERNET: stats.skipped_not_eth++;      break;
            case ParsedPacket::SKIP_NOT_IPV4:     stats.skipped_not_ipv4++;     break;
            case ParsedPacket::SKIP_NOT_TCP:      stats.skipped_not_tcp++;      break;
            case ParsedPacket::SKIP_NO_PAYLOAD:   stats.skipped_no_payload++;   break;
            case ParsedPacket::SKIP_MALFORMED:    stats.skipped_malformed++;    break;
        }
    }
    return results;
}

/* -----------------------------------------------------------------------
 * pcap_stats_print — human-readable summary.
 * --------------------------------------------------------------------- */
void pcap_stats_print(const ParseStats& stats)
{
    printf("\n=== Packet Parsing Statistics ===\n");
    printf("  Total packets read      : %u\n", stats.total);
    printf("  Valid TCP (with payload): %u\n", stats.valid_tcp);
    printf("  Skipped — truncated     : %u\n", stats.skipped_truncated);
    printf("  Skipped — not IPv4      : %u\n", stats.skipped_not_ipv4);
    printf("  Skipped — not TCP       : %u\n", stats.skipped_not_tcp);
    printf("  Skipped — no payload    : %u\n", stats.skipped_no_payload);
    printf("  Skipped — malformed     : %u\n", stats.skipped_malformed);
    printf("  Skipped — not Ethernet  : %u\n", stats.skipped_not_eth);
    printf("=================================\n\n");
}
