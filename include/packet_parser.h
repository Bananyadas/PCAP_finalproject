/**
 * packet_parser.h — PCAP reading and Ethernet/IPv4/TCP header parsing.
 *
 * Public API:
 *   pcap_load()   — read the entire PCAP file into memory.
 *   parse_packet() — parse one raw captured frame into a ParsedPacket.
 *   parse_all_packets() — parallel wrapper (OpenMP) over a raw packet list.
 *   pcap_stats_print() — print diagnostic counts.
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <string>

/* -----------------------------------------------------------------------
 * RawPacket
 * A single captured frame as stored in the PCAP file.
 * We copy the bytes into a std::vector so the libpcap handle can be closed
 * before processing begins.
 * --------------------------------------------------------------------- */
struct RawPacket {
    std::vector<uint8_t> data;   /* raw frame bytes (up to caplen)      */
    uint32_t             caplen; /* bytes actually captured              */
    uint32_t             wirelen;/* original wire length (may be larger) */
    /* Timestamp kept for debugging; not used in processing. */
    uint32_t             ts_sec;
    uint32_t             ts_usec;
};

/* -----------------------------------------------------------------------
 * FiveTuple
 * The canonical 5-tuple that identifies a directional network flow.
 * --------------------------------------------------------------------- */
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;      /* IPPROTO_TCP = 6 */
};

/* -----------------------------------------------------------------------
 * ParsedPacket
 * Metadata extracted from one captured frame.
 * If `valid` is false the frame was truncated, unsupported, or had no
 * TCP payload; all other fields are undefined.
 * --------------------------------------------------------------------- */
struct ParsedPacket {
    bool      valid;       /* true only when tcp_payload_len > 0         */
    FiveTuple tuple;
    uint32_t  seq;         /* TCP sequence number (host byte order)       */
    uint32_t  ack;         /* TCP acknowledgement number                  */
    uint8_t   tcp_flags;   /* raw TCP flags byte                          */
    uint16_t  tcp_payload_len; /* bytes of TCP application payload        */

    /* Offset of the TCP payload inside RawPacket::data.
     * Use this to avoid copying data during parsing. */
    uint16_t  payload_offset;

    /* Index of the originating RawPacket in the load vector.
     * Useful for retrieving the payload bytes without an extra copy. */
    uint32_t  raw_idx;

    /* Diagnostics — why was this packet skipped? */
    enum SkipReason {
        SKIP_NONE = 0,
        SKIP_TRUNCATED,
        SKIP_NOT_ETHERNET,
        SKIP_NOT_IPV4,
        SKIP_NOT_TCP,
        SKIP_NO_PAYLOAD,
        SKIP_MALFORMED,
    } skip_reason;
};

/* -----------------------------------------------------------------------
 * ParseStats
 * Aggregate counts after a parsing pass.
 * --------------------------------------------------------------------- */
struct ParseStats {
    uint32_t total;
    uint32_t valid_tcp;         /* had non-zero TCP payload */
    uint32_t skipped_truncated;
    uint32_t skipped_not_eth;
    uint32_t skipped_not_ipv4;
    uint32_t skipped_not_tcp;
    uint32_t skipped_no_payload;
    uint32_t skipped_malformed;
};

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

/**
 * pcap_load — open `filename`, check the link-layer type, read every
 * packet into `out_packets`, then close the handle.
 *
 * Returns true on success.
 * On failure prints an error to stderr and returns false.
 */
bool pcap_load(const std::string& filename,
               std::vector<RawPacket>& out_packets);

/**
 * parse_packet — parse one RawPacket into a ParsedPacket.
 *
 * `raw_idx` is stored in the result for payload retrieval.
 * Thread-safe: reads only from `raw` (no global state).
 */
ParsedPacket parse_packet(const RawPacket& raw, uint32_t raw_idx);

/**
 * parse_all_packets — parse every RawPacket in parallel using OpenMP.
 *
 * Returns a vector of ParsedPacket (same length as `raws`).
 * The `stats` struct is populated with aggregate counts.
 */
std::vector<ParsedPacket> parse_all_packets(
    const std::vector<RawPacket>& raws,
    ParseStats& stats);

/**
 * pcap_stats_print — pretty-print the ParseStats to stdout.
 */
void pcap_stats_print(const ParseStats& stats);

#endif /* PACKET_PARSER_H */
