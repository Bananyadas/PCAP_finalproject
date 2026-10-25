/*
 * packet_parser.h - Offline PCAP loading + Ethernet/IPv4/TCP parsing.
 *
 * Pipeline position:   [PCAP file] -> pcap_load_file() -> parse_all() -> flow table
 */
#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stddef.h>
#include <stdint.h>

/* TCP flag bits (byte 13 of the TCP header). */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

/*
 * The directional 5-tuple that identifies a flow.
 * IPs are stored in HOST byte order. 'pad' makes the padding explicit;
 * we never hash or compare it (we work field by field).
 */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  pad[3];
} FiveTuple;

/* Result of parsing one packet. */
typedef enum {
    PARSE_OK = 0,       /* valid IPv4/TCP packet                          */
    PARSE_TRUNCATED,    /* captured bytes shorter than the headers claim  */
    PARSE_NOT_IPV4,     /* ARP, IPv6, ...                                 */
    PARSE_NOT_TCP,      /* UDP, ICMP, ...                                 */
    PARSE_FRAGMENT,     /* IPv4 fragment (not reassembled - limitation)   */
    PARSE_BAD_HEADER,   /* nonsense field values (IHL < 5, doff < 5, ...) */
    PARSE_STATUS_COUNT
} ParseStatus;

const char *parse_status_name(ParseStatus s);

/* One packet exactly as read from the file (owned copy of the bytes). */
typedef struct {
    uint8_t *data;
    uint32_t caplen;    /* bytes actually captured   */
    uint32_t wirelen;   /* original length on wire   */
    uint64_t ts_us;     /* timestamp in microseconds */
} RawPacket;

/* Growable array of packets: the whole capture lives in memory. */
typedef struct {
    RawPacket *pkts;
    size_t     count;
    size_t     cap;
} PacketList;

/* Parsed metadata for one packet. The payload is NOT copied: it is
 * data[payload_off .. payload_off + payload_len) of the RawPacket. */
typedef struct {
    ParseStatus status;
    FiveTuple   tuple;
    uint32_t    seq;
    uint8_t     tcp_flags;
    uint32_t    payload_off;
    uint32_t    payload_len;
} ParsedPacket;

/* Load every packet of an offline PCAP into memory.
 * Only Ethernet (DLT_EN10MB) captures are accepted.
 * Returns 0 on success, -1 on error (message in err). */
int  pcap_load_file(const char *path, PacketList *out, char *err, size_t errlen);
int  packet_list_push(PacketList *pl, const uint8_t *data, uint32_t caplen,
                      uint32_t wirelen, uint64_t ts_us);
void pcap_free_packets(PacketList *pl);

/* Parse one Ethernet frame. Pure function: safe to call from many threads. */
ParseStatus parse_packet(const uint8_t *data, uint32_t caplen, ParsedPacket *out);

/* Parse all packets in parallel with OpenMP. out must have pl->count slots.
 * threads <= 0 means "use the OpenMP default". */
void parse_all(const PacketList *pl, ParsedPacket *out, int threads);

#endif /* PACKET_PARSER_H */
