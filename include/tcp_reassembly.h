/*
 * tcp_reassembly.h - Rebuilds one direction of a TCP byte stream.
 *
 * Policies (easy to state in a viva):
 *  - Sequence numbers are compared wraparound-safe: (int32_t)(a - b) < 0.
 *  - FIRST-WINS: bytes we already hold (delivered or buffered) are never
 *    overwritten by a later retransmission carrying different data.
 *  - Out-of-order data is buffered in a sorted linked list, capped at
 *    ooo_cap bytes per stream (default 64 MiB); excess is dropped and counted.
 *  - GAPS: if bytes are missing at end-of-file, the buffered data after the
 *    hole is NOT glued onto the stream; it is counted as "stranded".
 *  - SYN consumes one sequence number (data starts at ISN + 1).
 */
#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include <stddef.h>
#include <stdint.h>

#define TCP_OOO_CAP_DEFAULT (64u * 1024u * 1024u)

/* Simple growable byte buffer. */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} ByteBuf;

/* One buffered out-of-order piece. The list never contains overlaps. */
typedef struct OooSeg {
    uint32_t seq;
    uint32_t len;
    uint8_t *data;
    struct OooSeg *next;
} OooSeg;

typedef struct {
    /* state */
    int      isn_set;        /* have we fixed the starting sequence?      */
    uint32_t next_seq;       /* next byte we expect to append              */
    int      syn_seen;
    int      fin_seen;
    int      finished;
    ByteBuf  out;            /* reassembled, in-order bytes                */
    OooSeg  *ooo;            /* sorted out-of-order list                   */
    size_t   ooo_bytes;
    size_t   ooo_cap;

    /* statistics */
    uint64_t packets;
    uint64_t ooo_packets;      /* data packets that arrived ahead of time */
    uint64_t retransmits;      /* packets that were 100% old data          */
    uint64_t dup_bytes;        /* bytes discarded because already held     */
    uint64_t ooo_dropped_bytes;/* bytes dropped because of the OOO cap     */
    uint64_t gaps;             /* holes found at end-of-stream             */
    uint64_t stranded_bytes;   /* buffered bytes after a hole (not output) */
} TcpStream;

void stream_init(TcpStream *s);
/* Feed one TCP segment. Returns 0 on success, -1 on out-of-memory. */
int  stream_add(TcpStream *s, uint32_t seq, uint8_t flags,
                const uint8_t *payload, uint32_t len);
/* Call once at end of input: accounts for gaps and frees the OOO list. */
void stream_finish(TcpStream *s);
void stream_free(TcpStream *s);

/* Wraparound-safe sequence comparisons (exposed for tests). */
static inline int seq_lt (uint32_t a, uint32_t b) { return (int32_t)(a - b) <  0; }
static inline int seq_leq(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }

#endif /* TCP_REASSEMBLY_H */
