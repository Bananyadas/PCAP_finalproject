/*
 * tcp_reassembly.c - In-order TCP stream reconstruction.
 *
 * Fast path : segment starts exactly at next_seq and does not run into
 *             buffered data -> append directly.
 * Slow path : insert into the sorted OOO list using FIRST-WINS trimming,
 *             then "drain" every buffered piece that is now contiguous.
 */
#include "tcp_reassembly.h"
#include "packet_parser.h"   /* TCP_SYN / TCP_FIN */

#include <stdlib.h>
#include <string.h>

static int buf_append(ByteBuf *b, const uint8_t *d, size_t n)
{
    if (n == 0) return 0;
    if (b->len + n > b->cap) {
        size_t ncap = b->cap ? b->cap : 256;
        while (ncap < b->len + n) ncap *= 2;
        uint8_t *nd = realloc(b->data, ncap);
        if (!nd) return -1;
        b->data = nd;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, d, n);
    b->len += n;
    return 0;
}

void stream_init(TcpStream *s)
{
    memset(s, 0, sizeof *s);
    s->ooo_cap = TCP_OOO_CAP_DEFAULT;
}

/* Append bytes that start exactly at next_seq. */
static int deliver(TcpStream *s, const uint8_t *d, uint32_t n)
{
    if (buf_append(&s->out, d, n) != 0) return -1;
    s->next_seq += n;
    return 0;
}

/* Move every buffered piece that now touches next_seq into the output. */
static int drain(TcpStream *s)
{
    while (s->ooo && seq_leq(s->ooo->seq, s->next_seq)) {
        OooSeg *h = s->ooo;
        s->ooo = h->next;
        s->ooo_bytes -= h->len;
        uint32_t end = h->seq + h->len;
        int rc = 0;
        if (seq_lt(s->next_seq, end)) {
            uint32_t skip = s->next_seq - h->seq;
            s->dup_bytes += skip;
            rc = deliver(s, h->data + skip, h->len - skip);
        } else {
            s->dup_bytes += h->len;
        }
        free(h->data);
        free(h);
        if (rc) return -1;
    }
    return 0;
}

/*
 * Insert [seq, seq+len) into the sorted list. Bytes already covered by an
 * existing node are discarded (FIRST-WINS); only the uncovered pieces are
 * stored, so nodes never overlap each other.
 */
static int ooo_insert(TcpStream *s, uint32_t seq, const uint8_t *d, uint32_t len)
{
    OooSeg **link = &s->ooo;
    while (len > 0) {
        OooSeg *e = *link;
        if (e && seq_leq(e->seq + e->len, seq)) {   /* e lies wholly before us */
            link = &e->next;
            continue;
        }
        uint32_t piece;
        if (!e || seq_leq(seq + len, e->seq)) piece = len;     /* fits before e */
        else if (seq_lt(seq, e->seq))          piece = e->seq - seq; /* part before e */
        else                                    piece = 0;     /* starts inside e */

        if (piece > 0) {
            int in_order = seq_leq(seq, s->next_seq);  /* will drain at once */
            if (!in_order && s->ooo_bytes + piece > s->ooo_cap) {
                s->ooo_dropped_bytes += piece;          /* cap reached: drop */
            } else {
                OooSeg *n = malloc(sizeof *n);
                uint8_t *nd = malloc(piece);
                if (!n || !nd) { free(n); free(nd); return -1; }
                memcpy(nd, d, piece);
                n->seq = seq; n->len = piece; n->data = nd; n->next = e;
                *link = n;
                link = &n->next;
                s->ooo_bytes += piece;
            }
            seq += piece; d += piece; len -= piece;
        }
        if (len == 0) break;

        /* Here e != NULL and seq lies inside e: skip the overlap. */
        uint32_t ov = e->seq + e->len - seq;
        if (ov > len) ov = len;
        s->dup_bytes += ov;
        seq += ov; d += ov; len -= ov;
        link = &e->next;
    }
    return 0;
}

int stream_add(TcpStream *s, uint32_t seq, uint8_t flags,
               const uint8_t *payload, uint32_t len)
{
    s->packets++;

    /* SYN uses one sequence number: the first data byte is ISN + 1. */
    if (flags & TCP_SYN) {
        s->syn_seen = 1;
        if (!s->isn_set) { s->isn_set = 1; s->next_seq = seq + 1; }
        seq += 1;
    } else if (!s->isn_set) {
        /* No SYN captured: start the stream at the first packet we see. */
        s->isn_set = 1;
        s->next_seq = seq;
    }
    if (flags & TCP_FIN) s->fin_seen = 1;
    if (len == 0) return 0;

    /* Completely old data -> retransmission. */
    if (seq_leq(seq + len, s->next_seq)) {
        s->dup_bytes += len;
        s->retransmits++;
        return 0;
    }
    /* Partially old -> trim the front (first-wins). */
    if (seq_lt(seq, s->next_seq)) {
        uint32_t t = s->next_seq - seq;
        s->dup_bytes += t;
        seq += t; payload += t; len -= t;
    }

    /* Fast path. */
    if (seq == s->next_seq && (!s->ooo || seq_leq(seq + len, s->ooo->seq))) {
        if (deliver(s, payload, len) != 0) return -1;
        return drain(s);
    }

    if (seq != s->next_seq) s->ooo_packets++;
    if (ooo_insert(s, seq, payload, len) != 0) return -1;
    return drain(s);
}

void stream_finish(TcpStream *s)
{
    uint32_t expect = s->next_seq;
    OooSeg *e = s->ooo;
    while (e) {
        if (e->seq != expect) s->gaps++;   /* a hole precedes this piece */
        s->stranded_bytes += e->len;
        expect = e->seq + e->len;
        OooSeg *nx = e->next;
        free(e->data);
        free(e);
        e = nx;
    }
    s->ooo = NULL;
    s->ooo_bytes = 0;
    s->finished = 1;
}

void stream_free(TcpStream *s)
{
    stream_finish(s);
    free(s->out.data);
    s->out.data = NULL;
    s->out.len = s->out.cap = 0;
}
