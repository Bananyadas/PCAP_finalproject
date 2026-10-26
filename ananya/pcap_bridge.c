/* pcap_bridge.c -- runs Ananyaraj's stages (read, parse, flow table + reassembly, export) UNMODIFIED
 * and hands the result to our pipeline as PcapFlows. Plain C. Nothing in his code is edited.
 * It also exports per-flow protocol / port / key, which his ExportData does not carry (the cost
 * predictor's first guess needs them). */
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <omp.h>
#include "packet_parser.h"
#include "flow_table.h"
#include "flow_export.h"
#include "pcap_bridge.h"

typedef struct { uint32_t idx, flow; uint32_t rel; } Ord;
static int cmp_ord(const void* a, const void* b) {
    const Ord *x = (const Ord*)a, *y = (const Ord*)b;
    if (x->flow != y->flow) return x->flow < y->flow ? -1 : 1;
    if (x->rel != y->rel) return x->rel < y->rel ? -1 : 1;
    return x->idx < y->idx ? -1 : 1;                 /* ties: keep capture order (his first-wins policy unchanged) */
}

static double now_ms_(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }

int pcap_load_flows(const char* path, int threads, PcapFlows* out)
{
    char err[512];
    memset(out, 0, sizeof *out);
    if (threads <= 0) threads = omp_get_max_threads();

    double t0 = now_ms_();
    PacketList pl;
    if (pcap_load_file(path, &pl, err, sizeof err) != 0) { fprintf(stderr, "pcap: %s\n", err); return 1; }  /* whole file in memory first */
    double t1 = now_ms_();
    out->load_ms = t1 - t0;

    ParsedPacket* pp = (ParsedPacket*)malloc((pl.count ? pl.count : 1) * sizeof *pp);
    parse_all(&pl, pp, threads);                                 /* his OpenMP parsing */

    /* WORKAROUND (his code is untouched). His reassembler starts a stream at the first packet it sees
     * unless that packet is a SYN; if a capture has no SYN and an earlier part of the stream is
     * captured later, those bytes are dropped silently (no gap is reported). So give it each flow's
     * packets in SEQUENCE order: find every packet's flow and each flow's lowest sequence number
     * (wrap-aware), then permute the packet and parse arrays together. */
    FlowTable scratch;
    flow_table_init(&scratch, 1024);
    Ord* ord = (Ord*)malloc((pl.count ? pl.count : 1) * sizeof(Ord));
    uint32_t* base = NULL; size_t nb = 0;
    for (size_t i = 0; i < pl.count; i++) {
        ord[i].idx = (uint32_t)i; ord[i].rel = 0;
        if (pp[i].status != PARSE_OK) { ord[i].flow = UINT32_MAX; continue; }
        int created = 0;
        uint32_t f = flow_table_get_or_insert(&scratch, &pp[i].tuple, &created);
        ord[i].flow = f;
        if (f >= nb) { size_t nn = f + 1024; base = (uint32_t*)realloc(base, nn * sizeof(uint32_t)); nb = nn; }
        if (created || seq_lt(pp[i].seq, base[f])) base[f] = pp[i].seq;
    }
    for (size_t i = 0; i < pl.count; i++)
        if (ord[i].flow != UINT32_MAX) ord[i].rel = pp[i].seq - base[ord[i].flow];
    qsort(ord, pl.count, sizeof(Ord), cmp_ord);
    PacketList pl2 = pl;                                       /* shallow: shares the packet bytes */
    pl2.pkts = (RawPacket*)malloc((pl.count ? pl.count : 1) * sizeof(RawPacket));
    ParsedPacket* pp2 = (ParsedPacket*)malloc((pl.count ? pl.count : 1) * sizeof *pp2);
    for (size_t i = 0; i < pl.count; i++) { pl2.pkts[i] = pl.pkts[ord[i].idx]; pp2[i] = pp[ord[i].idx]; }
    flow_table_free(&scratch); free(ord); free(base);

    FlowTable ft; FlowStats st;
    if (flow_table_init(&ft, 1024) != 0 || flow_process_packets(&ft, &pl2, pp2, &st) != 0) { fprintf(stderr, "pcap: out of memory\n"); return 2; }
    free(pl2.pkts); free(pp2);
    ExportData ex;
    if (export_build(&ft, &ex, err, sizeof err) != 0 || export_verify(&ex, &ft, err, sizeof err) != 0) { fprintf(stderr, "pcap: %s\n", err); return 3; }
    out->process_ms = now_ms_() - t1;

    size_t n = ex.nsegs;
    out->n = n; out->arena_len = ex.arena_len;
    out->arena  = (uint8_t*)malloc(ex.arena_len ? ex.arena_len : 1);
    memcpy(out->arena, ex.arena, ex.arena_len);
    out->offset = (uint32_t*)calloc(n + 1, sizeof(uint32_t));
    out->len    = (uint32_t*)calloc(n + 1, sizeof(uint32_t));
    out->proto  = (uint8_t*) calloc(n + 1, 1);
    out->port   = (uint16_t*)calloc(n + 1, sizeof(uint16_t));
    out->key    = (uint64_t*)calloc(n + 1, sizeof(uint64_t));
    for (size_t i = 0; i < n; i++) {
        const Segment* s = &ex.segs[i];
        uint32_t f = s->flow_id;                                 /* flow_id == index in our arrays */
        out->offset[f] = s->offset; out->len[f] = s->len;
        const Flow* fl = &ft.flows[f];
        out->proto[f] = fl->tuple.protocol; out->port[f] = fl->tuple.dst_port; out->key[f] = fl->key;
        if (fl->stream.gaps) out->incomplete++;
    }
    export_free(&ex); flow_table_free(&ft); free(pp); pcap_free_packets(&pl);
    return 0;
}

void pcap_free_flows(PcapFlows* f)
{
    free(f->arena); free(f->offset); free(f->len); free(f->proto); free(f->port); free(f->key);
    memset(f, 0, sizeof *f);
}
