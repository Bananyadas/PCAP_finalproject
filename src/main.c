/*
 * main.c - Driver for the PCAP input & flow management component.
 *
 * Usage: ./pcap_flow <file.pcap> [threads]
 *
 * Stages:
 *   1. I/O      : load whole PCAP into memory     (timed separately)
 *   2. Parse    : OpenMP parallel header parsing
 *   3. Flows    : sequential flow table + TCP reassembly (deterministic)
 *   4. Export   : arena + Segment[] + FlowRec[], then self-verify
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <omp.h>

#include "packet_parser.h"
#include "flow_table.h"
#include "flow_export.h"

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.pcap> [threads]\n", argv[0]);
        return 1;
    }
    int threads = argc >= 3 ? atoi(argv[2]) : omp_get_max_threads();
    if (threads <= 0) threads = 1;
    char err[512];

    /* 1. I/O */
    double t0 = now_sec();
    PacketList pl;
    if (pcap_load_file(argv[1], &pl, err, sizeof err) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }
    double t1 = now_sec();

    /* 2. Parallel parse */
    ParsedPacket *pp = malloc((pl.count ? pl.count : 1) * sizeof *pp);
    if (!pp) { fprintf(stderr, "error: out of memory\n"); pcap_free_packets(&pl); return 1; }
    parse_all(&pl, pp, threads);
    double t2 = now_sec();

    /* 3. Sequential flow table + reassembly */
    FlowTable ft;
    FlowStats st;
    if (flow_table_init(&ft, 1024) != 0 || flow_process_packets(&ft, &pl, pp, &st) != 0) {
        fprintf(stderr, "error: out of memory in flow stage\n");
        return 1;
    }
    double t3 = now_sec();

    /* 4. Export + verify */
    ExportData ex;
    if (export_build(&ft, &ex, err, sizeof err) != 0) {
        fprintf(stderr, "error: %s\n", err);
        return 1;
    }
    double t4 = now_sec();
    int ok = export_verify(&ex, &ft, err, sizeof err) == 0;

    /* Aggregate reassembly statistics. */
    uint64_t dup = 0, gaps = 0, stranded = 0, dropped = 0, ooo = 0, retx = 0, syn = 0, fin = 0, empty = 0;
    for (size_t i = 0; i < ft.nflows; i++) {
        const TcpStream *s = &ft.flows[i].stream;
        dup += s->dup_bytes; gaps += s->gaps; stranded += s->stranded_bytes;
        dropped += s->ooo_dropped_bytes; ooo += s->ooo_packets; retx += s->retransmits;
        syn += s->syn_seen; fin += s->fin_seen; empty += (s->out.len == 0);
    }

    double proc = t4 - t1;
    printf("=== PCAP Flow Manager (C + OpenMP) ===\n");
    printf("file               : %s\n", argv[1]);
    printf("threads            : %d\n", threads);
    printf("packets            : %zu\n", pl.count);
    for (int s = 0; s < PARSE_STATUS_COUNT; s++)
        printf("  %-17s: %llu\n", parse_status_name((ParseStatus)s),
               (unsigned long long)st.status_count[s]);
    printf("flows (directional): %zu  (empty: %llu, SYN seen: %llu, FIN seen: %llu)\n",
           ft.nflows, (unsigned long long)empty, (unsigned long long)syn, (unsigned long long)fin);
    printf("tcp payload bytes  : %llu\n", (unsigned long long)st.payload_bytes);
    printf("reassembled bytes  : %zu\n", ex.arena_len);
    printf("duplicate bytes    : %llu  (retransmitted pkts: %llu)\n",
           (unsigned long long)dup, (unsigned long long)retx);
    printf("out-of-order pkts  : %llu\n", (unsigned long long)ooo);
    printf("gaps / stranded    : %llu / %llu bytes\n", (unsigned long long)gaps, (unsigned long long)stranded);
    printf("OOO cap dropped    : %llu bytes\n", (unsigned long long)dropped);
    printf("segments exported  : %zu\n", ex.nsegs);
    printf("export checksum    : %016llx\n", (unsigned long long)export_checksum(&ex));
    printf("export verify      : %s%s%s\n", ok ? "OK" : "FAILED", ok ? "" : " - ", ok ? "" : err);
    printf("--- timing ---\n");
    printf("I/O (load)         : %.6f s\n", t1 - t0);
    printf("parse (parallel)   : %.6f s\n", t2 - t1);
    printf("flows+reassembly   : %.6f s\n", t3 - t2);
    printf("export             : %.6f s\n", t4 - t3);
    printf("processing total   : %.6f s  (%.0f packets/s)\n", proc,
           proc > 0 ? (double)pl.count / proc : 0.0);

    export_free(&ex);
    flow_table_free(&ft);
    free(pp);
    pcap_free_packets(&pl);
    return ok ? 0 : 2;
}
