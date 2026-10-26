/* bench.c -- benchmark harness. Every number in the report comes from here.
 *
 *   ./bench --skew 1.2 --mode both            (CPU stand-in scanner, runs anywhere)
 *   ./bench_gpu --gpu --skew 1.2 --mode both  (GPU, built with `make gpu`)
 *
 * Until Ananyaraj's PCAP reader is ready, flows come from a built-in synthetic generator
 * (flow-size skew set by --skew, a Zipf exponent: 0 = all flows equal). When the reader is
 * ready, fill a `Flows` from it instead of calling make_trace(). */
#define _POSIX_C_SOURCE 200809L
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pipeline.h"
#ifdef USE_GPU
#include "gpu_scan.h"
#endif
#ifdef WITH_PCAP
#include "pcap_bridge.h"
#endif

typedef struct {
    const char* mode; double skew; size_t nflows, total_mb; unsigned seed; float alpha;
    size_t batch_kb, chunk, slice_kb; int sms, block, use_gpu; const char* sigs;
    const char* pcap; int threads; const char* sig_text;
    const char* dump; const char* flows_file; int dump_only;
} Opts;

/* ------------------------------------------------------------------ rng */
static uint64_t rs = 88172645463325252ull;
static uint64_t rnd(void) { rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27; return rs * 2685821657736338717ull; }
static uint64_t rndu(uint64_t n) { return n ? rnd() % n : 0; }
static double frand(void) { return (double)(rnd() >> 11) / 9007199254740992.0; }

/* ----------------------------------------------------------- signatures */
static Pat* default_sigs(size_t* n_out) {
    size_t cap = 400, n = 0;
    Pat* s = (Pat*)calloc(cap, sizeof(Pat));
    /* 8 "sled" signatures: long runs of one byte -- pathological for the scanner */
    const uint8_t sled[8] = { 0x90, 'A', '/', '0', 'a', ' ', '.', '\\' };
    for (int i = 0; i < 8; i++) {
        uint8_t* p = (uint8_t*)malloc(25);
        memset(p, sled[i], 24); p[24] = 'Z';
        s[n].p = p; s[n].len = 25; n++;
    }
    /* 300 ordinary printable patterns, a fifth sharing a common prefix */
    for (int i = 0; i < 300; i++) {
        size_t len = 4 + rndu(29);                    /* 4..32 */
        uint8_t* p = (uint8_t*)malloc(32); size_t k = 0;
        if (i % 5 == 0) { memcpy(p, "/admin/", 7); k = 7; }
        while (k < len) p[k++] = (uint8_t)(32 + rndu(95));
        s[n].p = p; s[n].len = k; n++;
    }
    *n_out = n; return s;
}
static Pat* load_sigs(const char* path, size_t* n_out) {   /* one hex-encoded pattern per line */
    FILE* f = fopen(path, "r");
    if (!f) { perror(path); exit(2); }
    size_t cap = 256, n = 0; Pat* s = (Pat*)calloc(cap, sizeof(Pat));
    char line[4096];
    while (fgets(line, sizeof line, f)) {
        size_t L = strcspn(line, "\r\n"), nb = L / 2;
        if (!nb) continue;
        uint8_t* p = (uint8_t*)malloc(nb);
        for (size_t i = 0; i < nb; i++) { char h[3] = { line[2 * i], line[2 * i + 1], 0 }; p[i] = (uint8_t)strtol(h, NULL, 16); }
        if (n == cap) { cap *= 2; s = (Pat*)realloc(s, cap * sizeof(Pat)); }
        s[n].p = p; s[n].len = nb; n++;
    }
    fclose(f); *n_out = n; return s;
}

/* --------------------------------------------------------------- traces */
enum { RANDOM, TEXT, SLED };

static void plant(uint8_t* b, size_t size, const Pat* s, int64_t at) {
    if (at < 0 || (size_t)at + s->len > size) return;
    memcpy(b + at, s->p, s->len);
}

static void make_trace(const Opts* o, const Pat* sigs, size_t nsigs, Flows* F) {
    const size_t n = o->nflows;
    double* w = (double*)malloc(n * sizeof(double)); double sum = 0;
    for (size_t i = 0; i < n; i++) sum += (w[i] = pow((double)(i + 1), -o->skew));
    size_t* rank = (size_t*)malloc(n * sizeof(size_t));      /* shuffled so elephants are not always first */
    for (size_t i = 0; i < n; i++) rank[i] = i;
    for (size_t i = n; i > 1; i--) { size_t j = rndu(i), t = rank[i - 1]; rank[i - 1] = rank[j]; rank[j] = t; }
    double total = (double)o->total_mb * 1024 * 1024;
    const size_t slice = o->slice_kb * 1024;

    F->n = n;
    F->data = (uint8_t**)calloc(n, sizeof(uint8_t*)); F->size = (uint64_t*)calloc(n, sizeof(uint64_t));
    F->proto = (uint8_t*)calloc(n, 1); F->port = (uint16_t*)calloc(n, sizeof(uint16_t)); F->key = (uint64_t*)calloc(n, sizeof(uint64_t));
    for (size_t i = 0; i < n; i++) {
        size_t size = (size_t)(total * w[rank[i]] / sum); if (size < 64) size = 64;
        /* the port decides the PRIOR, the content decides the TRUTH. They disagree sometimes,
         * which is exactly what the feedback has to repair. */
        double u = frand(), v; uint16_t port; uint8_t proto = 6; int kind;
        if (u < 0.35)      { port = 80;  v = frand(); kind = v < 0.60 ? TEXT : v < 0.85 ? RANDOM : SLED; }
        else if (u < 0.70) { port = 443; kind = frand() < 0.95 ? RANDOM : SLED; }
        else if (u < 0.85) { port = 53; proto = 17; kind = frand() < 0.7 ? TEXT : RANDOM; }
        else               { port = 25;  kind = frand() < 0.8 ? TEXT : RANDOM; }
        F->proto[i] = proto; F->port[i] = port; F->key[i] = 0x9e3779b97f4a7c15ull * (i + 1);
        F->size[i] = size;
        uint8_t* b = F->data[i] = (uint8_t*)malloc(size);
        if (kind == RANDOM) {
            for (size_t p = 0; p < size; p++) b[p] = (uint8_t)rnd();
        } else if (kind == TEXT) {
            size_t p = 0;
            while (p < size) {
                if (rnd() & 1) {   /* a signature prefix: a few steps deep, then fail */
                    const Pat* s = &sigs[rndu(nsigs)];
                    size_t L = 1 + rndu(s->len > 1 ? s->len - 1 : 1);
                    for (size_t j = 0; j < L && p < size; j++) b[p++] = s->p[j];
                } else {
                    size_t L = 4 + rndu(13);
                    for (size_t j = 0; j < L && p < size; j++) b[p++] = (uint8_t)(32 + rndu(95));
                }
            }
        } else {                   /* SLED: one repeated byte with an occasional break */
            uint8_t c = sigs[rndu(8)].p[0];
            for (size_t p = 0; p < size; p++) b[p] = (rndu(600) == 0) ? (uint8_t)rnd() : c;
        }
        /* plant real signatures: random places, plus some straddling window and chunk cuts */
        for (int k = 0; k < 3; k++) plant(b, size, &sigs[8 + rndu(nsigs - 8)], (int64_t)rndu(size));
        for (int k = 0; k < 3 && size > slice + 64; k++) {
            const Pat* s = &sigs[8 + rndu(nsigs - 8)];
            plant(b, size, s, (int64_t)((1 + rndu(size / slice)) * slice) - (int64_t)(1 + rndu(s->len - 1)));
        }
        for (int k = 0; k < 3 && size > o->chunk + 64; k++) {
            const Pat* s = &sigs[8 + rndu(nsigs - 8)];
            plant(b, size, s, (int64_t)((1 + rndu(size / o->chunk)) * o->chunk) - (int64_t)(1 + rndu(s->len - 1)));
        }
    }
    free(w); free(rank);
}

/* ----------------------------------------------------------- the oracle
 * Scan every flow whole, uncut, no carry: the ground truth for "the right alerts". */
static void oracle(const Flows* F, const Pfac* sc, AlertVec* out) {
    uint64_t mx = 1;
    for (size_t i = 0; i < F->n; i++) if (F->size[i] > mx) mx = F->size[i];
    uint32_t* st = (uint32_t*)malloc((size_t)mx * sizeof(uint32_t));
    MatchVec mv = {0};
    for (uint32_t i = 0; i < F->n; i++) {
        Segment seg = { i, 0, (uint32_t)F->size[i], 0 }; uint64_t fp = 0;
        Batch b; batch_init(&b);
        b.arena = F->data[i]; b.arena_len = (size_t)F->size[i]; b.segs = &seg; b.flow_pos = &fp; b.nsegs = 1;
        pfac_scan(sc, &b, &mv, st);
        append_alerts(&b, &mv, out);
    }
    alerts_sort(out);
    free(st); free(mv.v);
}

/* alerts of a (sorted) that are not in b (sorted) */
static size_t count_missing(const AlertVec* a, const AlertVec* b) {
    size_t i = 0, j = 0, miss = 0;
    while (i < a->n) {
        int c = j < b->n ? alert_cmp(&a->v[i], &b->v[j]) : -1;
        if (c < 0) { miss++; i++; } else if (c == 0) { i++; j++; } else j++;
    }
    return miss;
}
static int same_alerts(const AlertVec* a, const AlertVec* b) {
    if (a->n != b->n) return 0;
    for (size_t i = 0; i < a->n; i++) if (alert_cmp(&a->v[i], &b->v[i])) return 0;
    return 1;
}

/* ------------------------------------------------- flows file (libpcap-free hand-off)
 * format: "FLW1", u64 n, then per flow: u8 proto, u16 port, u64 key, u64 size, size bytes. */
static void save_flows(const char* path, const Flows* F) {
    FILE* f = fopen(path, "wb");
    if (!f) { perror(path); exit(2); }
    uint64_t n = F->n;
    fwrite("FLW1", 1, 4, f); fwrite(&n, 8, 1, f);
    for (size_t i = 0; i < F->n; i++) {
        fwrite(&F->proto[i], 1, 1, f); fwrite(&F->port[i], 2, 1, f); fwrite(&F->key[i], 8, 1, f);
        fwrite(&F->size[i], 8, 1, f); fwrite(F->data[i], 1, (size_t)F->size[i], f);
    }
    fclose(f);
}
static void load_flows(const char* path, Flows* F) {
    FILE* f = fopen(path, "rb");
    char magic[4]; uint64_t n;
    if (!f || fread(magic, 1, 4, f) != 4 || memcmp(magic, "FLW1", 4) || fread(&n, 8, 1, f) != 1) { fprintf(stderr, "bad flows file %s\n", path); exit(2); }
    F->n = (size_t)n;
    F->data = (uint8_t**)calloc(F->n, sizeof(uint8_t*)); F->size = (uint64_t*)calloc(F->n, 8);
    F->proto = (uint8_t*)calloc(F->n, 1); F->port = (uint16_t*)calloc(F->n, 2); F->key = (uint64_t*)calloc(F->n, 8);
    for (size_t i = 0; i < F->n; i++) {
        if (fread(&F->proto[i], 1, 1, f) != 1 || fread(&F->port[i], 2, 1, f) != 1 || fread(&F->key[i], 8, 1, f) != 1 ||
            fread(&F->size[i], 8, 1, f) != 1) { fprintf(stderr, "truncated flows file\n"); exit(2); }
        F->data[i] = (uint8_t*)malloc(F->size[i] ? (size_t)F->size[i] : 1);
        if (fread(F->data[i], 1, (size_t)F->size[i], f) != F->size[i]) { fprintf(stderr, "truncated flows file\n"); exit(2); }
    }
    fclose(f);
}

/* ----------------------------------------------------------------- main */
int main(int argc, char** argv) {
    Opts o = { "both", 1.0, 2000, 16, 1, 0.3f, 1024, 4096, 64, 16, 256, 0, NULL, NULL, 0, NULL, NULL, NULL, 0 };
    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        #define NEXT() (i + 1 < argc ? argv[++i] : (fprintf(stderr, "missing value for %s\n", a), exit(2), (char*)0))
        if      (!strcmp(a, "--mode"))     o.mode = NEXT();
        else if (!strcmp(a, "--skew"))     o.skew = atof(NEXT());
        else if (!strcmp(a, "--flows"))    o.nflows = (size_t)atol(NEXT());
        else if (!strcmp(a, "--total-mb")) o.total_mb = (size_t)atol(NEXT());
        else if (!strcmp(a, "--seed"))     o.seed = (unsigned)atoi(NEXT());
        else if (!strcmp(a, "--alpha"))    o.alpha = (float)atof(NEXT());
        else if (!strcmp(a, "--batch-kb")) o.batch_kb = (size_t)atol(NEXT());
        else if (!strcmp(a, "--chunk"))    o.chunk = (size_t)atol(NEXT());
        else if (!strcmp(a, "--slice-kb")) o.slice_kb = (size_t)atol(NEXT());
        else if (!strcmp(a, "--sms"))      o.sms = atoi(NEXT());
        else if (!strcmp(a, "--sigs"))     o.sigs = NEXT();
        else if (!strcmp(a, "--gpu"))      o.use_gpu = 1;
        else if (!strcmp(a, "--pcap"))     o.pcap = NEXT();
        else if (!strcmp(a, "--dump-flows")) o.dump = NEXT();        /* save reassembled flows (run where libpcap exists) */
        else if (!strcmp(a, "--flows-file")) o.flows_file = NEXT();  /* load them (no libpcap needed, e.g. on Kaggle) */
        else if (!strcmp(a, "--dump-only"))  o.dump_only = 1;
        else if (!strcmp(a, "--threads"))  o.threads = atoi(NEXT());
        else if (!strcmp(a, "--sig-text")) o.sig_text = NEXT();   /* comma-separated ASCII signatures to add */
        else { fprintf(stderr, "unknown flag %s\n", a); return 2; }
    }
#ifndef USE_GPU
    if (o.use_gpu) { fprintf(stderr, "--gpu needs a build with `make gpu`\n"); return 2; }
#endif
    rs ^= (uint64_t)o.seed * 0x9e3779b97f4a7c15ull; for (int i = 0; i < 8; i++) rnd();

    size_t nsigs; Pat* sigs = o.sigs ? load_sigs(o.sigs, &nsigs) : default_sigs(&nsigs);
    if (o.sig_text) {                                   /* add ASCII signatures (e.g. the ones passed to generate_pcap.py --pattern) */
        char* tmp = strdup(o.sig_text);
        for (char* t = strtok(tmp, ","); t; t = strtok(NULL, ",")) {
            sigs = (Pat*)realloc(sigs, (nsigs + 1) * sizeof(Pat));
            sigs[nsigs].p = (const uint8_t*)strdup(t); sigs[nsigs].len = strlen(t); nsigs++;
        }
        free(tmp);
    }
    if (nsigs < 9) { fprintf(stderr, "need at least 9 signatures\n"); return 2; }
    Pfac sc; pfac_build(&sc, sigs, nsigs);
    Flows F;
    if (o.pcap) {
#ifdef WITH_PCAP
        PcapFlows pf;
        if (pcap_load_flows(o.pcap, o.threads, &pf)) { fprintf(stderr, "failed to load %s\n", o.pcap); return 2; }
        F.n = pf.n;
        F.data = (uint8_t**)malloc(pf.n * sizeof(uint8_t*)); F.size = (uint64_t*)malloc(pf.n * sizeof(uint64_t));
        F.proto = pf.proto; F.port = pf.port; F.key = pf.key;
        for (size_t i = 0; i < pf.n; i++) { F.data[i] = pf.arena + pf.offset[i]; F.size[i] = pf.len[i]; }
        printf("pcap: %s -> %zu flows, %.1f KB reassembled, %u incomplete, I/O %.2f ms, ingest %.2f ms\n",
               o.pcap, pf.n, pf.arena_len / 1024.0, pf.incomplete, pf.load_ms, pf.process_ms);
#else
        fprintf(stderr, "--pcap needs the integrated build (make)\n"); return 2;
#endif
    } else if (o.flows_file) {
        load_flows(o.flows_file, &F);
    } else make_trace(&o, sigs, nsigs, &F);
    if (o.dump) { save_flows(o.dump, &F); printf("saved %zu flows to %s\n", F.n, o.dump); if (o.dump_only) return 0; }

    ComposeCfg cfg = { o.batch_kb * 1024, o.chunk, sc.maxlen };
    char skewbuf[32];
    uint64_t total = 0; for (size_t i = 0; i < F.n; i++) total += F.size[i];
    printf("trace: %zu flows, %.1f MB, %s, %zu signatures (lmax=%zu), seed=%u, scanner=%s\n",
           F.n, total / 1048576.0, (o.pcap || o.flows_file) ? "from capture" : (sprintf(skewbuf, "skew=%.2f", o.skew), skewbuf), sc.nsigs, cfg.lmax, o.seed, o.use_gpu ? "GPU" : "CPU stand-in");
    printf("config: batch=%zuKB chunk=%zuB window-slice=%zuKB alpha=%.2f  model: %d SMs, %d-thread blocks\n\n",
           o.batch_kb, o.chunk, o.slice_kb, o.alpha, o.sms, o.block);

    AlertVec truth = {0}; oracle(&F, &sc, &truth);

    struct { const char* name; ComposeFn fn; } rows[2]; int nr = 0;
    if (!strcmp(o.mode, "static")   || !strcmp(o.mode, "both")) { rows[nr].name = "static";   rows[nr++].fn = static_compose; }
    if (!strcmp(o.mode, "adaptive") || !strcmp(o.mode, "both")) { rows[nr].name = "adaptive"; rows[nr++].fn = adaptive_compose; }
    if (!nr) { fprintf(stderr, "--mode must be static|adaptive|both\n"); return 2; }

    struct GpuScanner* gpu = NULL;
#ifdef USE_GPU
    if (o.use_gpu) gpu = (struct GpuScanner*)gpu_create(sc.next, sc.term, sc.nnodes, cfg.batch_bytes, cfg.batch_bytes, 1u << 18);
#endif
    RunStats st[2]; AlertVec al[2] = {{0}, {0}};
    for (int k = 0; k < nr; k++) {
        CostPredictor pred; pred_init(&pred, o.alpha, F.n);
        for (uint32_t i = 0; i < F.n; i++) pred_register(&pred, i, F.key[i], F.proto[i], F.port[i]);
        run_pipeline(rows[k].fn, &F, &pred, &sc, &cfg, o.slice_kb * 1024, o.sms, o.block, gpu, &al[k], &st[k]);
        pred_free(&pred);
    }

    printf("%-9s %7s %9s %9s %9s %9s %9s %11s %9s\n", "mode", "batches", "compose", o.use_gpu ? "scan(gpu)" : "scan(cpu)", "wall",
           "warp-eff", "heavy/avg", "model-time", "alerts");
    for (int k = 0; k < nr; k++) {
        const RunStats* s = &st[k];
        if (o.use_gpu)
            printf("%-9s %7zu %7.0fms %7.0fms %7.0fms %9s %9s %11s %9zu\n", rows[k].name, s->batches, s->compose_ms,
                   s->scan_ms, s->wall_ms, "n/a", "n/a", "n/a", al[k].n);
        else
            printf("%-9s %7zu %7.0fms %7.0fms %7.0fms %8.1f%% %9.2f %11.0f %9zu\n", rows[k].name, s->batches, s->compose_ms,
                   s->scan_ms, s->wall_ms, s->warp_steps ? 100.0 * (double)s->steps / (32.0 * (double)s->warp_steps) : 0.0,
                   s->worst_batch_ratio, s->model_makespan, al[k].n);
    }
    if (nr == 2) {
        if (o.use_gpu)
            printf("\nmeasured speedup, wall (static / adaptive): %.3fx   scan only: %.3fx\n",
                   st[0].wall_ms / st[1].wall_ms, st[0].scan_ms / st[1].scan_ms);
        else
            printf("\nmodelled GPU speedup (static / adaptive): %.3fx   (model only -- the real number comes from the GPU run)\n",
                   st[0].model_makespan / st[1].model_makespan);
    }

    int rc = 0;
    printf("\ncorrectness (oracle = every flow scanned whole, no cuts: %zu alerts)\n", truth.n);
    for (int k = 0; k < nr; k++) {
        size_t missed = count_missing(&truth, &al[k]), extra = count_missing(&al[k], &truth);
        int ok = same_alerts(&al[k], &truth);
        printf("  %-9s missed=%zu extra=%zu  %s\n", rows[k].name, missed, extra, ok ? "PASS" : "FAIL");
        if (!ok) rc = 1;
    }
    if (nr == 2) {
        int same = same_alerts(&al[0], &al[1]);
        printf("  static vs adaptive alert sets: %s\n", same ? "IDENTICAL" : "DIFFER  <-- tail-carry or de-dup bug");
        if (!same) rc = 1;
    }
#ifdef USE_GPU
    if (gpu) gpu_destroy((GpuScanner*)gpu);
#endif
    return rc;
}
