#define _POSIX_C_SOURCE 200809L
#include "pipeline.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef USE_GPU
#include "gpu_scan.h"
#endif

typedef struct {   /* one compose job, run on its own thread */
    ComposeFn fn; FlowInput* w; size_t nw; CostPredictor snap; const ComposeCfg* cfg;
    BatchList out; double ms; pthread_t th;
} Job;

static void* job_main(void* arg) {
    Job* j = (Job*)arg;
    double t = now_ms();
    j->fn(j->w, j->nw, &j->snap, j->cfg, &j->out);
    j->ms = now_ms() - t;
    return NULL;
}

static Job* job_launch(ComposeFn fn, const Flows* F, size_t k, size_t slice, const CostPredictor* pred,
                       const ComposeCfg* cfg) {
    Job* j = (Job*)calloc(1, sizeof(Job));
    j->w = (FlowInput*)malloc((F->n ? F->n : 1) * sizeof(FlowInput));
    for (uint32_t i = 0; i < F->n; i++) {            /* arrival order = flow index order */
        uint64_t sz = F->size[i];
        if ((uint64_t)k * slice >= sz) continue;
        uint64_t e = (uint64_t)(k + 1) * slice; if (e > sz) e = sz;
        FlowInput f = { i, F->proto[i], F->port[i], F->data[i], sz, (uint64_t)k * slice, e };
        j->w[j->nw++] = f;
    }
    j->fn = fn; j->cfg = cfg;
    pred_copy(&j->snap, pred);                        /* snapshot: no race with pred_update */
    pthread_create(&j->th, NULL, job_main, j);
    return j;
}

void run_pipeline(ComposeFn compose, const Flows* F, CostPredictor* pred, const Pfac* sc,
                  const ComposeCfg* cfg, size_t slice, int sms, int block,
                  struct GpuScanner* gpu, AlertVec* alerts, RunStats* st) {
    memset(st, 0, sizeof *st);
#ifndef USE_GPU
    (void)gpu;
#endif
    uint64_t maxsize = 1;
    for (size_t i = 0; i < F->n; i++) if (F->size[i] > maxsize) maxsize = F->size[i];
    if (slice == 0) slice = (size_t)maxsize;
    size_t nwin = (size_t)((maxsize + slice - 1) / slice);
    st->windows = nwin;

    MatchVec mv = {0};
    uint32_t* pos_steps = NULL; size_t pos_cap = 0;
    uint32_t* seg_cost = NULL; size_t seg_cap = 0;
    double* bsteps = NULL; size_t nbs = 0, bscap = 0;
#ifdef USE_GPU
    Match* gm = gpu ? (Match*)malloc(gpu_max_matches((GpuScanner*)gpu) * sizeof(Match)) : NULL;
#endif

    double wall = now_ms();
    Job* job = job_launch(compose, F, 0, slice, pred, cfg);
    for (size_t k = 0; k < nwin; k++) {
        pthread_join(job->th, NULL);
        BatchList bl = job->out;
        st->compose_ms += job->ms;
        free(job->w); pred_free(&job->snap); free(job);
        job = (k + 1 < nwin) ? job_launch(compose, F, k + 1, slice, pred, cfg) : NULL;  /* compose k+1 while scanning k */

        double ts = now_ms();
#ifdef USE_GPU
        int slot_next = 0;
        if (gpu && bl.n) slot_next = gpu_submit((GpuScanner*)gpu, &bl.v[0]);
#endif
        for (size_t bi = 0; bi < bl.n; bi++) {
            const Batch* b = &bl.v[bi];
            if (b->nsegs > seg_cap) { seg_cap = b->nsegs * 2; seg_cost = (uint32_t*)realloc(seg_cost, seg_cap * sizeof(uint32_t)); }
#ifdef USE_GPU
            if (gpu) {
                int slot = slot_next;
                if (bi + 1 < bl.n) slot_next = gpu_submit((GpuScanner*)gpu, &bl.v[bi + 1]);  /* keep the GPU busy */
                uint32_t nm = 0;
                gpu_collect((GpuScanner*)gpu, slot, gm, &nm, seg_cost);
                mv.n = 0;
                for (uint32_t i = 0; i < nm; i++) matchvec_push(&mv, gm[i]);
                /* heavy/avg on the GPU too: the kernel returns steps per
                 * segment, so the batch total is just their sum. */
                {
                    double tot = 0;
                    for (size_t i = 0; i < b->nsegs; i++) tot += (double)seg_cost[i];
                    if (nbs == bscap) { bscap = bscap ? bscap * 2 : 64; bsteps = (double*)realloc(bsteps, bscap * sizeof(double)); }
                    bsteps[nbs++] = tot;
                }
            } else
#endif
            {
                if (b->arena_len > pos_cap) { pos_cap = b->arena_len * 2; pos_steps = (uint32_t*)realloc(pos_steps, pos_cap * sizeof(uint32_t)); }
                pfac_scan(sc, b, &mv, pos_steps);
                segment_costs(b, pos_steps, seg_cost);
                GpuModel g = model_batch(pos_steps, b->arena_len, block, sms);
                st->steps += g.sum_steps; st->warp_steps += g.sum_warp_max; st->model_makespan += g.makespan;
                if (nbs == bscap) { bscap = bscap ? bscap * 2 : 64; bsteps = (double*)realloc(bsteps, bscap * sizeof(double)); }
                bsteps[nbs++] = (double)g.sum_steps;
            }
            dedupe(b, &mv, sc);
            append_alerts(b, &mv, alerts);
            for (size_t i = 0; i < b->nsegs; i++)             /* feedback: measured cost -> predictor */
                pred_update(pred, b->segs[i].flow_id, b->segs[i].len, seg_cost[i]);
            st->batches++; st->segments += b->nsegs; st->arena_bytes += b->arena_len;
            for (size_t i = 0; i < b->nsegs; i++) st->payload_bytes += b->segs[i].len - b->segs[i].carry;
        }
        st->scan_ms += now_ms() - ts;
        batchlist_free(&bl);
    }
    st->wall_ms = now_ms() - wall;
    if (nbs) {
        double mean = 0, mx = 0;
        for (size_t i = 0; i < nbs; i++) { mean += bsteps[i]; if (bsteps[i] > mx) mx = bsteps[i]; }
        st->worst_batch_ratio = mx / (mean / (double)nbs);
    }
    alerts_sort(alerts);
    free(mv.v); free(pos_steps); free(seg_cost); free(bsteps);
#ifdef USE_GPU
    free(gm);
#endif
}
