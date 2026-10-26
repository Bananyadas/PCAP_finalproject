#include "predictor.h"
#include <stdlib.h>
#include <string.h>

void pred_init(CostPredictor* p, float alpha, size_t n) {
    p->alpha = alpha; p->n = n;
    p->recs = (FlowRec*)calloc(n ? n : 1, sizeof(FlowRec));
    for (size_t i = 0; i < n; i++) p->recs[i].cost_est = 1.0f;
}
void pred_free(CostPredictor* p) { free(p->recs); p->recs = NULL; p->n = 0; }
void pred_copy(CostPredictor* d, const CostPredictor* s) {
    d->alpha = s->alpha; d->n = s->n;
    d->recs = (FlowRec*)malloc((s->n ? s->n : 1) * sizeof(FlowRec));
    memcpy(d->recs, s->recs, s->n * sizeof(FlowRec));
}
/* Starting guesses only -- the EWMA corrects them. Text protocols tend to contain
 * keyword-like bytes that make the scanner walk deeper; encrypted ones die at once. */
float pred_prior(uint8_t proto, uint16_t port) {
    switch (port) {
        case 80: case 8080: case 8000:            return 3.0f;  /* HTTP */
        case 21: case 25: case 110: case 143:     return 2.0f;  /* FTP/SMTP/POP/IMAP */
        case 443: case 993: case 995: case 22:    return 1.0f;  /* encrypted */
        case 53:                                  return 1.5f;  /* DNS */
        default: return proto == 17 ? 1.5f : 1.8f;
    }
}
void pred_register(CostPredictor* p, uint32_t id, uint64_t key, uint8_t proto, uint16_t port) {
    if (id >= p->n) return;
    p->recs[id].key = key; p->recs[id].bytes = 0;
    p->recs[id].cost_est = pred_prior(proto, port);
}
float pred_cost_per_byte(const CostPredictor* p, uint32_t id) {
    return id < p->n ? p->recs[id].cost_est : 1.0f;
}
void pred_update(CostPredictor* p, uint32_t id, uint64_t bytes, uint64_t steps) {
    if (id >= p->n || bytes == 0) return;
    FlowRec* r = &p->recs[id];
    float measured = (float)((double)steps / (double)bytes);
    r->cost_est = p->alpha * measured + (1.0f - p->alpha) * r->cost_est;
    r->bytes += bytes;
}
