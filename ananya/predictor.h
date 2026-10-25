/* predictor.h -- per-flow scan-cost predictor.
 * First guess from protocol/port, then an EWMA of the cost the GPU measured:
 *     est = alpha*measured + (1-alpha)*est
 * "cost" = kernel steps per byte (1.0 = every position rejected after one byte). */
#ifndef PREDICTOR_H
#define PREDICTOR_H
#include "contracts.h"

typedef struct { float alpha; FlowRec* recs; size_t n; } CostPredictor;

void  pred_init(CostPredictor* p, float alpha, size_t nflows);
void  pred_free(CostPredictor* p);
void  pred_copy(CostPredictor* dst, const CostPredictor* src);   /* snapshot */
float pred_prior(uint8_t proto, uint16_t port);                   /* first guess */
void  pred_register(CostPredictor* p, uint32_t flow_id, uint64_t key, uint8_t proto, uint16_t port);
float pred_cost_per_byte(const CostPredictor* p, uint32_t flow_id);
/* feedback: this flow's segment of `bytes` bytes took `steps` kernel steps */
void  pred_update(CostPredictor* p, uint32_t flow_id, uint64_t bytes, uint64_t steps);
#endif
