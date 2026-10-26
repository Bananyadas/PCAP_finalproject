/* composer.h -- the two batch composers. SAME signature, SAME inputs, SAME outputs;
 * only the packing decision differs. That is what makes the comparison honest. */
#ifndef COMPOSER_H
#define COMPOSER_H
#include "contracts.h"
#include "predictor.h"

typedef struct {
    size_t batch_bytes;  /* arena capacity per batch (carry bytes included) */
    size_t chunk_bytes;  /* adaptive only: largest piece a flow is cut into */
    size_t lmax;         /* longest signature in bytes; carry = lmax - 1 */
} ComposeCfg;

typedef void (*ComposeFn)(const FlowInput* flows, size_t nflows, const CostPredictor* pred,
                          const ComposeCfg* cfg, BatchList* out);

/* Baseline: flows in arrival order, filled front to back, cut where a batch is full. */
void static_compose(const FlowInput* flows, size_t nflows, const CostPredictor* pred,
                    const ComposeCfg* cfg, BatchList* out);
/* Ours: cut flows into chunks, deal chunks over batches so predicted cost is level,
 * expensive chunks first inside each batch. */
void adaptive_compose(const FlowInput* flows, size_t nflows, const CostPredictor* pred,
                      const ComposeCfg* cfg, BatchList* out);
#endif
