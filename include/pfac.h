#ifndef IDS_PFAC_H
#define IDS_PFAC_H

#include "ids_types.h"
#include <string>
#include <vector>

// Build the flattened PFAC transition table from a set of byte patterns.
// Pattern index == sig_id. Caller owns the result; free with pfac_free.
PfacTable pfac_build(const std::vector<std::string> &patterns);

void   pfac_free(PfacTable *t);
size_t pfac_table_bytes(const PfacTable &t);   // device memory needed

#endif
