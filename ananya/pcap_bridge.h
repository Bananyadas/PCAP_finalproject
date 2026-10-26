/* pcap_bridge.h -- plain-C view of Ananyaraj's PCAP/flow stage (implemented in pcap_bridge.cpp).
 * Deliberately does NOT include contracts.h or his shared.h: both define Segment/Match/FlowRec
 * (identically) and must never meet in one translation unit. */
#ifndef PCAP_BRIDGE_H
#define PCAP_BRIDGE_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint8_t*  arena;  size_t arena_len;     /* every flow's reassembled bytes, back to back */
    uint32_t* offset; uint32_t* len;        /* flow i = arena[offset[i] .. offset[i]+len[i]) */
    uint8_t*  proto;  uint16_t* port;       /* from the flow's 5-tuple (port = destination) */
    uint64_t* key;                          /* FNV-1a hash of the 5-tuple */
    size_t    n;                            /* number of flows; flow_id == index */
    uint32_t  incomplete;                   /* flows that still have a sequence gap */
    double    load_ms, process_ms;          /* file I/O, and everything after it */
} PcapFlows;

/* Returns 0 on success. Reads the whole capture into memory first (I/O timed separately). */
int  pcap_load_flows(const char* path, int threads, PcapFlows* out);
void pcap_free_flows(PcapFlows* f);
#ifdef __cplusplus
}
#endif
#endif
