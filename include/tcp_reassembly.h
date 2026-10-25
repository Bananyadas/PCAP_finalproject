/**
 * tcp_reassembly.h — Sequence-ordered TCP payload reassembly.
 *
 * One ReassemblyBuffer per flow.
 *
 * Design:
 *   • Segments are stored in a std::map keyed by TCP sequence number.
 *   • `next_seq` tracks the first byte we still need.
 *   • As contiguous data arrives, bytes are drained from the map into
 *     `contiguous_data`.
 *   • Overlap policy (documented, first-wins):
 *       If a new segment overlaps already-accepted bytes, the overlapping
 *       portion is trimmed. Earlier data takes priority.
 *   • Out-of-order buffer is capped at OOO_BUFFER_LIMIT bytes per flow.
 *   • Gaps are recorded in `gaps` when the flow is finalised.
 *   • `carry` field is always 0; downstream batching owns it.
 */

#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include <cstdint>
#include <vector>
#include <map>
#include <string>

/* Maximum bytes held in the out-of-order buffer per flow (64 MiB). */
static constexpr size_t OOO_BUFFER_LIMIT = 64ULL * 1024 * 1024;

/* -----------------------------------------------------------------------
 * SeqSegment — one buffered out-of-order TCP payload chunk.
 * --------------------------------------------------------------------- */
struct SeqSegment {
    uint32_t             seq;   /* TCP sequence number of first byte    */
    std::vector<uint8_t> data;  /* payload bytes                        */
};

/* -----------------------------------------------------------------------
 * SeqGap — a range of missing sequence numbers detected at finalisation.
 * --------------------------------------------------------------------- */
struct SeqGap {
    uint32_t start_seq; /* first missing sequence number        */
    uint32_t end_seq;   /* one past the last missing seq number */
};

/* -----------------------------------------------------------------------
 * ReassemblyBuffer — per-flow TCP reassembly state.
 * --------------------------------------------------------------------- */
struct ReassemblyBuffer {
    uint32_t flow_id;

    /* Sequence number of the next expected byte.
     * Initialised to the ISN + 1 when the first SYN is seen,
     * or to the seq of the first data packet if we missed the SYN. */
    uint32_t next_seq;
    bool     initialized; /* false until we receive the first segment   */

    /* Contiguous reassembled payload bytes (already in order). */
    std::vector<uint8_t> contiguous_data;

    /* Out-of-order segments not yet drained, keyed by sequence number.
     * std::map keeps them sorted, making drain efficient. */
    std::map<uint32_t, std::vector<uint8_t>> ooo_buffer;

    /* Bytes currently held in ooo_buffer (for the OOO_BUFFER_LIMIT cap). */
    size_t ooo_bytes;

    /* Sequence gaps detected at finalisation (or during reassembly). */
    std::vector<SeqGap> gaps;

    /* Statistics */
    uint64_t retransmit_count;   /* segments trimmed as retransmissions  */
    uint64_t ooo_drop_count;     /* segments dropped because OOO full    */
    bool     has_gaps;           /* true if any gap was detected         */
};

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

/**
 * reassembly_buffer_init — create a fresh buffer for `flow_id`.
 */
ReassemblyBuffer reassembly_buffer_init(uint32_t flow_id);

/**
 * reassembly_add_segment — feed one TCP payload segment into the buffer.
 *
 * `seq`  — TCP sequence number of the first payload byte.
 * `data` — pointer to payload bytes.
 * `len`  — number of payload bytes.
 *
 * Thread-safety: call only from one thread per buffer (same flow).
 */
void reassembly_add_segment(ReassemblyBuffer& buf,
                            uint32_t seq,
                            const uint8_t* data,
                            uint16_t len);

/**
 * reassembly_finalize — signal end-of-capture for this flow.
 *
 * Scans ooo_buffer for any remaining segments, records gaps, and
 * sets `has_gaps` appropriately.
 */
void reassembly_finalize(ReassemblyBuffer& buf);

/**
 * reassembly_print_stats — print per-flow stats (gaps, retransmits, size).
 */
void reassembly_print_stats(const ReassemblyBuffer& buf);

#endif /* TCP_REASSEMBLY_H */
