/**
 * tcp_reassembly.cpp
 *
 * Reassembles TCP payload bytes into the correct sequence order.
 *
 * Beginner guide:
 *   • TCP splits application data into segments and numbers each byte
 *     with a "sequence number". If packets arrive out of order (e.g.
 *     packet 3 arrives before packet 2), we must buffer packet 3 and
 *     wait for packet 2 before we can hand data to the application.
 *   • We store out-of-order segments in a std::map<seq, data>.
 *     std::map keeps keys (sequence numbers) sorted, which makes
 *     draining easy: we keep taking the smallest key until we hit a gap.
 *   • "first-wins" overlap policy: if a retransmission contradicts
 *     already-accepted data, we keep the original.
 *   • TCP sequence numbers are 32-bit and wrap around after ~4 GB.
 *     We use a helper to handle wrap-around comparisons.
 */

#include "tcp_reassembly.h"
#include <cstring>
#include <cstdio>
#include <algorithm>

/* -----------------------------------------------------------------------
 * Sequence number arithmetic — wrap-around safe.
 *
 * TCP sequence numbers are unsigned 32-bit and wrap from 0xFFFFFFFF
 * back to 0x00000000.
 *
 * seq_lt(a, b)  — true if sequence number a comes before b
 * seq_le(a, b)  — true if a <= b in sequence space
 * seq_diff(a,b) — how many bytes from a to b (assuming b is ahead)
 * --------------------------------------------------------------------- */
static inline bool seq_lt(uint32_t a, uint32_t b)
{
    /* Treat the difference as a signed 32-bit number.
     * If the result is negative, a is "before" b. */
    return static_cast<int32_t>(a - b) < 0;
}

static inline bool seq_le(uint32_t a, uint32_t b)
{
    return static_cast<int32_t>(a - b) <= 0;
}

static inline uint32_t seq_diff(uint32_t later, uint32_t earlier)
{
    return later - earlier; /* unsigned subtraction wraps correctly */
}

/* -----------------------------------------------------------------------
 * reassembly_buffer_init
 * --------------------------------------------------------------------- */
ReassemblyBuffer reassembly_buffer_init(uint32_t flow_id)
{
    ReassemblyBuffer buf{};
    buf.flow_id          = flow_id;
    buf.next_seq         = 0;
    buf.initialized      = false;
    buf.ooo_bytes        = 0;
    buf.retransmit_count = 0;
    buf.ooo_drop_count   = 0;
    buf.has_gaps         = false;
    return buf;
}

/* -----------------------------------------------------------------------
 * drain_contiguous — internal helper.
 *
 * Drains as many consecutive segments as possible from ooo_buffer into
 * contiguous_data. Advances next_seq as we go.
 * --------------------------------------------------------------------- */
static void drain_contiguous(ReassemblyBuffer& buf)
{
    while (!buf.ooo_buffer.empty()) {
        auto it = buf.ooo_buffer.begin();
        uint32_t seg_seq = it->first;
        std::vector<uint8_t>& seg_data = it->second;

        if (seg_seq == buf.next_seq) {
            /* This segment starts exactly where we need it — accept it */
            buf.contiguous_data.insert(buf.contiguous_data.end(),
                                       seg_data.begin(), seg_data.end());
            buf.next_seq += static_cast<uint32_t>(seg_data.size());
            buf.ooo_bytes -= seg_data.size();
            buf.ooo_buffer.erase(it);

        } else if (seq_lt(seg_seq, buf.next_seq)) {
            /* This segment starts before next_seq — it overlaps already-
             * accepted data. Apply "first-wins": trim or discard. */
            uint32_t seg_end = seg_seq + static_cast<uint32_t>(seg_data.size());
            if (seq_le(seg_end, buf.next_seq)) {
                /* Entire segment is within already-accepted range → retransmit */
                buf.retransmit_count++;
                buf.ooo_bytes -= seg_data.size();
                buf.ooo_buffer.erase(it);
            } else {
                /* Segment partially overlaps; trim the leading overlap */
                uint32_t trim = seq_diff(buf.next_seq, seg_seq);
                std::vector<uint8_t> trimmed(seg_data.begin() + trim,
                                             seg_data.end());
                buf.retransmit_count++;
                buf.ooo_bytes -= seg_data.size();
                buf.ooo_buffer.erase(it);

                /* Re-insert the trimmed portion at next_seq */
                buf.ooo_bytes += trimmed.size();
                buf.ooo_buffer[buf.next_seq] = std::move(trimmed);
            }

        } else {
            /* seg_seq > next_seq: there is a gap — stop draining */
            break;
        }
    }
}

/* -----------------------------------------------------------------------
 * reassembly_add_segment
 * --------------------------------------------------------------------- */
void reassembly_add_segment(ReassemblyBuffer& buf,
                            uint32_t seq,
                            const uint8_t* data,
                            uint16_t len)
{
    if (len == 0) return;

    /* First segment initialises next_seq */
    if (!buf.initialized) {
        buf.next_seq    = seq;
        buf.initialized = true;
    }

    uint32_t seg_end = seq + static_cast<uint32_t>(len);

    /* Case 1: Segment is entirely behind next_seq → pure retransmission */
    if (seq_le(seg_end, buf.next_seq)) {
        buf.retransmit_count++;
        return;
    }

    /* Case 2: Segment starts at or after next_seq → buffer it */
    /* Trim any leading overlap (first-wins) */
    uint32_t effective_seq  = seq;
    const uint8_t* eff_data = data;
    uint16_t eff_len        = len;

    if (seq_lt(seq, buf.next_seq)) {
        uint32_t trim  = seq_diff(buf.next_seq, seq);
        effective_seq  = buf.next_seq;
        eff_data      += trim;
        eff_len        = static_cast<uint16_t>(len - trim);
        buf.retransmit_count++;
    }

    /* Check if this exact sequence start is already buffered (duplicate) */
    auto existing = buf.ooo_buffer.find(effective_seq);
    if (existing != buf.ooo_buffer.end()) {
        /* First-wins: keep the earlier-received data, discard this one */
        buf.retransmit_count++;
        return;
    }

    /* OOO buffer cap check */
    if (buf.ooo_bytes + eff_len > OOO_BUFFER_LIMIT) {
        buf.ooo_drop_count++;
        return;
    }

    /* Insert into out-of-order buffer */
    buf.ooo_buffer[effective_seq] = std::vector<uint8_t>(eff_data,
                                                          eff_data + eff_len);
    buf.ooo_bytes += eff_len;

    /* Try to drain any now-contiguous data */
    drain_contiguous(buf);
}

/* -----------------------------------------------------------------------
 * reassembly_finalize
 * --------------------------------------------------------------------- */
void reassembly_finalize(ReassemblyBuffer& buf)
{
    /* Do one final drain pass */
    drain_contiguous(buf);

    /* Any remaining entries in ooo_buffer represent gaps */
    if (!buf.ooo_buffer.empty()) {
        buf.has_gaps = true;

        /* Walk the sorted map to record gap ranges */
        uint32_t expected = buf.next_seq;
        for (const auto& kv : buf.ooo_buffer) {
            uint32_t seg_seq = kv.first;
            if (seq_lt(expected, seg_seq)) {
                SeqGap gap;
                gap.start_seq = expected;
                gap.end_seq   = seg_seq;
                buf.gaps.push_back(gap);
            }
            expected = seg_seq + static_cast<uint32_t>(kv.second.size());
        }
        /* Note: we do NOT append the stranded OOO data, because we
         * cannot determine whether the gap will ever be filled.
         * Incomplete flows are flagged via has_gaps = true. */
    }
}

/* -----------------------------------------------------------------------
 * reassembly_print_stats
 * --------------------------------------------------------------------- */
void reassembly_print_stats(const ReassemblyBuffer& buf)
{
    printf("  Flow %u: contiguous=%zu bytes, retransmits=%llu, "
           "ooo_drops=%llu, gaps=%zu, complete=%s\n",
           buf.flow_id,
           buf.contiguous_data.size(),
           (unsigned long long)buf.retransmit_count,
           (unsigned long long)buf.ooo_drop_count,
           buf.gaps.size(),
           buf.has_gaps ? "NO (gaps remain)" : "YES");
}
