/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon3.h -- OCTEON-III (PKI/SSO/PKO3) backend types.
 *
 * The PKO3 send descriptors are declared here as FFN's own structs, not the
 * SDK's, for two reasons: the assembly logic can then be unit-tested with no SDK
 * present, and the test can assert the exact field values that matter for buffer
 * ownership. On hardware these are translated into the SDK's cvmx_pko_send_*
 * types and written into the LMTLINE in this order.
 */
#ifndef FFN_DP_IO_OCTEON3_H
#define FFN_DP_IO_OCTEON3_H

#include "ffn_dp_io_octeon.h"
#include <stdint.h>

/* PKO3 send sub-descriptor codes. */
#define PKO3_SUBDC_HDR      0x0
#define PKO3_SUBDC_GATHER   0x1
#define PKO3_SUBDC_LINK     0x3
#define PKO3_SUBDC_FREE     0x6

/* One LMTLINE holds a bounded number of 64-bit words; exceeding it would run
 * past the line, so a packet needing more segments than this is refused rather
 * than truncated. */
#define PKO3_MAX_WORDS 16

/* SEND_HDR: exactly one per packet, always the first word.
 *
 * `aura` and `df` together decide who owns the packet data after transmit:
 *   df = 0  -> PKO3 returns the buffer to `aura` once it is on the wire, so the
 *              caller must NOT free it (this is the forward path);
 *   df = 1  -> PKO3 leaves the buffer alone and the caller still owns it.
 * `aura` must be the aura the DATA came from, which on OCTEON-III is not
 * necessarily the aura the WQE came from. */
struct pko3_send_hdr {
    uint32_t total;         /* total bytes in the packet            */
    uint16_t aura;          /* aura PKO3 returns the data buffer to */
    uint8_t  df;            /* 1 = don't free (caller keeps it)     */
    uint8_t  ii;            /* ignore-I                             */
    uint8_t  subdc;
};

/* SEND_LINK: one per buffer segment. */
struct pko3_send_link {
    uint64_t addr;
    uint16_t size;
    uint16_t aura;
    uint8_t  subdc;
};

/* A fully staged descriptor list. Assembled in full, then issued as one LMTDMA:
 * a partially written descriptor wedges the descriptor queue, so there is
 * deliberately no incremental path. */
struct pko3_desc {
    struct pko3_send_hdr  hdr;
    struct pko3_send_link link[PKO3_MAX_WORDS - 1];
    int    nlink;
    int    words;           /* 1 (hdr) + nlink */
};

/* Build the descriptor list for one packet.
 * keep_data = 0 -> PKO3 frees the data to its aura after the wire (forwarding)
 * keep_data = 1 -> caller retains ownership
 * Returns DP_OK, or DP_ERR_TOOMANY if the segment count would overrun the LMTLINE
 * (in which case nothing usable is produced and the caller must not issue). */
int oct3_build_desc(struct pko3_desc *d, const struct oct_wqe *w, int keep_data);

#endif /* FFN_DP_IO_OCTEON3_H */
