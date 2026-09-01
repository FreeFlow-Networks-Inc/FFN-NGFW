/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon3.h -- OCTEON-III (PKI/SSO/PKO3) backend types.
 *
 * The PKO3 send descriptor is declared here as FFN's own struct, not the SDK's,
 * so the assembly logic can be unit-tested with no SDK present and the test can
 * assert the exact field values that decide buffer ownership. On hardware the
 * same values are handed to the SDK's transmit call, and the build asserts that
 * FFN's sub-descriptor codes still match the SDK's (see ffn_dp_io_octeon3.c) --
 * a mismatch fails the build instead of wedging a descriptor queue.
 *
 * These encodings are the hardware's, taken from PKO_SEND_*_S. They were WRONG
 * in the first version of this file, which invented them: it had LINK = 0x3 and
 * a SEND_HDR "sub-descriptor code" of 0x0, when 0x0 is in fact LINK and SEND_HDR
 * has no code at all -- it is identified by being word 0 of the descriptor.
 * Writing 0x3 into a SUBDC3 field selects nothing valid, so every transmit would
 * have been rejected by the DQ (PKO_DQSTATUS_SENDPKTDROP, "illegal construct").
 */
#ifndef FFN_DP_IO_OCTEON3_H
#define FFN_DP_IO_OCTEON3_H

#include "ffn_dp_io_octeon.h"
#include <stdint.h>

/* PKO_SEND_*_S sub-command codes.
 *
 * SUBDC3 is the 3-bit field in a buffer-pointer word (PKO_SEND_LINK_S,
 * PKO_SEND_GATHER_S, PKO_SEND_JUMP_S all share that layout); SUBDC4 is the
 * 4-bit field used by the other sub-descriptors. They are separate encodings
 * living in different bit positions, so a SUBDC4 value must never be written
 * into a SUBDC3 field. */
#define PKO3_SUBDC3_LINK    0x0     /* buffer, chained via the word at addr-8 */
#define PKO3_SUBDC3_GATHER  0x1     /* buffer, one segment only               */
#define PKO3_SUBDC3_JUMP    0x2
#define PKO3_SUBDC4_TSO     0x8
#define PKO3_SUBDC4_FREE    0x9

/* PKO_SEND_HDR_S field limits that the caller can violate. `total` is 16 bits,
 * so a packet longer than this cannot be described at all; `aura` is 12 bits,
 * which is exactly the (node << 10) | local_aura form FPA3 uses. */
#define PKO3_MAX_TOTAL      0xFFFFu
#define PKO3_MAX_AURA       0x0FFFu

/* SEND_HDR: exactly one per packet, always word 0. It has no sub-descriptor
 * code -- position is what identifies it.
 *
 * `aura`, `df` and `ii` together decide who owns the packet data after
 * transmit:
 *   ii = 1  -> the per-buffer `i` bits are ignored and `df` alone decides;
 *   df = 0  -> PKO3 returns every buffer of the packet to `aura` once it is on
 *              the wire, so the caller must NOT free it (the forward path);
 *   df = 1  -> PKO3 leaves the buffers alone and the caller still owns them.
 * `aura` must be the aura the DATA came from. */
struct pko3_send_hdr {
    uint32_t total;         /* total bytes in the packet            */
    uint16_t aura;          /* aura PKO3 returns the data buffer to */
    uint8_t  df;            /* 1 = don't free (caller keeps it)     */
    uint8_t  ii;            /* 1 = ignore the per-buffer `i` bits   */
};

/* SEND_LINK: the first buffer of a PKI-chained packet. ONE of these describes
 * the whole packet however many buffers it occupies, because LINK tells PKO3 to
 * follow the chain: PKI stores the next buffer's pointer in the 8 bytes just
 * below each segment's data. Emitting one LINK per segment (which this file
 * used to do) describes a different, wrong packet. */
struct pko3_send_link {
    uint64_t addr;          /* first byte of the data, not of the buffer */
    uint16_t size;          /* bytes in THIS segment                     */
    uint8_t  subdc;         /* PKO3_SUBDC3_LINK                          */
};

/* A fully staged descriptor. Assembled in full, then issued as one LMTDMA: a
 * partially written descriptor wedges the DQ, so there is deliberately no
 * incremental path. */
struct pko3_desc {
    struct pko3_send_hdr  hdr;
    struct pko3_send_link link;
    int    words;           /* always 2: HDR + LINK */
    /* The SDK's transmit call takes ownership as a signed aura: negative means
     * "don't free". Kept here so the mapping from FFN's keep_data flag onto
     * that convention is one place, and is what the test pins down. */
    int    gaura;
};

/* Build the descriptor for one packet.
 * keep_data = 0 -> PKO3 frees the data to its aura after the wire (forwarding)
 * keep_data = 1 -> caller retains ownership
 * Returns DP_OK, or DP_ERR_TOOMANY if the packet cannot be described (zero
 * length, no data pointer, longer than PKO_SEND_HDR_S[TOTAL], or an aura that
 * does not fit the header field). On refusal nothing usable is produced and the
 * caller must not issue. */
int oct3_build_desc(struct pko3_desc *d, const struct oct_wqe *w, int keep_data);

#endif /* FFN_DP_IO_OCTEON3_H */
