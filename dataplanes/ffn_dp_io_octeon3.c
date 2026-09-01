/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon3.c -- OCTEON-III packet-I/O backend (PKI + SSO + PKO3).
 *
 * WHY A SECOND BACKEND RATHER THAN A REWRITE
 * ------------------------------------------
 * The PA-5220's dataplane processor is a CN78XX -- OCTEON III -- whose blocks
 * are PKI (input), SSO (scheduling) and PKO3 (output). The original backend
 * targets OCTEON II (IPD/PIP + POW + PKO), which is what a PA-3200 has. Both are
 * e-waste FFN wants to reclaim, so both stay: they sit behind the same
 * `oct_hw_ops` seam and `oct_detect_gen()` picks one at runtime. One FFN build
 * serves both families.
 *
 * WHAT ACTUALLY DIFFERS (and why it is not a search-and-replace)
 * -------------------------------------------------------------
 *  1. FPA3 frees to an AURA, not a pool. An aura is an indirection in front of a
 *     pool with its own accounting, so returning a buffer to the wrong aura
 *     corrupts counts without any immediate symptom. The aura is GLOBAL --
 *     (node << 10) | local_aura -- because CN78XX is a multi-node part.
 *  2. PKI usually places the WQE INSIDE the first packet buffer. Then the WQE
 *     and the data are ONE allocation and freeing the data frees the WQE too;
 *     freeing both is a double free. Which case a packet is in is recorded in
 *     the buffer pointer, and must be read on RECEIVE -- see the ordering hazard
 *     below.
 *  3. Transmit is a descriptor list (SEND_HDR + SEND_LINK) issued as ONE unit
 *     into a descriptor queue via LMTDMA -- not a prepare/finish pair against a
 *     command queue. A partially written descriptor wedges the DQ.
 *  4. Ownership transfer on send is the SEND_HDR `df` ("don't free") bit plus the
 *     aura in the header. Set the wrong aura and PKO3 credits the wrong pool.
 *  5. The output queue is a DQ resolved from the IPD port at init
 *     (cvmx_pko3_get_queue_base), not a queue number the caller invents.
 *
 * THE ORDERING HAZARD, WHICH IS THE POINT OF THIS FILE
 * ---------------------------------------------------
 * On the forward path PKO3 frees the packet data once it is on the wire. If the
 * WQE lives inside that data buffer, the buffer can be back in its aura and
 * refilled by PKI with a new packet before we get around to the WQE. So the
 * question "is the WQE its own allocation?" MUST be answered on receive, and
 * releasing the WQE must never dereference it -- the address and the aura are
 * enough. This backend captures `wqe_separate`, `data_aura` and the raw buffer
 * pointer in `oct_wqe` at work_get time and never reads the WQE again on the
 * transmit path.
 *
 * LICENSING / WHAT FFN SHIPS
 * -------------------------
 * The CVMX executive sources are Cavium/Marvell 3-clause BSD, so FFN may use
 * them with attribution, but they are still not vendored here: this file is
 * FFN's own code calling that API, gated behind -DFFN_HAVE_CVMX. Built without
 * it (the default) the file compiles and links, reports the backend
 * unavailable, and the dataplane keeps running on AF_PACKET.
 *
 * TESTING STATUS -- read this before trusting it
 * ---------------------------------------------
 * The ownership contract and descriptor assembly are verified by
 * ffn_dp_io_octeon3_test.c against a mock that models FPA3 auras, the
 * WQE-inside-the-buffer case and PKO3's df bit, on both little- and big-endian.
 * The CVMX call sites ARE now compile-checked against a real OCTEON SDK 5.1
 * executive for OCTEON_CN78XX (`make oct3-cvmx SDK=<path>`); the first version
 * of this file was not, and every one of the following was wrong:
 *   * PKO3_SUBDC_LINK was 0x3. The hardware's SUBDC3 code for LINK is 0x0, and
 *     0x3 is not a valid SUBDC3 at all, so every descriptor would have been
 *     rejected by the DQ as an illegal construct.
 *   * SEND_HDR was given a sub-descriptor code. It has none; it is word 0.
 *   * One SEND_LINK was emitted per buffer segment. ONE describes the whole
 *     chain -- LINK means "follow the pointer PKI stored below each segment".
 *   * `cvmx_wqe_pki_get_wqe_aura()` was invented; there is no separate WQE aura.
 *   * `cvmx_sso_set_group_priority()` was called with 3 arguments; it takes 6,
 *     and it tunes scheduler weights rather than doing anything this backend
 *     needs, so it is gone.
 *   * `cvmx_pko3_xmit_link_buf()` was called with a hand-built descriptor and
 *     its result read as a struct; it takes (dq, pki_ptr, len, gaura, counter,
 *     tag) and returns an int.
 * What is still unproven is behaviour on silicon: no packet has yet crossed
 * this path on a live CN78XX.
 */
#include "ffn_dp_io_octeon3.h"

#include <stdint.h>
#include <string.h>

/* Build the descriptor for one packet. Split out from the send path so the test
 * can assert the exact ownership fields with no hardware present.
 *
 * `keep_data` selects ownership: 0 lets PKO3 free the data to its aura after the
 * wire (the normal forward case), 1 keeps it ours (caller will free). */
int oct3_build_desc(struct pko3_desc *d, const struct oct_wqe *w, int keep_data)
{
    if (!d || !w)
        return DP_ERR_TOOMANY;
    /* Refuse anything PKO_SEND_HDR_S cannot express, rather than truncating it
     * into a descriptor that describes a different packet. */
    if (w->len == 0 || w->len > PKO3_MAX_TOTAL)
        return DP_ERR_TOOMANY;
    if (w->pkt_ptr == 0)
        return DP_ERR_TOOMANY;
    if (w->data_aura > PKO3_MAX_AURA)
        return DP_ERR_TOOMANY;

    memset(d, 0, sizeof(*d));

    d->hdr.total = w->len;
    d->hdr.df    = keep_data ? 1 : 0;
    /* ii = 1: the per-buffer `i` bits are ignored and `df` alone decides who
     * frees, for every buffer in the chain. Without this each segment's own bit
     * would govern, and this backend never sets those. */
    d->hdr.ii    = 1;
    /* The aura the DATA came from. Getting this wrong is the whole reason this
     * backend exists separately from the OCTEON-II one. */
    d->hdr.aura  = w->data_aura;

    /* Exactly one LINK, whatever the segment count: it tells PKO3 to walk the
     * chain PKI already built. `size` is this segment's length, which for a
     * single-segment packet equals the total. */
    d->link.subdc = PKO3_SUBDC3_LINK;
    d->link.addr  = FFN_PKI_PTR_ADDR(w->pkt_ptr);
    d->link.size  = FFN_PKI_PTR_SIZE(w->pkt_ptr);
    d->words = 2;

    /* The SDK's transmit call takes ownership as a signed aura: negative means
     * "do not free". Keep that mapping in one place. */
    d->gaura = keep_data ? -1 : (int)w->data_aura;
    return DP_OK;
}

const char *oct_gen_name(enum oct_gen g)
{
    switch (g) {
    case OCT_GEN_II:  return "OCTEON-II (IPD/POW/PKO)";
    case OCT_GEN_III: return "OCTEON-III (PKI/SSO/PKO3)";
    default:          return "none";
    }
}

/* ======================================================================== */
#ifdef FFN_HAVE_CVMX
/* ======================================================================== */

/* Supplied by the operator's OCTEON SDK for their own hardware; never vendored. */
#include "cvmx.h"
#include "cvmx-fpa3.h"
#include "cvmx-helper.h"
#include "cvmx-helper-util.h"
#include "cvmx-packet.h"
#include "cvmx-pko3.h"
#include "cvmx-pko3-queue.h"
#include "cvmx-pow.h"
#include "cvmx-wqe.h"

/* If the SDK ever disagrees with the encodings this backend assembles against,
 * fail the BUILD. The alternative is a descriptor queue that rejects every
 * packet at runtime with no obvious cause. */
typedef char ffn_oct3_subdc_link_matches_sdk
    [(PKO3_SUBDC3_LINK == CVMX_PKO_SENDSUBDC_LINK) ? 1 : -1];
typedef char ffn_oct3_subdc_gather_matches_sdk
    [(PKO3_SUBDC3_GATHER == CVMX_PKO_SENDSUBDC_GATHER) ? 1 : -1];
typedef char ffn_oct3_subdc_free_matches_sdk
    [(PKO3_SUBDC4_FREE == CVMX_PKO_SENDSUBDC_FREE) ? 1 : -1];

/* FFN decodes the PKI buffer pointer with its own macros in the descriptor
 * model and in the test, so that neither needs chip headers. Prove that decode
 * against the SDK's bitfields before any packet moves: if the layout ever
 * disagreed, every descriptor would be silently wrong and the only symptom
 * would be a wedged descriptor queue. */
static int cvmx3_check_ptr_layout(void)
{
    cvmx_buf_ptr_pki_t probe;

    probe.u64 = 0;
    probe.size = 0x1234;
    probe.packet_outside_wqe = 1;
    probe.addr = 0x3FF00000055ULL;

    return FFN_PKI_PTR_SIZE(probe.u64)    == 0x1234 &&
           FFN_PKI_PTR_OUTSIDE(probe.u64) == 1 &&
           FFN_PKI_PTR_ADDR(probe.u64)    == 0x3FF00000055ULL;
}

static int cvmx3_hw_init(struct oct_ctx *c)
{
    int i;

    if (!cvmx3_check_ptr_layout())
        return DP_ERR_NOMEM;

    if (cvmx_user_app_init() != 0)
        return DP_ERR_NOMEM;

    /* Refuse to drive PKI/SSO/PKO3 on a part that does not have them. Selecting
     * the wrong backend means writing the wrong blocks, which is worse than not
     * starting. */
    if (!octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
        return DP_ERR_NOMEM;

    if (cvmx_is_init_core()) {
        if (cvmx_helper_initialize_packet_io_global() != 0)
            return DP_ERR_NOMEM;
    }
    if (cvmx_helper_initialize_packet_io_local() != 0)
        return DP_ERR_NOMEM;

    /* The output queue is a PKO3 descriptor queue, and only the SDK knows which
     * DQ the helper assigned to each IPD port. Whatever the caller put in
     * `pko_queue` is a guess; this is the answer. */
    for (i = 0; i < c->nports; i++) {
        int dq = cvmx_pko3_get_queue_base(c->ports[i].ipd_port);
        if (dq < 0)
            return DP_ERR_NOMEM;
        c->ports[i].pko_queue = dq;
    }

    c->core_id = (int)cvmx_get_core_num();

    /* Which SSO groups this core takes work from. cvmx_helper_initialize_packet
     * _io_local() on CN78XX does nothing but set up the DQ table, and no other
     * SDK call programs SSO_PP(x)_S(y)_GRPMSK(z), so leaving this to a reset
     * default means betting the whole dataplane on an undocumented value: a
     * core with an empty mask simply never receives work, and reports nothing.
     * On CN78XX the mask is in legacy form -- each bit enables eight native
     * groups sharing that number. */
    cvmx_pow_set_group_mask((uint64_t)c->core_id, c->pow_group_mask);

    c->available = 1;
    return DP_OK;
}

static void cvmx3_hw_fini(struct oct_ctx *c) { c->available = 0; }

static int cvmx3_hw_work_get(struct oct_ctx *c, struct oct_wqe *w)
{
    cvmx_wqe_t *wqe;
    cvmx_buf_ptr_pki_t ptr;

    (void)c;
    wqe = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
    if (!wqe)
        return 0;

    memset(w, 0, sizeof(*w));
    w->hw   = wqe;
    w->disp = OCT_DISP_HELD;

    /* Capture everything the disposal path will need BEFORE deciding whether
     * this is a packet worth forwarding. A work item we are about to drop still
     * has to be released correctly, and the release rules depend on these same
     * fields -- an early return here would leave `wqe_separate` at 0 and leak
     * every WQE that arrived with something wrong with it.
     *
     * Use the accessor rather than reading packet_ptr directly: on CN78XX pass 1
     * it applies errata PKI-20776 to the buffer chain, once, and every later
     * walk of that chain depends on it having happened. */
    ptr = cvmx_wqe_get_pki_pkt_ptr(wqe);

    w->pkt_ptr = ptr.u64;
    /* Captured now, not on the transmit path: by then PKO3 may already have
     * recycled the buffer this bit lives in. */
    w->wqe_separate = (uint8_t)ptr.packet_outside_wqe;
    w->data_aura    = (uint16_t)cvmx_wqe_get_aura(wqe);
    w->segs         = (uint8_t)cvmx_wqe_get_bufs(wqe);

    /* Two kinds of work item carry no forwardable packet: one this application
     * submitted itself (FFN submits none, so it is an anomaly worth counting),
     * and one PKI could not parse or store. Both are reported as a zero-length
     * packet, which routes them through the ordinary disposal path -- the
     * buffers are ours either way. */
    if (cvmx_wqe_is_soft(wqe) || cvmx_wqe_get_rcv_err(wqe)) {
        c->stat_rx_err++;
        return 1;
    }

    w->len      = (uint32_t)cvmx_wqe_get_len(wqe);
    w->in_port  = (uint16_t)cvmx_wqe_get_port(wqe);
    w->data     = (uint8_t *)cvmx_phys_to_ptr(ptr.addr);
    w->flow_tag = (uint32_t)cvmx_wqe_get_tag(wqe);
    return 1;
}

static int cvmx3_hw_pkt_send(struct oct_ctx *c, struct oct_wqe *w, uint16_t port)
{
    const struct oct_port *p = &c->ports[port];
    struct pko3_desc d;
    cvmx_buf_ptr_pki_t pki_ptr;
    uint32_t tag;
    uint32_t *ptag = NULL;

    /* keep_data = 0: PKO3 frees the data to its aura once it is on the wire. */
    if (oct3_build_desc(&d, w, /*keep_data*/ 0) != DP_OK)
        return -1;

    pki_ptr.u64 = w->pkt_ptr;

    /* Egress ordering. Without a tag, packets of one flow can leave through
     * different cores in a different order than they arrived, which a stateful
     * firewall downstream will see as reordering. With one, PKO3 switches to an
     * atomic tag per (flow, DQ) before queueing, which costs a tag switch per
     * packet. Off by default for bring-up; `ordered_egress` is the knob. */
    if (c->ordered_egress) {
        tag = cvmx_pow_tag_compose(0xe9, w->flow_tag + (uint32_t)p->pko_queue);
        ptag = &tag;
    }

    /* Staged in full, then issued as one LMTDMA by the SDK: a partial write
     * wedges the descriptor queue, so there is no incremental path here. */
    return cvmx_pko3_xmit_link_buf(p->pko_queue, pki_ptr, d.hdr.total,
                                   d.gaura, NULL, ptag);
}

static void cvmx3_hw_data_free(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c;
    /* Walks the buffer chain and returns each segment to the WQE's aura. Only
     * ever called while the WQE is still ours -- it reads the chain out of it.
     * If the WQE shares the first buffer, this releases the WQE as well, which
     * is why cvmx3_hw_wqe_free below must then do nothing. */
    cvmx_helper_free_pki_pkt_data((cvmx_wqe_t *)w->hw);
}

static void cvmx3_hw_wqe_free(struct oct_ctx *c, struct oct_wqe *w)
{
    unsigned x;
    cvmx_fpa3_gaura_t aura;

    (void)c;
    /* Nothing to do when the WQE lives inside the first packet buffer: whoever
     * released the data -- us, or PKO3 after the wire -- released this too. */
    if (!w->wqe_separate)
        return;

    /* Deliberately does NOT dereference the WQE. On the forward path PKO3 may
     * already have freed and recycled the packet buffers by now, and while this
     * WQE is a separate allocation, reading it to find its aura is a habit that
     * breaks the moment the layout changes. The aura was captured on receive. */
    x = w->data_aura;
    aura = __cvmx_fpa3_gaura(x >> 10, x & 0x3ff);
    cvmx_fpa3_free(w->hw, aura, 0);
}

const struct oct_hw_ops OCT_HW_CVMX3 = {
    "cvmx(octeon-iii pki/sso/pko3)",
    cvmx3_hw_init, cvmx3_hw_fini, cvmx3_hw_work_get,
    cvmx3_hw_pkt_send, cvmx3_hw_data_free, cvmx3_hw_wqe_free
};

/* With the SDK present we can ask the chip itself, which beats any inference
 * from firmware names or PCI ids. */
enum oct_gen oct_detect_gen(void)
{
    if (octeon_has_feature(OCTEON_FEATURE_CN78XX_WQE))
        return OCT_GEN_III;
    return OCT_GEN_II;
}

/* ======================================================================== */
#else  /* !FFN_HAVE_CVMX ---------------------------------------------------- */
/* ======================================================================== */

static int  stub3_init(struct oct_ctx *c) { c->available = 0; return DP_ERR_NOMEM; }
static void stub3_fini(struct oct_ctx *c) { (void)c; }
static int  stub3_work_get(struct oct_ctx *c, struct oct_wqe *w)
{ (void)c; (void)w; return 0; }
static int  stub3_send(struct oct_ctx *c, struct oct_wqe *w, uint16_t p)
{ (void)c; (void)w; (void)p; return -1; }
static void stub3_data_free(struct oct_ctx *c, struct oct_wqe *w) { (void)c; (void)w; }
static void stub3_wqe_free(struct oct_ctx *c, struct oct_wqe *w) { (void)c; (void)w; }

const struct oct_hw_ops OCT_HW_CVMX3 = {
    "octeon-iii (unavailable: no SDK at build time)",
    stub3_init, stub3_fini, stub3_work_get,
    stub3_send, stub3_data_free, stub3_wqe_free
};

/* Without CVMX we cannot ask the chip, so we read the answer the management
 * layer worked out and wrote down.
 *
 * This deliberately does NOT infer the generation from a PCI device id or from
 * the names of the vendor's firmware. Both have already produced a wrong
 * answer here:
 *   * 177d:9700 was read as "CN73XX, therefore OCTEON III". `lspci` resolves
 *     that id through pci.ids, so the pretty name is a DATABASE's opinion, and
 *     the local pci.ids does not even list 9700.
 *   * The vendor's dataplane kernel is `vmlinux-3.10.87-oct2-dp` and its libc
 *     sits in `lib64/octeon2/`, which was read as "the part is OCTEON II".
 *     It is not: those are `-march=octeon2` MULTILIB directories, a compiler
 *     tuning choice, and octeon2 code runs unchanged on OCTEON III. The ELF
 *     headers say so outright -- `Flags: ... octeon2, mips64r2` on the tuned
 *     library against `octeon` on the base one.
 * The dataplane processor in a PA-5220 reports itself as CN7885, i.e. CN78XX
 * with 40 cores, which is OCTEON III.
 *
 * ffn_vendor.py weighs the evidence and writes /etc/ffn-ngfw/octeon-gen. Absent
 * that, report UNDETERMINED rather than guessing: selecting the wrong backend
 * means driving the wrong packet-input and output blocks. */
enum oct_gen oct_detect_gen(void)
{
#if defined(__linux__)
    FILE *f = fopen("/etc/ffn-ngfw/octeon-gen", "r");
    if (f) {
        int gen = 0;
        int got = fscanf(f, "%d", &gen);
        fclose(f);
        if (got == 1 && gen == 2)
            return OCT_GEN_II;
        if (got == 1 && gen == 3)
            return OCT_GEN_III;
    }
#endif
    return OCT_GEN_NONE;
}

#endif /* FFN_HAVE_CVMX */

const struct oct_hw_ops *oct_hw_for_gen(enum oct_gen g)
{
    switch (g) {
    case OCT_GEN_II:  return &OCT_HW_CVMX;
    case OCT_GEN_III: return &OCT_HW_CVMX3;
    default:          return NULL;
    }
}
