/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon3.c -- OCTEON-III packet-I/O backend (PKI + SSO + PKO3).
 *
 * WHY A SECOND BACKEND RATHER THAN A REWRITE
 * ------------------------------------------
 * The PA-5220 carries a CN73XX -- OCTEON III -- whose blocks are PKI (input),
 * SSO (scheduling) and PKO3 (output). The original backend targets OCTEON II
 * (IPD/PIP + POW + PKO), which is what a PA-3200 has. Both are e-waste FFN wants
 * to reclaim, so both stay: they sit behind the same `oct_hw_ops` seam and
 * `oct_detect_gen()` picks one at runtime. One FFN build serves both families.
 *
 * WHAT ACTUALLY DIFFERS (and why it is not a search-and-replace)
 * -------------------------------------------------------------
 *  1. FPA3 frees to an AURA, not a pool. An aura is an indirection in front of a
 *     pool with its own accounting, so returning a buffer to the wrong aura
 *     corrupts counts without any immediate symptom.
 *  2. PKI can place the WQE and the packet data in DIFFERENT auras. The
 *     OCTEON-II code frees both via one pool constant; doing that here is the
 *     bug that wedges the box. Each buffer carries its own aura in `oct_wqe`.
 *  3. Transmit is a descriptor list (SEND_HDR [+ SEND_LINK/SEND_GATHER]) issued
 *     as ONE unit into a descriptor queue via LMTDMA -- not a prepare/finish
 *     pair against a command queue. A partially written descriptor wedges the
 *     DQ, so the words are staged and issued together or not at all.
 *  4. Ownership transfer on send is the SEND_HDR `df` ("don't free") bit plus the
 *     aura in the header: with df=0 PKO3 returns the data buffer to that aura
 *     after the wire. Set the wrong aura and PKO3 credits the wrong pool.
 *  5. SSO groups are 8-bit-plus (CN73XX has 256), so the group mask is no longer
 *     a single 64-bit word.
 *
 * LICENSING / WHAT FFN SHIPS
 * -------------------------
 * Same rule as the OCTEON-II backend: this source is FFN's own code calling a
 * documented hardware API. CVMX headers and libraries are Marvell OCTEON SDK
 * property and are NEVER vendored or shipped. Built without -DFFN_HAVE_CVMX (the
 * default) the file compiles and links, reports the backend unavailable, and the
 * dataplane keeps running on AF_PACKET.
 *
 * TESTING STATUS -- read this before trusting it
 * ---------------------------------------------
 * The ownership contract and descriptor assembly are verified by
 * ffn_dp_io_octeon3_test.c against a mock that models FPA3 auras and PKO3
 * descriptors, on both little- and big-endian. The CVMX call sites below are
 * written against the documented cn73xx/cn78xx API but have NOT been
 * compile-checked against a real SDK, because FFN has no SDK to build against.
 * Expect to adjust names/arities on first real build; the surrounding logic is
 * what the tests pin down.
 */
#include "ffn_dp_io_octeon3.h"

#include <stdint.h>
#include <string.h>

/* Build the descriptor list for one packet. Split out from the send path so the
 * test can assert the descriptor without any hardware.
 *
 * `keep_data` selects ownership: 0 lets PKO3 free the data to its aura after the
 * wire (the normal forward case), 1 keeps it ours (caller will free). */
int oct3_build_desc(struct pko3_desc *d, const struct oct_wqe *w, int keep_data)
{
    if (!d || !w)
        return DP_ERR_TOOMANY;
    int segs = w->segs ? w->segs : 1;
    if (segs > PKO3_MAX_WORDS - 1)
        return DP_ERR_TOOMANY;    /* would overrun the LMTLINE */

    memset(d, 0, sizeof(*d));
    d->hdr.subdc = PKO3_SUBDC_HDR;
    d->hdr.total = w->len;
    d->hdr.df    = keep_data ? 1 : 0;
    d->hdr.ii    = 0;
    /* The aura the DATA came from -- not the WQE's. Getting this wrong is the
     * whole reason this backend exists. */
    d->hdr.aura  = w->data_aura;

    for (int i = 0; i < segs; i++) {
        d->link[i].subdc = PKO3_SUBDC_LINK;
        d->link[i].addr  = (uint64_t)(uintptr_t)w->data;
        d->link[i].size  = (uint16_t)w->len;
        d->link[i].aura  = w->data_aura;
    }
    d->nlink = segs;
    d->words = 1 + segs;
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
#include "cvmx-fpa.h"
#include "cvmx-fpa3.h"
#include "cvmx-helper.h"
#include "cvmx-pki.h"
#include "cvmx-pko3.h"
#include "cvmx-sso.h"
#include "cvmx-wqe.h"

static int cvmx3_hw_init(struct oct_ctx *c)
{
    if (cvmx_user_app_init() != 0)
        return DP_ERR_NOMEM;

    if (cvmx_is_init_core()) {
        if (cvmx_helper_initialize_packet_io_global() != 0)
            return DP_ERR_NOMEM;
    }
    if (cvmx_helper_initialize_packet_io_local() != 0)
        return DP_ERR_NOMEM;

    c->core_id = (int)cvmx_get_core_num();
    /* CN73XX has 256 SSO groups, so this is a per-group priority/affinity call
     * rather than OCTEON-II's single 64-bit group mask. */
    cvmx_sso_set_group_priority(c->core_id, c->pow_group, /*prio*/ 0);
    c->available = 1;
    return DP_OK;
}

static void cvmx3_hw_fini(struct oct_ctx *c) { c->available = 0; }

static int cvmx3_hw_work_get(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c;
    cvmx_wqe_t *wqe = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
    if (!wqe)
        return 0;

    memset(w, 0, sizeof(*w));
    w->hw      = wqe;
    w->len     = (uint32_t)cvmx_wqe_get_len(wqe);
    w->in_port = (uint16_t)cvmx_wqe_get_port(wqe);
    w->segs    = (uint8_t)cvmx_wqe_get_bufs(wqe);
    w->data    = (uint8_t *)cvmx_phys_to_ptr(cvmx_wqe_get_packet_ptr(wqe).s.addr);
    /* The two auras are read separately and deliberately: PKI is free to place
     * the WQE and the packet data in different ones. */
    w->data_aura = (uint16_t)cvmx_wqe_get_aura(wqe);
    w->wqe_aura  = (uint16_t)cvmx_wqe_pki_get_wqe_aura(wqe);
    w->disp      = OCT_DISP_HELD;
    return 1;
}

static int cvmx3_hw_pkt_send(struct oct_ctx *c, struct oct_wqe *w, uint16_t port)
{
    const struct oct_port *p = &c->ports[port];
    struct pko3_desc d;

    if (oct3_build_desc(&d, w, /*keep_data*/ 0) != DP_OK)
        return -1;

    /* Stage the whole descriptor, then issue once. A partial write wedges the
     * descriptor queue, so there is no incremental path here on purpose. */
    cvmx_pko_send_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.s.total = d.hdr.total;
    hdr.s.aura  = d.hdr.aura;
    hdr.s.df    = d.hdr.df;
    hdr.s.ii    = d.hdr.ii;

    cvmx_pko_buf_ptr_t link[PKO3_MAX_WORDS - 1];
    memset(link, 0, sizeof(link));
    for (int i = 0; i < d.nlink; i++) {
        link[i].s.subdc3 = CVMX_PKO_SENDSUBDC_LINK;
        link[i].s.addr   = d.link[i].addr;
        link[i].s.size   = d.link[i].size;
        link[i].s.i      = 0;
    }

    cvmx_pko_query_rtn_t rtn =
        cvmx_pko3_xmit_link_buf(p->pko_queue, hdr, link, d.nlink);
    return (rtn.s.dqstatus == PKO_DQSTATUS_PASS) ? 0 : -1;
}

static void cvmx3_hw_data_free(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c;
    /* FPA3: return to the aura this buffer came from. */
    cvmx_fpa3_free(w->data, w->data_aura, /*cache_lines*/ 0);
}

static void cvmx3_hw_wqe_free(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c;
    /* The WQE has its OWN aura, which may differ from the data's. */
    cvmx_fpa3_free(w->hw, w->wqe_aura, 0);
}

const struct oct_hw_ops OCT_HW_CVMX3 = {
    "cvmx(octeon-iii pki/sso/pko3)",
    cvmx3_hw_init, cvmx3_hw_fini, cvmx3_hw_work_get,
    cvmx3_hw_pkt_send, cvmx3_hw_data_free, cvmx3_hw_wqe_free
};

enum oct_gen oct_detect_gen(void)
{
    if (octeon_has_feature(OCTEON_FEATURE_PKO3))
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

/* Without CVMX we cannot ask the chip, so fall back to what the PCI device tells
 * us. 177d:9700 is the CN73XX in the PA-5220. Reported for display only -- the
 * stub ops refuse to run either way. */
enum oct_gen oct_detect_gen(void)
{
#if defined(__linux__)
    FILE *f = fopen("/sys/bus/pci/devices/0000:01:00.0/device", "r");
    if (f) {
        unsigned devid = 0;
        int got = fscanf(f, "%x", &devid);
        fclose(f);
        if (got == 1 && devid == 0x9700)
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
