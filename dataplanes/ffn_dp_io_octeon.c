/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon.c -- OCTEON-II hardware packet I/O (IPD/PIP + POW + PKO).
 *
 * Two layers:
 *   1. dp_io_ops  -- backend-neutral glue the forwarder calls (always built).
 *   2. oct_hw_ops -- the hardware seam. OCT_HW_CVMX calls the OCTEON SDK when
 *                    built with -DFFN_HAVE_CVMX; otherwise it is inert and the
 *                    backend reports itself unavailable. The test harness
 *                    supplies a mock implementing the same seam, which lets the
 *                    FPA buffer-ownership rules be verified without hardware.
 *
 * See the header for the ownership contract. Summary: PKO takes the packet data
 * on a successful send (so we free only the WQE); on drop or send failure we
 * free both; nothing is ever released twice.
 */
#include "ffn_dp_io_octeon.h"

#include <stdio.h>
#include <string.h>

/* ================================================================== *
 * 1. real hardware ops (CVMX)                                        *
 * ================================================================== */
#ifdef FFN_HAVE_CVMX

/* Supplied by the operator's OCTEON SDK; never vendored into FFN. */
#include "cvmx.h"
#include "cvmx-bootmem.h"
#include "cvmx-fpa.h"
#include "cvmx-helper.h"
#include "cvmx-pko.h"
#include "cvmx-pow.h"
#include "cvmx-wqe.h"

/* CVMX_FPA_WQE_POOL is NOT an SDK constant. It comes from the application's
 * generated cvmx-config.h, because FPA pool numbering is the application's
 * choice -- which is why building this file against a bare SDK include path
 * fails on it. Every OCTEON-II consumer in the SDK (the Linux port and u-boot
 * both) uses pool 1, so that is the default here; override it at build time if
 * the pool layout on your box differs. Returning WQEs to the wrong pool
 * corrupts FPA accounting with no immediate symptom. */
#ifndef CVMX_FPA_WQE_POOL
#define CVMX_FPA_WQE_POOL 1
#endif

static int cvmx_hw_init(struct oct_ctx *c)
{
    if (cvmx_user_app_init() != 0)
        return DP_ERR_NOMEM;

    /* Global packet-I/O bring-up happens once, on the first core to arrive. */
    if (cvmx_is_init_core()) {
        if (cvmx_helper_initialize_packet_io_global() != 0)
            return DP_ERR_NOMEM;
    }
    if (cvmx_helper_initialize_packet_io_local() != 0)
        return DP_ERR_NOMEM;

    c->core_id = (int)cvmx_get_core_num();
    /* Which groups this core takes work from. Explicit because an empty mask
     * means "no packets ever" with nothing logged. */
    cvmx_pow_set_group_mask(c->core_id, c->pow_group_mask);
    c->available = 1;
    return DP_OK;
}

static void cvmx_hw_fini(struct oct_ctx *c)
{
    c->available = 0;
}

static int cvmx_hw_work_get(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c;
    cvmx_wqe_t *wqe = cvmx_pow_work_request_sync(CVMX_POW_NO_WAIT);
    if (!wqe)
        return 0;
    memset(w, 0, sizeof(*w));
    w->hw = wqe;
    w->len = (uint32_t)cvmx_wqe_get_len(wqe);
    w->in_port = (uint16_t)cvmx_wqe_get_port(wqe);
    w->segs = (uint8_t)cvmx_wqe_get_bufs(wqe);
    w->data = (uint8_t *)cvmx_phys_to_ptr(cvmx_wqe_get_packet_ptr(wqe).s.addr);
    w->disp = OCT_DISP_HELD;
    /* A packet with an IPD error, or scattered across buffers, is not something
     * this bring-up path parses: the caller drops it and we free normally. */
    return 1;
}

static int cvmx_hw_pkt_send(struct oct_ctx *c, struct oct_wqe *w, uint16_t port)
{
    const struct oct_port *p = &c->ports[port];
    cvmx_wqe_t *wqe = (cvmx_wqe_t *)w->hw;
    cvmx_buf_ptr_t pkt = cvmx_wqe_get_packet_ptr(wqe);
    cvmx_pko_command_word0_t cmd;

    memset(&cmd, 0, sizeof(cmd));
    cmd.s.total_bytes = w->len;
    cmd.s.segs = w->segs ? w->segs : 1;
    /* dontfree = 0 => PKO returns the data buffer to its FPA pool after the
     * wire. That is what transfers data ownership away from us. */
    cmd.s.dontfree = 0;
    cmd.s.ignore_i = 0;
    cmd.s.gather = 0;

    cvmx_pko_send_packet_prepare(p->ipd_port, p->pko_queue, CVMX_PKO_LOCK_ATOMIC_TAG);
    cvmx_pko_return_value_t rv =
        cvmx_pko_send_packet_finish(p->ipd_port, p->pko_queue, cmd, pkt,
                                    CVMX_PKO_LOCK_ATOMIC_TAG);
    return (rv == CVMX_PKO_SUCCESS) ? 0 : -1;
}

static void cvmx_hw_data_free(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c;
    cvmx_helper_free_packet_data((cvmx_wqe_t *)w->hw);
}

static void cvmx_hw_wqe_free(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c;
    cvmx_fpa_free(w->hw, CVMX_FPA_WQE_POOL, 0);
}

const struct oct_hw_ops OCT_HW_CVMX = {
    "cvmx(octeon-ii ipd/pow/pko)",
    cvmx_hw_init, cvmx_hw_fini, cvmx_hw_work_get,
    cvmx_hw_pkt_send, cvmx_hw_data_free, cvmx_hw_wqe_free
};

int oct_backend_available(void) { return 1; }
/* Reports what this BUILD can drive, not which generation is live -- that is
 * c->hw->name, chosen at runtime by oct_detect_gen(). */
const char *oct_backend_name(void) { return "cvmx (octeon-ii and octeon-iii)"; }

#else  /* !FFN_HAVE_CVMX ------------------------------------------------ */

/* Built without the OCTEON SDK: the seam exists so everything links and the
 * dataplane can report precisely why the hardware path is unavailable, instead
 * of failing to build or silently pretending to forward. */
static int noop_init(struct oct_ctx *c)
{
    c->available = 0;
    return DP_ERR_NOMEM;
}
static void noop_fini(struct oct_ctx *c) { (void)c; }
static int noop_work_get(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c; (void)w; return 0;
}
static int noop_send(struct oct_ctx *c, struct oct_wqe *w, uint16_t p)
{
    (void)c; (void)w; (void)p; return -1;
}
static void noop_free(struct oct_ctx *c, struct oct_wqe *w) { (void)c; (void)w; }

const struct oct_hw_ops OCT_HW_CVMX = {
    "unavailable(no-cvmx)",
    noop_init, noop_fini, noop_work_get, noop_send, noop_free, noop_free
};

int oct_backend_available(void) { return 0; }
const char *oct_backend_name(void)
{
    return "unavailable: rebuild with -DFFN_HAVE_CVMX and an OCTEON SDK "
           "include path to enable IPD/POW/PKO";
}

#endif /* FFN_HAVE_CVMX */

/* ================================================================== *
 * 2. ownership-safe disposal helpers                                 *
 * ================================================================== */

/* Release everything we still own for this work item. Idempotent: a second
 * call is counted as a bug and does nothing, rather than double-freeing an
 * FPA buffer (which would corrupt the pool). */
static void oct_dispose_free(struct oct_ctx *c, struct oct_wqe *w)
{
    if (w->disp != OCT_DISP_HELD) {
        c->bug_double_dispose++;
        return;
    }
    c->hw->data_free(c, w);
    c->stat_data_freed++;
    c->hw->wqe_free(c, w);
    c->stat_wqe_freed++;
    w->disp = OCT_DISP_FREED;
}

/* Mark that PKO owns the data now; we still must release the WQE. */
static void oct_dispose_sent(struct oct_ctx *c, struct oct_wqe *w)
{
    if (w->disp != OCT_DISP_HELD) {
        c->bug_double_dispose++;
        return;
    }
    c->hw->wqe_free(c, w);          /* data is PKO's; WQE is ours */
    c->stat_wqe_freed++;
    w->disp = OCT_DISP_SENT;
}

/* ================================================================== *
 * 3. dp_io_ops glue                                                  *
 * ================================================================== */

static int oct_map_in_port(const struct oct_ctx *c, uint16_t ipd_port)
{
    for (int i = 0; i < c->nports; i++)
        if (c->ports[i].ipd_port == (int)ipd_port)
            return i;
    return -1;
}

static int oct_io_init(void *arg)
{
    struct oct_ctx *c = (struct oct_ctx *)arg;
    if (c->nports == 0)
        return DP_ERR_NOMEM;
    return c->hw->init(c);
}

static void oct_io_fini(void *arg)
{
    struct oct_ctx *c = (struct oct_ctx *)arg;
    /* Anything still held at teardown must go back to the FPA pools. */
    for (int i = 0; i < c->n_inflight; i++)
        if (c->inflight[i].disp == OCT_DISP_HELD)
            oct_dispose_free(c, &c->inflight[i]);
    c->n_inflight = 0;
    c->hw->fini(c);
}

static int oct_io_rx(void *arg, struct dp_pkt *burst, int max)
{
    struct oct_ctx *c = (struct oct_ctx *)arg;
    if (max > OCT_BURST)
        max = OCT_BURST;
    c->n_inflight = 0;

    int n = 0;
    while (n < max) {
        struct oct_wqe *w = &c->inflight[n];
        if (!c->hw->work_get(c, w))
            break;
        c->stat_rx++;

        int pidx = oct_map_in_port(c, w->in_port);
        /* Unknown ingress port or a scattered/oversize buffer: this bring-up
         * path only handles linear frames, so release it immediately rather
         * than hand the forwarder something it cannot parse. */
        if (pidx < 0 || w->segs > 1 || !w->data || w->len == 0) {
            oct_dispose_free(c, w);
            continue;
        }

        burst[n].data = w->data;
        burst[n].len = w->len;
        burst[n].vsys = c->ports[pidx].vsys;
        burst[n].decision = 0;
        burst[n].egress = DP_EGRESS_NONE;
        burst[n].cookie = w;                 /* ties the dp_pkt to its WQE */
        n++;
    }
    c->n_inflight = n;
    return n;
}

static int oct_io_tx(void *arg, struct dp_pkt *burst, int n)
{
    struct oct_ctx *c = (struct oct_ctx *)arg;
    int ok = 0;
    for (int i = 0; i < n; i++) {
        struct oct_wqe *w = (struct oct_wqe *)burst[i].cookie;
        if (!w || w->disp != OCT_DISP_HELD)
            continue;

        uint16_t out = burst[i].egress;
        if (out == DP_EGRESS_NONE) {
            if (c->nports == 2) {
                int in = oct_map_in_port(c, w->in_port);
                out = (uint16_t)((in == 0) ? 1 : 0);   /* bump-in-the-wire */
            } else {
                c->stat_no_egress++;
                oct_dispose_free(c, w);                /* nowhere to send it */
                continue;
            }
        }
        if (out >= (uint16_t)c->nports) {
            c->stat_bad_egress++;
            oct_dispose_free(c, w);
            continue;
        }

        if (c->hw->pkt_send(c, w, out) == 0) {
            oct_dispose_sent(c, w);                    /* PKO owns the data  */
            c->stat_tx++;
            ok++;
        } else {
            c->stat_tx_fail++;
            oct_dispose_free(c, w);                    /* still ours -> free */
        }
    }
    return ok;
}

static void oct_io_to_local(void *arg, struct dp_pkt *p)
{
    struct oct_ctx *c = (struct oct_ctx *)arg;
    /* A real local-delivery path would queue this to the Octeon's Linux stack
     * (or relay it to the MP over the shared region). Until that exists, say so
     * with a counter and release the buffer -- never leak it. */
    c->stat_local++;
    struct oct_wqe *w = (struct oct_wqe *)p->cookie;
    if (w) oct_dispose_free(c, w);
}

static void oct_io_to_offload(void *arg, struct dp_pkt *p)
{
    struct oct_ctx *c = (struct oct_ctx *)arg;
    /* FE100/FPGA punt is a later milestone; count and release. */
    c->stat_offload++;
    struct oct_wqe *w = (struct oct_wqe *)p->cookie;
    if (w) oct_dispose_free(c, w);
}

/* Called by the forwarder after every packet. Anything not already sent,
 * delivered or punted is a drop and must be released here. */
static void oct_io_free_pkt(void *arg, struct dp_pkt *p)
{
    struct oct_ctx *c = (struct oct_ctx *)arg;
    struct oct_wqe *w = (struct oct_wqe *)p->cookie;
    if (!w)
        return;
    if (w->disp == OCT_DISP_HELD) {
        oct_dispose_free(c, w);
        c->stat_drop_freed++;
    }
}

const struct dp_io_ops OCT_IO = {
    "octeon(ipd/pow/pko or pki/sso/pko3)",
    oct_io_init, oct_io_fini, oct_io_rx, oct_io_tx,
    oct_io_to_local, oct_io_to_offload, oct_io_free_pkt
};

/* ================================================================== *
 * 4. setup / reporting                                               *
 * ================================================================== */
void oct_ctx_init(struct oct_ctx *c, const struct oct_hw_ops *hw, void *hw_priv)
{
    memset(c, 0, sizeof(*c));
    c->hw = hw ? hw : &OCT_HW_CVMX;
    c->hw_priv = hw_priv;
    c->pow_group = 0;
    c->pow_group_mask = ~0ull;      /* accept work from every group */
    c->core_id = -1;
}

int oct_add_port(struct oct_ctx *c, const char *name, int ipd_port,
                 int pko_queue, uint8_t vsys)
{
    if (c->nports >= OCT_MAX_PORTS)
        return -1;
    struct oct_port *p = &c->ports[c->nports];
    p->port_id = (uint16_t)c->nports;
    p->ipd_port = ipd_port;
    p->pko_queue = pko_queue;
    p->vsys = vsys;
    snprintf(p->name, sizeof(p->name), "%s", name ? name : "");
    c->nports++;
    return p->port_id;
}

void oct_dump_stats(const struct oct_ctx *c, FILE *f)
{
    fprintf(f, "octeon(%s): ports=%d avail=%d rx=%llu rx_err=%llu tx=%llu tx_fail=%llu "
               "drop_freed=%llu local=%llu offload=%llu no_egress=%llu "
               "bad_egress=%llu\n",
            c->hw ? c->hw->name : "?", c->nports, c->available,
            (unsigned long long)c->stat_rx,
            (unsigned long long)c->stat_rx_err,
            (unsigned long long)c->stat_tx,
            (unsigned long long)c->stat_tx_fail,
            (unsigned long long)c->stat_drop_freed,
            (unsigned long long)c->stat_local,
            (unsigned long long)c->stat_offload,
            (unsigned long long)c->stat_no_egress,
            (unsigned long long)c->stat_bad_egress);
    fprintf(f, "  fpa accounting: wqe_freed=%llu data_freed=%llu "
               "double_dispose_bugs=%llu%s\n",
            (unsigned long long)c->stat_wqe_freed,
            (unsigned long long)c->stat_data_freed,
            (unsigned long long)c->bug_double_dispose,
            c->bug_double_dispose ? "  <-- BUG" : "");
    for (int i = 0; i < c->nports; i++)
        fprintf(f, "  port %u = %s (ipd_port %d, pko_queue %d, vsys %u)\n",
                c->ports[i].port_id, c->ports[i].name, c->ports[i].ipd_port,
                c->ports[i].pko_queue, c->ports[i].vsys);
}
