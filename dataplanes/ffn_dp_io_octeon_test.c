/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon_test.c -- verify the OCTEON-II backend without the hardware.
 *
 * The CVMX calls cannot run here, but everything around them can: WQE -> dp_pkt
 * translation, ingress-port mapping, egress selection, and above all the FPA
 * BUFFER-OWNERSHIP CONTRACT -- the property that wedges a real box within
 * minutes if it is wrong. A mock hardware layer implements the oct_hw_ops seam
 * and tracks every allocation, so the tests can assert:
 *
 *   * a forwarded packet: data handed to PKO exactly once, WQE freed exactly once
 *   * a dropped packet:   data AND WQE each freed exactly once by us
 *   * a send failure:     ownership stays with us -> both freed
 *   * local / punt:       released, never leaked
 *   * unknown port / scattered / zero-length frames: released immediately
 *   * teardown with packets in flight: nothing left outstanding
 *   * NOTHING is ever released twice (bug_double_dispose must stay 0)
 */
#include "ffn_dp_abi.h"
#include "ffn_dp_oct.h"
#include "ffn_dp_io_octeon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
static void chk(int cond, const char *msg)
{
    printf("  %s %s\n", cond ? "ok  " : "FAIL", msg);
    if (!cond) g_fail++;
}

/* ---------------- mock hardware ---------------- */
#define MOCK_MAX 64

struct mock_buf {
    uint8_t data[128];
    uint32_t len;
    uint16_t in_port;
    uint8_t  segs;
    int      queued;        /* pending delivery to the forwarder */
    int      data_freed;    /* freed by us                       */
    int      wqe_freed;
    int      sent_to_pko;   /* PKO took ownership of the data    */
};

struct mock_hw {
    struct mock_buf bufs[MOCK_MAX];
    int n, next;
    int fail_send;          /* make pkt_send fail                */
    int init_rc;
};

static int mock_init(struct oct_ctx *c)
{
    struct mock_hw *m = (struct mock_hw *)c->hw_priv;
    c->available = (m->init_rc == DP_OK);
    return m->init_rc;
}
static void mock_fini(struct oct_ctx *c) { c->available = 0; }

static int mock_work_get(struct oct_ctx *c, struct oct_wqe *w)
{
    struct mock_hw *m = (struct mock_hw *)c->hw_priv;
    while (m->next < m->n && !m->bufs[m->next].queued)
        m->next++;
    if (m->next >= m->n)
        return 0;
    struct mock_buf *b = &m->bufs[m->next++];
    b->queued = 0;
    memset(w, 0, sizeof(*w));
    w->hw = b;
    w->data = b->data;
    w->len = b->len;
    w->in_port = b->in_port;
    w->segs = b->segs;
    w->disp = OCT_DISP_HELD;
    return 1;
}
static int mock_send(struct oct_ctx *c, struct oct_wqe *w, uint16_t port)
{
    struct mock_hw *m = (struct mock_hw *)c->hw_priv;
    (void)port;
    if (m->fail_send)
        return -1;
    ((struct mock_buf *)w->hw)->sent_to_pko++;
    return 0;
}
static void mock_data_free(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c; ((struct mock_buf *)w->hw)->data_freed++;
}
static void mock_wqe_free(struct oct_ctx *c, struct oct_wqe *w)
{
    (void)c; ((struct mock_buf *)w->hw)->wqe_freed++;
}
static const struct oct_hw_ops MOCK_HW = {
    "mock", mock_init, mock_fini, mock_work_get,
    mock_send, mock_data_free, mock_wqe_free
};

/* build an IPv4/TCP frame into a mock buffer and queue it */
static struct mock_buf *push(struct mock_hw *m, uint32_t sip, uint32_t dip,
                             uint16_t dport, uint16_t in_port)
{
    struct mock_buf *b = &m->bufs[m->n++];
    memset(b, 0, sizeof(*b));
    uint8_t *p = b->data;
    memset(p, 0xAA, 6); memset(p + 6, 0xBB, 6);
    p[12] = 0x08; p[13] = 0x00;
    uint8_t *ip = p + 14;
    ip[0] = 0x45; ip[9] = 6;
    ip[12] = (uint8_t)(sip >> 24); ip[13] = (uint8_t)(sip >> 16);
    ip[14] = (uint8_t)(sip >> 8);  ip[15] = (uint8_t)sip;
    ip[16] = (uint8_t)(dip >> 24); ip[17] = (uint8_t)(dip >> 16);
    ip[18] = (uint8_t)(dip >> 8);  ip[19] = (uint8_t)dip;
    uint8_t *l4 = ip + 20;
    l4[0] = 0x30; l4[1] = 0x39;                 /* sport 12345 */
    l4[2] = (uint8_t)(dport >> 8); l4[3] = (uint8_t)dport;
    b->len = 14 + 20 + 20;
    b->in_port = in_port;
    b->segs = 1;
    b->queued = 1;
    return b;
}

/* ---- policy.bin builder (same wire format as the compiler) ---- */
static size_t build_policy(uint8_t *out, int allow_dport, int drop_dport)
{
    uint32_t n = 2;
    memset(out, 0, 36 + n * 32);
    memcpy(out, "FPPO", 4);
    st_le16(out + 4, 1); st_le16(out + 6, 0x40);
    st_le32(out + 8, n); st_le32(out + 24, 32); st_le32(out + 28, n);
    uint8_t *r = out + 36;
    /* allow */
    st_be32(r + 0, 0); st_be32(r + 4, 0); st_be32(r + 8, 0); st_be32(r + 12, 0);
    st_le16(r + 16, 0); st_le16(r + 18, 0xFFFF);
    st_le16(r + 20, (uint16_t)allow_dport); st_le16(r + 22, (uint16_t)allow_dport);
    r[24] = 6; r[25] = 1; r[26] = FP_FORWARD_W; r[27] = 0;
    st_le16(r + 28, DP_EGRESS_NONE); st_le16(r + 30, 501);
    r += 32;
    /* drop */
    st_be32(r + 0, 0); st_be32(r + 4, 0); st_be32(r + 8, 0); st_be32(r + 12, 0);
    st_le16(r + 16, 0); st_le16(r + 18, 0xFFFF);
    st_le16(r + 20, (uint16_t)drop_dport); st_le16(r + 22, (uint16_t)drop_dport);
    r[24] = 6; r[25] = 1; r[26] = FP_DROP_W; r[27] = 0;
    st_le16(r + 28, DP_EGRESS_NONE); st_le16(r + 30, 502);
    return 36 + n * 32;
}

#define IP(a,b,c,d) (((uint32_t)(a)<<24)|((uint32_t)(b)<<16)|((uint32_t)(c)<<8)|(uint32_t)(d))

/* count buffers that are still outstanding (never released by anyone) */
static int outstanding(const struct mock_hw *m)
{
    int n = 0;
    for (int i = 0; i < m->n; i++) {
        const struct mock_buf *b = &m->bufs[i];
        if (b->queued)
            continue;                       /* never delivered; not our problem */
        int data_gone = b->data_freed || b->sent_to_pko;
        if (!data_gone || !b->wqe_freed)
            n++;
    }
    return n;
}
static int double_frees(const struct mock_hw *m)
{
    int n = 0;
    for (int i = 0; i < m->n; i++) {
        const struct mock_buf *b = &m->bufs[i];
        if (b->data_freed > 1 || b->wqe_freed > 1 || b->sent_to_pko > 1)
            n++;
        if (b->data_freed && b->sent_to_pko)      /* freed AND given to PKO */
            n++;
    }
    return n;
}

static void setup(struct dp_ctx *dp, struct oct_ctx *oc, struct mock_hw *m,
                  void **region, int nports)
{
    memset(m, 0, sizeof(*m));
    m->init_rc = DP_OK;
    oct_ctx_init(oc, &MOCK_HW, m);
    oct_add_port(oc, "xaui0", 16, 0, 1);
    if (nports > 1) oct_add_port(oc, "xaui1", 17, 1, 1);
    if (nports > 2) oct_add_port(oc, "xaui2", 18, 2, 1);
    dp_init(dp, &OCT_IO, oc, 4096);
    size_t rsz = FFN_DP_OFF_BANK0 + 65536;
    *region = calloc(1, rsz);
    dp_region_attach(dp, *region, rsz, 1);
    static uint8_t pol[512];
    size_t plen = build_policy(pol, 443, 4444);
    memcpy((uint8_t *)*region + FFN_DP_OFF_BANK0, pol, plen);
    dp_activate_bank(dp, 0);
}

int main(void)
{
    printf("=== FFN OCTEON-II (IPD/POW/PKO) backend test ===\n");
    printf("backend: %s\n", oct_backend_name());
    printf("built with CVMX: %s\n\n", oct_backend_available() ? "yes" : "no (mock only)");

    struct dp_ctx dp;
    struct oct_ctx oc;
    struct mock_hw m;
    void *region = NULL;

    /* ---------- 1. forward path ---------- */
    printf("[1] forwarded packet: PKO takes the data, we free the WQE\n");
    setup(&dp, &oc, &m, &region, 2);
    struct mock_buf *b = push(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16);
    int n = dp_poll_once(&dp);
    chk(n == 1, "one packet polled");
    chk(dp.stat_forward == 1, "forwarder decided FORWARD");
    chk(oc.stat_tx == 1, "backend transmitted 1");
    chk(b->sent_to_pko == 1, "data handed to PKO exactly once");
    chk(b->data_freed == 0, "we did NOT free the data (PKO owns it)");
    chk(b->wqe_freed == 1, "WQE freed exactly once");
    chk(outstanding(&m) == 0, "no outstanding buffers");
    chk(oc.bug_double_dispose == 0, "no double dispose");
    dp_fini(&dp); free(region);

    /* ---------- 2. drop path ---------- */
    printf("\n[2] dropped packet: we free BOTH data and WQE\n");
    setup(&dp, &oc, &m, &region, 2);
    b = push(&m, IP(10,0,0,1), IP(8,8,8,8), 4444, 16);
    dp_poll_once(&dp);
    chk(dp.stat_drop == 1, "forwarder decided DROP");
    chk(oc.stat_tx == 0, "nothing transmitted");
    chk(b->sent_to_pko == 0, "data never went to PKO");
    chk(b->data_freed == 1, "data freed exactly once");
    chk(b->wqe_freed == 1, "WQE freed exactly once");
    chk(oc.stat_drop_freed == 1, "drop accounted");
    chk(outstanding(&m) == 0 && double_frees(&m) == 0, "no leak, no double free");
    dp_fini(&dp); free(region);

    /* ---------- 3. default-deny (no matching rule) ---------- */
    printf("\n[3] unmatched packet hits the DROP default and is released\n");
    setup(&dp, &oc, &m, &region, 2);
    b = push(&m, IP(10,0,0,1), IP(8,8,8,8), 9999, 16);
    dp_poll_once(&dp);
    chk(dp.stat_drop == 1, "default decision DROP applied");
    chk(b->data_freed == 1 && b->wqe_freed == 1, "buffer fully released");
    chk(outstanding(&m) == 0, "no leak on the default path");
    dp_fini(&dp); free(region);

    /* ---------- 4. send failure ---------- */
    printf("\n[4] PKO send failure: ownership stays with us, both freed\n");
    setup(&dp, &oc, &m, &region, 2);
    m.fail_send = 1;
    b = push(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16);
    dp_poll_once(&dp);
    chk(oc.stat_tx_fail == 1, "tx failure counted");
    chk(b->sent_to_pko == 0, "PKO did not take the data");
    chk(b->data_freed == 1 && b->wqe_freed == 1,
        "we released both after the failed send");
    chk(outstanding(&m) == 0 && double_frees(&m) == 0,
        "failed send leaks nothing and double-frees nothing");
    dp_fini(&dp); free(region);

    /* ---------- 5. bump-in-the-wire egress selection ---------- */
    printf("\n[5] egress selection\n");
    setup(&dp, &oc, &m, &region, 2);
    push(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16);   /* in on port 0 */
    push(&m, IP(10,0,0,2), IP(8,8,8,8), 443, 17);   /* in on port 1 */
    dp_poll_once(&dp);
    chk(oc.stat_tx == 2, "both forwarded to the opposite port");
    chk(oc.stat_no_egress == 0 && oc.stat_bad_egress == 0, "no egress errors");
    chk(outstanding(&m) == 0, "no leak across two ports");
    dp_fini(&dp); free(region);

    printf("\n[5b] three ports with no egress in the rule -> cannot bridge\n");
    setup(&dp, &oc, &m, &region, 3);
    b = push(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16);
    dp_poll_once(&dp);
    chk(oc.stat_no_egress == 1, "ambiguous egress reported");
    chk(b->data_freed == 1 && b->wqe_freed == 1,
        "buffer released instead of leaked when there is nowhere to send");
    dp_fini(&dp); free(region);

    /* ---------- 6. malformed / unknown-port frames ---------- */
    printf("\n[6] frames the bring-up path cannot handle are released at rx\n");
    setup(&dp, &oc, &m, &region, 2);
    struct mock_buf *unknown = push(&m, IP(1,1,1,1), IP(2,2,2,2), 443, 99);
    struct mock_buf *scattered = push(&m, IP(1,1,1,1), IP(2,2,2,2), 443, 16);
    scattered->segs = 3;
    struct mock_buf *empty = push(&m, IP(1,1,1,1), IP(2,2,2,2), 443, 16);
    empty->len = 0;
    struct mock_buf *good = push(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16);
    n = dp_poll_once(&dp);
    chk(n == 1, "only the good frame reached the forwarder");
    chk(unknown->data_freed == 1 && unknown->wqe_freed == 1,
        "unknown ingress port released");
    chk(scattered->data_freed == 1 && scattered->wqe_freed == 1,
        "scattered (multi-segment) frame released");
    chk(empty->data_freed == 1 && empty->wqe_freed == 1,
        "zero-length frame released");
    chk(good->sent_to_pko == 1, "good frame still forwarded");
    chk(outstanding(&m) == 0 && double_frees(&m) == 0,
        "rx-side rejects leak nothing");
    dp_fini(&dp); free(region);

    /* ---------- 7. local + punt ---------- */
    printf("\n[7] LOCAL and PUNT dispositions release their buffers\n");
    setup(&dp, &oc, &m, &region, 2);
    dp.default_decision = FP_LOCAL_W;
    b = push(&m, IP(10,0,0,1), IP(8,8,8,8), 9999, 16);
    dp_poll_once(&dp);
    chk(oc.stat_local == 1, "local delivery counted");
    chk(b->data_freed == 1 && b->wqe_freed == 1, "local path released the buffer");
    dp_fini(&dp); free(region);

    setup(&dp, &oc, &m, &region, 2);
    dp.default_decision = FP_PUNT_FPGA_W;
    b = push(&m, IP(10,0,0,1), IP(8,8,8,8), 9999, 16);
    dp_poll_once(&dp);
    chk(oc.stat_offload == 1, "offload punt counted (FE100 not present)");
    chk(b->data_freed == 1 && b->wqe_freed == 1, "punt path released the buffer");
    dp_fini(&dp); free(region);

    /* ---------- 8. burst + teardown with packets in flight ---------- */
    printf("\n[8] burst of 20 mixed packets, then teardown\n");
    setup(&dp, &oc, &m, &region, 2);
    for (int i = 0; i < 20; i++)
        push(&m, IP(10,0,0,1) + (uint32_t)i, IP(8,8,8,8),
             (i % 2) ? 443 : 4444, (uint16_t)(16 + (i % 2)));
    n = dp_poll_once(&dp);
    chk(n == 20, "all 20 polled in one burst");
    chk(oc.stat_tx == 10, "10 forwarded");
    chk(oc.stat_drop_freed == 10, "10 dropped and released");
    chk(outstanding(&m) == 0, "zero outstanding after the burst");
    chk(double_frees(&m) == 0, "zero double frees across the burst");
    chk(oc.bug_double_dispose == 0, "bug counter clean");
    dp_fini(&dp);
    chk(outstanding(&m) == 0, "teardown left nothing outstanding");
    oct_dump_stats(&oc, stdout);
    free(region);

    /* ---------- 9. no-hardware behaviour ---------- */
    printf("\n[9] without the SDK the backend refuses cleanly\n");
    struct oct_ctx oc2;
    oct_ctx_init(&oc2, &OCT_HW_CVMX, NULL);
    oct_add_port(&oc2, "xaui0", 16, 0, 1);
    struct dp_ctx dp2;
    int rc = dp_init(&dp2, &OCT_IO, &oc2, 1024);
    if (oct_backend_available()) {
        printf("  (built with CVMX -- init result %d on this host)\n", rc);
    } else {
        chk(rc != DP_OK, "dp_init fails without CVMX rather than pretending");
        chk(oc2.available == 0, "backend reports itself unavailable");
    }
    dp_flow_fini(&dp2.flows);

    printf("\n==== octeon backend test: %d failed ====\n", g_fail);
    return g_fail ? 1 : 0;
}
