/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon3_test.c -- OCTEON-III backend test against mock PKI/SSO/PKO3.
 *
 * The OCTEON-II test already proves the general "release each buffer exactly
 * once" contract. This one exists for the things OCTEON-III changes, because
 * those are the ways a working OCTEON-II port silently wedges a CN73XX:
 *
 *   * FPA3 frees go to an AURA, not a pool, and PKI may hand us a WQE and packet
 *     data from DIFFERENT auras. The mock gives every buffer two distinct auras
 *     and checks each free landed in the right one, so code that assumes a
 *     single pool fails here rather than in production.
 *   * Per-aura accounting must balance. A leak or a misdirected free shows up as
 *     an imbalance, which is exactly the failure that takes minutes to wedge a
 *     box and is invisible to a "did it forward?" test.
 *   * Ownership on transmit is the SEND_HDR `df` bit plus the aura in that
 *     header. The mock honours df: with df=0 it frees the data itself, as PKO3
 *     would, so a caller that also frees is caught as a double free.
 *   * The descriptor must be all-or-nothing. A segment count that would overrun
 *     the LMTLINE has to be refused before anything is issued.
 *
 * Runs identically on little-endian and, via qemu-mips64, big-endian.
 */
#include "ffn_dp_abi.h"
#include "ffn_dp_oct.h"
#include "ffn_dp_io_octeon3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
static void chk(int cond, const char *msg)
{
    printf("  %s %s\n", cond ? "ok  " : "FAIL", msg);
    if (!cond) g_fail++;
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

/* ---------------- mock FPA3 + PKO3 ---------------- */
#define MOCK3_MAX    8
#define MOCK3_AURAS  8

/* Distinct auras so a single-pool assumption cannot accidentally pass. */
#define AURA_DATA  3
#define AURA_WQE   5

struct mock3_aura {
    int alloc;
    int freed;
};

struct mock3_buf {
    uint8_t  data[256];
    uint32_t len;
    uint16_t in_port;
    uint8_t  segs;
    uint8_t  queued;
    uint16_t data_aura, wqe_aura;

    int sent_to_pko;
    int data_freed_by_us, wqe_freed_by_us;
    int data_freed_to, wqe_freed_to;    /* aura each free was credited to */
    int pko_freed_data;                 /* PKO3 freed it, as df=0 requires */
    int pko_freed_to;

    struct pko3_desc desc;              /* what the backend actually built */
    int  desc_built;
    int  desc_refused;
};

struct mock3_hw {
    struct mock3_buf  bufs[MOCK3_MAX];
    struct mock3_aura auras[MOCK3_AURAS];
    int n, next;
    int fail_send;
    int init_rc;
};

static void aura_alloc(struct mock3_hw *m, int aura)
{
    if (aura >= 0 && aura < MOCK3_AURAS) m->auras[aura].alloc++;
}
static void aura_free(struct mock3_hw *m, int aura)
{
    if (aura >= 0 && aura < MOCK3_AURAS) m->auras[aura].freed++;
}
static int auras_balanced(const struct mock3_hw *m)
{
    for (int i = 0; i < MOCK3_AURAS; i++)
        if (m->auras[i].alloc != m->auras[i].freed) return 0;
    return 1;
}

static int mock3_init(struct oct_ctx *c)
{
    struct mock3_hw *m = (struct mock3_hw *)c->hw_priv;
    c->available = (m->init_rc == DP_OK);
    return m->init_rc;
}
static void mock3_fini(struct oct_ctx *c) { c->available = 0; }

static int mock3_work_get(struct oct_ctx *c, struct oct_wqe *w)
{
    struct mock3_hw *m = (struct mock3_hw *)c->hw_priv;
    while (m->next < m->n && !m->bufs[m->next].queued)
        m->next++;
    if (m->next >= m->n)
        return 0;
    struct mock3_buf *b = &m->bufs[m->next++];
    b->queued = 0;
    memset(w, 0, sizeof(*w));
    w->hw        = b;
    w->data      = b->data;
    w->len       = b->len;
    w->in_port   = b->in_port;
    w->segs      = b->segs;
    w->data_aura = b->data_aura;
    w->wqe_aura  = b->wqe_aura;
    w->disp      = OCT_DISP_HELD;
    /* PKI took one buffer from each aura to deliver this packet. */
    aura_alloc(m, b->data_aura);
    aura_alloc(m, b->wqe_aura);
    return 1;
}

static int mock3_send(struct oct_ctx *c, struct oct_wqe *w, uint16_t port)
{
    struct mock3_hw *m = (struct mock3_hw *)c->hw_priv;
    struct mock3_buf *b = (struct mock3_buf *)w->hw;
    (void)port;

    /* Exercise the real descriptor builder, then behave as PKO3 would. */
    if (oct3_build_desc(&b->desc, w, /*keep_data*/ 0) != DP_OK) {
        b->desc_refused++;
        return -1;              /* nothing issued: ownership stays with caller */
    }
    b->desc_built++;

    if (m->fail_send)
        return -1;              /* DQ rejected it; we still own the buffers */

    b->sent_to_pko++;
    /* df = 0 means PKO3 returns the data buffer to the aura in SEND_HDR. */
    if (b->desc.hdr.df == 0) {
        b->pko_freed_data++;
        b->pko_freed_to = b->desc.hdr.aura;
        aura_free(m, b->desc.hdr.aura);
    }
    return 0;
}

static void mock3_data_free(struct oct_ctx *c, struct oct_wqe *w)
{
    struct mock3_hw *m = (struct mock3_hw *)c->hw_priv;
    struct mock3_buf *b = (struct mock3_buf *)w->hw;
    b->data_freed_by_us++;
    b->data_freed_to = w->data_aura;
    aura_free(m, w->data_aura);
}

static void mock3_wqe_free(struct oct_ctx *c, struct oct_wqe *w)
{
    struct mock3_hw *m = (struct mock3_hw *)c->hw_priv;
    struct mock3_buf *b = (struct mock3_buf *)w->hw;
    b->wqe_freed_by_us++;
    b->wqe_freed_to = w->wqe_aura;
    aura_free(m, w->wqe_aura);
}

static const struct oct_hw_ops MOCK3_HW = {
    "mock(octeon-iii pki/sso/pko3)",
    mock3_init, mock3_fini, mock3_work_get,
    mock3_send, mock3_data_free, mock3_wqe_free
};

/* ---------------- frame + policy builders ---------------- */
static struct mock3_buf *push3(struct mock3_hw *m, uint32_t sip, uint32_t dip,
                               uint16_t dport, uint16_t in_port, uint8_t segs)
{
    struct mock3_buf *b = &m->bufs[m->n++];
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
    l4[0] = 0x30; l4[1] = 0x39;
    l4[2] = (uint8_t)(dport >> 8); l4[3] = (uint8_t)dport;
    b->len = 14 + 20 + 20;
    b->in_port   = in_port;
    b->segs      = segs;
    b->queued    = 1;
    b->data_aura = AURA_DATA;
    b->wqe_aura  = AURA_WQE;     /* deliberately different */
    return b;
}

static size_t build_policy(uint8_t *out, int allow_dport, int drop_dport)
{
    uint32_t n = 2;
    memset(out, 0, 36 + n * 32);
    memcpy(out, "FPPO", 4);
    st_le16(out + 4, 1); st_le16(out + 6, 0x40);
    st_le32(out + 8, n); st_le32(out + 24, 32); st_le32(out + 28, n);
    uint8_t *r = out + 36;
    st_be32(r + 0, 0); st_be32(r + 4, 0); st_be32(r + 8, 0); st_be32(r + 12, 0);
    st_le16(r + 16, 0); st_le16(r + 18, 0xFFFF);
    st_le16(r + 20, (uint16_t)allow_dport); st_le16(r + 22, (uint16_t)allow_dport);
    r[24] = 6; r[25] = 1; r[26] = FP_FORWARD_W; r[27] = 0;
    st_le16(r + 28, DP_EGRESS_NONE); st_le16(r + 30, 501);
    r += 32;
    st_be32(r + 0, 0); st_be32(r + 4, 0); st_be32(r + 8, 0); st_be32(r + 12, 0);
    st_le16(r + 16, 0); st_le16(r + 18, 0xFFFF);
    st_le16(r + 20, (uint16_t)drop_dport); st_le16(r + 22, (uint16_t)drop_dport);
    r[24] = 6; r[25] = 1; r[26] = FP_DROP_W; r[27] = 0;
    st_le16(r + 28, DP_EGRESS_NONE); st_le16(r + 30, 502);
    return 36 + n * 32;
}

static void setup(struct dp_ctx *dp, struct oct_ctx *oc, struct mock3_hw *m,
                  void **region, int nports)
{
    memset(m, 0, sizeof(*m));
    m->init_rc = DP_OK;
    oct_ctx_init(oc, &MOCK3_HW, m);
    for (int i = 0; i < nports; i++) {
        char nm[16];
        snprintf(nm, sizeof(nm), "xe%d", i);
        oct_add_port(oc, nm, 16 + i, i, 1);
    }
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
    printf("=== FFN OCTEON-III (PKI/SSO/PKO3) backend test ===\n");
    printf("generation reported: %s\n", oct_gen_name(oct_detect_gen()));
    printf("hw ops for gen III : %s\n\n",
           oct_hw_for_gen(OCT_GEN_III) ? oct_hw_for_gen(OCT_GEN_III)->name : "(none)");

    struct dp_ctx dp;
    struct oct_ctx oc;
    struct mock3_hw m;
    void *region = NULL;

    /* ---------- 1. descriptor assembly, no hardware needed ---------- */
    printf("[1] SEND_HDR/SEND_LINK assembly\n");
    {
        struct oct_wqe w;
        struct pko3_desc d;
        memset(&w, 0, sizeof(w));
        w.len = 64; w.segs = 1; w.data_aura = AURA_DATA; w.wqe_aura = AURA_WQE;
        w.data = (uint8_t *)0x1000;

        chk(oct3_build_desc(&d, &w, 0) == DP_OK, "builds for a linear packet");
        chk(d.hdr.subdc == PKO3_SUBDC_HDR, "first sub-descriptor is SEND_HDR");
        chk(d.words == 2, "one HDR + one LINK = 2 words");
        chk(d.nlink == 1, "one LINK for a single segment");
        chk(d.link[0].subdc == PKO3_SUBDC_LINK, "segment is SEND_LINK");
        chk(d.hdr.total == 64, "SEND_HDR carries the total length");
        chk(d.hdr.df == 0, "df=0 on forward: PKO3 frees the data");
        /* The single most important field in this backend. */
        chk(d.hdr.aura == AURA_DATA,
            "SEND_HDR aura is the DATA aura, not the WQE aura");
        chk(d.hdr.aura != AURA_WQE, "SEND_HDR aura is NOT the WQE aura");
        chk(d.link[0].aura == AURA_DATA, "SEND_LINK carries the data aura too");

        chk(oct3_build_desc(&d, &w, 1) == DP_OK, "builds with keep_data");
        chk(d.hdr.df == 1, "df=1 when the caller keeps the data");

        /* multi-segment */
        w.segs = 4;
        chk(oct3_build_desc(&d, &w, 0) == DP_OK, "builds for 4 segments");
        chk(d.words == 5 && d.nlink == 4, "4 segments = HDR + 4 LINK");

        /* refusal must be clean: nothing usable, nothing issued */
        w.segs = PKO3_MAX_WORDS;      /* one too many */
        struct pko3_desc before;
        memset(&before, 0xEE, sizeof(before));
        struct pko3_desc probe = before;
        chk(oct3_build_desc(&probe, &w, 0) == DP_ERR_TOOMANY,
            "refuses a segment count that would overrun the LMTLINE");
        chk(memcmp(&probe, &before, sizeof(probe)) == 0,
            "refused build leaves the descriptor untouched (nothing to issue)");

        chk(oct3_build_desc(NULL, &w, 0) == DP_ERR_TOOMANY, "rejects a NULL descriptor");
        chk(oct3_build_desc(&d, NULL, 0) == DP_ERR_TOOMANY, "rejects a NULL wqe");
    }

    /* ---------- 2. forward: PKO3 owns the data, we own the WQE ---------- */
    printf("\n[2] forwarded packet, two distinct auras\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        struct mock3_buf *b = push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 1);
        int n = dp_poll_once(&dp);
        chk(n == 1, "one packet polled");
        chk(oc.stat_tx == 1, "backend transmitted 1");
        chk(b->desc_built == 1, "descriptor built exactly once");
        chk(b->sent_to_pko == 1, "handed to PKO3 exactly once");
        chk(b->pko_freed_data == 1, "PKO3 freed the data (df=0)");
        chk(b->pko_freed_to == AURA_DATA, "PKO3 freed it to the DATA aura");
        chk(b->data_freed_by_us == 0, "we did NOT free the data");
        chk(b->wqe_freed_by_us == 1, "we freed the WQE exactly once");
        chk(b->wqe_freed_to == AURA_WQE, "WQE went back to the WQE aura");
        chk(auras_balanced(&m), "every aura balances (no leak, no misdirect)");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 3. drop: we free both, each to its own aura ---------- */
    printf("\n[3] dropped packet\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        struct mock3_buf *b = push3(&m, IP(10,0,0,1), IP(8,8,8,8), 4444, 16, 1);
        dp_poll_once(&dp);
        chk(b->sent_to_pko == 0, "never handed to PKO3");
        chk(b->data_freed_by_us == 1, "we freed the data once");
        chk(b->wqe_freed_by_us == 1, "we freed the WQE once");
        chk(b->data_freed_to == AURA_DATA, "data returned to the DATA aura");
        chk(b->wqe_freed_to == AURA_WQE, "WQE returned to the WQE aura");
        chk(b->data_freed_to != b->wqe_freed_to,
            "the two frees went to DIFFERENT auras (single-pool code fails here)");
        chk(auras_balanced(&m), "every aura balances");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 4. send failure: ownership stays with us ---------- */
    printf("\n[4] descriptor queue rejects the packet\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        m.fail_send = 1;
        struct mock3_buf *b = push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 1);
        dp_poll_once(&dp);
        chk(b->sent_to_pko == 0, "not counted as sent");
        chk(b->pko_freed_data == 0, "PKO3 did NOT free the data");
        chk(b->data_freed_by_us == 1, "we freed the data ourselves");
        chk(b->wqe_freed_by_us == 1, "we freed the WQE ourselves");
        chk(auras_balanced(&m), "every aura still balances after a failed send");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 5. a burst, mixed verdicts ---------- */
    printf("\n[5] burst of mixed forward/drop\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        for (int i = 0; i < 3; i++)
            push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 1);
        for (int i = 0; i < 2; i++)
            push3(&m, IP(10,0,0,2), IP(8,8,8,8), 4444, 16, 1);
        int total = 0, n;
        while ((n = dp_poll_once(&dp)) > 0) total += n;
        chk(total == 5, "all five packets processed");
        chk(oc.stat_tx == 3, "three forwarded");
        int pko_frees = 0, our_data_frees = 0, our_wqe_frees = 0;
        for (int i = 0; i < m.n; i++) {
            pko_frees      += m.bufs[i].pko_freed_data;
            our_data_frees += m.bufs[i].data_freed_by_us;
            our_wqe_frees  += m.bufs[i].wqe_freed_by_us;
        }
        chk(pko_frees == 3, "PKO3 freed the three forwarded payloads");
        chk(our_data_frees == 2, "we freed only the two dropped payloads");
        chk(our_wqe_frees == 5, "every WQE freed exactly once");
        chk(auras_balanced(&m), "every aura balances across the burst");
        chk(m.auras[AURA_DATA].alloc == 5 && m.auras[AURA_WQE].alloc == 5,
            "both auras saw five allocations");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 6. teardown with work still queued ---------- */
    printf("\n[6] teardown leaves nothing outstanding\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 1);
        push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 1);
        dp_poll_once(&dp);
        dp_fini(&dp);
        chk(oc.bug_double_dispose == 0, "no double dispose through teardown");
    }
    free(region);

    /* ---------- 7. generation selection ---------- */
    printf("\n[7] generation selection\n");
    chk(oct_hw_for_gen(OCT_GEN_II) == &OCT_HW_CVMX, "gen II selects the OCTEON-II ops");
    chk(oct_hw_for_gen(OCT_GEN_III) == &OCT_HW_CVMX3, "gen III selects the OCTEON-III ops");
    chk(oct_hw_for_gen(OCT_GEN_NONE) == NULL, "no generation selects nothing");
    chk(strcmp(oct_gen_name(OCT_GEN_III), oct_gen_name(OCT_GEN_II)) != 0,
        "the two generations are named distinctly");

    printf("\n==== octeon-iii backend test: %d failed ====\n", g_fail);
    return g_fail ? 1 : 0;
}
