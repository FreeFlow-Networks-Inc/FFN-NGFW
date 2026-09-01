/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon3_test.c -- OCTEON-III backend test against mock PKI/SSO/PKO3.
 *
 * The OCTEON-II test already proves the general "release each buffer exactly
 * once" contract. This one exists for the things OCTEON-III changes, because
 * those are the ways a working OCTEON-II port silently wedges a CN78XX:
 *
 *   * FPA3 frees go to an AURA, not a pool, and the aura is global --
 *     (node << 10) | local_aura. Returning a buffer to the wrong aura corrupts
 *     accounting with no immediate symptom, so the mock checks every free
 *     landed in the right one and that each aura balances.
 *   * PKI usually puts the WQE INSIDE the first packet buffer. Then WQE and data
 *     are ONE allocation: freeing both is a double free, and on the forward path
 *     PKO3 has already recycled that memory, so even READING the WQE to decide
 *     is a use-after-free. Both cases are exercised, and the mock poisons a
 *     buffer the moment it is freed so a late read is caught rather than
 *     tolerated.
 *   * Ownership on transmit is the SEND_HDR `df` bit plus the aura in that
 *     header. The mock honours df: with df=0 it frees the data itself, as PKO3
 *     would, so a caller that also frees is caught as a double free.
 *   * The descriptor must describe the packet the hardware will actually send:
 *     ONE SEND_LINK for the whole PKI chain, with the sub-command code the
 *     hardware defines. An earlier version of this backend emitted one LINK per
 *     segment and used 0x3 as the LINK code, which is not a valid SUBDC3 at all.
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

/* ---------------- mock FPA3 + PKI + PKO3 ---------------- */
#define MOCK3_MAX    8
#define MOCK3_AURAS  8

/* A global aura on a two-node part: node 1, local aura 3 -> (1 << 10) | 3.
 * Deliberately not a small number, so code that truncates it to the local part
 * or forgets the node fails here. */
#define AURA_LOCAL   3
#define AURA_NODE    1
#define AURA_DATA    ((AURA_NODE << 10) | AURA_LOCAL)

/* Compose a PKI buffer-pointer word the way the hardware lays it out, so the
 * test drives the same decode path the backend uses. */
static uint64_t pki_ptr_make(uint64_t addr, uint16_t size, int outside)
{
    return ((uint64_t)size << 48) |
           ((uint64_t)(outside ? 1 : 0) << 47) |
           (addr & 0x3FFFFFFFFFFULL);
}

/* Auras are indexed by their LOCAL number in this mock; the global form is what
 * the code under test carries around. */
struct mock3_aura { int alloc, freed; };

struct mock3_buf {
    uint8_t  data[256];
    uint32_t len;
    uint16_t in_port;
    uint8_t  segs;
    uint8_t  queued;
    uint8_t  wqe_separate;      /* what PKI decided for this packet */
    uint16_t aura;

    int sent_to_pko;
    int data_freed_by_us, wqe_freed_by_us;
    int data_freed_to, wqe_freed_to;    /* aura each free was credited to */
    int pko_freed_data;                 /* PKO3 freed it, as df=0 requires */
    int pko_freed_to;

    /* Set once the buffer holding the WQE has gone back to its aura. Any later
     * access through the WQE is a use-after-free and is counted, not ignored. */
    int wqe_storage_gone;
    int use_after_free;

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

static void aura_alloc(struct mock3_hw *m, int gaura)
{
    int l = gaura & 0x3ff;
    if (l >= 0 && l < MOCK3_AURAS) m->auras[l].alloc++;
}
static void aura_free(struct mock3_hw *m, int gaura)
{
    int l = gaura & 0x3ff;
    if (l >= 0 && l < MOCK3_AURAS) m->auras[l].freed++;
}
static int auras_balanced(const struct mock3_hw *m)
{
    for (int i = 0; i < MOCK3_AURAS; i++)
        if (m->auras[i].alloc != m->auras[i].freed) return 0;
    return 1;
}
static int aura_frees(const struct mock3_hw *m, int gaura)
{
    return m->auras[gaura & 0x3ff].freed;
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
    w->data_aura = b->aura;
    w->pkt_ptr   = pki_ptr_make((uint64_t)(uintptr_t)b->data,
                                (uint16_t)b->len, b->wqe_separate);
    /* The backend must take this from the buffer pointer on RECEIVE. */
    w->wqe_separate = FFN_PKI_PTR_OUTSIDE(w->pkt_ptr);
    w->flow_tag  = 0x1234;
    w->disp      = OCT_DISP_HELD;

    /* PKI took one buffer for the data, and a second one for the WQE only when
     * the WQE did not fit inside the first. */
    aura_alloc(m, b->aura);
    if (b->wqe_separate)
        aura_alloc(m, b->aura);
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
    /* df = 0 means PKO3 returns the data buffer to the aura in SEND_HDR once the
     * packet is on the wire -- and if the WQE lives in that buffer, it is gone
     * with it. */
    if (b->desc.hdr.df == 0) {
        b->pko_freed_data++;
        b->pko_freed_to = b->desc.hdr.aura;
        aura_free(m, b->desc.hdr.aura);
        if (!b->wqe_separate)
            b->wqe_storage_gone = 1;
    }
    return 0;
}

static void mock3_data_free(struct oct_ctx *c, struct oct_wqe *w)
{
    struct mock3_hw *m = (struct mock3_hw *)c->hw_priv;
    struct mock3_buf *b = (struct mock3_buf *)w->hw;
    /* The real one walks the chain out of the WQE, so being called after the
     * WQE's storage is gone would be a use-after-free. */
    if (b->wqe_storage_gone) b->use_after_free++;
    b->data_freed_by_us++;
    b->data_freed_to = w->data_aura;
    aura_free(m, w->data_aura);
    if (!b->wqe_separate)
        b->wqe_storage_gone = 1;    /* the WQE lived in that buffer */
}

static void mock3_wqe_free(struct oct_ctx *c, struct oct_wqe *w)
{
    struct mock3_hw *m = (struct mock3_hw *)c->hw_priv;
    struct mock3_buf *b = (struct mock3_buf *)w->hw;

    /* This is what the real backend does, driven by the flag captured on
     * receive -- and crucially without reading the WQE, which by now may be
     * recycled memory. */
    if (!w->wqe_separate)
        return;

    if (b->wqe_storage_gone) b->use_after_free++;
    b->wqe_freed_by_us++;
    b->wqe_freed_to = w->data_aura;
    aura_free(m, w->data_aura);
    b->wqe_storage_gone = 1;
}

static const struct oct_hw_ops MOCK3_HW = {
    "mock(octeon-iii pki/sso/pko3)",
    mock3_init, mock3_fini, mock3_work_get,
    mock3_send, mock3_data_free, mock3_wqe_free
};

/* ---------------- frame + policy builders ---------------- */
static struct mock3_buf *push3(struct mock3_hw *m, uint32_t sip, uint32_t dip,
                               uint16_t dport, uint16_t in_port, int wqe_separate)
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
    b->in_port      = in_port;
    b->segs         = 1;
    b->queued       = 1;
    b->wqe_separate = (uint8_t)(wqe_separate ? 1 : 0);
    b->aura         = AURA_DATA;
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

/* Total buffers we released ourselves across every packet in the mock. */
static void tally(const struct mock3_hw *m, int *pko, int *ours, int *uaf)
{
    *pko = *ours = *uaf = 0;
    for (int i = 0; i < m->n; i++) {
        *pko  += m->bufs[i].pko_freed_data;
        *ours += m->bufs[i].data_freed_by_us + m->bufs[i].wqe_freed_by_us;
        *uaf  += m->bufs[i].use_after_free;
    }
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

    /* ---------- 1. PKI buffer-pointer decode ---------- */
    printf("[1] PKI buffer pointer decode\n");
    {
        uint64_t u = pki_ptr_make(0x3FF00000055ULL, 0x1234, 1);
        chk(FFN_PKI_PTR_SIZE(u) == 0x1234, "size comes back out");
        chk(FFN_PKI_PTR_OUTSIDE(u) == 1, "packet_outside_wqe comes back out");
        chk(FFN_PKI_PTR_ADDR(u) == 0x3FF00000055ULL, "42-bit address comes back out");
        u = pki_ptr_make(0x40ULL, 64, 0);
        chk(FFN_PKI_PTR_OUTSIDE(u) == 0, "WQE-inside-buffer decodes as 0");
        chk(FFN_PKI_PTR_ADDR(u) == 0x40ULL, "small address is not sign-extended");
    }

    /* ---------- 2. descriptor assembly, no hardware needed ---------- */
    printf("\n[2] SEND_HDR/SEND_LINK assembly\n");
    {
        struct oct_wqe w;
        struct pko3_desc d;
        memset(&w, 0, sizeof(w));
        w.len = 64; w.segs = 1; w.data_aura = AURA_DATA;
        w.data = (uint8_t *)0x1000;
        w.pkt_ptr = pki_ptr_make(0x1000, 64, 1);

        chk(oct3_build_desc(&d, &w, 0) == DP_OK, "builds for a linear packet");
        chk(d.words == 2, "one HDR + one LINK = 2 words");
        chk(d.link.subdc == PKO3_SUBDC3_LINK, "segment is SEND_LINK");
        chk(PKO3_SUBDC3_LINK == 0x0,
            "LINK is the hardware's SUBDC3 code 0x0, not an invented one");
        chk(d.hdr.total == 64, "SEND_HDR carries the total length");
        chk(d.hdr.df == 0, "df=0 on forward: PKO3 frees the data");
        chk(d.hdr.ii == 1, "ii=1 so df alone governs freeing, not per-buffer bits");
        chk(d.hdr.aura == AURA_DATA, "SEND_HDR carries the packet's global aura");
        chk(d.gaura == AURA_DATA, "forward passes the aura to the SDK positively");
        chk(d.link.addr == 0x1000 && d.link.size == 64,
            "SEND_LINK points at the data with this segment's size");

        chk(oct3_build_desc(&d, &w, 1) == DP_OK, "builds with keep_data");
        chk(d.hdr.df == 1, "df=1 when the caller keeps the data");
        chk(d.gaura < 0, "keep_data maps onto the SDK's negative-aura convention");

        /* One LINK describes the whole chain, however many buffers PKI used. */
        w.segs = 4;
        chk(oct3_build_desc(&d, &w, 0) == DP_OK, "builds for a 4-buffer chain");
        chk(d.words == 2,
            "still 2 words: LINK makes PKO3 walk the chain PKI already built");

        /* Refusals must be clean: nothing usable, nothing issued. */
        struct pko3_desc before, probe;
        memset(&before, 0xEE, sizeof(before));

        w.segs = 1;
        w.len = 0;
        probe = before;
        chk(oct3_build_desc(&probe, &w, 0) == DP_ERR_TOOMANY, "refuses a zero-length packet");
        chk(memcmp(&probe, &before, sizeof(probe)) == 0,
            "refused build leaves the descriptor untouched (nothing to issue)");

        w.len = PKO3_MAX_TOTAL + 1;
        chk(oct3_build_desc(&probe, &w, 0) == DP_ERR_TOOMANY,
            "refuses a length PKO_SEND_HDR_S[TOTAL] cannot hold");

        w.len = 64;
        w.pkt_ptr = 0;
        chk(oct3_build_desc(&probe, &w, 0) == DP_ERR_TOOMANY, "refuses a null buffer pointer");

        w.pkt_ptr = pki_ptr_make(0x1000, 64, 1);
        w.data_aura = PKO3_MAX_AURA + 1;
        chk(oct3_build_desc(&probe, &w, 0) == DP_ERR_TOOMANY,
            "refuses an aura wider than the 12-bit header field");
        w.data_aura = AURA_DATA;

        chk(oct3_build_desc(NULL, &w, 0) == DP_ERR_TOOMANY, "rejects a NULL descriptor");
        chk(oct3_build_desc(&d, NULL, 0) == DP_ERR_TOOMANY, "rejects a NULL wqe");
    }

    /* ---------- 3. forward, WQE in its own buffer ---------- */
    printf("\n[3] forwarded packet, WQE is a separate allocation\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        struct mock3_buf *b = push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 1);
        int n = dp_poll_once(&dp);
        chk(n == 1, "one packet polled");
        chk(oc.stat_tx == 1, "backend transmitted 1");
        chk(b->desc_built == 1, "descriptor built exactly once");
        chk(b->sent_to_pko == 1, "handed to PKO3 exactly once");
        chk(b->pko_freed_data == 1, "PKO3 freed the data (df=0)");
        chk(b->pko_freed_to == AURA_DATA, "PKO3 freed it to the packet's aura");
        chk(b->data_freed_by_us == 0, "we did NOT free the data");
        chk(b->wqe_freed_by_us == 1, "we freed the WQE exactly once");
        chk(b->use_after_free == 0, "nothing touched the WQE after it was gone");
        chk(aura_frees(&m, AURA_DATA) == 2, "two buffers returned: data and WQE");
        chk(auras_balanced(&m), "the aura balances (no leak, no misdirect)");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 4. forward, WQE inside the packet buffer ---------- */
    printf("\n[4] forwarded packet, WQE shares the first packet buffer\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        struct mock3_buf *b = push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 0);
        dp_poll_once(&dp);
        chk(oc.stat_tx == 1, "backend transmitted 1");
        chk(b->pko_freed_data == 1, "PKO3 freed the one buffer");
        chk(b->wqe_freed_by_us == 0,
            "we did NOT free the WQE -- PKO3 already released that memory");
        chk(b->data_freed_by_us == 0, "we did not free the data either");
        chk(b->use_after_free == 0,
            "the WQE was never read after PKO3 could have recycled it");
        chk(aura_frees(&m, AURA_DATA) == 1, "exactly one buffer returned");
        chk(auras_balanced(&m), "the aura balances");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 5. drop, both WQE placements ---------- */
    printf("\n[5] dropped packets\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        struct mock3_buf *sep = push3(&m, IP(10,0,0,1), IP(8,8,8,8), 4444, 16, 1);
        struct mock3_buf *shr = push3(&m, IP(10,0,0,2), IP(8,8,8,8), 4444, 16, 0);
        int n;
        while ((n = dp_poll_once(&dp)) > 0) { }
        chk(sep->sent_to_pko == 0 && shr->sent_to_pko == 0, "neither reached PKO3");
        chk(sep->data_freed_by_us == 1 && sep->wqe_freed_by_us == 1,
            "separate WQE: we free both buffers");
        chk(shr->data_freed_by_us == 1 && shr->wqe_freed_by_us == 0,
            "shared WQE: we free the one buffer, once");
        chk(sep->data_freed_to == AURA_DATA, "data returned to the packet's aura");
        chk(sep->wqe_freed_to == AURA_DATA,
            "the WQE goes to that SAME aura -- there is no separate WQE aura");
        chk(sep->use_after_free == 0 && shr->use_after_free == 0, "no use after free");
        chk(aura_frees(&m, AURA_DATA) == 3, "three buffers in total came back");
        chk(auras_balanced(&m), "the aura balances");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 6. send failure: ownership stays with us ---------- */
    printf("\n[6] descriptor queue rejects the packet\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        m.fail_send = 1;
        struct mock3_buf *b = push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 1);
        dp_poll_once(&dp);
        chk(b->sent_to_pko == 0, "not counted as sent");
        chk(b->pko_freed_data == 0, "PKO3 did NOT free the data");
        chk(b->data_freed_by_us == 1, "we freed the data ourselves");
        chk(b->wqe_freed_by_us == 1, "we freed the WQE ourselves");
        chk(b->use_after_free == 0, "the WQE was still ours to read");
        chk(auras_balanced(&m), "the aura still balances after a failed send");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 7. a burst, mixed verdicts and mixed WQE placement ---------- */
    printf("\n[7] burst of mixed forward/drop\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        for (int i = 0; i < 3; i++)
            push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, i & 1);
        for (int i = 0; i < 2; i++)
            push3(&m, IP(10,0,0,2), IP(8,8,8,8), 4444, 16, i & 1);
        int total = 0, n;
        while ((n = dp_poll_once(&dp)) > 0) total += n;
        chk(total == 5, "all five packets processed");
        chk(oc.stat_tx == 3, "three forwarded");
        int pko, ours, uaf;
        tally(&m, &pko, &ours, &uaf);
        chk(pko == 3, "PKO3 freed the three forwarded payloads");
        /* forwarded: 1 separate WQE freed by us; dropped: 1 shared (1 buffer) +
         * 1 separate (2 buffers) = 3. */
        chk(ours == 4, "we released exactly the four buffers PKO3 did not");
        chk(uaf == 0, "no use after free anywhere in the burst");
        chk(auras_balanced(&m), "the aura balances across the burst");
        chk(oc.bug_double_dispose == 0, "no double dispose");
    }
    dp_fini(&dp); free(region);

    /* ---------- 8. teardown with work still queued ---------- */
    printf("\n[8] teardown leaves nothing outstanding\n");
    setup(&dp, &oc, &m, &region, 2);
    {
        push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 1);
        push3(&m, IP(10,0,0,1), IP(8,8,8,8), 443, 16, 0);
        dp_poll_once(&dp);
        dp_fini(&dp);
        chk(auras_balanced(&m), "the aura balances through teardown");
        chk(oc.bug_double_dispose == 0, "no double dispose through teardown");
    }
    free(region);

    /* ---------- 9. generation selection ---------- */
    printf("\n[9] generation selection\n");
    chk(oct_hw_for_gen(OCT_GEN_II) == &OCT_HW_CVMX, "gen II selects the OCTEON-II ops");
    chk(oct_hw_for_gen(OCT_GEN_III) == &OCT_HW_CVMX3, "gen III selects the OCTEON-III ops");
    chk(oct_hw_for_gen(OCT_GEN_NONE) == NULL, "no generation selects nothing");
    chk(strcmp(oct_gen_name(OCT_GEN_III), oct_gen_name(OCT_GEN_II)) != 0,
        "the two generations are named distinctly");

    printf("\n==== octeon-iii backend test: %d failed ====\n", g_fail);
    return g_fail ? 1 : 0;
}
