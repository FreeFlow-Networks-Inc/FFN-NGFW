/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dpmem.h -- FFN-NGFW DPDK data-plane shared-memory ABI (REWORK_CONTRACT §10).
 *
 * This header is the *contract* between:
 *   - the primary/zygote (ffn_dpdk_mp.c)          -- reserves the region, seeds bank 0
 *   - the flatcc wire consumer (owner FLATCC)      -- writes the INACTIVE bank + flips
 *   - the DP-FWD workers (ffn_fastpath_fwd.c)      -- read the ACTIVE bank
 *
 * Layout of the "ffn_dpmem" rte_memzone (single contiguous hugepage region):
 *
 *   +----------------------------------------------------------+  <- memzone base (= hdr)
 *   | struct ffn_dpmem_hdr   (magic/version/active_bank/...)    |
 *   |   struct ffn_dpmem_bank bank[0]  (slot directory)         |
 *   |   struct ffn_dpmem_bank bank[1]  (slot directory)         |
 *   +----------------------------------------------------------+  <- hdr->bank_off[0]
 *   | bank-0 arena: TLV records (models) laid end to end       |
 *   +----------------------------------------------------------+  <- hdr->bank_off[1]
 *   | bank-1 arena: TLV records (models) laid end to end       |
 *   +----------------------------------------------------------+
 *
 * Double-buffer protocol (single writer, many readers):
 *   writer:  populate INACTIVE bank arena + its slot[] directory, then
 *            ffn_dpmem_flip() (store-release on active_bank).
 *   reader:  ffn_dpmem_active() (load-acquire on active_bank), then read that
 *            bank's slot[] + arena. A reader that started before a flip keeps
 *            using the (still-intact) old bank; the writer only ever mutates
 *            the bank that is currently INACTIVE, so readers never tear.
 *
 * Slot offsets are stored *base-relative* (bytes from the memzone base), NOT as
 * absolute pointers, so model lookup is correct even if the region happened to
 * map at a different VA in some process. (ASLR is still required OFF for DPDK's
 * own internal shared pointers + any absolute pointers a serialized model may
 * embed -- see ffn_dpdk_mp.c ensure_no_aslr().)
 *
 * No DPDK includes, so it is safe to include from any of the cooperating C
 * files. It pulls in ffn_mpdp_consumer.h for the decoded MP->DP row structs the
 * write-side helpers retain, and forward-declares struct fp_policy_ent.
 *
 * RECONCILE NOTE: a bank exposes two content views -- the base-relative slot/TLV
 * records the fast path (ffn_fastpath_fwd.c) walks, and the typed arena-backed
 * fields the FLATCC consumer stages (ml/policy/threat-intel). Unifying the two
 * (fast path consuming the typed fields, or the consumer emitting TLV records)
 * is a pending DP-MP task; all three consumers compile against this one ABI.
 */
#ifndef FFN_DPMEM_H
#define FFN_DPMEM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>   /* memcpy/strlen for the writer helpers */

/* Decoded MP->DP row structs (struct ffn_mpdp_sig / ffn_mpdp_ioc / flowkey) live
 * in the FLATCC consumer header; the write-side helpers below retain them into a
 * bank arena. Documented dependency direction: ffn_mpdp_consumer.h only
 * forward-declares struct ffn_dpmem_hdr, so there is no include cycle. */
#include "ffn_mpdp_consumer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* fp_policy_ent (ffn_fastpath.h) is referenced only by pointer in a bank; a
 * forward declaration keeps this header free of the fast-path record ABIs and
 * independent of include order. */
struct fp_policy_ent;

/* 'F','D','P','M' little-endian => 0x4D504446 */
#define FFN_DPMEM_MAGIC     0x4D504446u
#define FFN_DPMEM_VERSION   1u
#define FFN_DPMEM_NAME      "ffn_dpmem"     /* rte_memzone name */
#define FFN_DPMEM_NBANKS    2u
#define FFN_DPMEM_ALIGN     64u             /* per-TLV arena alignment (cache line) */

/* Model/table types carried in a bank. One slot per type per bank. */
enum ffn_model_type {
    FFN_MDL_AC_TABLES    = 0,  /* Aho-Corasick goto/fail/output tables (ffn_fpga_emu) */
    FFN_MDL_DFA_TABLE    = 1,  /* regex DFA transition table */
    FFN_MDL_ML_TREE      = 2,  /* XGBoost portable flat tree table (ffn_ml_engine) */
    FFN_MDL_NGRAM_PARAMS = 3,  /* byte n-gram hashing params + weights */
    FFN_MDL_SIG_TABLE    = 4,  /* compiled signature table (ffn_sigdb rows) */
    FFN_MDL_COUNT        = 5
};

/* Per-model directory entry (fixed slot indexed by ffn_model_type). */
struct ffn_dpmem_slot {
    uint32_t type;      /* ffn_model_type (redundant, for walkers) */
    uint32_t flags;     /* FFN_DPMEM_SLOT_* */
    uint64_t offset;    /* base-relative byte offset to the payload (NOT the TLV hdr) */
    uint64_t size;      /* payload length in bytes */
    uint32_t version;   /* monotonically increasing per model */
    uint32_t crc32;     /* payload crc32 (0 = unchecked) */
};
#define FFN_DPMEM_SLOT_PRESENT  0x1u

/* Per-model TLV record header that prefixes every payload in a bank arena.
 * Makes the arena self-describing / walkable independent of the slot dir. */
struct ffn_dpmem_tlv {
    uint32_t type;      /* ffn_model_type */
    uint32_t flags;
    uint64_t length;    /* payload bytes that follow this header */
    uint32_t version;
    uint32_t crc32;
    /* uint8_t payload[length] immediately follows; next TLV is FFN_DPMEM_ALIGN'd */
};

/* One double-buffer bank: a slot directory over its arena, PLUS the typed model
 * fields the FLATCC consumer stages and a bound arena cursor for the
 * arena_alloc/arena_dup bump allocator.
 *
 * Two coexisting views of a bank's contents:
 *   (a) slot[]/TLV records -- base-relative, VA-independent; written by
 *       ffn_dpmem_bank_put() (model seeder), walked by ffn_fastpath_fwd.c.
 *   (b) typed fields below -- absolute pointers into this bank's arena; written
 *       by the FLATCC consumer. Valid cross-process ONLY because the region maps
 *       at one VA in every worker (ASLR off, see ffn_dpdk_mp.c ensure_no_aslr()).
 * The two are not yet unified -- see the file banner RECONCILE NOTE. */
struct ffn_dpmem_bank {
    uint32_t seq;                              /* bumped by writer while dirty (even=stable) */
    uint32_t model_count;                      /* # present slots */
    uint64_t used;                             /* bytes consumed in this bank's arena (bump cursor) */
    struct ffn_dpmem_slot slot[FFN_MDL_COUNT];

    /* arena binding (set by ffn_dpmem_bank(); absolute, VA-stable with ASLR off) */
    uint8_t *arena_base;                       /* == (uint8_t*)hdr + bank_off[i] */
    uint64_t arena_size;                       /* == hdr->bank_size              */

    /* inline-ML model (MlModelUpdate) */
    uint32_t ml_version;
    uint32_t ml_features_version;
    uint8_t  ml_kind;                          /* enum ffn_mpdp_mlkind           */
    uint8_t *ml_tree_blob;    uint32_t ml_tree_len;
    uint8_t *ml_ngram_params; uint32_t ml_ngram_len;

    /* per-vsys policy rulebase (PolicyUpdate -> fp_policy_ent[]) */
    struct fp_policy_ent *policy; uint32_t policy_n;

    /* threat-intel row set (ThreatIntelUpdate); rows deep-copied into the arena */
    uint32_t ti_seq;
    struct ffn_mpdp_sig *sig; uint32_t sig_n;
    struct ffn_mpdp_ioc *ioc; uint32_t ioc_n;

    /* hot single-sample verdict (SignatureVerdict; patched in place, no flip) */
    uint32_t hot_sid;
    uint8_t  hot_verdict;
    uint8_t  hot_sha[32];
    uint64_t hot_ts;
};

/* Region header (lives at the memzone base). */
struct ffn_dpmem_hdr {
    uint32_t magic;                            /* FFN_DPMEM_MAGIC */
    uint32_t version;                          /* FFN_DPMEM_VERSION */
    uint32_t active_bank;                      /* 0/1 -- load-acquire read, store-release write */
    uint32_t nb_workers;                       /* DP worker processes == rx/tx queue pairs */
    uint64_t total_size;                       /* full memzone size in bytes */
    uint64_t bank_off[FFN_DPMEM_NBANKS];       /* base-relative offset of each bank arena */
    uint64_t bank_size;                        /* size of EACH bank arena in bytes */
    uint64_t ctrl_flags;                       /* FFN_DPMEM_CF_* */
    uint64_t reserved[8];
    struct ffn_dpmem_bank bank[FFN_DPMEM_NBANKS];
    /* bank arenas follow at bank_off[0], bank_off[1] (see file banner) */
};
#define FFN_DPMEM_CF_ASLR_OFF   0x1ull         /* set by primary once ASLR confirmed off */

/* ---- MP<->DP control channel ABI (rte_ring + frame mempool) --------------- */
#define FFN_MPDP_RING_NAME   "ffn_mpdp_ctrl"   /* rte_ring of struct ffn_mpdp_frame* */
#define FFN_MPDP_POOL_NAME   "ffn_mpdp_frames" /* rte_mempool of struct ffn_mpdp_frame */
#define FFN_MPDP_RING_DEPTH  1024u             /* power of two */
#define FFN_MPDP_POOL_COUNT  256u
#define FFN_MPDP_FRAME_MAX   65536u

/* One enqueued flatcc-encoded MpDpMessage frame (ffn_mpdp.fbs / §9). */
struct ffn_mpdp_frame {
    uint32_t len;                              /* valid bytes in data[] */
    uint32_t flags;
    uint8_t  data[FFN_MPDP_FRAME_MAX];         /* flatcc buffer */
};

/* =========================================================================
 * Read-side helpers (workers) -- lock-free, acquire/release ordered.
 * ========================================================================= */
static inline int ffn_dpmem_valid(const struct ffn_dpmem_hdr *h)
{
    return h && h->magic == FFN_DPMEM_MAGIC && h->version == FFN_DPMEM_VERSION;
}

static inline uint32_t ffn_dpmem_active(const struct ffn_dpmem_hdr *h)
{
    return __atomic_load_n(&h->active_bank, __ATOMIC_ACQUIRE) & 1u;
}

static inline uint32_t ffn_dpmem_inactive(const struct ffn_dpmem_hdr *h)
{
    return ffn_dpmem_active(h) ^ 1u;
}

static inline struct ffn_dpmem_bank *
ffn_dpmem_bank_at(struct ffn_dpmem_hdr *h, uint32_t bank)
{
    return &h->bank[bank & 1u];
}

/* Resolve a base-relative offset to a live pointer in *this* process. */
static inline void *ffn_dpmem_ptr(struct ffn_dpmem_hdr *h, uint64_t off)
{
    return (void *)((uint8_t *)h + off);
}

/* Fetch a model from an explicit bank. Returns payload ptr or NULL. */
static inline const void *
ffn_dpmem_model(struct ffn_dpmem_hdr *h, uint32_t bank, enum ffn_model_type t,
                uint64_t *size_out, uint32_t *ver_out)
{
    struct ffn_dpmem_bank *bk;
    const struct ffn_dpmem_slot *s;
    if ((unsigned)t >= FFN_MDL_COUNT)
        return NULL;
    bk = ffn_dpmem_bank_at(h, bank);
    s = &bk->slot[t];
    if (!(s->flags & FFN_DPMEM_SLOT_PRESENT))
        return NULL;
    if (size_out) *size_out = s->size;
    if (ver_out)  *ver_out  = s->version;
    return (const uint8_t *)h + s->offset;
}

/* Worker convenience: fetch a model from the currently-active bank. */
static inline const void *
ffn_dpmem_active_model(struct ffn_dpmem_hdr *h, enum ffn_model_type t,
                       uint64_t *size_out, uint32_t *ver_out)
{
    return ffn_dpmem_model(h, ffn_dpmem_active(h), t, size_out, ver_out);
}

/* =========================================================================
 * Write-side helpers (primary seed + flatcc consumer) -- single writer.
 * ========================================================================= */
static inline uint64_t ffn_dpmem_align_up(uint64_t x, uint64_t a)
{
    return (x + (a - 1)) & ~(a - 1);
}

/* Publish: store-release the new active bank. Readers see a consistent bank. */
static inline void ffn_dpmem_flip(struct ffn_dpmem_hdr *h)
{
    uint32_t next = (__atomic_load_n(&h->active_bank, __ATOMIC_RELAXED) ^ 1u) & 1u;
    __atomic_store_n(&h->active_bank, next, __ATOMIC_RELEASE);
}

/* Set active bank explicitly (used once at seed time). */
static inline void ffn_dpmem_set_active(struct ffn_dpmem_hdr *h, uint32_t bank)
{
    __atomic_store_n(&h->active_bank, bank & 1u, __ATOMIC_RELEASE);
}

/* Empty a bank's arena so it can be repopulated from scratch. */
static inline void ffn_dpmem_bank_reset(struct ffn_dpmem_hdr *h, uint32_t bank)
{
    struct ffn_dpmem_bank *bk = ffn_dpmem_bank_at(h, bank);
    unsigned i;
    bk->seq++;                 /* mark dirty (odd) */
    bk->used = 0;
    bk->model_count = 0;
    for (i = 0; i < FFN_MDL_COUNT; i++) {
        bk->slot[i].flags = 0;
        bk->slot[i].size = 0;
        bk->slot[i].offset = 0;
        bk->slot[i].version = 0;
        bk->slot[i].crc32 = 0;
    }
}

/* Bump-allocate + copy one model into a bank arena; updates its slot dir.
 * Returns 0 on success, -1 on bad type / arena overflow. */
static inline int
ffn_dpmem_bank_put(struct ffn_dpmem_hdr *h, uint32_t bank, enum ffn_model_type t,
                   const void *src, uint64_t len, uint32_t version, uint32_t crc32)
{
    struct ffn_dpmem_bank *bk;
    uint8_t *arena;
    struct ffn_dpmem_tlv *tlv;
    uint8_t *payload;
    uint64_t cur, need;

    if ((unsigned)t >= FFN_MDL_COUNT)
        return -1;
    bk = ffn_dpmem_bank_at(h, bank);
    cur  = ffn_dpmem_align_up(bk->used, FFN_DPMEM_ALIGN);
    need = sizeof(struct ffn_dpmem_tlv) + len;
    if (cur + need > h->bank_size)
        return -1;                                   /* arena overflow */

    arena   = (uint8_t *)h + h->bank_off[bank & 1u];
    tlv     = (struct ffn_dpmem_tlv *)(arena + cur);
    tlv->type = (uint32_t)t;
    tlv->flags = 0;
    tlv->length = len;
    tlv->version = version;
    tlv->crc32 = crc32;
    payload = (uint8_t *)(tlv + 1);
    if (src && len)
        memcpy(payload, src, len);

    bk->slot[t].type    = (uint32_t)t;
    bk->slot[t].offset  = (uint64_t)(payload - (uint8_t *)h);  /* base-relative */
    bk->slot[t].size    = len;
    bk->slot[t].version = version;
    bk->slot[t].crc32   = crc32;
    bk->slot[t].flags   = FFN_DPMEM_SLOT_PRESENT;
    bk->used = cur + need;
    bk->model_count++;
    return 0;
}

/* Clone src bank -> dst bank (arena bytes + slot dir with rebased offsets), so
 * the flatcc consumer can start from the live model set and apply a delta into
 * the inactive bank before flipping. Call ffn_dpmem_bank_reset(dst) is NOT
 * needed first -- this overwrites. */
static inline void
ffn_dpmem_bank_clone(struct ffn_dpmem_hdr *h, uint32_t dst, uint32_t src)
{
    struct ffn_dpmem_bank *bd = ffn_dpmem_bank_at(h, dst);
    struct ffn_dpmem_bank *bs = ffn_dpmem_bank_at(h, src);
    uint8_t *ad = (uint8_t *)h + h->bank_off[dst & 1u];
    uint8_t *as = (uint8_t *)h + h->bank_off[src & 1u];
    int64_t delta = (int64_t)h->bank_off[dst & 1u] - (int64_t)h->bank_off[src & 1u];
    unsigned i;
    if (bs->used)
        memcpy(ad, as, bs->used);
    for (i = 0; i < FFN_MDL_COUNT; i++) {
        bd->slot[i] = bs->slot[i];
        if (bd->slot[i].flags & FFN_DPMEM_SLOT_PRESENT)
            bd->slot[i].offset = (uint64_t)((int64_t)bs->slot[i].offset + delta);
    }
    bd->used = bs->used;
    bd->model_count = bs->model_count;
    bd->seq++;

    /* Carry the arena binding + typed model fields into dst, rebasing every
     * top-level arena pointer by the inter-arena delta (their payload bytes were
     * memcpy'd above). Inner row strings (sig/ioc) are re-interned by
     * ffn_dpmem_threatintel_load on the next threat-intel apply, so they are not
     * deep-rebased here. */
    bd->arena_base = ad;
    bd->arena_size = h->bank_size;
    bd->ml_version = bs->ml_version;
    bd->ml_features_version = bs->ml_features_version;
    bd->ml_kind = bs->ml_kind;
    bd->ml_tree_len = bs->ml_tree_len;
    bd->ml_ngram_len = bs->ml_ngram_len;
    bd->ml_tree_blob    = bs->ml_tree_blob    ? bs->ml_tree_blob    + delta : NULL;
    bd->ml_ngram_params = bs->ml_ngram_params ? bs->ml_ngram_params + delta : NULL;
    bd->policy   = bs->policy ? (struct fp_policy_ent *)((uint8_t *)bs->policy + delta) : NULL;
    bd->policy_n = bs->policy_n;
    bd->ti_seq = bs->ti_seq;
    bd->sig = bs->sig ? (struct ffn_mpdp_sig *)((uint8_t *)bs->sig + delta) : NULL;
    bd->sig_n = bs->sig_n;
    bd->ioc = bs->ioc ? (struct ffn_mpdp_ioc *)((uint8_t *)bs->ioc + delta) : NULL;
    bd->ioc_n = bs->ioc_n;
    bd->hot_sid = bs->hot_sid;
    bd->hot_verdict = bs->hot_verdict;
    bd->hot_ts = bs->hot_ts;
    memcpy(bd->hot_sha, bs->hot_sha, sizeof bd->hot_sha);
}

/* =========================================================================
 * FLATCC-consumer-facing bank helpers (ffn_mpdp_consumer.c).
 * Expose the same double-buffer as typed accessors + an arena bump allocator,
 * so the wire consumer can clone the live bank, append decoded models into the
 * inactive bank's arena, and publish.
 * ========================================================================= */

/* Resolve a bank and bind its arena cursor (absolute base + size) so the
 * arena_alloc/arena_dup bump allocator can work from the bank pointer alone. */
static inline struct ffn_dpmem_bank *
ffn_dpmem_bank(struct ffn_dpmem_hdr *h, uint32_t bank)
{
    struct ffn_dpmem_bank *b = &h->bank[bank & 1u];
    b->arena_base = (uint8_t *)h + h->bank_off[bank & 1u];
    b->arena_size = h->bank_size;
    return b;
}

/* Bump-allocate `size` bytes from bank `b`'s arena (cache-line aligned).
 * Returns NULL on arena overflow. Requires ffn_dpmem_bank() to have bound b. */
static inline void *
ffn_dpmem_arena_alloc(struct ffn_dpmem_bank *b, uint64_t size)
{
    uint64_t cur = ffn_dpmem_align_up(b->used, FFN_DPMEM_ALIGN);
    if (!b->arena_base || cur + size > b->arena_size)
        return NULL;                            /* arena overflow / unbound bank */
    b->used = cur + size;
    return b->arena_base + cur;
}

/* Copy `len` bytes from `src` into bank `b`'s arena; returns the copy or NULL. */
static inline uint8_t *
ffn_dpmem_arena_dup(struct ffn_dpmem_bank *b, const void *src, uint64_t len)
{
    uint8_t *p = (uint8_t *)ffn_dpmem_arena_alloc(b, len);
    if (p && src && len)
        memcpy(p, src, len);
    return p;
}

/* Clone the currently-active bank into `dst` (usually the inactive bank) so the
 * consumer starts from the live model set, then patches a delta. Returns 0. */
static inline int
ffn_dpmem_clone_active(struct ffn_dpmem_hdr *h, uint32_t dst)
{
    ffn_dpmem_bank_clone(h, dst, ffn_dpmem_active(h));
    return 0;
}

/* Publish `bank` as the new active bank (store-release). Marks it stable.
 * Consumer stages into the inactive bank and publishes it -> equivalent to a
 * flip, but names the target explicitly (idempotent, no double-flip race). */
static inline void
ffn_dpmem_publish(struct ffn_dpmem_hdr *h, uint32_t bank)
{
    struct ffn_dpmem_bank *b = &h->bank[bank & 1u];
    if (b->seq & 1u) b->seq++;                  /* even => stable */
    __atomic_store_n(&h->active_bank, bank & 1u, __ATOMIC_RELEASE);
}

/* ThreatIntelUpdate -> retain decoded rows in bank `bank`'s arena. The row
 * arrays are already arena-backed (the consumer allocated them); here we
 * deep-copy their string/digest payloads so the retained pointers stay valid
 * after the wire buffer is recycled, then record the row set + seq.
 * NOTE: Aho-Corasick/DFA/avhash compilation and the removes[] delta-merge from
 * these rows remain a DP-MP build step (see the file banner RECONCILE NOTE).
 * Returns 0. */
static inline int
ffn_dpmem_threatintel_load(struct ffn_dpmem_hdr *h, uint32_t bank, uint32_t seq,
                           struct ffn_mpdp_sig *adds, uint32_t n_adds,
                           const uint32_t *removes, uint32_t n_removes,
                           struct ffn_mpdp_ioc *iocs, uint32_t n_iocs)
{
    struct ffn_dpmem_bank *b = ffn_dpmem_bank(h, bank);
    uint32_t i;
    (void)removes; (void)n_removes;             /* delta-remove merge: DP-MP TODO */

    for (i = 0; i < n_adds; i++) {
        struct ffn_mpdp_sig *s = &adds[i];
        if (s->name)        s->name        = (const char *)ffn_dpmem_arena_dup(b, s->name,        (uint64_t)strlen(s->name) + 1);
        if (s->sig_type)    s->sig_type    = (const char *)ffn_dpmem_arena_dup(b, s->sig_type,    (uint64_t)strlen(s->sig_type) + 1);
        if (s->hash_type)   s->hash_type   = (const char *)ffn_dpmem_arena_dup(b, s->hash_type,   (uint64_t)strlen(s->hash_type) + 1);
        if (s->hex_pattern) s->hex_pattern = (const char *)ffn_dpmem_arena_dup(b, s->hex_pattern, (uint64_t)strlen(s->hex_pattern) + 1);
        if (s->family)      s->family      = (const char *)ffn_dpmem_arena_dup(b, s->family,      (uint64_t)strlen(s->family) + 1);
        if (s->digest && s->digest_len)
            s->digest = ffn_dpmem_arena_dup(b, s->digest, s->digest_len);
    }
    for (i = 0; i < n_iocs; i++) {
        struct ffn_mpdp_ioc *o = &iocs[i];
        if (o->kind)  o->kind  = (const char *)ffn_dpmem_arena_dup(b, o->kind,  (uint64_t)strlen(o->kind) + 1);
        if (o->value) o->value = (const char *)ffn_dpmem_arena_dup(b, o->value, (uint64_t)strlen(o->value) + 1);
    }

    b->ti_seq = seq;
    b->sig = adds; b->sig_n = n_adds;
    b->ioc = iocs; b->ioc_n = n_iocs;
    return 0;
}

/* SignatureVerdict -> patch the ACTIVE bank in place (no flip): the fast path
 * reads this hot single-sample verdict immediately. Returns 0. */
static inline int
ffn_dpmem_sigverdict_apply(struct ffn_dpmem_hdr *h, uint32_t sid,
                           const uint8_t *sha, uint32_t slen,
                           uint8_t verdict, uint64_t ts)
{
    struct ffn_dpmem_bank *b = ffn_dpmem_bank_at(h, ffn_dpmem_active(h));
    b->hot_sid = sid;
    b->hot_verdict = verdict;
    b->hot_ts = ts;
    memset(b->hot_sha, 0, sizeof b->hot_sha);
    if (sha && slen)
        memcpy(b->hot_sha, sha, slen < sizeof b->hot_sha ? slen : sizeof b->hot_sha);
    return 0;
}

/* =========================================================================
 * Cross-file entry points (declared here = the shared ABI; defined elsewhere).
 * ffn_dpdk_mp.c ships __attribute__((weak)) fallbacks so it links standalone;
 * the real owners provide strong definitions.
 * ========================================================================= */

/* DP worker entry -- owner: DP-FWD (ffn_fastpath_fwd.c refactor).
 * Called once per secondary worker after EAL secondary init + queue attach. */
struct ffn_dp_worker_args {
    uint16_t port;                 /* ethdev port to service */
    uint16_t queue;                /* this worker's rx/tx queue index */
    uint16_t nb_workers;
    uint16_t worker_id;
    void    *pool;                 /* struct rte_mempool* (opaque here); may be NULL */
    struct ffn_dpmem_hdr *dpmem;   /* attached shared model region */
    volatile int *stop;            /* worker exits when *stop != 0 */
};
int ffn_dp_worker_run(const struct ffn_dp_worker_args *a);

/* Initial model seed into a bank -- owner: EMU/ML (fpga_emu + ml_engine C side).
 * Loads AC/DFA + ML models (e.g. from tables_dir) via ffn_dpmem_bank_put(). */
int ffn_models_load_initial(struct ffn_dpmem_hdr *dpmem, uint32_t bank,
                            const char *tables_dir);

/* flatcc wire consumer -- owner: FLATCC (ffn_mpdp_consumer.c, strong def).
 * Decodes ONE MpDpMessage frame and applies model/sig/policy updates into the
 * INACTIVE bank (clones active->inactive first, then patches). The strong owner
 * PUBLISHES (flips) the bank itself on success, so it returns:
 *   0 = handled (published if a flip was warranted, or in-place/telemetry no-op)
 *       -- the caller must NOT flip again;
 *  <0 = decode/apply error.
 * (The removed weak fallback used the older ">0 => caller flips" contract; the
 * ctrl thread in ffn_dpdk_mp.c flips only on rc>0, so 0 is a safe no-double-flip
 * result for either.) */
int ffn_flatcc_apply(struct ffn_dpmem_hdr *dpmem, uint32_t inactive_bank,
                     const void *frame, size_t frame_len);

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct ffn_dpmem_slot) == 32,
               "ffn_dpmem_slot ABI must stay 32 bytes");
_Static_assert(sizeof(struct ffn_dpmem_tlv) == 24,
               "ffn_dpmem_tlv ABI must stay 24 bytes");
_Static_assert(FFN_MDL_COUNT == 5, "model-type table changed -- bump version");
#endif

#ifdef __cplusplus
}
#endif
#endif /* FFN_DPMEM_H */
