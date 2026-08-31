/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_mpdp_consumer.c -- C consumer of the MP<->DP FlatBuffers wire.
 *
 * OWNER: FLATCC.  Implements ffn_mpdp_consumer.h against the flatcc code
 * generated from ffn_mpdp.fbs (REWORK_CONTRACT ADDENDUM Section 9) and the
 * shared dpmem double-buffer from ffn_dpmem.h (owned by DP-MP).
 *
 * flatcc code generation (Makefile owner adds the rule; run on the box):
 *
 *     flatcc -a -o . ../ffn_mpdp.fbs
 *
 *   -a  == reader + builder + verifier + json parser/printer.  Produces
 *          ffn_mpdp_reader.h, ffn_mpdp_builder.h, ffn_mpdp_verifier.h, ...
 *   Link against the flatcc runtime: -lflatccrt  (and -I<flatcc>/include).
 *
 * Wire-format note (IMPORTANT)
 * ----------------------------
 * The flatcc reader/builder here speak *real FlatBuffers*.  On this offline
 * dev box, ffn_mpdp_wire.py has no `flatbuffers` runtime, so its parse()/build
 * fall back to a bespoke "FMDP" length-prefixed frame that is NOT FlatBuffers
 * wire-compatible -- it only preserves the same *field order + union tag* as
 * the schema.  Field/union parity is therefore guaranteed, but byte-for-byte
 * interop needs the Pass-2 MP side to switch ffn_mpdp_wire.py onto the
 * `flatbuffers` runtime + flatc/flatcc-generated Python bindings (its own
 * docstring already calls this out).  ffn_mpdp_apply() below rejects anything
 * that does not verify as a real FlatBuffers root, so a stray FMDP fallback
 * frame is safely refused rather than misread.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>         /* atoi */
#include <string.h>
#include <arpa/inet.h>      /* inet_pton, ntohl */

#include "ffn_fastpath.h"       /* struct fp_policy_ent, FP_FORWARD.. */
#include "ffn_mpdp_consumer.h"
#include "ffn_dpmem.h"          /* struct ffn_dpmem_hdr/bank + ffn_dpmem_* (DP-MP) */

/* flatcc generated headers (builder pulls in the reader). */
#include "ffn_mpdp_builder.h"
#include "ffn_mpdp_verifier.h"

/* Namespace shortener for the generated ffn.mpdp symbols. */
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(ffn_mpdp, x)

/* ======================================================================== */
/* MP -> DP : apply                                                          */
/* ======================================================================== */

/* Parse "a.b.c.d/pfx" (or "any" / "0.0.0.0/0" / bare "a.b.c.d") into a
 * host-order network address + mask.  Returns 0 on success, -1 on parse
 * error.  Host order matches the fast path's classify() which compares
 * against rte_be_to_cpu_32(ip->src_addr) (see ffn_fastpath_fwd.c). */
static int parse_cidr(const char *s, uint32_t *net_ho, uint32_t *mask_ho)
{
    if (!s || !*s || strcmp(s, "any") == 0) {
        *net_ho = 0; *mask_ho = 0;              /* match-any */
        return 0;
    }
    char tmp[64];
    size_t n = strlen(s);
    if (n >= sizeof tmp) return -1;
    memcpy(tmp, s, n + 1);

    int pfx = 32;
    char *slash = strchr(tmp, '/');
    if (slash) {
        *slash = '\0';
        pfx = atoi(slash + 1);
        if (pfx < 0 || pfx > 32) return -1;
    }
    struct in_addr a;
    if (inet_pton(AF_INET, tmp, &a) != 1) return -1;

    *net_ho  = ntohl(a.s_addr);
    *mask_ho = pfx ? (uint32_t)(0xFFFFFFFFu << (32 - pfx)) : 0u;
    *net_ho &= *mask_ho;                        /* normalise host bits off */
    return 0;
}

/* MlModelUpdate -> stage into the inactive bank + flip. */
static int apply_ml(struct ffn_dpmem_hdr *dp, ns(MlModelUpdate_table_t) m)
{
    unsigned inb = ffn_dpmem_inactive(dp);
    if (ffn_dpmem_clone_active(dp, inb) != 0)
        return FFN_MPDP_ENOMEM;

    struct ffn_dpmem_bank *b = ffn_dpmem_bank(dp, inb);

    flatbuffers_uint8_vec_t tv = ns(MlModelUpdate_tree_blob(m));
    flatbuffers_uint8_vec_t nv = ns(MlModelUpdate_ngram_params(m));
    const uint8_t *tree  = tv ? (const uint8_t *)(tv) : NULL;
    uint32_t       tlen  = tv ? (uint32_t)flatbuffers_uint8_vec_len(tv) : 0;
    const uint8_t *ngram = nv ? (const uint8_t *)(nv) : NULL;
    uint32_t       nlen  = nv ? (uint32_t)flatbuffers_uint8_vec_len(nv) : 0;

    uint8_t *tcopy = tlen ? ffn_dpmem_arena_dup(b, tree, tlen)  : NULL;
    uint8_t *ncopy = nlen ? ffn_dpmem_arena_dup(b, ngram, nlen) : NULL;
    if ((tlen && !tcopy) || (nlen && !ncopy))
        return FFN_MPDP_ENOMEM;

    /* --- fields written into the inactive dpmem bank --- */
    b->ml_version          = ns(MlModelUpdate_version(m));
    b->ml_kind             = (uint8_t)ns(MlModelUpdate_kind(m));
    b->ml_features_version = ns(MlModelUpdate_features_version(m));
    b->ml_tree_blob        = tcopy;
    b->ml_tree_len         = tlen;
    b->ml_ngram_params     = ncopy;
    b->ml_ngram_len        = nlen;

    ffn_dpmem_publish(dp, inb);                 /* atomic active_bank flip */
    return FFN_MPDP_OK;
}

/* ThreatIntelUpdate -> rebuild SIG/AC/DFA + IOC tables in the inactive bank.
 * Decode the flatbuffer vectors into neutral rows (so ffn_dpmem.c need not
 * depend on flatcc) and hand them to the DP-MP table builder, which owns the
 * Aho-Corasick / DFA / avhash construction and the add/remove merge. */
static int apply_threatintel(struct ffn_dpmem_hdr *dp,
                             ns(ThreatIntelUpdate_table_t) ti)
{
    unsigned inb = ffn_dpmem_inactive(dp);
    if (ffn_dpmem_clone_active(dp, inb) != 0)
        return FFN_MPDP_ENOMEM;
    struct ffn_dpmem_bank *b = ffn_dpmem_bank(dp, inb);

    ns(Signature_vec_t)      av = ns(ThreatIntelUpdate_adds(ti));
    flatbuffers_uint32_vec_t rv = ns(ThreatIntelUpdate_removes(ti));
    ns(Ioc_vec_t)            iv = ns(ThreatIntelUpdate_iocs(ti));

    size_t n_adds    = av ? ns(Signature_vec_len(av)) : 0;
    size_t n_removes = rv ? flatbuffers_uint32_vec_len(rv) : 0;
    size_t n_iocs    = iv ? ns(Ioc_vec_len(iv)) : 0;

    /* Decode adds into arena-backed rows (freed implicitly with the bank on
     * the next rebuild; scratch use only during this call). */
    struct ffn_mpdp_sig *adds = NULL;
    struct ffn_mpdp_ioc *iocs = NULL;
    if (n_adds) {
        adds = ffn_dpmem_arena_alloc(b, n_adds * sizeof *adds);
        if (!adds) return FFN_MPDP_ENOMEM;
        for (size_t i = 0; i < n_adds; i++) {
            ns(Signature_table_t) s = ns(Signature_vec_at(av, i));
            flatbuffers_uint8_vec_t dg = ns(Signature_digest(s));
            adds[i].sid         = ns(Signature_sid(s));
            adds[i].name        = ns(Signature_name(s));
            adds[i].sig_type    = ns(Signature_sig_type(s));
            adds[i].hash_type   = ns(Signature_hash_type(s));
            adds[i].digest      = dg ? (const uint8_t *)(dg) : NULL;
            adds[i].digest_len  = dg ? (uint32_t)flatbuffers_uint8_vec_len(dg) : 0;
            adds[i].hex_pattern = ns(Signature_hex_pattern(s));
            adds[i].severity    = ns(Signature_severity(s));
            adds[i].verdict     = (uint8_t)ns(Signature_verdict(s));
            adds[i].family      = ns(Signature_family(s));
        }
    }
    if (n_iocs) {
        iocs = ffn_dpmem_arena_alloc(b, n_iocs * sizeof *iocs);
        if (!iocs) return FFN_MPDP_ENOMEM;
        for (size_t i = 0; i < n_iocs; i++) {
            ns(Ioc_table_t) o = ns(Ioc_vec_at(iv, i));
            iocs[i].kind    = ns(Ioc_kind(o));
            iocs[i].value   = ns(Ioc_value(o));
            iocs[i].verdict = (uint8_t)ns(Ioc_verdict(o));
        }
    }

    /* Copy removes via _vec_at (endian-safe) into an arena array. */
    uint32_t *removes = NULL;
    if (n_removes) {
        removes = ffn_dpmem_arena_alloc(b, n_removes * sizeof *removes);
        if (!removes) return FFN_MPDP_ENOMEM;
        for (size_t i = 0; i < n_removes; i++)
            removes[i] = flatbuffers_uint32_vec_at(rv, i);
    }

    if (ffn_dpmem_threatintel_load(dp, inb, ns(ThreatIntelUpdate_seq(ti)),
                                   adds, (uint32_t)n_adds,
                                   removes, (uint32_t)n_removes,
                                   iocs, (uint32_t)n_iocs) != 0)
        return FFN_MPDP_EDPMEM;

    ffn_dpmem_publish(dp, inb);
    return FFN_MPDP_OK;
}

/* PolicyUpdate -> compile rows into fp_policy_ent[] in the inactive bank. */
static int apply_policy(struct ffn_dpmem_hdr *dp, ns(PolicyUpdate_table_t) pu)
{
    unsigned inb = ffn_dpmem_inactive(dp);
    if (ffn_dpmem_clone_active(dp, inb) != 0)
        return FFN_MPDP_ENOMEM;
    struct ffn_dpmem_bank *b = ffn_dpmem_bank(dp, inb);

    ns(PolicyRow_vec_t) rows = ns(PolicyUpdate_rows(pu));
    size_t nrows = rows ? ns(PolicyRow_vec_len(rows)) : 0;
    uint8_t base_vsys = (uint8_t)ns(PolicyUpdate_vsys(pu));

    struct fp_policy_ent *ent = NULL;
    if (nrows) {
        ent = ffn_dpmem_arena_alloc(b, nrows * sizeof *ent);
        if (!ent) return FFN_MPDP_ENOMEM;
        memset(ent, 0, nrows * sizeof *ent);

        for (size_t i = 0; i < nrows; i++) {
            ns(PolicyRow_table_t) r = ns(PolicyRow_vec_at(rows, i));
            struct fp_policy_ent *e = &ent[i];

            uint32_t sip = 0, smask = 0, dip = 0, dmask = 0;
            if (parse_cidr(ns(PolicyRow_src_ip(r)), &sip, &smask) != 0 ||
                parse_cidr(ns(PolicyRow_dst_ip(r)), &dip, &dmask) != 0)
                return FFN_MPDP_EDPMEM;         /* malformed CIDR on the wire */

            e->src_ip = sip; e->src_mask = smask;
            e->dst_ip = dip; e->dst_mask = dmask;

            uint16_t sp = ns(PolicyRow_src_port(r));
            uint16_t dp_ = ns(PolicyRow_dst_port(r));
            /* wire carries a single port; 0 == any -> full range. */
            e->sport_lo = sp ? sp : 0;   e->sport_hi = sp ? sp : 0xFFFF;
            e->dport_lo = dp_ ? dp_ : 0;  e->dport_hi = dp_ ? dp_ : 0xFFFF;

            e->proto  = (uint8_t)ns(PolicyRow_proto(r));      /* 0 == any */
            uint8_t rv = (uint8_t)ns(PolicyRow_vsys(r));      /* per-row override */
            e->vsys   = rv ? rv : base_vsys;
            e->action = (uint8_t)ns(PolicyRow_action(r));     /* FP_FORWARD.. */
            e->flags  = 0;
            e->egress_port = 0xFFFF;
            e->rule_id = (uint16_t)(i + 1);
        }
    }

    /* --- fields written into the inactive dpmem bank --- */
    b->policy   = ent;
    b->policy_n = (uint32_t)nrows;

    ffn_dpmem_publish(dp, inb);
    return FFN_MPDP_OK;
}

/* SignatureVerdict -> hot realtime verdict injected into the ACTIVE bank.
 * No bank flip: this is a single-slot update the fast path reads immediately. */
static int apply_sig_verdict(struct ffn_dpmem_hdr *dp,
                             ns(SignatureVerdict_table_t) sv)
{
    flatbuffers_uint8_vec_t hv = ns(SignatureVerdict_sha256(sv));
    const uint8_t *sha = hv ? (const uint8_t *)(hv) : NULL;
    uint32_t       slen = hv ? (uint32_t)flatbuffers_uint8_vec_len(hv) : 0;

    if (ffn_dpmem_sigverdict_apply(dp, ns(SignatureVerdict_sid(sv)),
                                   sha, slen,
                                   (uint8_t)ns(SignatureVerdict_verdict(sv)),
                                   ns(SignatureVerdict_ts(sv))) != 0)
        return FFN_MPDP_EDPMEM;
    return FFN_MPDP_OK;
}

int ffn_mpdp_apply(const uint8_t *buf, size_t len, struct ffn_dpmem_hdr *dp)
{
    if (!buf || !dp)
        return FFN_MPDP_EINVAL;

    /* Reject anything that is not a well-formed FlatBuffers root -- the buffer
     * arrives cross-process via the dpmem rte_ring, so verify before reading. */
    if (ns(MpDpMessage_verify_as_root(buf, len)) != flatcc_verify_ok)
        return FFN_MPDP_EBADMSG;

    ns(MpDpMessage_table_t) msg = ns(MpDpMessage_as_root(buf));
    if (!msg)
        return FFN_MPDP_EBADMSG;

    /* Only management -> data-plane frames are applied here. */
    if (ns(MpDpMessage_dir(msg)) != ns(Dir_MP2DP))
        return FFN_MPDP_EDIR;

    /* ver > FFN_MPDP_WIRE_VERSION is accepted (FlatBuffers forward-compat:
     * unknown appended fields are simply ignored by the generated reader). */

    ns(MpDpBody_union_type_t) bt = ns(MpDpMessage_body_type(msg));
    flatbuffers_generic_t     bp = ns(MpDpMessage_body(msg));
    if (!bp)
        return FFN_MPDP_EUNSUPP;

    switch (bt) {
    case ns(MpDpBody_MlModelUpdate):
        return apply_ml(dp, (ns(MlModelUpdate_table_t))bp);
    case ns(MpDpBody_ThreatIntelUpdate):
        return apply_threatintel(dp, (ns(ThreatIntelUpdate_table_t))bp);
    case ns(MpDpBody_PolicyUpdate):
        return apply_policy(dp, (ns(PolicyUpdate_table_t))bp);
    case ns(MpDpBody_SignatureVerdict):
        return apply_sig_verdict(dp, (ns(SignatureVerdict_table_t))bp);
    default:
        /* EngineTelemetry / FlowEvent are DP->MP only; NONE == empty body. */
        return FFN_MPDP_EUNSUPP;
    }
}

/* Strong ffn_flatcc_apply(): the ffn_dpdk_mp.c control-thread entry point
 * (declared in ffn_dpmem.h). Adapts ffn_mpdp_apply() to that contract and
 * OVERRIDES the weak no-op fallback, wiring the real consumer into the zygote.
 *
 * ffn_mpdp_apply() stages into the inactive bank and PUBLISHES (flips) itself on
 * success, so this returns 0 ("nothing more for the caller to do") rather than
 * >0 -- ffn_dpdk_mp.c's ctrl thread must NOT flip again. `inactive_bank` is
 * recomputed inside ffn_mpdp_apply() (single-writer control thread), so it is
 * accepted but unused. Returns 0 on success/no-op, <0 on decode/apply error. */
int ffn_flatcc_apply(struct ffn_dpmem_hdr *dpmem, uint32_t inactive_bank,
                     const void *frame, size_t frame_len)
{
    int rc;
    (void)inactive_bank;
    rc = ffn_mpdp_apply((const uint8_t *)frame, frame_len, dpmem);
    return (rc == FFN_MPDP_OK) ? 0 : -1;
}

/* ======================================================================== */
/* DP -> MP : build                                                          */
/* ======================================================================== */

uint8_t *ffn_mpdp_build_engine_telemetry(const char *engine,
                                         uint64_t packets, uint64_t matches,
                                         uint64_t drops, const char *mode,
                                         size_t *out_len)
{
    flatcc_builder_t builder, *B = &builder;
    if (out_len) *out_len = 0;
    flatcc_builder_init(B);

    /* Leaf strings must be created before the enclosing table. */
    flatbuffers_string_ref_t engine_ref =
        flatbuffers_string_create_str(B, engine ? engine : "");
    flatbuffers_string_ref_t mode_ref =
        flatbuffers_string_create_str(B, mode ? mode : "");

    ns(EngineTelemetry_ref_t) et =
        ns(EngineTelemetry_create(B, engine_ref, packets, matches, drops, mode_ref));

    ns(MpDpMessage_create_as_root(B, FFN_MPDP_WIRE_VERSION, ns(Dir_DP2MP),
                                  ns(MpDpBody_as_EngineTelemetry(et))));

    size_t sz = 0;
    uint8_t *buf = flatcc_builder_finalize_aligned_buffer(B, &sz);
    flatcc_builder_clear(B);
    if (buf && out_len) *out_len = sz;
    return buf;
}

uint8_t *ffn_mpdp_build_flow_event(uint32_t vsys,
                                   const struct ffn_mpdp_flowkey *key,
                                   uint8_t verdict, uint64_t byte_count,
                                   size_t *out_len)
{
    flatcc_builder_t builder, *B = &builder;
    if (out_len) *out_len = 0;
    flatcc_builder_init(B);

    struct ffn_mpdp_flowkey z = {0};
    const struct ffn_mpdp_flowkey *k = key ? key : &z;

    ns(FlowKey_ref_t) fk =
        ns(FlowKey_create(B, k->vsys, k->proto, k->src_ip, k->src_port,
                          k->dst_ip, k->dst_port));

    ns(FlowEvent_ref_t) fe =
        ns(FlowEvent_create(B, vsys, fk, (ns(Verdict_enum_t))verdict, byte_count));

    ns(MpDpMessage_create_as_root(B, FFN_MPDP_WIRE_VERSION, ns(Dir_DP2MP),
                                  ns(MpDpBody_as_FlowEvent(fe))));

    size_t sz = 0;
    uint8_t *buf = flatcc_builder_finalize_aligned_buffer(B, &sz);
    flatcc_builder_clear(B);
    if (buf && out_len) *out_len = sz;
    return buf;
}

void ffn_mpdp_free(uint8_t *buf)
{
    if (buf)
        flatcc_builder_aligned_free(buf);
}
