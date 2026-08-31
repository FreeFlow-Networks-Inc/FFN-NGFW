/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_mpdp_consumer.h -- C consumer of the MP<->DP FlatBuffers wire (ABI = the
 * `ffn_mpdp.fbs` schema, REWORK_CONTRACT ADDENDUM Section 9).
 *
 * OWNER: FLATCC.  This is the DPDK data-plane (Pass 2) side of the channel that
 * `ffn_mpdp_wire.py` produces/consumes on the management plane.
 *
 *   MP -> DP  : ffn_mpdp_apply()   -- parse an MpDpMessage (via the flatcc
 *               generated reader) and stage the payload into the *inactive*
 *               bank of the shared dpmem double-buffer, then flip.
 *   DP -> MP  : ffn_mpdp_build_*() -- build EngineTelemetry / FlowEvent frames
 *               (via the flatcc generated builder) for the DP to report back.
 *
 * Dependency direction (no include cycle):
 *   ffn_mpdp_consumer.h   -- forward-declares `struct ffn_dpmem_hdr`, defines
 *                            the decoded-row structs below.  Does NOT include
 *                            ffn_dpmem.h.
 *   ffn_dpmem.h (DP-MP)   -- #includes THIS header (for the row structs), then
 *                            defines `struct ffn_dpmem_hdr` / `struct
 *                            ffn_dpmem_bank` and the ffn_dpmem_* helpers.
 *   ffn_mpdp_consumer.c   -- #includes both, plus the flatcc generated headers
 *                            and ffn_fastpath.h.
 *
 * The decoded-row structs carry pointers straight into the FlatBuffers buffer;
 * they are valid only for the duration of the ffn_mpdp_apply() call (dpmem
 * helpers must copy anything they retain).  Strings are NUL-terminated (flatcc
 * guarantees this) and may be NULL when the wire field was absent.
 */
#ifndef FFN_MPDP_CONSUMER_H
#define FFN_MPDP_CONSUMER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bumped in lock-step with ffn_mpdp_wire.WIRE_VERSION (currently 1). */
#define FFN_MPDP_WIRE_VERSION 1u

/* Owned by DP-MP (ffn_dpmem.h); referenced here only by pointer. */
struct ffn_dpmem_hdr;

/* Verdict scale -- mirrors enum Verdict in ffn_mpdp.fbs / ffn_mpdp_wire.py. */
enum ffn_mpdp_verdict {
    FFN_MPDP_V_BENIGN   = 0,
    FFN_MPDP_V_GRAYWARE = 1,
    FFN_MPDP_V_MALWARE  = 2,
};

/* MlKind -- mirrors enum MlKind in ffn_mpdp.fbs. */
enum ffn_mpdp_mlkind {
    FFN_MPDP_ML_XGBOOST = 0,
    FFN_MPDP_ML_NGRAM   = 1,
};

/* ffn_mpdp_apply() return codes (0 = OK, negative = error). */
enum {
    FFN_MPDP_OK        =  0,
    FFN_MPDP_EINVAL    = -1,   /* NULL args */
    FFN_MPDP_EBADMSG   = -2,   /* failed flatcc verification / not a root msg */
    FFN_MPDP_EDIR      = -3,   /* not an MP->DP frame */
    FFN_MPDP_EUNSUPP   = -4,   /* body type not applicable on the DP side */
    FFN_MPDP_ENOMEM    = -5,   /* dpmem arena/clone exhausted */
    FFN_MPDP_EDPMEM    = -6,   /* a dpmem helper rejected the payload */
};

/* ------------------------------------------------------------------ rows */
/* Decoded `table Signature` (ffn_mpdp.fbs). Pointers alias the flatbuffer. */
struct ffn_mpdp_sig {
    uint32_t       sid;
    const char    *name;         /* may be NULL */
    const char    *sig_type;     /* "hash" | "pattern" | "yara" */
    const char    *hash_type;    /* "md5" | "sha1" | "sha256" */
    const uint8_t *digest;       /* raw hash bytes, may be NULL */
    uint32_t       digest_len;
    const char    *hex_pattern;  /* offset-anchored body / compiled pcre */
    uint8_t        severity;     /* 0..5 */
    uint8_t        verdict;      /* enum ffn_mpdp_verdict */
    const char    *family;
};

/* Decoded `table Ioc` (ffn_mpdp.fbs). */
struct ffn_mpdp_ioc {
    const char *kind;            /* "domain" | "ip" | "url" | "sha256" | ... */
    const char *value;
    uint8_t     verdict;         /* enum ffn_mpdp_verdict */
};

/* Decoded `table FlowKey` (ffn_mpdp.fbs); IPs in host byte order. */
struct ffn_mpdp_flowkey {
    uint8_t  vsys;
    uint8_t  proto;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
};

/* ------------------------------------------------------------------ apply */
/*
 * Parse `buf`[0..len) as an MpDpMessage and apply it to the shared dpmem
 * double-buffer `dp`.  The buffer MUST be a real FlatBuffers message (as
 * emitted by flatcc / by the Python `flatbuffers` runtime on the MP side in
 * Pass 2) -- it is verified with the flatcc verifier before any field is read.
 *
 * Applied bodies (dir == MP2DP):
 *   MlModelUpdate     -> stage tree_blob / ngram_params + version into the
 *                        inactive bank, then flip active_bank.
 *   ThreatIntelUpdate -> rebuild the SIG/AC/DFA + IOC tables in the inactive
 *                        bank (adds/removes/iocs), then flip.
 *   PolicyUpdate      -> compile rows -> fp_policy_ent[] in the inactive bank,
 *                        then flip.
 *   SignatureVerdict  -> hot realtime verdict injected into the ACTIVE bank
 *                        (no bank flip).
 *
 * Returns FFN_MPDP_OK on success, or a negative FFN_MPDP_E* code.
 */
int ffn_mpdp_apply(const uint8_t *buf, size_t len, struct ffn_dpmem_hdr *dp);

/* ------------------------------------------------------------------ build */
/*
 * DP -> MP builder helpers.  Each returns a freshly allocated, 8-byte-aligned
 * FlatBuffers buffer (dir == DP2MP, ver == FFN_MPDP_WIRE_VERSION) and writes
 * its length to *out_len.  Free the result with ffn_mpdp_free().  Returns NULL
 * on allocation failure (*out_len set to 0).
 *
 * The frames round-trip through ffn_mpdp_wire.parse() to the same field/union
 * shape (see the note in ffn_mpdp_consumer.c about the offline fallback codec).
 */
uint8_t *ffn_mpdp_build_engine_telemetry(const char *engine,
                                         uint64_t packets, uint64_t matches,
                                         uint64_t drops, const char *mode,
                                         size_t *out_len);

uint8_t *ffn_mpdp_build_flow_event(uint32_t vsys,
                                   const struct ffn_mpdp_flowkey *key,
                                   uint8_t verdict, uint64_t byte_count,
                                   size_t *out_len);

/* Free a buffer returned by ffn_mpdp_build_*(). */
void ffn_mpdp_free(uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* FFN_MPDP_CONSUMER_H */
