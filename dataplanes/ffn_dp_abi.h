/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_abi.h -- FFN management-plane <-> dataplane shared-region ABI.
 *
 * SINGLE SOURCE OF TRUTH for both sides:
 *   host side  (x86-64 LE) : ffn_oct.py / ffn-controld map this over a PCIe BAR
 *   DP side    (MIPS64 BE) : ffn_dp_oct.c maps it in Octeon DRAM
 *
 * ENDIANNESS POLICY
 * -----------------
 * The x86 host and an OCTEON-II dataplane have OPPOSITE byte order, so every
 * multi-byte field in this region -- and in the fastpath tables carried inside
 * it -- is defined as **little-endian on the wire**, accessed through the
 * ld_leNN / st_leNN helpers below. Consequences:
 *   * one policy.bin serves BOTH dataplanes (x86 DPDK and Octeon); the existing
 *     ffn_fastpath_compile.py output is used unchanged, no --arch variant;
 *   * the DP converts table rows to native structs ONCE at load time, so the
 *     per-packet hot path never byte-swaps.
 * Never dereference a struct field in this region directly -- always go through
 * the accessors, or the code silently breaks on the big-endian target.
 */
#ifndef FFN_DP_ABI_H
#define FFN_DP_ABI_H

#include <stdint.h>
#include <string.h>

#define FFN_DP_MAGIC      "FFNDP"
#define FFN_DP_ABI_VER    1u

/* ---- little-endian accessors (endian-agnostic, alignment-safe) ---- */
static inline uint16_t ld_le16(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}
static inline uint32_t ld_le32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static inline uint64_t ld_le64(const void *p)
{
    return (uint64_t)ld_le32(p) | ((uint64_t)ld_le32((const uint8_t *)p + 4) << 32);
}
/* Big-endian (network order) reader. IPv4 addresses inside the fastpath tables
 * are stored as NETWORK-ORDER BYTES, so they are read with this -- never with
 * ld_le32() + a host ntohl(), which byte-swaps on little-endian hosts only and
 * silently returns swapped addresses on a big-endian target like OCTEON-II. */
static inline uint32_t ld_be32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}
static inline void st_be32(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);  b[3] = (uint8_t)v;
}
static inline void st_le16(void *p, uint16_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8);
}
static inline void st_le32(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)v;         b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}
static inline void st_le64(void *p, uint64_t v)
{
    st_le32(p, (uint32_t)v);
    st_le32((uint8_t *)p + 4, (uint32_t)(v >> 32));
}

/* ---- region layout (byte offsets from the base of the shared window) ---- */
#define FFN_DP_OFF_HDR        0x0000u
#define FFN_DP_OFF_CMD_RING   0x0040u          /* MP -> DP */
#define FFN_DP_OFF_EVT_RING   0x1040u          /* DP -> MP */
#define FFN_DP_OFF_STATS      0x2040u
#define FFN_DP_OFF_BANK0      0x4000u
#define FFN_DP_BANK_SIZE      0x400000u        /* 4 MiB per policy bank */
#define FFN_DP_OFF_BANK1      (FFN_DP_OFF_BANK0 + FFN_DP_BANK_SIZE)
#define FFN_DP_REGION_SIZE    (FFN_DP_OFF_BANK1 + FFN_DP_BANK_SIZE)

/* ---- DP / host lifecycle states ---- */
enum {
    DP_STATE_RESET = 0,
    DP_STATE_BOOT,          /* DP image running, region not yet validated */
    DP_STATE_HANDSHAKE,     /* magic+version agreed, awaiting tables      */
    DP_STATE_READY,         /* tables loaded, forwarding                  */
    DP_STATE_ERROR,
};

/* ---- command opcodes (MP -> DP) ---- */
enum {
    DP_CMD_NOP = 0,
    DP_CMD_PING,
    DP_CMD_SET_BANK,        /* arg0 = bank index to activate            */
    DP_CMD_GET_STATS,
    DP_CMD_SET_DEFAULT,     /* arg0 = default decision (FP_*)           */
    DP_CMD_FLUSH_FLOWS,
    DP_CMD_SHUTDOWN,
};

/* ---- event opcodes (DP -> MP) ---- */
enum {
    DP_EVT_NONE = 0,
    DP_EVT_PONG,
    DP_EVT_READY,
    DP_EVT_STATS,
    DP_EVT_ERROR,
    DP_EVT_FLOW_DROP,
};

/* Region header. 64 bytes. All multi-byte fields little-endian. */
#define FFN_DP_HDR_SIZE 64
struct ffn_dp_hdr_raw {
    uint8_t magic[6];        /* "FFNDP\0"                     */
    uint8_t abi_version[2];  /* le16                          */
    uint8_t dp_state[4];     /* le32, DP_STATE_*              */
    uint8_t host_state[4];   /* le32                          */
    uint8_t dp_heartbeat[8]; /* le64, DP increments           */
    uint8_t host_heartbeat[8];
    uint8_t active_bank[4];  /* le32, 0 or 1                  */
    uint8_t default_dec[4];  /* le32, FP_* when no rule hits  */
    uint8_t dp_caps[4];      /* le32 bitmap                   */
    uint8_t dp_error[4];     /* le32                          */
    uint8_t reserved[16];
};

/* Ring: fixed 32-byte descriptors, single-producer/single-consumer.
 * head = producer index, tail = consumer index, both monotonic le32. */
#define FFN_DP_RING_DESCS   64u
#define FFN_DP_DESC_SIZE    32u
#define FFN_DP_RING_HDR_SZ  16u
struct ffn_dp_desc_raw {
    uint8_t opcode[2];       /* le16 */
    uint8_t flags[2];        /* le16 */
    uint8_t seq[4];          /* le32 */
    uint8_t arg0[8];         /* le64 */
    uint8_t arg1[8];         /* le64 */
    uint8_t arg2[8];         /* le64 */
};

/* ---- helpers over the raw header ---- */
static inline int ffn_dp_hdr_valid(const void *base)
{
    const struct ffn_dp_hdr_raw *h = (const struct ffn_dp_hdr_raw *)base;
    return memcmp(h->magic, FFN_DP_MAGIC, 5) == 0 &&
           ld_le16(h->abi_version) == FFN_DP_ABI_VER;
}
static inline void ffn_dp_hdr_init(void *base, uint32_t state)
{
    struct ffn_dp_hdr_raw *h = (struct ffn_dp_hdr_raw *)base;
    memset(h, 0, sizeof(*h));
    memcpy(h->magic, FFN_DP_MAGIC, 6);
    st_le16(h->abi_version, (uint16_t)FFN_DP_ABI_VER);
    st_le32(h->dp_state, state);
}

/* ring accessors: ring base -> [head le32][tail le32][pad 8][descs...] */
static inline uint32_t ffn_dp_ring_head(const void *ring) { return ld_le32(ring); }
static inline uint32_t ffn_dp_ring_tail(const void *ring)
{
    return ld_le32((const uint8_t *)ring + 4);
}
static inline void ffn_dp_ring_set_head(void *ring, uint32_t v) { st_le32(ring, v); }
static inline void ffn_dp_ring_set_tail(void *ring, uint32_t v)
{
    st_le32((uint8_t *)ring + 4, v);
}
static inline void *ffn_dp_ring_desc(void *ring, uint32_t idx)
{
    return (uint8_t *)ring + FFN_DP_RING_HDR_SZ +
           (size_t)(idx % FFN_DP_RING_DESCS) * FFN_DP_DESC_SIZE;
}

/* Push one descriptor. Returns 0 on success, -1 if the ring is full. */
static inline int ffn_dp_ring_push(void *ring, uint16_t opcode, uint64_t a0,
                                   uint64_t a1, uint64_t a2)
{
    uint32_t head = ffn_dp_ring_head(ring), tail = ffn_dp_ring_tail(ring);
    if (head - tail >= FFN_DP_RING_DESCS)
        return -1;
    struct ffn_dp_desc_raw *d =
        (struct ffn_dp_desc_raw *)ffn_dp_ring_desc(ring, head);
    st_le16(d->opcode, opcode);
    st_le16(d->flags, 0);
    st_le32(d->seq, head);
    st_le64(d->arg0, a0);
    st_le64(d->arg1, a1);
    st_le64(d->arg2, a2);
    ffn_dp_ring_set_head(ring, head + 1);
    return 0;
}

/* Pop one descriptor. Returns 1 if one was dequeued, 0 if empty. */
static inline int ffn_dp_ring_pop(void *ring, uint16_t *opcode, uint64_t *a0,
                                  uint64_t *a1, uint64_t *a2)
{
    uint32_t head = ffn_dp_ring_head(ring), tail = ffn_dp_ring_tail(ring);
    if (head == tail)
        return 0;
    const struct ffn_dp_desc_raw *d =
        (const struct ffn_dp_desc_raw *)ffn_dp_ring_desc(ring, tail);
    if (opcode) *opcode = ld_le16(d->opcode);
    if (a0) *a0 = ld_le64(d->arg0);
    if (a1) *a1 = ld_le64(d->arg1);
    if (a2) *a2 = ld_le64(d->arg2);
    ffn_dp_ring_set_tail(ring, tail + 1);
    return 1;
}

static inline void ffn_dp_ring_init(void *ring)
{
    memset(ring, 0, FFN_DP_RING_HDR_SZ +
           (size_t)FFN_DP_RING_DESCS * FFN_DP_DESC_SIZE);
}

#endif /* FFN_DP_ABI_H */
