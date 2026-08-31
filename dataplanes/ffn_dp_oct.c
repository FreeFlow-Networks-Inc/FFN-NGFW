/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_oct.c -- FFN dataplane forwarder for OCTEON-II (PA-5220 "Gryphon").
 *
 * Consumes the SAME fastpath tables ffn_fastpath_compile.py already produces for
 * the x86 DPDK fastpath (policy.bin, type 0x40 "FPPO", 32-byte rows) -- one
 * policy compiler, two dataplanes. Table rows are little-endian on the wire and
 * are converted to native structs ONCE at load time, so the per-packet path
 * never byte-swaps even though OCTEON-II is big-endian.
 *
 * Deliberately free of chip-specific includes: packet I/O sits behind
 * struct dp_io_ops, so the same object builds
 *   * natively (x86-64) against the "sim" backend for the test harness, and
 *   * for mips64-linux (OCTEON-II) against a PKI/PKO or AF_PACKET backend.
 * That keeps the forwarding logic testable without the hardware present.
 *
 * Pipeline (mirrors ffn_fastpath_fwd.c):
 *   rx -> parse L2/L3/L4 -> normalized flow key (+vsys)
 *      -> flow-cache lookup   hit : apply cached verdict
 *                            miss : classify() vs policy rows, cache result
 *      -> FP_FORWARD  : tx
 *         FP_INSPECT  : tx + mark for inspection (payload scan is a later stage)
 *         FP_DROP     : drop (+RST for FP_V_RESET)
 *         FP_PUNT_FPGA: hand to the FE100/FPGA path (backend-specific)
 *         FP_LOCAL    : hand to the local stack
 */
#include "ffn_dp_abi.h"
#include "ffn_dp_oct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- on-wire fastpath table layout (from ffn_fastpath.h / the compiler) ---- */
#define FP_HDR_SIZE_W     36u
#define FP_POLICY_SIZE_W  32u
#define FP_T_POLICY_W     0x40u
#define FP_MAGIC_POLICY_W "FPPO"

/* ------------------------------------------------------------------ */
/* table loading: little-endian wire rows -> native rows              */
/* ------------------------------------------------------------------ */
int dp_tables_load(struct dp_tables *t, const void *blob, size_t len)
{
    memset(t, 0, sizeof(*t));
    if (!blob || len < FP_HDR_SIZE_W)
        return DP_ERR_SHORT;

    const uint8_t *p = (const uint8_t *)blob;
    if (memcmp(p, FP_MAGIC_POLICY_W, 4) != 0)
        return DP_ERR_MAGIC;

    uint16_t ver   = ld_le16(p + 4);
    uint16_t type  = ld_le16(p + 6);
    uint32_t count = ld_le32(p + 8);
    uint32_t recsz = ld_le32(p + 24);

    if (type != FP_T_POLICY_W)
        return DP_ERR_TYPE;
    if (recsz != FP_POLICY_SIZE_W)
        return DP_ERR_RECSZ;
    if ((size_t)count * FP_POLICY_SIZE_W + FP_HDR_SIZE_W > len)
        return DP_ERR_SHORT;
    if (count > DP_MAX_POLICY)
        return DP_ERR_TOOMANY;

    t->version = ver;
    t->policy_n = count;
    const uint8_t *row = p + FP_HDR_SIZE_W;
    for (uint32_t i = 0; i < count; i++, row += FP_POLICY_SIZE_W) {
        struct dp_policy_row *r = &t->policy[i];
        /* IPv4 fields are stored as NETWORK-ORDER BYTES -> read big-endian to
         * get the host value. (Using ld_le32 + a host ntohl here works on x86
         * but returns byte-swapped addresses on big-endian OCTEON-II; the
         * cross-endian test catches exactly that.) */
        r->src_ip   = ld_be32(row + 0);
        r->src_mask = ld_be32(row + 4);
        r->dst_ip   = ld_be32(row + 8);
        r->dst_mask = ld_be32(row + 12);
        r->sport_lo = ld_le16(row + 16);
        r->sport_hi = ld_le16(row + 18);
        r->dport_lo = ld_le16(row + 20);
        r->dport_hi = ld_le16(row + 22);
        r->proto    = row[24];
        r->vsys     = row[25];
        r->action   = row[26];
        r->flags    = row[27];
        r->egress   = ld_le16(row + 28);
        r->rule_id  = ld_le16(row + 30);
    }
    return DP_OK;
}

/* ------------------------------------------------------------------ */
/* classify: first matching row wins (mirrors the x86 fastpath)        */
/* ------------------------------------------------------------------ */
int dp_classify(const struct dp_tables *t, const struct dp_tuple *k,
                uint16_t *rule_id, uint16_t *egress)
{
    for (uint32_t i = 0; i < t->policy_n; i++) {
        const struct dp_policy_row *r = &t->policy[i];

        if (r->vsys && r->vsys != k->vsys)          /* 0 = any vsys      */
            continue;
        if (r->proto && r->proto != k->proto)       /* 0 = any proto     */
            continue;
        if (r->src_mask && ((k->src_ip & r->src_mask) != (r->src_ip & r->src_mask)))
            continue;
        if (r->dst_mask && ((k->dst_ip & r->dst_mask) != (r->dst_ip & r->dst_mask)))
            continue;
        /* port ranges only apply to port-bearing protocols */
        if (k->proto == DP_IPPROTO_TCP || k->proto == DP_IPPROTO_UDP) {
            if (k->sport < r->sport_lo || k->sport > r->sport_hi)
                continue;
            if (k->dport < r->dport_lo || k->dport > r->dport_hi)
                continue;
        }
        if (rule_id) *rule_id = r->rule_id;
        if (egress)  *egress  = r->egress;
        return r->action;
    }
    if (rule_id) *rule_id = 0;
    if (egress)  *egress  = DP_EGRESS_NONE;
    return DP_DECISION_NOMATCH;                     /* caller applies default */
}

/* ------------------------------------------------------------------ */
/* flow cache: open-addressed, power-of-two, linear probe             */
/* ------------------------------------------------------------------ */
static uint32_t dp_flow_hash(const struct dp_flow_key *k)
{
    /* FNV-1a over the key bytes: stable across architectures because we feed
     * it native fields in a fixed order rather than raw struct memory. */
    uint32_t h = 2166136261u;
    const uint8_t bytes[18] = {
        (uint8_t)(k->ip_a), (uint8_t)(k->ip_a >> 8),
        (uint8_t)(k->ip_a >> 16), (uint8_t)(k->ip_a >> 24),
        (uint8_t)(k->ip_b), (uint8_t)(k->ip_b >> 8),
        (uint8_t)(k->ip_b >> 16), (uint8_t)(k->ip_b >> 24),
        (uint8_t)(k->port_a), (uint8_t)(k->port_a >> 8),
        (uint8_t)(k->port_b), (uint8_t)(k->port_b >> 8),
        k->proto, k->vsys, 0, 0, 0, 0
    };
    for (int i = 0; i < 14; i++) { h ^= bytes[i]; h *= 16777619u; }
    return h;
}

static int dp_key_eq(const struct dp_flow_key *a, const struct dp_flow_key *b)
{
    return a->ip_a == b->ip_a && a->ip_b == b->ip_b &&
           a->port_a == b->port_a && a->port_b == b->port_b &&
           a->proto == b->proto && a->vsys == b->vsys;
}

/* Normalize so both directions of a conversation share one entry. */
void dp_flow_key_from_tuple(struct dp_flow_key *k, const struct dp_tuple *t)
{
    memset(k, 0, sizeof(*k));
    int a_first = (t->src_ip < t->dst_ip) ||
                  (t->src_ip == t->dst_ip && t->sport <= t->dport);
    if (a_first) {
        k->ip_a = t->src_ip; k->port_a = t->sport;
        k->ip_b = t->dst_ip; k->port_b = t->dport;
    } else {
        k->ip_a = t->dst_ip; k->port_a = t->dport;
        k->ip_b = t->src_ip; k->port_b = t->sport;
    }
    k->proto = t->proto;
    k->vsys  = t->vsys;
}

int dp_flow_init(struct dp_flow_table *ft, uint32_t slots)
{
    uint32_t p = 1;
    while (p < slots) p <<= 1;
    ft->slots = p;
    ft->mask = p - 1;
    ft->count = 0;
    ft->ent = (struct dp_flow_ent *)calloc(p, sizeof(struct dp_flow_ent));
    return ft->ent ? DP_OK : DP_ERR_NOMEM;
}

void dp_flow_fini(struct dp_flow_table *ft)
{
    free(ft->ent);
    ft->ent = NULL;
    ft->slots = ft->mask = ft->count = 0;
}

void dp_flow_flush(struct dp_flow_table *ft)
{
    if (ft->ent)
        memset(ft->ent, 0, (size_t)ft->slots * sizeof(struct dp_flow_ent));
    ft->count = 0;
}

struct dp_flow_ent *dp_flow_lookup(struct dp_flow_table *ft,
                                   const struct dp_flow_key *k)
{
    uint32_t i = dp_flow_hash(k) & ft->mask;
    for (uint32_t probe = 0; probe <= ft->mask; probe++) {
        struct dp_flow_ent *e = &ft->ent[(i + probe) & ft->mask];
        if (!e->used)
            return NULL;
        if (dp_key_eq(&e->key, k))
            return e;
    }
    return NULL;
}

struct dp_flow_ent *dp_flow_insert(struct dp_flow_table *ft,
                                   const struct dp_flow_key *k)
{
    uint32_t i = dp_flow_hash(k) & ft->mask;
    for (uint32_t probe = 0; probe <= ft->mask; probe++) {
        struct dp_flow_ent *e = &ft->ent[(i + probe) & ft->mask];
        if (!e->used) {
            memset(e, 0, sizeof(*e));
            e->key = *k;
            e->used = 1;
            ft->count++;
            return e;
        }
        if (dp_key_eq(&e->key, k))
            return e;
    }
    return NULL;                                    /* table full */
}

/* ------------------------------------------------------------------ */
/* packet parse                                                       */
/* ------------------------------------------------------------------ */
int dp_parse(const uint8_t *pkt, uint32_t len, uint8_t vsys, struct dp_tuple *t)
{
    if (len < DP_ETH_HLEN + DP_IP4_MIN_HLEN)
        return DP_ERR_SHORT;

    uint16_t ethertype = (uint16_t)((pkt[12] << 8) | pkt[13]);
    uint32_t off = DP_ETH_HLEN;
    if (ethertype == DP_ETHERTYPE_VLAN) {           /* single 802.1Q tag */
        if (len < DP_ETH_HLEN + 4 + DP_IP4_MIN_HLEN)
            return DP_ERR_SHORT;
        ethertype = (uint16_t)((pkt[16] << 8) | pkt[17]);
        off += 4;
    }
    if (ethertype != DP_ETHERTYPE_IPV4)
        return DP_ERR_NOTIP;

    const uint8_t *ip = pkt + off;
    uint8_t ihl = (uint8_t)((ip[0] & 0x0f) * 4);
    if (ihl < DP_IP4_MIN_HLEN || off + ihl > len)
        return DP_ERR_SHORT;

    memset(t, 0, sizeof(*t));
    t->proto  = ip[9];
    /* IPv4 header is network byte order: build host value explicitly */
    t->src_ip = ((uint32_t)ip[12] << 24) | ((uint32_t)ip[13] << 16) |
                ((uint32_t)ip[14] << 8)  | (uint32_t)ip[15];
    t->dst_ip = ((uint32_t)ip[16] << 24) | ((uint32_t)ip[17] << 16) |
                ((uint32_t)ip[18] << 8)  | (uint32_t)ip[19];
    t->vsys = vsys;

    if (t->proto == DP_IPPROTO_TCP || t->proto == DP_IPPROTO_UDP) {
        const uint8_t *l4 = ip + ihl;
        if (off + ihl + 4 > len)
            return DP_ERR_SHORT;
        t->sport = (uint16_t)((l4[0] << 8) | l4[1]);
        t->dport = (uint16_t)((l4[2] << 8) | l4[3]);
        if (t->proto == DP_IPPROTO_TCP && off + ihl + 14 <= len)
            t->tcp_flags = l4[13];
    }
    return DP_OK;
}

/* ------------------------------------------------------------------ */
/* per-packet processing                                              */
/* ------------------------------------------------------------------ */
int dp_process(struct dp_ctx *c, const uint8_t *pkt, uint32_t len,
               uint8_t vsys, struct dp_result *out)
{
    struct dp_tuple t;
    memset(out, 0, sizeof(*out));
    out->decision = c->default_decision;

    int rc = dp_parse(pkt, len, vsys, &t);
    if (rc != DP_OK) {
        /* Non-IPv4 / malformed: fail closed for malformed, pass ARP-like L2
         * to the local stack so neighbour discovery still works. */
        c->stat_parse_err++;
        out->decision = (rc == DP_ERR_NOTIP) ? FP_LOCAL_W : FP_DROP_W;
        return rc;
    }
    out->tuple = t;

    struct dp_flow_key key;
    dp_flow_key_from_tuple(&key, &t);

    struct dp_flow_ent *fe = dp_flow_lookup(&c->flows, &key);
    if (fe && fe->verdict != FP_V_UNSET_W) {
        out->from_cache = 1;
        out->rule_id = fe->rule_id;
        out->decision = (fe->verdict == FP_V_ALLOW_W)
                        ? (fe->flags & DP_FF_INSPECT ? FP_INSPECT_W : FP_FORWARD_W)
                        : FP_DROP_W;
        out->reset = (fe->verdict == FP_V_RESET_W);
        out->egress = fe->egress;
        fe->pkts++;
        fe->bytes += len;
        c->stat_cache_hit++;
        /* Count the disposition on the cache path too: a firewall must report
         * every forwarded/dropped packet, not only the ones that reached
         * classify(), or the counters undercount steady-state traffic badly. */
        switch (out->decision) {
        case FP_FORWARD_W: c->stat_forward++; break;
        case FP_INSPECT_W: c->stat_inspect++; break;
        case FP_DROP_W:    c->stat_drop++;    break;
        default: break;
        }
        return DP_OK;
    }

    uint16_t rule_id = 0, egress = DP_EGRESS_NONE;
    int dec = dp_classify(&c->tables, &t, &rule_id, &egress);
    c->stat_classify++;
    if (dec == DP_DECISION_NOMATCH)
        dec = c->default_decision;

    out->decision = dec;
    out->rule_id = rule_id;
    out->egress = egress;

    if (!fe)
        fe = dp_flow_insert(&c->flows, &key);
    if (fe) {
        fe->rule_id = rule_id;
        fe->egress = egress;
        fe->pkts++;
        fe->bytes += len;
        switch (dec) {
        case FP_FORWARD_W: fe->verdict = FP_V_ALLOW_W; break;
        case FP_INSPECT_W: fe->verdict = FP_V_ALLOW_W;
                           fe->flags |= DP_FF_INSPECT; break;
        case FP_DROP_W:    fe->verdict = FP_V_DROP_W; break;
        default:           fe->verdict = FP_V_UNSET_W; break;  /* punt/local: re-evaluate */
        }
    } else {
        c->stat_flow_full++;
    }

    switch (dec) {
    case FP_FORWARD_W: c->stat_forward++; break;
    case FP_INSPECT_W: c->stat_inspect++; break;
    case FP_DROP_W:    c->stat_drop++;    break;
    case FP_PUNT_FPGA_W: c->stat_punt++;  break;
    case FP_LOCAL_W:   c->stat_local++;   break;
    default: break;
    }
    return DP_OK;
}

/* ------------------------------------------------------------------ */
/* shared-region control plane                                        */
/* ------------------------------------------------------------------ */
int dp_region_attach(struct dp_ctx *c, void *base, size_t size, int create)
{
    if (!base || size < FFN_DP_OFF_STATS)
        return DP_ERR_SHORT;
    c->region = base;
    c->region_size = size;
    if (create) {
        ffn_dp_hdr_init(base, DP_STATE_BOOT);
        ffn_dp_ring_init((uint8_t *)base + FFN_DP_OFF_CMD_RING);
        ffn_dp_ring_init((uint8_t *)base + FFN_DP_OFF_EVT_RING);
    }
    if (!ffn_dp_hdr_valid(base))
        return DP_ERR_HANDSHAKE;
    struct ffn_dp_hdr_raw *h = (struct ffn_dp_hdr_raw *)base;
    st_le32(h->dp_state, DP_STATE_HANDSHAKE);
    return DP_OK;
}

void dp_set_state(struct dp_ctx *c, uint32_t state)
{
    if (!c->region) return;
    struct ffn_dp_hdr_raw *h = (struct ffn_dp_hdr_raw *)c->region;
    st_le32(h->dp_state, state);
}

uint32_t dp_get_state(struct dp_ctx *c)
{
    if (!c->region) return DP_STATE_RESET;
    const struct ffn_dp_hdr_raw *h = (const struct ffn_dp_hdr_raw *)c->region;
    return ld_le32(h->dp_state);
}

void dp_heartbeat(struct dp_ctx *c)
{
    if (!c->region) return;
    struct ffn_dp_hdr_raw *h = (struct ffn_dp_hdr_raw *)c->region;
    st_le64(h->dp_heartbeat, ld_le64(h->dp_heartbeat) + 1);
}

/* Activate a policy bank: parse the tables sitting in it. */
int dp_activate_bank(struct dp_ctx *c, uint32_t bank)
{
    if (!c->region || bank > 1)
        return DP_ERR_BANK;
    size_t off = (bank == 0) ? FFN_DP_OFF_BANK0 : FFN_DP_OFF_BANK1;
    if (off + FP_HDR_SIZE_W > c->region_size)
        return DP_ERR_SHORT;
    size_t avail = c->region_size - off;
    if (avail > FFN_DP_BANK_SIZE)
        avail = FFN_DP_BANK_SIZE;
    int rc = dp_tables_load(&c->tables, (uint8_t *)c->region + off, avail);
    if (rc != DP_OK)
        return rc;
    c->active_bank = bank;
    struct ffn_dp_hdr_raw *h = (struct ffn_dp_hdr_raw *)c->region;
    st_le32(h->active_bank, bank);
    /* A policy change invalidates cached verdicts. */
    dp_flow_flush(&c->flows);
    return DP_OK;
}

/* Drain the MP->DP command ring. Returns commands handled. */
int dp_service_commands(struct dp_ctx *c)
{
    if (!c->region) return 0;
    void *cmd = (uint8_t *)c->region + FFN_DP_OFF_CMD_RING;
    void *evt = (uint8_t *)c->region + FFN_DP_OFF_EVT_RING;
    uint16_t op;
    uint64_t a0, a1, a2;
    int handled = 0;
    while (ffn_dp_ring_pop(cmd, &op, &a0, &a1, &a2)) {
        handled++;
        switch (op) {
        case DP_CMD_PING:
            ffn_dp_ring_push(evt, DP_EVT_PONG, a0, 0, 0);
            break;
        case DP_CMD_SET_BANK: {
            int rc = dp_activate_bank(c, (uint32_t)a0);
            if (rc == DP_OK) {
                dp_set_state(c, DP_STATE_READY);
                ffn_dp_ring_push(evt, DP_EVT_READY, a0, c->tables.policy_n, 0);
            } else {
                ffn_dp_ring_push(evt, DP_EVT_ERROR, (uint64_t)(-rc), a0, 0);
            }
            break;
        }
        case DP_CMD_SET_DEFAULT:
            c->default_decision = (int)a0;
            break;
        case DP_CMD_FLUSH_FLOWS:
            dp_flow_flush(&c->flows);
            break;
        case DP_CMD_GET_STATS:
            ffn_dp_ring_push(evt, DP_EVT_STATS, c->stat_forward, c->stat_drop,
                             c->stat_cache_hit);
            break;
        case DP_CMD_SHUTDOWN:
            c->stop = 1;
            break;
        default:
            break;
        }
    }
    return handled;
}

/* ------------------------------------------------------------------ */
/* main loop                                                          */
/* ------------------------------------------------------------------ */
int dp_init(struct dp_ctx *c, const struct dp_io_ops *io, void *io_arg,
            uint32_t flow_slots)
{
    memset(c, 0, sizeof(*c));
    c->io = io;
    c->io_arg = io_arg;
    c->default_decision = FP_DROP_W;         /* fail closed */
    int rc = dp_flow_init(&c->flows, flow_slots ? flow_slots : DP_DEFAULT_FLOWS);
    if (rc != DP_OK)
        return rc;
    if (io && io->init)
        return io->init(io_arg);
    return DP_OK;
}

void dp_fini(struct dp_ctx *c)
{
    if (c->io && c->io->fini)
        c->io->fini(c->io_arg);
    dp_flow_fini(&c->flows);
}

int dp_poll_once(struct dp_ctx *c)
{
    struct dp_pkt burst[DP_BURST];
    dp_service_commands(c);
    dp_heartbeat(c);

    if (!c->io || !c->io->rx)
        return 0;
    int n = c->io->rx(c->io_arg, burst, DP_BURST);
    for (int i = 0; i < n; i++) {
        struct dp_result res;
        c->stat_rx++;
        dp_process(c, burst[i].data, burst[i].len, burst[i].vsys, &res);
        burst[i].decision = res.decision;
        burst[i].egress = res.egress;
        if (res.decision == FP_FORWARD_W || res.decision == FP_INSPECT_W) {
            if (c->io->tx && c->io->tx(c->io_arg, &burst[i], 1) == 1)
                c->stat_tx++;
            else
                c->stat_tx_fail++;
        } else if (res.decision == FP_LOCAL_W) {
            if (c->io->to_local) c->io->to_local(c->io_arg, &burst[i]);
        } else if (res.decision == FP_PUNT_FPGA_W) {
            if (c->io->to_offload) c->io->to_offload(c->io_arg, &burst[i]);
        }
        if (c->io->free_pkt)
            c->io->free_pkt(c->io_arg, &burst[i]);
    }
    return n;
}

void dp_run(struct dp_ctx *c)
{
    dp_set_state(c, DP_STATE_READY);
    while (!c->stop)
        dp_poll_once(c);
    dp_set_state(c, DP_STATE_RESET);
}

const char *dp_strerror(int rc)
{
    switch (rc) {
    case DP_OK:            return "ok";
    case DP_ERR_SHORT:     return "buffer too short";
    case DP_ERR_MAGIC:     return "bad table magic";
    case DP_ERR_TYPE:      return "wrong table type";
    case DP_ERR_RECSZ:     return "unexpected record size";
    case DP_ERR_TOOMANY:   return "too many policy rows";
    case DP_ERR_NOMEM:     return "out of memory";
    case DP_ERR_NOTIP:     return "not IPv4";
    case DP_ERR_HANDSHAKE: return "shared-region handshake failed";
    case DP_ERR_BANK:      return "invalid policy bank";
    default:               return "unknown";
    }
}
