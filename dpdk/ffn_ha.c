/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_ha.c -- FFN-NGFW Active/Active HA core logic (daisy-chain / load-balance /
 * HA3 packet-forwarding). Pure C, no DPDK dependency -> unit-testable on any
 * host. The DPDK mbuf glue lives in ffn_ha_dpdk.c (built with FFN_HA_WITH_DPDK).
 */
#include "ffn_ha.h"

/* -------------------------------------------------------------------------- */
void ffn_ha_state_init(struct ffn_ha_state *st, uint8_t device_id,
                       enum ffn_ha_mode mode, enum ffn_ha_algo algo,
                       uint64_t now_ms)
{
    memset(st, 0, sizeof(*st));
    st->mode           = mode;
    st->algo           = algo;
    st->device_id      = device_id;
    st->ndevices       = 2;
    st->primary_device = 0;
    st->enabled        = (mode != FFN_HA_MODE_DISABLED);
    st->hstate         = FFN_HA_ST_INIT;
    st->ha3_port       = -1;
    /* PAN-OS-ish defaults: hello 1s, peer down after 3s silence, 2s failback hold */
    st->heartbeat_ms    = 1000;
    st->peer_timeout_ms = 3000;
    st->hold_ms         = 2000;
    st->peer_up            = false;
    st->peer_last_seen_ms  = now_ms;
    st->tentative_since_ms = 0;
    st->start_ms           = now_ms;
    /* An A/A member starts active; A/P: primary active, secondary passive. */
    if (mode == FFN_HA_MODE_ACTIVE_PASSIVE)
        st->hstate = (device_id == st->primary_device) ? FFN_HA_ST_ACTIVE
                                                        : FFN_HA_ST_PASSIVE;
    else if (mode == FFN_HA_MODE_ACTIVE_ACTIVE)
        st->hstate = (device_id == st->primary_device) ? FFN_HA_ST_ACTIVE
                                                        : FFN_HA_ST_ACTIVE_SEC;
}

/* Normalize a 5-tuple so BOTH directions of a conversation map to the same key
 * (symmetric ownership). Order the (ip,port) endpoints canonically. */
void ffn_ha_normalize_key(struct ffn_ha_flowkey *k,
                          uint32_t sip, uint32_t dip,
                          uint16_t sport, uint16_t dport, uint8_t proto)
{
    memset(k, 0, sizeof(*k));
    int src_first = (sip < dip) || (sip == dip && sport <= dport);
    if (src_first) {
        k->ip_lo = sip; k->port_lo = sport;
        k->ip_hi = dip; k->port_hi = dport;
    } else {
        k->ip_lo = dip; k->port_lo = dport;
        k->ip_hi = sip; k->port_hi = sport;
    }
    k->proto = proto;
}

/* FNV-1a over the meaningful key bytes (little-endian layout, explicit so it is
 * stable across compilers regardless of struct padding). */
uint32_t ffn_ha_hash(const struct ffn_ha_flowkey *k)
{
    uint8_t buf[13];
    buf[0]  = (uint8_t)(k->ip_lo);       buf[1]  = (uint8_t)(k->ip_lo >> 8);
    buf[2]  = (uint8_t)(k->ip_lo >> 16); buf[3]  = (uint8_t)(k->ip_lo >> 24);
    buf[4]  = (uint8_t)(k->ip_hi);       buf[5]  = (uint8_t)(k->ip_hi >> 8);
    buf[6]  = (uint8_t)(k->ip_hi >> 16); buf[7]  = (uint8_t)(k->ip_hi >> 24);
    buf[8]  = (uint8_t)(k->port_lo);     buf[9]  = (uint8_t)(k->port_lo >> 8);
    buf[10] = (uint8_t)(k->port_hi);     buf[11] = (uint8_t)(k->port_hi >> 8);
    buf[12] = k->proto;

    uint32_t h = 2166136261u;            /* FNV offset basis */
    for (int i = 0; i < 13; i++) {
        h ^= buf[i];
        h *= 16777619u;                  /* FNV prime */
    }
    return h;
}

/* Which device is the session owner for this (normalized) flow? */
uint8_t ffn_ha_owner(const struct ffn_ha_state *st,
                     const struct ffn_ha_flowkey *k)
{
    uint8_t n = st->ndevices ? st->ndevices : 1;
    switch (st->algo) {
    case FFN_HA_ALGO_PRIMARY:
        return st->primary_device;
    case FFN_HA_ALGO_IP_MODULO:
        /* normalized smaller IP modulo device-count -> symmetric */
        return (uint8_t)(k->ip_lo % n);
    case FFN_HA_ALGO_IP_HASH:
    default:
        return (uint8_t)(ffn_ha_hash(k) % n);
    }
}

/* Per-packet decision. `from_peer` = the frame arrived on the HA3 link. */
enum ffn_ha_decision ffn_ha_decide(const struct ffn_ha_state *st,
                                   const struct ffn_ha_flowkey *k,
                                   bool from_peer)
{
    if (!st->enabled || st->mode == FFN_HA_MODE_DISABLED)
        return FFN_HA_LOCAL;                 /* HA off -> always local */
    if (from_peer)
        return FFN_HA_FROM_PEER;             /* peer already chose us as owner */

    uint8_t owner = ffn_ha_owner(st, k);
    if (owner == st->device_id)
        return FFN_HA_LOCAL;                 /* we own it -> inspect here */
    /* peer owns it */
    return st->peer_up ? FFN_HA_FORWARD      /* dump raw over HA3 to the owner */
                       : FFN_HA_TAKEOVER;    /* peer down -> we take over */
}

/* HA1: a hello arrived from the peer. */
void ffn_ha_on_hello(struct ffn_ha_state *st,
                     const struct ffn_ha1_hello *h, uint64_t now_ms)
{
    if (!st->enabled)
        return;
    if (h->magic != FFN_HA1_MAGIC)
        return;
    if (h->device_id == st->device_id)
        return;                              /* ignore our own hello */
    st->hellos_rx++;
    st->peer_last_seen_ms = now_ms;
    if (!st->peer_up && st->tentative_since_ms == 0)
        st->tentative_since_ms = now_ms;     /* begin failback debounce */
}

/* Build our outgoing hello. */
void ffn_ha_build_hello(const struct ffn_ha_state *st,
                        struct ffn_ha1_hello *out, uint64_t now_ms)
{
    memset(out, 0, sizeof(*out));
    out->magic     = FFN_HA1_MAGIC;
    out->version   = FFN_HA3_VERSION;
    out->device_id = st->device_id;
    out->mode      = (uint8_t)st->mode;
    out->state     = (uint8_t)st->hstate;
    out->seq       = st->seq;
    out->uptime_ms = now_ms - st->start_ms;
    out->sessions  = st->local_owned;
}

/* Failover timer. Call ~every heartbeat interval. Fast down-detection on
 * silence past peer_timeout_ms; debounced failback (hold_ms) when the peer
 * returns, to avoid flapping. Returns true if peer_up changed. */
bool ffn_ha_tick(struct ffn_ha_state *st, uint64_t now_ms)
{
    if (!st->enabled || st->mode == FFN_HA_MODE_DISABLED)
        return false;

    uint64_t silence = (now_ms >= st->peer_last_seen_ms)
                     ? (now_ms - st->peer_last_seen_ms) : 0;
    bool changed = false;

    if (st->peer_up) {
        if (silence > st->peer_timeout_ms) {
            /* peer lost -> take over its flows immediately */
            st->peer_up = false;
            st->takeovers++;
            st->hstate = FFN_HA_ST_ACTIVE;   /* sole active */
            st->tentative_since_ms = 0;
            changed = true;
        }
    } else {
        /* peer down; see if it is recovering (recent hello) + debounce */
        if (st->tentative_since_ms != 0 && silence <= st->peer_timeout_ms) {
            if ((now_ms - st->tentative_since_ms) >= st->hold_ms) {
                st->peer_up = true;
                st->tentative_since_ms = 0;
                st->hstate = (st->device_id == st->primary_device)
                           ? FFN_HA_ST_ACTIVE : FFN_HA_ST_ACTIVE_SEC;
                changed = true;
            }
        } else if (silence > st->peer_timeout_ms) {
            st->tentative_since_ms = 0;       /* recovery aborted */
        }
    }
    return changed;
}
