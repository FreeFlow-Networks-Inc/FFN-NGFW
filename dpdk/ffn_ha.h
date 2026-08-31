/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_ha.h -- PAN-OS-style Active/Active High Availability for the FFN-NGFW
 * DPDK data plane. Daisy-chain / load-balance / packet-forwarding functions
 * that let two (or more) FFN boxes share the traffic load and "dump" raw
 * frames to a peer for additional inspection power + redundancy.
 *
 * Mapping to PAN-OS Active/Active HA (verified against the PA-VM schema):
 *   HA1  control/heartbeat  -> ffn_ha1_hello over a control link (UDP or raw)
 *   HA2  session-state sync -> (owned by ffn_ha_sync.*, out of this header)
 *   HA3  packet-forwarding  -> ffn_ha3_hdr + raw original frame over ha3_port
 *   session-setup           -> enum ffn_ha_algo (ip-hash|ip-modulo|primary)
 *   session-owner           -> the device a flow maps to; it inspects + logs
 *   device-id 0/1           -> ffn_ha_state.device_id
 *
 * The pure logic (key/hash/owner/decide/failover) has NO DPDK dependency so it
 * is unit-testable on any host; the mbuf glue lives behind FFN_HA_WITH_DPDK.
 */
#ifndef FFN_HA_H
#define FFN_HA_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define FFN_HA_MAX_DEVICES   4          /* pair today; headroom for daisy-chain */
#define FFN_HA3_ETHERTYPE    0xFA3F     /* custom ethertype for HA3 frames      */
#define FFN_HA3_VERSION      1
#define FFN_HA1_MAGIC        0x4641     /* 'FA' -- hello magic                  */

/* session-setup / load-balance algorithm (PAN-OS: session-setup) */
enum ffn_ha_algo {
    FFN_HA_ALGO_IP_HASH   = 0,  /* symmetric hash of the sorted 5-tuple (default) */
    FFN_HA_ALGO_IP_MODULO = 1,  /* normalized src ip modulo device-count          */
    FFN_HA_ALGO_PRIMARY   = 2,  /* primary-device owns all (active/passive)        */
};

/* HA operating mode (PAN-OS: group/mode) */
enum ffn_ha_mode {
    FFN_HA_MODE_DISABLED       = 0,
    FFN_HA_MODE_ACTIVE_ACTIVE  = 1,
    FFN_HA_MODE_ACTIVE_PASSIVE = 2,
};

/* local HA runtime state machine (PAN-OS: state) */
enum ffn_ha_hstate {
    FFN_HA_ST_INIT      = 0,
    FFN_HA_ST_ACTIVE    = 1,   /* active(-primary) */
    FFN_HA_ST_ACTIVE_SEC= 2,   /* active-secondary */
    FFN_HA_ST_PASSIVE   = 3,
    FFN_HA_ST_TENTATIVE = 4,   /* peer just lost; holding before takeover */
};

/* per-packet HA decision */
enum ffn_ha_decision {
    FFN_HA_LOCAL     = 0,  /* we own this flow -> inspect locally             */
    FFN_HA_FORWARD   = 1,  /* peer owns it & peer up -> dump raw over HA3     */
    FFN_HA_TAKEOVER  = 2,  /* peer owns it but peer DOWN -> we take over      */
    FFN_HA_FROM_PEER = 3,  /* arrived on HA3 from the peer -> inspect locally */
};

/* normalized (symmetric) flow key: both directions of a conversation produce
 * the SAME key, so the same box owns/inspects the whole flow. */
struct ffn_ha_flowkey {
    uint32_t ip_lo, ip_hi;     /* sorted src/dst, host order   */
    uint16_t port_lo, port_hi; /* sorted L4 ports, host order  */
    uint8_t  proto;
    uint8_t  _pad[3];
};

/* HA3 forwarding header, prepended to the raw ORIGINAL L2 frame on the HA3
 * link. Wire: [eth dst=peer][eth src=us][ethertype=FFN_HA3_ETHERTYPE]
 *             [ffn_ha3_hdr][original frame bytes...]  -- the "dump pure L1". */
struct ffn_ha3_hdr {
    uint16_t magic;        /* FFN_HA3_ETHERTYPE, network order */
    uint8_t  version;      /* FFN_HA3_VERSION */
    uint8_t  flags;        /* bit0 owner-hint valid; bit1 return-flow */
    uint8_t  src_device;   /* forwarding device-id */
    uint8_t  ingress_port; /* original DPDK ingress port on the sender */
    uint16_t orig_len;     /* original frame length (sanity check) */
    uint32_t flow_hash;    /* precomputed owner hash (peer may skip recompute) */
} __attribute__((packed));

/* HA1 heartbeat hello (control link) */
struct ffn_ha1_hello {
    uint16_t magic;        /* FFN_HA1_MAGIC */
    uint8_t  version;
    uint8_t  device_id;
    uint8_t  mode;         /* enum ffn_ha_mode  */
    uint8_t  state;        /* enum ffn_ha_hstate */
    uint16_t _pad;
    uint64_t seq;          /* monotonic hello counter */
    uint64_t uptime_ms;
    uint64_t sessions;     /* local owned-session count (LB telemetry) */
} __attribute__((packed));

/* runtime HA state (per box) */
struct ffn_ha_state {
    enum ffn_ha_mode   mode;
    enum ffn_ha_algo   algo;
    enum ffn_ha_hstate hstate;
    uint8_t  device_id;        /* 0 or 1 */
    uint8_t  ndevices;         /* 2 for a pair */
    uint8_t  primary_device;   /* for PRIMARY algo / active-passive */
    bool     enabled;

    /* peer liveness / failover */
    bool     peer_up;
    uint64_t peer_last_seen_ms;
    uint64_t tentative_since_ms;
    uint32_t hold_ms;          /* tentative-hold before takeover (anti-flap) */
    uint32_t heartbeat_ms;     /* hello interval */
    uint32_t peer_timeout_ms;  /* declare peer down after this silence */

    /* HA3 packet-forwarding link */
    int      ha3_port;         /* DPDK port id of the HA3 link (-1 = none) */
    uint8_t  peer_mac[6];
    uint8_t  self_mac[6];

    /* HA counters */
    uint64_t fwd_to_peer;      /* frames dumped to the peer over HA3 */
    uint64_t rx_from_peer;     /* frames received from the peer over HA3 */
    uint64_t local_owned;      /* flows inspected locally */
    uint64_t takeovers;        /* failover takeovers */
    uint64_t ha3_drops;        /* HA3 frames dropped (malformed / no port) */
    uint64_t hellos_rx, hellos_tx;
    uint64_t seq;              /* our hello sequence */
    uint64_t start_ms;         /* for uptime */
};

/* -------- pure logic (no DPDK; unit-testable) -------- */
void     ffn_ha_state_init(struct ffn_ha_state *st, uint8_t device_id,
                           enum ffn_ha_mode mode, enum ffn_ha_algo algo,
                           uint64_t now_ms);
void     ffn_ha_normalize_key(struct ffn_ha_flowkey *k,
                              uint32_t sip, uint32_t dip,
                              uint16_t sport, uint16_t dport, uint8_t proto);
uint32_t ffn_ha_hash(const struct ffn_ha_flowkey *k);
uint8_t  ffn_ha_owner(const struct ffn_ha_state *st,
                      const struct ffn_ha_flowkey *k);
enum ffn_ha_decision ffn_ha_decide(const struct ffn_ha_state *st,
                                   const struct ffn_ha_flowkey *k,
                                   bool from_peer);
void     ffn_ha_on_hello(struct ffn_ha_state *st,
                         const struct ffn_ha1_hello *h, uint64_t now_ms);
void     ffn_ha_build_hello(const struct ffn_ha_state *st,
                            struct ffn_ha1_hello *out, uint64_t now_ms);
/* failover timer: call periodically; flips peer_up->false past the timeout
 * (with tentative-hold) and counts the takeover. Returns true if state changed. */
bool     ffn_ha_tick(struct ffn_ha_state *st, uint64_t now_ms);

/* -------- DPDK glue (only when built into the data plane) -------- */
#ifdef FFN_HA_WITH_DPDK
#include <rte_mbuf.h>
/* extract a normalized flow key from an mbuf; 0 on success, <0 if not IPv4/parse */
int  ffn_ha_key_from_mbuf(struct rte_mbuf *m, struct ffn_ha_flowkey *k);
/* prepend the HA3 header + set eth dst=peer/src=us/ethertype; TX-ready. 0 ok. */
int  ffn_ha_ha3_encap(struct ffn_ha_state *st, struct rte_mbuf *m,
                      uint8_t ingress_port, uint32_t flow_hash);
/* validate + strip the HA3 header from a frame received on ha3_port. 0 ok. */
int  ffn_ha_ha3_decap(struct ffn_ha_state *st, struct rte_mbuf *m,
                      struct ffn_ha3_hdr *out);
#endif

#endif /* FFN_HA_H */
