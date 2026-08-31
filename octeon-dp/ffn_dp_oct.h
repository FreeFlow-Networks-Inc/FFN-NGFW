/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_oct.h -- FFN OCTEON-II dataplane: types + API.
 * Architecture-neutral: no chip headers, so this builds natively for the test
 * harness and cross-compiles for mips64 (OCTEON-II) unchanged.
 */
#ifndef FFN_DP_OCT_H
#define FFN_DP_OCT_H

#include <stdint.h>
#include <stddef.h>

/* decisions / verdicts -- values MUST match ffn_fastpath.h */
#define FP_FORWARD_W    0
#define FP_INSPECT_W    1
#define FP_PUNT_FPGA_W  2
#define FP_DROP_W       3
#define FP_LOCAL_W      4

#define FP_V_UNSET_W    0
#define FP_V_ALLOW_W    1
#define FP_V_DROP_W     2
#define FP_V_RESET_W    3

#define DP_DECISION_NOMATCH (-1)
#define DP_EGRESS_NONE      0xFFFFu

/* return codes */
#define DP_OK             0
#define DP_ERR_SHORT     (-1)
#define DP_ERR_MAGIC     (-2)
#define DP_ERR_TYPE      (-3)
#define DP_ERR_RECSZ     (-4)
#define DP_ERR_TOOMANY   (-5)
#define DP_ERR_NOMEM     (-6)
#define DP_ERR_NOTIP     (-7)
#define DP_ERR_HANDSHAKE (-8)
#define DP_ERR_BANK      (-9)

#define DP_MAX_POLICY     16384u
#define DP_DEFAULT_FLOWS  262144u
#define DP_BURST          32

#define DP_ETH_HLEN        14u
#define DP_IP4_MIN_HLEN    20u
#define DP_ETHERTYPE_IPV4  0x0800u
#define DP_ETHERTYPE_VLAN  0x8100u
#define DP_IPPROTO_TCP     6u
#define DP_IPPROTO_UDP     17u

#define DP_FF_INSPECT   0x1
#define DP_FF_OFFLOADED 0x2

/* NOTE: there is deliberately no dp_ntohl()-style helper here. IPv4 fields in
 * the fastpath tables are network-order BYTES and must be read with ld_be32()
 * from ffn_dp_abi.h, which is endian-neutral. A host-endianness-dependent
 * ntohl applied to an already-neutral load byte-swaps addresses on big-endian
 * targets (OCTEON-II) while looking correct on x86. */

/* native-endian policy row (converted once from the wire rows) */
struct dp_policy_row {
    uint32_t src_ip, src_mask, dst_ip, dst_mask;   /* host order */
    uint16_t sport_lo, sport_hi, dport_lo, dport_hi;
    uint8_t  proto, vsys, action, flags;
    uint16_t egress, rule_id;
};

struct dp_tables {
    uint16_t version;
    uint32_t policy_n;
    struct dp_policy_row policy[DP_MAX_POLICY];
};

/* parsed packet 5-tuple (host order) */
struct dp_tuple {
    uint32_t src_ip, dst_ip;
    uint16_t sport, dport;
    uint8_t  proto, vsys, tcp_flags, pad;
};

/* normalized bidirectional flow key */
struct dp_flow_key {
    uint32_t ip_a, ip_b;
    uint16_t port_a, port_b;
    uint8_t  proto, vsys;
};

struct dp_flow_ent {
    struct dp_flow_key key;
    uint8_t  used, verdict, flags, pad;
    uint16_t rule_id, egress;
    uint32_t pkts;
    uint64_t bytes;
};

struct dp_flow_table {
    struct dp_flow_ent *ent;
    uint32_t slots, mask, count;
};

/* one packet handed between the I/O backend and the forwarder */
struct dp_pkt {
    uint8_t *data;
    uint32_t len;
    uint8_t  vsys;
    uint8_t  decision;
    uint16_t egress;
    void    *cookie;        /* backend-private (mbuf/wqe/etc.) */
};

/* pluggable packet I/O: "sim" for tests, PKI/PKO or AF_PACKET on real Octeon */
struct dp_io_ops {
    const char *name;
    int  (*init)(void *arg);
    void (*fini)(void *arg);
    int  (*rx)(void *arg, struct dp_pkt *burst, int max);
    int  (*tx)(void *arg, struct dp_pkt *burst, int n);
    void (*to_local)(void *arg, struct dp_pkt *p);
    void (*to_offload)(void *arg, struct dp_pkt *p);
    void (*free_pkt)(void *arg, struct dp_pkt *p);
};

struct dp_result {
    struct dp_tuple tuple;
    int      decision;
    uint16_t rule_id, egress;
    uint8_t  from_cache, reset;
};

struct dp_ctx {
    void   *region;
    size_t  region_size;
    uint32_t active_bank;
    int     default_decision;
    int     stop;
    struct dp_tables tables;
    struct dp_flow_table flows;
    const struct dp_io_ops *io;
    void   *io_arg;
    /* counters */
    uint64_t stat_rx, stat_tx, stat_tx_fail, stat_forward, stat_inspect;
    uint64_t stat_drop, stat_punt, stat_local, stat_cache_hit, stat_classify;
    uint64_t stat_parse_err, stat_flow_full;
};

/* API */
int  dp_tables_load(struct dp_tables *t, const void *blob, size_t len);
int  dp_classify(const struct dp_tables *t, const struct dp_tuple *k,
                 uint16_t *rule_id, uint16_t *egress);
int  dp_parse(const uint8_t *pkt, uint32_t len, uint8_t vsys, struct dp_tuple *t);
void dp_flow_key_from_tuple(struct dp_flow_key *k, const struct dp_tuple *t);
int  dp_flow_init(struct dp_flow_table *ft, uint32_t slots);
void dp_flow_fini(struct dp_flow_table *ft);
void dp_flow_flush(struct dp_flow_table *ft);
struct dp_flow_ent *dp_flow_lookup(struct dp_flow_table *ft,
                                   const struct dp_flow_key *k);
struct dp_flow_ent *dp_flow_insert(struct dp_flow_table *ft,
                                   const struct dp_flow_key *k);
int  dp_process(struct dp_ctx *c, const uint8_t *pkt, uint32_t len,
                uint8_t vsys, struct dp_result *out);
int  dp_region_attach(struct dp_ctx *c, void *base, size_t size, int create);
void dp_set_state(struct dp_ctx *c, uint32_t state);
uint32_t dp_get_state(struct dp_ctx *c);
void dp_heartbeat(struct dp_ctx *c);
int  dp_activate_bank(struct dp_ctx *c, uint32_t bank);
int  dp_service_commands(struct dp_ctx *c);
int  dp_init(struct dp_ctx *c, const struct dp_io_ops *io, void *io_arg,
             uint32_t flow_slots);
void dp_fini(struct dp_ctx *c);
int  dp_poll_once(struct dp_ctx *c);
void dp_run(struct dp_ctx *c);
const char *dp_strerror(int rc);

#endif /* FFN_DP_OCT_H */
