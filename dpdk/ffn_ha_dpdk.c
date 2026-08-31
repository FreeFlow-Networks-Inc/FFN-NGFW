/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_ha_dpdk.c -- DPDK mbuf glue for the FFN HA core (ffn_ha.c). Built into
 * the data plane with -DFFN_HA_WITH_DPDK. Turns real frames into flow keys and
 * implements the HA3 "dump pure L1" wire format (wrap the original frame).
 */
#define FFN_HA_WITH_DPDK 1
#include "ffn_ha.h"

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

/* Extract a normalized (symmetric) flow key from an IPv4 frame. Returns 0 on
 * success, -1 if the frame is not IPv4 / too short to parse. */
int ffn_ha_key_from_mbuf(struct rte_mbuf *m, struct ffn_ha_flowkey *k)
{
    if (rte_pktmbuf_pkt_len(m) < sizeof(struct rte_ether_hdr) +
                                 sizeof(struct rte_ipv4_hdr))
        return -1;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return -1;

    struct rte_ipv4_hdr *ip4 = (struct rte_ipv4_hdr *)(eth + 1);
    uint32_t sip = rte_be_to_cpu_32(ip4->src_addr);
    uint32_t dip = rte_be_to_cpu_32(ip4->dst_addr);
    uint8_t  proto = ip4->next_proto_id;
    uint8_t  ihl = (ip4->version_ihl & 0x0F) * 4;
    uint16_t sport = 0, dport = 0;

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *t = (struct rte_tcp_hdr *)((uint8_t *)ip4 + ihl);
        sport = rte_be_to_cpu_16(t->src_port);
        dport = rte_be_to_cpu_16(t->dst_port);
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *u = (struct rte_udp_hdr *)((uint8_t *)ip4 + ihl);
        sport = rte_be_to_cpu_16(u->src_port);
        dport = rte_be_to_cpu_16(u->dst_port);
    }

    ffn_ha_normalize_key(k, sip, dip, sport, dport, proto);
    return 0;
}

/* HA3 encap: wrap the ENTIRE original frame (its own L2 included) behind a new
 * Ethernet header (dst=peer, src=us, ethertype=FFN_HA3) + ffn_ha3_hdr. This is
 * the raw "L1/L2 dump" -- the peer strips it and processes the inner frame as
 * if received locally. Returns 0 on success, -1 on headroom failure. */
int ffn_ha_ha3_encap(struct ffn_ha_state *st, struct rte_mbuf *m,
                     uint8_t ingress_port, uint32_t flow_hash)
{
    uint16_t orig_len = rte_pktmbuf_pkt_len(m);
    const uint16_t wrap = sizeof(struct rte_ether_hdr) + sizeof(struct ffn_ha3_hdr);

    char *p = rte_pktmbuf_prepend(m, wrap);
    if (p == NULL) {
        st->ha3_drops++;
        return -1;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    memcpy(eth->dst_addr.addr_bytes, st->peer_mac, 6);
    memcpy(eth->src_addr.addr_bytes, st->self_mac, 6);
    eth->ether_type = rte_cpu_to_be_16(FFN_HA3_ETHERTYPE);

    struct ffn_ha3_hdr *h = (struct ffn_ha3_hdr *)(eth + 1);
    h->magic        = rte_cpu_to_be_16(FFN_HA3_ETHERTYPE);
    h->version      = FFN_HA3_VERSION;
    h->flags        = 0x01;                 /* owner-hint valid */
    h->src_device   = st->device_id;
    h->ingress_port = ingress_port;
    h->orig_len     = rte_cpu_to_be_16(orig_len);
    h->flow_hash    = rte_cpu_to_be_32(flow_hash);

    st->fwd_to_peer++;
    return 0;
}

/* HA3 decap: validate + strip the wrapper from a frame received on the HA3
 * port, leaving the original inner frame at the mbuf head. Copies the parsed
 * header into *out (host order). Returns 0 on success, -1 if not a valid HA3
 * frame. */
int ffn_ha_ha3_decap(struct ffn_ha_state *st, struct rte_mbuf *m,
                     struct ffn_ha3_hdr *out)
{
    const uint16_t wrap = sizeof(struct rte_ether_hdr) + sizeof(struct ffn_ha3_hdr);
    if (rte_pktmbuf_pkt_len(m) < wrap) {
        st->ha3_drops++;
        return -1;
    }

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(FFN_HA3_ETHERTYPE)) {
        st->ha3_drops++;
        return -1;
    }

    struct ffn_ha3_hdr *h = (struct ffn_ha3_hdr *)(eth + 1);
    if (rte_be_to_cpu_16(h->magic) != FFN_HA3_ETHERTYPE ||
        h->version != FFN_HA3_VERSION) {
        st->ha3_drops++;
        return -1;
    }

    if (out) {
        out->magic        = FFN_HA3_ETHERTYPE;
        out->version      = h->version;
        out->flags        = h->flags;
        out->src_device   = h->src_device;
        out->ingress_port = h->ingress_port;
        out->orig_len     = rte_be_to_cpu_16(h->orig_len);
        out->flow_hash    = rte_be_to_cpu_32(h->flow_hash);
    }

    /* strip the wrapper -> original inner frame is now at the head */
    rte_pktmbuf_adj(m, wrap);
    st->rx_from_peer++;
    return 0;
}
