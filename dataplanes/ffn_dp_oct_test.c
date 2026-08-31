/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_oct_test.c -- end-to-end test harness for the OCTEON-II dataplane.
 *
 * Proves the dataplane WITHOUT Octeon hardware: it builds real policy.bin bytes
 * in ffn_fastpath_compile.py's exact wire format (LE, 36-byte fp_hdr + 32-byte
 * rows), stages them into a simulated shared region, drives synthetic packets
 * through dp_process(), and exercises the MP<->DP command/event rings.
 *
 * Because the tables and the region are little-endian on the wire and the code
 * only touches them through the ld_leNN / st_leNN helpers, passing here on
 * x86-64 LE and on a big-endian build are the same test -- run it under
 * `qemu-mips64` (or on the Octeon) to validate BE with identical expectations.
 */
#include "ffn_dp_abi.h"
#include "ffn_dp_oct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
static void chk(int cond, const char *msg)
{
    printf("  %s %s\n", cond ? "ok  " : "FAIL", msg);
    if (!cond) g_fail++;
}

/* ---- build a policy.bin exactly as the Python compiler does ---- */
struct trow {
    uint32_t src_ip, src_mask, dst_ip, dst_mask;   /* host order in, NBO out */
    uint16_t sport_lo, sport_hi, dport_lo, dport_hi;
    uint8_t  proto, vsys, action, flags;
    uint16_t egress, rule_id;
};

static void put_nbo32(uint8_t *p, uint32_t host)
{
    /* IPv4 table fields are network-order bytes (what struct.pack("<I", ...) of
     * an already-NBO integer produces on the compiler side). */
    st_be32(p, host);
}

static size_t build_policy_bin(uint8_t *out, size_t cap,
                               const struct trow *rows, uint32_t n)
{
    size_t need = 36 + (size_t)n * 32;
    if (cap < need) return 0;
    memset(out, 0, need);
    memcpy(out, "FPPO", 4);
    st_le16(out + 4, 1);            /* version      */
    st_le16(out + 6, 0x40);         /* table_type   */
    st_le32(out + 8, n);            /* entry_count  */
    st_le64(out + 12, 1787000000ull); /* build_unix */
    st_le32(out + 20, 0);           /* crc32        */
    st_le32(out + 24, 32);          /* record_size  */
    st_le32(out + 28, n);           /* populated    */
    st_le32(out + 32, 0);           /* reserved     */
    uint8_t *r = out + 36;
    for (uint32_t i = 0; i < n; i++, r += 32) {
        put_nbo32(r + 0,  rows[i].src_ip);
        put_nbo32(r + 4,  rows[i].src_mask);
        put_nbo32(r + 8,  rows[i].dst_ip);
        put_nbo32(r + 12, rows[i].dst_mask);
        st_le16(r + 16, rows[i].sport_lo);
        st_le16(r + 18, rows[i].sport_hi);
        st_le16(r + 20, rows[i].dport_lo);
        st_le16(r + 22, rows[i].dport_hi);
        r[24] = rows[i].proto;
        r[25] = rows[i].vsys;
        r[26] = rows[i].action;
        r[27] = rows[i].flags;
        st_le16(r + 28, rows[i].egress);
        st_le16(r + 30, rows[i].rule_id);
    }
    return need;
}

/* ---- synthetic packet builder ---- */
static uint32_t mkpkt(uint8_t *buf, uint32_t sip, uint32_t dip, uint8_t proto,
                      uint16_t sp, uint16_t dp_, int vlan, uint32_t payload)
{
    uint32_t o = 0;
    memset(buf, 0, 128);
    memset(buf + 0, 0xAA, 6);          /* dst mac */
    memset(buf + 6, 0xBB, 6);          /* src mac */
    o = 12;
    if (vlan) {
        buf[o++] = 0x81; buf[o++] = 0x00;
        buf[o++] = 0x00; buf[o++] = 0x64;   /* vid 100 */
    }
    buf[o++] = 0x08; buf[o++] = 0x00;       /* IPv4 */
    uint8_t *ip = buf + o;
    ip[0] = 0x45;                            /* v4, ihl 5 */
    ip[9] = proto;
    ip[12] = (uint8_t)(sip >> 24); ip[13] = (uint8_t)(sip >> 16);
    ip[14] = (uint8_t)(sip >> 8);  ip[15] = (uint8_t)sip;
    ip[16] = (uint8_t)(dip >> 24); ip[17] = (uint8_t)(dip >> 16);
    ip[18] = (uint8_t)(dip >> 8);  ip[19] = (uint8_t)dip;
    uint8_t *l4 = ip + 20;
    l4[0] = (uint8_t)(sp >> 8); l4[1] = (uint8_t)sp;
    l4[2] = (uint8_t)(dp_ >> 8); l4[3] = (uint8_t)dp_;
    if (proto == DP_IPPROTO_TCP) l4[13] = 0x02;   /* SYN */
    return o + 20 + 20 + payload;
}

/* ---- sim I/O backend ---- */
struct sim_io {
    struct { uint8_t buf[128]; uint32_t len; uint8_t vsys; } q[64];
    int n, head;
    int txed, localed, offloaded;
};
static int sim_rx(void *arg, struct dp_pkt *b, int max)
{
    struct sim_io *s = (struct sim_io *)arg;
    int i = 0;
    while (i < max && s->head < s->n) {
        b[i].data = s->q[s->head].buf;
        b[i].len = s->q[s->head].len;
        b[i].vsys = s->q[s->head].vsys;
        b[i].cookie = NULL;
        s->head++; i++;
    }
    return i;
}
static int sim_tx(void *arg, struct dp_pkt *b, int n)
{
    (void)b; ((struct sim_io *)arg)->txed += n; return n;
}
static void sim_local(void *arg, struct dp_pkt *p)
{
    (void)p; ((struct sim_io *)arg)->localed++;
}
static void sim_offload(void *arg, struct dp_pkt *p)
{
    (void)p; ((struct sim_io *)arg)->offloaded++;
}
static const struct dp_io_ops SIM_IO = {
    "sim", NULL, NULL, sim_rx, sim_tx, sim_local, sim_offload, NULL
};
static void sim_push(struct sim_io *s, const uint8_t *pkt, uint32_t len, uint8_t vsys)
{
    if (s->n >= 64) return;
    memcpy(s->q[s->n].buf, pkt, len > 128 ? 128 : len);
    s->q[s->n].len = len;
    s->q[s->n].vsys = vsys;
    s->n++;
}

#define IP(a,b,c,d) (((uint32_t)(a)<<24)|((uint32_t)(b)<<16)|((uint32_t)(c)<<8)|(uint32_t)(d))

int main(void)
{
    printf("=== FFN OCTEON-II dataplane test ===\n");
    printf("[host is %s-endian]\n",
           (*(const uint16_t *)"\x01\x02" == 0x0201) ? "little" : "big");

    /* ---------- 1. table load ---------- */
    printf("\n[1] policy table load (compiler wire format)\n");
    struct trow rows[] = {
      /* allow 10.1.0.0/16 -> any tcp/443, vsys1, rule 101 */
      { IP(10,1,0,0), IP(255,255,0,0), 0, 0, 0,65535, 443,443,
        DP_IPPROTO_TCP, 1, FP_FORWARD_W, 0, 7, 101 },
      /* inspect 10.1.0.0/16 -> any tcp/80 */
      { IP(10,1,0,0), IP(255,255,0,0), 0, 0, 0,65535, 80,80,
        DP_IPPROTO_TCP, 1, FP_INSPECT_W, 0, 7, 102 },
      /* drop anything to 192.0.2.66/32 */
      { 0, 0, IP(192,0,2,66), IP(255,255,255,255), 0,65535, 0,65535,
        0, 1, FP_DROP_W, 0, DP_EGRESS_NONE, 103 },
      /* udp/53 from any -> local */
      { 0, 0, 0, 0, 0,65535, 53,53, DP_IPPROTO_UDP, 1, FP_LOCAL_W, 0,
        DP_EGRESS_NONE, 104 },
      /* vsys2-only rule: proves vsys isolation */
      { IP(10,1,0,0), IP(255,255,0,0), 0, 0, 0,65535, 443,443,
        DP_IPPROTO_TCP, 2, FP_DROP_W, 0, DP_EGRESS_NONE, 105 },
    };
    uint32_t nrows = (uint32_t)(sizeof(rows) / sizeof(rows[0]));
    static uint8_t polbin[8192];
    size_t polsz = build_policy_bin(polbin, sizeof(polbin), rows, nrows);
    chk(polsz == 36 + nrows * 32, "policy.bin built at expected size");

    struct dp_tables t;
    int rc = dp_tables_load(&t, polbin, polsz);
    chk(rc == DP_OK, "dp_tables_load OK");
    chk(t.policy_n == nrows, "row count parsed");
    chk(t.policy[0].src_ip == IP(10,1,0,0), "row0 src_ip decoded to host order");
    chk(t.policy[0].src_mask == IP(255,255,0,0), "row0 mask decoded");
    chk(t.policy[0].dport_lo == 443 && t.policy[0].rule_id == 101,
        "row0 ports/rule_id decoded");
    chk(t.policy[2].dst_ip == IP(192,0,2,66), "row2 dst_ip decoded");

    /* rejection paths */
    uint8_t bad[64];
    memcpy(bad, polbin, 64);
    bad[0] = 'X';
    chk(dp_tables_load(&t, bad, 64) == DP_ERR_MAGIC, "bad magic rejected");
    memcpy(bad, polbin, 64);
    st_le32(bad + 24, 31);
    chk(dp_tables_load(&t, bad, 64) == DP_ERR_RECSZ, "bad record_size rejected");
    chk(dp_tables_load(&t, polbin, 20) == DP_ERR_SHORT, "truncated blob rejected");
    rc = dp_tables_load(&t, polbin, polsz);   /* reload good */

    /* ---------- 2. classify ---------- */
    printf("\n[2] classify\n");
    struct dp_tuple k;
    uint16_t rid, egr;
    memset(&k, 0, sizeof(k));
    k.src_ip = IP(10,1,2,3); k.dst_ip = IP(93,184,216,34);
    k.sport = 40000; k.dport = 443; k.proto = DP_IPPROTO_TCP; k.vsys = 1;
    chk(dp_classify(&t, &k, &rid, &egr) == FP_FORWARD_W && rid == 101,
        "vsys1 tcp/443 -> FORWARD rule 101");
    chk(egr == 7, "egress port carried from the rule");

    k.dport = 80;
    chk(dp_classify(&t, &k, &rid, NULL) == FP_INSPECT_W && rid == 102,
        "vsys1 tcp/80 -> INSPECT rule 102");

    k.dport = 443; k.vsys = 2;
    chk(dp_classify(&t, &k, &rid, NULL) == FP_DROP_W && rid == 105,
        "same 5-tuple in vsys2 -> DROP (vsys isolation)");

    k.vsys = 1; k.dst_ip = IP(192,0,2,66); k.dport = 8080;
    chk(dp_classify(&t, &k, &rid, NULL) == FP_DROP_W && rid == 103,
        "dst 192.0.2.66 -> DROP rule 103");

    k.dst_ip = IP(8,8,8,8); k.proto = DP_IPPROTO_UDP; k.dport = 53;
    chk(dp_classify(&t, &k, &rid, NULL) == FP_LOCAL_W && rid == 104,
        "udp/53 -> LOCAL rule 104");

    k.proto = DP_IPPROTO_TCP; k.dport = 9999; k.dst_ip = IP(1,1,1,1);
    chk(dp_classify(&t, &k, &rid, NULL) == DP_DECISION_NOMATCH,
        "no rule -> NOMATCH (caller applies default)");

    /* ---------- 3. parse ---------- */
    printf("\n[3] packet parse\n");
    uint8_t pkt[128];
    uint32_t len = mkpkt(pkt, IP(10,1,2,3), IP(93,184,216,34),
                         DP_IPPROTO_TCP, 40000, 443, 0, 0);
    struct dp_tuple pt;
    chk(dp_parse(pkt, len, 1, &pt) == DP_OK, "parse plain IPv4/TCP");
    chk(pt.src_ip == IP(10,1,2,3) && pt.dst_ip == IP(93,184,216,34),
        "addresses parsed to host order");
    chk(pt.sport == 40000 && pt.dport == 443, "ports parsed");
    chk(pt.tcp_flags == 0x02, "TCP flags parsed (SYN)");

    len = mkpkt(pkt, IP(10,1,2,3), IP(1,2,3,4), DP_IPPROTO_UDP, 1, 53, 1, 0);
    chk(dp_parse(pkt, len, 1, &pt) == DP_OK && pt.dport == 53,
        "802.1Q tagged frame parsed");
    uint8_t arp[64];
    memset(arp, 0, sizeof(arp));
    arp[12] = 0x08; arp[13] = 0x06;          /* ARP */
    chk(dp_parse(arp, 60, 1, &pt) == DP_ERR_NOTIP, "non-IPv4 reported");
    chk(dp_parse(pkt, 10, 1, &pt) == DP_ERR_SHORT, "runt rejected");

    /* ---------- 4. flow cache ---------- */
    printf("\n[4] flow cache (bidirectional normalization)\n");
    struct dp_flow_table ft;
    chk(dp_flow_init(&ft, 1024) == DP_OK, "flow table init");
    struct dp_tuple fwd = { IP(10,1,2,3), IP(5,6,7,8), 1234, 443,
                            DP_IPPROTO_TCP, 1, 0, 0 };
    struct dp_tuple rev = { IP(5,6,7,8), IP(10,1,2,3), 443, 1234,
                            DP_IPPROTO_TCP, 1, 0, 0 };
    struct dp_flow_key kf, kr;
    dp_flow_key_from_tuple(&kf, &fwd);
    dp_flow_key_from_tuple(&kr, &rev);
    chk(memcmp(&kf, &kr, sizeof(kf)) == 0,
        "forward and return direction map to ONE key");
    struct dp_flow_ent *e = dp_flow_insert(&ft, &kf);
    chk(e != NULL, "insert");
    e->verdict = FP_V_ALLOW_W; e->rule_id = 101;
    chk(dp_flow_lookup(&ft, &kr) == e, "return direction hits the same entry");
    struct dp_tuple other = fwd; other.vsys = 2;
    dp_flow_key_from_tuple(&kr, &other);
    chk(dp_flow_lookup(&ft, &kr) == NULL, "different vsys does not alias");
    dp_flow_flush(&ft);
    chk(ft.count == 0 && dp_flow_lookup(&ft, &kf) == NULL, "flush clears");
    dp_flow_fini(&ft);

    /* ---------- 5. shared region + rings ---------- */
    printf("\n[5] shared region, bank activation, command ring\n");
    size_t rsz = FFN_DP_OFF_BANK0 + 65536;
    uint8_t *region = (uint8_t *)calloc(1, rsz);
    struct dp_ctx ctx;
    struct sim_io sim;
    memset(&sim, 0, sizeof(sim));
    chk(dp_init(&ctx, &SIM_IO, &sim, 4096) == DP_OK, "dp_init");
    chk(ctx.default_decision == FP_DROP_W, "default decision is DROP (fail closed)");
    chk(dp_region_attach(&ctx, region, rsz, 1) == DP_OK, "region attach + handshake");
    chk(ffn_dp_hdr_valid(region), "region header magic/version valid");
    chk(dp_get_state(&ctx) == DP_STATE_HANDSHAKE, "state = HANDSHAKE");

    uint8_t junk[8] = {0};
    memcpy(region, junk, 8);
    chk(dp_region_attach(&ctx, region, rsz, 0) == DP_ERR_HANDSHAKE,
        "corrupt header fails the handshake (fail closed)");
    dp_region_attach(&ctx, region, rsz, 1);

    memcpy(region + FFN_DP_OFF_BANK0, polbin, polsz);
    void *cmd = region + FFN_DP_OFF_CMD_RING;
    void *evt = region + FFN_DP_OFF_EVT_RING;
    chk(ffn_dp_ring_push(cmd, DP_CMD_PING, 0xABCD, 0, 0) == 0, "push PING");
    chk(ffn_dp_ring_push(cmd, DP_CMD_SET_BANK, 0, 0, 0) == 0, "push SET_BANK 0");
    chk(dp_service_commands(&ctx) == 2, "DP handled 2 commands");
    chk(ctx.tables.policy_n == nrows, "bank activation loaded the tables");
    chk(dp_get_state(&ctx) == DP_STATE_READY, "state = READY after bank load");

    uint16_t op; uint64_t a0, a1, a2;
    chk(ffn_dp_ring_pop(evt, &op, &a0, &a1, &a2) && op == DP_EVT_PONG &&
        a0 == 0xABCD, "PONG event with echoed cookie");
    chk(ffn_dp_ring_pop(evt, &op, &a0, &a1, &a2) && op == DP_EVT_READY &&
        a1 == nrows, "READY event reports row count");
    chk(ffn_dp_ring_pop(evt, &op, &a0, &a1, &a2) == 0, "event ring drained");

    uint64_t hb = ld_le64(((struct ffn_dp_hdr_raw *)region)->dp_heartbeat);
    dp_heartbeat(&ctx);
    chk(ld_le64(((struct ffn_dp_hdr_raw *)region)->dp_heartbeat) == hb + 1,
        "heartbeat increments in the shared header");

    /* bad bank index must be refused */
    chk(dp_activate_bank(&ctx, 5) == DP_ERR_BANK, "invalid bank refused");

    /* ---------- 6. end-to-end forwarding ---------- */
    printf("\n[6] end-to-end packet processing\n");
    struct dp_result res;
    len = mkpkt(pkt, IP(10,1,2,3), IP(93,184,216,34), DP_IPPROTO_TCP,
                40000, 443, 0, 0);
    chk(dp_process(&ctx, pkt, len, 1, &res) == DP_OK &&
        res.decision == FP_FORWARD_W && res.rule_id == 101 && !res.from_cache,
        "first packet: classified FORWARD (cache miss)");
    chk(dp_process(&ctx, pkt, len, 1, &res) == DP_OK &&
        res.decision == FP_FORWARD_W && res.from_cache,
        "second packet: served from the flow cache");

    len = mkpkt(pkt, IP(93,184,216,34), IP(10,1,2,3), DP_IPPROTO_TCP,
                443, 40000, 0, 0);
    chk(dp_process(&ctx, pkt, len, 1, &res) == DP_OK &&
        res.decision == FP_FORWARD_W && res.from_cache,
        "return traffic hits the same cached flow");

    len = mkpkt(pkt, IP(10,9,9,9), IP(192,0,2,66), DP_IPPROTO_TCP,
                1111, 8080, 0, 0);
    chk(dp_process(&ctx, pkt, len, 1, &res) == DP_OK &&
        res.decision == FP_DROP_W && res.rule_id == 103,
        "blocked destination dropped");

    len = mkpkt(pkt, IP(10,1,2,3), IP(93,184,216,34), DP_IPPROTO_TCP,
                40001, 9999, 0, 0);
    chk(dp_process(&ctx, pkt, len, 1, &res) == DP_OK &&
        res.decision == FP_DROP_W,
        "unmatched traffic hits the DROP default (fail closed)");

    /* policy change must invalidate the cache */
    printf("\n[7] policy reload invalidates cached verdicts\n");
    struct trow rows2[] = {
      { IP(10,1,0,0), IP(255,255,0,0), 0, 0, 0,65535, 443,443,
        DP_IPPROTO_TCP, 1, FP_DROP_W, 0, DP_EGRESS_NONE, 201 },
    };
    polsz = build_policy_bin(polbin, sizeof(polbin), rows2, 1);
    memcpy(region + FFN_DP_OFF_BANK0, polbin, polsz);
    chk(dp_activate_bank(&ctx, 0) == DP_OK, "bank reactivated with new policy");
    chk(ctx.flows.count == 0, "flow cache flushed on policy change");
    len = mkpkt(pkt, IP(10,1,2,3), IP(93,184,216,34), DP_IPPROTO_TCP,
                40000, 443, 0, 0);
    chk(dp_process(&ctx, pkt, len, 1, &res) == DP_OK &&
        res.decision == FP_DROP_W && res.rule_id == 201,
        "previously-allowed flow now DROPs under the new policy");

    /* ---------- 8. poll loop through the sim backend ---------- */
    printf("\n[8] dp_poll_once through the I/O backend\n");
    polsz = build_policy_bin(polbin, sizeof(polbin), rows, nrows);
    memcpy(region + FFN_DP_OFF_BANK0, polbin, polsz);
    dp_activate_bank(&ctx, 0);
    memset(&sim, 0, sizeof(sim));
    len = mkpkt(pkt, IP(10,1,2,3), IP(93,184,216,34), DP_IPPROTO_TCP,
                40000, 443, 0, 0);
    sim_push(&sim, pkt, len, 1);                       /* -> forward */
    len = mkpkt(pkt, IP(10,1,2,3), IP(93,184,216,34), DP_IPPROTO_TCP,
                40002, 80, 0, 0);
    sim_push(&sim, pkt, len, 1);                       /* -> inspect (tx too) */
    len = mkpkt(pkt, IP(10,9,9,9), IP(192,0,2,66), DP_IPPROTO_TCP,
                1, 1, 0, 0);
    sim_push(&sim, pkt, len, 1);                       /* -> drop */
    len = mkpkt(pkt, IP(10,1,2,3), IP(8,8,8,8), DP_IPPROTO_UDP, 5, 53, 0, 0);
    sim_push(&sim, pkt, len, 1);                       /* -> local */
    int n = dp_poll_once(&ctx);
    chk(n == 4, "polled 4 packets");
    chk(sim.txed == 2, "2 transmitted (forward + inspect)");
    chk(sim.localed == 1, "1 delivered locally");
    chk(ctx.stat_drop >= 1, "drop counted");
    chk(ctx.stat_rx == 4, "rx counter");

    printf("\ncounters: rx=%llu tx=%llu fwd=%llu insp=%llu drop=%llu local=%llu "
           "cache_hit=%llu classify=%llu\n",
           (unsigned long long)ctx.stat_rx, (unsigned long long)ctx.stat_tx,
           (unsigned long long)ctx.stat_forward, (unsigned long long)ctx.stat_inspect,
           (unsigned long long)ctx.stat_drop, (unsigned long long)ctx.stat_local,
           (unsigned long long)ctx.stat_cache_hit,
           (unsigned long long)ctx.stat_classify);

    dp_fini(&ctx);
    free(region);
    printf("\n==== ffn_dp_oct test: %d failed ====\n", g_fail);
    return g_fail ? 1 : 0;
}
