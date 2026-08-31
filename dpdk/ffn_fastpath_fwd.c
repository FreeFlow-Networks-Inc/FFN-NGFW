/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_fastpath_fwd -- FFN NGFW host DPDK fast path (DPDK-primary data plane).
 *
 * Pass-2 rework (REWORK_CONTRACT §2, §5, §10) against DPDK 22.11:
 *
 *   1. Multi-lcore, symmetric queue-pair workers. The primary launches one
 *      worker per data lcore (RTE_LCORE_FOREACH_WORKER + rte_eal_remote_launch);
 *      each worker owns ONE rx/tx queue index across every port (RSS spreads
 *      flows to queues) and a private rte_hash flow table -- no cross-lcore
 *      locking on the hot path.
 *
 *   2. VSYS-aware. Every packet carries a numeric vsys tag; the data plane reads
 *      it from the mbuf flow-director MARK (rte_flow MARK / kernel meta mark ->
 *      RTE_MBUF_F_RX_FDIR_ID + hash.fdir.hi) into flow_key.vsys. The flow-table
 *      key includes vsys and classify() matches policy rows per vsys (0 = any).
 *
 *   3. DPDK-primary. Pure software by default: policy classify + rte_hash flow
 *      cache + Hyperscan content scan + verdict enforce (forward / drop /
 *      TCP-RST). FPGA punt (FP_PUNT_FPGA) is gated behind an explicit --offload
 *      flag; without it, a "punt" rule degrades to software INSPECT.
 *
 *   4. Real policy.bin. Rows (fp_policy_ent, incl. per-row vsys) are matched in
 *      order; INSPECT is the default ONLY when no rule matches.
 *
 *   5. Shared-memory model/table updates + telemetry. The management plane
 *      stages hot-swappable tables (policy/patmeta/avhash/strings) and engine
 *      blobs (AC/DFA Hyperscan DB, ML tree) into a double-buffered dpmem region
 *      (ffn_dpmem.h, owned by DP-MP). The data plane flips to the new bank via
 *      the active_bank index and re-points its tables lock-free; it publishes
 *      per-engine EngineTelemetry counters back into the telemetry memzone.
 *
 *   build:  make            (pkg-config libdpdk [+ libhs])
 *   run:    ./ffn_fastpath_fwd -l 1-4 -a 0000:05:00.0 -a 0000:05:00.1 \
 *                              -- --tables /var/lib/ffn-ngfw/fastpath [--offload]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_launch.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_memzone.h>
#include <rte_malloc.h>

#ifdef HAVE_HYPERSCAN
#include <hs/hs.h>
#endif

#include "ffn_fastpath.h"

/* ffn_dpmem.h is owned by DP-MP (REWORK_CONTRACT §5/§10); this file DEPENDS on
 * its contract but never defines it. Required contract:
 *
 *   struct ffn_dpmem_hdr {   // header at the base of the dpmem region
 *       uint32_t magic;      // FFN_DPMEM_MAGIC
 *       uint32_t version;    // FFN_DPMEM_VERSION
 *       uint32_t active_bank;// 0 or 1  (double-buffer index, updated by MP)
 *       ...
 *       uint64_t bank_off[2];// byte offset of each bank from the region base
 *       uint64_t bank_size;  // usable bytes per bank
 *   };
 *   FFN_DPMEM_MEMZONE  -- rte_memzone name of the region
 *   FFN_DPMEM_MAGIC / FFN_DPMEM_VERSION
 *   FFN_DPMEM_TELEM_MEMZONE -- rte_memzone name of the DP->MP telemetry array
 *
 * If DP-MP's header is absent at build time, define FFN_NO_DPMEM to compile a
 * pure static-table build (no hot swap / no telemetry publish). */
#ifndef FFN_NO_DPMEM
#include "ffn_dpmem.h"
#endif

/* Fallbacks so this file still compiles if DP-MP only ships the struct and not
 * the well-known names (documented assumption; box build should not need these). */
#ifndef FFN_DPMEM_MEMZONE
#define FFN_DPMEM_MEMZONE        "ffn_dpmem"
#endif
#ifndef FFN_DPMEM_TELEM_MEMZONE
#define FFN_DPMEM_TELEM_MEMZONE  "ffn_dpmem_telem"
#endif

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS    16383
#define MBUF_CACHE   256
#define BURST        32
#define FLOW_ENTRIES (1 << 20)

static volatile int g_stop;
/* Under the ffn_dpdk_mp zygote, the primary owns the stop flag and passes it via
 * ffn_dp_worker_args.stop; the shared worker loop honours it in addition to the
 * standalone g_stop. NULL in the standalone build (loop reduces to !g_stop). */
static volatile int *g_ext_stop;
static struct rte_mempool *g_pool;
static char *g_tables_dir = "/var/lib/ffn-ngfw/fastpath";
static int   g_offload;                    /* --offload: enable FP_PUNT_FPGA   */

/* ------------------------------------------------------------------ tables
 * Double-buffered table view. Workers read the pointer set indexed by the
 * active generation (acquire-load); the main lcore fills the inactive buffer
 * from a new dpmem bank and flips the index (release-store). Lock-free. */
static struct fp_tables g_tab_buf[2];
static volatile uint32_t g_tab_gen;        /* 0/1: which g_tab_buf is live     */

static inline const struct fp_tables *active_tables(void)
{
    uint32_t g = __atomic_load_n(&g_tab_gen, __ATOMIC_ACQUIRE);
    return &g_tab_buf[g & 1];
}

#ifdef HAVE_HYPERSCAN
/* Block-mode content DB, hot-swappable from dpmem. Workers acquire-load the
 * pointer; the compiled DB is immutable, only the pointer flips. */
static hs_database_t *volatile g_block_db;
#endif

/* ------------------------------------------------------------------ dpmem */
#ifndef FFN_NO_DPMEM
static const struct rte_memzone *g_dpmem_mz;
static const struct rte_memzone *g_telem_mz;
static uint32_t g_dpmem_last_bank = (uint32_t)-1;   /* bank we last loaded    */

/* Scan a dpmem bank (a concatenation of fp_hdr-prefixed tables laid out by the
 * MP) for the table whose 4-byte magic matches. Returns a pointer just past the
 * header, or NULL. *count / *record_size receive the header fields. */
static const void *bank_find(const uint8_t *base, size_t size, const char *magic,
                             uint32_t *count, uint32_t *record_size)
{
    size_t off = 0;
    while (off + FP_HDR_SIZE <= size) {
        const struct fp_hdr *h = (const struct fp_hdr *)(base + off);
        /* stop at an unwritten / zeroed region */
        int printable = h->magic[0] >= 'A' && h->magic[0] <= 'Z';
        if (!printable || h->version != 1)
            break;
        size_t payload = (size_t)h->entry_count * h->record_size;
        if (h->table_type == FP_T_STRINGS)     /* strings: recsz 1, count=bytes */
            payload = h->entry_count;
        if (off + FP_HDR_SIZE + payload > size)
            break;
        if (memcmp(h->magic, magic, 4) == 0) {
            if (count)       *count       = h->entry_count;
            if (record_size) *record_size = h->record_size;
            return base + off + FP_HDR_SIZE;
        }
        off += FP_HDR_SIZE + payload;
    }
    return NULL;
}
#endif /* !FFN_NO_DPMEM */

/* mmap a file-backed fast-path table (boot-time static load path). */
static const void *map_table(const char *dir, const char *fn, const char *magic,
                             uint32_t *count, uint32_t *record_size)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, fn);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return NULL; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)FP_HDR_SIZE) { close(fd); return NULL; }
    void *base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror("mmap"); return NULL; }
    const struct fp_hdr *h = base;
    if (memcmp(h->magic, magic, 4) != 0 || h->version != 1) {
        fprintf(stderr, "%s: bad magic/version\n", fn); return NULL;
    }
    if (count)       *count       = h->entry_count;
    if (record_size) *record_size = h->record_size;
    return (const uint8_t *)base + FP_HDR_SIZE;
}

static int load_tables_from_files(struct fp_tables *t, const char *dir)
{
    uint32_t rs;
    memset(t, 0, sizeof *t);
    t->policy = map_table(dir, "ffn_fastpath.policy.bin", FP_MAGIC_POLICY,
                          &t->policy_n, &rs);
    if (t->policy && rs != FP_POLICY_SIZE) { fprintf(stderr, "policy recsz %u\n", rs); return -1; }
    t->patmeta = map_table(dir, "ffn_fastpath.patmeta.bin", FP_MAGIC_PATMETA,
                           &t->patmeta_n, &rs);
    if (t->patmeta && rs != FP_PATMETA_SIZE) { fprintf(stderr, "patmeta recsz %u != %d\n", rs, FP_PATMETA_SIZE); return -1; }
    t->avhash = map_table(dir, "ffn_fastpath.avhash.bin", FP_MAGIC_AVHASH,
                          &t->avhash_slots, &rs);
    t->strings = map_table(dir, "ffn_fastpath.strings.bin", FP_MAGIC_STRINGS,
                           &t->strings_n, &rs);
    printf("tables(file): policy=%u patmeta=%u avhash_slots=%u strings=%uB\n",
           t->policy_n, t->patmeta_n, t->avhash_slots, t->strings_n);
    return (t->patmeta || t->policy) ? 0 : -1;
}

#ifdef HAVE_HYPERSCAN
static hs_database_t *deserialize_block(const char *buf, size_t len)
{
    hs_database_t *db = NULL;
    if (hs_deserialize_database(buf, len, &db) != HS_SUCCESS) {
        fprintf(stderr, "hs_deserialize failed\n"); return NULL;
    }
    return db;
}

static int load_hsdb_from_file(const char *dir)
{
    char path[512];
    snprintf(path, sizeof path, "%s/ffn_fastpath.block.hsdb", dir);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "no %s (%s)\n", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    char *buf = malloc(st.st_size);
    if (!buf || read(fd, buf, st.st_size) != st.st_size) { close(fd); free(buf); return -1; }
    close(fd);
    hs_database_t *db = deserialize_block(buf, st.st_size);
    free(buf);
    if (!db) return -1;
    __atomic_store_n(&g_block_db, db, __ATOMIC_RELEASE);
    printf("hyperscan: block db loaded (hs %s)\n", hs_version());
    return 0;
}
#endif /* HAVE_HYPERSCAN */

/* ------------------------------------------------------------------ per-lcore */
struct lcore_ctx {
    unsigned lcore;
    uint16_t qid;                 /* rx/tx queue index this worker owns        */
    struct rte_hash *flows;
#ifdef HAVE_HYPERSCAN
    hs_scratch_t *scratch;
#endif
    /* engine-attributed counters (aggregated into telemetry) */
    uint64_t rx, tx, dropped, forwarded;
    uint64_t classify_hits;       /* policy rows that matched (tcam)           */
    uint64_t inspected, threats;  /* dpi_regex                                 */
    uint64_t tcp_pkts, udp_pkts;  /* tcp_reassembly / udp_processor            */
    uint64_t punted;              /* FP_PUNT_FPGA (only when --offload)        */
    uint64_t rst_sent, rst_fail;  /* TCP-RST verdict path                      */
    uint64_t flow_events;         /* new flows tracked (flow_exporter)         */
} __rte_cache_aligned;
static struct lcore_ctx g_ctx[RTE_MAX_LCORE];

/* ------------------------------------------------------------------ flow tbl */
static struct rte_hash *make_flow_table(unsigned lcore)
{
    char name[32]; snprintf(name, sizeof name, "flows_%u", lcore);
    struct rte_hash_parameters p = {
        .name = name, .entries = FLOW_ENTRIES, .key_len = sizeof(struct flow_key),
        .hash_func = rte_hash_crc, .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
    };
    return rte_hash_create(&p);
}

static void make_key(struct flow_key *k, uint8_t vsys, uint32_t sip, uint32_t dip,
                     uint16_t sp, uint16_t dp, uint8_t proto)
{
    memset(k, 0, sizeof *k);
    if (sip <= dip) { k->ip_a = sip; k->ip_b = dip; k->port_a = sp; k->port_b = dp; }
    else            { k->ip_a = dip; k->ip_b = sip; k->port_a = dp; k->port_b = sp; }
    k->proto = proto;
    k->vsys  = vsys;              /* flows never alias across virtual systems  */
}

/* Read the per-packet vsys tag from the mbuf flow-director mark. rte_flow's
 * MARK action (or the kernel meta-mark carried across the MP<->DP path) lands
 * in hash.fdir.hi with RTE_MBUF_F_RX_FDIR_ID set. 0 = shared/untagged. */
static inline uint8_t mbuf_vsys(const struct rte_mbuf *m)
{
    if (m->ol_flags & RTE_MBUF_F_RX_FDIR_ID)
        return (uint8_t)(m->hash.fdir.hi & 0xff);
    return 0;
}

/* linear per-vsys policy classify (rte_acl is the scale path; linear for v1).
 * A rule with vsys==0 matches any vsys; otherwise vsys must equal the packet's.
 * Returns a classify decision (FP_FORWARD/INSPECT/PUNT_FPGA/DROP/LOCAL);
 * INSPECT is returned ONLY when no rule matches. */
static int classify(const struct fp_tables *t, uint8_t vsys,
                    uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
                    uint8_t proto, uint16_t *rule_id)
{
    for (uint32_t i = 0; i < t->policy_n; i++) {
        const struct fp_policy_ent *r = &t->policy[i];
        if (r->vsys && r->vsys != vsys) continue;          /* 0 = any vsys     */
        if (r->proto && r->proto != proto) continue;
        if (r->src_mask && (sip & r->src_mask) != (r->src_ip & r->src_mask)) continue;
        if (r->dst_mask && (dip & r->dst_mask) != (r->dst_ip & r->dst_mask)) continue;
        if (sp < r->sport_lo || sp > r->sport_hi) continue;
        if (dp < r->dport_lo || dp > r->dport_hi) continue;
        if (rule_id) *rule_id = r->rule_id;
        return r->action;
    }
    if (rule_id) *rule_id = 0;
    return FP_INSPECT;                                     /* default: inspect */
}

#ifdef HAVE_HYPERSCAN
struct scan_ctx { int matched; uint8_t action; uint16_t sid; const struct fp_tables *t; };
static int on_match(unsigned id, unsigned long long from, unsigned long long to,
                    unsigned flags, void *c)
{
    (void)from; (void)to; (void)flags;
    struct scan_ctx *s = c;
    if (id < s->t->patmeta_n) {
        const struct fp_patmeta_ent *m = &s->t->patmeta[id];
        if (m->host_confirm) return 0;          /* prefilter-only; host confirms */
        s->matched = 1;
        if (m->action > s->action) { s->action = m->action; s->sid = m->src_sid; }
    }
    return 0;
}
#endif

/* ------------------------------------------------------------------ TCP-RST
 * Craft a reflected RST toward the sender (spoofing the destination) into a
 * fresh mbuf and TX it out the given queue. TCP-only. Per RFC793: if the
 * offending segment carried ACK, RST.seq = seg.ack (no ACK flag); else RST.seq
 * = 0, RST.ack = seg.seq + seglen, ACK flag set. */
static void send_tcp_rst(struct lcore_ctx *c, uint16_t tx_port, uint16_t qid,
                         const struct rte_ether_hdr *eth,
                         const struct rte_ipv4_hdr *ip,
                         const struct rte_tcp_hdr *tcp, uint32_t seglen)
{
    struct rte_mbuf *r = rte_pktmbuf_alloc(g_pool);
    if (!r) { c->rst_fail++; return; }
    const uint32_t frame = sizeof(struct rte_ether_hdr) +
                           sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
    char *p = rte_pktmbuf_append(r, frame);
    if (!p) { rte_pktmbuf_free(r); c->rst_fail++; return; }

    struct rte_ether_hdr *e2 = (struct rte_ether_hdr *)p;
    struct rte_ipv4_hdr  *i2 = (struct rte_ipv4_hdr *)(e2 + 1);
    struct rte_tcp_hdr   *t2 = (struct rte_tcp_hdr *)(i2 + 1);

    rte_ether_addr_copy(&eth->src_addr, &e2->dst_addr);   /* back to sender    */
    rte_ether_addr_copy(&eth->dst_addr, &e2->src_addr);
    e2->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    i2->version_ihl   = 0x45;
    i2->type_of_service = 0;
    i2->total_length  = rte_cpu_to_be_16(sizeof(*i2) + sizeof(*t2));
    i2->packet_id     = 0;
    i2->fragment_offset = 0;
    i2->time_to_live  = 64;
    i2->next_proto_id = IPPROTO_TCP;
    i2->src_addr      = ip->dst_addr;                     /* reflect L3        */
    i2->dst_addr      = ip->src_addr;
    i2->hdr_checksum  = 0;

    t2->src_port = tcp->dst_port;                         /* reflect L4        */
    t2->dst_port = tcp->src_port;
    if (tcp->tcp_flags & RTE_TCP_ACK_FLAG) {
        t2->sent_seq  = tcp->recv_ack;
        t2->recv_ack  = 0;
        t2->tcp_flags = RTE_TCP_RST_FLAG;
    } else {
        t2->sent_seq  = 0;
        t2->recv_ack  = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->sent_seq) + seglen);
        t2->tcp_flags = RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG;
    }
    t2->data_off = (uint8_t)((sizeof(*t2) / 4) << 4);
    t2->rx_win   = 0;
    t2->cksum    = 0;
    t2->tcp_urp  = 0;

    i2->hdr_checksum = rte_ipv4_cksum(i2);
    t2->cksum        = rte_ipv4_udptcp_cksum(i2, t2);

    if (rte_eth_tx_burst(tx_port, qid, &r, 1) < 1) { rte_pktmbuf_free(r); c->rst_fail++; }
    else c->rst_sent++;
}

/* ------------------------------------------------------------------ worker */
static int worker(void *arg)
{
    struct lcore_ctx *c = arg;
    struct rte_mbuf *bufs[BURST];
    uint16_t nports = rte_eth_dev_count_avail();

    printf("lcore %u: worker on queue %u (%u port(s), offload=%s)\n",
           c->lcore, c->qid, nports, g_offload ? "on" : "off");

    while (!g_stop && !(g_ext_stop && *g_ext_stop)) {
        uint16_t idle = 1;
        uint16_t rx_port;
        RTE_ETH_FOREACH_DEV(rx_port) {
            uint16_t n = rte_eth_rx_burst(rx_port, c->qid, bufs, BURST);
            if (n == 0) continue;
            idle = 0;
            c->rx += n;
            uint16_t out_port = (nports > 1) ? (uint16_t)(rx_port ^ 1) : rx_port;
            const struct fp_tables *t = active_tables();

            for (uint16_t i = 0; i < n; i++) {
                struct rte_mbuf *m = bufs[i];
                int verdict = FP_FORWARD;
                int is_tcp = 0;
                struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                struct rte_ipv4_hdr  *ip  = NULL;
                struct rte_tcp_hdr   *tcp = NULL;
                uint32_t seglen = 0;

                if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                    ip = (struct rte_ipv4_hdr *)(eth + 1);
                    uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
                    uint8_t proto = ip->next_proto_id;
                    uint8_t vsys = mbuf_vsys(m);
                    uint16_t sp = 0, dp = 0;
                    const uint8_t *payload = NULL; uint32_t plen = 0;
                    uint8_t *l4 = (uint8_t *)ip + ihl;

                    if (proto == IPPROTO_TCP) {
                        tcp = (struct rte_tcp_hdr *)l4;
                        is_tcp = 1; c->tcp_pkts++;
                        sp = rte_be_to_cpu_16(tcp->src_port);
                        dp = rte_be_to_cpu_16(tcp->dst_port);
                        uint8_t doff = (tcp->data_off >> 4) * 4;
                        payload = l4 + doff;
                    } else if (proto == IPPROTO_UDP) {
                        struct rte_udp_hdr *u = (struct rte_udp_hdr *)l4;
                        c->udp_pkts++;
                        sp = rte_be_to_cpu_16(u->src_port);
                        dp = rte_be_to_cpu_16(u->dst_port);
                        payload = l4 + sizeof(*u);
                    }
                    uint32_t sip = rte_be_to_cpu_32(ip->src_addr);
                    uint32_t dip = rte_be_to_cpu_32(ip->dst_addr);
                    uint8_t *pkt_end = rte_pktmbuf_mtod(m, uint8_t *) + rte_pktmbuf_pkt_len(m);
                    if (payload && payload < pkt_end) plen = (uint32_t)(pkt_end - payload);
                    seglen = plen;
                    if (is_tcp && (tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG)))
                        seglen += 1;                 /* SYN/FIN consume a seqno */

                    struct flow_key k; make_key(&k, vsys, sip, dip, sp, dp, proto);
                    struct flow_state *fs = NULL;
                    if (rte_hash_lookup_data(c->flows, &k, (void **)&fs) < 0) {
                        fs = rte_zmalloc(NULL, sizeof *fs, 0);
                        if (fs) { rte_hash_add_key_data(c->flows, &k, fs); c->flow_events++; }
                    }
                    if (fs) { fs->pkts++; fs->bytes += rte_pktmbuf_pkt_len(m); }

                    if (fs && (fs->verdict == FP_V_DROP || fs->verdict == FP_V_RESET)) {
                        /* convicted flow: keep tearing it down (re-RST TCP) */
                        verdict = FP_DROP;
                        if (fs->verdict == FP_V_RESET && is_tcp)
                            send_tcp_rst(c, out_port, c->qid, eth, ip, tcp, seglen);
                    } else {
                        uint16_t rid = 0;
                        int dec = classify(t, vsys, sip, dip, sp, dp, proto, &rid);
                        if (rid) c->classify_hits++;
                        if (dec == FP_PUNT_FPGA && !g_offload)
                            dec = FP_INSPECT;            /* software-only path  */

                        if (dec == FP_DROP) {
                            verdict = FP_DROP;
                            if (fs) { fs->verdict = FP_V_DROP; fs->rule_id = rid; }
                        } else if (dec == FP_PUNT_FPGA) {
                            verdict = FP_PUNT_FPGA;      /* offload enabled     */
                        } else if (dec == FP_INSPECT && payload && plen) {
                            c->inspected++;
#ifdef HAVE_HYPERSCAN
                            hs_database_t *db = __atomic_load_n(&g_block_db, __ATOMIC_ACQUIRE);
                            struct scan_ctx sc = { 0, FP_ACT_ALERT, 0, t };
                            if (db)
                                hs_scan(db, (const char *)payload, plen, 0,
                                        c->scratch, on_match, &sc);
                            if (sc.matched && sc.action == FP_ACT_RESET) {
                                verdict = FP_DROP; c->threats++;
                                if (fs) { fs->verdict = FP_V_RESET; fs->rule_id = sc.sid; }
                                if (is_tcp) send_tcp_rst(c, out_port, c->qid, eth, ip, tcp, seglen);
                            } else if (sc.matched && sc.action == FP_ACT_DROP) {
                                verdict = FP_DROP; c->threats++;
                                if (fs) { fs->verdict = FP_V_DROP; fs->rule_id = sc.sid; }
                            } else {
                                verdict = FP_FORWARD;
                            }
#else
                            verdict = FP_FORWARD;
#endif
                        } else {
                            verdict = FP_FORWARD;
                        }
                    }
                }

                if (verdict == FP_DROP) {
                    rte_pktmbuf_free(m); c->dropped++;
                } else if (verdict == FP_PUNT_FPGA) {
                    /* offload: hand to the FPGA-facing port (peer of ingress) */
                    if (rte_eth_tx_burst(out_port, c->qid, &m, 1) < 1) {
                        rte_pktmbuf_free(m); c->dropped++;
                    } else { c->tx++; c->punted++; }
                } else {
                    if (rte_eth_tx_burst(out_port, c->qid, &m, 1) < 1) {
                        rte_pktmbuf_free(m); c->dropped++;
                    } else { c->tx++; c->forwarded++; }
                }
            }
        }
        if (idle) rte_delay_us_block(50);
    }
    return 0;
}

/* ------------------------------------------------------------------ ports */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .mq_mode = RTE_ETH_MQ_RX_RSS },
    .rx_adv_conf = {
        .rss_conf = { .rss_key = NULL,
                      .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP },
    },
    .txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE },
};

static int port_init(uint16_t port, uint16_t nb_queues)
{
    struct rte_eth_conf conf = port_conf_default;
    struct rte_eth_dev_info info;
    struct rte_eth_txconf txconf;
    if (rte_eth_dev_info_get(port, &info) != 0) return -1;

    if (nb_queues > info.max_rx_queues) nb_queues = info.max_rx_queues;
    if (nb_queues > info.max_tx_queues) nb_queues = info.max_tx_queues;
    if (nb_queues == 0) nb_queues = 1;

    conf.rx_adv_conf.rss_conf.rss_hf &= info.flow_type_rss_offloads;
    if (conf.rx_adv_conf.rss_conf.rss_hf == 0)
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;   /* single-queue vdevs      */
    if (info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    if (rte_eth_dev_configure(port, nb_queues, nb_queues, &conf) != 0) return -1;
    for (uint16_t q = 0; q < nb_queues; q++)
        if (rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port),
                                   NULL, g_pool) != 0) return -1;
    txconf = info.default_txconf;
    txconf.offloads = conf.txmode.offloads;
    for (uint16_t q = 0; q < nb_queues; q++)
        if (rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port),
                                   &txconf) != 0) return -1;
    if (rte_eth_dev_start(port) != 0) return -1;
    rte_eth_promiscuous_enable(port);
    printf("  port %u: %u rx/tx queue pair(s) up\n", port, nb_queues);
    return 0;
}

/* ------------------------------------------------------------------ dpmem swap */
#ifndef FFN_NO_DPMEM
static void dpmem_attach(void)
{
    g_dpmem_mz = rte_memzone_lookup(FFN_DPMEM_MEMZONE);
    if (!g_dpmem_mz) { printf("dpmem: region '%s' absent -> static tables only\n",
                              FFN_DPMEM_MEMZONE); return; }
    const struct ffn_dpmem_hdr *h = (const struct ffn_dpmem_hdr *)g_dpmem_mz->addr;
    if (h->magic != FFN_DPMEM_MAGIC) {
        printf("dpmem: bad magic 0x%08x -> ignoring\n", h->magic);
        g_dpmem_mz = NULL; return;
    }
    g_telem_mz = rte_memzone_lookup(FFN_DPMEM_TELEM_MEMZONE);
    printf("dpmem: attached region=%s ver=%u telem=%s\n",
           FFN_DPMEM_MEMZONE, h->version, g_telem_mz ? "yes" : "no");
}

/* If the MP advanced active_bank, load the new bank into the inactive table
 * buffer and flip the generation. Runs on the main lcore only. */
static void dpmem_refresh(void)
{
    if (!g_dpmem_mz) return;
    const struct ffn_dpmem_hdr *h = (const struct ffn_dpmem_hdr *)g_dpmem_mz->addr;
    uint32_t bank = __atomic_load_n(&h->active_bank, __ATOMIC_ACQUIRE);
    if (bank == g_dpmem_last_bank || bank > 1) return;

    const uint8_t *base = (const uint8_t *)g_dpmem_mz->addr + h->bank_off[bank];
    size_t size = h->bank_size;

    uint32_t gen = __atomic_load_n(&g_tab_gen, __ATOMIC_ACQUIRE);
    struct fp_tables *nt = &g_tab_buf[(gen ^ 1) & 1];
    memset(nt, 0, sizeof *nt);
    uint32_t rs;
    nt->policy  = bank_find(base, size, FP_MAGIC_POLICY,  &nt->policy_n,     &rs);
    nt->patmeta = bank_find(base, size, FP_MAGIC_PATMETA, &nt->patmeta_n,    &rs);
    nt->avhash  = bank_find(base, size, FP_MAGIC_AVHASH,  &nt->avhash_slots, &rs);
    nt->strings = bank_find(base, size, FP_MAGIC_STRINGS, &nt->strings_n,    &rs);
    if (!nt->policy && !nt->patmeta) {   /* empty bank: keep current tables    */
        printf("dpmem: bank %u carries no policy/patmeta -> keep current\n", bank);
    }

#ifdef HAVE_HYPERSCAN
    uint32_t hb_count, hb_rs;
    const void *hb = bank_find(base, size, FP_MAGIC_HSBLOCK, &hb_count, &hb_rs);
    if (hb) {   /* hot-swap the AC/DFA (Hyperscan) block DB */
        hs_database_t *db = deserialize_block((const char *)hb, (size_t)hb_count * hb_rs);
        if (db) {
            hs_database_t *old = __atomic_exchange_n(&g_block_db, db, __ATOMIC_ACQ_REL);
            if (old) hs_free_database(old);
            printf("dpmem: swapped Hyperscan block DB from bank %u\n", bank);
        }
    }
#endif
    /* ML tree blob (FP_MAGIC_MLTREE) is located here and handed to the inline
     * ML scorer when that hook lands; opaque to the fast path for now. */

    __atomic_store_n(&g_tab_gen, gen ^ 1, __ATOMIC_RELEASE);
    g_dpmem_last_bank = bank;
    printf("dpmem: activated bank %u (policy=%u patmeta=%u avhash=%u)\n",
           bank, nt->policy_n, nt->patmeta_n, nt->avhash_slots);
}

static void publish_telemetry(void)
{
    if (!g_telem_mz) return;
    struct fp_engine_stat *slot = (struct fp_engine_stat *)g_telem_mz->addr;
    struct { const char *name; uint64_t pk, mt, dr; } agg[FP_ENG_COUNT];
    static const char *names[FP_ENG_COUNT] = {
        "tcam_lookup", "dpi_regex", "tcp_reassembly", "udp_processor", "flow_exporter"
    };
    memset(agg, 0, sizeof agg);
    unsigned lc;
    RTE_LCORE_FOREACH_WORKER(lc) {
        struct lcore_ctx *c = &g_ctx[lc];
        agg[FP_ENG_TCAM].pk        += c->rx;         agg[FP_ENG_TCAM].mt += c->classify_hits;
        agg[FP_ENG_DPI_REGEX].pk   += c->inspected;  agg[FP_ENG_DPI_REGEX].mt += c->threats;
        agg[FP_ENG_DPI_REGEX].dr   += c->threats;
        agg[FP_ENG_TCP_REASM].pk   += c->tcp_pkts;   agg[FP_ENG_TCP_REASM].dr += c->rst_sent;
        agg[FP_ENG_UDP_PROC].pk    += c->udp_pkts;
        agg[FP_ENG_FLOW_EXPORT].pk += c->flow_events;
        agg[FP_ENG_TCAM].dr        += c->dropped;
    }
    for (int e = 0; e < FP_ENG_COUNT; e++) {
        strncpy(slot[e].engine, names[e], sizeof slot[e].engine - 1);
        slot[e].engine[sizeof slot[e].engine - 1] = 0;
        __atomic_store_n(&slot[e].packets, agg[e].pk, __ATOMIC_RELEASE);
        __atomic_store_n(&slot[e].matches, agg[e].mt, __ATOMIC_RELEASE);
        __atomic_store_n(&slot[e].drops,   agg[e].dr, __ATOMIC_RELEASE);
        slot[e].mode = 0;   /* host */
    }
}
#endif /* !FFN_NO_DPMEM */

static void handle_sig(int s) { (void)s; g_stop = 1; }

static void print_stats(void)
{
    uint64_t rx = 0, tx = 0, dr = 0, in = 0, th = 0, rst = 0, pu = 0;
    unsigned lc;
    RTE_LCORE_FOREACH(lc) {
        rx += g_ctx[lc].rx; tx += g_ctx[lc].tx; dr += g_ctx[lc].dropped;
        in += g_ctx[lc].inspected; th += g_ctx[lc].threats;
        rst += g_ctx[lc].rst_sent; pu += g_ctx[lc].punted;
    }
    printf("\n=== ffn_fastpath_fwd stats ===\n");
    printf("  rx=%" PRIu64 " forwarded/punted=%" PRIu64 " dropped=%" PRIu64 "\n", rx, tx, dr);
    printf("  inspected=%" PRIu64 " THREATS=%" PRIu64 " rst_sent=%" PRIu64 " punted=%" PRIu64 "\n",
           in, th, rst, pu);
}

/* ------------------------------------------------------------ MP zygote worker
 * Strong ffn_dp_worker_run(): the real classify -> scan -> verdict RX/TX loop
 * for one lcore/queue under the ffn_dpdk_mp multi-process zygote. It OVERRIDES
 * the weak forward-only fallback that ffn_dpdk_mp.c used to link, so the actual
 * inspect worker runs in each forked secondary. Signature matches the
 * declaration in ffn_dpmem.h (const struct ffn_dp_worker_args *).
 *
 * Compiled in BOTH binaries: extern (never unused-warns) and only referenced by
 * the MP build. Requires the dpmem ABI (struct ffn_dp_worker_args), so it lives
 * under the same guard as the ffn_dpmem.h include. */
#ifndef FFN_NO_DPMEM
int ffn_dp_worker_run(const struct ffn_dp_worker_args *a)
{
    /* Each secondary is its own process (fork+execv), so g_tab_buf / g_block_db
     * are per-worker copies -- reuse the standalone pipeline with no locking. */
    struct lcore_ctx *c = &g_ctx[rte_lcore_id()];
    memset(c, 0, sizeof *c);
    c->lcore = rte_lcore_id();
    c->qid   = a->queue;

    g_pool     = (struct rte_mempool *)a->pool;  /* for TCP-RST mbuf alloc      */
    g_ext_stop = a->stop;                         /* honour the primary's stop  */

    /* Attach the shared region + load the active bank's tables (fp_hdr TLV
     * records) into this process's generation-0 buffer via the same lock-free
     * flip machinery the standalone path uses. */
    dpmem_attach();
    dpmem_refresh();

    c->flows = make_flow_table(c->lcore);
    if (!c->flows) {
        fprintf(stderr, "ffn_dp_worker_run: flow table create failed (worker %u)\n",
                a->worker_id);
        return -1;
    }
#ifdef HAVE_HYPERSCAN
    hs_alloc_scratch(__atomic_load_n(&g_block_db, __ATOMIC_ACQUIRE), &c->scratch);
#endif

    printf("ffn_dp_worker_run: worker %u -> port %u queue %u (active_bank=%u)\n",
           a->worker_id, a->port, a->queue, ffn_dpmem_active(a->dpmem));

    return worker(c);        /* runs until *a->stop (via g_ext_stop) */
}
#endif /* !FFN_NO_DPMEM */

#ifndef FFN_BUILD_MP
/* Standalone ffn-fastpath-fwd entry point. In the ffn-dpdk-mp build this TU is
 * compiled with -DFFN_BUILD_MP so ffn_dpdk_mp.c owns main() and drives the
 * exported ffn_dp_worker_run() above; guarding here resolves the double-main. */
int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");
    argc -= ret; argv += ret;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--tables") && i + 1 < argc) g_tables_dir = argv[++i];
        else if (!strcmp(argv[i], "--offload")) g_offload = 1;
    }

    signal(SIGINT, handle_sig); signal(SIGTERM, handle_sig);

    uint16_t nports = rte_eth_dev_count_avail();
    if (nports == 0) rte_exit(EXIT_FAILURE, "no ethdev ports (add a -a/--vdev)\n");
    g_pool = rte_pktmbuf_pool_create("ffn_pool", NUM_MBUFS, MBUF_CACHE, 0,
                                     RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!g_pool) rte_exit(EXIT_FAILURE, "mbuf pool failed\n");

    /* Boot-time static tables (the MP later hot-swaps via dpmem). Loaded into
     * generation 0; workers start reading it immediately. */
    if (load_tables_from_files(&g_tab_buf[0], g_tables_dir) < 0)
        rte_exit(EXIT_FAILURE, "fast-path tables not found in %s\n", g_tables_dir);
    g_tab_buf[1] = g_tab_buf[0];
    __atomic_store_n(&g_tab_gen, 0, __ATOMIC_RELEASE);
#ifdef HAVE_HYPERSCAN
    if (load_hsdb_from_file(g_tables_dir) < 0)
        rte_exit(EXIT_FAILURE, "hyperscan block db not found\n");
#else
    printf("built WITHOUT hyperscan: content scan disabled\n");
#endif

    /* Workers = data lcores (RTE_LCORE_FOREACH_WORKER); each owns one queue.
     * Fall back to the main lcore as a single worker if none were given. */
    unsigned nworkers = rte_lcore_count() - 1;
    uint16_t nqueues = nworkers ? (uint16_t)nworkers : 1;

    uint16_t port;
    RTE_ETH_FOREACH_DEV(port)
        if (port_init(port, nqueues) != 0)
            rte_exit(EXIT_FAILURE, "port %u init failed\n", port);
    printf("ffn_fastpath_fwd: %u port(s), %u worker(s), tables from %s\n",
           nports, nqueues, g_tables_dir);

#ifndef FFN_NO_DPMEM
    dpmem_attach();
    dpmem_refresh();
#endif

    /* Assign queue ids + per-worker flow table/scratch, then launch. */
    uint16_t q = 0;
    unsigned lc;
    if (nworkers) {
        RTE_LCORE_FOREACH_WORKER(lc) {
            struct lcore_ctx *c = &g_ctx[lc];
            c->lcore = lc; c->qid = q++;
            c->flows = make_flow_table(lc);
            if (!c->flows) rte_exit(EXIT_FAILURE, "flow table create failed (lcore %u)\n", lc);
#ifdef HAVE_HYPERSCAN
            hs_alloc_scratch(__atomic_load_n(&g_block_db, __ATOMIC_ACQUIRE), &c->scratch);
#endif
            rte_eal_remote_launch(worker, c, lc);
        }
        /* main lcore: periodic dpmem refresh + telemetry publish + stats */
        uint64_t hz = rte_get_tsc_hz(), prev = rte_rdtsc();
        while (!g_stop) {
#ifndef FFN_NO_DPMEM
            dpmem_refresh();
            publish_telemetry();
#endif
            if (rte_rdtsc() - prev >= hz * 10) { print_stats(); prev = rte_rdtsc(); }
            rte_delay_us_block(1000);
        }
        RTE_LCORE_FOREACH_WORKER(lc) rte_eal_wait_lcore(lc);
    } else {
        /* single-lcore fallback: run the worker inline on the main lcore */
        struct lcore_ctx *c = &g_ctx[rte_lcore_id()];
        c->lcore = rte_lcore_id(); c->qid = 0;
        c->flows = make_flow_table(c->lcore);
        if (!c->flows) rte_exit(EXIT_FAILURE, "flow table create failed\n");
#ifdef HAVE_HYPERSCAN
        hs_alloc_scratch(__atomic_load_n(&g_block_db, __ATOMIC_ACQUIRE), &c->scratch);
#endif
        worker(c);
    }

    print_stats();
    RTE_ETH_FOREACH_DEV(port) { rte_eth_dev_stop(port); rte_eth_dev_close(port); }
    rte_eal_cleanup();
    return 0;
}
#endif /* !FFN_BUILD_MP */
