// SPDX-License-Identifier: Apache-2.0
/*
 * ffn_dpdk_fwd.c -- DPDK fast-path forwarder for FFN-NGFW host CPU NICs.
 *
 * Handles traffic on the host's regular Ethernet NICs (Intel i350, X710,
 * Mellanox, etc.) alongside the 4x100G CMAC ports on the FPGA.
 *
 * Pipeline:  RX -> classify -> { punt to FPGA | local deliver | forward }
 *
 *  - Packets destined for FPGA-managed networks: inject via QDMA H2C
 *  - Packets from FPGA (punted via C2H):         forward to CPU NIC
 *  - Management traffic (SSH/HTTPS/BGP/OSPF):    deliver to Linux via KNI
 *
 * Build:
 *   meson setup build -Dexamples=
 *   ninja -C build
 * or:
 *   cc -O2 $(pkg-config --cflags libdpdk) ffn_dpdk_fwd.c \
 *      $(pkg-config --libs libdpdk) -o ffn_dpdk_fwd
 *
 * Usage:
 *   ffn_dpdk_fwd --fpga-pci 0000:3b:00.0 \
 *                --cpu-nics 0000:05:00.0,0000:05:00.1 \
 *                [--rx-queues 4] [--burst 32]
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_kni.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_tcp.h>
#include <rte_udp.h>

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

#define APP_NAME            "ffn_dpdk_fwd"
#define MAX_CPU_PORTS       8
#define MAX_RX_QUEUES       16
#define MAX_TX_QUEUES       16
#define DEFAULT_RX_QUEUES   4
#define DEFAULT_BURST_SIZE  32
#define MBUF_POOL_SIZE      16383   /* per-port */
#define MBUF_CACHE_SIZE     256
#define RX_RING_SIZE        1024
#define TX_RING_SIZE        1024
#define KNI_FIFO_SIZE       2048
#define STATS_INTERVAL_SEC  10
#define DRAIN_INTERVAL_US   100

/* Management-plane destination ports that should be delivered locally */
#define PORT_SSH            22
#define PORT_HTTPS          443
#define PORT_BGP            179
#define PORT_OSPF_PROTO     89   /* IP protocol, not TCP/UDP port */
#define PORT_DHCP_S         67
#define PORT_DHCP_C         68
#define PORT_DNS            53
#define PORT_SNMP           161

/* Packet classification result */
enum pkt_action {
    ACT_FORWARD,        /* forward between CPU NICs */
    ACT_PUNT_FPGA,      /* inject into FPGA via QDMA H2C */
    ACT_LOCAL_DELIVER,  /* hand to Linux kernel via KNI */
    ACT_DROP,           /* discard */
};

/* --------------------------------------------------------------------------
 * Per-core statistics
 * -------------------------------------------------------------------------- */

struct lcore_stats {
    uint64_t rx_pkts;
    uint64_t tx_pkts;
    uint64_t forwarded;
    uint64_t punted;
    uint64_t local_deliver;
    uint64_t dropped;
} __rte_cache_aligned;

static struct lcore_stats stats[RTE_MAX_LCORE];

/* --------------------------------------------------------------------------
 * Global configuration
 * -------------------------------------------------------------------------- */

struct ffn_dpdk_config {
    uint16_t fpga_port_id;              /* DPDK port for FPGA QDMA */
    uint16_t cpu_port_ids[MAX_CPU_PORTS]; /* DPDK ports for CPU NICs */
    int      num_cpu_ports;
    int      num_rx_queues;
    int      burst_size;

    /* Parsed from command line */
    char     fpga_pci[32];             /* e.g. "0000:3b:00.0" */
    char     cpu_pci[MAX_CPU_PORTS][32];

    /* KNI interfaces for local delivery */
    struct rte_kni *kni[MAX_CPU_PORTS];

    /* Subnets managed by the FPGA (simplified: up to 16 /8.../24 prefixes) */
    uint32_t fpga_nets[16];            /* network address, host order */
    uint32_t fpga_masks[16];           /* netmask, host order */
    int      num_fpga_nets;
};

static struct ffn_dpdk_config g_cfg;
static volatile int g_running = 1;
static struct rte_mempool *g_mbuf_pool;

/* --------------------------------------------------------------------------
 * Signal handler
 * -------------------------------------------------------------------------- */

static void signal_handler(int sig)
{
    (void)sig;
    printf("\n%s: caught signal, stopping...\n", APP_NAME);
    g_running = 0;
}

/* --------------------------------------------------------------------------
 * Ethernet port setup
 * -------------------------------------------------------------------------- */

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf  = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

static int
port_init(uint16_t port_id, struct rte_mempool *mp, int n_rx_q, int n_tx_q)
{
    struct rte_eth_conf port_conf = port_conf_default;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    int ret;
    uint16_t q;

    if (!rte_eth_dev_is_valid_port(port_id))
        return -1;

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        printf("Error getting dev info for port %u: %s\n",
               port_id, strerror(-ret));
        return ret;
    }

    /* Clamp queues to hardware limits */
    if ((unsigned)n_rx_q > dev_info.max_rx_queues)
        n_rx_q = dev_info.max_rx_queues;
    if ((unsigned)n_tx_q > dev_info.max_tx_queues)
        n_tx_q = dev_info.max_tx_queues;

    /* Enable offloads if available */
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Adjust RSS hash function to what the device supports */
    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;

    ret = rte_eth_dev_configure(port_id, n_rx_q, n_tx_q, &port_conf);
    if (ret != 0) {
        printf("Error configuring port %u: %s\n", port_id, strerror(-ret));
        return ret;
    }

    /* Set up RX queues */
    for (q = 0; q < (uint16_t)n_rx_q; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE,
                                     rte_eth_dev_socket_id(port_id),
                                     NULL, mp);
        if (ret < 0) {
            printf("RX queue %u setup failed on port %u: %s\n",
                   q, port_id, strerror(-ret));
            return ret;
        }
    }

    /* Set up TX queues */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < (uint16_t)n_tx_q; q++) {
        ret = rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE,
                                     rte_eth_dev_socket_id(port_id),
                                     &txconf);
        if (ret < 0) {
            printf("TX queue %u setup failed on port %u: %s\n",
                   q, port_id, strerror(-ret));
            return ret;
        }
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        printf("Error starting port %u: %s\n", port_id, strerror(-ret));
        return ret;
    }

    /* Enable promiscuous mode for the FPGA port so we see all traffic */
    ret = rte_eth_promiscuous_enable(port_id);
    if (ret != 0)
        printf("Warning: promiscuous mode failed on port %u\n", port_id);

    /* Print link status */
    struct rte_eth_link link;
    ret = rte_eth_link_get_nowait(port_id, &link);
    if (ret == 0 && link.link_status) {
        printf("  Port %u: link UP, %u Mbps, %s\n", port_id,
               link.link_speed,
               link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX ? "FDX" : "HDX");
    } else {
        printf("  Port %u: link DOWN\n", port_id);
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * KNI setup (local delivery to Linux kernel)
 * -------------------------------------------------------------------------- */

static int kni_change_mtu(uint16_t port_id, unsigned new_mtu)
{
    (void)port_id;
    (void)new_mtu;
    return 0; /* accept any MTU change */
}

static int kni_config_network_if(uint16_t port_id, uint8_t if_up)
{
    if (!rte_eth_dev_is_valid_port(port_id))
        return -EINVAL;
    if (if_up)
        return rte_eth_dev_set_link_up(port_id);
    else
        return rte_eth_dev_set_link_down(port_id);
}

static struct rte_kni *
kni_alloc(uint16_t port_id, struct rte_mempool *mp)
{
    struct rte_kni_conf conf;
    struct rte_kni_ops  ops;
    struct rte_eth_dev_info dev_info;

    memset(&conf, 0, sizeof(conf));
    memset(&ops, 0, sizeof(ops));

    rte_eth_dev_info_get(port_id, &dev_info);

    snprintf(conf.name, RTE_KNI_NAMESIZE, "ffn_kni%u", port_id);
    conf.core_id   = rte_get_main_lcore();
    conf.group_id  = port_id;
    conf.mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;

    ops.port_id           = port_id;
    ops.change_mtu        = kni_change_mtu;
    ops.config_network_if = kni_config_network_if;

    struct rte_kni *kni = rte_kni_alloc(mp, &conf, &ops);
    if (!kni)
        printf("Warning: KNI alloc failed for port %u\n", port_id);

    return kni;
}

/* --------------------------------------------------------------------------
 * Packet classification
 * -------------------------------------------------------------------------- */

static inline int
is_fpga_network(uint32_t dst_ip)
{
    for (int i = 0; i < g_cfg.num_fpga_nets; i++) {
        if ((dst_ip & g_cfg.fpga_masks[i]) == g_cfg.fpga_nets[i])
            return 1;
    }
    return 0;
}

static inline int
is_mgmt_port(uint16_t dport)
{
    switch (dport) {
    case PORT_SSH:
    case PORT_HTTPS:
    case PORT_BGP:
    case PORT_DHCP_S:
    case PORT_DHCP_C:
    case PORT_DNS:
    case PORT_SNMP:
        return 1;
    default:
        return 0;
    }
}

static inline enum pkt_action
classify_packet(struct rte_mbuf *pkt, uint16_t rx_port)
{
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr  *ip4;
    uint32_t dst_ip;
    uint8_t  proto;
    uint16_t dport = 0;

    eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

    /* Non-IPv4: forward as-is between CPU NICs */
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        /* ARP and other L2 -> local deliver for the kernel to handle */
        if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
            return ACT_LOCAL_DELIVER;
        return ACT_FORWARD;
    }

    ip4 = (struct rte_ipv4_hdr *)(eth + 1);
    dst_ip = rte_be_to_cpu_32(ip4->dst_addr);
    proto  = ip4->next_proto_id;

    /* OSPF (protocol 89) always goes to kernel */
    if (proto == PORT_OSPF_PROTO)
        return ACT_LOCAL_DELIVER;

    /* Extract L4 destination port for TCP/UDP */
    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)
            ((uint8_t *)ip4 + (ip4->version_ihl & 0x0F) * 4);
        dport = rte_be_to_cpu_16(tcp->dst_port);
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)
            ((uint8_t *)ip4 + (ip4->version_ihl & 0x0F) * 4);
        dport = rte_be_to_cpu_16(udp->dst_port);
    }

    /* Management traffic -> kernel */
    if (is_mgmt_port(dport))
        return ACT_LOCAL_DELIVER;

    /* If coming from the FPGA port, it was punted to host -> forward out
     * CPU NIC (or deliver locally) */
    if (rx_port == g_cfg.fpga_port_id)
        return ACT_FORWARD;

    /* If the destination is on an FPGA-managed network -> punt to FPGA */
    if (is_fpga_network(dst_ip))
        return ACT_PUNT_FPGA;

    /* Default: forward between CPU NICs */
    return ACT_FORWARD;
}

/* --------------------------------------------------------------------------
 * Forwarding core
 * -------------------------------------------------------------------------- */

static int
lcore_main(void *arg)
{
    (void)arg;
    unsigned lcore_id = rte_lcore_id();
    struct lcore_stats *st = &stats[lcore_id];
    uint16_t queue_id;
    struct rte_mbuf *bufs[DEFAULT_BURST_SIZE];
    uint16_t nb_rx, nb_tx;
    int burst = g_cfg.burst_size;

    /* Determine which RX queue this lcore services.
     * Simple static assignment: lcore N handles queue (N - first_worker). */
    unsigned first_worker = rte_get_next_lcore(rte_get_main_lcore(), 1, 1);
    unsigned qoffset = 0;
    unsigned lc = first_worker;
    while (lc != lcore_id && lc < RTE_MAX_LCORE) {
        lc = rte_get_next_lcore(lc, 1, 0);
        qoffset++;
    }
    queue_id = qoffset % g_cfg.num_rx_queues;

    printf("  lcore %u: servicing RX queue %u\n", lcore_id, queue_id);

    while (g_running) {
        /* ---- Poll FPGA port (QDMA C2H -- packets punted from FPGA) ---- */
        nb_rx = rte_eth_rx_burst(g_cfg.fpga_port_id, queue_id,
                                 bufs, burst);
        if (nb_rx > 0) {
            st->rx_pkts += nb_rx;
            for (uint16_t i = 0; i < nb_rx; i++) {
                enum pkt_action act = classify_packet(bufs[i],
                                                      g_cfg.fpga_port_id);
                switch (act) {
                case ACT_LOCAL_DELIVER:
                    if (g_cfg.kni[0]) {
                        rte_kni_tx_burst(g_cfg.kni[0], &bufs[i], 1);
                        st->local_deliver++;
                    } else {
                        rte_pktmbuf_free(bufs[i]);
                        st->dropped++;
                    }
                    break;

                case ACT_FORWARD:
                    /* Send out the first CPU NIC */
                    if (g_cfg.num_cpu_ports > 0) {
                        nb_tx = rte_eth_tx_burst(
                            g_cfg.cpu_port_ids[0], queue_id, &bufs[i], 1);
                        if (nb_tx > 0) st->forwarded++;
                        else { rte_pktmbuf_free(bufs[i]); st->dropped++; }
                    } else {
                        rte_pktmbuf_free(bufs[i]);
                        st->dropped++;
                    }
                    break;

                default:
                    rte_pktmbuf_free(bufs[i]);
                    st->dropped++;
                    break;
                }
            }
        }

        /* ---- Poll each CPU NIC ---- */
        for (int p = 0; p < g_cfg.num_cpu_ports; p++) {
            nb_rx = rte_eth_rx_burst(g_cfg.cpu_port_ids[p], queue_id,
                                     bufs, burst);
            if (nb_rx == 0)
                continue;

            st->rx_pkts += nb_rx;

            for (uint16_t i = 0; i < nb_rx; i++) {
                enum pkt_action act = classify_packet(bufs[i],
                                                      g_cfg.cpu_port_ids[p]);
                switch (act) {
                case ACT_PUNT_FPGA:
                    /* Inject into FPGA via QDMA H2C */
                    nb_tx = rte_eth_tx_burst(g_cfg.fpga_port_id,
                                             queue_id, &bufs[i], 1);
                    if (nb_tx > 0) st->punted++;
                    else { rte_pktmbuf_free(bufs[i]); st->dropped++; }
                    break;

                case ACT_LOCAL_DELIVER:
                    if (g_cfg.kni[p]) {
                        rte_kni_tx_burst(g_cfg.kni[p], &bufs[i], 1);
                        st->local_deliver++;
                    } else {
                        rte_pktmbuf_free(bufs[i]);
                        st->dropped++;
                    }
                    break;

                case ACT_FORWARD: {
                    /* Forward to the other CPU NIC (simple 2-port bridge)
                     * or to the FPGA if only one CPU NIC */
                    uint16_t dst_port;
                    if (g_cfg.num_cpu_ports > 1)
                        dst_port = g_cfg.cpu_port_ids[(p + 1) %
                                                       g_cfg.num_cpu_ports];
                    else
                        dst_port = g_cfg.fpga_port_id;

                    nb_tx = rte_eth_tx_burst(dst_port, queue_id,
                                             &bufs[i], 1);
                    if (nb_tx > 0) st->forwarded++;
                    else { rte_pktmbuf_free(bufs[i]); st->dropped++; }
                    break;
                }

                case ACT_DROP:
                default:
                    rte_pktmbuf_free(bufs[i]);
                    st->dropped++;
                    break;
                }
            }
        }

        /* Handle KNI requests (link up/down, MTU) */
        for (int p = 0; p < g_cfg.num_cpu_ports; p++) {
            if (g_cfg.kni[p])
                rte_kni_handle_request(g_cfg.kni[p]);
        }
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Statistics printer (runs on main lcore)
 * -------------------------------------------------------------------------- */

static void
print_stats(void)
{
    uint64_t total_rx = 0, total_tx = 0, total_fwd = 0;
    uint64_t total_punt = 0, total_local = 0, total_drop = 0;
    unsigned lcore_id;

    printf("\n====== FFN DPDK Forwarder Statistics ======\n");
    printf("  %-6s  %12s  %12s  %12s  %12s  %12s\n",
           "lcore", "RX", "Forwarded", "Punted", "Local", "Dropped");
    printf("  ------ ------------ ------------ "
           "------------ ------------ ------------\n");

    RTE_LCORE_FOREACH(lcore_id) {
        struct lcore_stats *s = &stats[lcore_id];
        if (s->rx_pkts == 0 && s->forwarded == 0)
            continue;
        printf("  %6u  %12lu  %12lu  %12lu  %12lu  %12lu\n",
               lcore_id, s->rx_pkts, s->forwarded,
               s->punted, s->local_deliver, s->dropped);
        total_rx    += s->rx_pkts;
        total_fwd   += s->forwarded;
        total_punt  += s->punted;
        total_local += s->local_deliver;
        total_drop  += s->dropped;
    }
    total_tx = total_fwd + total_punt + total_local;
    printf("  ------ ------------ ------------ "
           "------------ ------------ ------------\n");
    printf("  %6s  %12lu  %12lu  %12lu  %12lu  %12lu\n",
           "TOTAL", total_rx, total_fwd, total_punt, total_local, total_drop);

    /* Per-port counters from DPDK */
    printf("\n  Per-port hardware counters:\n");
    printf("  %-6s  %15s  %15s  %15s  %15s\n",
           "port", "RX-pkts", "RX-bytes", "TX-pkts", "TX-bytes");
    struct rte_eth_stats es;

    /* FPGA port */
    if (rte_eth_stats_get(g_cfg.fpga_port_id, &es) == 0)
        printf("  FPGA    %15lu  %15lu  %15lu  %15lu\n",
               es.ipackets, es.ibytes, es.opackets, es.obytes);

    for (int p = 0; p < g_cfg.num_cpu_ports; p++) {
        if (rte_eth_stats_get(g_cfg.cpu_port_ids[p], &es) == 0)
            printf("  CPU%-2d   %15lu  %15lu  %15lu  %15lu\n",
                   p, es.ipackets, es.ibytes, es.opackets, es.obytes);
    }
    printf("\n");
}

/* --------------------------------------------------------------------------
 * Argument parsing (app-specific, after EAL args separated by --)
 * -------------------------------------------------------------------------- */

static void
usage(const char *prog)
{
    printf("Usage: %s [EAL options] -- [app options]\n"
           "\n"
           "App options:\n"
           "  --fpga-pci  BDF       FPGA QDMA PCI address (e.g. 0000:3b:00.0)\n"
           "  --cpu-nics  BDF[,...] Comma-separated CPU NIC PCI addresses\n"
           "  --rx-queues N         Number of RX queues per port (default %d)\n"
           "  --burst     N         Burst size (default %d)\n"
           "  --fpga-net  CIDR      FPGA-managed network (repeatable)\n"
           "  -h, --help            Show this help\n",
           prog, DEFAULT_RX_QUEUES, DEFAULT_BURST_SIZE);
}

static int
parse_app_args(int argc, char **argv)
{
    g_cfg.num_rx_queues = DEFAULT_RX_QUEUES;
    g_cfg.burst_size    = DEFAULT_BURST_SIZE;
    g_cfg.num_cpu_ports = 0;
    g_cfg.num_fpga_nets = 0;

    /* Default FPGA-managed networks (RFC1918) */
    g_cfg.fpga_nets[0]  = 0x0A000000; /* 10.0.0.0 */
    g_cfg.fpga_masks[0] = 0xFF000000; /* /8 */
    g_cfg.fpga_nets[1]  = 0xAC100000; /* 172.16.0.0 */
    g_cfg.fpga_masks[1] = 0xFFF00000; /* /12 */
    g_cfg.fpga_nets[2]  = 0xC0A80000; /* 192.168.0.0 */
    g_cfg.fpga_masks[2] = 0xFFFF0000; /* /16 */
    g_cfg.num_fpga_nets = 3;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--fpga-pci") == 0 && i + 1 < argc) {
            snprintf(g_cfg.fpga_pci, sizeof(g_cfg.fpga_pci), "%s",
                     argv[++i]);
        } else if (strcmp(argv[i], "--cpu-nics") == 0 && i + 1 < argc) {
            char *tok = strtok(argv[++i], ",");
            while (tok && g_cfg.num_cpu_ports < MAX_CPU_PORTS) {
                snprintf(g_cfg.cpu_pci[g_cfg.num_cpu_ports],
                         sizeof(g_cfg.cpu_pci[0]), "%s", tok);
                g_cfg.num_cpu_ports++;
                tok = strtok(NULL, ",");
            }
        } else if (strcmp(argv[i], "--rx-queues") == 0 && i + 1 < argc) {
            g_cfg.num_rx_queues = atoi(argv[++i]);
            if (g_cfg.num_rx_queues < 1)
                g_cfg.num_rx_queues = 1;
            if (g_cfg.num_rx_queues > MAX_RX_QUEUES)
                g_cfg.num_rx_queues = MAX_RX_QUEUES;
        } else if (strcmp(argv[i], "--burst") == 0 && i + 1 < argc) {
            g_cfg.burst_size = atoi(argv[++i]);
            if (g_cfg.burst_size < 1)   g_cfg.burst_size = 1;
            if (g_cfg.burst_size > 512)  g_cfg.burst_size = 512;
        } else if (strcmp(argv[i], "--fpga-net") == 0 && i + 1 < argc) {
            /* Parse CIDR, e.g. "10.0.0.0/8" */
            char *cidr = argv[++i];
            char *slash = strchr(cidr, '/');
            if (slash && g_cfg.num_fpga_nets < 16) {
                *slash = '\0';
                int pfx = atoi(slash + 1);
                struct in_addr addr;
                if (inet_pton(AF_INET, cidr, &addr) == 1) {
                    int idx = g_cfg.num_fpga_nets;
                    g_cfg.fpga_nets[idx]  = ntohl(addr.s_addr);
                    g_cfg.fpga_masks[idx] = pfx > 0
                        ? (0xFFFFFFFFu << (32 - pfx)) : 0;
                    g_cfg.num_fpga_nets++;
                }
            }
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            exit(0);
        }
    }

    if (g_cfg.fpga_pci[0] == '\0') {
        printf("Error: --fpga-pci is required\n");
        usage(argv[0]);
        return -1;
    }
    if (g_cfg.num_cpu_ports == 0) {
        printf("Warning: no --cpu-nics specified; will only bridge FPGA\n");
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Port-to-DPDK-ID resolution
 * -------------------------------------------------------------------------- */

static int
resolve_port_ids(void)
{
    uint16_t port_id;
    struct rte_eth_dev_info info;
    char pci_name[64];

    /* Resolve FPGA port */
    g_cfg.fpga_port_id = RTE_MAX_ETHPORTS;
    RTE_ETH_FOREACH_DEV(port_id) {
        rte_eth_dev_info_get(port_id, &info);
        if (info.device)
            rte_dev_name(info.device, pci_name, sizeof(pci_name));
        else
            pci_name[0] = '\0';

        if (strstr(pci_name, g_cfg.fpga_pci)) {
            g_cfg.fpga_port_id = port_id;
            printf("  FPGA QDMA port: %s -> port_id %u\n",
                   g_cfg.fpga_pci, port_id);
            break;
        }
    }
    if (g_cfg.fpga_port_id == RTE_MAX_ETHPORTS) {
        printf("Error: FPGA PCI %s not found among DPDK ports\n",
               g_cfg.fpga_pci);
        return -1;
    }

    /* Resolve CPU NIC ports */
    for (int i = 0; i < g_cfg.num_cpu_ports; i++) {
        g_cfg.cpu_port_ids[i] = RTE_MAX_ETHPORTS;
        RTE_ETH_FOREACH_DEV(port_id) {
            rte_eth_dev_info_get(port_id, &info);
            if (info.device)
                rte_dev_name(info.device, pci_name, sizeof(pci_name));
            else
                pci_name[0] = '\0';

            if (strstr(pci_name, g_cfg.cpu_pci[i])) {
                g_cfg.cpu_port_ids[i] = port_id;
                printf("  CPU NIC %d: %s -> port_id %u\n",
                       i, g_cfg.cpu_pci[i], port_id);
                break;
            }
        }
        if (g_cfg.cpu_port_ids[i] == RTE_MAX_ETHPORTS) {
            printf("Error: CPU NIC PCI %s not found\n", g_cfg.cpu_pci[i]);
            return -1;
        }
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int
main(int argc, char **argv)
{
    int ret;
    unsigned lcore_id;

    printf("FFN NGFW DPDK Forwarder v1.0\n");

    /* Initialize DPDK EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    argc -= ret;
    argv += ret;

    /* Parse application arguments */
    if (parse_app_args(argc, argv) < 0)
        rte_exit(EXIT_FAILURE, "Invalid arguments\n");

    /* Install signal handlers */
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    /* Verify we have enough lcores */
    unsigned n_lcores = rte_lcore_count();
    if (n_lcores < 2) {
        printf("Warning: only %u lcores available; need >=2 for best "
               "performance\n", n_lcores);
    }

    /* Resolve PCI BDF -> DPDK port IDs */
    if (resolve_port_ids() < 0)
        rte_exit(EXIT_FAILURE, "Port resolution failed\n");

    /* Create mbuf pool */
    unsigned total_ports = 1 + g_cfg.num_cpu_ports;
    unsigned pool_size = MBUF_POOL_SIZE * total_ports;
    g_mbuf_pool = rte_pktmbuf_pool_create("ffn_pool", pool_size,
                                           MBUF_CACHE_SIZE, 0,
                                           RTE_MBUF_DEFAULT_BUF_SIZE,
                                           rte_socket_id());
    if (g_mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize KNI subsystem */
    rte_kni_init(g_cfg.num_cpu_ports + 1);

    /* Initialize FPGA port */
    printf("Initializing FPGA QDMA port %u...\n", g_cfg.fpga_port_id);
    if (port_init(g_cfg.fpga_port_id, g_mbuf_pool,
                  g_cfg.num_rx_queues, g_cfg.num_rx_queues) != 0)
        rte_exit(EXIT_FAILURE, "FPGA port init failed\n");

    /* Initialize CPU NIC ports */
    for (int p = 0; p < g_cfg.num_cpu_ports; p++) {
        printf("Initializing CPU NIC port %u...\n", g_cfg.cpu_port_ids[p]);
        if (port_init(g_cfg.cpu_port_ids[p], g_mbuf_pool,
                      g_cfg.num_rx_queues, g_cfg.num_rx_queues) != 0)
            rte_exit(EXIT_FAILURE, "CPU NIC port %d init failed\n", p);

        /* Create KNI for local delivery */
        g_cfg.kni[p] = kni_alloc(g_cfg.cpu_port_ids[p], g_mbuf_pool);
    }

    /* Clear stats */
    memset(stats, 0, sizeof(stats));

    /* Launch worker lcores */
    printf("Launching forwarding on %u lcores...\n", n_lcores - 1);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_main, NULL, lcore_id);
    }

    /* Main lcore: periodic stats + KNI handling */
    uint64_t prev_tsc = rte_rdtsc();
    uint64_t stats_interval = rte_get_tsc_hz() * STATS_INTERVAL_SEC;

    while (g_running) {
        uint64_t now = rte_rdtsc();
        if (now - prev_tsc >= stats_interval) {
            print_stats();
            prev_tsc = now;
        }
        /* Handle KNI RX -> kernel (ingress from kernel-generated traffic) */
        for (int p = 0; p < g_cfg.num_cpu_ports; p++) {
            if (g_cfg.kni[p]) {
                struct rte_mbuf *kni_bufs[32];
                unsigned nb = rte_kni_rx_burst(g_cfg.kni[p], kni_bufs, 32);
                if (nb > 0) {
                    /* Kernel-originated packets: send out the CPU NIC */
                    uint16_t sent = rte_eth_tx_burst(
                        g_cfg.cpu_port_ids[p], 0, kni_bufs, nb);
                    for (uint16_t i = sent; i < nb; i++)
                        rte_pktmbuf_free(kni_bufs[i]);
                }
                rte_kni_handle_request(g_cfg.kni[p]);
            }
        }
        usleep(1000);  /* 1ms poll */
    }

    /* Wait for workers */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_wait_lcore(lcore_id);
    }

    /* Final stats */
    print_stats();

    /* Cleanup */
    for (int p = 0; p < g_cfg.num_cpu_ports; p++) {
        if (g_cfg.kni[p]) {
            rte_kni_release(g_cfg.kni[p]);
            g_cfg.kni[p] = NULL;
        }
    }

    printf("Stopping ports...\n");
    rte_eth_dev_stop(g_cfg.fpga_port_id);
    rte_eth_dev_close(g_cfg.fpga_port_id);
    for (int p = 0; p < g_cfg.num_cpu_ports; p++) {
        rte_eth_dev_stop(g_cfg.cpu_port_ids[p]);
        rte_eth_dev_close(g_cfg.cpu_port_ids[p]);
    }

    rte_eal_cleanup();
    printf("FFN DPDK Forwarder stopped.\n");
    return 0;
}
