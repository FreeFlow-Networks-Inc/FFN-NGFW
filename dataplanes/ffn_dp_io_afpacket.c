/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_afpacket.c -- AF_PACKET packet-I/O backend for the FFN dataplane.
 *
 * Implements struct dp_io_ops on plain Linux raw sockets, so the OCTEON-II
 * forwarder (ffn_dp_oct.c) runs end-to-end on ANY Linux box -- a laptop, the
 * x86 control plane of a reclaimed PA-5220, or the DP Octeon once it is booted
 * into Linux. That makes the forwarding logic exercisable against real kernel
 * networking long before the PKI/PKO line-rate backend exists.
 *
 * Model: one raw socket per port, port index = the order interfaces were added,
 * which is the same index the policy rows' `egress` field selects. With exactly
 * two ports and no egress in the rule, traffic is bridged to the other port
 * (bump-in-the-wire), which is the common lab topology.
 *
 * PERFORMANCE: this is the correctness/bring-up path, not the line-rate path.
 * It uses one recvfrom() per frame; PACKET_MMAP (TPACKET_V3) rings and
 * recvmmsg() are the drop-in optimisation, and the PKI/PKO backend is the real
 * fast path. Nothing above dp_io_ops changes when those land.
 *
 * CAVEAT (deliberate, documented): AF_PACKET is a TAP, not a diversion -- the
 * kernel stack still sees every frame. For a real inline firewall the ports must
 * be isolated from the host stack (dedicated NICs, or drop the traffic in nft),
 * otherwise the kernel forwards in parallel with us. FP_LOCAL is therefore a
 * no-op + counter here: the kernel already has its copy.
 */
#define _GNU_SOURCE
#include "ffn_dp_oct.h"
#include "ffn_dp_io_afpacket.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>          /* htons -- must be declared, not implicit */
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>

#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23      /* kernel >= 4.20 */
#endif

static int afp_open_port(struct afp_port *p, const char *ifname, int promisc)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return -errno;

    unsigned idx = if_nametoindex(ifname);
    if (!idx) {
        close(fd);
        return -ENODEV;
    }

    /* Bind to this interface only. */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)idx;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        int e = -errno;
        close(fd);
        return e;
    }

    /* Never see our own transmits: without this a two-port bridge loops
     * frames straight back into the classifier. Fall back to filtering on
     * sll_pkttype == PACKET_OUTGOING if the kernel is too old for the option. */
    int one = 1;
    p->ignore_outgoing =
        (setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one)) == 0);

    if (promisc) {
        struct packet_mreq mr;
        memset(&mr, 0, sizeof(mr));
        mr.mr_ifindex = (int)idx;
        mr.mr_type = PACKET_MR_PROMISC;
        (void)setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    }

    /* Bigger socket buffer: bursts are lost silently otherwise. */
    int rcvbuf = 4 * 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    p->fd = fd;
    p->ifindex = (int)idx;
    snprintf(p->name, sizeof(p->name), "%s", ifname);
    return 0;
}

int afp_add_port(struct afp_ctx *c, const char *ifname, uint8_t vsys)
{
    if (c->nports >= AFP_MAX_PORTS)
        return -E2BIG;
    struct afp_port *p = &c->ports[c->nports];
    memset(p, 0, sizeof(*p));
    int rc = afp_open_port(p, ifname, c->promisc);
    if (rc < 0)
        return rc;
    p->vsys = vsys;
    p->port_id = (uint16_t)c->nports;
    c->nports++;
    return p->port_id;
}

/* ---- dp_io_ops implementation ---- */

static int afp_init(void *arg)
{
    struct afp_ctx *c = (struct afp_ctx *)arg;
    return c->nports > 0 ? DP_OK : DP_ERR_NOMEM;
}

static void afp_fini(void *arg)
{
    struct afp_ctx *c = (struct afp_ctx *)arg;
    for (int i = 0; i < c->nports; i++) {
        if (c->ports[i].fd >= 0) {
            close(c->ports[i].fd);
            c->ports[i].fd = -1;
        }
    }
    c->nports = 0;
}

static int afp_rx(void *arg, struct dp_pkt *burst, int max)
{
    struct afp_ctx *c = (struct afp_ctx *)arg;
    if (c->nports == 0)
        return 0;
    if (max > AFP_BURST)
        max = AFP_BURST;

    /* Wait briefly for any port so an idle dataplane does not spin a core. */
    struct pollfd pfd[AFP_MAX_PORTS];
    for (int i = 0; i < c->nports; i++) {
        pfd[i].fd = c->ports[i].fd;
        pfd[i].events = POLLIN;
        pfd[i].revents = 0;
    }
    int pr = poll(pfd, (unsigned)c->nports, c->poll_ms);
    if (pr <= 0)
        return 0;

    int n = 0;
    /* Round-robin the starting port so one busy link cannot starve the others. */
    for (int k = 0; k < c->nports && n < max; k++) {
        int i = (c->rr_start + k) % c->nports;
        if (!(pfd[i].revents & POLLIN))
            continue;
        struct afp_port *p = &c->ports[i];
        while (n < max) {
            struct sockaddr_ll from;
            socklen_t flen = sizeof(from);
            uint8_t *buf = c->bufs[n];
            ssize_t got = recvfrom(p->fd, buf, AFP_FRAME_MAX, MSG_DONTWAIT,
                                   (struct sockaddr *)&from, &flen);
            if (got <= 0)
                break;
            /* Older kernels: drop our own transmits explicitly. */
            if (!p->ignore_outgoing && from.sll_pkttype == PACKET_OUTGOING) {
                c->stat_own_skipped++;
                continue;
            }
            burst[n].data = buf;
            burst[n].len = (uint32_t)got;
            burst[n].vsys = p->vsys;
            burst[n].decision = 0;
            burst[n].egress = DP_EGRESS_NONE;
            /* remember the ingress port so tx can pick "the other one" */
            c->in_port[n] = p->port_id;
            burst[n].cookie = &c->in_port[n];
            n++;
            c->stat_rx++;
        }
    }
    c->rr_start = (c->rr_start + 1) % c->nports;
    return n;
}

static int afp_tx_one(struct afp_ctx *c, struct dp_pkt *pk)
{
    uint16_t out = pk->egress;
    uint16_t in_port = pk->cookie ? *(uint16_t *)pk->cookie : 0;

    if (out == DP_EGRESS_NONE) {
        if (c->nports == 2) {
            out = (uint16_t)(in_port == 0 ? 1 : 0);   /* bump-in-the-wire */
        } else {
            c->stat_no_egress++;
            return 0;                                  /* nowhere to send it */
        }
    }
    if (out >= (uint16_t)c->nports) {
        c->stat_bad_egress++;
        return 0;
    }
    struct afp_port *p = &c->ports[out];

    struct sockaddr_ll to;
    memset(&to, 0, sizeof(to));
    to.sll_family = AF_PACKET;
    to.sll_protocol = htons(ETH_P_ALL);
    to.sll_ifindex = p->ifindex;
    to.sll_halen = ETH_ALEN;
    memcpy(to.sll_addr, pk->data, ETH_ALEN);   /* dest mac from the frame */

    ssize_t sent = sendto(p->fd, pk->data, pk->len, 0,
                          (struct sockaddr *)&to, sizeof(to));
    if (sent != (ssize_t)pk->len) {
        c->stat_tx_err++;
        return 0;
    }
    c->stat_tx++;
    return 1;
}

static int afp_tx(void *arg, struct dp_pkt *burst, int n)
{
    struct afp_ctx *c = (struct afp_ctx *)arg;
    int ok = 0;
    for (int i = 0; i < n; i++)
        ok += afp_tx_one(c, &burst[i]);
    return ok;
}

static void afp_to_local(void *arg, struct dp_pkt *p)
{
    (void)p;
    /* AF_PACKET is a tap: the kernel stack already received this frame, so
     * "deliver locally" is accounting only. A diverting backend (NFQUEUE, or
     * PKI on the Octeon) would actually inject here. */
    ((struct afp_ctx *)arg)->stat_local++;
}

static void afp_to_offload(void *arg, struct dp_pkt *p)
{
    (void)p;
    /* No FE100/FPGA on a generic Linux host: count it so a policy that punts
     * is visibly not being offloaded rather than silently dropped. */
    ((struct afp_ctx *)arg)->stat_offload_unavail++;
}

const struct dp_io_ops AFP_IO = {
    "af_packet",
    afp_init,
    afp_fini,
    afp_rx,
    afp_tx,
    afp_to_local,
    afp_to_offload,
    NULL                    /* buffers are owned by afp_ctx; nothing to free */
};

void afp_ctx_init(struct afp_ctx *c, int promisc, int poll_ms)
{
    memset(c, 0, sizeof(*c));
    for (int i = 0; i < AFP_MAX_PORTS; i++)
        c->ports[i].fd = -1;
    c->promisc = promisc;
    c->poll_ms = poll_ms > 0 ? poll_ms : 100;
}

void afp_dump_stats(const struct afp_ctx *c, FILE *f)
{
    fprintf(f, "af_packet: ports=%d rx=%llu tx=%llu tx_err=%llu local=%llu "
               "no_egress=%llu bad_egress=%llu own_skipped=%llu offload_unavail=%llu\n",
            c->nports,
            (unsigned long long)c->stat_rx, (unsigned long long)c->stat_tx,
            (unsigned long long)c->stat_tx_err, (unsigned long long)c->stat_local,
            (unsigned long long)c->stat_no_egress,
            (unsigned long long)c->stat_bad_egress,
            (unsigned long long)c->stat_own_skipped,
            (unsigned long long)c->stat_offload_unavail);
    for (int i = 0; i < c->nports; i++)
        fprintf(f, "  port %u = %s (ifindex %d, ignore_outgoing=%s)\n",
                c->ports[i].port_id, c->ports[i].name, c->ports[i].ifindex,
                c->ports[i].ignore_outgoing ? "yes" : "no(filtering)");
}
