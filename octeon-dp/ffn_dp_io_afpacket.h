/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_afpacket.h -- AF_PACKET packet-I/O backend for the FFN dataplane.
 */
#ifndef FFN_DP_IO_AFPACKET_H
#define FFN_DP_IO_AFPACKET_H

#include "ffn_dp_oct.h"
#include <stdint.h>
#include <stdio.h>

#define AFP_MAX_PORTS   8
#define AFP_BURST       DP_BURST
#define AFP_FRAME_MAX   2048          /* jumbo-safe enough for bring-up */
#define AFP_IFNAME_MAX  32

struct afp_port {
    int      fd;
    int      ifindex;
    uint16_t port_id;                 /* index used by policy `egress` */
    uint8_t  vsys;                    /* vsys tag applied to frames from here */
    int      ignore_outgoing;         /* kernel honoured PACKET_IGNORE_OUTGOING */
    char     name[AFP_IFNAME_MAX];
};

struct afp_ctx {
    struct afp_port ports[AFP_MAX_PORTS];
    int      nports;
    int      promisc;
    int      poll_ms;
    int      rr_start;                                  /* fairness rotation */
    uint8_t  bufs[AFP_BURST][AFP_FRAME_MAX];            /* rx staging */
    uint16_t in_port[AFP_BURST];                        /* ingress port per slot */
    uint64_t stat_rx, stat_tx, stat_tx_err, stat_local;
    uint64_t stat_no_egress, stat_bad_egress, stat_own_skipped;
    uint64_t stat_offload_unavail;
};

/* the dp_io_ops vtable for this backend */
extern const struct dp_io_ops AFP_IO;

void afp_ctx_init(struct afp_ctx *c, int promisc, int poll_ms);
/* returns the assigned port id (>=0) or a negative errno */
int  afp_add_port(struct afp_ctx *c, const char *ifname, uint8_t vsys);
void afp_dump_stats(const struct afp_ctx *c, FILE *f);

#endif /* FFN_DP_IO_AFPACKET_H */
