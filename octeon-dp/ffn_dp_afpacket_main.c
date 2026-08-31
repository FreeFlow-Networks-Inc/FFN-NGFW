/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_afpacket_main.c -- runnable FFN dataplane over AF_PACKET.
 *
 * Runs the OCTEON-II forwarder (ffn_dp_oct.c) against real Linux interfaces, so
 * the whole path -- policy tables, classify, flow cache, verdicts, forwarding --
 * is exercisable end-to-end without Octeon hardware.
 *
 *   ffn_dp_afpacket -i vethA0 -i vethB0 -p policy.bin [-d drop|forward] [-P] [-s 2]
 *
 *   -i IFACE     add a port (repeatable; port index = order, matches the policy
 *                `egress` field). Two ports with no egress = bump-in-the-wire.
 *   -p FILE      policy.bin from ffn_fastpath_compile.py (type 0x40 "FPPO")
 *   -d DECISION  default when no rule matches: drop (default) | forward | local
 *   -v N         vsys tag applied to frames (default 1)
 *   -P           promiscuous mode on each port
 *   -s SEC       print stats every SEC seconds (0 = only at exit)
 *   -c N         stop after N packets (0 = run until signalled) -- for tests
 */
#define _GNU_SOURCE
#include "ffn_dp_abi.h"
#include "ffn_dp_oct.h"
#include "ffn_dp_io_afpacket.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

static void *slurp(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    rewind(f);
    void *buf = malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if (got != (size_t)n) { free(buf); return NULL; }
    *len_out = got;
    return buf;
}

static void usage(const char *a0)
{
    fprintf(stderr,
        "usage: %s -i IFACE [-i IFACE ...] [-p policy.bin] [-d drop|forward|local]\n"
        "          [-v vsys] [-P] [-s sec] [-c count]\n", a0);
}

int main(int argc, char **argv)
{
    const char *ifaces[AFP_MAX_PORTS];
    int nif = 0;
    const char *polpath = NULL;
    int default_dec = FP_DROP_W;
    int promisc = 0, stats_sec = 0;
    unsigned long stop_after = 0;
    uint8_t vsys = 1;

    int opt;
    while ((opt = getopt(argc, argv, "i:p:d:v:Ps:c:h")) != -1) {
        switch (opt) {
        case 'i':
            if (nif >= AFP_MAX_PORTS) { fprintf(stderr, "too many ports\n"); return 2; }
            ifaces[nif++] = optarg;
            break;
        case 'p': polpath = optarg; break;
        case 'd':
            if (!strcmp(optarg, "drop"))         default_dec = FP_DROP_W;
            else if (!strcmp(optarg, "forward")) default_dec = FP_FORWARD_W;
            else if (!strcmp(optarg, "local"))   default_dec = FP_LOCAL_W;
            else { fprintf(stderr, "bad -d %s\n", optarg); return 2; }
            break;
        case 'v': vsys = (uint8_t)atoi(optarg); break;
        case 'P': promisc = 1; break;
        case 's': stats_sec = atoi(optarg); break;
        case 'c': stop_after = strtoul(optarg, NULL, 10); break;
        default: usage(argv[0]); return 2;
        }
    }
    if (nif == 0) { usage(argv[0]); return 2; }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    struct afp_ctx io;
    afp_ctx_init(&io, promisc, 100);
    for (int i = 0; i < nif; i++) {
        int rc = afp_add_port(&io, ifaces[i], vsys);
        if (rc < 0) {
            fprintf(stderr, "port %s: %s\n", ifaces[i], strerror(-rc));
            return 1;
        }
        printf("port %d = %s\n", rc, ifaces[i]);
    }

    struct dp_ctx dp;
    int rc = dp_init(&dp, &AFP_IO, &io, 0);
    if (rc != DP_OK) {
        fprintf(stderr, "dp_init: %s\n", dp_strerror(rc));
        return 1;
    }
    dp.default_decision = default_dec;

    /* A shared region gives us the same handshake + bank/ring machinery the
     * Octeon uses; here it is ordinary memory instead of a PCIe BAR. */
    size_t rsz = FFN_DP_OFF_BANK0 + (4u << 20);
    void *region = calloc(1, rsz);
    if (!region) { fprintf(stderr, "region alloc failed\n"); return 1; }
    rc = dp_region_attach(&dp, region, rsz, 1);
    if (rc != DP_OK) {
        fprintf(stderr, "region attach: %s\n", dp_strerror(rc));
        return 1;
    }

    if (polpath) {
        size_t plen = 0;
        void *pol = slurp(polpath, &plen);
        if (!pol) { fprintf(stderr, "cannot read %s\n", polpath); return 1; }
        if (plen > FFN_DP_BANK_SIZE) { fprintf(stderr, "policy too large\n"); return 1; }
        memcpy((uint8_t *)region + FFN_DP_OFF_BANK0, pol, plen);
        free(pol);
        rc = dp_activate_bank(&dp, 0);
        if (rc != DP_OK) {
            fprintf(stderr, "policy load: %s\n", dp_strerror(rc));
            return 1;
        }
        printf("policy: %u rule(s) from %s\n", dp.tables.policy_n, polpath);
    } else {
        printf("policy: none loaded -- every packet takes the default (%s)\n",
               default_dec == FP_DROP_W ? "drop" :
               default_dec == FP_FORWARD_W ? "forward" : "local");
    }
    printf("default decision: %s\nrunning (ctrl-c to stop)\n",
           default_dec == FP_DROP_W ? "drop" :
           default_dec == FP_FORWARD_W ? "forward" : "local");
    fflush(stdout);

    dp_set_state(&dp, DP_STATE_READY);
    time_t last = time(NULL);
    while (!g_stop) {
        dp_poll_once(&dp);
        if (stop_after && dp.stat_rx >= stop_after)
            break;
        if (stats_sec) {
            time_t now = time(NULL);
            if (now - last >= stats_sec) {
                last = now;
                printf("rx=%llu fwd=%llu insp=%llu drop=%llu local=%llu "
                       "cache_hit=%llu classify=%llu parse_err=%llu\n",
                       (unsigned long long)dp.stat_rx,
                       (unsigned long long)dp.stat_forward,
                       (unsigned long long)dp.stat_inspect,
                       (unsigned long long)dp.stat_drop,
                       (unsigned long long)dp.stat_local,
                       (unsigned long long)dp.stat_cache_hit,
                       (unsigned long long)dp.stat_classify,
                       (unsigned long long)dp.stat_parse_err);
                fflush(stdout);
            }
        }
    }

    printf("\n--- final ---\n");
    printf("dp: rx=%llu tx=%llu tx_fail=%llu fwd=%llu insp=%llu drop=%llu "
           "punt=%llu local=%llu cache_hit=%llu classify=%llu parse_err=%llu "
           "flow_full=%llu flows=%u\n",
           (unsigned long long)dp.stat_rx, (unsigned long long)dp.stat_tx,
           (unsigned long long)dp.stat_tx_fail,
           (unsigned long long)dp.stat_forward, (unsigned long long)dp.stat_inspect,
           (unsigned long long)dp.stat_drop, (unsigned long long)dp.stat_punt,
           (unsigned long long)dp.stat_local, (unsigned long long)dp.stat_cache_hit,
           (unsigned long long)dp.stat_classify,
           (unsigned long long)dp.stat_parse_err,
           (unsigned long long)dp.stat_flow_full, dp.flows.count);
    afp_dump_stats(&io, stdout);

    dp_fini(&dp);
    free(region);
    return 0;
}
