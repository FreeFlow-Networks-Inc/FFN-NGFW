/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_ha_selftest.c -- standalone unit test for the FFN HA core logic.
 * Build: gcc -O2 -Wall -Wextra -o ffn_ha_selftest ffn_ha.c ffn_ha_selftest.c
 * No DPDK required.
 */
#include "ffn_ha.h"
#include <stdio.h>
#include <stdlib.h>

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); } \
} while (0)

static uint32_t rnd_ip(void)   { return ((uint32_t)rand() << 17) ^ (uint32_t)rand(); }
static uint16_t rnd_port(void) { return (uint16_t)(1 + (rand() % 65535)); }

/* find a flow (sip,dip,sport,dport,proto) whose owner == want */
static void find_flow_owned_by(const struct ffn_ha_state *st, uint8_t want,
                               uint32_t *sip, uint32_t *dip,
                               uint16_t *sp, uint16_t *dp, uint8_t *proto)
{
    struct ffn_ha_flowkey k;
    for (int i = 0; i < 100000; i++) {
        uint32_t a = rnd_ip(), b = rnd_ip();
        uint16_t pa = rnd_port(), pb = rnd_port();
        uint8_t  pr = (i & 1) ? 6 : 17;
        ffn_ha_normalize_key(&k, a, b, pa, pb, pr);
        if (ffn_ha_owner(st, &k) == want) {
            *sip = a; *dip = b; *sp = pa; *dp = pb; *proto = pr;
            return;
        }
    }
    printf("  FAIL: could not find a flow owned by %u\n", want);
    g_fail++;
}

int main(void)
{
    srand(12345);
    struct ffn_ha_state st;

    /* ---- 0: ABI / struct sizes (catch wire drift) ---- */
    printf("[0] ABI struct sizes\n");
    CHECK(sizeof(struct ffn_ha3_hdr)  == 12, "ffn_ha3_hdr is 12 bytes");
    CHECK(sizeof(struct ffn_ha1_hello) == 32, "ffn_ha1_hello is 32 bytes");

    /* ---- 1: symmetric ownership (A->B and B->A same owner) ---- */
    printf("[1] symmetric ownership (ip-hash)\n");
    ffn_ha_state_init(&st, 0, FFN_HA_MODE_ACTIVE_ACTIVE, FFN_HA_ALGO_IP_HASH, 0);
    int asym = 0;
    for (int i = 0; i < 50000; i++) {
        uint32_t a = rnd_ip(), b = rnd_ip();
        uint16_t pa = rnd_port(), pb = rnd_port();
        uint8_t  pr = (i & 1) ? 6 : 17;
        struct ffn_ha_flowkey kf, kr;
        ffn_ha_normalize_key(&kf, a, b, pa, pb, pr);   /* forward */
        ffn_ha_normalize_key(&kr, b, a, pb, pa, pr);   /* reverse */
        if (ffn_ha_hash(&kf) != ffn_ha_hash(&kr)) asym++;
        if (ffn_ha_owner(&st, &kf) != ffn_ha_owner(&st, &kr)) asym++;
    }
    CHECK(asym == 0, "forward/return flows always hash to the same owner");

    /* ---- 2: load-balance distribution ~50/50 ---- */
    printf("[2] load-balance distribution\n");
    int cnt[FFN_HA_MAX_DEVICES] = {0};
    int N = 100000;
    for (int i = 0; i < N; i++) {
        struct ffn_ha_flowkey k;
        ffn_ha_normalize_key(&k, rnd_ip(), rnd_ip(), rnd_port(), rnd_port(),
                             (i & 1) ? 6 : 17);
        cnt[ffn_ha_owner(&st, &k)]++;
    }
    double share0 = 100.0 * cnt[0] / N, share1 = 100.0 * cnt[1] / N;
    printf("    device0=%.1f%%  device1=%.1f%%\n", share0, share1);
    CHECK(share0 > 40.0 && share0 < 60.0, "device0 share within 40-60%");
    CHECK(share1 > 40.0 && share1 < 60.0, "device1 share within 40-60%");

    /* ---- 3: per-packet decision (device 0) ---- */
    printf("[3] decide(): local / forward / takeover / from-peer\n");
    ffn_ha_state_init(&st, 0, FFN_HA_MODE_ACTIVE_ACTIVE, FFN_HA_ALGO_IP_HASH, 0);
    st.peer_up = true;
    uint32_t sip, dip; uint16_t sp, dp; uint8_t pr;
    struct ffn_ha_flowkey k;

    find_flow_owned_by(&st, 0, &sip, &dip, &sp, &dp, &pr);   /* owned by us */
    ffn_ha_normalize_key(&k, sip, dip, sp, dp, pr);
    CHECK(ffn_ha_decide(&st, &k, false) == FFN_HA_LOCAL, "own flow -> LOCAL");
    CHECK(ffn_ha_decide(&st, &k, true)  == FFN_HA_FROM_PEER, "from HA3 -> FROM_PEER");

    find_flow_owned_by(&st, 1, &sip, &dip, &sp, &dp, &pr);   /* owned by peer */
    ffn_ha_normalize_key(&k, sip, dip, sp, dp, pr);
    CHECK(ffn_ha_decide(&st, &k, false) == FFN_HA_FORWARD, "peer flow, peer up -> FORWARD");
    st.peer_up = false;
    CHECK(ffn_ha_decide(&st, &k, false) == FFN_HA_TAKEOVER, "peer flow, peer down -> TAKEOVER");

    /* ---- 4: heartbeat + failover + debounced failback ---- */
    printf("[4] failover / failback timers\n");
    ffn_ha_state_init(&st, 0, FFN_HA_MODE_ACTIVE_ACTIVE, FFN_HA_ALGO_IP_HASH, 1000);
    struct ffn_ha1_hello hello;
    /* peer alive: a hello at t=1000 brings peer up after a hold */
    hello.magic = FFN_HA1_MAGIC; hello.version = 1; hello.device_id = 1;
    ffn_ha_on_hello(&st, &hello, 1000);
    ffn_ha_tick(&st, 1000 + st.hold_ms);          /* debounce elapsed */
    CHECK(st.peer_up == true, "peer comes up after failback hold");
    /* silence past timeout -> failover */
    bool ch = ffn_ha_tick(&st, 1000 + st.hold_ms + st.peer_timeout_ms + 1);
    CHECK(ch && st.peer_up == false, "peer silence past timeout -> peer down");
    CHECK(st.takeovers == 1, "one takeover counted on failover");
    /* peer returns: hello + hold -> back up */
    uint64_t t = 1000 + st.hold_ms + st.peer_timeout_ms + 100;
    ffn_ha_on_hello(&st, &hello, t);
    ffn_ha_tick(&st, t + st.hold_ms);
    CHECK(st.peer_up == true, "peer recovers after hello + hold");

    /* a device with HA disabled always decides LOCAL */
    ffn_ha_state_init(&st, 0, FFN_HA_MODE_DISABLED, FFN_HA_ALGO_IP_HASH, 0);
    ffn_ha_normalize_key(&k, 0x01020304, 0x05060708, 1000, 2000, 6);
    CHECK(ffn_ha_decide(&st, &k, false) == FFN_HA_LOCAL, "HA disabled -> LOCAL");

    /* ---- 5: ip-modulo + primary-device algorithms ---- */
    printf("[5] ip-modulo + primary-device\n");
    ffn_ha_state_init(&st, 0, FFN_HA_MODE_ACTIVE_ACTIVE, FFN_HA_ALGO_IP_MODULO, 0);
    ffn_ha_normalize_key(&k, 10, 20, 111, 222, 6);   /* ip_lo=10 -> 10%2=0 */
    CHECK(ffn_ha_owner(&st, &k) == 0, "ip-modulo even ip_lo -> device 0");
    ffn_ha_normalize_key(&k, 21, 40, 111, 222, 6);   /* ip_lo=21 -> 21%2=1 */
    CHECK(ffn_ha_owner(&st, &k) == 1, "ip-modulo odd ip_lo -> device 1");

    ffn_ha_state_init(&st, 1, FFN_HA_MODE_ACTIVE_PASSIVE, FFN_HA_ALGO_PRIMARY, 0);
    st.peer_up = true;                                /* device 1, primary=0 */
    ffn_ha_normalize_key(&k, 10, 20, 111, 222, 6);
    CHECK(ffn_ha_owner(&st, &k) == 0, "primary-device -> owner is primary (0)");
    CHECK(ffn_ha_decide(&st, &k, false) == FFN_HA_FORWARD,
          "A/P secondary forwards to primary while up");
    st.peer_up = false;
    CHECK(ffn_ha_decide(&st, &k, false) == FFN_HA_TAKEOVER,
          "A/P secondary takes over when primary down");

    printf("\n==== ffn_ha selftest: %d passed, %d failed ====\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
