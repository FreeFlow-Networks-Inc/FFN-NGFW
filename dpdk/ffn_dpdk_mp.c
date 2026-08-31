/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dpdk_mp.c -- FFN-NGFW DPDK 22.11 multi-process + zygote data plane.
 *
 * REWORK_CONTRACT §10. One binary, two roles selected by DPDK proc type:
 *
 *   PRIMARY / zygote:
 *     - ensure ASLR is OFF (personality ADDR_NO_RANDOMIZE + re-exec self, and
 *       best-effort kernel.randomize_va_space=0) BEFORE any mapping is laid out;
 *     - rte_eal_init() as primary;
 *     - create the mbuf pool;
 *     - smp_port_init(port, pool, nb_queues=nb_workers) -- symmetric_mp shape:
 *       configure N rx + N tx queues, one pair per worker;
 *     - rte_memzone_reserve() the "ffn_dpmem" region on hugepages (double-buffer
 *       bank 0/1 + slot dirs, see ffn_dpmem.h);
 *     - seed the initial AC/DFA + ML models into bank 0, set active_bank = 0;
 *     - create the MP<->DP control ring + frame pool;
 *     - fork()+execv() nb_workers secondary workers (the "zygote" fork: the
 *       models live in the *shared* hugepage memzone, not COW heap, so every
 *       worker sees identical model bytes at an identical VA);
 *     - run the control thread: poll the ring, hand frames to the flatcc
 *       consumer which writes the INACTIVE bank + flips.
 *
 *   SECONDARY / worker:
 *     - rte_eal_init() with --proc-type=secondary (EAL re-maps every memzone at
 *       the same VA as the primary);
 *     - rte_memzone_lookup("ffn_dpmem") + validate;
 *     - attach its queue pair (queue index == --worker id);
 *     - run ffn_dp_worker_run() over the shared, hot-swappable models.
 *
 * WHY fork()+execv() (and not a bare fork): DPDK EAL cannot be re-initialised in
 * a process that already inherited the primary's initialised EAL state (the
 * "already initialised" guard is inherited across fork, and rte_eal_init() would
 * return -EALREADY). The supported realisation of the zygote is therefore
 * fork()+execv() of the same image with --proc-type=secondary: the child is a
 * fresh EAL that *attaches* the primary's shared hugepage config. Data identity
 * across workers comes from the shared memzone + ASLR-off deterministic mapping,
 * exactly as the contract requires -- COW heap inheritance is NOT relied upon.
 *
 *   build (box): add ffn_dpdk_mp.c to the Makefile APP alongside the DP-FWD
 *                worker + flatcc gen + model loaders (see compile_checklist).
 *   run:  ffn-dpdk-fwd.service runs the primary; cpu_planes supplies -l coremask.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <pthread.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_launch.h>

#include "ffn_dpmem.h"
#include "ffn_fastpath.h"

#define RX_RING_SIZE   1024
#define TX_RING_SIZE   1024
#define NUM_MBUFS      (1 << 16)      /* 65536 - 1 rounded; ample for N queues */
#define MBUF_CACHE     256
#define BURST          32
#define MBUF_POOL_NAME "ffn_mp_pool"

#define DEFAULT_BANK_MB      256u     /* per-bank arena size */
#define DEFAULT_NB_WORKERS   2u
#define MAX_WORKERS          64u

static volatile int g_stop;
static struct ffn_dpmem_hdr *g_hdr;          /* attached region base */
static struct rte_mempool   *g_frame_pool;   /* control-channel frame pool */

/* pristine argv (dup'd before rte_eal_init permutes/consumes it) so the primary
 * can reconstruct a secondary argv for its forked children. */
static int    g_orig_argc;
static char **g_orig_argv;

/* app-level options (after the EAL "--") */
static const char *g_tables_dir = "/var/lib/ffn-ngfw/fastpath";
static unsigned    g_nb_workers = 0;         /* 0 => derive */
static unsigned    g_bank_mb    = DEFAULT_BANK_MB;
static int         g_worker_id  = -1;        /* set in secondary children */

/* ------------------------------------------------------------------ signals */
static void handle_sig(int s) { (void)s; g_stop = 1; }

/* ---------------------------------------------------------------- ASLR guard */
static void try_disable_aslr_sysctl(void)
{
    int fd = open("/proc/sys/kernel/randomize_va_space", O_WRONLY);
    if (fd < 0)
        return;                          /* not root / not permitted: best effort */
    if (write(fd, "0\n", 2) < 0) { /* ignore */ }
    close(fd);
}

/* Must run BEFORE rte_eal_init (mappings are laid out during EAL init). Sets the
 * ADDR_NO_RANDOMIZE personality (setarch -R semantics) and re-execs self so the
 * loader relaunches with ASLR off. Personality is inherited across execve AND
 * fork, so the re-exec'd primary + all forked/exec'd workers get ASLR off too. */
static void ensure_no_aslr(char **argv)
{
    int p = personality(0xffffffffUL);
    if (p == -1)
        return;                          /* personality() unsupported: proceed */
    if (p & ADDR_NO_RANDOMIZE)
        return;                          /* already off (this is the re-exec) */
    if (personality((unsigned long)p | ADDR_NO_RANDOMIZE) == -1)
        return;
    try_disable_aslr_sysctl();           /* box-wide, needs root; non-fatal */
    execv("/proc/self/exe", argv);       /* relaunch with ASLR off */
    fprintf(stderr,
            "ffn_dpdk_mp: WARN ASLR re-exec failed (%s); set "
            "kernel.randomize_va_space=0 or run under `setarch -R`\n",
            strerror(errno));
}

static int aslr_is_off(void)
{
    int p = personality(0xffffffffUL);
    return (p != -1) && (p & ADDR_NO_RANDOMIZE);
}

/* --------------------------------------------------------------- arg helpers */
static void save_orig_args(int argc, char **argv)
{
    int i;
    g_orig_argc = argc;
    g_orig_argv = calloc((size_t)argc + 1, sizeof(char *));
    if (!g_orig_argv)
        rte_exit(EXIT_FAILURE, "oom saving argv\n");
    for (i = 0; i < argc; i++)
        g_orig_argv[i] = strdup(argv[i]);
    g_orig_argv[argc] = NULL;
}

static void parse_app_args(int argc, char **argv)
{
    int i;
    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--tables") && i + 1 < argc)
            g_tables_dir = argv[++i];
        else if (!strcmp(argv[i], "--nb-workers") && i + 1 < argc)
            g_nb_workers = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--bank-mb") && i + 1 < argc)
            g_bank_mb = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--worker") && i + 1 < argc)
            g_worker_id = (int)strtol(argv[++i], NULL, 10);
    }
}

/* Build a NULL-terminated argv for a forked secondary worker:
 *   prog, --proc-type=secondary, <EAL args minus any --proc-type>, --,
 *   <app args>, --worker <id>
 * The EAL/app split is the first "--" in the pristine argv. */
static char **build_secondary_argv(int worker_id)
{
    char **out;
    int cap = g_orig_argc + 8;
    int n = 0, i, dd = -1;
    char idbuf[16];

    for (i = 1; i < g_orig_argc; i++)
        if (!strcmp(g_orig_argv[i], "--")) { dd = i; break; }

    out = calloc((size_t)cap + 1, sizeof(char *));
    if (!out)
        return NULL;
    snprintf(idbuf, sizeof idbuf, "%d", worker_id);

    out[n++] = g_orig_argv[0];
    out[n++] = (char *)"--proc-type=secondary";
    /* EAL args: [1 .. dd-1] (or [1 .. end] if no "--"), skipping proc-type dups */
    {
        int eal_end = (dd >= 0) ? dd : g_orig_argc;
        for (i = 1; i < eal_end; i++) {
            if (!strncmp(g_orig_argv[i], "--proc-type", 11))
                continue;
            out[n++] = g_orig_argv[i];
        }
    }
    out[n++] = (char *)"--";
    if (dd >= 0)                             /* copy existing app args */
        for (i = dd + 1; i < g_orig_argc; i++)
            out[n++] = g_orig_argv[i];
    out[n++] = (char *)"--worker";
    out[n++] = strdup(idbuf);
    out[n] = NULL;
    return out;
}

/* ------------------------------------------------------------------- ports */
/* symmetric_mp smp_port_init shape (DPDK 22.11): configure num_queues rx + tx
 * queue pairs on a single port, RSS spread across them. Only the PRIMARY calls
 * this (secondaries may not configure/start the device in DPDK MP). */
static int smp_port_init(uint16_t port, struct rte_mempool *pool, uint16_t num_queues)
{
    struct rte_eth_conf conf;
    struct rte_eth_dev_info info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    uint16_t nb_rxd = RX_RING_SIZE, nb_txd = TX_RING_SIZE, q;
    int ret;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;
    ret = rte_eth_dev_info_get(port, &info);
    if (ret != 0)
        return ret;

    memset(&conf, 0, sizeof conf);
    conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    conf.rxmode.offloads = 0;                /* vdev-friendly; enable per-NIC on box */
    conf.rx_adv_conf.rss_conf.rss_key = NULL;
    conf.rx_adv_conf.rss_conf.rss_hf =
        (RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP) &
        info.flow_type_rss_offloads;
    conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    /* vdevs (pcap/null/ring) advertise no RSS: fall back to a single-hash NONE. */
    if (num_queues <= 1 || conf.rx_adv_conf.rss_conf.rss_hf == 0)
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    ret = rte_eth_dev_configure(port, num_queues, num_queues, &conf);
    if (ret != 0)
        return ret;

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret != 0)
        return ret;

    rxq_conf = info.default_rxconf;
    rxq_conf.offloads = conf.rxmode.offloads;
    for (q = 0; q < num_queues; q++) {
        ret = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                     rte_eth_dev_socket_id(port), &rxq_conf, pool);
        if (ret < 0)
            return ret;
    }
    txq_conf = info.default_txconf;
    txq_conf.offloads = conf.txmode.offloads;
    for (q = 0; q < num_queues; q++) {
        ret = rte_eth_tx_queue_setup(port, q, nb_txd,
                                     rte_eth_dev_socket_id(port), &txq_conf);
        if (ret < 0)
            return ret;
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0)
        return ret;
    rte_eth_promiscuous_enable(port);
    return 0;
}

/* -------------------------------------------------------------- dpmem region */
static struct ffn_dpmem_hdr *dpmem_reserve(unsigned nb_workers, uint64_t bank_size)
{
    const struct rte_memzone *mz;
    struct ffn_dpmem_hdr *h;
    uint64_t hdr_sz = ffn_dpmem_align_up(sizeof(struct ffn_dpmem_hdr), FFN_DPMEM_ALIGN);
    uint64_t total  = hdr_sz + (uint64_t)FFN_DPMEM_NBANKS * bank_size;

    /* Reserved on hugepages; visible to every secondary via memzone_lookup.
     * RTE_MEMZONE_SIZE_HINT_ONLY lets EAL satisfy from 2M pages if 1G is scarce. */
    mz = rte_memzone_reserve_aligned(FFN_DPMEM_NAME, total, rte_socket_id(),
                                     RTE_MEMZONE_SIZE_HINT_ONLY, FFN_DPMEM_ALIGN);
    if (!mz) {
        fprintf(stderr, "dpmem: rte_memzone_reserve(%" PRIu64 "B) failed: %s\n",
                total, rte_strerror(rte_errno));
        return NULL;
    }
    h = (struct ffn_dpmem_hdr *)mz->addr;
    memset(h, 0, hdr_sz);                     /* zero header + both bank dirs */
    h->magic = FFN_DPMEM_MAGIC;
    h->version = FFN_DPMEM_VERSION;
    h->nb_workers = nb_workers;
    h->total_size = total;
    h->bank_size = bank_size;
    h->bank_off[0] = hdr_sz;
    h->bank_off[1] = hdr_sz + bank_size;
    h->ctrl_flags = aslr_is_off() ? FFN_DPMEM_CF_ASLR_OFF : 0;
    ffn_dpmem_set_active(h, 0);
    return h;
}

/* --------------------------------------------------------- control channel */
static int ctrl_channel_create(void)
{
    struct rte_ring *r;
    /* Single consumer (this control thread); producers = MP bridge(s). */
    r = rte_ring_create(FFN_MPDP_RING_NAME, FFN_MPDP_RING_DEPTH,
                        rte_socket_id(), RING_F_SC_DEQ);
    if (!r) {
        fprintf(stderr, "ctrl: rte_ring_create failed: %s\n",
                rte_strerror(rte_errno));
        return -1;
    }
    g_frame_pool = rte_mempool_create(FFN_MPDP_POOL_NAME, FFN_MPDP_POOL_COUNT,
                                      sizeof(struct ffn_mpdp_frame), 0, 0,
                                      NULL, NULL, NULL, NULL,
                                      rte_socket_id(), 0);
    if (!g_frame_pool) {
        fprintf(stderr, "ctrl: rte_mempool_create failed: %s\n",
                rte_strerror(rte_errno));
        return -1;
    }
    return 0;
}

/* Control thread: poll the MP->DP ring, apply each frame into the INACTIVE
 * bank via the flatcc consumer, and flip on change. rte_ctrl_thread_create
 * pins this off the datapath lcores. */
static void *ctrl_thread_main(void *arg)
{
    struct rte_ring *r = rte_ring_lookup(FFN_MPDP_RING_NAME);
    (void)arg;
    if (!r)
        return NULL;
    while (!g_stop) {
        void *obj = NULL;
        if (rte_ring_dequeue(r, &obj) == 0) {
            struct ffn_mpdp_frame *f = obj;
            uint32_t inact = ffn_dpmem_inactive(g_hdr);
            int rc = ffn_flatcc_apply(g_hdr, inact, f->data, f->len);
            if (rc > 0)
                ffn_dpmem_flip(g_hdr);       /* publish the new bank */
            rte_mempool_put(g_frame_pool, obj);
        } else {
            rte_delay_us_sleep(500);         /* idle backoff */
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ primary */
static pid_t g_children[MAX_WORKERS];
static unsigned g_nchild;

static int spawn_workers(unsigned nb_workers)
{
    unsigned i;
    for (i = 0; i < nb_workers; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            return -1;
        }
        if (pid == 0) {
            /* child: relaunch self as an EAL secondary bound to queue i */
            char **av = build_secondary_argv((int)i);
            if (!av)
                _exit(127);
            execv("/proc/self/exe", av);
            fprintf(stderr, "worker %u execv failed: %s\n", i, strerror(errno));
            _exit(127);
        }
        g_children[g_nchild++] = pid;
    }
    return 0;
}

static void reap_workers(void)
{
    unsigned i;
    for (i = 0; i < g_nchild; i++)
        if (g_children[i] > 0)
            kill(g_children[i], SIGTERM);
    for (i = 0; i < g_nchild; i++) {
        int status;
        if (g_children[i] > 0)
            waitpid(g_children[i], &status, 0);
    }
}

static int primary_main(void)
{
    struct rte_mempool *pool;
    uint16_t nports, port;
    unsigned nb_workers = g_nb_workers;
    pthread_t ctrl_tid;
    int ret;

    if (!aslr_is_off())
        fprintf(stderr, "ffn_dpdk_mp: WARN ASLR still ON -- shared-model pointers "
                        "may diverge across workers (want kernel.randomize_va_space=0)\n");

    /* Worker count: CLI, else one per available worker lcore, else default. */
    if (nb_workers == 0) {
        unsigned lc = rte_lcore_count();
        nb_workers = (lc > 1) ? (lc - 1) : DEFAULT_NB_WORKERS;
    }
    if (nb_workers > MAX_WORKERS)
        nb_workers = MAX_WORKERS;

    nports = rte_eth_dev_count_avail();
    if (nports == 0)
        rte_exit(EXIT_FAILURE, "no ethdev ports (add a --vdev)\n");

    pool = rte_pktmbuf_pool_create(MBUF_POOL_NAME, NUM_MBUFS - 1, MBUF_CACHE, 0,
                                   RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool)
        rte_exit(EXIT_FAILURE, "mbuf pool create failed: %s\n",
                 rte_strerror(rte_errno));

    RTE_ETH_FOREACH_DEV(port) {
        ret = smp_port_init(port, pool, (uint16_t)nb_workers);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "port %u init (%u queues) failed: %d\n",
                     port, nb_workers, ret);
    }

    g_hdr = dpmem_reserve(nb_workers, (uint64_t)g_bank_mb << 20);
    if (!g_hdr)
        rte_exit(EXIT_FAILURE, "dpmem reserve failed\n");

    /* Seed initial models into bank 0, then publish it as active. */
    if (ffn_models_load_initial(g_hdr, 0, g_tables_dir) < 0)
        fprintf(stderr, "ffn_dpdk_mp: WARN initial model load reported error "
                        "(continuing with empty bank 0)\n");
    ffn_dpmem_set_active(g_hdr, 0);

    if (ctrl_channel_create() < 0)
        rte_exit(EXIT_FAILURE, "control channel create failed\n");

    printf("ffn_dpdk_mp: PRIMARY up -- %u port(s), %u worker(s), dpmem=%" PRIu64
           "B (bank=%uMiB x2), aslr_off=%d, tables=%s\n",
           nports, nb_workers, g_hdr->total_size, g_bank_mb,
           aslr_is_off(), g_tables_dir);

    if (spawn_workers(nb_workers) < 0)
        rte_exit(EXIT_FAILURE, "worker spawn failed\n");

    /* Control thread (pinned off datapath cores by EAL). */
    ret = rte_ctrl_thread_create(&ctrl_tid, "ffn-mpdp-ctrl", NULL,
                                 ctrl_thread_main, NULL);
    if (ret != 0)
        fprintf(stderr, "ffn_dpdk_mp: WARN ctrl thread create failed (%d): "
                        "no live model updates\n", ret);

    while (!g_stop)
        rte_delay_us_sleep(100 * 1000);      /* 100 ms supervisor tick */

    printf("ffn_dpdk_mp: PRIMARY stopping -- reaping %u worker(s)\n", g_nchild);
    reap_workers();
    if (ret == 0)
        pthread_join(ctrl_tid, NULL);
    return 0;
}

/* ---------------------------------------------------------------- secondary */
static int secondary_main(void)
{
    const struct rte_memzone *mz;
    struct rte_mempool *pool;
    struct ffn_dp_worker_args a;
    uint16_t port = 0;

    if (g_worker_id < 0)
        rte_exit(EXIT_FAILURE, "secondary started without --worker <id>\n");

    mz = rte_memzone_lookup(FFN_DPMEM_NAME);
    if (!mz)
        rte_exit(EXIT_FAILURE, "dpmem memzone not found (primary up?)\n");
    g_hdr = (struct ffn_dpmem_hdr *)mz->addr;
    if (!ffn_dpmem_valid(g_hdr))
        rte_exit(EXIT_FAILURE, "dpmem magic/version mismatch\n");

    pool = rte_mempool_lookup(MBUF_POOL_NAME);   /* may be NULL; fwd rx path ok */

    /* First available port; queue index == this worker's id. */
    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "worker sees no ethdev ports\n");
    RTE_ETH_FOREACH_DEV(port)
        break;

    memset(&a, 0, sizeof a);
    a.port = port;
    a.queue = (uint16_t)g_worker_id;
    a.nb_workers = (uint16_t)g_hdr->nb_workers;
    a.worker_id = (uint16_t)g_worker_id;
    a.pool = pool;
    a.dpmem = g_hdr;
    a.stop = &g_stop;

    printf("ffn_dpdk_mp: SECONDARY worker %d -- port %u queue %u, active_bank=%u\n",
           g_worker_id, a.port, a.queue, ffn_dpmem_active(g_hdr));

    return ffn_dp_worker_run(&a);
}

/* ---------------------------------------------------------------------- main */
int main(int argc, char **argv)
{
    int ret, app_argc;
    char **app_argv;

    ensure_no_aslr(argv);            /* may re-exec; MUST precede rte_eal_init */
    save_orig_args(argc, argv);      /* dup before EAL permutes/consumes argv */

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed: %s\n", rte_strerror(rte_errno));
    app_argc = argc - ret;
    app_argv = argv + ret;
    parse_app_args(app_argc, app_argv);

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    if (rte_eal_process_type() == RTE_PROC_SECONDARY)
        ret = secondary_main();
    else
        ret = primary_main();

    rte_eal_cleanup();
    return ret;
}

/* =========================================================================
 * Weak fallbacks so this file links standalone before the real owners land.
 * The real inspect+verdict worker ffn_dp_worker_run() is now a STRONG export
 * from ffn_fastpath_fwd.c (compiled into ffn-dpdk-mp), so its weak fallback is
 * removed -- the zygote always runs the real worker. EMU+ML / FLATCC still ship
 * weak stubs here; the real owners provide strong definitions that override them
 * (ffn_mpdp_consumer.c is a strong ffn_flatcc_apply owner in this build).
 * ========================================================================= */

/* EMU/ML: seed AC/DFA + ML models into bank at seed time. */
__attribute__((weak))
int ffn_models_load_initial(struct ffn_dpmem_hdr *dpmem, uint32_t bank,
                            const char *tables_dir)
{
    (void)dpmem; (void)bank; (void)tables_dir;
    return 0;                        /* empty bank 0 (workers fwd-only) */
}

/* FLATCC: decode one MpDpMessage + apply into the inactive bank. */
__attribute__((weak))
int ffn_flatcc_apply(struct ffn_dpmem_hdr *dpmem, uint32_t inactive_bank,
                     const void *frame, size_t frame_len)
{
    (void)dpmem; (void)inactive_bank; (void)frame; (void)frame_len;
    return 0;                        /* no-op: nothing published */
}
