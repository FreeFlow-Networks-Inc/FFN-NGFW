// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FFN NGFW — FIB/ARP Route Sync Agent
 *
 * Daemon that bridges the Linux kernel routing table and ARP/neighbor
 * cache to the FPGA L3 router engine.  Subscribes to Netlink
 * RTM_NEWROUTE / RTM_DELROUTE / RTM_NEWNEIGH / RTM_DELNEIGH events
 * and pushes changes to the FPGA FIB/ARP BRAM via /dev/ngfw0 ioctls.
 *
 * At startup it performs a full synchronization by walking all routes
 * and neighbors.  Supports VRF by reading the route table ID.
 *
 * Designed to run under systemd with sd_notify(READY=1).
 *
 * Build:
 *   cc -O2 -Wall -o ffn_route_agent ffn_route_agent.c \
 *      -I../libngfw/include -lsystemd
 *
 * Usage:
 *   ffn_route_agent [-d] [-D /dev/ngfwN]
 *     -d  : run in foreground (debug mode)
 *     -D  : device path (default /dev/ngfw0)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <ngfw/ngfw_regs.h>

/* Optional: sd_notify for systemd readiness.  If libsystemd is not
 * available, the sd_notify call is a no-op. */
#ifdef HAVE_SYSTEMD
#  include <systemd/sd-daemon.h>
#else
#  define sd_notify(u, s) do {} while(0)
#endif

/* ============================================================
 * Configuration
 * ============================================================ */
#define DEFAULT_DEV_PATH   "/dev/ngfw0"
#define NL_BUF_SIZE        16384
#define MAX_VRF_ID         255

static const char *dev_path = DEFAULT_DEV_PATH;
static int dev_fd = -1;
static volatile sig_atomic_t running = 1;
static int debug_mode = 0;

/* ============================================================
 * Signal handling
 * ============================================================ */
static void sig_handler(int signo)
{
    (void)signo;
    running = 0;
}

/* ============================================================
 * FPGA ioctl wrappers
 * ============================================================ */
static int fpga_fib_add(const struct ngfw_fib_entry *fib)
{
    int ret = ioctl(dev_fd, NGFW_IOC_FIB_ADD, fib);
    if (ret < 0) {
        syslog(LOG_ERR, "FIB_ADD failed: dst=%08x/%u nh=%08x port=%u vrf=%u: %s",
               fib->dst_ip, fib->prefix_len, fib->next_hop,
               fib->egress_port, fib->vrf_id, strerror(errno));
    } else if (debug_mode) {
        syslog(LOG_DEBUG, "FIB_ADD: dst=%08x/%u nh=%08x port=%u vrf=%u",
               fib->dst_ip, fib->prefix_len, fib->next_hop,
               fib->egress_port, fib->vrf_id);
    }
    return ret;
}

static int fpga_fib_del(const struct ngfw_fib_entry *fib)
{
    int ret = ioctl(dev_fd, NGFW_IOC_FIB_DEL, fib);
    if (ret < 0) {
        syslog(LOG_ERR, "FIB_DEL failed: dst=%08x/%u vrf=%u: %s",
               fib->dst_ip, fib->prefix_len, fib->vrf_id,
               strerror(errno));
    } else if (debug_mode) {
        syslog(LOG_DEBUG, "FIB_DEL: dst=%08x/%u vrf=%u",
               fib->dst_ip, fib->prefix_len, fib->vrf_id);
    }
    return ret;
}

static int fpga_arp_add(const struct ngfw_arp_entry *arp)
{
    int ret = ioctl(dev_fd, NGFW_IOC_ARP_ADD, arp);
    if (ret < 0) {
        syslog(LOG_ERR, "ARP_ADD failed: ip=%08x mac=%02x:%02x:%02x:%02x:%02x:%02x: %s",
               arp->ip, arp->mac[0], arp->mac[1], arp->mac[2],
               arp->mac[3], arp->mac[4], arp->mac[5], strerror(errno));
    } else if (debug_mode) {
        syslog(LOG_DEBUG, "ARP_ADD: ip=%08x mac=%02x:%02x:%02x:%02x:%02x:%02x port=%u",
               arp->ip, arp->mac[0], arp->mac[1], arp->mac[2],
               arp->mac[3], arp->mac[4], arp->mac[5], arp->port);
    }
    return ret;
}

static int fpga_arp_del(const struct ngfw_arp_entry *arp)
{
    int ret = ioctl(dev_fd, NGFW_IOC_ARP_DEL, arp);
    if (ret < 0) {
        syslog(LOG_ERR, "ARP_DEL failed: ip=%08x: %s",
               arp->ip, strerror(errno));
    } else if (debug_mode) {
        syslog(LOG_DEBUG, "ARP_DEL: ip=%08x", arp->ip);
    }
    return ret;
}

/* ============================================================
 * Interface index -> FPGA port mapping
 *
 * Maps Linux interface names "ngfw0".."ngfw3" to FPGA ports 0..3.
 * Returns 0xFF for non-NGFW interfaces (they are ignored for
 * direct FPGA programming but may still be relevant for VRF).
 * ============================================================ */
static uint8_t ifindex_to_port(int ifindex)
{
    char ifname[IFNAMSIZ];
    int port;

    if (!if_indextoname(ifindex, ifname))
        return 0xFF;

    if (sscanf(ifname, "ngfw%d", &port) == 1 && port >= 0 && port <= 3)
        return (uint8_t)port;

    return 0xFF;
}

/* ============================================================
 * Netlink route message parser
 * ============================================================ */
static void handle_route_msg(struct nlmsghdr *nlh)
{
    struct rtmsg *rtm = NLMSG_DATA(nlh);
    struct rtattr *rta;
    int rta_len;
    struct ngfw_fib_entry fib;

    /* Only handle IPv4 unicast routes in main or VRF tables */
    if (rtm->rtm_family != AF_INET)
        return;
    if (rtm->rtm_type != RTN_UNICAST &&
        rtm->rtm_type != RTN_BLACKHOLE &&
        rtm->rtm_type != RTN_UNREACHABLE)
        return;

    memset(&fib, 0, sizeof(fib));
    fib.prefix_len = rtm->rtm_dst_len;

    /* VRF support: use route table ID as VRF ID.
     * Table RT_TABLE_MAIN (254) maps to VRF 0.
     * Custom tables (1..252) map directly to VRF IDs. */
    if (rtm->rtm_table == RT_TABLE_MAIN || rtm->rtm_table == RT_TABLE_DEFAULT)
        fib.vrf_id = 0;
    else if (rtm->rtm_table <= MAX_VRF_ID)
        fib.vrf_id = (uint8_t)rtm->rtm_table;
    else
        fib.vrf_id = 0;

    /* Set flags based on route type */
    if (rtm->rtm_type == RTN_BLACKHOLE)
        fib.flags |= 0x02;   /* bit1 = blackhole */

    /* Parse route attributes */
    rta = RTM_RTA(rtm);
    rta_len = RTM_PAYLOAD(nlh);

    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        switch (rta->rta_type) {
        case RTA_DST:
            memcpy(&fib.dst_ip, RTA_DATA(rta), 4);
            fib.dst_ip = ntohl(fib.dst_ip);
            break;
        case RTA_GATEWAY:
            memcpy(&fib.next_hop, RTA_DATA(rta), 4);
            fib.next_hop = ntohl(fib.next_hop);
            break;
        case RTA_OIF: {
            int oif = *(int *)RTA_DATA(rta);
            fib.egress_port = ifindex_to_port(oif);
            break;
        }
        case RTA_TABLE:
            /* 32-bit table ID for tables > 255 */
            if (*(uint32_t *)RTA_DATA(rta) <= MAX_VRF_ID)
                fib.vrf_id = (uint8_t)(*(uint32_t *)RTA_DATA(rta));
            break;
        }
    }

    /* Connected routes (no gateway) */
    if (fib.next_hop == 0 && rtm->rtm_type == RTN_UNICAST)
        fib.flags |= 0x01;   /* bit0 = connected */

    if (nlh->nlmsg_type == RTM_NEWROUTE)
        fpga_fib_add(&fib);
    else if (nlh->nlmsg_type == RTM_DELROUTE)
        fpga_fib_del(&fib);
}

/* ============================================================
 * Netlink neighbor message parser
 * ============================================================ */
static void handle_neigh_msg(struct nlmsghdr *nlh)
{
    struct ndmsg *ndm = NLMSG_DATA(nlh);
    struct rtattr *rta;
    int rta_len;
    struct ngfw_arp_entry arp;

    /* Only handle IPv4 neighbors */
    if (ndm->ndm_family != AF_INET)
        return;

    /* Only process reachable / stale / permanent neighbors for ADD.
     * NOARP and INCOMPLETE states are not useful for FPGA. */
    memset(&arp, 0, sizeof(arp));
    arp.port = ifindex_to_port(ndm->ndm_ifindex);

    if (nlh->nlmsg_type == RTM_NEWNEIGH) {
        if (!(ndm->ndm_state & (NUD_REACHABLE | NUD_STALE |
                                 NUD_DELAY | NUD_PROBE | NUD_PERMANENT)))
            return;
        arp.valid = 1;
    } else {
        arp.valid = 0;
    }

    rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(*ndm)));
    rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ndm));

    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        switch (rta->rta_type) {
        case NDA_DST:
            memcpy(&arp.ip, RTA_DATA(rta), 4);
            arp.ip = ntohl(arp.ip);
            break;
        case NDA_LLADDR:
            if (RTA_PAYLOAD(rta) >= 6)
                memcpy(arp.mac, RTA_DATA(rta), 6);
            break;
        }
    }

    if (arp.ip == 0)
        return;

    if (nlh->nlmsg_type == RTM_NEWNEIGH)
        fpga_arp_add(&arp);
    else
        fpga_arp_del(&arp);
}

/* ============================================================
 * Netlink socket helpers
 * ============================================================ */
static int nl_open(unsigned int groups)
{
    int fd;
    struct sockaddr_nl sa;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        syslog(LOG_ERR, "socket(NETLINK_ROUTE): %s", strerror(errno));
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = groups;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        syslog(LOG_ERR, "bind(NETLINK_ROUTE): %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * nl_dump_request() — Send a RTM_GETROUTE/RTM_GETNEIGH dump request
 * to retrieve all current entries.
 */
static int nl_dump_request(int fd, int type, int family)
{
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg gen;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.gen));
    req.nlh.nlmsg_type  = type;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq   = 1;
    req.gen.rtgen_family = family;

    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        syslog(LOG_ERR, "send(NL dump %d): %s", type, strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * nl_recv_process() — Receive and process Netlink messages.
 * Returns 0 on success, -1 on error, 1 when dump is complete.
 */
static int nl_recv_process(int fd)
{
    char buf[NL_BUF_SIZE];
    struct nlmsghdr *nlh;
    ssize_t len;

    len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
        if (errno == EINTR || errno == EAGAIN)
            return 0;
        syslog(LOG_ERR, "recv(NETLINK): %s", strerror(errno));
        return -1;
    }
    if (len == 0)
        return -1;

    for (nlh = (struct nlmsghdr *)buf;
         NLMSG_OK(nlh, (unsigned int)len);
         nlh = NLMSG_NEXT(nlh, len)) {

        if (nlh->nlmsg_type == NLMSG_DONE)
            return 1;  /* dump complete */

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = NLMSG_DATA(nlh);
            if (err->error != 0) {
                syslog(LOG_ERR, "Netlink error: %s",
                       strerror(-err->error));
            }
            continue;
        }

        switch (nlh->nlmsg_type) {
        case RTM_NEWROUTE:
        case RTM_DELROUTE:
            handle_route_msg(nlh);
            break;
        case RTM_NEWNEIGH:
        case RTM_DELNEIGH:
            handle_neigh_msg(nlh);
            break;
        }
    }

    return 0;
}

/* ============================================================
 * Full synchronization at startup
 *
 * Walk all IPv4 routes and all IPv4 neighbors, pushing each
 * to the FPGA.
 * ============================================================ */
static int full_sync(void)
{
    int fd, ret, done;
    int route_count = 0, neigh_count = 0;

    fd = nl_open(0);   /* no multicast groups for dump */
    if (fd < 0)
        return -1;

    syslog(LOG_INFO, "full sync: dumping routes...");

    /* Dump all IPv4 routes */
    if (nl_dump_request(fd, RTM_GETROUTE, AF_INET) < 0)
        goto err;

    done = 0;
    while (!done) {
        ret = nl_recv_process(fd);
        if (ret < 0) goto err;
        if (ret == 1) done = 1;
        route_count++;
    }

    syslog(LOG_INFO, "full sync: dumping neighbors...");

    /* Dump all IPv4 neighbors */
    if (nl_dump_request(fd, RTM_GETNEIGH, AF_INET) < 0)
        goto err;

    done = 0;
    while (!done) {
        ret = nl_recv_process(fd);
        if (ret < 0) goto err;
        if (ret == 1) done = 1;
        neigh_count++;
    }

    close(fd);
    syslog(LOG_INFO, "full sync complete: ~%d route batches, ~%d neigh batches",
           route_count, neigh_count);
    return 0;

err:
    close(fd);
    return -1;
}

/* ============================================================
 * Main event loop
 * ============================================================ */
static int event_loop(void)
{
    int nl_fd;
    unsigned int groups = RTMGRP_IPV4_ROUTE | RTMGRP_NEIGH;

    nl_fd = nl_open(groups);
    if (nl_fd < 0)
        return -1;

    syslog(LOG_INFO, "listening for route/neighbor events...");

    while (running) {
        int ret = nl_recv_process(nl_fd);
        if (ret < 0 && running) {
            syslog(LOG_ERR, "event loop error, restarting listener");
            close(nl_fd);
            usleep(100000);   /* 100ms backoff */
            nl_fd = nl_open(groups);
            if (nl_fd < 0)
                return -1;
        }
    }

    close(nl_fd);
    return 0;
}

/* ============================================================
 * Daemonize (if not running under systemd)
 * ============================================================ */
static void daemonize(void)
{
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        exit(EXIT_SUCCESS);   /* parent exits */

    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Second fork to fully detach */
    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Redirect stdio to /dev/null */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);

    umask(0027);
    chdir("/");
}

/* ============================================================
 * Entry point
 * ============================================================ */
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-d] [-D /dev/ngfwN]\n", prog);
    fprintf(stderr, "  -d  Run in foreground (debug mode)\n");
    fprintf(stderr, "  -D  Device path (default %s)\n", DEFAULT_DEV_PATH);
}

int main(int argc, char *argv[])
{
    int opt;
    int foreground = 0;

    while ((opt = getopt(argc, argv, "dD:h")) != -1) {
        switch (opt) {
        case 'd':
            foreground = 1;
            debug_mode = 1;
            break;
        case 'D':
            dev_path = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    /* Open syslog */
    openlog("ffn_route_agent", LOG_PID | (foreground ? LOG_PERROR : 0),
            LOG_DAEMON);
    syslog(LOG_INFO, "FFN NGFW route agent starting (dev=%s)", dev_path);

    /* Open FPGA device */
    dev_fd = open(dev_path, O_RDWR);
    if (dev_fd < 0) {
        syslog(LOG_ERR, "open(%s): %s", dev_path, strerror(errno));
        fprintf(stderr, "Cannot open %s: %s\n", dev_path, strerror(errno));
        return EXIT_FAILURE;
    }

    /* Verify device is responding — read scratch register */
    {
        struct ngfw_reg_rw rw = { .offset = NGFW_REG_SCRATCH };
        if (ioctl(dev_fd, NGFW_IOC_REG_READ, &rw) < 0) {
            syslog(LOG_ERR, "FPGA not responding: %s", strerror(errno));
            close(dev_fd);
            return EXIT_FAILURE;
        }
        syslog(LOG_INFO, "FPGA scratch register: 0x%08x", rw.value);
    }

    /* Install signal handlers */
    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);
    signal(SIGHUP,  SIG_IGN);

    /* Daemonize unless running in foreground */
    if (!foreground)
        daemonize();

    /* Full synchronization: walk all existing routes + neighbors */
    if (full_sync() < 0) {
        syslog(LOG_WARNING, "full sync failed, continuing with event-only mode");
    }

    /* Notify systemd we are ready */
    sd_notify(0, "READY=1");
    syslog(LOG_INFO, "route agent ready");

    /* Main event loop */
    event_loop();

    /* Cleanup */
    syslog(LOG_INFO, "route agent shutting down");
    sd_notify(0, "STOPPING=1");
    close(dev_fd);
    closelog();

    return EXIT_SUCCESS;
}
