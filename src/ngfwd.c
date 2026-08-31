/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ngfwd — FFN NGFW Control-Plane Daemon
 *
 * Responsibilities:
 *   1. Maintain watchdog heartbeat (every 500ms) so FPGA doesn't enter
 *      AUTONOMOUS mode while the host is alive.
 *   2. Periodic stats pull (1s) → write to /run/ngfw/stats.json for
 *      Prometheus/other monitoring consumers.
 *   3. Drain syslog event ring → systemd journal.
 *   4. Drain packet capture ring → /var/log/ngfw/capture.pcap.
 *   5. Accept config via UNIX socket (/run/ngfw/ngfwd.sock):
 *      - "table-load <table_id> <file>"
 *      - "engine <id> {on|off}"
 *      - "vsys {enable|disable} <id>"
 *      - etc.
 *   6. On SIGTERM: flush capture, log shutdown, exit cleanly.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "ngfw/ngfw.h"

#define SOCKET_PATH     "/run/ngfw/ngfwd.sock"
#define STATS_PATH      "/run/ngfw/stats.json"
#define PIDFILE_PATH    "/run/ngfw/ngfwd.pid"
#define CAPTURE_PATH    "/var/log/ngfw/capture.pcap"

static volatile sig_atomic_t g_stop = 0;
static ngfw_handle_t *g_hw = NULL;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void setup_signals(void)
{
    struct sigaction sa = { .sa_handler = on_signal };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static int write_pidfile(void)
{
    mkdir("/run/ngfw", 0755);
    FILE *f = fopen(PIDFILE_PATH, "w");
    if (!f) return -1;
    fprintf(f, "%d\n", getpid());
    fclose(f);
    return 0;
}

/* ============================================================
 * Watchdog thread — pet FPGA every 500ms
 * ============================================================ */
static void *wdg_thread(void *arg)
{
    (void)arg;
    while (!g_stop) {
        ngfw_wdg_heartbeat(g_hw);
        usleep(500 * 1000);  /* 500ms */
    }
    syslog(LOG_INFO, "watchdog thread exiting");
    return NULL;
}

/* ============================================================
 * Stats publisher — dump all stats to JSON every second
 * ============================================================ */
static void publish_stats(void)
{
    FILE *f = fopen(STATS_PATH ".tmp", "w");
    if (!f) return;

    struct ngfw_info info;
    ngfw_get_info(g_hw, &info);

    fprintf(f, "{\n");
    fprintf(f, "  \"timestamp\": %ld,\n", (long)time(NULL));
    fprintf(f, "  \"fpga\": {\n");
    fprintf(f, "    \"version\": \"0x%08x\",\n", info.version);
    fprintf(f, "    \"uptime_sec\": %u,\n", info.uptime_sec);
    fprintf(f, "    \"fips_approved\": %s,\n", info.fips_approved ? "true" : "false");
    fprintf(f, "    \"watchdog_state\": %u,\n", info.watchdog_state);
    fprintf(f, "    \"port_enable\": %u,\n", info.port_enable);
    fprintf(f, "    \"remap_en\": \"0x%08x\"\n", info.remap_en);
    fprintf(f, "  },\n");

    fprintf(f, "  \"ports\": [\n");
    for (int p = 0; p < 4; p++) {
        struct ngfw_port_stats ps;
        ngfw_port_stats(g_hw, p, &ps);
        fprintf(f, "    {\"port\": %d, \"rx_pkts\": %lu, \"rx_bytes\": %lu, "
                   "\"rx_drops\": %lu, \"tx_pkts\": %lu, \"tx_bytes\": %lu, "
                   "\"tx_drops\": %lu}%s\n",
                p, ps.rx_packets, ps.rx_bytes, ps.rx_drops,
                ps.tx_packets, ps.tx_bytes, ps.tx_drops,
                (p == 3) ? "" : ",");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);

    rename(STATS_PATH ".tmp", STATS_PATH);
}

static void *stats_thread(void *arg)
{
    (void)arg;
    while (!g_stop) {
        publish_stats();
        sleep(1);
    }
    return NULL;
}

/* ============================================================
 * Syslog drain — pull FPGA security events → journal
 * ============================================================ */
static void *syslog_thread(void *arg)
{
    (void)arg;
    /* TODO: mmap the syslog ring from DMA BAR, track head pointer */
    while (!g_stop) {
        sleep(5);
    }
    return NULL;
}

/* ============================================================
 * Control socket — accept commands from ngfwctl
 * ============================================================ */
static int handle_command(int cfd, char *line)
{
    char reply[256];
    char *cmd = strtok(line, " \t\n");
    if (!cmd) return 0;

    if (strcmp(cmd, "status") == 0) {
        struct ngfw_info info;
        ngfw_get_info(g_hw, &info);
        snprintf(reply, sizeof(reply),
                 "OK version=0x%08x uptime=%us fips_approved=%d\n",
                 info.version, info.uptime_sec, info.fips_approved);
    }
    else if (strcmp(cmd, "engine") == 0) {
        char *id_s = strtok(NULL, " \t\n");
        char *op   = strtok(NULL, " \t\n");
        if (!id_s || !op) {
            snprintf(reply, sizeof(reply), "ERR usage: engine <0..15> {on|off}\n");
        } else {
            int id = atoi(id_s);
            bool on = strcmp(op, "on") == 0;
            if (ngfw_engine_enable(g_hw, id, on) == NGFW_OK)
                snprintf(reply, sizeof(reply), "OK engine %d %s\n", id, op);
            else
                snprintf(reply, sizeof(reply), "ERR %s\n", ngfw_strerror(g_hw));
        }
    }
    else if (strcmp(cmd, "ddos") == 0) {
        char *op = strtok(NULL, " \t\n");
        if (op) {
            ngfw_ddos_enable(g_hw, strcmp(op, "on") == 0);
            snprintf(reply, sizeof(reply), "OK ddos %s\n", op);
        } else {
            snprintf(reply, sizeof(reply), "ERR usage: ddos {on|off}\n");
        }
    }
    else if (strcmp(cmd, "fips-zeroize") == 0) {
        ngfw_fips_zeroize(g_hw);
        snprintf(reply, sizeof(reply), "OK zeroized\n");
        syslog(LOG_WARNING, "FIPS zeroize invoked via socket");
    }
    else if (strcmp(cmd, "fips-post") == 0) {
        ngfw_fips_post_trigger(g_hw);
        snprintf(reply, sizeof(reply), "OK POST triggered\n");
    }
    else if (strcmp(cmd, "port-enable") == 0) {
        char *mask_s = strtok(NULL, " \t\n");
        if (mask_s) {
            uint8_t mask = strtoul(mask_s, NULL, 0);
            ngfw_port_enable(g_hw, mask);
            snprintf(reply, sizeof(reply), "OK port_enable=0x%x\n", mask);
        } else {
            snprintf(reply, sizeof(reply), "ERR usage: port-enable <mask>\n");
        }
    }
    else if (strcmp(cmd, "table-write") == 0) {
        char *t = strtok(NULL, " \t\n");
        char *i = strtok(NULL, " \t\n");
        char *d = strtok(NULL, " \t\n");
        if (!t || !i || !d) {
            snprintf(reply, sizeof(reply), "ERR usage: table-write <id> <idx> <hex>\n");
        } else {
            uint8_t  tbl  = strtoul(t, NULL, 0);
            uint16_t idx  = strtoul(i, NULL, 0);
            uint64_t data = strtoull(d, NULL, 0);
            ngfw_tbl_write(g_hw, tbl, idx, data);
            snprintf(reply, sizeof(reply), "OK table=%u idx=%u data=0x%lx\n", tbl, idx, data);
        }
    }
    else if (strcmp(cmd, "quit") == 0) {
        return -1;
    }
    else {
        snprintf(reply, sizeof(reply), "ERR unknown command '%s'\n", cmd);
    }

    write(cfd, reply, strlen(reply));
    return 0;
}

static void *sock_thread(void *arg)
{
    (void)arg;
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        syslog(LOG_ERR, "socket: %s", strerror(errno));
        return NULL;
    }

    unlink(SOCKET_PATH);
    struct sockaddr_un sa = { .sun_family = AF_UNIX };
    strncpy(sa.sun_path, SOCKET_PATH, sizeof(sa.sun_path) - 1);
    if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        syslog(LOG_ERR, "bind: %s", strerror(errno));
        close(sfd);
        return NULL;
    }
    chmod(SOCKET_PATH, 0660);
    listen(sfd, 5);

    while (!g_stop) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; break; }
        char buf[1024];
        ssize_t n;
        while ((n = read(cfd, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = 0;
            if (handle_command(cfd, buf) < 0) break;
        }
        close(cfd);
    }

    close(sfd);
    unlink(SOCKET_PATH);
    return NULL;
}

/* ============================================================
 * Main
 * ============================================================ */
int main(int argc, char **argv)
{
    int foreground = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) foreground = 1;
    }

    openlog("ngfwd", LOG_PID | (foreground ? LOG_PERROR : 0), LOG_DAEMON);
    syslog(LOG_INFO, "ngfwd starting");

    g_hw = ngfw_open();
    if (!g_hw) {
        syslog(LOG_ERR, "cannot open %s — is ffn_ngfw.ko loaded?", NGFW_DEVICE_PATH);
        return 1;
    }

    struct ngfw_info info;
    ngfw_get_info(g_hw, &info);
    syslog(LOG_INFO, "FPGA version 0x%08x, uptime %us, FIPS approved=%d",
           info.version, info.uptime_sec, info.fips_approved);

    if (!info.fips_approved) {
        syslog(LOG_WARNING, "FIPS not in APPROVED state — triggering POST");
        ngfw_fips_post_trigger(g_hw);
    }

    setup_signals();
    write_pidfile();

    /* Set watchdog timeout to 5 seconds */
    ngfw_wdg_set_timeout(g_hw, 5000);

    pthread_t t_wdg, t_stats, t_syslog, t_sock;
    pthread_create(&t_wdg,    NULL, wdg_thread,    NULL);
    pthread_create(&t_stats,  NULL, stats_thread,  NULL);
    pthread_create(&t_syslog, NULL, syslog_thread, NULL);
    pthread_create(&t_sock,   NULL, sock_thread,   NULL);

    syslog(LOG_INFO, "ngfwd ready (socket %s)", SOCKET_PATH);

    /* Wait for shutdown */
    while (!g_stop) pause();

    syslog(LOG_INFO, "ngfwd shutting down");
    pthread_join(t_wdg,    NULL);
    pthread_join(t_stats,  NULL);
    pthread_join(t_syslog, NULL);
    pthread_join(t_sock,   NULL);

    ngfw_close(g_hw);
    unlink(PIDFILE_PATH);
    closelog();
    return 0;
}
