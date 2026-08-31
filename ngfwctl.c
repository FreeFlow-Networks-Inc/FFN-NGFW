/*
 * ngfwctl.c — FFN-NGFW-FPGA command-line control tool
 *
 * Usage:
 *   ngfwctl status                          # show link/heartbeat/DDR status
 *   ngfwctl port enable 0 1 2 3             # enable ports 0-3
 *   ngfwctl port disable 3                  # disable port 3
 *   ngfwctl engine list                     # show all engines + enable state
 *   ngfwctl engine enable appid             # enable App-ID engine
 *   ngfwctl engine disable tls_decrypt      # disable TLS decryption
 *   ngfwctl mode l3                         # set L3 route mode
 *   ngfwctl ddos threshold 0 syn 500000     # zone 0: 500k SYN/sec limit
 *   ngfwctl ddos blocklist add 10.0.0.1     # blackhole an IP
 *   ngfwctl db load appid /etc/ngfw/appid.db
 *   ngfwctl db load threats /etc/ngfw/threats.db
 *   ngfwctl stats show                      # dump all counters
 *   ngfwctl stats clear                     # reset all counters
 *
 * Build:
 *   gcc -O2 -o ngfwctl ngfwctl.c -Wall
 *
 * Requires:
 *   - PCIe BAR2 accessible via sysfs resource file
 *   - Root or CAP_SYS_RAWIO for mmap of PCI resources
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include "ngfw_regs.h"

/* Default PCIe BDF — override with NGFW_PCI_BDF env var */
#define DEFAULT_PCI_BDF "0000:d8:00.0"
#define PCI_RESOURCE    "resource2"

static volatile uint32_t *regs = NULL;
static int bar_fd = -1;

/* ============================================================
 * PCIe BAR mapping
 * ============================================================ */
static int ngfw_open(void) {
    const char *bdf = getenv("NGFW_PCI_BDF");
    if (!bdf) bdf = DEFAULT_PCI_BDF;

    char path[256];
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/%s", bdf, PCI_RESOURCE);

    bar_fd = open(path, O_RDWR | O_SYNC);
    if (bar_fd < 0) {
        perror(path);
        fprintf(stderr, "Hint: set NGFW_PCI_BDF=XXXX:XX:XX.X or run as root\n");
        return -1;
    }

    regs = mmap(NULL, NGFW_BAR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, bar_fd, 0);
    if (regs == MAP_FAILED) {
        perror("mmap");
        close(bar_fd);
        return -1;
    }
    return 0;
}

static void ngfw_close(void) {
    if (regs && regs != MAP_FAILED) munmap((void *)regs, NGFW_BAR_SIZE);
    if (bar_fd >= 0) close(bar_fd);
}

/* ============================================================
 * Engine name <-> bit mapping
 * ============================================================ */
static const struct { const char *name; uint32_t bit; } engines[] = {
    { "iface_class",   NGFW_EN_IFACE_CLASS },
    { "session",       NGFW_EN_SESSION },
    { "nat",           NGFW_EN_NAT },
    { "sec_policy",    NGFW_EN_SEC_POLICY },
    { "appid",         NGFW_EN_APPID },
    { "proto_decode",  NGFW_EN_PROTO_DECODE },
    { "cid_threat",    NGFW_EN_CID_THREAT },
    { "cid_malware",   NGFW_EN_CID_MALWARE },
    { "cid_url",       NGFW_EN_CID_URL },
    { "cid_file",      NGFW_EN_CID_FILE },
    { "cid_spyware",   NGFW_EN_CID_SPYWARE },
    { "user_policy",   NGFW_EN_USER_POLICY },
    { "app_policy",    NGFW_EN_APP_POLICY },
    { "tls_decrypt",   NGFW_EN_TLS_DECRYPT },
    { "tls_inspect",   NGFW_EN_TLS_INSPECT },
    { "tls_reencrypt", NGFW_EN_TLS_REENCRYPT },
    { "ddos",          NGFW_EN_DDOS },
    { "rate_limiter",  NGFW_EN_RATE_LIMITER },
    { NULL, 0 }
};

static uint32_t engine_bit(const char *name) {
    for (int i = 0; engines[i].name; i++)
        if (strcasecmp(engines[i].name, name) == 0)
            return engines[i].bit;
    return 0;
}

/* ============================================================
 * Commands
 * ============================================================ */
static void cmd_status(void) {
    uint32_t status  = ngfw_read(regs, NGFW_REG_STATUS);
    uint32_t version = ngfw_read(regs, NGFW_REG_VERSION);
    uint32_t remap   = ngfw_read(regs, NGFW_REG_REMAP_EN);
    uint32_t port_en = ngfw_read(regs, NGFW_REG_PORT_EN);
    uint32_t mode    = ngfw_read(regs, NGFW_REG_IFACE_MODE);

    printf("FFN-NGFW-FPGA Status\n");
    printf("  Version    : 0x%08X\n", version);
    printf("  Heartbeat  : %s\n", (status & NGFW_STATUS_HEARTBEAT) ? "alive" : "dead");
    printf("  DDR4 C0 cal: %s\n", (status & NGFW_STATUS_DDR0_CAL) ? "done" : "pending");
    printf("  DDR4 C1 cal: %s\n", (status & NGFW_STATUS_DDR1_CAL) ? "done" : "pending");
    printf("  Ports      :\n");
    for (int p = 0; p < 4; p++) {
        int link = (status >> (1 + p)) & 1;
        int en   = (port_en >> p) & 1;
        printf("    QSFP%d: link=%s  enable=%s\n", p,
               link ? "UP  " : "DOWN", en ? "ON " : "OFF");
    }
    static const char *mode_names[] = {"L2-bridge","L3-route","vWire","Q-in-Q","VXLAN","VSYS"};
    printf("  Mode       : %s (%d)\n", mode < 6 ? mode_names[mode] : "unknown", mode);
    printf("  REMAP_EN   : 0x%08X\n", remap);
    printf("  Engines    :\n");
    for (int i = 0; engines[i].name; i++) {
        printf("    %-16s : %s\n", engines[i].name,
               (remap & engines[i].bit) ? "ON" : "OFF");
    }
}

static void cmd_port(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: ngfwctl port <enable|disable> <port...>\n"); return; }

    uint32_t port_en = ngfw_read(regs, NGFW_REG_PORT_EN);
    int enable = (strcmp(argv[0], "enable") == 0);

    for (int i = 1; i < argc; i++) {
        int p = atoi(argv[i]);
        if (p < 0 || p > 3) { fprintf(stderr, "Invalid port: %d\n", p); continue; }
        if (enable) port_en |=  (1 << p);
        else        port_en &= ~(1 << p);
    }
    ngfw_write(regs, NGFW_REG_PORT_EN, port_en);
    printf("PORT_EN = 0x%X\n", port_en);
}

static void cmd_engine(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "Usage: ngfwctl engine <list|enable|disable> [name]\n"); return; }

    if (strcmp(argv[0], "list") == 0) {
        uint32_t remap = ngfw_read(regs, NGFW_REG_REMAP_EN);
        for (int i = 0; engines[i].name; i++)
            printf("  %-16s : %s\n", engines[i].name,
                   (remap & engines[i].bit) ? "ON" : "OFF");
        return;
    }

    if (argc < 2) { fprintf(stderr, "Usage: ngfwctl engine <enable|disable> <name>\n"); return; }
    int enable = (strcmp(argv[0], "enable") == 0);
    uint32_t bit = engine_bit(argv[1]);
    if (!bit) { fprintf(stderr, "Unknown engine: %s\n", argv[1]); return; }

    uint32_t remap = ngfw_read(regs, NGFW_REG_REMAP_EN);
    if (enable) remap |= bit; else remap &= ~bit;
    ngfw_write(regs, NGFW_REG_REMAP_EN, remap);
    printf("REMAP_EN = 0x%08X  (%s %s)\n", remap,
           enable ? "enabled" : "disabled", argv[1]);
}

static void cmd_mode(const char *mode_str) {
    static const struct { const char *name; uint8_t val; } modes[] = {
        {"l2", 0}, {"bridge", 0}, {"l3", 1}, {"route", 1},
        {"vwire", 2}, {"qinq", 3}, {"vxlan", 4}, {"vsys", 5}, {NULL, 0}
    };
    for (int i = 0; modes[i].name; i++) {
        if (strcasecmp(modes[i].name, mode_str) == 0) {
            ngfw_write(regs, NGFW_REG_IFACE_MODE, modes[i].val);
            printf("INTERFACE_MODE = %d (%s)\n", modes[i].val, mode_str);
            return;
        }
    }
    fprintf(stderr, "Unknown mode: %s (valid: l2, l3, vwire, qinq, vxlan, vsys)\n", mode_str);
}

static void cmd_db_load(const char *table_name, const char *path) {
    /* Database file format: binary, each entry is:
     *   uint16_t index
     *   uint64_t data
     * (10 bytes per entry, little-endian) */

    uint8_t tbl;
    if      (strcmp(table_name, "appid") == 0)       tbl = NGFW_TBL_APPID;
    else if (strcmp(table_name, "threats") == 0)      tbl = NGFW_TBL_CID_THREAT;
    else if (strcmp(table_name, "url") == 0)          tbl = NGFW_TBL_CID_URL;
    else if (strcmp(table_name, "spyware") == 0)      tbl = NGFW_TBL_CID_SPYWARE;
    else if (strcmp(table_name, "policy") == 0)       tbl = NGFW_TBL_SEC_POLICY;
    else if (strcmp(table_name, "user_policy") == 0)  tbl = NGFW_TBL_USER_POLICY;
    else if (strcmp(table_name, "app_policy") == 0)   tbl = NGFW_TBL_APP_POLICY;
    else if (strcmp(table_name, "geoip") == 0)        tbl = NGFW_TBL_DDOS_GEOIP;
    else if (strcmp(table_name, "blocklist") == 0)    tbl = NGFW_TBL_DDOS_IP_BLOCKLIST;
    else { fprintf(stderr, "Unknown table: %s\n", table_name); return; }

    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return; }

    int count = 0;
    uint16_t index;
    uint64_t data;
    while (fread(&index, 2, 1, f) == 1 && fread(&data, 8, 1, f) == 1) {
        ngfw_table_write(regs, tbl, index, data);
        count++;
    }
    fclose(f);
    printf("Loaded %d entries into table '%s' from %s\n", count, table_name, path);
}

static void cmd_ddos_threshold(int zone, const char *counter, uint32_t value) {
    /* Counter offsets within zone: pps=0, bps=1, syn=2, conn=3, udp_amp=4, frag=5 */
    int ctr_off;
    if      (strcmp(counter, "pps") == 0)     ctr_off = 0;
    else if (strcmp(counter, "bps") == 0)     ctr_off = 1;
    else if (strcmp(counter, "syn") == 0)     ctr_off = 2;
    else if (strcmp(counter, "conn") == 0)    ctr_off = 3;
    else if (strcmp(counter, "udp_amp") == 0) ctr_off = 4;
    else if (strcmp(counter, "frag") == 0)    ctr_off = 5;
    else { fprintf(stderr, "Unknown counter: %s\n", counter); return; }

    uint16_t index = zone * 6 + ctr_off;
    ngfw_table_write(regs, NGFW_TBL_DDOS_THRESHOLDS, index, value);
    printf("Zone %d %s threshold = %u\n", zone, counter, value);
}

static void cmd_ddos_blocklist_add(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", ip_str); return;
    }
    uint32_t ip = ntohl(addr.s_addr);
    uint16_t hash = (ip & 0xFFF) ^ ((ip >> 12) & 0xFFF) ^ ((ip >> 20) & 0xFFF);
    uint64_t entry = ((uint64_t)1 << 32) | ip;  /* valid=1, ip=32 bits */
    ngfw_table_write(regs, NGFW_TBL_DDOS_IP_BLOCKLIST, hash, entry);
    printf("Blocklist: added %s (hash=0x%03X)\n", ip_str, hash);
}

static void cmd_stats(const char *subcmd) {
    if (strcmp(subcmd, "clear") == 0) {
        ngfw_write(regs, NGFW_REG_STATS_CLEAR, 1);
        printf("All stats counters cleared\n");
        return;
    }

    /* show */
    static const char *engine_names[] = {
        "iface_class","session","nat","sec_policy","appid","proto_decode",
        "cid_threat","cid_malware","cid_url","cid_file","cid_spyware",
        "user_policy","app_policy","tls_decrypt","tls_inspect","tls_reencrypt"
    };

    printf("Per-engine statistics:\n");
    printf("  %-16s  %12s  %12s  %12s\n", "Engine", "Processed", "Matched", "Dropped");
    for (int e = 0; e < 16; e++) {
        /* Stats registers not yet wired for per-engine readback;
         * placeholder for when ngfw_stats_counters_v is connected */
        printf("  %-16s  %12s  %12s  %12s\n", engine_names[e], "—", "—", "—");
    }

    printf("\nPer-port statistics:\n");
    printf("  %-8s  %12s  %12s\n", "Port", "RX Packets", "RX Bytes");
    for (int p = 0; p < 4; p++) {
        printf("  QSFP%-3d  %12s  %12s\n", p, "—", "—");
    }
}

/* ============================================================
 * Main
 * ============================================================ */
static void usage(void) {
    fprintf(stderr,
        "Usage: ngfwctl <command> [args...]\n"
        "\n"
        "Commands:\n"
        "  status                              Show FPGA status\n"
        "  port <enable|disable> <port...>     Enable/disable 100G ports\n"
        "  engine <list|enable|disable> [name] Control pipeline engines\n"
        "  mode <l2|l3|vwire|qinq|vxlan|vsys> Set interface mode\n"
        "  ddos threshold <zone> <counter> <val> Set DDoS threshold\n"
        "  ddos blocklist add <ip>             Add IP to DDoS blocklist\n"
        "  db load <table> <file>              Load database into FPGA table\n"
        "  stats <show|clear>                  Show/clear statistics\n"
        "\n"
        "Environment:\n"
        "  NGFW_PCI_BDF=XXXX:XX:XX.X          Override PCIe BDF address\n"
    );
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }

    if (ngfw_open() < 0) return 1;

    if (strcmp(argv[1], "status") == 0) {
        cmd_status();
    } else if (strcmp(argv[1], "port") == 0) {
        cmd_port(argc - 2, argv + 2);
    } else if (strcmp(argv[1], "engine") == 0) {
        cmd_engine(argc - 2, argv + 2);
    } else if (strcmp(argv[1], "mode") == 0 && argc >= 3) {
        cmd_mode(argv[2]);
    } else if (strcmp(argv[1], "ddos") == 0 && argc >= 3) {
        if (strcmp(argv[2], "threshold") == 0 && argc >= 6) {
            cmd_ddos_threshold(atoi(argv[3]), argv[4], (uint32_t)strtoul(argv[5], NULL, 0));
        } else if (strcmp(argv[2], "blocklist") == 0 && argc >= 5 && strcmp(argv[3], "add") == 0) {
            cmd_ddos_blocklist_add(argv[4]);
        } else {
            fprintf(stderr, "Unknown ddos subcommand\n");
        }
    } else if (strcmp(argv[1], "db") == 0 && argc >= 5 && strcmp(argv[2], "load") == 0) {
        cmd_db_load(argv[3], argv[4]);
    } else if (strcmp(argv[1], "stats") == 0 && argc >= 3) {
        cmd_stats(argv[2]);
    } else {
        usage();
        ngfw_close();
        return 1;
    }

    ngfw_close();
    return 0;
}
