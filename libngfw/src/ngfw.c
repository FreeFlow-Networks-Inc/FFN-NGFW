/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libngfw — implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "ngfw/ngfw.h"

struct ngfw_handle {
    int  fd;
    char errbuf[256];
};

static void set_err(ngfw_handle_t *h, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(h->errbuf, sizeof(h->errbuf), fmt, ap);
    va_end(ap);
}

ngfw_handle_t *ngfw_open(void)
{
    return ngfw_open_path(NGFW_DEVICE_PATH);
}

ngfw_handle_t *ngfw_open_path(const char *path)
{
    ngfw_handle_t *h = calloc(1, sizeof(*h));
    if (!h) return NULL;

    h->fd = open(path, O_RDWR);
    if (h->fd < 0) {
        free(h);
        return NULL;
    }
    return h;
}

void ngfw_close(ngfw_handle_t *h)
{
    if (!h) return;
    if (h->fd >= 0) close(h->fd);
    free(h);
}

const char *ngfw_strerror(const ngfw_handle_t *h)
{
    return h ? h->errbuf : "null handle";
}

/* ============================================================
 * Register access
 * ============================================================ */
ngfw_err_t ngfw_reg_read(ngfw_handle_t *h, uint32_t off, uint32_t *val)
{
    struct ngfw_reg_rw rw = { .offset = off };
    if (ioctl(h->fd, NGFW_IOC_REG_READ, &rw) < 0) {
        set_err(h, "reg_read(0x%x): %s", off, strerror(errno));
        return NGFW_ERR_IOCTL;
    }
    *val = rw.value;
    return NGFW_OK;
}

ngfw_err_t ngfw_reg_write(ngfw_handle_t *h, uint32_t off, uint32_t val)
{
    struct ngfw_reg_rw rw = { .offset = off, .value = val };
    if (ioctl(h->fd, NGFW_IOC_REG_WRITE, &rw) < 0) {
        set_err(h, "reg_write(0x%x,0x%x): %s", off, val, strerror(errno));
        return NGFW_ERR_IOCTL;
    }
    return NGFW_OK;
}

/* ============================================================
 * Info
 * ============================================================ */
ngfw_err_t ngfw_get_info(ngfw_handle_t *h, struct ngfw_info *info)
{
    uint32_t v;
    memset(info, 0, sizeof(*info));

    if (ngfw_reg_read(h, NGFW_REG_VERSION, &info->version) < 0) return NGFW_ERR_IOCTL;
    ngfw_reg_read(h, NGFW_REG_SCRATCH, &info->scratch);
    ngfw_reg_read(h, NGFW_REG_REMAP_EN, &info->remap_en);
    ngfw_reg_read(h, NGFW_REG_PORT_EN, &info->port_enable);

    ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_ID, &info->crypto_id);
    ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_CAPABILITIES, &info->crypto_caps);

    ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_FIPS_STATUS, &v);
    info->fips_state = v & 0x7;
    info->fips_approved = (v >> 3) & 0x1;

    ngfw_reg_read(h, NGFW_REG_WDG_BASE + NGFW_WDG_STATE, &v);
    info->watchdog_state = v & 0xFF;
    ngfw_reg_read(h, NGFW_REG_WDG_BASE + NGFW_WDG_UPTIME_SEC, &info->uptime_sec);

    return NGFW_OK;
}

/* ============================================================
 * Engine control
 * ============================================================ */
static ngfw_err_t set_bit(ngfw_handle_t *h, uint32_t reg, uint32_t bit, bool on)
{
    uint32_t v;
    ngfw_err_t r = ngfw_reg_read(h, reg, &v);
    if (r != NGFW_OK) return r;
    v = on ? (v | bit) : (v & ~bit);
    return ngfw_reg_write(h, reg, v);
}

ngfw_err_t ngfw_engine_enable(ngfw_handle_t *h, uint8_t stage_id, bool on)
{
    if (stage_id > 15) { set_err(h, "stage_id > 15"); return NGFW_ERR_INVALID_ARG; }
    return set_bit(h, NGFW_REG_REMAP_EN, NGFW_REMAP_EN_STAGE(stage_id), on);
}

ngfw_err_t ngfw_ddos_enable(ngfw_handle_t *h, bool on)
{
    return set_bit(h, NGFW_REG_REMAP_EN, NGFW_REMAP_EN_DDOS, on);
}

ngfw_err_t ngfw_rate_limit_enable(ngfw_handle_t *h, bool on)
{
    return set_bit(h, NGFW_REG_REMAP_EN, NGFW_REMAP_EN_RATE_LIMIT, on);
}

ngfw_err_t ngfw_qos_enable(ngfw_handle_t *h, bool on)
{
    return set_bit(h, NGFW_REG_REMAP_EN, NGFW_REMAP_EN_QOS, on);
}

ngfw_err_t ngfw_port_enable(ngfw_handle_t *h, uint8_t mask)
{
    return ngfw_reg_write(h, NGFW_REG_PORT_EN, mask & 0xF);
}

ngfw_err_t ngfw_set_interface_mode(ngfw_handle_t *h, uint8_t mode)
{
    return ngfw_reg_write(h, NGFW_REG_INTERFACE_MODE, mode);
}

ngfw_err_t ngfw_set_bypass_mode(ngfw_handle_t *h, uint8_t mode)
{
    uint32_t v;
    if (mode > 2) return NGFW_ERR_INVALID_ARG;
    ngfw_reg_read(h, NGFW_REG_OFFLOAD_CTRL, &v);
    v = (v & ~0x60) | ((mode & 0x3) << 5);    /* bits [6:5] */
    return ngfw_reg_write(h, NGFW_REG_OFFLOAD_CTRL, v);
}

/* ============================================================
 * Table programming
 * ============================================================ */
ngfw_err_t ngfw_tbl_write(ngfw_handle_t *h, uint8_t tbl, uint16_t idx, uint64_t data)
{
    struct ngfw_tbl_write tw = { .table_id = tbl, .index = idx, .data = data };
    if (ioctl(h->fd, NGFW_IOC_TBL_WRITE, &tw) < 0) {
        set_err(h, "tbl_write(%u,%u): %s", tbl, idx, strerror(errno));
        return NGFW_ERR_IOCTL;
    }
    return NGFW_OK;
}

ngfw_err_t ngfw_tbl_load(ngfw_handle_t *h, uint8_t tbl,
                         const uint64_t *entries, uint16_t n)
{
    for (uint16_t i = 0; i < n; i++) {
        ngfw_err_t r = ngfw_tbl_write(h, tbl, i, entries[i]);
        if (r != NGFW_OK) return r;
    }
    return NGFW_OK;
}

/* ============================================================
 * Stats
 * ============================================================ */
ngfw_err_t ngfw_stats_read(ngfw_handle_t *h, uint16_t idx, uint64_t *val)
{
    struct ngfw_stats_read sr = { .index = idx };
    if (ioctl(h->fd, NGFW_IOC_STATS_READ, &sr) < 0) {
        set_err(h, "stats_read(%u): %s", idx, strerror(errno));
        return NGFW_ERR_IOCTL;
    }
    *val = sr.value;
    return NGFW_OK;
}

ngfw_err_t ngfw_stats_clear(ngfw_handle_t *h)
{
    return ngfw_reg_write(h, NGFW_REG_STATS_CLEAR, 1);
}

ngfw_err_t ngfw_port_stats(ngfw_handle_t *h, uint8_t p, struct ngfw_port_stats *o)
{
    if (p > 3) return NGFW_ERR_INVALID_ARG;
    uint16_t base = 16 + p * 8;
    ngfw_stats_read(h, base + 0, &o->rx_packets);
    ngfw_stats_read(h, base + 1, &o->rx_bytes);
    ngfw_stats_read(h, base + 2, &o->rx_drops);
    ngfw_stats_read(h, base + 3, &o->tx_packets);
    ngfw_stats_read(h, base + 4, &o->tx_bytes);
    ngfw_stats_read(h, base + 5, &o->tx_drops);
    return NGFW_OK;
}

ngfw_err_t ngfw_zone_stats(ngfw_handle_t *h, uint16_t z, struct ngfw_zone_stats *o)
{
    if (z >= 256) return NGFW_ERR_INVALID_ARG;
    uint16_t base = 256 + z * 6;
    ngfw_stats_read(h, base + 0, &o->pps);
    ngfw_stats_read(h, base + 1, &o->bps);
    ngfw_stats_read(h, base + 2, &o->syn);
    ngfw_stats_read(h, base + 3, &o->conn);
    ngfw_stats_read(h, base + 4, &o->udp_amp);
    ngfw_stats_read(h, base + 5, &o->frag);
    return NGFW_OK;
}

/* ============================================================
 * Crypto / FIPS
 * ============================================================ */
ngfw_err_t ngfw_crypto_key_set(ngfw_handle_t *h, ngfw_key_size_t ksz,
                                const uint8_t *key)
{
    struct ngfw_key_write kw = { .key_size = ksz };
    int n = (ksz == NGFW_KEY_AES128) ? 16 :
            (ksz == NGFW_KEY_AES192) ? 24 : 32;
    memcpy(kw.key, key, n);
    if (ioctl(h->fd, NGFW_IOC_KEY_WRITE, &kw) < 0) {
        set_err(h, "key_write: %s", strerror(errno));
        return NGFW_ERR_IOCTL;
    }
    return NGFW_OK;
}

ngfw_err_t ngfw_crypto_enable_modes(ngfw_handle_t *h, uint16_t mask)
{
    return ngfw_reg_write(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_ENABLE, mask);
}

ngfw_err_t ngfw_fips_post_trigger(ngfw_handle_t *h)
{
    if (ioctl(h->fd, NGFW_IOC_POST_TRIGGER) < 0) return NGFW_ERR_IOCTL;
    return NGFW_OK;
}

ngfw_err_t ngfw_fips_zeroize(ngfw_handle_t *h)
{
    if (ioctl(h->fd, NGFW_IOC_FIPS_ZEROIZE) < 0) return NGFW_ERR_IOCTL;
    return NGFW_OK;
}

ngfw_err_t ngfw_fips_is_approved(ngfw_handle_t *h, bool *approved)
{
    uint32_t v;
    ngfw_err_t r = ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_FIPS_STATUS, &v);
    if (r != NGFW_OK) return r;
    *approved = (v >> 3) & 0x1;
    return NGFW_OK;
}

ngfw_err_t ngfw_drbg_get(ngfw_handle_t *h, uint32_t *out)
{
    uint32_t status;
    /* Request fresh bytes */
    ngfw_reg_write(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_DRBG_REQ_DATA, 1);
    /* Poll for valid */
    for (int i = 0; i < 100; i++) {
        ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_DRBG_STATUS, &status);
        if (status & 1) break;
        usleep(1);
    }
    if (!(status & 1)) { set_err(h, "DRBG timeout"); return NGFW_ERR_NOT_READY; }
    return ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_DRBG_REQ_DATA, out);
}

ngfw_err_t ngfw_sha256_block(ngfw_handle_t *h, const uint8_t msg[64],
                              uint8_t digest[32])
{
    const uint32_t *w = (const uint32_t *)msg;
    uint32_t status, h0, h1, h2;

    /* Load 16 message words */
    for (int i = 0; i < 16; i++) {
        ngfw_reg_write(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_SHA256_MSG_0 + i * 4, w[i]);
    }
    /* Start hash */
    ngfw_reg_write(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_SHA256_STATUS, 1);

    /* Poll for done (64 rounds @ 322 MHz ≈ 200 ns) */
    for (int i = 0; i < 1000; i++) {
        ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_SHA256_STATUS, &status);
        if (status & 1) break;
        usleep(1);
    }
    if (!(status & 1)) { set_err(h, "SHA-256 timeout"); return NGFW_ERR_NOT_READY; }

    /* Read back first 3 H words (the rest go via repeated reads) */
    ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_SHA256_H0, &h0);
    ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_SHA256_H1, &h1);
    ngfw_reg_read(h, NGFW_REG_CRYPTO_BASE + NGFW_CR_SHA256_H2, &h2);

    memcpy(digest + 0,  &h0, 4);
    memcpy(digest + 4,  &h1, 4);
    memcpy(digest + 8,  &h2, 4);
    /* digest[12..31] would need additional SHA256_H3..H7 registers */
    return NGFW_OK;
}

/* ============================================================
 * VSYS
 * ============================================================ */
ngfw_err_t ngfw_vsys_set_max(ngfw_handle_t *h, uint16_t max)
{
    return ngfw_reg_write(h, NGFW_REG_VSYS_LICENSE_MAX, max);
}

ngfw_err_t ngfw_vsys_enable(ngfw_handle_t *h, uint16_t id, bool on)
{
    if (id >= 256) return NGFW_ERR_INVALID_ARG;
    uint32_t reg = NGFW_REG_VSYS_ENABLE_0 + (id / 32) * 4;
    uint32_t mask = 1u << (id % 32);
    return set_bit(h, reg, mask, on);
}

ngfw_err_t ngfw_vsys_active_count(ngfw_handle_t *h, uint16_t *count)
{
    uint32_t v;
    ngfw_err_t r = ngfw_reg_read(h, NGFW_REG_VSYS_ACTIVE_COUNT, &v);
    if (r == NGFW_OK) *count = v & 0xFFFF;
    return r;
}

/* ============================================================
 * Watchdog
 * ============================================================ */
ngfw_err_t ngfw_wdg_heartbeat(ngfw_handle_t *h)
{
    return ngfw_reg_write(h, NGFW_REG_WDG_BASE + NGFW_WDG_HEARTBEAT, 1);
}

ngfw_err_t ngfw_wdg_set_timeout(ngfw_handle_t *h, uint32_t timeout_ms)
{
    return ngfw_reg_write(h, NGFW_REG_WDG_BASE + NGFW_WDG_TIMEOUT_MS, timeout_ms);
}

ngfw_err_t ngfw_wdg_recover(ngfw_handle_t *h, uint32_t auth_key)
{
    ngfw_reg_write(h, NGFW_REG_WDG_BASE + NGFW_WDG_AUTH_KEY, auth_key);
    return ngfw_reg_write(h, NGFW_REG_WDG_BASE + NGFW_WDG_RECOVER, 1);
}

ngfw_err_t ngfw_wdg_get_state(ngfw_handle_t *h, uint8_t *state,
                               uint32_t *missed, bool *locked)
{
    uint32_t v;
    ngfw_reg_read(h, NGFW_REG_WDG_BASE + NGFW_WDG_STATE, &v);
    *state = v & 0xFF;
    ngfw_reg_read(h, NGFW_REG_WDG_BASE + NGFW_WDG_MISSED_COUNT, missed);
    ngfw_reg_read(h, NGFW_REG_WDG_BASE + NGFW_WDG_CONFIG_LOCKED, &v);
    *locked = v & 1;
    return NGFW_OK;
}

/* ============================================================
 * DMA mmap
 * ============================================================ */
void *ngfw_dma_mmap(ngfw_handle_t *h, size_t length, off_t offset)
{
    return mmap(NULL, length, PROT_READ, MAP_SHARED, h->fd, offset);
}

int ngfw_dma_munmap(void *addr, size_t length)
{
    return munmap(addr, length);
}

/* ============================================================
 * DDR4 region helpers
 * ============================================================ */
#include <sys/stat.h>

static const struct {
    uint32_t id;
    const char *name;
} ddr_region_names[] = {
    { NGFW_RGN_SESSIONS,    "sessions"    },
    { NGFW_RGN_CONNTRACK,   "conntrack"   },
    { NGFW_RGN_PKTCAP,      "pktcap"      },
    { NGFW_RGN_SYSLOG,      "syslog"      },
    { NGFW_RGN_FLOWSTATS,   "flowstats"   },
    { NGFW_RGN_PKTBUF,      "pktbuf"      },
    { NGFW_RGN_GEOIP,       "geoip"       },
    { NGFW_RGN_BLOCKLIST,   "blocklist"   },
    { NGFW_RGN_URL,         "url"         },
    { NGFW_RGN_APPID_EXT,   "appid"       },
    { NGFW_RGN_THREATS,     "threats"     },
    { NGFW_RGN_MALWARE,     "malware"     },
    { NGFW_RGN_FILEMAGIC,   "filemagic"   },
    { NGFW_RGN_TLSFP,       "tlsfp"       },
    { NGFW_RGN_DNSBL,       "dnsbl"       },
    { NGFW_RGN_SPYWARE,     "spyware"     },
    { NGFW_RGN_VSYS_POLICY, "vsys_policy" },
    { NGFW_RGN_USER_POLICY, "user_policy" },
};

int ngfw_ddr_region_from_name(const char *name)
{
    for (size_t i = 0; i < sizeof(ddr_region_names)/sizeof(ddr_region_names[0]); i++)
        if (strcmp(ddr_region_names[i].name, name) == 0)
            return (int)ddr_region_names[i].id;
    return -1;
}

const char *ngfw_ddr_region_name(uint32_t region)
{
    for (size_t i = 0; i < sizeof(ddr_region_names)/sizeof(ddr_region_names[0]); i++)
        if (ddr_region_names[i].id == region)
            return ddr_region_names[i].name;
    return "unknown";
}

ngfw_err_t ngfw_ddr_write(ngfw_handle_t *h, uint32_t region, uint64_t offset,
                          const void *src, uint64_t length)
{
    struct ngfw_ddr_xfer xfer = {
        .region = region,
        .offset = offset,
        .length = length,
        .buf = (uint8_t *)(uintptr_t)src,
    };
    if (ioctl(h->fd, NGFW_IOC_DDR_WRITE, &xfer) < 0) {
        set_err(h, "ddr_write region=%u: %s", region, strerror(errno));
        return NGFW_ERR_IOCTL;
    }
    return NGFW_OK;
}

ngfw_err_t ngfw_ddr_read(ngfw_handle_t *h, uint32_t region, uint64_t offset,
                         void *dst, uint64_t length)
{
    struct ngfw_ddr_xfer xfer = {
        .region = region,
        .offset = offset,
        .length = length,
        .buf = dst,
    };
    if (ioctl(h->fd, NGFW_IOC_DDR_READ, &xfer) < 0) {
        set_err(h, "ddr_read region=%u: %s", region, strerror(errno));
        return NGFW_ERR_IOCTL;
    }
    return NGFW_OK;
}

ngfw_err_t ngfw_ddr_region_info(ngfw_handle_t *h, uint32_t region,
                                 uint64_t *base, uint64_t *size)
{
    struct ngfw_ddr_xfer xfer = { .region = region };
    if (ioctl(h->fd, NGFW_IOC_DDR_REGION_INFO, &xfer) < 0)
        return NGFW_ERR_IOCTL;
    if (base) *base = xfer.offset;
    if (size) *size = xfer.length;
    return NGFW_OK;
}

ngfw_err_t ngfw_ddr_load_file(ngfw_handle_t *h, uint32_t region, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { set_err(h, "open %s: %s", path, strerror(errno)); return NGFW_ERR_OPEN; }

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NGFW_ERR_IOCTL; }

    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { set_err(h, "mmap %s: %s", path, strerror(errno)); return NGFW_ERR_OPEN; }

    /* Chunk the write to avoid huge ioctls (max 16 MB per call) */
    const uint64_t CHUNK = 16ULL << 20;
    uint64_t off = 0;
    while (off < (uint64_t)st.st_size) {
        uint64_t n = (st.st_size - off > CHUNK) ? CHUNK : (st.st_size - off);
        ngfw_err_t r = ngfw_ddr_write(h, region, off, (uint8_t *)map + off, n);
        if (r != NGFW_OK) { munmap(map, st.st_size); return r; }
        off += n;
    }
    munmap(map, st.st_size);
    return NGFW_OK;
}
