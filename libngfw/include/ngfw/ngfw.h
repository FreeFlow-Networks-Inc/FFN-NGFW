/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libngfw — High-level API for FFN NGFW FPGA
 *
 * Userspace library that sits on top of /dev/ngfw0. Provides:
 *   - Device open/close
 *   - Register read/write (typed helpers)
 *   - Engine enable/disable
 *   - Table programming (policy, sessions, zones, crypto keys)
 *   - Stats readback
 *   - FIPS 140-3 operations (zeroize, POST, DRBG, SHA-256)
 *   - VSYS licensing
 *   - Watchdog heartbeat
 *
 * Thread safety: All functions are reentrant. The kernel driver
 * serializes CSR access via internal mutex.
 */

#ifndef NGFW_H
#define NGFW_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "ngfw_regs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle */
typedef struct ngfw_handle ngfw_handle_t;

/* Error codes */
typedef enum {
    NGFW_OK              =  0,
    NGFW_ERR_OPEN        = -1,
    NGFW_ERR_IOCTL       = -2,
    NGFW_ERR_INVALID_ARG = -3,
    NGFW_ERR_NOT_READY   = -4,
    NGFW_ERR_FIPS        = -5,
    NGFW_ERR_LICENSE     = -6,
    NGFW_ERR_LOCKED      = -7,   /* watchdog config lock */
} ngfw_err_t;

/* ============================================================
 * Device lifecycle
 * ============================================================ */

/* Open the default device (/dev/ngfw0). Returns NULL on failure. */
ngfw_handle_t *ngfw_open(void);

/* Open a specific device path. */
ngfw_handle_t *ngfw_open_path(const char *path);

/* Close the handle. */
void ngfw_close(ngfw_handle_t *h);

/* Return the last error message for this handle. */
const char *ngfw_strerror(const ngfw_handle_t *h);

/* ============================================================
 * Low-level register access
 * ============================================================ */
ngfw_err_t ngfw_reg_read(ngfw_handle_t *h, uint32_t offset, uint32_t *value);
ngfw_err_t ngfw_reg_write(ngfw_handle_t *h, uint32_t offset, uint32_t value);

/* ============================================================
 * Info / status
 * ============================================================ */
struct ngfw_info {
    uint32_t version;          /* NGFW_REG_VERSION */
    uint32_t scratch;
    uint32_t crypto_id;        /* NGFW_CR_ID */
    uint32_t crypto_caps;      /* NGFW_CR_CAPABILITIES */
    uint32_t fips_state;
    bool     fips_approved;
    uint32_t watchdog_state;
    uint32_t uptime_sec;
    uint32_t port_enable;      /* 4-bit port enable mask */
    uint32_t remap_en;         /* 32-bit engine enable */
};

ngfw_err_t ngfw_get_info(ngfw_handle_t *h, struct ngfw_info *info);

/* ============================================================
 * Engine control
 * ============================================================ */
ngfw_err_t ngfw_engine_enable(ngfw_handle_t *h, uint8_t stage_id, bool on);
ngfw_err_t ngfw_ddos_enable(ngfw_handle_t *h, bool on);
ngfw_err_t ngfw_rate_limit_enable(ngfw_handle_t *h, bool on);
ngfw_err_t ngfw_qos_enable(ngfw_handle_t *h, bool on);
ngfw_err_t ngfw_port_enable(ngfw_handle_t *h, uint8_t port_mask);

/* Interface mode (L2/L3/vWire/QinQ/VXLAN/VSYS) */
ngfw_err_t ngfw_set_interface_mode(ngfw_handle_t *h, uint8_t mode);

/* L1 bypass mode: 0=normal, 1=loopback, 2=inline-cross */
ngfw_err_t ngfw_set_bypass_mode(ngfw_handle_t *h, uint8_t mode);

/* ============================================================
 * Table programming
 * ============================================================ */
ngfw_err_t ngfw_tbl_write(ngfw_handle_t *h, uint8_t table_id,
                          uint16_t index, uint64_t data);

/* Bulk-load a table from an array */
ngfw_err_t ngfw_tbl_load(ngfw_handle_t *h, uint8_t table_id,
                         const uint64_t *entries, uint16_t n_entries);

/* ============================================================
 * Stats
 * ============================================================ */
ngfw_err_t ngfw_stats_read(ngfw_handle_t *h, uint16_t index, uint64_t *value);
ngfw_err_t ngfw_stats_clear(ngfw_handle_t *h);

struct ngfw_port_stats {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t rx_drops;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_drops;
};
ngfw_err_t ngfw_port_stats(ngfw_handle_t *h, uint8_t port,
                           struct ngfw_port_stats *out);

struct ngfw_zone_stats {
    uint64_t pps;
    uint64_t bps;
    uint64_t syn;
    uint64_t conn;
    uint64_t udp_amp;
    uint64_t frag;
};
ngfw_err_t ngfw_zone_stats(ngfw_handle_t *h, uint16_t zone_id,
                           struct ngfw_zone_stats *out);

/* ============================================================
 * Crypto / FIPS
 * ============================================================ */
typedef enum {
    NGFW_KEY_AES128 = 0,
    NGFW_KEY_AES192 = 1,
    NGFW_KEY_AES256 = 2,
} ngfw_key_size_t;

ngfw_err_t ngfw_crypto_key_set(ngfw_handle_t *h,
                                ngfw_key_size_t ksz,
                                const uint8_t *key);

ngfw_err_t ngfw_crypto_enable_modes(ngfw_handle_t *h, uint16_t mask);

/* FIPS 140-3 */
ngfw_err_t ngfw_fips_post_trigger(ngfw_handle_t *h);
ngfw_err_t ngfw_fips_zeroize(ngfw_handle_t *h);
ngfw_err_t ngfw_fips_is_approved(ngfw_handle_t *h, bool *approved);

/* CTR_DRBG: get 4 bytes of random */
ngfw_err_t ngfw_drbg_get(ngfw_handle_t *h, uint32_t *out);

/* SHA-256: hash a 512-bit (64-byte) message block */
ngfw_err_t ngfw_sha256_block(ngfw_handle_t *h,
                              const uint8_t msg[64],
                              uint8_t digest[32]);

/* ============================================================
 * VSYS licensing
 * ============================================================ */
ngfw_err_t ngfw_vsys_set_max(ngfw_handle_t *h, uint16_t max);
ngfw_err_t ngfw_vsys_enable(ngfw_handle_t *h, uint16_t vsys_id, bool on);
ngfw_err_t ngfw_vsys_active_count(ngfw_handle_t *h, uint16_t *count);

/* ============================================================
 * Watchdog
 * ============================================================ */
ngfw_err_t ngfw_wdg_heartbeat(ngfw_handle_t *h);
ngfw_err_t ngfw_wdg_set_timeout(ngfw_handle_t *h, uint32_t timeout_ms);
ngfw_err_t ngfw_wdg_recover(ngfw_handle_t *h, uint32_t auth_key);
ngfw_err_t ngfw_wdg_get_state(ngfw_handle_t *h, uint8_t *state,
                               uint32_t *missed, bool *locked);

/* ============================================================
 * DMA memory (stats/pktcap/syslog rings) — mmap-based
 * ============================================================ */
void *ngfw_dma_mmap(ngfw_handle_t *h, size_t length, off_t offset);
int   ngfw_dma_munmap(void *addr, size_t length);

/* ============================================================
 * DDR4 database load/read
 * ============================================================ */

/* Write a binary buffer to a DDR4 region at offset. */
ngfw_err_t ngfw_ddr_write(ngfw_handle_t *h,
                          uint32_t region,        /* enum ngfw_ddr_region */
                          uint64_t offset,
                          const void *src,
                          uint64_t length);

/* Read from a DDR4 region. */
ngfw_err_t ngfw_ddr_read(ngfw_handle_t *h,
                         uint32_t region,
                         uint64_t offset,
                         void *dst,
                         uint64_t length);

/* Get region base + size for sanity checks. */
ngfw_err_t ngfw_ddr_region_info(ngfw_handle_t *h, uint32_t region,
                                 uint64_t *base, uint64_t *size);

/* High-level: load a full binary file into a region (offset 0). */
ngfw_err_t ngfw_ddr_load_file(ngfw_handle_t *h, uint32_t region,
                               const char *path);

/* Convert region name string to enum. */
int ngfw_ddr_region_from_name(const char *name);
const char *ngfw_ddr_region_name(uint32_t region);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NGFW_H */
