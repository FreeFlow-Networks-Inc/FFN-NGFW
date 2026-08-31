/*
 * ngfw_regs.h — FFN-NGFW-FPGA register map definitions
 *
 * This header maps to the AXI-Lite register bank exposed by
 * ngfw_remap_ctrl_v through the QDMA PCIe BAR2.
 *
 * Usage:
 *   #include "ngfw_regs.h"
 *   int fd = open("/sys/bus/pci/devices/XXXX:XX:XX.X/resource2", O_RDWR|O_SYNC);
 *   volatile uint32_t *regs = mmap(NULL, NGFW_BAR_SIZE, PROT_READ|PROT_WRITE,
 *                                  MAP_SHARED, fd, 0);
 *   regs[NGFW_REG_REMAP_EN / 4] = 0x0001FFFF;
 */

#ifndef NGFW_REGS_H
#define NGFW_REGS_H

#include <stdint.h>

/* ============================================================
 * BAR size (4 KB page-aligned minimum for mmap)
 * ============================================================ */
#define NGFW_BAR_SIZE           4096

/* ============================================================
 * Core control registers (offset from BAR base)
 * ============================================================ */
#define NGFW_REG_SCRATCH        0x00    /* RW: 32-bit sanity check */
#define NGFW_REG_REMAP_EN       0x04    /* RW: per-engine enable bitmask */
#define NGFW_REG_IFACE_MODE     0x08    /* RW: interface mode (L2/L3/vWire/QinQ/VXLAN/VSYS) */
#define NGFW_REG_OFFLOAD_CTRL   0x0C    /* RW: fast-path/offload/accel */
#define NGFW_REG_VSYS_ID        0x10    /* RW: virtual system ID */
#define NGFW_REG_STATUS         0x14    /* RO: liveness + link + DDR status */
#define NGFW_REG_VERSION        0x18    /* RO: firmware version */
#define NGFW_REG_PORT_EN        0x1C    /* RW: per-port 100G enable [3:0] */

/* ============================================================
 * Table programmer registers
 * ============================================================ */
#define NGFW_REG_TBL_SELECT     0x20    /* RW: target table ID [7:0] */
#define NGFW_REG_TBL_INDEX      0x24    /* RW: entry index [15:0] */
#define NGFW_REG_TBL_DATA_LO    0x28    /* RW: data bits [31:0] */
#define NGFW_REG_TBL_DATA_HI    0x2C    /* RW: data bits [63:32] */
#define NGFW_REG_TBL_COMMIT     0x30    /* WO: write 1 to push entry */

/* ============================================================
 * VSYS licensing and management
 * ============================================================ */
#define NGFW_REG_VSYS_HW_MAX       0x44    /* RO: hardware max VSYS (synth param) */
#define NGFW_REG_VSYS_LICENSE_MAX   0x48    /* RW: licensed maximum VSYS count */
#define NGFW_REG_VSYS_ACTIVE_COUNT  0x4C    /* RO: currently active VSYS count */
#define NGFW_REG_VSYS_LICENSE_KEY   0x50    /* WO: license key hash */
#define NGFW_REG_VSYS_STATUS        0x54    /* RO: [0]=license_valid, [1]=at_capacity */
#define NGFW_REG_VSYS_ENABLE_0      0x60    /* RW: VSYS enable bitmap bits [31:0] */
#define NGFW_REG_VSYS_ENABLE_1      0x64    /* RW: bits [63:32] */
#define NGFW_REG_VSYS_ENABLE_2      0x68    /* RW: bits [95:64] */
#define NGFW_REG_VSYS_ENABLE_3      0x6C    /* RW: bits [127:96] */
#define NGFW_REG_VSYS_ENABLE_4      0x70    /* RW: bits [159:128] */
#define NGFW_REG_VSYS_ENABLE_5      0x74    /* RW: bits [191:160] */
#define NGFW_REG_VSYS_ENABLE_6      0x78    /* RW: bits [223:192] */
#define NGFW_REG_VSYS_ENABLE_7      0x7C    /* RW: bits [255:224] */

/* VSYS status bits */
#define NGFW_VSYS_STATUS_LICENSE_VALID  (1 << 0)
#define NGFW_VSYS_STATUS_AT_CAPACITY    (1 << 1)

/* Helper: enable/disable a VSYS ID (0-255) */
static inline void ngfw_vsys_enable(volatile uint32_t *base, uint8_t vsys_id) {
    uint32_t reg = NGFW_REG_VSYS_ENABLE_0 + (vsys_id / 32) * 4;
    uint32_t bit = 1u << (vsys_id % 32);
    uint32_t val = ngfw_read(base, reg);
    ngfw_write(base, reg, val | bit);
}

static inline void ngfw_vsys_disable(volatile uint32_t *base, uint8_t vsys_id) {
    uint32_t reg = NGFW_REG_VSYS_ENABLE_0 + (vsys_id / 32) * 4;
    uint32_t bit = 1u << (vsys_id % 32);
    uint32_t val = ngfw_read(base, reg);
    ngfw_write(base, reg, val & ~bit);
}

static inline int ngfw_vsys_is_enabled(volatile uint32_t *base, uint8_t vsys_id) {
    uint32_t reg = NGFW_REG_VSYS_ENABLE_0 + (vsys_id / 32) * 4;
    uint32_t bit = 1u << (vsys_id % 32);
    return (ngfw_read(base, reg) & bit) ? 1 : 0;
}

/* ============================================================
 * HA (High Availability) registers
 * ============================================================ */
#define NGFW_REG_HA_MODE            0x80    /* RW: [1:0] 0=disabled, 1=A/P, 2=A/A */
#define NGFW_REG_HA_PRIORITY        0x84    /* RW: [31:0] higher = prefer active */
#define NGFW_REG_HA_STATE           0x88    /* RO: [7:0] current HA state */
#define NGFW_REG_HA_PEER_STATE      0x8C    /* RO: [7:0] last peer state */
#define NGFW_REG_HA_HB_INTERVAL     0x90    /* RW: heartbeat interval (clocks) */
#define NGFW_REG_HA_HB_TIMEOUT      0x94    /* RW: missed HBs before failover */
#define NGFW_REG_HA_PEER_SEQ        0x98    /* RO: last peer sequence number */
#define NGFW_REG_HA_LOCAL_SEQ       0x9C    /* RO: local heartbeat sequence */
#define NGFW_REG_HA_FAILOVER_CNT    0xA0    /* RO: total failover events */
#define NGFW_REG_HA_FORCE_ACTIVE    0xA4    /* WO: write 1 to force active */
#define NGFW_REG_HA_FORCE_STANDBY   0xA8    /* WO: write 1 to force standby */
#define NGFW_REG_HA_SESSION_SYNC    0xAC    /* RW: [0] enable session sync */
#define NGFW_REG_L1_BYPASS_MODE     0xB0    /* RW: [1:0] 0=normal, 1=loopback, 2=inline cross */
#define NGFW_REG_L1_BYPASS_STATUS   0xB4    /* RO: [0]=bypass_active, [1]=watchdog_triggered */

/* L1 bypass mode values */
#define NGFW_BYPASS_NORMAL          0       /* pipeline active */
#define NGFW_BYPASS_LOOPBACK        1       /* each port loops to itself */
#define NGFW_BYPASS_INLINE_CROSS    2       /* port 0↔1 cross-connect (bump in wire) */

/* HA state values */
#define NGFW_HA_INIT                0x00
#define NGFW_HA_ACTIVE              0x01
#define NGFW_HA_STANDBY             0x02
#define NGFW_HA_ACTIVE_ACTIVE       0x03
#define NGFW_HA_FAILED              0x04

/* HA mode values */
#define NGFW_HA_MODE_DISABLED       0
#define NGFW_HA_MODE_ACTIVE_PASSIVE 1
#define NGFW_HA_MODE_ACTIVE_ACTIVE  2

/* ============================================================
 * Host watchdog (autonomous operation)
 * ============================================================ */
#define NGFW_REG_WDG_KEEPALIVE      0xC0    /* WO: write any value = "I'm alive" */
#define NGFW_REG_WDG_TIMEOUT        0xC4    /* RW: keepalive timeout (clocks) */
#define NGFW_REG_WDG_STATE          0xC8    /* RO: 0=NORMAL, 1=AUTONOMOUS, 2=RECOVERY */
#define NGFW_REG_WDG_AUTO_DURATION  0xCC    /* RO: seconds spent in AUTONOMOUS */
#define NGFW_REG_WDG_AUTH_KEY       0xD0    /* WO: write 0xC0DECAFE to re-authenticate */
#define NGFW_REG_WDG_BOOT_COUNT     0xD4    /* RO: host reboot count survived */
#define NGFW_REG_WDG_CONFIG_LOCK    0xD8    /* RO: [0]=config writes blocked */
#define NGFW_REG_WDG_PCIE_LINK      0xDC    /* RO: [0]=PCIe link up */

/* Watchdog state values */
#define NGFW_WDG_NORMAL             0       /* host alive, config accepted */
#define NGFW_WDG_AUTONOMOUS         1       /* host absent, config frozen, dataplane runs */
#define NGFW_WDG_RECOVERY           2       /* host returned, re-authenticated */

/* Auth key that the host must write to exit AUTONOMOUS mode */
#define NGFW_WDG_AUTH_KEY_VALUE     0xC0DECAFE

/* Helper: send keepalive (call every 500ms from ngfwd daemon) */
static inline void ngfw_keepalive(volatile uint32_t *base) {
    ngfw_write(base, NGFW_REG_WDG_KEEPALIVE, 1);
}

/* Helper: re-authenticate after host reboot */
static inline int ngfw_reauth(volatile uint32_t *base) {
    ngfw_write(base, NGFW_REG_WDG_AUTH_KEY, NGFW_WDG_AUTH_KEY_VALUE);
    ngfw_keepalive(base);
    /* Read back state — should be RECOVERY or NORMAL */
    uint32_t state = ngfw_read(base, NGFW_REG_WDG_STATE);
    return (state != NGFW_WDG_AUTONOMOUS) ? 0 : -1;
}

/* ============================================================
 * Stats counter readback
 * ============================================================ */
#define NGFW_REG_STATS_IDX      0x34    /* RW: counter index [5:0] */
#define NGFW_REG_STATS_DATA_LO  0x38    /* RO: counter value [31:0] */
#define NGFW_REG_STATS_DATA_HI  0x3C    /* RO: counter value [63:32] */
#define NGFW_REG_STATS_CLEAR    0x40    /* WO: write 1 to clear all */

/* ============================================================
 * REMAP_EN bit assignments
 * ============================================================ */
#define NGFW_EN_IFACE_CLASS     (1 <<  0)
#define NGFW_EN_SESSION         (1 <<  1)
#define NGFW_EN_NAT             (1 <<  2)
#define NGFW_EN_SEC_POLICY      (1 <<  3)
#define NGFW_EN_APPID           (1 <<  4)
#define NGFW_EN_PROTO_DECODE    (1 <<  5)
#define NGFW_EN_CID_THREAT      (1 <<  6)
#define NGFW_EN_CID_MALWARE     (1 <<  7)
#define NGFW_EN_CID_URL         (1 <<  8)
#define NGFW_EN_CID_FILE        (1 <<  9)
#define NGFW_EN_CID_SPYWARE    (1 << 10)
#define NGFW_EN_USER_POLICY     (1 << 11)
#define NGFW_EN_APP_POLICY      (1 << 12)
#define NGFW_EN_TLS_DECRYPT     (1 << 13)
#define NGFW_EN_TLS_INSPECT     (1 << 14)
#define NGFW_EN_TLS_REENCRYPT   (1 << 15)
#define NGFW_EN_DDOS            (1 << 16)
#define NGFW_EN_RATE_LIMITER    (1 << 17)
#define NGFW_EN_ALL_ENGINES     0x0003FFFF

/* ============================================================
 * Interface mode values
 * ============================================================ */
#define NGFW_MODE_L2_BRIDGE     0
#define NGFW_MODE_L3_ROUTE      1
#define NGFW_MODE_VWIRE         2
#define NGFW_MODE_QINQ          3
#define NGFW_MODE_VXLAN         4
#define NGFW_MODE_VSYS          5

/* ============================================================
 * Table programmer select IDs
 * ============================================================ */
#define NGFW_TBL_DDOS_ZONE_MAP      0x00
#define NGFW_TBL_DDOS_THRESHOLDS    0x01
#define NGFW_TBL_DDOS_IP_BLOCKLIST  0x02
#define NGFW_TBL_DDOS_GEOIP         0x03
#define NGFW_TBL_DDOS_SYN_SEED      0x04
#define NGFW_TBL_SEC_POLICY         0x05
#define NGFW_TBL_APPID              0x06
#define NGFW_TBL_CID_THREAT         0x07
#define NGFW_TBL_CID_URL            0x08
#define NGFW_TBL_CID_SPYWARE        0x09
#define NGFW_TBL_USER_POLICY        0x0A
#define NGFW_TBL_APP_POLICY         0x0B
#define NGFW_TBL_CID_FILE_MASK      0x0C
#define NGFW_TBL_RATE_LIMITER       0x0D
#define NGFW_TBL_SESSION_INSERT     0x0E
#define NGFW_TBL_BLOOM_PROGRAM      0x0F

/* ============================================================
 * STATUS register bit fields
 * ============================================================ */
#define NGFW_STATUS_HEARTBEAT   (1 << 0)
#define NGFW_STATUS_LINK0_UP    (1 << 1)
#define NGFW_STATUS_LINK1_UP    (1 << 2)
#define NGFW_STATUS_LINK2_UP    (1 << 3)
#define NGFW_STATUS_LINK3_UP    (1 << 4)
#define NGFW_STATUS_DDR0_CAL    (1 << 5)
#define NGFW_STATUS_DDR1_CAL    (1 << 6)

/* ============================================================
 * DDoS verdict reason codes (bitfield)
 * ============================================================ */
#define NGFW_DDOS_R_SYN_FLOOD   0x01
#define NGFW_DDOS_R_IP_BLOCKED  0x02
#define NGFW_DDOS_R_CONN_RATE   0x04
#define NGFW_DDOS_R_UDP_AMP     0x08
#define NGFW_DDOS_R_FRAG_FLOOD  0x10
#define NGFW_DDOS_R_GEOIP       0x20
#define NGFW_DDOS_R_PPS_LIMIT   0x40
#define NGFW_DDOS_R_BPS_LIMIT   0x80

/* ============================================================
 * Helper: read/write register
 * ============================================================ */
static inline uint32_t ngfw_read(volatile uint32_t *base, uint32_t offset) {
    return base[offset / 4];
}

static inline void ngfw_write(volatile uint32_t *base, uint32_t offset, uint32_t val) {
    base[offset / 4] = val;
}

/* ============================================================
 * Helper: program a table entry
 * ============================================================ */
static inline void ngfw_table_write(volatile uint32_t *base,
                                     uint8_t table, uint16_t index,
                                     uint64_t data) {
    ngfw_write(base, NGFW_REG_TBL_SELECT, table);
    ngfw_write(base, NGFW_REG_TBL_INDEX, index);
    ngfw_write(base, NGFW_REG_TBL_DATA_LO, (uint32_t)(data & 0xFFFFFFFF));
    ngfw_write(base, NGFW_REG_TBL_DATA_HI, (uint32_t)(data >> 32));
    ngfw_write(base, NGFW_REG_TBL_COMMIT, 1);
}

#endif /* NGFW_REGS_H */
