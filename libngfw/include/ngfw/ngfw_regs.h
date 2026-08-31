/*
 * FFN NGFW FPGA — Hardware Register Map
 *
 * Shared between kernel driver, userspace library, daemon, and CLI.
 * Address map matches the AXI-Lite demux in top_ngfw_xupp3r_4x100g.v.
 *
 * Bus layout (from host AXI-Lite master on QDMA):
 *   addr[12]  == 1  : cmac_csr    (per-port 100G MAC) base 0x1000
 *   addr[9:8] == 00 : remap_ctrl  (control plane)     base 0x000
 *   addr[9:8] == 01 : crypto IP   (AES/PQC/FIPS)      base 0x100
 *   addr[9:8] == 10 : watchdog    (host liveness)     base 0x200
 *   addr[9:8] == 11 : reserved                         base 0x300
 *
 * Within cmac_csr, addr[9:8] selects the port (0..3) and addr[7:0] the
 * register within that port.
 */

#ifndef NGFW_REGS_H
#define NGFW_REGS_H

#ifdef __KERNEL__
#  include <linux/types.h>
#else
#  include <stdint.h>
#endif

/* ============================================================
 * BAR layout
 * ============================================================ */
#define NGFW_BAR_CSR         0   /* BAR0: AXI-Lite CSRs            */
#define NGFW_BAR_DMA         2   /* BAR2: QDMA MM descriptor ring  */

/* Region bases (within BAR0) */
#define NGFW_REG_REMAP_BASE  0x0000
#define NGFW_REG_CRYPTO_BASE 0x0100
#define NGFW_REG_WDG_BASE    0x0200
#define NGFW_REG_CMAC_BASE   0x1000   /* addr[12] selects this window */

/* ============================================================
 * Per-port CMAC CSR — 0x1000 + p*0x100
 * 4 ports × 256 bytes each
 * ============================================================ */
#define NGFW_CMAC_PORT_BASE(p)      (NGFW_REG_CMAC_BASE + (p) * 0x100)
#define NGFW_CMAC_CONFIG(p)         (NGFW_CMAC_PORT_BASE(p) + 0x40)
   /* CMAC_CONFIG bits:
    *   [0]  = ctl_rx_enable        (RW, default 1)
    *   [1]  = ctl_tx_enable        (RW, default 1)
    *   [2]  = ctl_rx_force_resync  (RW level — hold, then clear, to re-sync RS-FEC)
    *   [8]  = ctl_rx_ctl_enable    (RW, default 1 — reserved for CMAC extended ctl)
    *   [16] = ctl_tx_send_idle     (RW, default 0) */
#define NGFW_CMAC_FEC_CONFIG(p)     (NGFW_CMAC_PORT_BASE(p) + 0x44)
   /* FEC_CONFIG bits:
    *   [0] = ctl_rx_rsfec_enable   (RW, default 1)
    *   [1] = ctl_tx_rsfec_enable   (RW, default 1) */
#define NGFW_CMAC_QSFP_PRESENT(p)   (NGFW_CMAC_PORT_BASE(p) + 0x50)
   /* QSFP_PRESENT bits:
    *   [0] = 1 if module present  (derived from ~qsfp<p>_modprsl) */
#define NGFW_CMAC_RX_STATUS(p)      (NGFW_CMAC_PORT_BASE(p) + 0x54)
   /* RX_STATUS bits:
    *   [0] = stat_rx_aligned       (CMAC RS-FEC + lane aligner locked)
    *   [1] = stat_rx_status        (overall link OK) */
#define NGFW_CMAC_FAULT_STATUS(p)   (NGFW_CMAC_PORT_BASE(p) + 0x58)
   /* FAULT_STATUS bits:
    *   [0] = stat_rx_local_fault
    *   [1] = stat_rx_remote_fault
    *   [2] = stat_rx_hi_ber
    *   [3] = stat_tx_local_fault
    *   [4] = all 20 PCS lanes locked (AND of stat_rx_block_lock) */
#define NGFW_CMAC_BLOCK_LOCK(p)     (NGFW_CMAC_PORT_BASE(p) + 0x5C)
   /* BLOCK_LOCK bits:
    *   [19:0] = per-lane stat_rx_block_lock mask */
#define NGFW_CMAC_LOOPBACK_CFG(p)   (NGFW_CMAC_PORT_BASE(p) + 0x60)
   /* LOOPBACK_CFG bits:
    *   [11:0] = gt_loopback_in (3 bits per GT lane × 4 lanes)
    *   Per-lane values (Xilinx GTY):
    *     000 = normal, 001 = near-end PCS, 010 = near-end PMA,
    *     100 = far-end PMA,  110 = far-end PCS */
#define NGFW_CMAC_TEST_PATTERN(p)   (NGFW_CMAC_PORT_BASE(p) + 0x64)
   /* TEST_PATTERN bits:
    *   [0] = ctl_rx_test_pattern (RX PRBS check)
    *   [1] = ctl_tx_test_pattern (TX PRBS generate) */
#define NGFW_CMAC_SNAPSHOT_REQ(p)   (NGFW_CMAC_PORT_BASE(p) + 0x68)
   /* SNAPSHOT_REQ (WO): write 1 to force fresh stats snapshot.
    *                    (Automatic ~1.6 ms snapshot also runs.) */
#define NGFW_CMAC_SNAPSHOT_SEQ(p)   (NGFW_CMAC_PORT_BASE(p) + 0x6C)
   /* SNAPSHOT_SEQ (RO): 8-bit rolling counter, increments per snapshot.
    *                    Software polls to detect fresh stats. */

/* ---- Per-port 64-bit stats (LO/HI at 8-byte stride) ---- */
#define NGFW_CMAC_RX_PACKETS_LO(p)     (NGFW_CMAC_PORT_BASE(p) + 0x80)
#define NGFW_CMAC_RX_PACKETS_HI(p)     (NGFW_CMAC_PORT_BASE(p) + 0x84)
#define NGFW_CMAC_RX_BYTES_LO(p)       (NGFW_CMAC_PORT_BASE(p) + 0x88)
#define NGFW_CMAC_RX_BYTES_HI(p)       (NGFW_CMAC_PORT_BASE(p) + 0x8C)
#define NGFW_CMAC_RX_ERRORS_LO(p)      (NGFW_CMAC_PORT_BASE(p) + 0x90)
#define NGFW_CMAC_RX_ERRORS_HI(p)      (NGFW_CMAC_PORT_BASE(p) + 0x94)
#define NGFW_CMAC_RX_DROPS_LO(p)       (NGFW_CMAC_PORT_BASE(p) + 0x98)
#define NGFW_CMAC_RX_DROPS_HI(p)       (NGFW_CMAC_PORT_BASE(p) + 0x9C)
#define NGFW_CMAC_RX_MULTICAST_LO(p)   (NGFW_CMAC_PORT_BASE(p) + 0xA0)
#define NGFW_CMAC_RX_MULTICAST_HI(p)   (NGFW_CMAC_PORT_BASE(p) + 0xA4)
#define NGFW_CMAC_TX_PACKETS_LO(p)     (NGFW_CMAC_PORT_BASE(p) + 0xA8)
#define NGFW_CMAC_TX_PACKETS_HI(p)     (NGFW_CMAC_PORT_BASE(p) + 0xAC)
#define NGFW_CMAC_TX_BYTES_LO(p)       (NGFW_CMAC_PORT_BASE(p) + 0xB0)
#define NGFW_CMAC_TX_BYTES_HI(p)       (NGFW_CMAC_PORT_BASE(p) + 0xB4)
#define NGFW_CMAC_TX_ERRORS_LO(p)      (NGFW_CMAC_PORT_BASE(p) + 0xB8)
#define NGFW_CMAC_TX_ERRORS_HI(p)      (NGFW_CMAC_PORT_BASE(p) + 0xBC)
#define NGFW_CMAC_FEC_COR_LO(p)        (NGFW_CMAC_PORT_BASE(p) + 0xC0)
#define NGFW_CMAC_FEC_COR_HI(p)        (NGFW_CMAC_PORT_BASE(p) + 0xC4)
#define NGFW_CMAC_FEC_UNCOR_LO(p)      (NGFW_CMAC_PORT_BASE(p) + 0xC8)
#define NGFW_CMAC_FEC_UNCOR_HI(p)      (NGFW_CMAC_PORT_BASE(p) + 0xCC)

/* FAULT_STATUS bit helpers */
#define NGFW_CMAC_FLT_RX_LOCAL      (1u << 0)
#define NGFW_CMAC_FLT_RX_REMOTE     (1u << 1)
#define NGFW_CMAC_FLT_RX_HI_BER     (1u << 2)
#define NGFW_CMAC_FLT_TX_LOCAL      (1u << 3)
#define NGFW_CMAC_FLT_ALL_LOCKED    (1u << 4)

/* TEST_PATTERN bit helpers */
#define NGFW_CMAC_TP_RX             (1u << 0)
#define NGFW_CMAC_TP_TX             (1u << 1)

/* LOOPBACK_CFG per-lane modes (3 bits per lane, shifted by lane*3) */
#define NGFW_GT_LB_NORMAL           0x0
#define NGFW_GT_LB_NEAR_PCS         0x1
#define NGFW_GT_LB_NEAR_PMA         0x2
#define NGFW_GT_LB_FAR_PMA          0x4
#define NGFW_GT_LB_FAR_PCS          0x6
#define NGFW_GT_LB_ALL_LANES(mode)  (((mode) << 0)  | ((mode) << 3) | \
                                     ((mode) << 6) | ((mode) << 9))

/* CMAC_CONFIG bit helpers */
#define NGFW_CMAC_CFG_RX_EN         (1u << 0)
#define NGFW_CMAC_CFG_TX_EN         (1u << 1)
#define NGFW_CMAC_CFG_FORCE_RESYNC  (1u << 2)
#define NGFW_CMAC_CFG_RX_CTL_EN     (1u << 8)
#define NGFW_CMAC_CFG_TX_SEND_IDLE  (1u << 16)
#define NGFW_CMAC_CFG_DEFAULT       (NGFW_CMAC_CFG_RX_EN | NGFW_CMAC_CFG_TX_EN | NGFW_CMAC_CFG_RX_CTL_EN)

/* FEC_CONFIG bit helpers */
#define NGFW_CMAC_FEC_RX_EN         (1u << 0)
#define NGFW_CMAC_FEC_TX_EN         (1u << 1)
#define NGFW_CMAC_FEC_DEFAULT       (NGFW_CMAC_FEC_RX_EN | NGFW_CMAC_FEC_TX_EN)

/* ============================================================
 * remap_ctrl (control plane) — 0x000-0x07F
 * ============================================================ */
#define NGFW_REG_SCRATCH            0x00
#define NGFW_REG_REMAP_EN           0x04   /* [31:0] per-engine enable */
#define NGFW_REG_INTERFACE_MODE     0x08   /* [7:0]  L2/L3/vWire/QinQ  */
#define NGFW_REG_OFFLOAD_CTRL       0x0C   /* [6:5] = L1 bypass mode   */
#define NGFW_REG_VSYS_ID            0x10   /* [7:0]  global VSYS tag   */
#define NGFW_REG_STATUS             0x14   /* heartbeat + link + DDR   */
#define NGFW_REG_VERSION            0x18   /* 0xFFF1_0003              */
#define NGFW_REG_PORT_EN            0x1C   /* [3:0] per-port 100G en   */

/* Table programmer */
#define NGFW_REG_TBL_SELECT         0x20
#define NGFW_REG_TBL_INDEX          0x24
#define NGFW_REG_TBL_DATA_LO        0x28
#define NGFW_REG_TBL_DATA_HI        0x2C
#define NGFW_REG_TBL_COMMIT         0x30

/* Stats readback */
#define NGFW_REG_STATS_IDX          0x34
#define NGFW_REG_STATS_DATA_LO      0x38
#define NGFW_REG_STATS_DATA_HI      0x3C
#define NGFW_REG_STATS_CLEAR        0x40

/* VSYS licensing */
#define NGFW_REG_VSYS_HW_MAX        0x44
#define NGFW_REG_VSYS_LICENSE_MAX   0x48
#define NGFW_REG_VSYS_ACTIVE_COUNT  0x4C
#define NGFW_REG_VSYS_LICENSE_KEY   0x50
#define NGFW_REG_VSYS_STATUS        0x54
#define NGFW_REG_VSYS_ENABLE_0      0x60   /* 8×32-bit bitmap (256 VSYS) */

/* ============================================================
 * Device DNA — 96-bit unique ID per Xilinx silicon die
 *
 * Sourced from the DNA_PORTE2 primitive (US/US+ devices). The
 * bitstream samples it once at power-on and exposes the 96 bits
 * across these three 32-bit registers. Reads are cheap; the value
 * never changes for the life of the silicon.
 *
 * Lives in the previously-reserved 0x300 quarter of remap_ctrl so it
 * doesn't collide with per-port NIC management at 0x80-0xFF.
 *
 * Used for:
 *   - Per-device licensing (engines + features bound to this DNA)
 *   - Anti-cloning attestation (HQ signing service signs license
 *     tokens scoped to the DNA, driver verifies signature against
 *     embedded vendor public key)
 *   - Telemetry / asset inventory
 * ============================================================ */
#define NGFW_REG_DEVICE_DNA_BASE    0x300
#define NGFW_REG_DEVICE_DNA_0       (NGFW_REG_DEVICE_DNA_BASE + 0x00) /* DNA[31:0]  */
#define NGFW_REG_DEVICE_DNA_1       (NGFW_REG_DEVICE_DNA_BASE + 0x04) /* DNA[63:32] */
#define NGFW_REG_DEVICE_DNA_2       (NGFW_REG_DEVICE_DNA_BASE + 0x08) /* DNA[95:64] */
#define NGFW_REG_DEVICE_DNA_VALID   (NGFW_REG_DEVICE_DNA_BASE + 0x0C) /* [0]=DNA sampled OK after POR */

#define NGFW_DEVICE_DNA_W           96      /* bits */
#define NGFW_DEVICE_DNA_BYTES       12

/* ============================================================
 * License + signing-key hierarchy
 *
 * Two-tier PKI rooted in a hardcoded MASTER public key (ECDSA on
 * NIST P-521 / secp521r1).  The master private key lives on a
 * SafeNet eToken 5110+ FIPS (or equivalent FIPS 140-2 L3 PKCS#11
 * token); the matching public key (133-byte uncompressed point) is
 * baked into the driver image at compile time.
 *
 * Vendors, 1st-party resellers, and OEMs each receive a VENDOR cert:
 * a master-signed bundle {vendor_pubkey (Ed25519), granted_feature_mask,
 * expiry, master_sig (ECDSA P-521)}.  License tokens are then signed
 * by EITHER the master (ECDSA P-521 sig) OR a vendor (Ed25519 sig) —
 * verified by:
 *
 *   1. Lookup the token's signer_id
 *   2. If signer is master → verify token sig against hardcoded master
 *      pubkey using ECDSA P-521 / SHA-512
 *   3. If signer is vendor → verify vendor cert against master pubkey
 *      (ECDSA P-521), then verify token sig against vendor pubkey (Ed25519)
 *   4. Check DNA matches the live FPGA, expiry > now,
 *      feature_id in vendor's granted_feature_mask
 *
 * Why ECDSA P-521 for master and Ed25519 for vendors?
 *   - Master key is hardcoded in the driver and rotates only on a
 *     firmware re-flash. It must remain unbreakable for the entire
 *     deployable life of the silicon (decade-plus).  ECDSA P-521 has
 *     ~256-bit symmetric-equivalent strength (NIST classifies it at
 *     security level 5, "AES-256 ladder") — comfortably above any
 *     practical classical attack horizon.
 *   - Native to FIPS 140-2/3 PKCS#11 hardware tokens (eToken 5110+,
 *     YubiHSM 2, Luna), so the master private key NEVER exists outside
 *     tamper-resistant silicon.  PIN-gated, audit-trailed, anti-cloning.
 *   - Sig is 132 B (raw r||s) vs RSA-16384's 2048 B → smaller vendor
 *     certs and master-signed tokens, faster boot-time verification
 *     (~3 ms vs ~100 ms).
 *   - Vendor keys are revocable + reissuable from HQ, and license
 *     verification runs on every boot — Ed25519 keeps that fast
 *     (~50 µs / verify) and the keys small (32 B).
 *
 * Signature verification happens entirely in userspace
 * (ffn-license-verify, links openssl + libsodium). The kernel driver
 * only stores "verified OK" bits per engine + feature, set by an
 * ioctl from the verifier.  Keeps crypto out of the kernel and lets
 * key material rotate without a kernel rebuild.
 *
 * Vendor certs live in /etc/ffn-ngfw/vendor-keys/ as one .vcert file
 * per signer_id. Removing the file revokes that vendor's key. The
 * master can also publish a CRL (revoked vendor IDs) that the
 * verifier consults before accepting any vendor signature.
 *
 * Future-proofing: the sig_alg field is an enum with room for ML-DSA
 * (post-quantum) algorithms in a later spin.  Verifier picks based on
 * sig_alg, so a master cert can be dual-signed (P-521 + ML-DSA-87)
 * during the PQC transition window without breaking older drivers.
 * ============================================================ */

/* Signature-algorithm IDs — embedded in tokens and certs so the
 * verifier knows which alg + key length to expect.  Reserved range
 * 8..15 is for PQC algs (ML-DSA-44/65/87, Falcon-1024) in a future
 * spin.  Master can sign with any ECDSA curve the eToken supports;
 * verifier dispatches at run-time on sig_alg. */
#define NGFW_SIG_ALG_NONE           0
#define NGFW_SIG_ALG_ED25519        1   /* vendor signing                 */
/* 2 was RSA-16384 in earlier drafts — withdrawn (smart-card limit).    */
#define NGFW_SIG_ALG_ECDSA_P521     3   /* master (P-521 / SHA-512) — needs eToken 5110+ FIPS */
#define NGFW_SIG_ALG_ECDSA_P384     4   /* master (P-384 / SHA-384) — supported on every IDPrime / 5110 GA */
#define NGFW_SIG_ALG_ECDSA_P256     5   /* master (P-256 / SHA-256) — universal smart-card support */

/* Sizes per algorithm (bytes).  ECDSA sig is always raw r||s of two
 * scalars; pubkey is always SEC1 uncompressed point (0x04 || X || Y). */
#define NGFW_SIG_BYTES_ED25519       64
#define NGFW_SIG_BYTES_ECDSA_P521    132   /* 66 + 66 */
#define NGFW_SIG_BYTES_ECDSA_P384    96    /* 48 + 48 */
#define NGFW_SIG_BYTES_ECDSA_P256    64    /* 32 + 32 */
#define NGFW_PUBKEY_BYTES_ED25519    32
#define NGFW_PUBKEY_BYTES_ECDSA_P521 133   /* 1 + 66 + 66 */
#define NGFW_PUBKEY_BYTES_ECDSA_P384 97    /* 1 + 48 + 48 */
#define NGFW_PUBKEY_BYTES_ECDSA_P256 65    /* 1 + 32 + 32 */

/* Largest sig + pubkey across all supported algs.  Used for fixed-size
 * field allocations on disk; current max is set by ECDSA P-521. */
#define NGFW_SIG_MAX_BYTES          NGFW_SIG_BYTES_ECDSA_P521
#define NGFW_PUBKEY_MAX_BYTES       NGFW_PUBKEY_BYTES_ECDSA_P521

/* Signer-ID space: 16-byte identifier (compact SHA-256 prefix of
 * pubkey).  The special all-zero ID means "master" — the hardcoded
 * ECDSA P-521 key.  Any non-zero ID must resolve to a vendor cert in
 * the local store. */
#define NGFW_SIGNER_ID_BYTES        16
#define NGFW_SIGNER_MASTER_ID       "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

/* ----------------------------------------------------------
 * License token wire format
 *
 *   offset  size       field
 *   ─────────────────────────────────────────────────────────
 *    0       8         magic "FFN-LIC1"
 *    8       4         version (= 1)
 *   12      12         dna[NGFW_DEVICE_DNA_BYTES]
 *   24       4         feature_id    (NGFW_LIC_FEAT_* or engine slot)
 *   28       4         subfeature_id
 *   32       8         issued_unix_s
 *   40       8         expiry_unix_s
 *   48       4         flags          (NGFW_LIC_FLAG_*)
 *   52      16         signer_id      (master = all-zero)
 *   68       4         sig_alg        (NGFW_SIG_ALG_*)
 *   72      12         reserved (must be zero)
 *   ─────────────────────────────────────────────────────────
 *   84                 = NGFW_LIC_PAYLOAD_BYTES (signed region ends here)
 *   84    sig_len      sig
 *   ─────────────────────────────────────────────────────────
 *   sig_len is 64 (Ed25519) or 132 (ECDSA P-521 raw r||s).
 *   Total on-disk size: 84 + sig_len.  Userspace tools size the
 *   buffer from sig_alg.
 * ---------------------------------------------------------- */
#define NGFW_LIC_MAGIC              "FFN-LIC1"
#define NGFW_LIC_VERSION            1
#define NGFW_LIC_PAYLOAD_BYTES      84
#define NGFW_LIC_BUNDLE_MAGIC       "FFN-LBND"

/* On-disk total sizes for the two valid sig algs */
#define NGFW_LIC_TOKEN_ED25519_BYTES    (NGFW_LIC_PAYLOAD_BYTES + NGFW_SIG_BYTES_ED25519)
#define NGFW_LIC_TOKEN_ECDSA521_BYTES   (NGFW_LIC_PAYLOAD_BYTES + NGFW_SIG_BYTES_ECDSA_P521)
#define NGFW_LIC_TOKEN_MAX_BYTES        NGFW_LIC_TOKEN_ECDSA521_BYTES

/* ----------------------------------------------------------
 * Vendor cert wire format (always master-signed → ECDSA P-521 sig)
 *
 *   offset  size       field
 *   ─────────────────────────────────────────────────────────
 *    0       8         magic "FFN-VND1"
 *    8       4         version (= 1)
 *   12      16         signer_id (this vendor's ID)
 *   28      32         pubkey (Ed25519)
 *   60      32         granted_feature_mask (bitmap of NGFW_LIC_FEAT_*)
 *   92       8         issued_unix_s
 *  100       8         expiry_unix_s
 *  108       4         flags ([0]=reseller, [1]=oem, [2]=internal)
 *  112       4         master_sig_alg (always NGFW_SIG_ALG_ECDSA_P521)
 *  116      20         reserved (must be zero)
 *   ─────────────────────────────────────────────────────────
 *  136                 = NGFW_VND_PAYLOAD_BYTES (signed region ends here)
 *  136     132         master_sig (ECDSA P-521 raw r||s)
 *   ─────────────────────────────────────────────────────────
 *   Total = 268 bytes.
 * ---------------------------------------------------------- */
#define NGFW_VND_MAGIC              "FFN-VND1"
#define NGFW_VND_VERSION            1
#define NGFW_VND_PAYLOAD_BYTES      136
#define NGFW_VND_SIG_BYTES          NGFW_SIG_BYTES_ECDSA_P521
#define NGFW_VND_CERT_BYTES         (NGFW_VND_PAYLOAD_BYTES + NGFW_VND_SIG_BYTES)
#define NGFW_VND_SIG_OFFSET         NGFW_VND_PAYLOAD_BYTES

/* Hardcoded master pubkey lives in the driver / userspace verifier
 * as a self-describing 144-byte blob.  The point is exported once
 * from the SafeNet eToken at HQ key-gen time and baked into the
 * verifier binary.  The private key never leaves the eToken silicon.
 *
 * For the source tree, a placeholder all-zero blob is shipped that
 * all evaluation builds use — production builds override via:
 *   make NGFW_MASTER_PUBKEY=/path/to/master.<curve>.pub
 *
 * Layout (NGFW_MASTER_PUBKEY_BLOB_BYTES = 144):
 *    0      1   curve_id  — one of NGFW_SIG_ALG_ECDSA_P{256,384,521}.
 *                           A zero (NGFW_SIG_ALG_NONE) flags this as
 *                           a placeholder / refusal.
 *    1    133   uncompressed point (0x04 || X || Y).
 *                           Actual valid bytes depend on the curve:
 *                              P-256 →  65 bytes
 *                              P-384 →  97 bytes
 *                              P-521 → 133 bytes
 *                           Trailing bytes within the 133-byte slot
 *                           are zero for sub-521 curves.
 *  134     10   reserved zero bytes (key-version, token serial, etc.
 *                           in a future spin).
 *
 * Total = 144 bytes regardless of curve, so the embedded blob is
 * a fixed-size symbol pair.  The verifier reads byte 0 to dispatch.
 */
#define NGFW_MASTER_PUBKEY_BLOB_BYTES   144
#define NGFW_MASTER_PUBKEY_CURVE_OFFSET   0
#define NGFW_MASTER_PUBKEY_POINT_OFFSET   1
#define NGFW_MASTER_PUBKEY_POINT_MAX      133  /* large enough for P-521 */

/* Vendor flags */
#define NGFW_VND_FLAG_RESELLER      (1u << 0)
#define NGFW_VND_FLAG_OEM           (1u << 1)
#define NGFW_VND_FLAG_INTERNAL      (1u << 2)   /* FFN HQ-issued vendor cert */

#define NGFW_LIC_FLAG_EVALUATION    (1u << 0)
#define NGFW_LIC_FLAG_NONTRANSFER   (1u << 1)
#define NGFW_LIC_FLAG_REVOKED       (1u << 2)

/* Feature IDs.  Engine licenses use the engine codename slot
 * (NGFW_ENG_PANTHEON .. NGFW_ENG_AEOLUS) in feature_id, with
 * subfeature_id ignored. Capacity-tier licenses use these
 * top-level IDs. */
#define NGFW_LIC_FEAT_BASE          0x100   /* shipped product, always required */
#define NGFW_LIC_FEAT_TIER_10G      0x101   /* up to 10G aggregate              */
#define NGFW_LIC_FEAT_TIER_40G      0x102   /* up to 40G aggregate              */
#define NGFW_LIC_FEAT_TIER_100G     0x103   /* unlock 100G CMAC line-rate path  */
#define NGFW_LIC_FEAT_TIER_400G     0x104   /* full 4×100G                       */
#define NGFW_LIC_FEAT_VSYS_EXPAND   0x110   /* >32 active vsys (Pantheon)        */
#define NGFW_LIC_FEAT_PQC           0x111   /* enable Janus PQC algorithms       */
#define NGFW_LIC_FEAT_THREAT_FEED   0x120   /* daily Lynceus signature updates  */

/* The 80-byte signed payload — same shape on disk and in the kernel,
 * since the kernel never touches the variable-size sig that follows. */
#ifdef __KERNEL__
struct ngfw_lic_payload {
    char     magic[8];
    __le32   version;
    u8       dna[NGFW_DEVICE_DNA_BYTES];
    __le32   feature_id;
    __le32   subfeature_id;
    __le64   issued_unix_s;
    __le64   expiry_unix_s;
    __le32   flags;
    u8       signer_id[NGFW_SIGNER_ID_BYTES];
    __le32   sig_alg;
    u8       reserved[12];
} __attribute__((packed));
#else
struct ngfw_lic_payload {
    char     magic[8];
    uint32_t version;
    uint8_t  dna[NGFW_DEVICE_DNA_BYTES];
    uint32_t feature_id;
    uint32_t subfeature_id;
    uint64_t issued_unix_s;
    uint64_t expiry_unix_s;
    uint32_t flags;
    uint8_t  signer_id[NGFW_SIGNER_ID_BYTES];
    uint32_t sig_alg;
    uint8_t  reserved[12];
} __attribute__((packed));
#endif

/* Backward-compat alias: existing callers that referenced
 * "struct ngfw_lic_token" get the verified-payload form. */
#define ngfw_lic_token  ngfw_lic_payload

/* Driver-userspace ioctl for pushing already-verified license payloads.
 * Userspace verifies the sig (RSA-16384 or Ed25519) BEFORE invoking
 * this ioctl — the kernel only sees the trusted payload. */
struct ngfw_lic_push {
    uint32_t count;                          /* number of payloads following */
    /* struct ngfw_lic_payload payloads[count] follows in the same buffer */
};
#define NGFW_IOC_LIC_PUSH    _IOW (NGFW_IOC_MAGIC, 0x30, struct ngfw_lic_push)
#define NGFW_IOC_LIC_QUERY   _IOWR(NGFW_IOC_MAGIC, 0x31, struct ngfw_lic_payload)
#define NGFW_IOC_DNA_READ    _IOR (NGFW_IOC_MAGIC, 0x32, uint8_t[NGFW_DEVICE_DNA_BYTES])

/* ============================================================
 * mqnic_app_block APP CSR window (BAR2 + 0x000000)
 *
 * The Phase 1+2 switch-fabric bitstream adds a small CSR slave at
 * master 4 of the mqnic_app_block axil_crossbar, mapped at the BAR2
 * base.  Holds bitstream identity, the runtime APP_BYPASS toggle that
 * controls the port-pair bridge fabric, and aggregated verdict counts.
 *
 * Address layout (32-bit word access, BAR2-relative):
 *   0x0000  APP_ID         RO   = 0x4E474657 ('NGFW')
 *   0x0004  VERDICT_AGGR   RO   = packed [redirect[7:0], punt[7:0],
 *                                         drop[7:0],     fwd[7:0]]
 *   0x0008  APP_BYPASS     RW   bit[0]=bridge_enable
 *                                  1 = port-pair bridge ON
 *                                      (FFN engines bypassed, ngfw0↔ngfw1
 *                                      and ngfw2↔ngfw3 forwarded on-chip
 *                                      at line rate)
 *                                  0 = NGFW host-routed
 *                                      (frames pass through ngfw_pipeline
 *                                      and FORWARD/PUNT/REDIRECT/DROP
 *                                      verdicts apply)
 *   0x000C  BUILD_INFO     RO   build rev (1 = Phase 1+2)
 *   0x0010  PORT_PAIRING   RO   partner nibbles, partner(p) at bits[4p+:4]
 *   0x0014  STAT_FWD       RO   per-port forwarded count   (port 0)
 *   0x0018  STAT_DROP      RO   per-port dropped count     (port 0)
 *   0x001C  STAT_PUNT      RO   per-port punted count      (port 0)
 *   0x0020  STAT_REDIR     RO   per-port redirected count  (port 0)
 *
 * NOTE: BAR2 holds BOTH the engine window (NGFW_ENG_BASE = 0x10000+)
 * AND the app CSR window (NGFW_APP_REG_BASE = 0x0).  Both are reachable
 * via ngfw_read_eng32_ext() / ngfw_write_eng32_ext() — the offsets are
 * disjoint by design.
 * ============================================================ */

#define NGFW_APP_REG_BASE           0x00000
#define NGFW_APP_REG_APP_ID         (NGFW_APP_REG_BASE + 0x0000)
#define NGFW_APP_REG_VERDICT_AGGR   (NGFW_APP_REG_BASE + 0x0004)
#define NGFW_APP_REG_APP_BYPASS     (NGFW_APP_REG_BASE + 0x0008)
#define NGFW_APP_REG_BUILD_INFO     (NGFW_APP_REG_BASE + 0x000C)
#define NGFW_APP_REG_PORT_PAIRING   (NGFW_APP_REG_BASE + 0x0010)
#define NGFW_APP_REG_STAT_FWD       (NGFW_APP_REG_BASE + 0x0014)
#define NGFW_APP_REG_STAT_DROP      (NGFW_APP_REG_BASE + 0x0018)
#define NGFW_APP_REG_STAT_PUNT      (NGFW_APP_REG_BASE + 0x001C)
#define NGFW_APP_REG_STAT_REDIR     (NGFW_APP_REG_BASE + 0x0020)

#define NGFW_APP_ID_MAGIC           0x4E474657u    /* 'NGFW' */

/* APP_BYPASS bits */
#define NGFW_APP_BYPASS_ENABLE      (1u << 0)      /* 1 = bridge mode */

/* Driver-side policy mode for the bypass register.  Userspace sets the
 * mode via NGFW_IOC_APP_BYPASS_SET, the driver runs the policy in
 * response to license-cache changes (push, expiry timer) when in AUTO. */
#define NGFW_APP_BYPASS_MODE_AUTO        0  /* license cache decides */
#define NGFW_APP_BYPASS_MODE_FORCE_ON    1  /* always bypass (bridge always on) */
#define NGFW_APP_BYPASS_MODE_FORCE_OFF   2  /* never bypass (FFN engines always run) */

struct ngfw_app_bypass_state {
    uint32_t mode;          /* NGFW_APP_BYPASS_MODE_* */
    uint32_t bypass_value;  /* 0|1 — actual register value at last write
                             * (named "bypass_value" not "current" to avoid
                             *  collision with the Linux kernel macro
                             *  current = get_current() in <asm/current.h>) */
    uint32_t reason_code;   /* see NGFW_APP_BYPASS_REASON_* */
    uint32_t pad;
    int64_t  last_apply_unix_s;
};

/* Reason codes returned from NGFW_IOC_APP_BYPASS_GET — explains why
 * the driver chose the current bypass value.  Keeps userspace tools
 * out of the business of replicating policy logic. */
#define NGFW_APP_BYPASS_REASON_BOOT_DEFAULT        0  /* never reapplied yet */
#define NGFW_APP_BYPASS_REASON_LIC_OK              1  /* base license + tier valid → engines run */
#define NGFW_APP_BYPASS_REASON_LIC_NO_BASE         2  /* missing NGFW_LIC_FEAT_BASE */
#define NGFW_APP_BYPASS_REASON_LIC_EXPIRED         3  /* token expiry passed since last push */
#define NGFW_APP_BYPASS_REASON_LIC_NO_TOKENS       4  /* cache empty (daemon not running?) */
#define NGFW_APP_BYPASS_REASON_LIC_BAR2_DEAD       5  /* APP_ID readback wrong, register fenced off */
#define NGFW_APP_BYPASS_REASON_USER_FORCE_ON       6  /* mode == FORCE_ON */
#define NGFW_APP_BYPASS_REASON_USER_FORCE_OFF      7  /* mode == FORCE_OFF */

#define NGFW_IOC_APP_BYPASS_GET   _IOR (NGFW_IOC_MAGIC, 0x33, struct ngfw_app_bypass_state)
#define NGFW_IOC_APP_BYPASS_SET   _IOW (NGFW_IOC_MAGIC, 0x34, struct ngfw_app_bypass_state)
/* Force re-evaluation of the AUTO policy without changing mode — useful
 * after the daemon refreshes its tokens by re-pushing them. */
#define NGFW_IOC_APP_BYPASS_REAPPLY _IO  (NGFW_IOC_MAGIC, 0x35)

/* ============================================================
 * Per-port NIC management — 0x80-0xFF
 * 4 ports × 16 bytes each
 * ============================================================ */
#define NGFW_REG_PORT_BASE(p)       (0x80 + (p) * 0x10)
#define NGFW_REG_PORT_MTU(p)        (NGFW_REG_PORT_BASE(p) + 0x00) /* 14-bit */
#define NGFW_REG_PORT_MAC_LO(p)     (NGFW_REG_PORT_BASE(p) + 0x04) /* MAC[31:0]  */
#define NGFW_REG_PORT_MAC_HI(p)     (NGFW_REG_PORT_BASE(p) + 0x08) /* MAC[47:32] */
#define NGFW_REG_PORT_FLAGS(p)      (NGFW_REG_PORT_BASE(p) + 0x0C)
   /* PORT_FLAGS bits:
    *   [0] = link_up           (RO from CMAC)
    *   [1] = promisc           (RW)
    *   [2] = allmulticast      (RW)
    *   [3] = loopback          (RW — diag)
    *   [4] = lacp_passive      (RW)
    *   [5] = lacp_active       (RW)
    *   [7:6] = pause (none/rx/tx/both)
    *   [15:8] = bond_group     (0=none, 1-15=LAG ID, 0xFF=mirror) */

/* LACP/bond table — 16 LAG groups × 4 entries (port mask + hash policy) */
#define NGFW_REG_BOND_BASE          0xC0
#define NGFW_REG_BOND_GROUP(g)      (NGFW_REG_BOND_BASE + (g) * 4)
   /* BOND_GROUP bits:
    *   [3:0]  = port_mask (which physical ports belong to this LAG)
    *   [7:4]  = hash_mode (0=L2, 1=L3, 2=L4, 3=encap-aware)
    *   [15:8] = active_mask (currently UP ports — set by LACP daemon) */

/* REMAP_EN bit definitions (per-engine enables) */
#define NGFW_REMAP_EN_STAGE(i)      (1u << (i))     /* i = 0..15 */
#define NGFW_REMAP_EN_DDOS          (1u << 16)
#define NGFW_REMAP_EN_RATE_LIMIT    (1u << 17)
#define NGFW_REMAP_EN_QOS           (1u << 18)
#define NGFW_REMAP_EN_URL_FILTER    (1u << 19)
#define NGFW_REMAP_EN_DNS_SECURITY  (1u << 20)
#define NGFW_REMAP_EN_DLP           (1u << 21)
#define NGFW_REMAP_EN_ML_INFERENCE  (1u << 22)
#define NGFW_REMAP_EN_CRED_GUARD    (1u << 23)
#define NGFW_REMAP_EN_IOT_FP        (1u << 24)
#define NGFW_REMAP_EN_NETFLOW       (1u << 25)
#define NGFW_REMAP_EN_SESSION_TBL   (1u << 26)
#define NGFW_REMAP_EN_TCAM_MATCH    (1u << 27)
#define NGFW_REMAP_EN_IPSEC         (1u << 28)
#define NGFW_REMAP_EN_SDWAN         (1u << 29)
#define NGFW_REMAP_EN_SSL_PROXY     (1u << 30)
#define NGFW_REMAP_EN_L3_ROUTER     (1u << 31)

/* Engine stage indices */
#define NGFW_STAGE_IFACE_CLASS      0
#define NGFW_STAGE_SESSION          1
#define NGFW_STAGE_NAT              2
#define NGFW_STAGE_SEC_POLICY       3
#define NGFW_STAGE_APPID            4
#define NGFW_STAGE_PROTO_DECODE     5
#define NGFW_STAGE_CID_THREAT       6
#define NGFW_STAGE_CID_MALWARE      7
#define NGFW_STAGE_CID_URL          8
#define NGFW_STAGE_CID_FILE         9
#define NGFW_STAGE_CID_SPYWARE      10
#define NGFW_STAGE_USER_POLICY      11
#define NGFW_STAGE_APP_POLICY       12
#define NGFW_STAGE_TLS_DECRYPT      13
#define NGFW_STAGE_TLS_INSPECT      14
#define NGFW_STAGE_TLS_REENCRYPT    15

/* Table IDs (write to TBL_SELECT before TBL_COMMIT) */
#define NGFW_TBL_DDOS_ZONE          0x00
#define NGFW_TBL_DDOS_THRESH_PPS    0x01
#define NGFW_TBL_DDOS_THRESH_BPS    0x02
#define NGFW_TBL_DDOS_THRESH_SYN    0x03
#define NGFW_TBL_DDOS_BLOCKLIST     0x04
#define NGFW_TBL_SEC_POLICY         0x05
#define NGFW_TBL_APPID              0x06
#define NGFW_TBL_CID_THREAT         0x07
#define NGFW_TBL_CID_URL            0x08
#define NGFW_TBL_CID_FILE           0x09
#define NGFW_TBL_USER_POLICY        0x0A
#define NGFW_TBL_APP_POLICY         0x0B
#define NGFW_TBL_SESSION            0x0C
#define NGFW_TBL_RATE_LIMIT         0x0D
#define NGFW_TBL_QOS_WEIGHTS        0x0E   /* idx[5:3]=port, idx[2:0]=queue */

/* PA-parity IP engine table IDs (config bus cp_tbl_cfg_wr_table) */
#define NGFW_TBL_DPI_ENGINE         0x10   /* Aho-Corasick patterns          */
#define NGFW_TBL_DPI_OUTPUT         0x11   /* DPI output table               */
#define NGFW_TBL_URL_FILTER         0x12   /* bloom + categories             */
#define NGFW_TBL_DNS_SECURITY       0x13   /* bloom + entropy threshold      */
#define NGFW_TBL_DLP_ENGINE         0x14   /* DLP patterns                   */
#define NGFW_TBL_ML_INFERENCE       0x15   /* BNN weights + thresholds       */
#define NGFW_TBL_CREDENTIAL_GUARD   0x16   /* trusted destinations           */
#define NGFW_TBL_IOT_FINGERPRINT    0x17   /* OUI + TCP fp + DHCP fp + meta  */
#define NGFW_TBL_NETFLOW_EXPORT     0x18   /* age_timeout, export_interval,
                                            * domain_id, collector_ip        */
#define NGFW_TBL_SESSION_TABLE      0x19   /* age_timeout, enable            */
#define NGFW_TBL_TCAM_MATCH         0x1A   /* firewall rules                 */
#define NGFW_TBL_IPSEC_ENGINE       0x1B   /* SA tables                      */
#define NGFW_TBL_SDWAN_ENGINE       0x1C   /* link metrics, app SLA          */
#define NGFW_TBL_SSL_PROXY          0x1D   /* session key cache              */
#define NGFW_TBL_BLOOM_FILTER       0x1E   /* shared bloom filter            */
#define NGFW_TBL_L3_ROUTER          0x20   /* FIB + ARP + interface config   */
#define NGFW_TBL_EGRESS_CROSSBAR    0x21   /* status only (read-only)        */
#define NGFW_TBL_ZEROTIER           0x22   /* ZT networks + peers            */

/* ZeroTier sub-tables (index high bits select sub-table within 0x22) */
#define NGFW_ZT_SUBTBL_NETWORK      0x00
#define NGFW_ZT_SUBTBL_PEER         0x01
#define NGFW_ZT_SUBTBL_STATS        0x02

/* L3 router sub-tables (index high bits select sub-table within 0x20) */
#define NGFW_L3_SUBTBL_FIB          0x00   /* idx[15:8] = sub-table 0        */
#define NGFW_L3_SUBTBL_ARP          0x01   /* idx[15:8] = sub-table 1        */
#define NGFW_L3_SUBTBL_IFACE_CFG    0x02   /* idx[15:8] = sub-table 2        */

/* IPsec sub-tables (index high bits select SA direction) */
#define NGFW_IPSEC_SUBTBL_SA_OUT    0x00   /* outbound SA                    */
#define NGFW_IPSEC_SUBTBL_SA_IN     0x01   /* inbound SA                     */
#define NGFW_IPSEC_SUBTBL_POLICY    0x02   /* SPD policy table               */

/* ML inference sub-tables (layer selection) */
#define NGFW_ML_SUBTBL_WEIGHTS      0x00   /* BNN weight data                */
#define NGFW_ML_SUBTBL_THRESHOLDS   0x01   /* per-layer thresholds           */
#define NGFW_ML_SUBTBL_CONFIG       0x02   /* enable, mode, batch size       */

/* ============================================================
 * NGFW pipeline engines (Build #16+)
 *
 * Each engine gets a 4-KiB CSR window starting at BAR2+0x10000.
 * mqnic_app_block routes BAR2[0x10000..0x1FFFF] -> ngfw_app_chain
 * port 0 (the inspection direction); ngfw_app_chain demuxes the
 * 16-bit local address with [15:12] selecting the engine.
 *
 * Within each window:
 *   +0x000  CTRL (RW: enable, flush_all, clear_stats — bit layout per engine)
 *   +0x004  STATUS (RO: bits[11:0] = NGFW_ENG_VERSION, bit[12] = flush_in_progress)
 *   +0x008+ engine-specific
 *
 * Every engine reports the same NGFW_ENG_VERSION = 0x010 so the
 * driver's probe-time self-test can detect "engine present + sane".
 * On mismatch the driver logs a warning and continues — engine
 * absence is not fatal: Build #15 bitstream pre-engines is still
 * supported, and so is the current Build #17 transitional bitstream
 * which instantiates ngfw_pipeline (Cerberus/Themis/Mnemos/Minos)
 * instead of ngfw_app_chain.  The driver reports both states clean.
 *
 * IMPORTANT: NGFW_ENG_BASE/STRIDE are interpreted against BAR2
 * (dev->dma_bar) by the driver's engine accessors — see
 * ngfw_read_eng32_ext() / ngfw_write_eng32_ext() in ffn_ngfw.c.
 * They are NOT BAR0 offsets even though earlier docs claimed so.
 * ============================================================ */

#define NGFW_ENG_BASE               0x10000  /* base of engine window in BAR2 */
#define NGFW_ENG_STRIDE             0x1000   /* 4 KiB per engine               */
#define NGFW_ENG_VERSION            0x010    /* every engine's STATUS[11:0]    */

#define NGFW_ENG_CTRL_OFFSET        0x000
#define NGFW_ENG_STATUS_OFFSET      0x004

/* Engine codenames + slot index. Order is significant — matches the
 * ngfw_app_chain demux IDs and the Build #16 mqnic_app_block wiring. */
#define NGFW_ENG_PANTHEON           0     /* virtual-system gate           */
#define NGFW_ENG_PROTEUS            1     /* NAT44 lookup engine           */
#define NGFW_ENG_DAEDALUS           2     /* vRouter (FIB + ARP)           */
#define NGFW_ENG_DAEDALUS_BOND      3     /* CMAC bond resolver            */
#define NGFW_ENG_IRIS               4     /* QoS classifier + meter        */
#define NGFW_ENG_LYNCEUS            5     /* DPI signature lookup          */
#define NGFW_ENG_AEGIS              6     /* SSL VPN session lookup (M2)   */
#define NGFW_ENG_JANUS              7     /* PQC algorithm dispatch (M2)   */
#define NGFW_ENG_ORACLE             8     /* ZeroTrust posture (M2)        */
#define NGFW_ENG_AEOLUS             9     /* SD-WAN link selector (M2)     */
#define NGFW_ENG_VERDICT_AGG        10    /* verdict aggregator (no CSRs)  */
#define NGFW_ENG_ACTION_STEER       11    /* egress demux + drop counter   */

#define NGFW_ENG_COUNT              12

/* Compute the BAR2 offset of any engine */
#define NGFW_ENG_OFFSET(eid)        (NGFW_ENG_BASE + (eid) * NGFW_ENG_STRIDE)

/* Per-engine CTRL register bit layout (uniform across all engines) */
#define NGFW_ENG_CTRL_ENABLE        (1u << 0)
#define NGFW_ENG_CTRL_FLUSH_ALL     (1u << 1)   /* W1C pulse */
#define NGFW_ENG_CTRL_CLEAR_STATS   (1u << 2)   /* W1C pulse */

/* Codename strings — defined in libngfw/ngfw_engines.c (or in a
 * single driver .c file) to avoid per-TU duplication. Header-only
 * consumers can declare them inline; the strings + sizes live in
 * one place per binary. */
extern const char * const ngfw_engine_names[NGFW_ENG_COUNT];
extern const char * const ngfw_engine_descs[NGFW_ENG_COUNT];

/* M1 engines that should be present in Build #16. M2 engines may
 * read 0xDEADC0DE on STATUS until their bitstream slot is filled. */
#define NGFW_M1_ENGINES_COUNT       8
extern const unsigned char ngfw_m1_engines[NGFW_M1_ENGINES_COUNT];

/* ============================================================
 * Crypto IP — 0x100-0x1BF (all offsets relative to 0x100)
 * ============================================================ */
#define NGFW_CR_ID                  0x00   /* 0xFF0C_0001 */
#define NGFW_CR_VERSION             0x04
#define NGFW_CR_CAPABILITIES        0x08   /* build-time bitmap */
#define NGFW_CR_ENABLE              0x0C   /* runtime mode enable */
#define NGFW_CR_STATUS              0x10
#define NGFW_CR_KEY_SIZE            0x14   /* 0=128, 1=192, 2=256 */
#define NGFW_CR_KEY_DATA_0          0x18
#define NGFW_CR_KEY_DATA_1          0x1C
#define NGFW_CR_KEY_DATA_2          0x20
#define NGFW_CR_KEY_DATA_3          0x24
#define NGFW_CR_KEY_DATA_4          0x28
#define NGFW_CR_KEY_DATA_5          0x2C
#define NGFW_CR_KEY_DATA_6          0x30
#define NGFW_CR_KEY_DATA_7          0x34
#define NGFW_CR_KEY_COMMIT          0x38
#define NGFW_CR_PQC_CTRL            0x40
#define NGFW_CR_PQC_STATUS          0x44
#define NGFW_CR_PQC_COEFF_ADDR      0x48
#define NGFW_CR_PQC_COEFF_DATA      0x4C
#define NGFW_CR_PQC_COEFF_RD        0x50

/* FIPS 140-3 */
#define NGFW_CR_FIPS_STATUS         0x54
#define NGFW_CR_ZEROIZE             0x58   /* magic value 0xDEAD_0000 */
#define NGFW_CR_POST_TRIGGER        0x5C
#define NGFW_CR_INTEGRITY_EXPECT    0x60
#define NGFW_CR_INTEGRITY_ACTUAL    0x64
#define NGFW_CR_DRBG_REQ_DATA       0x68
#define NGFW_CR_DRBG_STATUS         0x6C
#define NGFW_CR_SHA256_STATUS       0x70
#define NGFW_CR_SHA256_H0           0x74
#define NGFW_CR_SHA256_H1           0x78
#define NGFW_CR_SHA256_H2           0x7C
#define NGFW_CR_SHA256_MSG_0        0x80   /* 16 × 32-bit words */

/* Crypto modes */
#define NGFW_CR_MODE_ECB            0
#define NGFW_CR_MODE_CBC            1
#define NGFW_CR_MODE_CTR            2
#define NGFW_CR_MODE_GCM            3
#define NGFW_CR_MODE_CCM            4
#define NGFW_CR_MODE_XTS            5
#define NGFW_CR_MODE_CHACHA20       6
#define NGFW_CR_MODE_PQC            7

/* FIPS states */
#define NGFW_FIPS_STATE_POWER_ON    0
#define NGFW_FIPS_STATE_SELF_TEST   1
#define NGFW_FIPS_STATE_APPROVED    2
#define NGFW_FIPS_STATE_ERROR       3
#define NGFW_FIPS_STATE_ZEROIZE     4

/* Zeroize magic value */
#define NGFW_CR_ZEROIZE_MAGIC       0xDEAD0000u

/* ============================================================
 * Watchdog — 0x200-0x2FF (all offsets relative to 0x200)
 * ============================================================ */
#define NGFW_WDG_ID                 0x00
#define NGFW_WDG_STATE              0x04   /* [7:0] = wdg_state */
#define NGFW_WDG_HEARTBEAT          0x08   /* write periodically to keep alive */
#define NGFW_WDG_TIMEOUT_MS         0x0C   /* ms before AUTONOMOUS mode */
#define NGFW_WDG_AUTH_KEY           0x10   /* write 0xC0DECAFE to re-auth */
#define NGFW_WDG_UPTIME_SEC         0x14   /* RO: seconds since reset */
#define NGFW_WDG_MISSED_COUNT       0x18   /* RO: missed heartbeats */
#define NGFW_WDG_CONFIG_LOCKED      0x1C   /* RO: 1 = config frozen */
#define NGFW_WDG_RECOVER            0x20   /* WO: exit AUTONOMOUS on valid auth */

#define NGFW_WDG_AUTH_KEY_VALUE     0xC0DECAFEu

/* Watchdog states */
#define NGFW_WDG_STATE_NORMAL       0
#define NGFW_WDG_STATE_WARNING      1
#define NGFW_WDG_STATE_AUTONOMOUS   2
#define NGFW_WDG_STATE_RECOVERY     3

/* ============================================================
 * DMA stats memory map (via QDMA MM BAR2)
 * ============================================================ */
#define NGFW_DMA_STATS_BASE         0x0000
#define NGFW_DMA_STATS_SIZE         (1024 * 8)   /* 1024 × 64-bit counters */
#define NGFW_DMA_STATS_GLOBAL       0
#define NGFW_DMA_STATS_PORT(p)      (16 + (p) * 8)    /* 4 ports × 8 ctrs */
#define NGFW_DMA_STATS_ENGINE(e)    (64 + (e) * 4)    /* 16 legacy engines × 4 ctrs */
#define NGFW_DMA_STATS_ZONE(z)      (256 + (z))       /* 256 DDoS zones */

/* Extended stats for PA-parity engines (30 IP cores × 4 counters each) */
#define NGFW_DMA_STATS_EXT_ENGINE(e)  (512 + (e) * 4)
#define NGFW_DMA_STATS_EXT_PACKETS(e) (NGFW_DMA_STATS_EXT_ENGINE(e) + 0)
#define NGFW_DMA_STATS_EXT_MATCHES(e) (NGFW_DMA_STATS_EXT_ENGINE(e) + 1)
#define NGFW_DMA_STATS_EXT_DROPS(e)   (NGFW_DMA_STATS_EXT_ENGINE(e) + 2)
#define NGFW_DMA_STATS_EXT_ERRORS(e)  (NGFW_DMA_STATS_EXT_ENGINE(e) + 3)

/* Packet capture ring (dropped packets) */
#define NGFW_DMA_PKTCAP_BASE        0x10000
#define NGFW_DMA_PKTCAP_ENTRIES     256
#define NGFW_DMA_PKTCAP_ENTRY_SIZE  256    /* bytes per captured packet */

/* Syslog event ring */
#define NGFW_DMA_SYSLOG_BASE        0x20000
#define NGFW_DMA_SYSLOG_ENTRIES     128
#define NGFW_DMA_SYSLOG_ENTRY_SIZE  32

/* ============================================================
 * DDR4 region map (off-chip databases)
 *
 * MIG 1 (SLR1, base 0x0_0000_0000) — packet & session-heavy
 * MIG 2 (SLR2, base 0x4_0000_0000) — DB-heavy
 *
 * Sizes are RESERVED capacity; actual entries < capacity is fine.
 * ============================================================ */

#define NGFW_DDR_MIG1_BASE          0x000000000ULL
#define NGFW_DDR_MIG2_BASE          0x400000000ULL

/* MIG 1 regions (SLR1) — packet/session state */
#define NGFW_DDR_RGN_SESSIONS       0x000000000ULL  /* 64 MB — 1M × 64B */
#define NGFW_DDR_RGN_SESSIONS_SZ    (64ULL << 20)
#define NGFW_DDR_RGN_CONNTRACK      0x004000000ULL  /* 64 MB */
#define NGFW_DDR_RGN_CONNTRACK_SZ   (64ULL << 20)
#define NGFW_DDR_RGN_PKTCAP         0x008000000ULL  /* 64 MB */
#define NGFW_DDR_RGN_PKTCAP_SZ      (64ULL << 20)
#define NGFW_DDR_RGN_SYSLOG         0x00C000000ULL  /* 64 MB */
#define NGFW_DDR_RGN_SYSLOG_SZ      (64ULL << 20)
#define NGFW_DDR_RGN_FLOWSTATS      0x010000000ULL  /* 256 MB */
#define NGFW_DDR_RGN_FLOWSTATS_SZ   (256ULL << 20)
#define NGFW_DDR_RGN_PKTBUF         0x040000000ULL  /* 15 GB — packet payload pool */
#define NGFW_DDR_RGN_PKTBUF_SZ      (15ULL << 30)

/* MIG 2 regions (SLR2) — signature/policy databases */
#define NGFW_DDR_RGN_GEOIP          0x400000000ULL  /* 2 MB */
#define NGFW_DDR_RGN_GEOIP_SZ       (2ULL << 20)
#define NGFW_DDR_RGN_BLOCKLIST      0x400200000ULL  /* 4 MB */
#define NGFW_DDR_RGN_BLOCKLIST_SZ   (4ULL << 20)
#define NGFW_DDR_RGN_URL            0x400600000ULL  /* 8 MB */
#define NGFW_DDR_RGN_URL_SZ         (8ULL << 20)
#define NGFW_DDR_RGN_APPID_EXT      0x400E00000ULL  /* 3 MB */
#define NGFW_DDR_RGN_APPID_EXT_SZ   (3ULL << 20)
#define NGFW_DDR_RGN_THREATS        0x401100000ULL  /* 1 MB */
#define NGFW_DDR_RGN_THREATS_SZ     (1ULL << 20)
#define NGFW_DDR_RGN_MALWARE        0x401200000ULL  /* 1 MB */
#define NGFW_DDR_RGN_MALWARE_SZ     (1ULL << 20)
#define NGFW_DDR_RGN_FILEMAGIC      0x401300000ULL  /* 1 MB */
#define NGFW_DDR_RGN_FILEMAGIC_SZ   (1ULL << 20)
#define NGFW_DDR_RGN_TLSFP          0x401400000ULL  /* 1 MB */
#define NGFW_DDR_RGN_TLSFP_SZ       (1ULL << 20)
#define NGFW_DDR_RGN_DNSBL          0x401500000ULL  /* 3 MB */
#define NGFW_DDR_RGN_DNSBL_SZ       (3ULL << 20)
#define NGFW_DDR_RGN_SPYWARE        0x401800000ULL  /* 8 MB */
#define NGFW_DDR_RGN_SPYWARE_SZ     (8ULL << 20)
#define NGFW_DDR_RGN_VSYS_POLICY    0x402000000ULL  /* 10 MB — per-VSYS rules */
#define NGFW_DDR_RGN_VSYS_POLICY_SZ (10ULL << 20)
#define NGFW_DDR_RGN_USER_POLICY    0x402A00000ULL  /* 6 MB */
#define NGFW_DDR_RGN_USER_POLICY_SZ (6ULL << 20)

/* Region IDs — passed in NGFW_IOC_DDR_WRITE/READ */
enum ngfw_ddr_region {
    NGFW_RGN_SESSIONS = 0,
    NGFW_RGN_CONNTRACK,
    NGFW_RGN_PKTCAP,
    NGFW_RGN_SYSLOG,
    NGFW_RGN_FLOWSTATS,
    NGFW_RGN_PKTBUF,
    NGFW_RGN_GEOIP,
    NGFW_RGN_BLOCKLIST,
    NGFW_RGN_URL,
    NGFW_RGN_APPID_EXT,
    NGFW_RGN_THREATS,
    NGFW_RGN_MALWARE,
    NGFW_RGN_FILEMAGIC,
    NGFW_RGN_TLSFP,
    NGFW_RGN_DNSBL,
    NGFW_RGN_SPYWARE,
    NGFW_RGN_VSYS_POLICY,
    NGFW_RGN_USER_POLICY,
    NGFW_RGN_MAX
};

/* ============================================================
 * Char device interface (kernel driver ↔ userspace)
 * ============================================================ */
#define NGFW_DEVICE_PATH            "/dev/ngfw0"
#define NGFW_DEVICE_NAME            "ngfw"

/* ioctl numbers — see ngfw_ioctl.h for structs */
#define NGFW_IOC_MAGIC              'N'

struct ngfw_reg_rw {
    uint32_t offset;    /* byte offset from BAR0 */
    uint32_t value;     /* R: filled in; W: value to write */
};

struct ngfw_tbl_write {
    uint8_t  table_id;
    uint16_t index;
    uint64_t data;
};

struct ngfw_stats_read {
    uint16_t index;
    uint64_t value;
};

struct ngfw_key_write {
    uint8_t  key_size;      /* 0=128, 1=192, 2=256 */
    uint8_t  key[32];       /* key bytes (little-endian) */
};

struct ngfw_dma_read {
    uint64_t src_offset;    /* byte offset in DMA BAR */
    uint32_t length;
    uint8_t *dst;           /* userspace pointer */
};

struct ngfw_ddr_xfer {
    uint32_t region;        /* enum ngfw_ddr_region */
    uint64_t offset;        /* byte offset within region */
    uint64_t length;        /* bytes to transfer */
    uint8_t *buf;           /* userspace source (write) or dest (read) */
};

/* ioctl structs — generic IP config bus write */
struct ngfw_ip_cfg_write {
    uint8_t  table_id;      /* NGFW_TBL_* target IP on config bus      */
    uint16_t addr;          /* address/index within IP table           */
    uint32_t data;          /* lower 32 bits of data                   */
    uint32_t data_hi;       /* upper 32 bits of data (64-bit entries)  */
};

/* L3 FIB entry — pushed to L3_ROUTER FIB BRAM */
struct ngfw_fib_entry {
    uint32_t dst_ip;        /* destination network (host byte order)   */
    uint32_t next_hop;      /* next-hop IP address                     */
    uint8_t  egress_port;   /* physical egress port (0..3)             */
    uint8_t  prefix_len;    /* CIDR prefix length (0..32)              */
    uint8_t  vrf_id;        /* VRF / routing table ID                  */
    uint8_t  flags;         /* bit0=connected, bit1=blackhole,
                             * bit2=ECMP, bit3=recursive               */
};

/* ARP table entry — pushed to L3_ROUTER ARP BRAM */
struct ngfw_arp_entry {
    uint32_t ip;            /* IP address (host byte order)            */
    uint8_t  mac[6];        /* resolved MAC address                    */
    uint8_t  valid;         /* 1 = entry is valid, 0 = invalidate      */
    uint8_t  port;          /* physical port this neighbor is on       */
};

/* IPsec Security Association — pushed to IPSEC_ENGINE SA table */
struct ngfw_sa_entry {
    uint32_t spi;           /* Security Parameter Index                */
    uint8_t  key[32];       /* AES-256-GCM key (or AES-128/192 zero-padded) */
    uint8_t  iv[16];        /* initialization vector / nonce           */
    uint32_t seq;           /* next expected sequence number           */
    uint64_t replay_win;    /* anti-replay window bitmap               */
};

/* BNN weight load — pushed to ML_INFERENCE weight BRAM */
struct ngfw_bnn_weight_load {
    uint8_t  layer;         /* BNN layer index (0..N)                  */
    uint16_t offset;        /* word offset within layer                */
    uint32_t data;          /* binary-quantized weight word            */
};

/* Per-engine statistics readback */
struct ngfw_engine_stats {
    uint8_t  engine_id;     /* NGFW_TBL_* engine identifier            */
    uint64_t packets;       /* total packets processed                 */
    uint64_t matches;       /* hits / matches / alerts (engine-specific) */
    uint64_t drops;         /* packets dropped by this engine          */
    uint64_t errors;        /* processing errors                       */
};

/* ============================================================
 * ZeroTier offload — networks, peers, stats
 *
 * The driver keeps a bounded in-kernel state mirror and pushes each
 * registered network and peer to the FPGA via NGFW_TBL_ZEROTIER so the
 * data-plane can:
 *   - classify packets on ZT tap interfaces (iifname "zt*") without
 *     walking userspace state every time
 *   - punt unknown-peer traffic to the zerotier-one daemon
 *   - gate per-network VSYS and policy bindings at the TCAM stage
 *
 * ZT network IDs are 64-bit; peer addresses are 40-bit (packed into 64).
 * ============================================================ */

/* Network role */
#define NGFW_ZT_ROLE_CLIENT         0
#define NGFW_ZT_ROLE_MEMBER         1
#define NGFW_ZT_ROLE_CONTROLLER     2

/* Network flags */
#define NGFW_ZT_NET_FLAG_ENABLED         (1u << 0)
#define NGFW_ZT_NET_FLAG_L2              (1u << 1)  /* bridging mode          */
#define NGFW_ZT_NET_FLAG_L3              (1u << 2)  /* routed mode            */
#define NGFW_ZT_NET_FLAG_BRIDGE          (1u << 3)  /* enable 802.1 bridge    */
#define NGFW_ZT_NET_FLAG_BYPASS_HARD_MTU (1u << 4)  /* ignore port Hard MTU:
                                                      * ZT-tagged frames are
                                                      * exempt from the port
                                                      * wire-MTU check so a
                                                      * 2800-MTU ZT network
                                                      * can traverse a port
                                                      * whose hard MTU is
                                                      * smaller.             */

/* Network status */
#define NGFW_ZT_STATUS_OFFLINE      0
#define NGFW_ZT_STATUS_OK           1
#define NGFW_ZT_STATUS_REQUESTING   2
#define NGFW_ZT_STATUS_ACCESS_DENIED 3

struct ngfw_zt_network {
    uint64_t nwid;              /* ZeroTier 64-bit network ID           */
    uint16_t vsys_id;           /* virtual system this network binds to */
    uint8_t  iface_index;       /* 0..3 (or 0xFF = any)                 */
    uint8_t  flags;             /* NGFW_ZT_NET_FLAG_*                   */
    uint32_t mtu;
    uint8_t  role;              /* NGFW_ZT_ROLE_*                       */
    uint8_t  status;            /* NGFW_ZT_STATUS_*                     */
    uint8_t  _pad[2];
};

struct ngfw_zt_peer {
    uint64_t peer_id;           /* 40-bit address, zero-padded in upper */
    uint32_t last_ip;           /* last seen physical IPv4 (host order) */
    uint16_t last_port;
    uint8_t  role;              /* NGFW_ZT_ROLE_*                       */
    uint8_t  trust;             /* 0..255 trust score                   */
    uint64_t last_seen_s;       /* seconds since epoch                  */
};

struct ngfw_zt_stats {
    uint32_t network_count;
    uint32_t peer_count;
    uint64_t frames_rx;
    uint64_t frames_tx;
    uint64_t punted_to_userspace;
    uint64_t drops_unknown_peer;
    uint64_t drops_access_denied;
};

#define NGFW_IOC_ZT_NET_ADD     _IOW (NGFW_IOC_MAGIC, 0x20, struct ngfw_zt_network)
#define NGFW_IOC_ZT_NET_DEL     _IOW (NGFW_IOC_MAGIC, 0x21, struct ngfw_zt_network)
#define NGFW_IOC_ZT_PEER_ADD    _IOW (NGFW_IOC_MAGIC, 0x22, struct ngfw_zt_peer)
#define NGFW_IOC_ZT_PEER_DEL    _IOW (NGFW_IOC_MAGIC, 0x23, struct ngfw_zt_peer)
#define NGFW_IOC_ZT_STATS       _IOR (NGFW_IOC_MAGIC, 0x24, struct ngfw_zt_stats)
#define NGFW_IOC_ZT_CLEAR       _IO  (NGFW_IOC_MAGIC, 0x25)

/* Hard-Path MTU (per-physical-port wire-level MTU, independent of
 * each ngfwN netdev's soft MTU). Userspace sets it once per port at
 * boot; the data-plane enforces it on non-ZT traffic. ZeroTier
 * networks with NGFW_ZT_NET_FLAG_BYPASS_HARD_MTU skip this check. */
struct ngfw_port_hard_mtu {
    uint8_t  port_id;        /* 0..3                              */
    uint8_t  _pad[3];
    uint32_t mtu;            /* bytes; 0 on GET to return current */
};
#define NGFW_IOC_PORT_HARD_MTU_SET _IOW (NGFW_IOC_MAGIC, 0x26, struct ngfw_port_hard_mtu)
#define NGFW_IOC_PORT_HARD_MTU_GET _IOWR(NGFW_IOC_MAGIC, 0x27, struct ngfw_port_hard_mtu)

#define NGFW_IOC_REG_READ       _IOWR(NGFW_IOC_MAGIC, 0x01, struct ngfw_reg_rw)
#define NGFW_IOC_REG_WRITE      _IOW (NGFW_IOC_MAGIC, 0x02, struct ngfw_reg_rw)
#define NGFW_IOC_TBL_WRITE      _IOW (NGFW_IOC_MAGIC, 0x03, struct ngfw_tbl_write)
#define NGFW_IOC_STATS_READ     _IOWR(NGFW_IOC_MAGIC, 0x04, struct ngfw_stats_read)
#define NGFW_IOC_KEY_WRITE      _IOW (NGFW_IOC_MAGIC, 0x05, struct ngfw_key_write)
#define NGFW_IOC_DMA_READ       _IOWR(NGFW_IOC_MAGIC, 0x06, struct ngfw_dma_read)
#define NGFW_IOC_FIPS_ZEROIZE   _IO  (NGFW_IOC_MAGIC, 0x07)
#define NGFW_IOC_POST_TRIGGER   _IO  (NGFW_IOC_MAGIC, 0x08)
#define NGFW_IOC_DDR_WRITE      _IOW (NGFW_IOC_MAGIC, 0x09, struct ngfw_ddr_xfer)
#define NGFW_IOC_DDR_READ       _IOWR(NGFW_IOC_MAGIC, 0x0A, struct ngfw_ddr_xfer)
#define NGFW_IOC_DDR_REGION_INFO _IOR(NGFW_IOC_MAGIC, 0x0B, struct ngfw_ddr_xfer)

/* New ioctls — PA-parity IP engine management */
#define NGFW_IOC_IP_CFG_WRITE   _IOW (NGFW_IOC_MAGIC, 0x10, struct ngfw_ip_cfg_write)
#define NGFW_IOC_FIB_ADD        _IOW (NGFW_IOC_MAGIC, 0x11, struct ngfw_fib_entry)
#define NGFW_IOC_FIB_DEL        _IOW (NGFW_IOC_MAGIC, 0x12, struct ngfw_fib_entry)
#define NGFW_IOC_ARP_ADD        _IOW (NGFW_IOC_MAGIC, 0x13, struct ngfw_arp_entry)
#define NGFW_IOC_ARP_DEL        _IOW (NGFW_IOC_MAGIC, 0x14, struct ngfw_arp_entry)
#define NGFW_IOC_SA_ADD         _IOW (NGFW_IOC_MAGIC, 0x15, struct ngfw_sa_entry)
#define NGFW_IOC_SA_DEL         _IOW (NGFW_IOC_MAGIC, 0x16, struct ngfw_sa_entry)
#define NGFW_IOC_BNN_LOAD       _IOW (NGFW_IOC_MAGIC, 0x17, struct ngfw_bnn_weight_load)
#define NGFW_IOC_ENGINE_STATS   _IOWR(NGFW_IOC_MAGIC, 0x18, struct ngfw_engine_stats)

#endif /* NGFW_REGS_H */
