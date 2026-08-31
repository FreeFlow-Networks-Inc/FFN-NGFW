/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_fastpath.h -- shared ABI between ffn_fastpath_compile.py (producer) and
 * the DPDK fast path ffn_dpdk_fwd (consumer). Field layouts MUST match the
 * Python compiler's struct.pack formats exactly (little-endian, packed).
 * See docs/FASTPATH_ABI.md.
 */
#ifndef FFN_FASTPATH_H
#define FFN_FASTPATH_H
#include <stdint.h>

/* action codes (shared with ffn_sigdb / ffn_threatdb) */
enum { FP_ACT_ALERT = 0, FP_ACT_DROP = 1, FP_ACT_RESET = 2 };
/* classify decision */
enum { FP_FORWARD = 0, FP_INSPECT = 1, FP_PUNT_FPGA = 2, FP_DROP = 3, FP_LOCAL = 4 };
/* per-flow cached verdict */
enum { FP_V_UNSET = 0, FP_V_ALLOW = 1, FP_V_DROP = 2, FP_V_RESET = 3 };

/* table_type ids + magics */
#define FP_T_POLICY  0x40
#define FP_T_PATMETA 0x41
#define FP_T_AVHASH  0x42
#define FP_T_STRINGS 0x43
#define FP_MAGIC_POLICY  "FPPO"
#define FP_MAGIC_PATMETA "FPPM"
#define FP_MAGIC_AVHASH  "FPPH"
#define FP_MAGIC_STRINGS "FPPS"

/* Pass-2 in-dpmem engine-blob envelopes (DP-side ABI). The management plane /
 * emulator / ML producer wraps every hot-swappable blob it stages into a
 * shared-memory (ffn_dpmem.h) bank with an fp_hdr carrying one of these magics,
 * so the data plane locates it by magic when it flips to a new active bank.
 * These are the "AC/DFA/ML tables" the fast path consumes per REWORK_CONTRACT
 * §10; the bank layout itself (offsets/size/active index) is owned by
 * ffn_dpmem.h, which this header does NOT define. */
#define FP_T_HSBLOCK  0x44   /* serialized Hyperscan BLOCK database (AC/DFA)   */
#define FP_T_HSSTREAM 0x45   /* serialized Hyperscan STREAM database (AC/DFA)  */
#define FP_T_MLTREE   0x46   /* inline-ML flat tree / n-gram blob (opaque)     */
#define FP_T_TELEM    0x47   /* DP->MP per-engine telemetry snapshot           */
#define FP_MAGIC_HSBLOCK  "FPHB"
#define FP_MAGIC_HSSTREAM "FPHT"
#define FP_MAGIC_MLTREE   "FPML"
#define FP_MAGIC_TELEM    "FPTL"

#pragma pack(push, 1)

/* 36-byte common header (matches ffn_fastpath_compile._hdr / HDR_FMT) */
struct fp_hdr {
    char     magic[4];
    uint16_t version;
    uint16_t table_type;
    uint32_t entry_count;
    uint64_t build_unix;
    uint32_t crc32;
    uint32_t record_size;
    uint32_t populated;
    uint32_t reserved;
};

/* policy.bin, type 0x40, 32 bytes */
struct fp_policy_ent {
    uint32_t src_ip, src_mask, dst_ip, dst_mask;   /* network byte order */
    uint16_t sport_lo, sport_hi, dport_lo, dport_hi;
    uint8_t  proto, vsys, action, flags;           /* action = FP_FORWARD.. */
    uint16_t egress_port, rule_id;
};

/* patmeta.bin, type 0x41, 30 bytes, direct-indexed by Hyperscan pattern id */
struct fp_patmeta_ent {
    uint32_t pat_id, hs_flags, min_offset, max_offset;
    uint16_t min_length;
    uint8_t  action, severity, origin, host_confirm;
    uint16_t combo_group, name_idx, verdict, src_sid;
};

/* avhash.bin, type 0x42, 40 bytes, open-addressed linear probe */
struct fp_avhash_ent {
    uint8_t  sha256[32];       /* all-zero = empty slot */
    uint32_t file_size;        /* 0 = any */
    uint8_t  action, severity;
    uint16_t name_idx;
};

/* DP->MP telemetry snapshot row (mirrors ffn.mpdp.EngineTelemetry from
 * ffn_mpdp.fbs). The data plane writes an array of these, indexed by the
 * FP_ENG_* enum below, into the telemetry memzone; the management plane
 * (ffn_mpdp_wire.py) re-emits them as EngineTelemetry on the FlatBuffers wire.
 * type 0x47, 56 bytes. */
struct fp_engine_stat {
    char     engine[24];       /* NUL-padded engine name (ENGINE_BACKENDS key)  */
    uint64_t packets, matches, drops;
    uint8_t  mode;             /* 0=host 1=emulated 2=hardware                  */
    uint8_t  pad[7];
};

#pragma pack(pop)

#define FP_HDR_SIZE         36
#define FP_POLICY_SIZE      32
#define FP_PATMETA_SIZE     30
#define FP_AVHASH_SIZE      40
#define FP_ENGINE_STAT_SIZE 56

/* Telemetry engine slots the DP publishes (indices into the telemetry array). */
enum {
    FP_ENG_TCAM = 0,       /* tcam_lookup   : policy classify        */
    FP_ENG_DPI_REGEX,      /* dpi_regex     : Hyperscan content scan */
    FP_ENG_TCP_REASM,      /* tcp_reassembly: TCP path               */
    FP_ENG_UDP_PROC,       /* udp_processor : UDP path               */
    FP_ENG_FLOW_EXPORT,    /* flow_exporter : flow table / events    */
    FP_ENG_COUNT
};

/* runtime flow table (not mmap'd).
 * `vsys` is the per-packet virtual-system tag (REWORK_CONTRACT §2): a stable
 * int in [1..N], 0 = shared/untagged. It is part of the flow-table key so flows
 * in different vsys never alias, and classify() matches policy rows on it. The
 * data plane reads it from the mbuf flow-director mark (rte_flow MARK action set
 * by the NIC, or meta mark carried from the kernel MP path). */
struct flow_key {
    uint32_t ip_a, ip_b;       /* normalized ip_a<=ip_b for bidir match */
    uint16_t port_a, port_b;
    uint8_t  proto, vsys;
    uint16_t pad;
};
struct flow_state {
    uint8_t  verdict;          /* FP_V_* */
    uint8_t  flags;            /* bit0 offloaded, bit1 inspected_done, bit2 punted */
    uint16_t rule_id;
    uint32_t pkts, bytes;
    uint64_t last_tsc;
    void    *hs_stream;        /* hs_stream_t*, NULL until first payload */
};
#define FLOW_F_OFFLOADED  0x1
#define FLOW_F_INSPECTED  0x2
#define FLOW_F_PUNTED     0x4

/* loaded-table handles */
struct fp_tables {
    const struct fp_policy_ent  *policy;   uint32_t policy_n;
    const struct fp_patmeta_ent *patmeta;  uint32_t patmeta_n;
    const struct fp_avhash_ent  *avhash;   uint32_t avhash_slots;
    const char *strings;                   uint32_t strings_n;
};

#endif /* FFN_FASTPATH_H */
