/* SPDX-License-Identifier: GPL-2.0-or-later
 * ffn_dp_io_octeon.h -- OCTEON-II hardware packet-I/O backend (IPD/PIP + POW + PKO).
 *
 * NAMING: the shorthand is "PKI/PKO". On OCTEON-III (cn78xx) the input block
 * really is PKI + SSO; on the OCTEON-II parts in a PA-5220 it is IPD/PIP (input)
 * + POW (work scheduling) + PKO (output). This backend targets OCTEON-II and
 * uses those names; the structure is identical for PKI/SSO/PKO3.
 *
 * LICENSING / WHAT FFN SHIPS
 * -------------------------
 * The CVMX headers and libraries are Cavium/Marvell OCTEON SDK property. FFN
 * ships THIS SOURCE ONLY -- our own code calling a documented hardware API. It
 * compiles against an SDK the operator supplies on their own box for their own
 * hardware, gated behind -DFFN_HAVE_CVMX. Without the SDK the file still builds
 * and links, reporting the backend as unavailable, so the dataplane keeps
 * working on the AF_PACKET path. No SDK-derived binary ever ships with FFN.
 *
 * BUFFER OWNERSHIP (the property that matters most)
 * ------------------------------------------------
 * Every work-queue entry from POW owns two allocations: the WQE itself (FPA WQE
 * pool) and the packet data (FPA packet pool). Each must be released EXACTLY
 * ONCE or the box leaks FPA buffers and wedges within minutes. Rules enforced:
 *   * on transmit, PKO takes ownership of the packet data and frees it after the
 *     wire, so we must NOT free the data -- only the WQE;
 *   * on drop, we free both;
 *   * a send failure leaves ownership with us, so we free both;
 *   * every WQE records its disposition, and a second disposal is a no-op that
 *     increments a bug counter instead of double-freeing.
 * The mock hardware in the test harness asserts exactly this.
 */
#ifndef FFN_DP_IO_OCTEON_H
#define FFN_DP_IO_OCTEON_H

#include "ffn_dp_oct.h"
#include <stdint.h>
#include <stdio.h>

#define OCT_MAX_PORTS   8
#define OCT_BURST       DP_BURST

/* disposition of a work entry, tracked so nothing is released twice */
enum oct_disp {
    OCT_DISP_HELD = 0,      /* we still own it               */
    OCT_DISP_SENT,          /* data handed to PKO, WQE freed  */
    OCT_DISP_FREED,         /* both released by us            */
};

/* One received work item, abstracted away from cvmx types so the logic is
 * testable without the SDK. `hw` is the opaque cvmx_wqe_t* on real hardware. */
struct oct_wqe {
    void    *hw;            /* cvmx_wqe_t*                   */
    uint8_t *data;          /* packet data                   */
    uint32_t len;
    uint16_t in_port;       /* IPD port -> our port index    */
    uint8_t  segs;          /* buffer segments (1 = linear)  */
    uint8_t  disp;          /* enum oct_disp                 */
    /* OCTEON-III only. FPA3 frees to an AURA, not a pool, and PKI may place the
     * WQE and the packet data in DIFFERENT auras -- so a single-pool assumption
     * (correct on OCTEON-II) silently corrupts FPA accounting here. Each buffer
     * therefore carries the aura it must be returned to. OCTEON-II leaves these
     * zero and ignores them. */
    uint16_t data_aura;
    uint16_t wqe_aura;
};

/* Which OCTEON family the hardware backend is talking to. Selected at runtime so
 * one FFN build serves a PA-3200 (OCTEON-II) and a PA-5220 (OCTEON-III). */
enum oct_gen {
    OCT_GEN_NONE = 0,
    OCT_GEN_II,             /* IPD/PIP + POW  + PKO   (cn6xxx/cn7xxx-II) */
    OCT_GEN_III,            /* PKI     + SSO  + PKO3  (cn73xx/cn78xx)    */
};

const char *oct_gen_name(enum oct_gen g);
enum oct_gen oct_detect_gen(void);
const struct oct_hw_ops *oct_hw_for_gen(enum oct_gen g);

struct oct_ctx;

/* Hardware seam: the real implementation calls CVMX, the mock implementation in
 * the test harness simulates POW/PKO so ownership rules can be verified. */
struct oct_hw_ops {
    const char *name;
    int  (*init)(struct oct_ctx *c);
    void (*fini)(struct oct_ctx *c);
    /* 1 if a work item was dequeued, 0 if none pending */
    int  (*work_get)(struct oct_ctx *c, struct oct_wqe *w);
    /* hand the packet to PKO on `port`; 0 = success (PKO now owns the data) */
    int  (*pkt_send)(struct oct_ctx *c, struct oct_wqe *w, uint16_t port);
    /* release the packet data buffer we still own */
    void (*data_free)(struct oct_ctx *c, struct oct_wqe *w);
    /* release the WQE itself */
    void (*wqe_free)(struct oct_ctx *c, struct oct_wqe *w);
};

struct oct_port {
    uint16_t port_id;       /* index used by the policy `egress` field */
    int      ipd_port;      /* OCTEON IPD/PKO port number             */
    int      pko_queue;
    uint8_t  vsys;
    char     name[16];
};

struct oct_ctx {
    const struct oct_hw_ops *hw;
    void    *hw_priv;                       /* mock state / cvmx bits */
    struct oct_port ports[OCT_MAX_PORTS];
    int      nports;
    int      core_id;
    int      pow_group;
    int      available;                     /* hardware present + initialised */
    struct oct_wqe inflight[OCT_BURST];     /* current burst */
    int      n_inflight;

    uint64_t stat_rx, stat_tx, stat_tx_fail, stat_drop_freed, stat_local;
    uint64_t stat_no_egress, stat_bad_egress, stat_offload;
    uint64_t stat_wqe_freed, stat_data_freed;
    uint64_t bug_double_dispose;            /* must stay 0 */
};

/* the dp_io_ops vtable for this backend */
extern const struct dp_io_ops OCT_IO;

/* Hardware op tables, one per generation. Either may be a stub that reports the
 * backend unavailable when built without the matching SDK support. */
extern const struct oct_hw_ops OCT_HW_CVMX;    /* OCTEON-II  */
extern const struct oct_hw_ops OCT_HW_CVMX3;   /* OCTEON-III */

void oct_ctx_init(struct oct_ctx *c, const struct oct_hw_ops *hw, void *hw_priv);
int  oct_add_port(struct oct_ctx *c, const char *name, int ipd_port,
                  int pko_queue, uint8_t vsys);
void oct_dump_stats(const struct oct_ctx *c, FILE *f);
int  oct_backend_available(void);           /* built with CVMX? */
const char *oct_backend_name(void);

#endif /* FFN_DP_IO_OCTEON_H */
