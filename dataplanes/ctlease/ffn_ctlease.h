/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FFN_CTLEASE_H
#define FFN_CTLEASE_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct ffn_ctlease_tuple {
    __be32 source, destination;
    __be16 source_port, destination_port;
};
/* Scalars use the local kernel ABI, tuples use network byte order, labels
 * are the exact 16 CTA_LABELS bytes emitted by this kernel. No pointers. */
struct ffn_ctlease_bind {
    __u32 version, conntrack_id, timeout_seconds, protocol;
    __u16 zone, reserved;
    __u32 mark;
    __u8 labels[16];
    struct ffn_ctlease_tuple original, reply;
    __u16 ethernet_bytes[2];
    __u32 reserved2;
};
struct ffn_ctlease_update {
    __u64 sequence;
    __u64 packets[2], octets[2]; /* Hardware deltas include ingress Ethernet. */
    __u32 active_mask, reserved;
};
#define FFN_CTLEASE_BIND _IOW('F', 0x70, struct ffn_ctlease_bind)
#define FFN_CTLEASE_UPDATE _IOW('F', 0x71, struct ffn_ctlease_update)
#define FFN_CTLEASE_CHECK _IO('F', 0x72)
#endif
