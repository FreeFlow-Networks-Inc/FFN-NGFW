// SPDX-License-Identifier: GPL-2.0-or-later
/* Bind a file to one existing UDP or established TCP conntrack object. No
 * tuple-only refresh, flow creation, NAT allocation, status change, or packet
 * forwarding API. This does not authorize FE100 admission or replace its
 * withdrawal watchdog.
 *
 * TCP: while the hardware carries the flow the kernel sees none of its
 * segments, so its window tracking goes stale and would drop every segment
 * as invalid on hand-back (PA-5220, 2026-10-19). Binding therefore marks both
 * directions BE_LIBERAL, exactly as nf_flow_table does when it offloads a
 * flow, and release zeroes both td_maxwin so the windows are re-learned from
 * the next segments, as its teardown fixup does. A FIN or RST that reaches the
 * kernel moves the state off ESTABLISHED and invalidates the lease; the owner
 * must make such segments reach the kernel (hardware exception or acknowledged
 * withdrawal). Sequence-adjusted and helper sessions are rejected.
 */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/nsproxy.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_labels.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include "ffn_ctlease.h"

#define FFN_CTLEASE_UDP_MAX_TIMEOUT 300U
/* nf_conntrack_tcp_timeout_established's default: a leased established flow
 * must not expire sooner than it would in software. */
#define FFN_CTLEASE_TCP_MAX_TIMEOUT 432000U

struct lease {
    struct list_head claim;
    struct mutex lock;
    struct net *net;
    struct nf_conn *ct;
    struct ffn_ctlease_bind identity;
    u64 sequence;
    bool invalid;
};
/* A single accounting owner per object, even across separate file handles. */
static LIST_HEAD(claims);
static DEFINE_MUTEX(claims_lock);
static void tuple_init(struct nf_conntrack_tuple *t, const struct ffn_ctlease_tuple *s, u8 direction, u8 protocol)
{
    memset(t,0,sizeof(*t));
    t->src.l3num=NFPROTO_IPV4;t->src.u3.ip=s->source;t->dst.u3.ip=s->destination;
    t->src.u.all=s->source_port;t->dst.u.all=s->destination_port;
    t->dst.protonum=protocol;t->dst.dir=direction;
}
static u32 max_timeout(u32 protocol)
{
    return protocol==IPPROTO_TCP?FFN_CTLEASE_TCP_MAX_TIMEOUT:FFN_CTLEASE_UDP_MAX_TIMEOUT;
}
static int usable(struct lease *l)
{
    struct nf_conn *ct=l->ct;
    struct nf_conn_labels *labels=nf_ct_labels_find(ct);
    unsigned long status=READ_ONCE(ct->status);
    if(nf_ct_is_dying(ct) || nf_ct_is_expired(ct))return -ESTALE;
    if((status&(IPS_CONFIRMED|IPS_SEEN_REPLY|IPS_ASSURED))!=(IPS_CONFIRMED|IPS_SEEN_REPLY|IPS_ASSURED) ||
       status&(IPS_FIXED_TIMEOUT|IPS_TEMPLATE|IPS_OFFLOAD|IPS_HW_OFFLOAD|IPS_SEQ_ADJUST) || nfct_help(ct))return -EOPNOTSUPP;
    /* A FIN or RST reached the kernel: the hardware flow must be withdrawn. */
    if(l->identity.protocol==IPPROTO_TCP && ct->proto.tcp.state!=TCP_CONNTRACK_ESTABLISHED)return -ESTALE;
    /* ctnetlink_dump_id casts the opaque hash to __be32 without htonl.
     * Match the numeric CTA_ID returned by a normal netlink decoder. */
    if(be32_to_cpu((__force __be32)nf_ct_get_id(ct))!=l->identity.conntrack_id ||
       READ_ONCE(ct->mark)!=l->identity.mark || !labels ||
       memcmp(labels->bits,l->identity.labels,sizeof(l->identity.labels)))return -ESTALE;
    if(!nf_conn_acct_find(ct))return -EOPNOTSUPP;
    return 0;
}
static int bind_lease(struct lease *l, const struct ffn_ctlease_bind *b)
{
    struct nf_conntrack_tuple orig,reply;
    struct nf_conntrack_tuple_hash *found;
    struct nf_conntrack_zone zone;
    struct nf_conn *ct;
    struct lease *other;
    int err;
    if(l->ct)return -EALREADY;
    if(b->protocol!=IPPROTO_UDP && b->protocol!=IPPROTO_TCP)return -EOPNOTSUPP;
    if(b->version!=1 || !b->conntrack_id || b->reserved || b->reserved2 ||
       !b->timeout_seconds || b->timeout_seconds>max_timeout(b->protocol) ||
       !memchr_inv(b->labels,0,sizeof(b->labels)))return -EINVAL;
    for(unsigned i=0;i<2;i++)if(b->ethernet_bytes[i]!=14 && b->ethernet_bytes[i]!=18)return -EINVAL;
    tuple_init(&orig,&b->original,IP_CT_DIR_ORIGINAL,b->protocol);
    tuple_init(&reply,&b->reply,IP_CT_DIR_REPLY,b->protocol);
    nf_ct_zone_init(&zone,b->zone,NF_CT_DEFAULT_ZONE_DIR,0);
    found=nf_conntrack_find_get(l->net,&zone,&orig);
    if(!found)return -ENOENT;
    ct=nf_ct_tuplehash_to_ctrack(found);
    mutex_lock(&claims_lock);
    list_for_each_entry(other,&claims,claim) {
        if(other->ct==ct) {
            mutex_unlock(&claims_lock);nf_ct_put(ct);return -EBUSY;
        }
    }
    spin_lock_bh(&ct->lock);
    if(NF_CT_DIRECTION(found)!=IP_CT_DIR_ORIGINAL ||
       !nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,&orig) ||
       !nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_REPLY].tuple,&reply))err=-ESTALE;
    else {
        l->ct=ct;l->identity=*b;
        /* Only an established flow can be carried blind; anything else is
         * unsupported at bind time rather than stale. */
        err=b->protocol==IPPROTO_TCP && ct->proto.tcp.state!=TCP_CONNTRACK_ESTABLISHED?-EOPNOTSUPP:usable(l);
        if(err)l->ct=NULL;
        else if(b->protocol==IPPROTO_TCP) {
            ct->proto.tcp.seen[0].flags|=IP_CT_TCP_FLAG_BE_LIBERAL;
            ct->proto.tcp.seen[1].flags|=IP_CT_TCP_FLAG_BE_LIBERAL;
        }
    }
    spin_unlock_bh(&ct->lock);
    if(!err)list_add(&l->claim,&claims);
    mutex_unlock(&claims_lock);
    if(err)nf_ct_put(ct);
    return err;
}
static int update_lease(struct lease *l, const struct ffn_ctlease_update *u)
{
    struct nf_conn_acct *acct;
    int err;
    if(!l->ct)return -ENOTCONN;
    if(l->invalid)return -ESTALE;
    if(!u->sequence || u->sequence!=l->sequence+1 || u->reserved || u->active_mask&~3U)return -EINVAL;
    if(!u->packets[0] && !u->packets[1])return -EINVAL;
    for(unsigned i=0;i<2;i++) {
        if(u->packets[i]>65535 || u->octets[i]>u->packets[i]*9216 ||
           u->octets[i]<u->packets[i]*(l->identity.ethernet_bytes[i]+20) ||
           ((u->active_mask&(1U<<i)) && !u->packets[i]))return -EINVAL;
    }
    spin_lock_bh(&l->ct->lock);
    err=usable(l);
    if(err)l->invalid=true;
    if(!err) {
        acct=nf_conn_acct_find(l->ct);
        /* Never shorten a timeout refreshed by a recent software packet. */
        if(u->active_mask && nf_ct_expires(l->ct)<l->identity.timeout_seconds*HZ)
            nf_ct_refresh(l->ct,l->identity.timeout_seconds*HZ);
        for(unsigned i=0;i<2;i++) {
            atomic64_add(u->packets[i],&acct->counter[i].packets);
            atomic64_add(u->octets[i]-u->packets[i]*l->identity.ethernet_bytes[i],&acct->counter[i].bytes);
        }
        l->sequence=u->sequence;
        if(nf_ct_is_dying(l->ct)) {l->invalid=true;err=-ESTALE;}
    }
    spin_unlock_bh(&l->ct->lock);
    return err;
}
static int check_lease(struct lease *l)
{
    int err;
    if(!l->ct)return -ENOTCONN;
    if(l->invalid)return -ESTALE;
    spin_lock_bh(&l->ct->lock);
    err=usable(l);
    if(err)l->invalid=true;
    spin_unlock_bh(&l->ct->lock);
    return err;
}
static long control(struct file *file,unsigned int cmd,unsigned long arg)
{
    struct lease *l=file->private_data;
    struct ffn_ctlease_bind bind;
    struct ffn_ctlease_update update;
    int err;
    if(current->nsproxy->net_ns!=l->net || !ns_capable(l->net->user_ns,CAP_NET_ADMIN))return -EPERM;
    if(cmd==FFN_CTLEASE_BIND) {
        if(copy_from_user(&bind,(void __user *)arg,sizeof(bind)))return -EFAULT;
    } else if(cmd==FFN_CTLEASE_UPDATE) {
        if(copy_from_user(&update,(void __user *)arg,sizeof(update)))return -EFAULT;
    } else if(cmd==FFN_CTLEASE_CHECK) {
        if(arg)return -EINVAL;
    } else return -ENOTTY;
    mutex_lock(&l->lock);
    err=cmd==FFN_CTLEASE_BIND?bind_lease(l,&bind):
        cmd==FFN_CTLEASE_UPDATE?update_lease(l,&update):check_lease(l);
    mutex_unlock(&l->lock);
    return err;
}
static int lease_open(struct inode *inode,struct file *file)
{
    struct lease *l;
    if(!ns_capable(current->nsproxy->net_ns->user_ns,CAP_NET_ADMIN))return -EPERM;
    l=kzalloc(sizeof(*l),GFP_KERNEL);if(!l)return -ENOMEM;
    mutex_init(&l->lock);l->net=get_net(current->nsproxy->net_ns);file->private_data=l;
    return nonseekable_open(inode,file);
}
static void handback(struct lease *l)
{
    struct nf_conn *ct=l->ct;
    if(l->identity.protocol!=IPPROTO_TCP)return;
    spin_lock_bh(&ct->lock);
    /* The flow is back on the software path: re-learn both windows from the
     * next segments (nf_flow_table's teardown fixup). BE_LIBERAL stays, as
     * there too, so segments reordered across the hand-back are not invalid. */
    if(!nf_ct_is_dying(ct) && ct->proto.tcp.state==TCP_CONNTRACK_ESTABLISHED) {
        ct->proto.tcp.seen[0].td_maxwin=0;
        ct->proto.tcp.seen[1].td_maxwin=0;
    }
    spin_unlock_bh(&ct->lock);
}
static int lease_release(struct inode *inode,struct file *file)
{
    struct lease *l=file->private_data;
    if(l->ct) {
        mutex_lock(&claims_lock);list_del(&l->claim);mutex_unlock(&claims_lock);
        handback(l);
        nf_ct_put(l->ct);
    }
    put_net(l->net);kfree(l);return 0;
}
static const struct file_operations operations={.owner=THIS_MODULE,.open=lease_open,
    .release=lease_release,.unlocked_ioctl=control};
static struct miscdevice device={.minor=MISC_DYNAMIC_MINOR,.name="ffn-ctlease",.fops=&operations,.mode=0600};
static int __init lease_init(void)
{
    BUILD_BUG_ON(sizeof(struct ffn_ctlease_bind)!=72);
    BUILD_BUG_ON(sizeof(struct ffn_ctlease_update)!=48);
    return misc_register(&device);
}
static void __exit lease_exit(void) {misc_deregister(&device);}
module_init(lease_init);module_exit(lease_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FFN identity-bound UDP/TCP hardware accounting lease");
