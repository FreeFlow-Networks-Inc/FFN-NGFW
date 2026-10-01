// SPDX-License-Identifier: GPL-2.0-or-later
/* Bind a file to one existing UDP conntrack object. No tuple-only refresh,
 * flow creation, NAT allocation, status change, or packet forwarding API.
 * This does not authorize FE100 admission or replace its withdrawal watchdog.
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
#include "ffn_ctlease.h"

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
static void tuple_init(struct nf_conntrack_tuple *t, const struct ffn_ctlease_tuple *s, u8 direction)
{
    memset(t,0,sizeof(*t));
    t->src.l3num=NFPROTO_IPV4;t->src.u3.ip=s->source;t->dst.u3.ip=s->destination;
    t->src.u.udp.port=s->source_port;t->dst.u.udp.port=s->destination_port;
    t->dst.protonum=IPPROTO_UDP;t->dst.dir=direction;
}
static int usable(struct lease *l)
{
    struct nf_conn *ct=l->ct;
    struct nf_conn_labels *labels=nf_ct_labels_find(ct);
    unsigned long status=READ_ONCE(ct->status);
    if(nf_ct_is_dying(ct) || nf_ct_is_expired(ct))return -ESTALE;
    if((status&(IPS_CONFIRMED|IPS_SEEN_REPLY|IPS_ASSURED))!=(IPS_CONFIRMED|IPS_SEEN_REPLY|IPS_ASSURED) ||
       status&(IPS_FIXED_TIMEOUT|IPS_TEMPLATE|IPS_OFFLOAD|IPS_HW_OFFLOAD) || nfct_help(ct))return -EOPNOTSUPP;
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
    /* TCP needs sequence/window and FIN/RST synchronization, not just byte
     * counters. Keep it unsupported until that separate path is qualified. */
    if(b->protocol!=IPPROTO_UDP)return -EOPNOTSUPP;
    if(b->version!=1 || !b->conntrack_id || b->reserved || b->reserved2 ||
       !b->timeout_seconds || b->timeout_seconds>300 ||
       !memchr_inv(b->labels,0,sizeof(b->labels)))return -EINVAL;
    for(unsigned i=0;i<2;i++)if(b->ethernet_bytes[i]!=14 && b->ethernet_bytes[i]!=18)return -EINVAL;
    tuple_init(&orig,&b->original,IP_CT_DIR_ORIGINAL);
    tuple_init(&reply,&b->reply,IP_CT_DIR_REPLY);
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
        l->ct=ct;l->identity=*b;err=usable(l);
        if(err)l->ct=NULL;
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
static int lease_release(struct inode *inode,struct file *file)
{
    struct lease *l=file->private_data;
    if(l->ct) {
        mutex_lock(&claims_lock);list_del(&l->claim);mutex_unlock(&claims_lock);
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
MODULE_DESCRIPTION("FFN identity-bound UDP hardware accounting lease");
