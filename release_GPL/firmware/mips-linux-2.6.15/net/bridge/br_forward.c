/*
 *	Forwarding decision
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	$Id: //depot/sw/src3/linux/kernels/mips-linux-2.6.15/net/bridge/br_forward.c#1 $
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter_bridge.h>
#include "br_private.h"

static inline int should_deliver(const struct net_bridge_port *p, 
				 const struct sk_buff *skb)
{
	if (skb->dev == p->dev ||
	    p->state != BR_STATE_FORWARDING)
		return 0;

	return 1;
}

int br_dev_queue_push_xmit(struct sk_buff *skb)
{
	/* drop mtu oversized packets except tso */
	if (skb->len > skb->dev->mtu && !skb_shinfo(skb)->tso_size)
		kfree_skb(skb);
	else {
#ifdef CONFIG_BRIDGE_NETFILTER
		/* ip_refrag calls ip_fragment, doesn't copy the MAC header. */
		nf_bridge_maybe_copy_header(skb);
#endif
		skb_push(skb, ETH_HLEN);

		dev_queue_xmit(skb);
	}

	return 0;
}

int br_forward_finish(struct sk_buff *skb)
{
	NF_HOOK(PF_BRIDGE, NF_BR_POST_ROUTING, skb, NULL, skb->dev,
			br_dev_queue_push_xmit);

	return 0;
}

static void __br_deliver(const struct net_bridge_port *to, struct sk_buff *skb)
{
	skb->dev = to->dev;
	NF_HOOK(PF_BRIDGE, NF_BR_LOCAL_OUT, skb, NULL, skb->dev,
			br_forward_finish);
}

static void __br_forward(const struct net_bridge_port *to, struct sk_buff *skb)
{
	struct net_device *indev;

	indev = skb->dev;
	skb->dev = to->dev;
	skb->ip_summed = CHECKSUM_NONE;

	NF_HOOK(PF_BRIDGE, NF_BR_FORWARD, skb, indev, skb->dev,
			br_forward_finish);
}

/* called with rcu_read_lock */
void br_deliver(const struct net_bridge_port *to, struct sk_buff *skb)
{
	if (should_deliver(to, skb)) {
		__br_deliver(to, skb);
		return;
	}

	kfree_skb(skb);
}

/* called with rcu_read_lock */
void br_forward(const struct net_bridge_port *to, struct sk_buff *skb)
{
	if (should_deliver(to, skb)) {
		__br_forward(to, skb);
		return;
	}

	kfree_skb(skb);
}

/* called under bridge lock */
static void br_flood(struct net_bridge *br, struct sk_buff *skb, int clone,
	void (*__packet_hook)(const struct net_bridge_port *p, 
			      struct sk_buff *skb))
{
	struct net_bridge_port *p;
	struct net_bridge_port *prev;

#ifdef CONFIG_SC_FEATURE_ENABLE 
	unsigned char *dest;
	struct net_bridge_fdb_entry *dst = NULL;
	int    to_limit_if = 0;

	/* to check if pkt dst if to the port that need do limitation*/
	if (br && br_if_limitation)
	{
		dest = skb->mac.ethernet->h_dest;
		dst = br_fdb_get(br, dest);

		if (dst && dst->dst && dst->dst->dev && dst->dst->dev->name)	
		{

			to_limit_if = (!strcmp(dst->dst->dev->name, IF_NAME_TO_LIMIT));
//            printk("%s:%d do_acl:%d devname:%s to_if:%d mac:%02x:%02x:%02x:%02x:%02x:%02x\n", __FILE__, __LINE__,
//                    br_if_limitation, dst->dst->dev->name,to_limit_if, dest[0],dest[1],dest[2],dest[3],dest[4],dest[5]);
		}
	}
#endif

	if (clone) {
		struct sk_buff *skb2;

		if ((skb2 = skb_clone(skb, GFP_ATOMIC)) == NULL) {
			br->statistics.tx_dropped++;
			return;
		}

		skb = skb2;
	}

	prev = NULL;

	list_for_each_entry_rcu(p, &br->port_list, list) {
		if (should_deliver(p, skb)) {
#ifdef CONFIG_SC_FEATURE_ENABLE 
        	/*
        	 * limitation off || dst not to limit iterface || dst is for the right port,
        	 * then forward it!	 
        	 */
        	if (!br_if_limitation || !to_limit_if || (to_limit_if && !strcmp(p->dev->name, IF_NAME_TO_LIMIT)))
        	{
#endif
    			if (prev != NULL) {
    				struct sk_buff *skb2;
    
    				if ((skb2 = skb_clone(skb, GFP_ATOMIC)) == NULL) {
    					br->statistics.tx_dropped++;
    					kfree_skb(skb);
    					return;
    				}
    
    				__packet_hook(prev, skb2);
    			}

    			prev = p;
#ifdef CONFIG_SC_FEATURE_ENABLE
			}
#endif
		}
	}

	if (prev != NULL) {
		__packet_hook(prev, skb);
		return;
	}

	kfree_skb(skb);
}


/* called with rcu_read_lock */
void br_flood_deliver(struct net_bridge *br, struct sk_buff *skb, int clone)
{
	br_flood(br, skb, clone, __br_deliver);
}

/* called under bridge lock */
void br_flood_forward(struct net_bridge *br, struct sk_buff *skb, int clone)
{
	br_flood(br, skb, clone, __br_forward);
}
