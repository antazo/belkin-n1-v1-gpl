/*****************************************************************************
//
//  Copyright (c) 2000-2002  Broadcom Corporation
//  All Rights Reserved
//  No portions of this material may be reproduced in any form without the
//  written permission of:
//          Broadcom Corporation
//          16215 Alton Parkway
//          Irvine, California 92619
//  All information contained in this document is Broadcom Corporation
//  company private, proprietary, and trade secret.
//
******************************************************************************
//
//  Filename:       ip_conntrack_ipsec.c
//  Author:         Pavan Kumar
//  Creation Date:  05/27/04
//
//  Description:
//      Implements the IPSec ALG connectiontracking.
//
*****************************************************************************/
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ip_conntrack_helper.h>
#include <linux/netfilter_ipv4/ip_conntrack_ipsec.h>
#include <linux/moduleparam.h>


#define IPSEC_FREE  0
#define IPSEC_INUSE 1
#define MAX_PORTS 64

static struct _ipsec_table {
	ulong initcookie[2];
	ulong respcookie[2];
	u_int32_t l_ip;
	u_int32_t r_ip;
	u_int32_t timeout;
	int       inuse;
} ipsec_table[MAX_PORTS];

static int ports[MAX_PORTS];
static int ports_c = 0;
#ifdef MODULE_PARM
MODULE_PARM(ports, "1-" __MODULE_STRING(MAX_PORTS) "i");
MODULE_PARM_DESC(ports, "port numbers of IPSEC");
#endif

#if 0
#define DEBUGP(format, args...)	printk(KERN_DEBUG "%s:%s: " format, __FILE__, __FUNCTION__, ## args)
#else
#define DEBUGP(format, args...)
#endif

unsigned int (*ip_nat_ipsec_hook)(struct sk_buff **pskb,
				 enum ip_conntrack_info ctinfo,
				 u_int32_t l_ip,
				 struct ip_conntrack_expect *exp);
EXPORT_SYMBOL_GPL(ip_nat_ipsec_hook);
/*
 * Allocate a free IPSEC table entry.
 */
struct _ipsec_table *alloc_ipsec_entry ( void )
{
	int idx = 0;
	struct _ipsec_table *ipsec_entry = ipsec_table;

	for ( ; idx < MAX_PORTS; idx++ ) {
		if ( ipsec_entry->inuse == IPSEC_FREE ) {
			return ipsec_entry;
		}
		ipsec_entry++;
	}
	return NULL;
}

/*
 * Search an IPSEC table entry by the source IP address.
 */
struct _ipsec_table *search_ipsec_entry_by_addr ( struct isakmphdr *isakmph,
					      const struct iphdr *iph )
{
	int idx = 0;
	struct _ipsec_table *ipsec_entry = ipsec_table;

	for ( ; idx < MAX_PORTS; idx++ ) {
		if ( ntohl(ipsec_entry->l_ip) == ntohl(iph->saddr) ) {
			return ipsec_entry;
		}
		ipsec_entry++;
	}
	return NULL;
}

/*
 * Search an IPSEC table entry by the initiator cookie.
 */
struct _ipsec_table *search_ipsec_entry_by_cookie ( struct isakmphdr *isakmph )
{
	int idx = 0;
	struct _ipsec_table *ipsec_entry = ipsec_table;

	for ( ; idx < MAX_PORTS; idx++ ) {
		if ( (ntohl(isakmph->initcookie[0]) == ntohl(ipsec_entry->initcookie[0])) &&
		     (ntohl(isakmph->initcookie[1]) == ntohl(ipsec_entry->initcookie[1]))) {
			return ipsec_entry;
		}
		ipsec_entry++;
	}
	return NULL;
}

/*
 * Handle an incoming packet.
 */
static int ipsec_help(struct sk_buff **pskb,
	struct ip_conntrack *ct,
	enum ip_conntrack_info ctinfo)
{
	struct isakmphdr _isakmph,*isakmph;
	struct ip_conntrack_expect *exp;
	struct _ipsec_table *ipsec_entry;
	struct iphdr *iph=(*pskb)->nh.iph;
	unsigned int ret = NF_ACCEPT;

	/*
	 * Handle a new connection by recording its initiator cookie
	 * and src ip address. Here for a new connection, always the
	 * responder cookie is zero.
	 */
	isakmph = skb_header_pointer(*pskb,
				 (*pskb)->nh.iph->ihl*4+sizeof(struct udphdr),
				 sizeof(_isakmph), &_isakmph);

	if (isakmph == NULL)
		return NF_ACCEPT;

	if ( ntohl(isakmph->respcookie[0]) == 0 && ntohl(isakmph->respcookie[1]) == 0 ) {
		/*
		 * Check if this is the same LAN client creating another session.
		 * If the originating LAN client is the same, then the src IP will
		 * be the same but the initiator cookie will be different.
		 */
		if ( (ipsec_entry = search_ipsec_entry_by_addr ( isakmph,
							iph )) == NULL ) {
			ipsec_entry = alloc_ipsec_entry ();
			if ( ipsec_entry == NULL ) {
				/* All entries are currently in use */
				return NF_DROP;
			}
		}
		ipsec_entry->initcookie[0] = ntohl(isakmph->initcookie[0]);
		ipsec_entry->initcookie[1] = ntohl(isakmph->initcookie[1]);
		ipsec_entry->respcookie[0] = ntohl(isakmph->respcookie[0]);
		ipsec_entry->respcookie[1] = ntohl(isakmph->respcookie[1]);
		ipsec_entry->l_ip          = ntohl(iph->saddr);
		ipsec_entry->r_ip          = ntohl(iph->daddr);
		ipsec_entry->timeout       = 30;
		/*
	 	 * There will be at least one more packet for this tuple
	 	 * so set our expectation for it here.
	 	 */
		DUMP_TUPLE(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		DUMP_TUPLE(&ct->tuplehash[IP_CT_DIR_REPLY].tuple);
		exp = ip_conntrack_expect_alloc(ct);
		if (exp == NULL)
				return NF_ACCEPT;

		exp->tuple                       = ct->tuplehash[IP_CT_DIR_REPLY].tuple;
		exp->mask.src.ip                 = 0xFFFFFFFF;
		exp->mask.dst.ip                 = 0xFFFFFFFF;
		exp->mask.dst.u.udp.port         = ntohs(IPSEC_UDP_PORT);
		exp->mask.dst.protonum           = (u_int8_t)0xFFFF;
		exp->expectfn                    = NULL;

		//printk( KERN_DEBUG "%s:%s expect: 0x%x 0x%x"
		//	  " sip %u.%u.%u.%u:%u\n", __FILE__, __FUNCTION__,
		//	  ntohl(isakmph->initcookie[0]), ntohl(isakmph->initcookie[1]),
		//	  NIPQUAD(iph->saddr), udph->source);
		DEBUGP("expect: ");
		DUMP_TUPLE(&exp->tuple);
		DUMP_TUPLE(&exp->mask);
		if (ip_nat_ipsec_hook)
			ret = ip_nat_ipsec_hook(pskb, ctinfo, ipsec_entry->l_ip, exp);
		else if (ip_conntrack_expect_related(exp) != 0)
			ret = NF_DROP;
		ip_conntrack_expect_put(exp);
		return NF_ACCEPT;
	} else {
		if ( (ipsec_entry = search_ipsec_entry_by_cookie ( isakmph ) ) != NULL ) {
			if ( ctinfo >= IP_CT_IS_REPLY ) {
				//printk ( KERN_DEBUG "%s:%s IS REPLY sip 0x%x\n",
				//	 __FILE__, __FUNCTION__, ipsec_entry->l_ip);
//				ct->nat.help.ipsec_info.saddr = ipsec_entry->l_ip;
        		if (ip_nat_ipsec_hook)
        			ret = ip_nat_ipsec_hook(pskb, ctinfo, ipsec_entry->l_ip, NULL);
			}
				
			return NF_ACCEPT;
		}
	}
	/*
	 * I know we are not a packet filter. But to make connection tracking
	 * more accurate, lets drop the packet if we do not have any trace
	 * for this session.
	 */
	/*kenneth: for cdrouter 150,156*/
	return NF_ACCEPT;
	//return NF_DROP;
}

static struct ip_conntrack_helper ipsec[MAX_PORTS];
static char ipsec_names[MAX_PORTS][10];

static void fini(void)
{
	int i;

	for (i = 0 ; i < ports_c; i++) {
		//printk( KERN_DEBUG "%s:%s unregistering helper for port %d\n",
		//	  __FILE__, __FUNCTION__, ports[i]);
		ip_conntrack_helper_unregister(&ipsec[i]);
	} 
}

static int __init init(void)
{
	int i, ret;
	char *tmpname;

	if (!ports[0])
		ports[0] = IPSEC_UDP_PORT;

	for (i = 0 ; (i < MAX_PORTS) && ports[i] ; i++) {
		/* Create helper structure */
		ipsec[i].tuple.dst.protonum   = IPPROTO_UDP;
		ipsec[i].tuple.src.u.udp.port = htons(ports[i]);
		ipsec[i].mask.dst.protonum    = (u_int8_t)0xFFFF;
		ipsec[i].mask.src.u.udp.port  = 0xFFFF;
		ipsec[i].max_expected         = 1;
		ipsec[i].help                 = ipsec_help;
		ipsec[i].timeout              = 5 * 60;
		tmpname                     = &ipsec_names[i][0];
		if (ports[i] == IPSEC_UDP_PORT)
			sprintf(tmpname, "ipsec");
		else
			sprintf(tmpname, "ipsec-%d", i);
		ipsec[i].name = tmpname;

		//printk( KERN_DEBUG "%s:%sport #%d: %d\n", __FILE__,
		//	  __FUNCTION__, i, ports[i]);

		ret=ip_conntrack_helper_register(&ipsec[i]);
		if (ret) {
			//printk("ERROR registering helper for port %d\n", ports[i]);
			fini();
			return(ret);
		}
		ports_c++;
	}
	return(0);
}

module_init(init);
module_exit(fini);
