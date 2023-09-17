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
//  Filename:       ip_nat_ipsec.c
//  Author:         Pavan Kumar
//  Creation Date:  05/27/04
//
//  Description:
//      Implements the IPSec ALG connectiontracking.
//
*****************************************************************************/
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ip_nat.h>
#include <linux/netfilter_ipv4/ip_nat_helper.h>
#include <linux/netfilter_ipv4/ip_nat_rule.h>
#include <linux/netfilter_ipv4/ip_nat_ipsec.h>
#include <linux/netfilter_ipv4/ip_conntrack_ipsec.h>
#include <linux/netfilter_ipv4/ip_conntrack_helper.h>
#include <linux/moduleparam.h>

MODULE_AUTHOR("Pavan Kumar <pavank@broadcom.com>");
MODULE_DESCRIPTION("Netfilter NAT helper for ipsec");
MODULE_LICENSE("Proprietary");

#define MAX_PORTS	64
#define UDP_HLEN	8

//static int ports[MAX_PORTS];
//static int ports_c = 0;
#ifdef MODULE_PARM
MODULE_PARM(ports,"1-" __MODULE_STRING(MAX_PORTS) "i");
MODULE_PARM_DESC(ports, "port numbers of IPSEC");
#endif

#if 0
#define DEBUGP(format, args...)	printk(KERN_DEBUG "%s:%s: " format, __FILE__, __FUNCTION__, ## args)
#else
#define DEBUGP(format, args...)
#endif
//static unsigned int 
//ipsec_nat_help(struct ip_conntrack *ct,
//	      struct ip_conntrack_expect *exp,
//	      struct ip_nat_info *info,
//	      enum ip_conntrack_info ctinfo,
//	      unsigned int hooknum,
//	      struct sk_buff **pskb)
	      
	      
static unsigned int 
ipsec_nat_help(struct sk_buff **pskb,
          enum ip_conntrack_info ctinfo,
          u_int32_t l_ip,
	      struct ip_conntrack_expect *exp
	      )
{
	int dir = CTINFO2DIR(ctinfo);
	struct iphdr              *iph = (*pskb)->nh.iph;
	struct udphdr             *udph = (void *)iph + iph->ihl * 4;
//	struct ip_nat_ipsec_info  *nat = &ct->nat.help.ipsec_info;

	/* 
         * Only mangle things once: original direction in POST_ROUTING
	 * and reply direction on PRE_ROUTING.
         */
//	if (!((hooknum == NF_IP_POST_ROUTING && dir == IP_CT_DIR_ORIGINAL)
//	      || (hooknum == NF_IP_PRE_ROUTING && dir == IP_CT_DIR_REPLY))) 
//		return NF_ACCEPT;

        /*
         *      for original direction (outgoing), masquerade the UDP
         *      port and IP address.
         */
//	LOCK_BH(&ip_ipsec_lock);
        if(ctinfo == IP_CT_NEW)
        {
		//printk ( KERN_DEBUG "%s:%s Bef. Masq sip %u.%u.%u.%u:%u"
		//	   " skb_chk 0x%x\n", __FILE__, __FUNCTION__,
		//	   NIPQUAD(iph->saddr), udph->check, (*pskb)->csum );
    	exp->saved_proto.tcp.port = exp->tuple.dst.u.tcp.port;
    	exp->dir = !dir;
    	exp->expectfn = ip_nat_follow_master;
//    	printk(KERN_WARNING "src %u, dst %u, id %u\n", udph->source, udph->dest, iph->id);
		udph->dest = htons(IPSEC_UDP_PORT);
		udph->check = 0;
		//printk ( KERN_DEBUG "DEBUG: Masq. Orig Dir sip %u.%u.%u.%u:%u"
		//	   " check 0x%x dip %u.%u.%u.%u:%u\n",
		//	   NIPQUAD(iph->saddr), ntohs(udph->dest), udph->check,
		//	   NIPQUAD(iph->daddr), udph->dest );
	}

        /*
         *      for reply direction (incoming), demasquerade the peer initiator
	 *	cookie lookup original initiator cookie in our internal table
	 *	and assign the proper IP address.
         */
        if(ctinfo == IP_CT_IS_REPLY)
        {
		//printk ( KERN_DEBUG "%s:%s Bef Masq Reply Dir"
		//	   " dip %u.%u.%u.%u:%u check 0x%x\n",
		//	   __FILE__, __FUNCTION__, NIPQUAD(iph->daddr),
		//	   udph->dest, udph->check);
//		    printk(KERN_WARNING "reply, dst %u, id %u\n", udph->dest, iph->id);
//    		udph->dest = htons(IPSEC_UDP_PORT);
//    		iph->daddr = htonl(l_ip);
//    		udph->check = 0;
		//printk ( KERN_DEBUG "DEBUG: Masq. Reply Dir udp dest port %d"
		//	   " ip src %u.%u.%u.%u\n", ntohs(udph->dest),
		//	   NIPQUAD(iph->saddr) );
	}
//	UNLOCK_BH(&ip_ipsec_lock);

	return NF_ACCEPT;
}

//static unsigned int 
//ipsec_nat_expected(struct sk_buff **pskb,
//		  unsigned int hooknum,
//		  struct ip_conntrack *ct, 
//		  struct ip_nat_info *info) 
//{
//	const struct ip_conntrack *master = ct->master->expectant;
//	const struct ip_conntrack_tuple *orig = 
//			&master->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
//	struct ip_nat_multi_range mr;
//	//struct iphdr *iph = (*pskb)->nh.iph;
//	//struct udphdr *udph = (void *)iph + iph->ihl * 4;
//
//	IP_NF_ASSERT(info);
//	IP_NF_ASSERT(master);
//	IP_NF_ASSERT(!(info->initialized & (1 << HOOK2MANIP(hooknum))));
//
//	mr.rangesize = 1;
//	mr.range[0].flags = IP_NAT_RANGE_MAP_IPS;
//
//	if (HOOK2MANIP(hooknum) == IP_NAT_MANIP_SRC) {
//		mr.range[0].min_ip = mr.range[0].max_ip = orig->dst.ip; 
//		//printk( KERN_DEBUG "%s:%sorig: %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u "
//		//	"newsrc: %u.%u.%u.%u\n", __FILE__, __FUNCTION__,
//                //      NIPQUAD((*pskb)->nh.iph->saddr), ntohs(udph->source),
//		//	NIPQUAD((*pskb)->nh.iph->daddr), ntohs(udph->dest),
//		//	NIPQUAD(orig->dst.ip));
//	} else {
//		mr.range[0].min_ip = mr.range[0].max_ip = orig->src.ip;
//		mr.range[0].min.udp.port = mr.range[0].max.udp.port = 
//							orig->src.u.udp.port;
//		mr.range[0].flags |= IP_NAT_RANGE_PROTO_SPECIFIED;
//
//		//printk( KERN_DEBUG "%s:%sorig: %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u "
//		//	"newdst: %u.%u.%u.%u:%u\n", __FILE__, __FUNCTION__,
//                //      NIPQUAD((*pskb)->nh.iph->saddr), ntohs(udph->source),
//                //      NIPQUAD((*pskb)->nh.iph->daddr), ntohs(udph->dest),
//                //      NIPQUAD(orig->src.ip), ntohs(orig->src.u.udp.port));
//	}
//
//	return ip_nat_setup_info(ct,&mr,hooknum);
//}

//static struct ip_nat_helper ipsec[MAX_PORTS];
//static char ipsec_names[MAX_PORTS][10];

static void fini(void)
{
//	int i;

    ip_nat_ipsec_hook = NULL;
//	for (i = 0 ; i < ports_c; i++) {
//		//printk( KERN_DEBUG "%s:%sunregistering helper for port %d\n",
//		//	  __FILE__, __FUNCTION__, ports[i]);
//		ip_nat_helper_unregister(&ipsec[i]);
//	}
}

static int __init init(void)
{
//	int i, ret = 0;
//	char *tmpname;
//
//	if (!ports[0])
//		ports[0] = IPSEC_UDP_PORT;
//
//	for (i = 0 ; (i < MAX_PORTS) && ports[i] ; i++) {
//		ipsec[i].tuple.dst.protonum = IPPROTO_UDP;
//		ipsec[i].tuple.src.u.udp.port = htons(ports[i]);
//		ipsec[i].mask.dst.protonum = 0xFFFF;
//		ipsec[i].mask.src.u.udp.port = 0xFFFF;
//		ipsec[i].help = ipsec_nat_help;
//#ifdef CONFIG_MIPS_BRCM
//		//ipsec[i].flags = 0;
//		//ipsec[i].me = THIS_MODULE;
//#else
//		ipsec[i].flags = 0;
//		ipsec[i].me = THIS_MODULE;
//#endif
//		ipsec[i].expect = ipsec_nat_expected;
//
//		tmpname = &ipsec_names[i][0];
//		if (ports[i] == IPSEC_UDP_PORT)
//			sprintf(tmpname, "ipsec");
//		else
//			sprintf(tmpname, "ipsec-%d", i);
//		ipsec[i].name = tmpname;
//		
//		//printk( KERN_DEBUG "%s:%s registering for port %d: name %s\n",
//		//	__FILE__, __FUNCTION__, ports[i], ipsec[i].name);
//		ret = ip_nat_helper_register(&ipsec[i]);
//
//		if (ret) {
//			//printk(KERN_DEBUG "ip_nat_ipsec: unable to register"
//			//	 " for port %d\n", ports[i]);
//			fini();
//			return ret;
//		}
//		ports_c++;
//	}
	BUG_ON(ip_nat_ipsec_hook);
	ip_nat_ipsec_hook = ipsec_nat_help;
	return 0;
}

module_init(init);
module_exit(fini);
