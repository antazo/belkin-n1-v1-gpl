/*
* H.323 connection tracking helper
* (c) 2005 Max Kellermann <max@duempel.org>
*
* Based on the 'brute force' H.323 connection tracking module by
* Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
*/


#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/tcp.h>

#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <linux/netfilter_ipv4/ip_conntrack_helper.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include <linux/netfilter_ipv4/ip_conntrack_h323.h>

MODULE_AUTHOR("Max Kellermann <max@duempel.org>");
MODULE_DESCRIPTION("H.323 connection tracking helper");
MODULE_LICENSE("GPL");

static int __init init(void)
{
    return ip_conntrack_helper_register(&ip_conntrack_helper_h225);
}

static void __exit fini(void)
{
    ip_conntrack_helper_unregister(&ip_conntrack_helper_h225);
}

module_init(init);
module_exit(fini);
