/* Shared library add-on to iptables for conntrack matching support.
 * GPL (C) 2001  Marc Boucher (marc@mbsi.ca).
 */

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_tuple.h>
#include <linux/netfilter_ipv4/ipt_conntrack.h>

int main( int, char** );

int main(int argc, char** argv)
{
	printf("hello world\n");
	return 0;
}
