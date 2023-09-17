#! /bin/sh
# $Id: iptables_flush.sh,v 1.1 2007-08-16 09:42:39 oliver_hao Exp $
IPTABLES=iptables

#flush all rules owned by miniupnpd
$IPTABLES -t nat -F MINIUPNPD
$IPTABLES -t filter -F MINIUPNPD

