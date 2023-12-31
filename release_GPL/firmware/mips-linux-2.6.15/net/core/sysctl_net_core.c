/* -*- linux-c -*-
 * sysctl_net_core.c: sysctl interface to net core subsystem.
 *
 * Begun April 1, 1996, Mike Shaver.
 * Added /proc/sys/net/core directory entry (empty =) ). [MS]
 */

#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <net/sock.h>

#ifdef CONFIG_SYSCTL

extern int netdev_max_backlog;
extern int weight_p;

extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

extern int sysctl_core_destroy_delay;

#ifdef CONFIG_NET_DIVERT
extern char sysctl_divert_version[];
#endif /* CONFIG_NET_DIVERT */

#ifdef CONFIG_SC_FEATURE_ENABLE
extern int  br_if_limitation; /* limit for wireless guest access */
#endif

#if defined(_SC_BUILD_) && !defined(CONFIG_IPV6)
extern int ipv6_passthru;
#endif

ctl_table core_table[] = {
#ifdef CONFIG_NET
	{
		.ctl_name	= NET_CORE_WMEM_MAX,
		.procname	= "wmem_max",
		.data		= &sysctl_wmem_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_CORE_RMEM_MAX,
		.procname	= "rmem_max",
		.data		= &sysctl_rmem_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_CORE_WMEM_DEFAULT,
		.procname	= "wmem_default",
		.data		= &sysctl_wmem_default,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_CORE_RMEM_DEFAULT,
		.procname	= "rmem_default",
		.data		= &sysctl_rmem_default,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_CORE_DEV_WEIGHT,
		.procname	= "dev_weight",
		.data		= &weight_p,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_CORE_MAX_BACKLOG,
		.procname	= "netdev_max_backlog",
		.data		= &netdev_max_backlog,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_CORE_MSG_COST,
		.procname	= "message_cost",
		.data		= &net_msg_cost,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec_jiffies,
		.strategy	= &sysctl_jiffies,
	},
	{
		.ctl_name	= NET_CORE_MSG_BURST,
		.procname	= "message_burst",
		.data		= &net_msg_burst,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= NET_CORE_OPTMEM_MAX,
		.procname	= "optmem_max",
		.data		= &sysctl_optmem_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
#ifdef CONFIG_NET_DIVERT
	{
		.ctl_name	= NET_CORE_DIVERT_VERSION,
		.procname	= "divert_version",
		.data		= (void *)sysctl_divert_version,
		.maxlen		= 32,
		.mode		= 0444,
		.proc_handler	= &proc_dostring
	},
#endif /* CONFIG_NET_DIVERT */
#endif /* CONFIG_NET */
	{
		.ctl_name	= NET_CORE_SOMAXCONN,
		.procname	= "somaxconn",
		.data		= &sysctl_somaxconn,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.ctl_name	= NET_CORE_BUDGET,
		.procname	= "netdev_budget",
		.data		= &netdev_budget,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
#ifdef CONFIG_SC_FEATURE_ENABLE
	{
		.ctl_name	= NET_CORE_BR_IF_LIMITATION,
		.procname	= "br_if_limitation",
		.data		= &br_if_limitation,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
#endif
#if defined(_SC_BUILD_) && !defined(CONFIG_IPV6)
	{
	    .ctl_name	= NET_CORE_IPV6_PASSTHRU,
	    .procname	= "ipv6_passthru",
        .data		= &ipv6_passthru,
        .maxlen		= sizeof(int),
        .mode		= 0644,
        .proc_handler	= &proc_dointvec
    },
#endif
	{ .ctl_name = 0 }
};

#endif
