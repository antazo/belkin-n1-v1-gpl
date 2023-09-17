#ifndef _IP_CONNTRACK_H323_H
#define _IP_CONNTRACK_H323_H
/* H.323 connection tracking. */

#ifdef __KERNEL__

/* Default H.225 port */
#define H225_PORT	1720

struct ip_conntrack_expect;
struct ip_conntrack;
struct ip_conntrack_helper;

extern int (*ip_nat_h245_hook)(struct sk_buff **pskb,
			       enum ip_conntrack_info ctinfo,
			       unsigned int offset,
			       struct ip_conntrack_expect *exp);

extern int (*ip_nat_h225_hook)(struct sk_buff **pskb,
			       enum ip_conntrack_info ctinfo,
			       unsigned int offset,
			       struct ip_conntrack_expect *exp);

extern void (*ip_nat_h225_signal_hook)(struct sk_buff **pskb,
				       struct ip_conntrack *ct,
				       enum ip_conntrack_info ctinfo,
				       unsigned int offset,
				       int dir,
				       int orig_dir);

extern struct ip_conntrack_helper ip_conntrack_helper_h225;

void ip_conntrack_h245_expect(struct ip_conntrack *new,
			      struct ip_conntrack_expect *this);

#endif /* __KERNEL__ */

#endif /* _IP_CONNTRACK_H323_H */
