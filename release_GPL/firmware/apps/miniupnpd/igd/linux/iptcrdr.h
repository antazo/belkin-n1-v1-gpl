/* $Id: iptcrdr.h,v 1.1 2007-08-16 09:42:39 oliver_hao Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef __IPTCRDR_H__
#define __IPTCRDR_H__

int
add_redirect_rule2(unsigned short eport, const char * iaddr, 
                    unsigned short iport, int proto, const char * desc);

int
add_filter_rule2(const char * iaddr, unsigned short eport, 
                    int proto, const char * desc);

int
get_redirect_rule(unsigned short *pmenable, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * desc, int desclen);

int
get_redirect_rule_by_index(unsigned short *pmenable, int index,
                           unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto, char * desc, int desclen);

int
delete_redirect_and_filter_rules(unsigned short pmenable, unsigned short eport, int proto);

/* for debug */
int
list_redirect_rule(void);

int
addnatrule(int proto, unsigned short eport,
               const char * iaddr, unsigned short iport);

int
add_filter_rule(int proto, const char * iaddr, unsigned short iport);

#endif

