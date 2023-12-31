
/*

    File: master.c - Small master DNS for local hosts
    
    Copyright (C) 1999 by Wolfgang Zekoll  <wzk@quietsche-entchen.de>

    This source is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2, or (at your option)
    any later version.

    This source is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef EXCLUDE_MASTER

#include <stdlib.h>
#include <stdio.h>
#define _GNU_SOURCE
#include <string.h>
#include <ctype.h>

#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "common.h"
#include "dns.h"
#include "lib.h"
//#include "value_parser_file.h"
#include "nvram.h"
//#include "socket_tools.h"

#ifndef EXCLUDE_MASTER
#include "master.h"
#define	MASTER_CONFIG		DNRD_ROOT "/master"
#endif
#include "string.h"

//#include "../../Allen_debug.h"

#define	PACKET_ASSEMBLYSIZE	600


#define	ARPADOMAIN		".in-addr.arpa"

#define	DNS_TYPE_A		1
#define	DNS_TYPE_NS		2
#define	DNS_TYPE_PTR		12
#define	DNS_TYPE_MX		15


#define	DEFAULT_TTL		(60 * 60)

//james ye add it
#if 0
#include <stdarg.h>
void mBUG(char *format,...){
 va_list args;
    FILE *fp;

    fp = fopen("/var/cgitest","a+");
    if(!fp){
        return;
    }
    va_start(args,format);
    vfprintf(fp,format,args);
    va_end(args);
    fprintf(fp,"\n");
    fflush(fp);
    fclose(fp);
//    system("/bin/chmod 777 /var/cgitest");

}
#else 
#define mBUG(format,...) 
#endif

typedef struct _string {
    unsigned int code;
    char	*string;
} string_t;



typedef struct _nameip {
    string_t	arpa;
    unsigned long ipnum;
} nameip_t;

/*
 * This is the primaty data structure for our little DNS.  It
 * contains an object name and a variable data type.  For usual
 * name - IP mappings the object name is the FQDN (hostname
 * with domain) and the data part contains the IP number in
 * string and binary format (both in `network order').
 */

#define	DNS_NAMEIP		1
#define	DNS_DNS			2
#define	DNS_AUTHORITY		3

typedef struct _dnsrec {
    int		type;
    string_t	object;

    union {
	nameip_t	nameip;
	string_t	dns;
    } u;
} dnsrec_t;

char master_param[200]		= "";

static int master_onoff		= 1;
static int master_initialised	= 0;
static char config[200]		= MASTER_CONFIG;

static int auto_authority	= 1;
static int master_reload	= 0;

	/*
	 * The DNS database is stored in an array of dbmax length.  The
	 * elements 0..dbc are already in use.
	 */

static int dbmax =		0;
static int dbc =		0;
static dnsrec_t	**dbv =		NULL;

	/*
	 * mkstring() simply fills a string_t structure.
	 */

static char *mkstring(string_t *string, const char *name, const int maxlen)
{
    string->string = (char *)strdup(name);
    strnlwr(string->string, maxlen);
    string->code   = get_stringcode(string->string);

    return (string->string);
}


/*
 * These are handler for the data part of the dnsrec_t
 * structure.  They return their DNS-type identifier on
 * success and 0 otherwise.
 */
static int create_nameip(nameip_t *nameip, const int maxnamelen, char *ip)
{
    struct in_addr ipnum;

    if (inet_aton(ip, &ipnum) == 0) {
	log_msg(LOG_NOTICE, "invalid ip number: %s", ip);
	return (0);
    }

    nameip->ipnum = ntohl(ipnum.s_addr);
    // Swap the bytes.  Don't assume 32-bit integers.
    ipnum.s_addr = ((nameip->ipnum & 0xff000000 >> 24) |
		    (nameip->ipnum & 0x00ff0000 >> 8) |
		    (nameip->ipnum & 0x0000ff00 << 8) |
		    (nameip->ipnum & 0x000000ff << 24));

    mkstring(&nameip->arpa, inet_ntoa(ipnum), maxnamelen);
    
    return (DNS_NAMEIP);
}


/*
 * Because the dnsrec_t type contains different pointers to
 * allocated memory we have to be careful when freeing it.
 */
static int free_dnsrec(dnsrec_t *rec)
{
    switch (rec->type) {
      case DNS_NAMEIP:
	  free(rec->u.nameip.arpa.string);
	  break;

      case DNS_DNS:
	  free(rec->u.dns.string);
	  break;

      case DNS_AUTHORITY:	/* No allocated memory. */
	  break;
	    
      case 0: /* This is allowed. Assume that the data part is not used. */
	  break;

      default:
	  log_msg(LOG_ALERT, "unknown DNS record type: %d "
		 "-- expect memory leaks", rec->type);
	  break;
    }

    free(rec->object.string);
    free(rec);

    return (0);
}

static dnsrec_t *alloc_dnsrec(char *name, const int maxlen)
{
    dnsrec_t *rec;

    rec = allocate(sizeof(dnsrec_t));
    mkstring(&rec->object, name, maxlen);

    return (rec);
}

static int reset_master(void)
{
    int	i;

    log_msg(LOG_NOTICE, "resetting master DNS");

#ifndef EMBED
    sem_wait(&dnrd_sem);
#endif

    for (i = 0; i < dbc; i++) { 
	free_dnsrec(dbv[i]);
    }

    if (dbv)
    {
	free(dbv);
	dbc = 0;
    }

    dbc = 0;    
    dbmax = 0;  

#ifndef EMBED
    sem_post(&dnrd_sem);
#endif

    return (0);
}


	/*
	 * Functions to manipulate the DNS database.
	 */

static dnsrec_t *add_record(dnsrec_t *rec)
{
    if (dbc >= dbmax) {
	dbv = reallocate(dbv, (dbmax += 10) * sizeof(dnsrec_t));
    }

    dbv[dbc++] = rec;
    return (rec);
}

static dnsrec_t *add_nameip(char *name, const int maxlen, char *ipnum)
{
    dnsrec_t *rec;

//printf("L<%d> add_nameip ipnum=%s\n",__LINE__,ipnum); 
    rec = alloc_dnsrec(name, maxlen);
    if ((rec->type = create_nameip(&rec->u.nameip, maxlen, ipnum)) != 0) {
	add_record(rec);
	return (rec);
    }

    free_dnsrec(rec);
    return (NULL);
}

static dnsrec_t *add_dns(char *domain, const int maxdomainlen, 
			 char *dns, const int maxdnslen)
{
    dnsrec_t *rec;
    
    rec = alloc_dnsrec(domain, maxdomainlen);
    mkstring(&rec->u.dns, dns, maxdnslen);
    rec->type = DNS_DNS;
    add_record(rec);

    return (rec);
}

static dnsrec_t *add_authority(char *domain, const int maxlen)
{
    dnsrec_t *rec;
    
    rec = alloc_dnsrec(domain, maxlen);
    rec->type = DNS_AUTHORITY;
    add_record(rec);
    log_debug(1, "added authority for %s", domain);

    return (rec);
}


	/*
	 * Here we read the DNS configuration file.
	 */

char *get_hostname(char **from, char *domain, char *name, int size)
{
    int	 len;
    char word[100];

    *name = 0;
    size -= 2;
    if (*get_word(from, word, sizeof(word)) == 0) {
	return (name);
    }

    if (*word == '+') {	/* Not a hostname but an option. */
	copy_string(name, word, size);
    }
    else if ((len = strnlen(word, sizeof(word))) > 0  &&  word[len-1] == '+') {
	word[len-1] = 0;
	snprintf (name, size, "%s%s%s", word, domain[0] ? "." : "", domain);
    }
    /* patch from maillinglist
       http://groups.yahoo.com/group/dnrd/message/231 

       This is to let dnrd resolve short hostnames in master file so a
       dialup line won't open a connection.
    */
    else if ((len = strnlen(word, sizeof(word))) > 0 && word[len-1] == '.') {
      word[len-1] = 0;
      size--;
      copy_string(name, word, size);
    }

    else if (strchr(word, '.') == NULL) {
	snprintf (name, size, "%s%s%s", word, domain[0] ? "." : "", domain);
    }
    else {
	copy_string(name, word, size);
    }

    return (name);
}

int read_hosts(char *filename, char *domain)
{
    int		count;
    char	*p, word[100], ipnum[100], line[300];
    FILE	*fp;
    
    if ((fp = fopen(filename, "r")) == NULL) {
	log_msg(LOG_NOTICE, "can't open file: %s", filename);
	return (1);
    }

    count = dbc;
    while (fgets(line, sizeof(line), fp) != NULL) {
	p = skip_ws((char *)noctrln(line, sizeof(line)));
	if (*p == 0  ||  *p == '#') continue;

	if (isdigit((int)(*p))) {
	    /*
	     * Usual hosts records start with an IP number.  This
	     * might be followed by one or more names.  Every
	     * name makes one DNS record.
	     */
	    get_word(&p, ipnum, sizeof(ipnum));
	    while (*get_hostname(&p, domain, word, sizeof(word)) != 0) {
		add_nameip(word, sizeof(word), ipnum);
	    }
	}
    }
	    
    fclose (fp);
    log_debug(1, "%s: %d records", filename, dbc - count);

    return (0);
}
	
int read_configuration(char *filename)
{
    int	count;
    char *p, word[100], ipnum[100], line[300];
    char domain[40];
    FILE *fp;
    
    if ((fp = fopen(filename, "r")) == NULL) {
	log_debug(1, "no master configuration: %s", filename);
	return (1);
    }

    count = dbc;
    while (fgets(line, sizeof(line), fp) != NULL) {
	p = skip_ws(noctrln(line,sizeof(line) ));
	if (*p == 0  ||  *p == '#') continue;

	if (isdigit((int)(*p))) {
	    /*
	     * Usual hosts records start with an IP number.  This
	     * might be followed by one or more names.  Every
	     * name makes one DNS record.
	     */
	    get_word(&p, ipnum, sizeof(ipnum));
	    while (*get_hostname(&p, domain, word, sizeof(word)) != 0)
		    add_nameip(word, sizeof(word), ipnum);
	}
	else if (strcmp(get_word(&p, word, sizeof(word)), "domain") == 0) {
	    get_word(&p, domain, sizeof(domain));
	    if (*domain == 0) continue;

	    while (*get_hostname(&p, domain, word, sizeof(word)) != 0) {
		if (strcmp(word, "+auth") == 0) {
		    add_authority(domain, sizeof(domain));
		}
		else {
		    add_dns(domain, sizeof(domain),  word, sizeof(word));
		}
	    }
	}
	else if (strcmp(word, "hosts") == 0) {
	    char	filename[200];

	    if (*get_word(&p, filename, sizeof(filename)) == 0) continue;
	    
	    if (strcmp(filename, "-") == 0) {
		strcpy(filename, "/etc/hosts");
	    }
	    
	    if (*get_word(&p, word, sizeof(word)) == 0) {
		copy_string(word, domain, sizeof(word));
	    }

	    read_hosts(filename, word);
	}
	else {
	    log_msg(LOG_NOTICE, "%s: unknown directive: %s", filename, word);
	}
    }
	    
    fclose (fp);
    log_debug(1, "%s: %d records", filename, dbc - count);

    return (0);
}


/*
 * DNS database lookups.
 */
static dnsrec_t *ptr_lookup(char *arpanum)
{
    unsigned int code;
    int	i;
    dnsrec_t *rec;

    code = get_stringcode(arpanum);
    for (i = 0; i < dbc; i++) {
	rec = dbv[i];
	if ((rec->type == DNS_NAMEIP) &&
	    (rec->u.nameip.arpa.code == code) &&
	    (strcmp(rec->u.nameip.arpa.string, arpanum) == 0)) {
	    return (rec);
	}
    }
	    
    return (NULL);
}

static dnsrec_t *name_lookup(char *name)
{
    unsigned int code;
    int	i;
    dnsrec_t *rec;

    code = get_stringcode(name);
    for (i = 0; i < dbc; i++) {
	rec = dbv[i];
	if ((rec->type == DNS_NAMEIP) &&
	    (rec->object.code == code) &&
	    (strcmp(rec->object.string, name) == 0)) {
	    return (rec);
	}
    }
		
    return (NULL);
}

static dnsrec_t *dns_lookup(char *name, int *last)
{
    int	i, k, len;
    dnsrec_t *rec;

    len = strlen(name);
    *last = (*last < 0) ? 0 : *last + 1;

    for (i = *last; i < dbc; i++) {
	rec = dbv[i];
	if (rec->type == DNS_DNS  &&
	    (k = len - strlen(rec->object.string)) >= 0) {
	    if (k > 0  &&  name[k-1] == '.'  &&
		strcmp(&name[k], rec->object.string) == 0) {
		*last = i;
		return (rec);
	    }
	    else if (k == 0  &&  strcmp(name, rec->object.string) == 0) {
		*last = i;
		return (rec);
	    }
	}
    }
	    
    return (NULL);
}

static dnsrec_t *authority_lookup(char *domain)
{
    unsigned int code;
    int	i;
    dnsrec_t *rec;

    code = get_stringcode(domain);
    for (i = dbc-1; i >= 0; i--) {
	rec = dbv[i];
	if ((rec->type == DNS_AUTHORITY)  &&
	    (rec->object.code == code)  &&
	    (strcmp(rec->object.string, domain) == 0)) {
	    return (rec);
	}
    }
	    
    return (NULL);
}


/*
 * Answer assembly.
 */
static int compile_name(dnsheader_t *x, char *name)
{
    unsigned int c;
    int	i, k, n, offset;

    offset = x->here - x->packet;
    k = 0;
    while ((c = name[k]) != 0) {
	n = 0;
	while ((c = name[k+n]) != 0  &&  c != '.') {
	    n++;
	}

	if (n == 0) break;

	*x->here++ = (unsigned char) (n & 0x3F);
	for (i = 0; i < n; i++) {
	    *x->here++ = name[k++];
	}

	if (name[k] == '.') {
	    k++;
	}
    }

    *x->here++ = 0;
    return (offset);
}

static int compile_namepointer(dnsheader_t *x, int offset)
{
    *x->here++ = 0xC0;
    *x->here++ = (unsigned int) (offset & 0x3F);

    return (0);
}

static unsigned char *compile_int(dnsheader_t *x, int number)
{
    unsigned short conv = htons((unsigned short) number);
    memcpy(x->here, &conv, 2);
    x->here += 2;

    return (x->here);
}

static unsigned char *compile_long(dnsheader_t *x, long number)
{
    unsigned long conv = htonl((unsigned long) number);
    memcpy(x->here, &conv, 4);

    x->here += 4;

    return (x->here);
}

static unsigned char *compile_objectname(dnsheader_t *x)
{
    *x->here++ = 0xC0;
    *x->here++ = 0x0C;

    return (x->here);
}

static int end_rdata(dnsheader_t *x)
{
    unsigned short int conv;

    if (x->rdata != NULL) {
	int	rsize;

	rsize = x->here - (x->rdata + 2);
	conv = htons((unsigned short int) rsize);
	memcpy(x->rdata, &conv, 2);
    }
    
    x->rdata = NULL;
    return (0);
}

static int start_rdata(dnsheader_t *x)
{
    x->rdata = x->here;
    compile_int(x, 0);

    return (0);
}

static int end_assembly(dnsheader_t *x)
{
    unsigned short int *pkt;

    end_rdata(x);
/*  SET_AA(x->u, 0); */

    pkt = (unsigned short int *) x->packet;
    pkt[1] = htons(x->u);
    pkt[2] = htons(x->qdcount);
    pkt[3] = htons(x->ancount);
    pkt[4] = htons(x->nscount);
    pkt[5] = htons(x->arcount);
    
    x->len = x->here - x->packet;
    return (x->len);
}

static dnsheader_t *begin_assembly(rr_t *query)
{
    static dnsheader_t *x = NULL;

    if (x == NULL) {
	x = allocate(sizeof(dnsheader_t));
	x->packet = allocate(PACKET_ASSEMBLYSIZE);
    }

    /*
     * Reset the packet ...
     */

    x->id = 0;
    x->u  = 0;
    SET_QR(x->u, 1);

    x->qdcount = 1;
    x->ancount = 0;
    x->nscount = 0;
    x->arcount = 0;
    x->rdata   = NULL;

    memset(x->packet, 0, PACKET_ASSEMBLYSIZE);
    x->here = &x->packet[PACKET_DATABEGIN];

    /*
     * ... and write the original query data.
     */

    compile_name(x, query->name);
    compile_int(x, query->type);
    compile_int(x, query->class);
    
    return (x);
}

static int compile_dnsrecords(dnsheader_t *x, char *object)
{
    int	pos, last;
    dnsrec_t *rec;

    last = -1;
    pos = 0;
    while ((rec = dns_lookup(object, &last)) != NULL) {
	if (pos == 0) {
	    pos = compile_name(x, rec->object.string);
	}
	else {
	    compile_namepointer(x, pos);
	}

	compile_int(x, DNS_TYPE_NS);
	compile_int(x, DNS_CLASS_INET);
	compile_long(x, DEFAULT_TTL);
	start_rdata(x);
	compile_name(x, rec->u.dns.string);
	end_rdata(x);

	x->nscount++;
    }

    if (x->nscount > 0) SET_AA(x->u, 1);

    return (0);
}


/*
 * master_init()
 *
 * Create the DNS database with the data from the configuration
 * file.
 */
static int _master_init(void)
{
		char *lan_url, *lan_ip;

    if (master_onoff == 0) return (0);

    log_debug(1, "initialising master DNS database");

    add_nameip("localhost", sizeof("localhost"), "127.0.0.1");
    add_dns("0.0.127.in-addr.arpa", sizeof("0.0.127.in-addr.arpa"),
	    "localhost", sizeof("localhost"));
/*    
	//james ye add this

	add_nameip("www.routerlogin.com",sizeof("www.routerlogin.com"),nvram_get("lan_ipaddr"));
	add_nameip("www.routerlogin.net",sizeof("www.routerlogin.net"),nvram_get("lan_ipaddr"));
	add_nameip("routerlogin.com",sizeof("routerlogin.com"),nvram_get("lan_ipaddr"));
	add_nameip("routerlogin.net",sizeof("routerlogin.net"),nvram_get("lan_ipaddr"));
	//james ye add this
*/
    if ((strcmp(master_param, "hosts") == 0) ||
	(read_configuration(config) != 0)) {
	char	domain[80];
	FILE	*fp;

	/*
	 * Hmm, no dnrd.conf - let's try to initialize with the
	 * /etc/hosts only.
	 */

	*domain = 0;
	if ((fp = fopen("/etc/resolv.conf", "r")) != NULL) {
	    char	*p, word[80], line[300];

	    /*
	     * We try to get the default domain name from here.
	     */

	    while (fgets(line, sizeof(line), fp) != NULL) {
		p = skip_ws(noctrln(line,sizeof(line)));
		if (*p == 0  ||  *p == '#') continue;

		get_word(&p, word, sizeof(word));
		if (strcmp(word, "domain") == 0) {
		    get_word(&p, domain, sizeof(domain));
		    break;
		}
	    }

	    fclose (fp);

	    log_debug(1, "initialising from /etc/hosts, domain= %s",
		      *domain == 0? "<none>": domain);
	    read_hosts("/etc/hosts", domain);
	}
    }

    if (auto_authority != 0) {
	int	i;
	char	*domain, arpaname[200];
	
	
	for (i = 0; i < dbc; i++) {
	    if (dbv[i]->type == DNS_NAMEIP) {
		snprintf (arpaname, sizeof(arpaname) - 2, "%s%s",
			  dbv[i]->u.nameip.arpa.string, ARPADOMAIN);
		if ((domain = strchr(arpaname, '.')) == NULL) continue;
		domain++;
		if (authority_lookup(domain) == 0) {
		    add_authority(domain,sizeof(arpaname)-(arpaname-domain));
		}
	    }
	}
    }

    log_debug(1, "%d records in master DNS database", dbc);
    master_initialised = 1;

//mBUG("L<%d> _master_init ",__LINE__);
    return (0);
}

static char *xbox_urls[]={
	"AS.XBOXLIVE.COM",
	"TGS.XBOXLIVE.COM",
	"MACS.XBOXLIVE.COM",
	NULL
};

//James ye added
int is_xbox_url(char *url)
{
	int i,j;
	for(i=0;xbox_urls[i];i++)
	{
		int j=0;
		while(xbox_urls[i][j])
		{
			if(xbox_urls[i][j]!=toupper(url[j]))
				break;
			j++;
		}
		if(j==strlen(xbox_urls[i]))return 1;
	}
	return 0;
}

/*
 * master_lookup()
 *
 * Get the query from the packet(msg, len) and look if it can
 * be answered by the local master.  If so assemble the response
 * and copy if to msg, return the answer length in the
 * function's return code.  0 means here that the master hasn't
 * any data.
 *
 * The function assumes that the buffer area answer points to
 * is large enough.
 *
 * The assembly functions do no size checking, so basically an
 * overflow might occur.  Otherwise the answer packets are
 * relatively small.  They should always fit into 512 bytes.
 */
typedef struct{
    unsigned char mac[6];
    short flag;
    struct in_addr ip;
    struct in_addr mask;
    struct in_addr gw;    
}IFACE_STATUS;
#define ETH_WAN         "eth1"
#define PPP0_WAN	"ppp0"
#define DOD_IP "10.64.64.64"
#define WAN_GetStatusOK             0
#define WAN_GetStatusErr            -1

/********************************************************************************
 *  GetIfaceStatus()        Get interface status and put the data to *pStatus   *
 *                                                                              *
 *  0                   ==>     Successed                                       *
 *  other               ==>     Fail                                            *
 *                                                                              *
 ********************************************************************************/
int GetIfaceStatus(char *if_name, IFACE_STATUS *pStatus){
    struct ifreq ifr;
    int sockd;
    struct sockaddr_in *mysockaddr;

    memset(pStatus,0,sizeof(IFACE_STATUS));
    sockd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockd == -1) { /* Open socket error. */
		return WAN_GetStatusErr;
	}
	/* Init iface name. */
	strcpy(ifr.ifr_name, if_name);

    /* Try to get HW address. */
    if(ioctl(sockd, SIOCGIFHWADDR, &ifr) < 0) {
    		close(sockd);
		return WAN_GetStatusErr;
	}
	memcpy(pStatus->mac,ifr.ifr_hwaddr.sa_data,6);

    /* Try to get IP address. */
    if(ioctl(sockd, SIOCGIFADDR, &ifr) < 0) { ///This is not fitable for pppoe,because 10.64.64.64. so add following, gavin,2004-11-13
    		close(sockd);
		return WAN_GetStatusErr;
	}
	mysockaddr = (struct sockaddr_in *)&(ifr.ifr_addr);
	pStatus->ip = mysockaddr->sin_addr;
       ///gavin added the following ^M 
       if(!strcmp(if_name,PPP0_WAN) && !strcmp(inet_ntoa(pStatus->ip),DOD_IP)) 
         {
                close(sockd);
                return WAN_GetStatusErr;
        }
       /* Try to get netmask. */
    if(ioctl(sockd, SIOCGIFNETMASK, &ifr) < 0) {
    		close(sockd);
		return WAN_GetStatusErr;
	}
	mysockaddr = (struct sockaddr_in *)&(ifr.ifr_netmask);
	pStatus->mask = mysockaddr->sin_addr;

#if 0
    /* Try to get gw. */
    if(ioctl(sockd, SIOCGIFDSTADDR, &ifr) < 0) {
    		close(sockd);
		return WAN_GetStatusErr;
	}
	mysockaddr = (struct sockaddr_in *)&(ifr.ifr_addr);
	pStatus->gw = mysockaddr->sin_addr;
#elif0
{
    FILE *fp;
    char sys_cmd[128];
    #define ROUTE_RESULT    "/var/routeResult"

    sprintf(sys_cmd,"/sbin/route -n | grep \"^0.0.0.0\" > %s 2>&1",ROUTE_RESULT);
    system(sys_cmd);

    fp = fopen(ROUTE_RESULT,"r");
    if(fp){

        char line[128];
        int i;
        while(fgets(line,sizeof(line),fp) != NULL){
            for(i=16;line[i] != ' ';i++);
            line[i] = '\0';
            inet_aton(&line[16],&pStatus->gw);
        }
        fclose(fp);
    }
    remove(ROUTE_RESULT);
}
#else
{
	FILE *fp;
	fp=fopen("/proc/net/route", "r");
	if(fp){
		char buf[128];
		while(fgets(buf, sizeof(buf), fp)){
			if(!strstr(buf, if_name))
				continue;
			if(sscanf(buf, "%*s\t00000000\t%lx",(long int *)&pStatus->gw.s_addr))
				break;
		}
		fclose(fp);
	}
}
#endif

    /* Try to get flag. */
    if(ioctl(sockd, SIOCGIFFLAGS, &ifr) < 0) {
    		close(sockd);
		return WAN_GetStatusErr;
	}
	pStatus->flag = ifr.ifr_flags;
///debug1("flag=%x", pStatus->flag);	
    close(sockd);

    return WAN_GetStatusOK;
}




/****************************************************************
 *  Function    :  GetConnectionStatus()                        *
 *                                                              *
 *  Input       :  Connection Method get form system conf       *
 *                                                              *
 *  Output      :  WAN_GetStatusOK                              *
 *                 WAN_GetStatusErr                             *
 *  Note        :  Will fill in status in pStatus.              *
 ****************************************************************/
int GetConnectionStatus(IFACE_STATUS *pStatus){
    char if_name[6];
    char mac[6];

    /* Try to get connection Type. */
    char *pt=nvram_get("wan_mode");

    memset(pStatus,0,sizeof(IFACE_STATUS));

	/* For I can not get ppp iface's MAC ,get ethx MAC first.*/
	GetIfaceStatus(ETH_WAN,pStatus);
	memcpy(mac,pStatus->mac,6);
	
	if(!strcmp(pt,"dhcpc") || !strcmp(pt, "ip"))
		strcpy(if_name, ETH_WAN);
	else if(strcmp(pt,"pppoe")==0
	        || strcmp(pt,"pptp")==0
	        )
		strcpy(if_name,"ppp0");
	else
		return WAN_GetStatusErr;

    GetIfaceStatus(if_name,pStatus);
    /* Then copy MAC back. */
    memcpy(pStatus->mac,mac,6);

    return WAN_GetStatusOK;
}

/* allen get it from ip1006mo */
int master_lookup(unsigned char *msg, int len)
{
    char	*domain;
    rr_t	query;
    dnsrec_t *rec;

    if (master_onoff == 0) return (0);


    if (master_initialised == 0) {
	_master_init();
    }

    if ((parse_query(&query, msg, len) == NULL) ||
	(query.class != DNS_CLASS_INET  ||  GET_OPCODE(query.flags) != 0)) {
	return (0);
    }
    
    if (query.type == DNS_TYPE_PTR) {
	int	k, len;
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);    
	len = strlen(query.name);
	k = len - strlen(ARPADOMAIN);
	if (k < 0  ||  strcmp(&query.name[k], ARPADOMAIN) != 0) {
	    return (0);
	}

	query.name[k] = 0;
	if ((rec = ptr_lookup(query.name)) != NULL) {
	    dnsheader_t *x;
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);  	    
	    query.name[k] = '.';
	    log_debug(2, "master: found PTR %s\n", query.name);

	    x = begin_assembly(&query);
	    compile_objectname(x);
	    compile_int(x, DNS_TYPE_PTR);
	    compile_int(x, DNS_CLASS_INET);
	    compile_long(x, DEFAULT_TTL);
	    start_rdata(x);
	    compile_name(x, rec->object.string);
	    end_rdata(x);

	    compile_dnsrecords(x, query.name);

	    x->ancount = 1;
	    end_assembly(x);

	    dump_dnspacket("assembled", x->packet, x->len);

	    memcpy(msg + 2, x->packet + 2, x->len - 2);
	    return (x->len);
	}

	/* Repair query for later authority lookup. */
	query.name[k] = '.';
    }
    else if (query.type == DNS_TYPE_A) {
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);

       /* dns request routersetup will goto router self */
       if(strstr(query.name, "routersetup") && !name_lookup(query.name))
           add_nameip(query.name, sizeof(query.name), nvram_get("lan_ipaddr"));
       
	if ((rec = name_lookup(query.name)) != NULL) {
	    dnsheader_t *x;
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);
	    x = begin_assembly(&query);
	    compile_objectname(x);
	    compile_int(x, DNS_TYPE_A);
	    compile_int(x, DNS_CLASS_INET);
	    compile_long(x, DEFAULT_TTL);
	    start_rdata(x);
	    compile_long(x, rec->u.nameip.ipnum);
	    end_rdata(x);
	    
	    compile_dnsrecords(x, query.name);

	    x->ancount = 1;
	    end_assembly(x);

	    dump_dnspacket("assembled", x->packet, x->len);

	    memcpy(msg + 2, x->packet + 2, x->len - 2);
	    return (x->len);
	}
    }
    else if (query.type == DNS_TYPE_NS) {
	int	last;
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);
	last = -1;
	if ((rec = dns_lookup(query.name, &last)) != NULL) {
	    dnsheader_t *x;
	    
	    x = begin_assembly(&query);
	    while (rec != NULL) {
		compile_objectname(x);
		compile_int(x, DNS_TYPE_NS);
		compile_int(x, DNS_CLASS_INET);
		compile_long(x, DEFAULT_TTL);

		start_rdata(x);
		compile_name(x, rec->u.dns.string);
		end_rdata(x);
		
		x->ancount++;
		rec = dns_lookup(query.name, &last);
	    }

	    SET_AA(x->u, 1);
	    end_assembly(x);

	    dump_dnspacket("assembled", x->packet, x->len);

	    memcpy(msg + 2, x->packet + 2, x->len - 2);
	    return (x->len);
	}
    }
    else {
	/*
	 * Return here if this type of request isn't handled
	 * by the master.
	 */
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);
	return (0);
    }

    /*
     * At this point we have a request that would have been
     * answered by us if we only had the data for it.  Look
     * if we are authoritative for it and assemble a negative
     * response if yes.
     */
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);
    if ((domain = strchr(query.name, '.')) == NULL) {
	return (0);
    }
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);
    domain++;
    if (authority_lookup(domain) != NULL) {
	dnsheader_t *x;

	log_debug(2, "master: found AUTHORITY for %s\n", domain);
//allen_DEBUG("file=%s, In master_lookup, line=%d",__FILE__,__LINE__);
	x = begin_assembly(&query);
	x->ancount = 0;
	SET_AA(x->u, 1);
	end_assembly(x);

	dump_dnspacket("assembled", x->packet, x->len);

	memcpy(msg + 2, x->packet + 2, x->len - 2);
	return (x->len);
    }

    return (0);
}


/*
 * master_dontknow()
 *
 * Take the given packet and assemble a `we dont know' answer
 * for the client.  This answer isn't authoritative.  It's
 * tells the client that we are actually unable to process his
 * request.
 */ 
int master_dontknow(unsigned char *msg, int len, unsigned char *answer)
{
    rr_t	query;
    dnsheader_t	*x;

    if (master_onoff == 0) return (0);


    if (master_initialised == 0) {
	_master_init();
    }

    if (parse_query(&query, msg, len) == NULL) {
	return (0);
    }
    else if (query.class != DNS_CLASS_INET  ||  GET_OPCODE(query.flags) != 0) {
	return (0);
    }

    x = begin_assembly(&query);
    x->ancount = 0;
    SET_AA(x->u, 0);
    SET_RCODE(x->u, 1);
    end_assembly(x);

    dump_dnspacket("assembled", x->packet, x->len);

    memcpy(answer, x->packet, x->len);
    return (x->len);
}


/*
 * master_sighup(), master_reinit()
 *
 * master_reinit() erases the whole master DNS database and makes a
 * complete reread of the database definition.  master_sighup()
 * is the correponding signal handler that sets the reload flag.
 * The actual reload is done from run() in relay.c after return
 * from the select() function.
 */
static void master_sighup(int sig)
{
    if (master_onoff != 0) {
        master_reload = 1;
    }

    signal(sig, master_sighup);
    return;
}

int master_reinit(void)
{
    if (master_onoff == 0) return (0);

    if (master_reload != 0) {
        reset_master();
        _master_init();
    }

    master_reload = 0;
    return (0);
}


/*
 * master_init()
 *
 * Should be called once from main() to initialise the master
 * database.
 */ 
int master_init(void)
{
    if (strcmp(master_param, "off") == 0) master_onoff = 0;

    if (master_onoff == 0) {
	log_msg(LOG_NOTICE, "local DNS master turned off");
    }
    else {
	_master_init();
	/* This does not work at all. I turn it off...
	signal(SIGHUP, master_sighup);
	*/
    }

    /*
     * Since our root dir will have changed to /etc/dnrd, we need to change
     * the path of our config file so that future re-reads will continue to
     * work.
     */
    strcpy(config, "master");

    return (0);
}

#endif
