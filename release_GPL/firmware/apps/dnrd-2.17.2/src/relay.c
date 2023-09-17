/*
 * relay.c - the guts of the program.
 *
 * Copyright (C) 1998 Brad M. Garcia <garsh@home.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#define _BB_
#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include "query.h"
#include "relay.h"
#include "cache.h"
#include "common.h"
#include "tcp.h"
#include "udp.h"
#include "dns.h"
#include "domnode.h"

#include "nvram.h"

#ifndef EXCLUDE_MASTER
#include "master.h"
#endif
//#include "../../Allen_debug.h"

/* extern list */
char wan_mode_global[16];
char s1_dial_mode[16], s2_dial_mode[16];
char s1_enabled[16], s2_enabled[16];
char s1_accountNo[16];
/* static list */
static int replace_flag=0;
static now_is_dialing_session1 = 0; // 0 is not, else 1.
static now_is_dialing_session2 = 0;
		
/* prepare the dns packet for a not found reply */
/* not used anymore
char *set_notfound(char *msg, const int len) {
  if (len < 4) return NULL;
  msg[2] |= 0x84;
  msg[3] = 0x83;
  return msg;
}
*/

/* prepare the dns packet for a Server Failure reply */
char *set_srvfail(char *msg, const int len) {
  if (len < 4) return NULL;
  /* FIXME: host to network should be called here */
  /* Set flags QR and AA */
  msg[2] |= 0x84;
  /* Set flags RA and RCODE=3 */
  msg[3] = 0x82;
  return msg;
}

void dnrd_nvram_get(char *name, char *buf, int buf_len)
{
	char *sp;

	if((name==NULL)||(buf==NULL))
		return;
	strcpy(buf, "");
	sp=nvram_get(name);
	if(sp!=NULL)
	{
		if(strlen(sp)>buf_len)
		{
			free(sp);
			return;
		}
		strcpy(buf,sp);
		free(sp);
	}
}


int traffic_rule_hit(char *query_url)
{
	FILE *fp;
	char url[128];
	char *pt;

	fp = fopen("/var/url_trf_ls","r");
	if (!fp)
	{
		return 0;
	}
	while (fgets(url,128,fp))
	{
		url[127] = '\0';
		pt = strchr(url,'\n');
		if (pt) *pt = '\0';

		pt = strchr(url,'/');

		if (pt) *pt = '\0';

		if (strstr(query_url, url))
		{
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}

int url_on_session2(char *domain, int *len)
{
	char cname_buf[256];
	int ret;
	
	sprintf_cname(&domain[12], *len-12, cname_buf, 256);
	ret = traffic_rule_hit(cname_buf);
	log_debug(1, "<%d>url_on_session2, ret<%d>", __LINE__, ret);
	if (ret)
		return 0;
	return -1;
}


int replace_srvnode(domnode_t *dptr, int session_index)
{
	srvnode_t *srv_p=dptr->srvlist, *p;
	int t=replace_flag + session_index;
	FILE *f;
	char srvbuf[200];
	log_debug(1, "<%d>replace_srvnode\n", __LINE__);

	if ((t!=1) && !no_srvlist(dptr->srvlist))
	{
		return 0;
	}
	else
	{
		replace_flag = (replace_flag==1)?0:1;
	}
	//destroy_srvlist(srv_p);
	/* add server */
	if (session_index == 1)
	f = fopen("/var/run/dnrd2.serv", "r");
	else
	f = fopen("/var/run/dnrd.serv", "r");

	if (!f)
		return -1;


  	//dptr->srvlist=alloc_srvnode();
  	//if (!dptr->srvlist)
  	//	return -1;
  	//dptr->next = dptr->srvlist;


	clear_srvlist(dptr->srvlist);
	dptr->srvlist->next = dptr->srvlist;
	srv_p=dptr->srvlist;
	log_debug(1, "<%d>replace_srvnode\n", __LINE__);

	while (fscanf(f, "%s", srvbuf) != EOF)
	{
		log_debug(1, "srvnode add for session 2<%d>, ip<%s>", __LINE__, srvbuf);
		if (!add_srv(last_srvnode(srv_p), srvbuf))
		{
			log_debug(1, "add server fail");
			fclose(f);
			return -1;
		}
	}

	dptr->current = dptr->srvlist;
	//while (dptr->current->addr.sin_addr == 0)
	//{
	//	dptr->current = dptr->next;
	//	if (dptr->current == dptr->srvlist)
	//		break;
	//}
	log_debug(1, "list srvlist<%s>", inet_ntoa(dptr->current->addr.sin_addr));
	for (dptr->current=dptr->srvlist->next;
			dptr->current != dptr->srvlist;
			dptr->current = dptr->current->next)
	{
  		dptr->current->addr.sin_family = AF_INET;
  		dptr->current->addr.sin_port   = htons(53);
		log_debug(1, "list srvlist<%s>", inet_ntoa(dptr->current->addr.sin_addr));
	}


	dptr->current = dptr->srvlist->next;

	//if (srv_p->next != srv_p)
	//{
	//	p=srv_p;
	//	srv_p = srv_p->next;
	//	destroy_srvnode(p);
	//}
	fclose(f);
	return 0;
}

int set_value_from_nvram(void)
{
    char temp_buff[64];
    
		dnrd_nvram_get("wan_mode", wan_mode_global, 16);
		dnrd_nvram_get("Session1Enable", s1_enabled, 16);
		dnrd_nvram_get("Session2Enable", s2_enabled, 16);
		dnrd_nvram_get("Session1Account", s1_accountNo, 16);
		sprintf(temp_buff, "ac%s_%s", s1_accountNo, "dialmode");
		dnrd_nvram_get(temp_buff, s1_dial_mode, 16);
		dnrd_nvram_get("ac6_dialmode", s2_dial_mode, 16);
		
		return 0;
}

/*
 * handle_query()
 *
 * In:      fromaddrp - address of the sender of the query.
 *
 * In/Out:  msg       - the query on input, the reply on output.
 *          len       - length of the query/reply
 *
 * Out:     dptr      - dptr->current contains the server to which to forward the query
 *
 * Returns:  -1 if the query is bogus
 *           1  if the query should be forwarded to the srvidx server
 *           0  if msg now contains the reply
 *
 * Takes a single DNS query and determines what to do with it.
 * This is common code used for both TCP and UDP.
 *
 * Assumptions: There is only one request per message.
 */
int handle_query(const struct sockaddr_in *fromaddrp, char *msg, int *len,
		 domnode_t **dptr)

{
    int       replylen;
    domnode_t *d;
    
    int is_session2=0;
    pid_t ppp0_pid=-1;
    pid_t ppp1_pid=-1;
    FILE *fp;
    
    if (opt_debug) 
		{
			char      cname_buf[256];
			sprintf_cname(&msg[12], *len-12, cname_buf, 256);
			log_debug(3, "Received DNS query for \"%s\"", cname_buf);
			if (dump_dnspacket("query", msg, *len) < 0)
			  log_debug(3, "Format error");
    }
#ifndef EXCLUDE_MASTER
    /* First, check to see if we are master server */
    if ((replylen = master_lookup(msg, *len)) > 0) {
			log_debug(2, "Replying to query as master");
			*len = replylen;
			return 0;
    }
#endif
    /* Next, see if we have the answer cached */
    if ((replylen = cache_lookup(msg, *len)) > 0) {
			log_debug(3, "Replying to query with cached answer.");
			*len = replylen;
			return 0;
    }

/* Now dial pppoe if DoD */	

		if (!url_on_session2(msg, len))
			is_session2 = 1;	
		
		if (*wan_mode_global == 'm')  // wan is multi_pppoe
		{
			if ((is_session2)&&(*s2_enabled == '1'))
        	{
                if (*s2_dial_mode == '1')  // session 2 is dod and not been dial up.
                {
                    if (now_is_dialing_session2 == 1)
                    {
                        if (access("/tmp/pppoe_multi_uptime", F_OK) == 0)
                            now_is_dialing_session2 = 0;
                    }
                    else if (access("/tmp/pppoe_multi_uptime", F_OK) != 0)
                    {
                        fp=fopen("/var/run/ppp1.pid","r");
                        if(fp)
                        {
                            fscanf(fp,"%d",&ppp1_pid);
                            fclose(fp);
                        }
                        if(ppp1_pid!=-1)
                        {
                            kill(ppp1_pid, SIGUSR1);  // dial up
                            now_is_dialing_session2 = 1;
                        }
                    }
                }
            }
		}

    /* get the server list for this domain */
    d=search_subdomnode(domain_list, &msg[12], *len);

	if ((*wan_mode_global == 'm') && (*s2_enabled == '1'))
	{  
		if (is_session2)
		{
			replace_srvnode(d, 1);
		}
		else
		{
			replace_srvnode(d, 0);
		}
	}
	
    if (no_srvlist(d->srvlist)) {
      /* there is no servers for this domain, reply with "Server failure" */
	log_debug(2, "Replying to query with \"Server failure\"");
	if (!set_srvfail(msg, *len)) return -1;
	return 0;
    }

    if (d->roundrobin) set_current(d, next_active(d));
    /* Send to a server until it "times out". */
    if (d->current) {
      time_t now = time(NULL);
      if ((d->current->send_time != 0) 
	  && (forward_timeout != 0)
	  && (reactivate_interval != 0)
	  && (now - d->current->send_time > forward_timeout)) {
	deactivate_current(d);
      }
    }

    if (d->current) {
	log_debug(3, "Forwarding the query to DNS server %s",
		  inet_ntoa(d->current->addr.sin_addr));
    } else {
/* 
    One domain time out several times will cause all domain fail, 
    Fix bug dns proxy don't work after long tiem 
    Bobby 2006-06-13
*/
    	d->current = d->srvlist->next;
    	log_debug(1, "try from head, never fail");
      //log_debug(3, "All servers deactivated. Replying with \"Server failure\"");
      //if (!set_srvfail(msg, *len)) return -1;
      //return 0;
    }

    *dptr = d;
    return 1;
}

/* Check if any deactivated server are back online again */

static void reactivate_servers(int interval) {
  time_t now=time(NULL);
  static int last_try = 0;
  domnode_t *d = domain_list;
  /*  srvnode_t *s;*/

  if (!last_try) last_try = now;
  /* check for reactivate servers */
  if ( (now - last_try < interval) || no_srvlist(d->srvlist)  ) 
    return;
 
  last_try = now;
  do {
    retry_srvlist(d, interval );
    if (!d->roundrobin) {
      /* find the first active server in serverlist */
      d->current=NULL;
      d->current=next_active(d);
    }
  } while ((d = d->next) != domain_list);  
}

void srv_stats(time_t interval) {
  srvnode_t *s;
  domnode_t *d=domain_list;
  time_t now = time(NULL);
  static time_t last=0;
  
  if (last + interval > now) {
    last = now;
    do {
      if ((s=d->srvlist)) 
	while ((s=s->next) != d->srvlist)
	  log_debug(1, "stats for %s: send count=%i",
		    inet_ntoa(s->addr.sin_addr), s->send_count);
    } while ((d=d->next) != domain_list);
  }
}


/*
 * run()
 *
 * Abstract: This function runs continuously, waiting for packets to arrive
 *           and processing them accordingly.
 */
void run()
{
  struct timeval     tout;
  fd_set             fdread;
  int                retn;
  /*
  domnode_t          *d = domain_list;
  srvnode_t          *s;
  */
    /*    int                i, j;*/

  FD_ZERO(&fdmaster);
  FD_SET(isock,   &fdmaster);
#ifdef ENABLE_TCP
  FD_SET(tcpsock, &fdmaster);
  maxsock = (tcpsock > isock) ? tcpsock : isock;
#else
  maxsock = isock;
#endif

  while(1) {
    query_t *q;
    tout.tv_sec  = select_timeout;
    tout.tv_usec = 0;
    fdread = fdmaster;
   
    /* Wait for input or timeout */
    retn = select(maxsock+1, &fdread, (fd_set *)NULL,(fd_set *)NULL, &tout);
#if 0
    /* reactivate servers */
    if (reactivate_interval != 0) 
      reactivate_servers(reactivate_interval);
#endif
    /* Handle errors */
    if (retn < 0) {
      log_msg(LOG_ERR, "select returned %s", strerror(errno));
      continue;
    }
    else if (retn != 0) {
      for (q = &qlist; q->next != &qlist; q = q->next) {
	if (FD_ISSET(q->next->sock, &fdread)) {
	  udp_handle_reply(q);
	}
      }

#ifdef ENABLE_TCP
      /* Check for incoming TCP requests */
//james ye test it      if (FD_ISSET(tcpsock, &fdread)) tcp_handle_request();
      if (FD_ISSET(tcpsock, &fdread)) 
	{
		tcp_handle_request();
	}
#endif
      /* Check for new DNS queries */
      if (FD_ISSET(isock, &fdread)) {
	q = udp_handle_request();
	if (q != NULL) {
	}
      }
    } else {
      /* idle */
    }
    
    /* ok, we are done with replies and queries, lets do some
	   maintenance work */
    
    /* Expire lookups from the cache */
    cache_expire();
#ifndef EXCLUDE_MASTER
    /* Reload the master database if neccessary */
    master_reinit();
#endif
    /* Remove old unanswered queries */
    query_timeout(20);
    
    /* create new query/socket for next incomming request */
    /* this did not make the program run any faster
    d=domain_list;
    do {
      if ((s=d->srvlist)) 
	while ((s=s->next) != d->srvlist)
	  if (s->newquery == NULL) 
	    s->newquery = query_get_new(d, s);
    } while ((d=d->next) != domain_list);
    */

    /* print som query statestics */
    query_stats(10);
    srv_stats(10);
  }
}
