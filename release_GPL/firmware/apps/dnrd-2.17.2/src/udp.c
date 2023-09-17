/*
 * udp.c - handle upd connections
 *
 * Copyright (C) 1999 Brad M. Garcia <garsh@home.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "common.h"
#include "relay.h"
#include "cache.h"
#include "query.h"
#include "domnode.h"
#include "check.h"

#ifndef EXCLUDE_MASTER
#include "master.h"
#endif

//#include <stdio.h>
//#include "../../Allen_debug.h"


/*
 * dnssend()						22OCT99wzk
 *
 * Abstract: A small wrapper for send()/sendto().  If an error occurs a
 *           message is written to syslog.
 *
 * Returns:  The return code from sendto().
 */
static int udp_send(int sock, srvnode_t *srv, void *msg, int len)
{
    int	rc;
    time_t now = time(NULL);
    rc = sendto(sock, msg, len, 0,
		(const struct sockaddr *) &srv->addr,
		sizeof(struct sockaddr_in));

    if (rc != len) {
	log_msg(LOG_ERR, "sendto error: %s: ",
		inet_ntoa(srv->addr.sin_addr), strerror(errno));
	return (rc);
    }
    if ((srv->send_time == 0)) srv->send_time = now;
    srv->send_count++;
    return (rc);
}

int send2current(query_t *q, void *msg, const int len) {
    /* If we have domains associated with our servers, send it to the
       appropriate server as determined by srvr */
  domnode_t *d;
  assert(q != NULL);
  assert(q->domain != NULL);

  d = q->domain;

  /*
  	patched by chenyl(2005/0202):

  	Dr. Edward found a DNRD's bug:

  		/bin/dnrd: udp.c: 75: send2current: Assertion `q->domain != ((void *)0)' failed.

  		DNRD crashed due to this bug.
  */
  if (d == NULL)
  {
  	return 0;
  }
  
  while ((d->current != NULL) && (udp_send(q->sock, d->current, msg, len) != len)) {
    if (reactivate_interval) deactivate_current(d);
  }
  if (d->current != NULL) {
    return len;
  } else return 0;
}
#if 0
int probe_acl(struct sockaddr_in from_addr)
{
	char *pt=value_parser_file("fw_out_rules"), *pt1, tmpstr[60]={0};
	int i;
	for(i = 0, pt1 = pt; *pt1; i++)
		{
			char *p = strchr(pt1, '\1');
			
			unsigned char ip[16] = {0};
			char protocol[7] = {0};
			unsigned int port_start = 0, port_end = 0;
			char name[20] = {0};
			if(p)
				strncpy(tmpstr, pt1, p - pt1);
			else
				strcpy(tmpstr, pt1);
			//9999:3333-3333:192.88.88.88:TCP/UDP
			sscanf(tmpstr,"%[^:]:%d-%d:%[^:]:%[^:]",
			name, &port_start, &port_end, ip, protocol);
			//debug1("file:%s, line:%d, name=%s, port=%d-%d, protocol=%s. ipaddr=%s, from_ip=%s.", __FILE__, __LINE__
			//, name, port_start, port_end, protocol, ip, inet_ntoa(from_addr.sin_addr));

			if( port_start <= 53 && port_end >= 53 && (strncmp(protocol, "UDP", 3) == 0)
			&& (strcmp(ip, inet_ntoa(from_addr.sin_addr)) == 0 || strcmp(ip, "0.0.0.0") == 0) )
			{
				//debug1("file:%s, line:%d.", __FILE__, __LINE__);
				return 1;
			}
			
			if(p)
				pt1 = p + 1;
			else 
				*pt1 = 0;	
		}
	//debug1("file:%s, line:%d.", __FILE__, __LINE__);
	return 0;
}
#endif

/*
 * handle_udprequest()
 *
 * This function handles udp DNS requests by either replying to them (if we
 * know the correct reply via master, caching, etc.), or forwarding them to
 * an appropriate DNS server.
 */
query_t *udp_handle_request()
{
    unsigned           addr_len;
    int                len;
    const int          maxsize = UDP_MAXSIZE;
    static char        msg[UDP_MAXSIZE+4];
    struct sockaddr_in from_addr;
    int                fwd;
    domnode_t          *dptr;
    query_t *q, *prev;
    
    /* Read in the message */
    addr_len = sizeof(struct sockaddr_in);
    len = recvfrom(isock, msg, maxsize, 0,
		   (struct sockaddr *)&from_addr, &addr_len);
    if (len < 0) {        
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
	log_debug(1, "recvfrom error %s", strerror(errno));
	return NULL;
    }
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
    /* do some basic checking */
    if (check_query(msg, len) < 0) 
        return NULL;
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
//	if(probe_acl(from_addr)) return NULL;
    /* Determine how query should be handled */
    if ((fwd = handle_query(&from_addr, msg, &len, &dptr)) < 0)
    {
        return NULL; /* if its bogus, just ignore it */
    }
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
    /* If we already know the answer, send it and we're done */
    if (fwd == 0) {
				if (sendto(isock, msg, len, 0, (const struct sockaddr *)&from_addr,
					   addr_len) != len) {
				    log_debug(1, "sendto error %s", strerror(errno));
				}
				return NULL;
				
    }
    
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
    /* dptr->current should never be NULL it is checked in handle_query */

    //    dnsquery_add(&from_addr, msg, len);
    // if (!send2current(dptr, msg, len)) {

    /* rewrite msg, get id and add to list*/
    
    if ((prev=query_add(dptr, dptr->current, &from_addr, msg, len)) == NULL){
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
      /* of some reason we could not get any new queries. we have to
	 drop this packet */
      return NULL;
    }
    q = prev->next;


    if (send2current(q, msg, len) > 0) {
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
      /* add to query list etc etc */
      return q;
    } else {
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
      /* we couldn't send the query */
#ifndef EXCLUDE_MASTER
      int	packetlen;
      char	packet[maxsize+4];

      /*
       * If we couldn't send the packet to our DNS servers,
       * perhaps the `network is unreachable', we tell the
       * client that we are unable to process his request
       * now.  This will show a `No address (etc.) records
       * available for host' in nslookup.  With this the
       * client won't wait hang around till he gets his
       * timeout.
       * For this feature dnrd has to run on the gateway
       * machine.
       */
      
      if ((packetlen = master_dontknow(msg, len, packet)) > 0) {
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
	query_delete_next(prev);
	return NULL;
	if (sendto(isock, msg, len, 0, (const struct sockaddr *)&from_addr,
		   addr_len) != len) {
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
	  log_debug(1, "sendto error %s", strerror(errno));
	  return NULL;
	}
      }
#endif
    }
//allen_DEBUG("\nIn udp_handle_request, line=%d\n",__LINE__);
    return q;
}

/*
 * dnsrecv()							22OCT99wzk
 *
 * Abstract: A small wrapper for recv()/recvfrom() with output of an
 *           error message if needed.
 *
 * Returns:  A positove number indicating of the bytes received, -1 on a
 *           recvfrom error and 0 if the received message is too large.
 */
static int reply_recv(query_t *q, void *msg, int len)
{
    int	rc, fromlen;
    struct sockaddr_in from;

    fromlen = sizeof(struct sockaddr_in);
    rc = recvfrom(q->sock, msg, len, 0,
		  (struct sockaddr *) &from, &fromlen);

    if (rc == -1) {
	log_msg(LOG_ERR, "recvfrom error: %s",
		inet_ntoa(q->srv->addr.sin_addr));
	return (-1);
    }
    else if (rc > len) {
	log_msg(LOG_NOTICE, "packet too large: %s",
		inet_ntoa(q->srv->addr.sin_addr));
	return (0);
    }
#if 0 // allen
    else if (memcmp(&from.sin_addr, &q->srv->addr.sin_addr,
		    sizeof(from.sin_addr)) != 0) {
	log_msg(LOG_WARNING, "unexpected server: %s",
		inet_ntoa(from.sin_addr));
	return (0);
    }
#endif
    return (rc);
}

/*
 * handle_udpreply()
 *
 * This function handles udp DNS requests by either replying to them (if we
 * know the correct reply via master, caching, etc.), or forwarding them to
 * an appropriate DNS server.
 *
 * Note that the mached query is prev->next and not prev.
 */
void udp_handle_reply(query_t *prev)
{
  //    const int          maxsize = 512; /* According to RFC 1035 */
    static char        msg[UDP_MAXSIZE+4];
    int                len;
    unsigned           addr_len;
    query_t *q = prev->next;
    log_debug(3, "handling socket %i", q->sock);
    if ((len = reply_recv(q, msg, UDP_MAXSIZE)) < 0)
      {
	log_debug(1, "dnsrecv failed: %i", len);
	query_delete_next(prev);
	return; /* recv error */
      }
    /* do basic checking */
    if (check_reply(q->srv, msg, len) < 0) {
      log_debug(1, "check_reply failed");
      query_delete_next(prev);
      return;
    }

    if (opt_debug) {
	char buf[256];
	sprintf_cname(&msg[12], len-12, buf, 256);
	log_debug(3, "Received DNS reply for \"%s\"", buf);
    }
    dump_dnspacket("reply", msg, len);
    addr_len = sizeof(struct sockaddr_in);

    /* was this a dummy reactivate query? */
    if (q->domain != NULL) {
      /* no, lets cache the reply and send to client */
      cache_dnspacket(msg, len, q->srv);

      /* set the client qid */
      *((unsigned short *)msg) = q->client_qid;
      log_debug(3, "Forwarding the reply to the host %s",
		inet_ntoa(q->client.sin_addr));
      if (sendto(isock, msg, len, 0,
		 (const struct sockaddr *)&q->client,
		 addr_len) != len) {
	log_debug(1, "sendto error %s", strerror(errno));
      }
    } else {
      log_debug(2, "We got a reactivation dummy reply. Cool!");
    }
      
    /* this server is obviously alive, we reset the counters */
    q->srv->send_time = 0;
    if (q->srv->inactive) log_debug(1, "Reactivating server %s",
				 inet_ntoa(q->srv->addr.sin_addr));
    q->srv->inactive = 0;
    /* remove query from list and destroy it */
    query_delete_next(prev);
}


/* send a dummy packet to a deactivated server to check if its back*/
int udp_send_dummy(srvnode_t *s) {
  static unsigned char dnsbuf[] = {
  /* HEADER */
    /* will this work on a big endian system? */
    0x00, 0x00, /* ID */
    0x00, 0x00, /* QR|OC|AA|TC|RD -  RA|Z|RCODE  */
    0x00, 0x01, /* QDCOUNT */
    0x00, 0x00, /* ANCOUNT */
    0x00, 0x00, /* NSCOUNT */
    0x00, 0x00, /* ARCOUNT */
    
    /* QNAME */
    9, 'l','o','c','a','l','h','o','s','t',0,
    /* QTYPE */
    0x00,0x01,   /* A record */
    
    /* QCLASS */
    0x00,0x01   /* IN */
  };
  query_t *q;
  struct sockaddr_in srcaddr;

  /* should not happen */
  assert(s != NULL);

  if ((q=query_add(NULL, s, &srcaddr, dnsbuf, sizeof(dnsbuf))) != NULL) {
    int rc;
    q = q->next; /* query add returned the query 1 before in list */
    /* don't let those queries live too long */
    q->ttl = reactivate_interval;
    memset(&srcaddr, 0, sizeof(srcaddr));
    log_debug(2, "Sending dummy id=%i to %s", ((unsigned short *)dnsbuf)[0], 
	      inet_ntoa(s->addr.sin_addr));
    /*  return dnssend(s, &dnsbuf, sizeof(dnsbuf)); */
    rc=udp_send(q->sock, s, dnsbuf, sizeof(dnsbuf));
    ((unsigned short *)dnsbuf)[0]++;
    return rc;
  }
  return -1;
}
