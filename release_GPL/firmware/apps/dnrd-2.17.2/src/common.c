/*
 * common.c - includes global variables and functions.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include "common.h"
#include "lib.h"


#ifdef DEBUG
#define OPT_DEBUG 1
#else
#define OPT_DEBUG 0
#endif /* DEBUG */


/*
 * These are all the global variables.
 */
int                 opt_debug = OPT_DEBUG;
int                 opt_serv = 0;
const char*         progname = 0;

#ifdef ENABLE_PIDFILE
#if defined(__sun__)
const char*         pid_file = "/var/tmp/dnrd.pid";
const char*         serv_file = "/var/tmp/dnrd.serv";
#else
const char*         pid_file = "/var/run/dnrd.pid";
const char*         serv_file = "/var/run/dnrd.serv";
#endif
#endif

int                 isock = -1;
#ifdef ENABLE_TCP
int                 tcpsock = -1;
#endif
int                 select_timeout = SELECT_TIMEOUT;
int                 forward_timeout = FORWARD_TIMEOUT;
//int                 load_balance = 0;
uid_t               daemonuid = 0;
gid_t               daemongid = 0;
const char*         version = PACKAGE_VERSION;
int                 gotterminal = 1; /* 1 if attached to a terminal */
sem_t               dnrd_sem;  /* Used for all thread synchronization */

int			load_balance = 0;
int                 reactivate_interval = REACTIVATE_INTERVAL;

/* The path where we chroot. All config files are relative this path */
char                dnrd_root[512] = DNRD_ROOT;

char                config_file[512] = DNRD_ROOT "/" CONFIG_FILE;

domnode_t           *domain_list;
/* turn this on to skip cache hits from responses of inactive dns servers */
int                 ignore_inactive_cache_hits = 0; 

/* highest socket number */
int                 maxsock;

/* maximum number of open sockets. If we have this amount of
   concurrent queries, we start dropping new ones */
int max_sockets = 200;

/* the fd set. query modifies this so we make it global */
fd_set              fdmaster;



/*
 * This is the address we listen on.  It gets initialized to INADDR_ANY,
 * which means we listen on all local addresses.  Both the address and
 * the port can be changed through command-line options.
 */
/*
#if defined(__sun__)
struct sockaddr_in recv_addr = { AF_INET, 53, { { {0, 0, 0, 0} } } };
#else
struct sockaddr_in recv_addr = { AF_INET, 53, { INADDR_ANY } };
#endif
*/

/* init recv_addr in main.c instead of here */ 
struct sockaddr_in recv_addr;

#ifdef ENABLE_PIDFILE
/* check if a pid is running 
 * from the unix faq
 * http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC18
 */

int isrunning(int pid) {
  if (kill(pid, 0) ) {
    if (errno==EPERM) { 
      return 1;
    } else return 0;
  } else {
    return 1;
  }
}

/* wait_for_exit()
 *
 * In: pid     - the process id to wait for
 *     timeout - maximum time to wait in 1/100 secs
 *
 * Returns: 1 if it died in before timeout
 *
 * Abstract: Check if a process is running and wait til it does not
 */
int wait_for_exit(int pid, int timeout) {
  while (timeout--) {
    if (! isrunning(pid)) return 1;
    usleep(10000);
  }
  /* ouch... we timed out */
  return 0;
}

/*
 * kill_current()
 *
 * Returns: 1 if a currently running dnrd was found & killed, 0 otherwise.
 *
 * Abstract: This function sees if pid_file already exists and, if it does,
 *           will kill the current dnrd process and remove the file.
 */
int kill_current()
{
    int         pid;
    int         retn;
    struct stat finfo;
    FILE*       filep;

    if (stat(pid_file, &finfo) != 0) return 0;

    filep = fopen(pid_file, "r");
    if (!filep) {
	log_msg(LOG_ERR, "%s: Can't open %s\n", progname, pid_file);
	exit(-1);
    }
    if ((retn = (fscanf(filep, "%i%*s", &pid) == 1))) {
	if (kill(pid, SIGTERM)) {
	    log_msg(LOG_ERR, "Couldn't kill dnrd: %s", strerror(errno));
	}
	/* dnrd gets 4 seconds to die or we give up */
	if (!wait_for_exit(pid, 400)) {
	  log_msg(LOG_ERR, "The dnrd process didn't die within 4 seconds");
	}
    }
    fclose(filep);
    unlink(pid_file);
    return retn;
}
#endif /* ENABLE_PIDFILE*/

/*
 * log_msg()
 *
 * In:      type - a syslog priority
 *          fmt  - a formatting string, ala printf.
 *          ...  - other printf-style arguments.
 *
 * Sends a message to stdout or stderr if attached to a terminal, otherwise
 * it sends a message to syslog.
 */
#ifndef EMBED
void log_msg(int type, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);

    if (gotterminal) {
	const char *typestr;
	switch (type) {
	  case LOG_EMERG:   typestr = "EMERG: "; break;
	  case LOG_ALERT:   typestr = "ALERT: "; break;
	  case LOG_CRIT:    typestr = "CRIT:  "; break;
	  case LOG_ERR:     typestr = "ERROR: "; break;
	  case LOG_WARNING: typestr = "Warning: "; break;
	  case LOG_NOTICE:  typestr = "Notice: "; break;
	  case LOG_INFO:    typestr = "Info:  "; break;
	  case LOG_DEBUG:   typestr = "Debug: "; break;
	  default:          typestr = ""; break;
	}
	fprintf(stderr, typestr);
	vfprintf(stderr, fmt, ap);
	if (fmt[strlen(fmt) - 1] != '\n') fprintf(stderr, "\n");
    }
    else {
	vsyslog(type, fmt, ap);
    }
    va_end(ap);
}

/*
 * log_debug()
 *
 * In:      fmt - a formatting string, ala printf.
 *          ... - other printf-style arguments.
 *
 * Abstract: If debugging is turned on, this will send the message
 *           to syslog with LOG_DEBUG priority.
 */
void log_debug(int level, const char *fmt, ...)
{
    va_list ap;
    
    if (opt_debug < level) return;

    va_start(ap, fmt);
    if (gotterminal) {
	fprintf(stderr, "Debug: ");
	vfprintf(stderr, fmt, ap);
	if (fmt[strlen(fmt) - 1] != '\n') fprintf(stderr, "\n");
    }
    else {
	vsyslog(LOG_DEBUG, fmt, ap);
    }
    va_end(ap);
}
#endif

#ifdef USERAPP_NOMMU
/*
 * cleanall()
 *
 *
 * Abstract: This function closes our sockets
 */
void cleanall()
{
    int i;

    /* Only let one process run this code) */
#ifndef EMBED
    sem_wait(&dnrd_sem);
#endif

    log_debug("Shutting down...\n");
    if (isock >= 0) close(isock);
    if (tcpsock >= 0) close(tcpsock);
    /*
    for (i = 0; i < serv_cnt; i++) {
	close(dns_srv[i].sock);
    }
    */
    destroy_domlist(domain_list);
}


/*
 * rmFile()
 *
 *
 * Abstract: This  removes /var/run/dnrd.pid, /var/run/dnrd.serv
 */
void rmFile()
{
	char tmpStr[strlen(pid_file) + 10];
	char tmpStr2[strlen(serv_file) + 10];

	bzero(tmpStr, (strlen(pid_file) + 10));
	bzero(tmpStr2, (strlen(serv_file) + 10));
	sprintf(tmpStr, "rm %s", pid_file);
	sprintf(tmpStr2, "rm %s", serv_file);
	system(tmpStr);
	system(tmpStr2);
}
#endif


/*
 * cleanexit()
 *
 * In:      status - the exit code.
 *
 * Abstract: This closes our sockets, removes /var/run/dnrd.pid,
 *           and then calls exit.
 */
void cleanexit(int status)
{
  /*    int i;*/

#ifdef USERAPP_NOMMU
    cleanall();
    rmFile();
#else
    /* Only let one process run this code) */
#ifndef EMBED
    sem_wait(&dnrd_sem);
#endif

    log_debug(1, "Shutting down...\n");
    if (isock >= 0) close(isock);
#ifdef ENABLE_TCP
    if (tcpsock >= 0) close(tcpsock);
#endif
    /*
    for (i = 0; i < serv_cnt; i++) {
	close(dns_srv[i].sock);
    }
    */
    destroy_domlist(domain_list);
#endif
    exit(status);
}

/*
 * make_cname()
 *
 * In:       text - human readable domain name string
 *
 * Returns:  Pointer to the allocated, filled in character string on success,
 *           NULL on failure.
 *
 * Abstract: converts the human-readable domain name to the DNS CNAME
 *           form, where each node has a length byte followed by the
 *           text characters, and ends in a null byte.  The space for
 *           this new representation is allocated by this function.
 */
char* make_cname(const char *text, const int maxlen)
{
  /* this kind of code can easily contain buffer overflow. 
     I have checked it and double checked it so I believe it does not.
     Natanael */
    const char *tptr = text;
    const char *end = text;
    char *cname = (char*)allocate(strnlen(text, maxlen) + 2);
    char *cptr = cname;

    while (*end != 0) {
	size_t diff;
	end = strchr(tptr, '.');
	if (end == NULL) end = text + strnlen(text, maxlen);
	if (end <= tptr) {
	    free(cname);
	    return NULL;
	}
	diff = end - tptr;
	*cptr++ = diff;
	memcpy(cptr, tptr, diff);
	cptr += diff;
	tptr = end + 1;
    }
    *cptr = 0;
    assert((unsigned)(cptr - cname) == strnlen(text, maxlen) + 1);
    return cname;
}



void sprintf_cname(const char *cname, int namesize, char *buf, int bufsize)
{
  const char *s = cname; /*source pointer */
  char *d = buf; /* destination pointer */

  if (cname == NULL) return;
    
  if ((strnlen(cname, namesize)+1) > (unsigned)bufsize) {
    if (bufsize > 11) {
      sprintf(buf, "(too long)");
    }
    else {
      buf[0] = 0;
    }
    return;
  }

  /* extract the pascal style strings */
  while (*s) {
    int i;
    int size = *s;

    /* Let us see if we are bypassing end of buffer.  Also remember
     * that we need space for an ending \0
     */
    if ((s + *s - cname) >= (bufsize)) {
      if (bufsize > 15 ) {
	sprintf(buf, "(malformatted)");
      } else {
	buf[0] = 0;
      }
      return;
    }

    /* delimit the labels with . */
    if (s++ != cname) sprintf(d++, ".");
   
    for(i = 0; i < size; i++) {
      *d++ = *s++;
    }
    *d=0;
  }
}

/* convert cname to ascii and return a static buffer */
char *cname2asc(const char *cname) {
  static char buf[256];
  /* Note: we don't really check the size of the incomming cname. but
     according to RFC 1035 a name must not be bigger than 255 octets.
   */
  if (cname) 
    sprintf_cname(cname, sizeof(buf), buf, sizeof(buf));
  else
    strncpy(buf, "(default)", sizeof(buf));
  return buf;
}

/*
	parse server file and reset server list
*/

void parse_serfile()
{
	FILE *sf = NULL;
	char tmp[30];
	int ptr;
	int gotdomain = 0;

#ifndef EMBED
	sem_wait(&dnrd_sem);
#endif
	sf = fopen(serv_file, "r");
	if (!sf)
	{
		log_msg(LOG_ERR, "%s: Server List file does not exist!\n", progname);
		goto errout;
	}
	bzero(tmp, sizeof(tmp));
//	serv_cnt = 0;
	while ((ptr = fscanf(sf,"%s", tmp)) != EOF)
	{
		char *sep = tmp;
		char *s;
		domnode_t *p;
		int domain_is_defined = 0;
		
		if (tmp[0] == '\0')
			continue;
		/***********************************************************************************/

		if (sep)
		{
			/* if domain is defined, we add it to specific domain */
			if (domain_is_defined)
			{
				/* remove '.' */
				if ((s = make_cname(strnlwr(sep, 200),200)) == NULL)
					continue;
				/* find domain */
				if ((p = search_domnode(domain_list, s)) == NULL)
				{	/* add domain */
					p = add_domain(domain_list, load_balance, s, 200);
						log_debug("Added domain %s %s load balancing", sep,
							  load_balance ? "with" : "without");
					assert(p);
				}
			}else
			{
				p = domain_list;
			}
			/* add server */
			if (!add_srv(last_srvnode(p->srvlist), sep))
			{
				log_msg(LOG_ERR, "%s: Bad ip address \"%s\"\n",
					progname, sep);
				goto errout;
			}else
			{
				log_debug("Server %s added to domain %s", sep, sep);
			}
			if (p->roundrobin != load_balance)
			{
				p->roundrobin = load_balance;
				log_debug("Turned on load balancing for domain %s",
					cname2asc(p->domain));
			}
		}
#if 0
	      if (serv_cnt >= MAX_SERV) {
		  log_msg(LOG_ERR, "%s: Max. %d DNS servers allowed\n",
			  progname, MAX_SERV);
		  goto errout;
	      }
	      if (gotdomain == -1) {
		  log_msg(LOG_ERR, "%s: When giving server arguments with "
			  "domain names,\nonly the last one is permitted to "
			  "not have a domain name.\n", progname);
		  goto errout;
	      }
	      if (sep) {
		  dns_srv[serv_cnt].domain = make_cname(sep + 1);
		  if (gotdomain == -1) {
		      log_msg(LOG_ERR, "%s: Server arguments with domain "
			      "names must appear before\n"
			      "those without domain names.\n", progname);
		      goto errout;
		  }
		  gotdomain = 1;
		  *sep = 0;
	      }
	      else if (gotdomain != 0) {
		  gotdomain = -1;
	      }

	      if (!inet_aton(tmp, &dns_srv[serv_cnt].addr.sin_addr)) {
		  log_msg(LOG_ERR, "%s: Bad ip address \"%s\"\n",
			  progname, tmp);
		  goto errout;
	      }
#endif
//	      if (sep) *sep = ':';
//	      serv_cnt++;
		/**********************************************************************************/
		bzero(tmp, sizeof(tmp));
	}

out:
	fclose(sf);
#ifndef EMBED
	sem_post(&dnrd_sem);
#endif
	return;
errout:
	if (sf)
		fclose(sf);
#ifndef EMBED
	sem_post(&dnrd_sem);
#endif
	exit(-1);
}

