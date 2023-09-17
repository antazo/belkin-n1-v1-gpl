/*
 * Event loop
 * Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#ifdef CONFIG_NATIVE_WINDOWS
#include "common.h"
#endif /* CONFIG_NATIVE_WINDOWS */

#include "eloop.h"

#ifdef LINUX_WSC

#include "wsc_api.h"
#include <linux/netlink.h>

#include "../wsc_module/kwsc_mod.h"

#define MAX_MSGSIZE 2048
typedef struct
{
	struct nlmsghdr msghdr;
	wsc_argv_buf argvbuf;
}wsc_net_buf;

void invoke_wsc_sta_callback(wsc_argv_head myhead,char *myargv[])
{
	int i=0,j=0;
	int unit,len[3];
	char tmp[30];
	if(myhead.argc!=8 || myhead.len[0]!=6)
		return;

	memset(len,0,sizeof(len));
	if(myargv[1]!=NULL)
	{
		memset(tmp,0,30);
		memcpy(tmp,myargv[1],myhead.len[1]);
		tmp[myhead.len[1]]=0;
		unit=atoi(tmp);
#ifdef NETLINK_DEBUG		
		printf("unit=%d\n",unit);
#endif		
	}
	for(i=3;i<8;i+=2)
	{
		if(myargv[i]!=NULL)
		{
			memset(tmp,0,30);
			memcpy(tmp,myargv[i],myhead.len[i]);
			tmp[myhead.len[i]]=0;
			len[j]=atoi(tmp);
#ifdef NETLINK_DEBUG			
			printf("len[%d]=%d\n",j,len[j]);
#endif			
			j++;
		}
	}
#ifdef NETLINK_DEBUG	
	for(i=0;i<myhead.argc;i++)
	{
		printf("argv[%d]=%s\n",i,myargv[i]==NULL?"NULL":myargv[i]);
	}	
#endif	
	wsc_staAssocCallback(myargv[0],unit,myargv[2],len[0],myargv[4],len[1],myargv[6],len[2]);
#ifdef NETLINK_DEBUG	
	printf("isWSCClient:%d\n",isWSCClient(myargv[0]));
#endif	

}

#if 0

int CallWSCUPnPEventFunc(char *WLANEventMAC6, int WLANEventType,char *WLANEventStr, int WLANEventStrLen)
{
	int wscupnpevt_shm_id;	
	WSCUPnPEventFuncArgStc *wscupnpevt_p_map;
	wscupnpevt_shm_id=shmget(SHM_WSCUPnPEVENT_KEY,sizeof(WSCUPnPEventFuncArgStc),IPC_CREAT);        
	if(wscupnpevt_shm_id==-1)
  	{
	      perror("shmget error");
	      return -1;
  	}
  	else
	{
	      /* add this share memory into this application's memory segment */
	      wscupnpevt_p_map=(WSCUPnPEventFuncArgStc *)shmat(wscupnpevt_shm_id,NULL,0);
	      wscupnpevt_p_map->SHMSTATUS=SHM_STATUS_DATA_INVALID;
  	}	
    /* write data into share memory */
    if(wscupnpevt_p_map!=NULL){
        wscupnpevt_p_map->SHMSTATUS = SHM_STATUS_DATA_VALID;
        memcpy(wscupnpevt_p_map->WLANEventMAC,WLANEventMAC6,6);
        wscupnpevt_p_map->WLANEventType=WLANEventType;
        memcpy(wscupnpevt_p_map->WLANEventStr,WLANEventStr,((WLANEventStrLen<WLANEventStrMaxLen)?WLANEventStrLen:WLANEventStrMaxLen));
        wscupnpevt_p_map->WLANEventStrLen=WLANEventStrLen;
    }
	
      if(wscupnpevt_shm_id!=-1 && wscupnpevt_p_map!=NULL)
      {
		wscupnpevt_p_map->SHMSTATUS = SHM_STATUS_EXIT;
		if(shmdt(wscupnpevt_p_map)==-1)
		{
          		printf(" upnp free error\n ");
		}
     }		    
    return 0;
}
#endif


void invoke_wsc_txUPNPEvent(wsc_argv_head myhead,char *myargv[])
{
	char tmp[30];
	int  type=0;
	int msglen=0;
	
#ifdef NETLINK_DEBUG
    int i=0,j=0;
	printf("invoke_wsc_txUPNPEvent() - myhead.argc=%d, myhead.len[0]=%d\n",myhead.argc,myhead.len[0]);
#endif
	if(myhead.argc!=4 || myhead.len[0]!=6)
		return;
	
	if(myargv[1]!=NULL)
	{
		memset(tmp,0,30);
		memcpy(tmp,myargv[1],myhead.len[1]);
		tmp[myhead.len[1]]=0;
		type=atoi(tmp);
#ifdef NETLINK_DEBUG		
		printf("%s type = %d\n",__FUNCTION__,type);
#endif		
	}
	
	if(myargv[3]!=NULL)
	{
		memset(tmp,0,30);
		memcpy(tmp,myargv[3],myhead.len[3]);
		tmp[myhead.len[3]]=0;
		msglen=atoi(tmp);
#ifdef NETLINK_DEBUG		
		printf("%s msglen = %d\n",__FUNCTION__,msglen);		
#endif		
	}
#ifdef NETLINK_DEBUG
	for(i=0;i<myhead.argc;i++)
	{
		printf("argv[%d]=%s\n",i,myargv[i]==NULL?"NULL":myargv[i]);
	}
#endif	
	wsc_txUPNPEvent(myargv[0],type,myargv[2],msglen);
}


void invoke_setpin(wsc_argv_head myhead,char *myargv[])
{
	char tmppin[9];
	
	if( myhead.argc == CANCEL_PIN )
	{
	    printf("[%s]%d cacncel PIN mode\n",PRE);
	    wps_pin_cancel();
	    return;
    }    
	if(myhead.argc!=1 || myhead.len[0]>10)
	{
	    printf("[%s]%d myhead.arc=%d, myhead.len[0]=%d\n",PRE, myhead.argc, myhead.len[0]);
		return;
	}
	if(myargv[0]== NULL)
	{
	    printf("[%s]%d myhead.arcv[0]=NULL\n",PRE); 
		return;
	}
	strncpy(tmppin,myargv[0],8);
	tmppin[8]=0;
	
	setPin(tmppin);
}

wps_pbc_process(wsc_argv_head myhead,char *myargv[])
{
    
    if( myhead.argc == CANCEL_PIN )
	{
	    printf("[%s]%d cacncel PIN mode\n",PRE);
	    wps_pbc_cancel();
	    return;
    }
    /* else wps pbc start */
    wsc_pushButtonPressed();
    
}

void freeargv(char *argv[],int n)
{
	int i;
	if(n!=0)
	{
		for(i=0;i<n;i++)
		{
			if(argv[i]!=NULL)
				free(argv[i]);
		}
	}
}
	

int parserecvbuf(wsc_net_buf *recvbuf)
{
	int i;
	wsc_argv_buf *argvtmp=NULL;
//	wsc_argv_head *headtmp=NULL;
	struct nlmsghdr msghead;
	char *datatmp=NULL;
	int datasum=0;
	unsigned long msglen;
	unsigned short msgtype,msgpid;
	wsc_argv_head head_tmp;
//	int head_argc=0;
//	int head_len[MAX_ARGV_COUNTER];
	char *myargv[MAX_ARGV_COUNTER];

	if(recvbuf==NULL)
		return -1;
	
	for(i=0;i<MAX_ARGV_COUNTER;i++)
		myargv[i]=NULL;
	
	memset(&msghead,0,sizeof(msghead));
	memcpy(&msghead,recvbuf,sizeof(msghead));
	
	msglen=msghead.nlmsg_len;
	msgtype=msghead.nlmsg_type;
	msgpid=msghead.nlmsg_pid;
#ifdef NETLINK_DEBUG	
	printf("msg len  : %u\n",msglen);
	printf("msg type : %u\n",msgtype);
	printf("msg pid  : %u\n",msgpid);
#endif	
	argvtmp=(struct wsc_argv_buf *)(((char *)recvbuf)+sizeof(struct nlmsghdr));

	head_tmp.argc=argvtmp->head.argc;
#ifdef NETLINK_DEBUG
	printf("argv->head.argc = %d\n",head_tmp.argc);
#endif	
	
	for(i=0;i<head_tmp.argc;i++)
	{	
		head_tmp.len[i]=argvtmp->head.len[i];
#ifdef NETLINK_DEBUG		
		printf("argv->head.len[%d]=%d\n",i,head_tmp.len[i]);
#endif		
	}

	datasum=DATALEN(head_tmp);
#ifdef NETLINK_DEBUG
	printf("data sum = %d\n",datasum);
#endif	
	datatmp=(char *)(argvtmp)+sizeof(wsc_argv_head);
	
#ifdef NETLINK_DEBUG	
	for(i=0;i<datasum;i++)
	{
		printf("0x%02X ",(unsigned char)datatmp[i]);
	}
#endif
	for(i=0;i<head_tmp.argc;i++)
	{
#ifdef NETLINK_DEBUG		
		printf("head_len[%d]==%d\n",i,head_tmp.len[i]);
#endif		
		if(head_tmp.len[i]==0)
		{

			myargv[i]=NULL;
			continue;
		}
		
		myargv[i]=malloc(head_tmp.len[i]);
		if(myargv[i]==NULL)
		{
#ifdef NETLINK_DEBUG			
			printf("malloc myargv[%d]==NULL\n",i);
#endif			
			freeargv(myargv,i);
			return -1;
		}

		memcpy(myargv[i],datatmp,head_tmp.len[i]);
		datatmp+=head_tmp.len[i];
	}

	switch(msgtype)
	{
		case WSC_STA_CALLBACK:
			printf("kernel call WSC_STA_CALLBACK\n");			
			invoke_wsc_sta_callback(head_tmp,myargv);
			break;
		case WSC_TX_UPNPEVENT:
			printf("kernel call WSC_TX_UPNPEVENT\n");
			invoke_wsc_txUPNPEvent(head_tmp,myargv);
			break;
		case WSC_DAEMON:
		//	printf("kernel call WSC_DAEMON\n");
			wsc_daemon();
			break;
		case WSC_PUSH_BUTTON:
			printf("kernel call WSC_PUSH_BUTTON\n");
			/* blink wps led for pbc */
//			system("/bin/echo wpsled > /proc/led");
			wps_pbc_process(head_tmp,myargv);
			break;
		case WSC_SETPIN:
			printf("kernel call WSC_SETPIN\n");
			/* blink wps led for pbc */
//			system("/bin/echo wpsled > /proc/led");			
			invoke_setpin(head_tmp,myargv);
			break;
		default:
			return -1;
	}
	freeargv(myargv,head_tmp.argc);
	return 0;
}

int netlink_skfd=-1;

int creat_netlink_sock(void)
{
        struct sockaddr_nl local;
	int skfd;
		
	skfd=socket(PF_NETLINK,SOCK_RAW,NETLINK_WSC);

	if(skfd<0)
	{
		printf("creat socket error\n ");
		return -1;
	}

	memset(&local,0,sizeof(local));

	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 1;

	if(bind(skfd,(struct sockaddr*)&local,sizeof(local))!=0)
	{
		printf("bind error\n");
		return -1;
	}
	return skfd;

}

#endif /* LINUX_WSC */




struct eloop_sock {
	int sock;
	void *eloop_data;
	void *user_data;
	void (*handler)(int sock, void *eloop_ctx, void *sock_ctx);
};

struct eloop_timeout {
	struct timeval time;
	void *eloop_data;
	void *user_data;
	void (*handler)(void *eloop_ctx, void *sock_ctx);
	struct eloop_timeout *next;
};

struct eloop_signal {
	int sig;
	void *user_data;
	void (*handler)(int sig, void *eloop_ctx, void *signal_ctx);
	int signaled;
};

struct eloop_data {
	void *user_data;

	int max_sock, reader_count;
	struct eloop_sock *readers;

	struct eloop_timeout *timeout;

	int signal_count;
	struct eloop_signal *signals;
	int signaled;
	int pending_terminate;

	int terminate;
};

static struct eloop_data eloop;


void eloop_init(void *user_data)
{
	memset(&eloop, 0, sizeof(eloop));
	eloop.user_data = user_data;
}


int eloop_register_read_sock(int sock,
			     void (*handler)(int sock, void *eloop_ctx,
					     void *sock_ctx),
			     void *eloop_data, void *user_data)
{
	struct eloop_sock *tmp;

	tmp = (struct eloop_sock *)
		realloc(eloop.readers,
			(eloop.reader_count + 1) * sizeof(struct eloop_sock));
	if (tmp == NULL)
		return -1;

	tmp[eloop.reader_count].sock = sock;
	tmp[eloop.reader_count].eloop_data = eloop_data;
	tmp[eloop.reader_count].user_data = user_data;
	tmp[eloop.reader_count].handler = handler;
	eloop.reader_count++;
	eloop.readers = tmp;
	if (sock > eloop.max_sock)
		eloop.max_sock = sock;

	return 0;
}


void eloop_unregister_read_sock(int sock)
{
	int i;

	if (eloop.readers == NULL || eloop.reader_count == 0)
		return;

	for (i = 0; i < eloop.reader_count; i++) {
		if (eloop.readers[i].sock == sock)
			break;
	}
	if (i == eloop.reader_count)
		return;
	if (i != eloop.reader_count - 1) {
		memmove(&eloop.readers[i], &eloop.readers[i + 1],
			(eloop.reader_count - i - 1) *
			sizeof(struct eloop_sock));
	}
	eloop.reader_count--;
}


int eloop_register_timeout(unsigned int secs, unsigned int usecs,
			   void (*handler)(void *eloop_ctx, void *timeout_ctx),
			   void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *tmp, *prev;

	timeout = (struct eloop_timeout *) malloc(sizeof(*timeout));
	if (timeout == NULL)
		return -1;
	gettimeofday(&timeout->time, NULL);
	timeout->time.tv_sec += secs;
	timeout->time.tv_usec += usecs;
	while (timeout->time.tv_usec >= 1000000) {
		timeout->time.tv_sec++;
		timeout->time.tv_usec -= 1000000;
	}
	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;
	timeout->next = NULL;

	if (eloop.timeout == NULL) {
		eloop.timeout = timeout;
		return 0;
	}

	prev = NULL;
	tmp = eloop.timeout;
	while (tmp != NULL) {
		if (timercmp(&timeout->time, &tmp->time, <))
			break;
		prev = tmp;
		tmp = tmp->next;
	}

	if (prev == NULL) {
		timeout->next = eloop.timeout;
		eloop.timeout = timeout;
	} else {
		timeout->next = prev->next;
		prev->next = timeout;
	}

	return 0;
}


int eloop_cancel_timeout(void (*handler)(void *eloop_ctx, void *sock_ctx),
			 void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout, *prev, *next;
	int removed = 0;

	prev = NULL;
	timeout = eloop.timeout;
	while (timeout != NULL) {
		next = timeout->next;

		if (timeout->handler == handler &&
		    (timeout->eloop_data == eloop_data ||
		     eloop_data == ELOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		     user_data == ELOOP_ALL_CTX)) {
			if (prev == NULL)
				eloop.timeout = next;
			else
				prev->next = next;
			free(timeout);
			removed++;
		} else
			prev = timeout;

		timeout = next;
	}

	return removed;
}


#ifndef CONFIG_NATIVE_WINDOWS
static void eloop_handle_alarm(int sig)
{
	fprintf(stderr, "eloop: could not process SIGINT or SIGTERM in two "
		"seconds. Looks like there\n"
		"is a bug that ends up in a busy loop that "
		"prevents clean shutdown.\n"
		"Killing program forcefully.\n");
	exit(1);
}
#endif /* CONFIG_NATIVE_WINDOWS */


static void eloop_handle_signal(int sig)
{
	int i;

#ifndef CONFIG_NATIVE_WINDOWS
	if ((sig == SIGINT || sig == SIGTERM) && !eloop.pending_terminate) {
		/* Use SIGALRM to break out from potential busy loops that
		 * would not allow the program to be killed. */
		eloop.pending_terminate = 1;
		signal(SIGALRM, eloop_handle_alarm);
		alarm(2);
	}
#endif /* CONFIG_NATIVE_WINDOWS */

	eloop.signaled++;
	for (i = 0; i < eloop.signal_count; i++) {
		if (eloop.signals[i].sig == sig) {
			eloop.signals[i].signaled++;
			break;
		}
	}
}


static void eloop_process_pending_signals(void)
{
	int i;

	if (eloop.signaled == 0)
		return;
	eloop.signaled = 0;

	if (eloop.pending_terminate) {
#ifndef CONFIG_NATIVE_WINDOWS
		alarm(0);
#endif /* CONFIG_NATIVE_WINDOWS */
		eloop.pending_terminate = 0;
	}

	for (i = 0; i < eloop.signal_count; i++) {
		if (eloop.signals[i].signaled) {
			eloop.signals[i].signaled = 0;
			eloop.signals[i].handler(eloop.signals[i].sig,
						 eloop.user_data,
						 eloop.signals[i].user_data);
		}
	}
}


int eloop_register_signal(int sig,
			  void (*handler)(int sig, void *eloop_ctx,
					  void *signal_ctx),
			  void *user_data)
{
	struct eloop_signal *tmp;

	tmp = (struct eloop_signal *)
		realloc(eloop.signals,
			(eloop.signal_count + 1) *
			sizeof(struct eloop_signal));
	if (tmp == NULL)
		return -1;

	tmp[eloop.signal_count].sig = sig;
	tmp[eloop.signal_count].user_data = user_data;
	tmp[eloop.signal_count].handler = handler;
	tmp[eloop.signal_count].signaled = 0;
	eloop.signal_count++;
	eloop.signals = tmp;
	signal(sig, eloop_handle_signal);

	return 0;
}

#ifndef LINUX_WSC
void eloop_run(void)
{
	fd_set rfds;
	int i, res;
	struct timeval tv, now;

	while (!eloop.terminate &&
		(eloop.timeout || eloop.reader_count > 0)) {
		if (eloop.timeout) {
			gettimeofday(&now, NULL);
			if (timercmp(&now, &eloop.timeout->time, <))
				timersub(&eloop.timeout->time, &now, &tv);
			else
				tv.tv_sec = tv.tv_usec = 0;
#if 0
			printf("next timeout in %lu.%06lu sec\n",
			       tv.tv_sec, tv.tv_usec);
#endif
		}

		FD_ZERO(&rfds);
		for (i = 0; i < eloop.reader_count; i++)
			FD_SET(eloop.readers[i].sock, &rfds);
		res = select(eloop.max_sock + 1, &rfds, NULL, NULL,
			     eloop.timeout ? &tv : NULL);
		if (res < 0 && errno != EINTR) {
			perror("select");
			return;
		}
		eloop_process_pending_signals();

		/* check if some registered timeouts have occurred */
		if (eloop.timeout) {
			struct eloop_timeout *tmp;

			gettimeofday(&now, NULL);
			if (!timercmp(&now, &eloop.timeout->time, <)) {
				tmp = eloop.timeout;
				eloop.timeout = eloop.timeout->next;
				tmp->handler(tmp->eloop_data,
					     tmp->user_data);
				free(tmp);
			}

		}

		if (res <= 0)
			continue;

		for (i = 0; i < eloop.reader_count; i++) {
			if (FD_ISSET(eloop.readers[i].sock, &rfds)) {
				eloop.readers[i].handler(
					eloop.readers[i].sock,
					eloop.readers[i].eloop_data,
					eloop.readers[i].user_data);
			}
		}
	}
}
#else /* for wsc */
void eloop_run(void)
{
	fd_set rfds;
	int i, res;
	struct timeval tv, now;

	struct sockaddr_nl kpeer;
	int kpeerlen;
	int rcvlen=0;
	char buf[MAX_MSGSIZE];
	wsc_net_buf *pt_buf=NULL;
	netlink_skfd=creat_netlink_sock();
	if(netlink_skfd<0)
		return;
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;	
	
	while (!eloop.terminate &&
		(eloop.timeout || eloop.reader_count > 0)) {
		if (eloop.timeout) {
			gettimeofday(&now, NULL);
			if (timercmp(&now, &eloop.timeout->time, <))
				timersub(&eloop.timeout->time, &now, &tv);
			else
				tv.tv_sec = tv.tv_usec = 0;
#if 0
			printf("next timeout in %lu.%06lu sec\n",
			       tv.tv_sec, tv.tv_usec);
#endif
		}
		FD_ZERO(&rfds);
		FD_SET(netlink_skfd,&rfds); 
		for (i = 0; i < eloop.reader_count; i++)
			FD_SET(eloop.readers[i].sock, &rfds);
		res = select((eloop.max_sock>netlink_skfd?eloop.max_sock:netlink_skfd) + 1, &rfds, NULL, NULL,
			     eloop.timeout ? &tv : NULL);
		if (res < 0 && errno != EINTR) {
			perror("select");
			return;
		}
		eloop_process_pending_signals();

		/* check if some registered timeouts have occurred */
		if (eloop.timeout) {
			struct eloop_timeout *tmp;

			gettimeofday(&now, NULL);
			if (!timercmp(&now, &eloop.timeout->time, <)) {
				tmp = eloop.timeout;
				eloop.timeout = eloop.timeout->next;
				tmp->handler(tmp->eloop_data,
					     tmp->user_data);
				free(tmp);
			}

		}

		if (res <= 0)
			continue;

		
		if(FD_ISSET(netlink_skfd,&rfds) && wsc_enable())
		{
			rcvlen=recvfrom(netlink_skfd,buf,MAX_MSGSIZE,0,(struct sockaddr*)&kpeer,&kpeerlen);
			if(rcvlen>0)
			{
#ifdef NETLINK_DEBUG				
				printf("recv buf:\n");
				for(i=0;i<rcvlen;i++)
				{
					printf("0x%02X ",buf[i]);
				}
				printf("\n");
#endif				
				pt_buf=(wsc_net_buf *)buf;
				parserecvbuf(pt_buf);
			}
		}

		for (i = 0; i < eloop.reader_count; i++) {
			if (FD_ISSET(eloop.readers[i].sock, &rfds)) {
				eloop.readers[i].handler(
					eloop.readers[i].sock,
					eloop.readers[i].eloop_data,
					eloop.readers[i].user_data);
			}
		}
	}
	if(netlink_skfd>0)
		close(netlink_skfd);
}
#endif

void eloop_terminate(void)
{
	eloop.terminate = 1;
}


void eloop_destroy(void)
{
	struct eloop_timeout *timeout, *prev;

	timeout = eloop.timeout;
	while (timeout != NULL) {
		prev = timeout;
		timeout = timeout->next;
		free(prev);
	}
	free(eloop.readers);
	free(eloop.signals);
}


int eloop_terminated(void)
{
	return eloop.terminate;
}
