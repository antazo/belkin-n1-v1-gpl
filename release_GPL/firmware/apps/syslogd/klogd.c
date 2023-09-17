/* vi: set sw=4 ts=4: */
/*
 * Mini klogd implementation for busybox
 *
 * Copyright (C) 2001 by Gennady Feldman <gfeldman@gena01.com>.
 * Changes: Made this a standalone busybox module which uses standalone
 * 					syslog() client interface.
 *
 * Copyright (C) 1999,2000 by Lineo, inc. and Erik Andersen
 * Copyright (C) 1999,2000,2001 by Erik Andersen <andersee@debian.org>
 *
 * Copyright (C) 2000 by Karl M. Hegbloom <karlheg@debian.org>
 *
 * "circular buffer" Copyright (C) 2000 by Gennady Feldman <gfeldman@gena01.com>
 *
 * Maintainer: Gennady Feldman <gfeldman@gena01.com> as of Mar 12, 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>		/* for our signal() handlers */
#include <string.h>		/* strncpy() */
#include <errno.h>		/* errno and friends */
#include <unistd.h>
#include <ctype.h>
#include <sys/syslog.h>

#if __GNU_LIBRARY__ < 5
# ifdef __alpha__
#   define klogctl syslog
# endif
#else
# include <sys/klog.h>
#endif
#include <syslog.h>
#include "sysklogd.h"

//#define _LOG_DEBUG_

#ifdef _LOG_DEBUG_

#include <stdarg.h>
void mBug(char *format, ...)
{
    va_list args;
    FILE *fp;

    fp = fopen("/var/debug_file", "a+");
    if (!fp)
        return ;
        
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    fprintf(fp, "\n");
    fflush(fp);
    fclose(fp);
    system("/bin/chmod 777 /var/debug_file");
}
#endif

int check_wlan_info(const int priority, char *pWlanInfoStart);
void flash_wlan_led(int reason);

static void klogd_signal(int sig)
{
	klogctl(7, NULL, 0);
	klogctl(0, 0, 0);
	/* logMessage(0, "Kernel log daemon exiting."); */
	exit(TRUE);
}

static void doKlogd(const char console_log_level) __attribute__ ((noreturn));
static void doKlogd(const char console_log_level)
{
	int priority = LOG_INFO;
	char log_buffer[4096];
	int i, n, lastc;
	char *start;
	int reason = -1; /* for wlan infor reason */

	/* Set up sig handlers */
	signal(SIGINT, klogd_signal);
	signal(SIGKILL, klogd_signal);
	signal(SIGTERM, klogd_signal);
	signal(SIGHUP, SIG_IGN);

	/* "Open the log. Currently a NOP." */
	klogctl(1, NULL, 0);

	/* Set level of kernel console messaging.. */
	if (console_log_level)
		klogctl(8, NULL, console_log_level);

	while (1) {
		/* Use kernel syscalls */
		memset(log_buffer, '\0', sizeof(log_buffer));
		n = klogctl(2, log_buffer, sizeof(log_buffer));
		if (n < 0) {
		
			if (errno == EINTR)
				continue;
#ifdef _LOG_DEBUG_
			
			char message[80];
			snprintf(message, 79,"klogd: Error return from sys_sycall: %d - %s.\n",
															 errno,strerror(errno));
#endif /* end debug */
			exit(1);
		}
#ifdef _LOG_DEBUG_
		printf("start write log_buffer\n");
		mBug("%s\n", log_buffer);
#endif/* end debug */

		/* klogctl buffer parsing modelled after code in dmesg.c */
		start = &log_buffer[0];
		lastc = '\0';
		for (i = 0; i < n; i++) {
			if (lastc == '\0' && log_buffer[i] == '<') {
				priority = 0;
				i++;
				while (isdigit(log_buffer[i])) {
					priority = priority * 10 + (log_buffer[i] - '0');
					i++;
				}
				if (log_buffer[i] == '>')
					i++;
				start = &log_buffer[i];
			}
			if (log_buffer[i] == '\n') {
				log_buffer[i] = '\0';	/* zero terminate this message */
#ifdef _LOG_DEBUG_				
				printf("<%d>syslog_ record: priority=<%d>\n",__LINE__, priority);
#endif	
				syslog(priority, start);
				/* add for wlan diagnosticate */				
//				reason = check_wlan_info(priority,start);
//				flash_wlan_led(reason);
				
				start = &log_buffer[i + 1];
				priority = LOG_INFO;
			}
			lastc = log_buffer[i];
		}
	}
}

int klogd_main(int argc, char **argv)
//int main(int argc, char **argv)
{
	/* no options, no getopt */
	int opt;
	int doFork = TRUE;
	unsigned char console_log_level = 7; /* for debug chang 7 to 6 */

	/* do normal option parsing */
	while ((opt = getopt(argc, argv, "c:n")) > 0) {
		switch (opt) {
		case 'c':
			if ((optarg == NULL) || (optarg[1] != '\0')) {
				show_usage();
			}
			/* Valid levels are between 1 and 8 */
			console_log_level = *optarg - '1';
#ifdef _LOG_DEBUG_
	printf("__LINE__, console_log_level=<%d>\n",console_log_level);
#endif				
			if (console_log_level > 7) {
				show_usage();
			}
			console_log_level++;
			
			break;
		case 'n':
			doFork = FALSE;
#ifdef _LOG_DEBUG_
	printf("__LINE__, console_log_level=<%d>\n",console_log_level);
#endif				
			break;
		default:
			show_usage();
		}
	}

	if (doFork) {
#if !defined(__UCLIBC__) || defined(__UCLIBC_HAS_MMU__)
		if (daemon(0, 1) < 0)
			perror_msg_and_die("daemon");
#else
		error_msg_and_die("daemon not supported");
#endif
	}

	openlog( "kernel", 0 ,LOG_LOCAL0);

#ifdef _LOG_DEBUG_
	openlog( "kernel", 0 ,LOG_KERN);
	printf("__LINE__, console_log_level=<%d>\n",console_log_level);
#endif	

	doKlogd(console_log_level);

	return EXIT_SUCCESS;
}

/* 
 * check_wlan_info:
 *  input: priority --- log levele
 *  	   pWlanInfoStart ---- wlan information start
 *  output:
 *		reason---  -1, not found wlan information
 *			        >=0 wlan information reason 
 * wlan info Example:
 *	WLAN: MLME - Disconnecting (deauth) wireless client: 00c002ffa64a Reason 6
 *
 */
int check_wlan_info(const int priority, char *pWlanInfoStart)
{
	char *p;
	int reason = 0;
	char *buf = pWlanInfoStart;
	
#ifdef _LOG_DEBUG_
			printf(" catch wlan info:<%s>\n", buf);
#endif			

	if(priority == 6){
		if(!strncmp(buf, "WLAN:", 5)){
			buf +=5;
			p = strstr(buf,"Reason");
			if(p){
				p += 7;
				while(isdigit(*p)){
					reason = reason * 10 + (*p - '0');
					p++;
				}
			}	
		}	
#ifdef _LOG_DEBUG_				
				printf("wlan :reason = <%d>\n",reason);
#endif				
	}
	
	return reason;
}

/* 
 * flash_wlan_led: blink the wlan error led following the reason,
 *      input : reason
 *   15 : wpa/wpa2 passphase failed	
 *
 */
void flash_wlan_led(int reason)
{
	if(reason == 15){
//		system("/bin/echo wlanlink0 > /proc/led");
//		system("/bin/echo wlanlink3 > /proc/led");
//		system("/bin/echo wlanerr60 > /proc/led");
	}
	return ;	
}
