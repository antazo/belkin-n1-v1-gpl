/* $Id: upnphttp.h,v 1.1 2007-08-16 09:40:26 oliver_hao Exp $ */ 
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef __UPNPHTTP_H__
#define __UPNPHTTP_H__

#include <sys/queue.h>

/*
 states :
  0 - waiting for data to read
  1 - waiting for HTTP Post Content.
  ...
  >= 100 - to be deleted
*/

enum httpCommands {
	EUnknown = 0,
	EGet,
	EPost
};

struct upnphttp {
	int socket;
	int state;
	char HttpVer[16];
	/* request */
	char * req_buf;
	int req_buflen;
	int req_contentlen;
	int req_contentoff;     /* header length */
	enum httpCommands req_command;
	char * req_soapAction;
	int req_soapActionLen;
	/* response */
	char * res_buf;
	int res_buflen;
	int res_buf_alloclen;
	/*int res_contentlen;*/
	/*int res_contentoff;*/		/* header length */
	LIST_ENTRY(upnphttp) entries;
};

#endif

