/* $Id: getifstats.c,v 1.1 2007-08-16 09:42:39 oliver_hao Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "getifstats.h"

int
getifstats(const char * ifname, struct ifdata * data)
{
	FILE *f;
	char line[512];
	char * p;
	int i;
	int r = -1;
	int j;
	
	j = get_wan_phy_speed();

	switch (j)
	{
		case 10:
			data->baudrate = 10000000; //10Mbps
			break;
		case 100:
			data->baudrate = 100000000; //100Mbps
			break;
		case 1000:
			data->baudrate = 1000000000; //1000Mbps
			break;
	}
	
	data->opackets = 0;
	data->ipackets = 0;
	data->obytes = 0;
	data->ibytes = 0;
	f = fopen("/proc/net/dev", "r");
	if(!f)
	{
		syslog(LOG_ERR, "cannot open /proc/net/dev : %m");
		return -1;
	}
	/* discard the two header lines */
	fgets(line, sizeof(line), f);
	fgets(line, sizeof(line), f);
	while(fgets(line, sizeof(line), f))
	{
		p = line;
		while(*p==' ') p++;
		i = 0;
		while(ifname[i] == *p)
		{
			p++; i++;
		}
		/* TODO : how to handle aliases ? */
		if(ifname[i] || *p != ':')
			continue;
		p++;
		while(*p==' ') p++;
		data->ibytes = strtoul(p, &p, 0);
		while(*p==' ') p++;
		data->ipackets = strtoul(p, &p, 0);
		/* skip 6 columns */
		for(i=6; i>0 && *p!='\0'; i--)
		{
			while(*p==' ') p++;
			while(*p!=' ' && *p) p++;
		}
		while(*p==' ') p++;
		data->obytes = strtoul(p, &p, 0);
		while(*p==' ') p++;
		data->opackets = strtoul(p, &p, 0);
		r = 0;
		break;
	}
	fclose(f);
	return r;
}

int get_wan_phy_speed(void)
 {
 	char tmpBuf[256]={0};
	FILE *fp;
	int len=0;
	char *p;
	int status = 0;
	
	fp = fopen("/proc/eth_status","r");
	if(!fp){
		printf("fopen failed\n");
		return 1;
	}
	len = fread(tmpBuf, 1, sizeof(tmpBuf)-1, fp);
	fclose(fp);
	if(len <= 0)
		return 1;
	/* in our board, wan is 4 port*/	
    p = strstr(tmpBuf, "=");
    if(!p)
    	return 1;
    
    status = *(p+1) - '0';

	switch(status){
		case 0:
			//*speed = 10;
			return 10;
			break;
		case 1:
			//*speed = 100;
			return 100;
			break;
		case 2:
			//*speed = 1000;
			return 1000;
		default:
			break;
		}

	return 0;
 }

