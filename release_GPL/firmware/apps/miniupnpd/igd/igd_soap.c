/* $Id: igd_soap.c,v 1.1 2007-08-16 09:41:18 oliver_hao Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006 Thomas Bernard 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "maco.h"
#include "upnphttp.h"
#include "upnpevent.h"
#include "upnphttp_func.h"
#include "upnpsoap.h"
#include "upnpreplyparse.h"
#include "getifaddr.h"
#include "linux/getifstats.h"
#include "igd_globalvars.h"
#include "igd_redirect.h"
#include "port.h"

static void
GetConnectionTypeInfo(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetConnectionTypeInfoResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewConnectionType>IP_Routed</NewConnectionType>"
		"<NewPossibleConnectionTypes>IP_Routed</NewPossibleConnectionTypes>"
		"</u:GetConnectionTypeInfoResponse>";
	BuildSendAndCloseSoapResp(h, resp, sizeof(resp)-1);
}

static void
GetTotalBytesSent(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetTotalBytesSentResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		"<NewTotalBytesSent>%lu</NewTotalBytesSent>"
		"</u:GetTotalBytesSentResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	r = getifstats(ext_if_name, &data);
	bodylen = snprintf(body, sizeof(body), resp, r<0?0:data.obytes);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetTotalBytesReceived(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetTotalBytesReceivedResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		"<NewTotalBytesReceived>%lu</NewTotalBytesReceived>"
		"</u:GetTotalBytesReceivedResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	r = getifstats(ext_if_name, &data);
	bodylen = snprintf(body, sizeof(body), resp, r<0?0:data.ibytes);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetTotalPacketsSent(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetTotalPacketsSentResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		"<NewTotalPacketsSent>%lu</NewTotalPacketsSent>"
		"</u:GetTotalPacketsSentResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	r = getifstats(ext_if_name, &data);
	bodylen = snprintf(body, sizeof(body), resp, r<0?0:data.opackets);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetTotalPacketsReceived(struct upnphttp * h)
{
	int r;

	static const char resp[] =
		"<u:GetTotalPacketsReceivedResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		"<NewTotalPacketsReceived>%lu</NewTotalPacketsReceived>"
		"</u:GetTotalPacketsReceivedResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	r = getifstats(ext_if_name, &data);
	bodylen = snprintf(body, sizeof(body), resp, r<0?0:data.ipackets);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetCommonLinkProperties(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetCommonLinkPropertiesResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1\">"
		/*"<NewWANAccessType>DSL</NewWANAccessType>"*/
		"<NewWANAccessType>Cable</NewWANAccessType>"
		"<NewLayer1UpstreamMaxBitRate>%lu</NewLayer1UpstreamMaxBitRate>"
		"<NewLayer1DownstreamMaxBitRate>%lu</NewLayer1DownstreamMaxBitRate>"
		"<NewPhysicalLinkStatus>Up</NewPhysicalLinkStatus>"
		"</u:GetCommonLinkPropertiesResponse>";

	char body[2048];
	int bodylen;
	struct ifdata data;

	if((downstream_bitrate == 0) || (upstream_bitrate == 0))
	{
		if(getifstats(ext_if_name, &data) >= 0)
		{
			if(downstream_bitrate == 0) downstream_bitrate = data.baudrate;
			if(upstream_bitrate == 0) upstream_bitrate = data.baudrate;
		}
	}
	bodylen = snprintf(body, sizeof(body), resp,
		upstream_bitrate, downstream_bitrate);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
RequestConnection(struct upnphttp * h)
{
	static const char resp[] =
		"<u:RequestConnectionResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"</u:RequestConnectionResponse>";
	start_wan();
	sleep(3);
	
	BuildSendAndCloseSoapResp(h, resp, sizeof(resp) - 1);
}

static void
ForceTermination(struct upnphttp * h)
{
	static const char resp[] =
		"<u:ForceTerminationResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"</u:ForceTerminationResponse>";

	char body[512];
	int bodylen;

	stop_wan();
	bodylen = snprintf(body, sizeof(body), resp);	
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetStatusInfo(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetStatusInfoResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewConnectionStatus>%s</NewConnectionStatus>"
		"<NewLastConnectionError>ERROR_NONE</NewLastConnectionError>"
		"<NewUptime>%ld</NewUptime>"
		"</u:GetStatusInfoResponse>";

	char body[512];
	int bodylen;
	char wan_status[32];
	time_t uptime;

	if(get_wan_up(ext_if_name))
		sprintf(wan_status,"Connected");
	else
		sprintf(wan_status,"Disconnected");

//	uptime = (time(NULL) - startup_time);
	uptime = get_uptime();
	bodylen = snprintf(body, sizeof(body), resp, wan_status,(long)uptime);	
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetNATRSIPStatus(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetNATRSIPStatusResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewRSIPAvailable>0</NewRSIPAvailable>"
		"<NewNATEnabled>%d</NewNATEnabled>"
		"</u:GetNATRSIPStatusResponse>";
	char body[512];
	int bodylen;
	bodylen = snprintf(body, sizeof(body), resp, nat_enable);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
GetExternalIPAddress(struct upnphttp * h)
{
	static const char resp[] =
		"<u:GetExternalIPAddressResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewExternalIPAddress>%s</NewExternalIPAddress>"
		"</u:GetExternalIPAddressResponse>";

	char body[512];
	int bodylen;
	char ext_ip_addr[INET_ADDRSTRLEN];

    if(getifaddr(ext_if_name, ext_ip_addr, INET_ADDRSTRLEN) < 0)
	{
		syslog(LOG_ERR, "Failed to get ip address for interface %s",
			ext_if_name);
		strncpy(ext_ip_addr, "0.0.0.0", INET_ADDRSTRLEN);
	}
	bodylen = snprintf(body, sizeof(body), resp, ext_ip_addr);
	BuildSendAndCloseSoapResp(h, body, bodylen);
}

static void
AddPortMapping(struct upnphttp * h)
{
	int r;
	pid_t pid;

	static const char resp[] =
		"<u:AddPortMappingResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"/>";

	struct NameValueParserData data;
	char * int_ip, * int_port, * ext_port, * protocol, * desc, *pmenable;
	unsigned short iport, eport;

	struct hostent *hp; /* getbyhostname() */
	char ** ptr; /* getbyhostname() */
	unsigned char result_ip[16]; /* inet_pton() */

	if((pid = fork()) == 0)
	{
	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	int_ip = GetValueFromNameValueList(&data, "NewInternalClient");
    pmenable = GetValueFromNameValueList(&data, "NewEnabled");
    
	if (!int_ip)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
			exit(0);
	}

	/* if ip not valid assume hostname and convert */
	if (inet_pton(AF_INET, int_ip, result_ip) <= 0) 
	{
		hp = gethostbyname(int_ip);
		if(hp && hp->h_addrtype == AF_INET) 
		{ 
			for(ptr = hp->h_addr_list; ptr && *ptr; ptr++)
		   	{
				int_ip = inet_ntoa(*((struct in_addr *) *ptr));
				/* TODO : deal with more than one ip per hostname */
					exit(0);
			}
		} 
		else 
		{
			syslog(LOG_ERR, "Failed to convert hostname '%s' to ip address", int_ip); 
			ClearNameValueList(&data);
			SoapError(h, 402, "Invalid Args");
				exit(0);
		}				
	}

	int_port = GetValueFromNameValueList(&data, "NewInternalPort");
	ext_port = GetValueFromNameValueList(&data, "NewExternalPort");
	protocol = GetValueFromNameValueList(&data, "NewProtocol");
	desc = GetValueFromNameValueList(&data, "NewPortMappingDescription");

	if (!int_port || !ext_port || !protocol)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
			exit(0);
	}

	eport = (unsigned short)atoi(ext_port);
	iport = (unsigned short)atoi(int_port);

	syslog(LOG_INFO, "AddPortMapping: external port %hu to %s:%hu protocol %s for: %s",
			eport, int_ip, iport, protocol, desc);
    
	r = upnp_redirect((unsigned short)atoi(pmenable), eport, int_ip, iport, protocol, desc);
    
	ClearNameValueList(&data);

	/* possible error codes for AddPortMapping :
	 * 402 - Invalid Args
	 * 501 - Action Failed
	 * 715 - Wildcard not permited in SrcAddr
	 * 716 - Wildcard not permited in ExtPort
	 * 718 - ConflictInMappingEntry
	 * 724 - SamePortValuesRequired */
	switch(r)
	{
	case 0:	/* success */
		BuildSendAndCloseSoapResp(h, resp, sizeof(resp)-1);
		break;
	case -2:	/* already redirected */
		SoapError(h, 718, "ConflictInMappingEntry");
		break;
	default:
		SoapError(h, 501, "ActionFailed");
	}
		exit(0);
	}
	wait(NULL);
	CloseSocket_upnphttp(h);
}

static void
GetSpecificPortMappingEntry(struct upnphttp * h)
{
	int r;
	pid_t pid;
	static const char resp[] =
		"<u:GetSpecificPortMappingEntryResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewInternalPort>%u</NewInternalPort>"
		"<NewInternalClient>%s</NewInternalClient>"
		"<NewEnabled>%u</NewEnabled>"
		"<NewPortMappingDescription>%s</NewPortMappingDescription>"
		"<NewLeaseDuration>0</NewLeaseDuration>"
		"</u:GetSpecificPortMappingEntryResponse>";

	char body[2048];
	int bodylen;
	struct NameValueParserData data;
	const char * r_host, * ext_port, * protocol;
	unsigned short eport, iport, local_pmable;
	char int_ip[32];
	char desc[64];

	if((pid = fork()) == 0)
	{	
	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	r_host = GetValueFromNameValueList(&data, "NewRemoteHost");
	ext_port = GetValueFromNameValueList(&data, "NewExternalPort");
	protocol = GetValueFromNameValueList(&data, "NewProtocol");

	if(!ext_port || !protocol)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
			exit(0);
	}

	eport = (unsigned short)atoi(ext_port);

	r = upnp_get_redirection_infos(&local_pmable, eport, protocol, &iport,
	                               int_ip, sizeof(int_ip),
	                               desc, sizeof(desc));
	if(r < 0)
	{		
		SoapError(h, 714, "NoSuchEntryInArray");
	}
	else
	{
		syslog(LOG_INFO, "GetSpecificPortMappingEntry: rhost='%s' %s %s found => %s:%u desc='%s'",
		       r_host, ext_port, protocol, int_ip, (unsigned int)iport, desc);
		bodylen = snprintf(body, sizeof(body), resp, (unsigned int)iport, int_ip, local_pmable, desc);
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}

	ClearNameValueList(&data);
		exit(0);
	}
	wait(NULL);
	CloseSocket_upnphttp(h);
}


static void
DeletePortMapping(struct upnphttp * h)
{
	int r;
	pid_t pid;
	static const char resp[] =
		"<u:DeletePortMappingResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"</u:DeletePortMappingResponse>";

	struct NameValueParserData data;
	const char * r_host, * ext_port, * protocol;
	unsigned short eport;

	if((pid = fork()) == 0)
	{
	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	r_host = GetValueFromNameValueList(&data, "NewRemoteHost");
	ext_port = GetValueFromNameValueList(&data, "NewExternalPort");
	protocol = GetValueFromNameValueList(&data, "NewProtocol");

	if(!ext_port || !protocol)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
			exit(0);
	}

	eport = (unsigned short)atoi(ext_port);

	syslog(LOG_INFO, "DeletePortMapping: external port: %hu, protocol: %s", 
		eport, protocol);
    
	r = upnp_delete_redirection(eport, protocol);

	if(r < 0)
	{	
		SoapError(h, 714, "NoSuchEntryInArray");
	}
	else
	{
		BuildSendAndCloseSoapResp(h, resp, sizeof(resp)-1);
	}

	ClearNameValueList(&data);
		exit(0);
	}
	wait(NULL);
	CloseSocket_upnphttp(h);
}

static void
GetGenericPortMappingEntry(struct upnphttp * h)
{
	int r;
	pid_t pid;	
	static const char resp[] =
		"<u:GetGenericPortMappingEntryResponse "
		"xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
		"<NewRemoteHost></NewRemoteHost>"
		"<NewExternalPort>%u</NewExternalPort>"
		"<NewProtocol>%s</NewProtocol>"
		"<NewInternalPort>%u</NewInternalPort>"
		"<NewInternalClient>%s</NewInternalClient>"
		"<NewEnabled>%u</NewEnabled>"
		"<NewPortMappingDescription>%s</NewPortMappingDescription>"
		"<NewLeaseDuration>0</NewLeaseDuration>"
		"</u:GetGenericPortMappingEntryResponse>";

	int index = 0;
	unsigned short eport, iport, local_pmable;
	const char * m_index;
	char protocol[4], iaddr[32];
	char desc[64];
	struct NameValueParserData data;

	if((pid = fork()) == 0)
	{
	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	m_index = GetValueFromNameValueList(&data, "NewPortMappingIndex");

	if(!m_index)
	{
		ClearNameValueList(&data);
		SoapError(h, 402, "Invalid Args");
			exit(0);
	}	

	index = (int)atoi(m_index);

	syslog(LOG_INFO, "GetGenericPortMappingEntry: index=%d", index);
    
	r = upnp_get_redirection_infos_by_index(&local_pmable, index, &eport, protocol, &iport,
                                            iaddr, sizeof(iaddr),
	                                        desc, sizeof(desc));
	if(r < 0)
	{
		SoapError(h, 713, "SpecifiedArrayIndexInvalid");
	}
	else
	{
		int bodylen;
		char body[2048];
		bodylen = snprintf(body, sizeof(body), resp, (unsigned int)eport,
			protocol, (unsigned int)iport, iaddr, local_pmable, desc);
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}

	ClearNameValueList(&data);
		exit(0);
	}
	wait(NULL);
	CloseSocket_upnphttp(h);
}

/*
If a control point calls QueryStateVariable on a state variable that is not
buffered in memory within (or otherwise available from) the service,
the service must return a SOAP fault with an errorCode of 404 Invalid Var.

QueryStateVariable remains useful as a limited test tool but may not be
part of some future versions of UPnP.
*/
static void
QueryStateVariable(struct upnphttp * h)
{
	static const char resp[] =
        "<u:QueryStateVariableResponse "
        "xmlns:u=\"urn:schemas-upnp-org:control-1-0\">"
		"<return>%s</return>"
        "</u:QueryStateVariableResponse>";
	pid_t pid;
	char body[2048];
	int bodylen;
	struct NameValueParserData data;
	const char * var_name;

	if((pid = fork()) == 0)
	{
	ParseNameValue(h->req_buf + h->req_contentoff, h->req_contentlen, &data);
	/*var_name = GetValueFromNameValueList(&data, "QueryStateVariable"); */
	/*var_name = GetValueFromNameValueListIgnoreNS(&data, "varName");*/
	var_name = GetValueFromNameValueList(&data, "varName");

	/*syslog(LOG_INFO, "QueryStateVariable(%.40s)", var_name); */

	if(!var_name)
	{
		SoapError(h, 402, "Invalid Args");
	}
	else if(strcmp(var_name, "ConnectionStatus") == 0)
	{	
		char wan_status[32];
		if(get_wan_up(ext_if_name))
			sprintf(wan_status,"Connected");
		else
			sprintf(wan_status,"Disconnected");
		bodylen = snprintf(body, sizeof(body), resp, wan_status);
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}

	else if(strcmp(var_name, "PortMappingNumberOfEntries") == 0)
	{
		int r = 0, index = 0;
		unsigned short eport, iport, local_pmable;
		char protocol[4], iaddr[32], desc[64];
		char strindex[10];

		do
		{
			protocol[0] = '\0'; iaddr[0] = '\0'; desc[0] = '\0';

			r = upnp_get_redirection_infos_by_index(&local_pmable, index, &eport, protocol, &iport,
													iaddr, sizeof(iaddr),
													desc, sizeof(desc));
			index++;
		}
		while(r==0);

		snprintf(strindex, sizeof(strindex), "%i", index - 1);
		bodylen = snprintf(body, sizeof(body), resp, strindex);
		BuildSendAndCloseSoapResp(h, body, bodylen);
	}
	else
	{
		syslog(LOG_NOTICE, "QueryStateVariable: Unknown: %s", var_name?var_name:"");
		SoapError(h, 404, "Invalid Var");
	}

	ClearNameValueList(&data);	
		exit(0);
	}
	wait(NULL);
	CloseSocket_upnphttp(h);
}

struct method igd_soapMethods[] =
{
	{ "GetConnectionTypeInfo", GetConnectionTypeInfo },
	{ "GetNATRSIPStatus", GetNATRSIPStatus},
	{ "GetExternalIPAddress", GetExternalIPAddress},
	{ "AddPortMapping", AddPortMapping},
	{ "DeletePortMapping", DeletePortMapping},
	{ "GetGenericPortMappingEntry", GetGenericPortMappingEntry},
	{ "GetSpecificPortMappingEntry", GetSpecificPortMappingEntry},
	{ "QueryStateVariable", QueryStateVariable},
	{ "GetTotalBytesSent", GetTotalBytesSent},
	{ "GetTotalBytesReceived", GetTotalBytesReceived},
	{ "GetTotalPacketsSent", GetTotalPacketsSent},
	{ "GetTotalPacketsReceived", GetTotalPacketsReceived},
	{ "GetCommonLinkProperties", GetCommonLinkProperties},
	{ "GetStatusInfo", GetStatusInfo},
/* Oliver Add for support ForceTermination and RequestConnection */	
	{ "ForceTermination", ForceTermination},
	{ "RequestConnection", RequestConnection},
	{ 0, 0 }
};

