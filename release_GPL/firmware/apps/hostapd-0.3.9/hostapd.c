/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver
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
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "eloop.h"
#include "hostapd.h"
#include "ieee802_1x.h"
#include "ieee802_11.h"
#include "accounting.h"
#include "eapol_sm.h"
#include "iapp.h"
#include "ap.h"
#include "ieee802_11_auth.h"
#include "sta_info.h"
#include "driver.h"
#include "radius_client.h"
#include "radius_server.h"
#include "wpa.h"
#include "ctrl_iface.h"
#include "tls.h"
#include "eap_sim_db.h"
#include "version.h"

#ifdef LINUX_WSC
#include "wsc.h"
#include "wsc_api.h"
#include <sys/shm.h>
#include <sys/ipc.h>
#endif

#ifdef JUMPSTART
#include "openssl/bn.h"
#include "openssl/dh.h"
#include "jswproto.h"
#include "jswAuth.h"
#endif /* JUMPSTART */

struct hapd_interfaces {
	int count;
	hostapd **hapd;
};

unsigned char rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };


extern int wpa_debug_level;
extern int wpa_debug_show_keys;
extern int wpa_debug_timestamp;

#ifdef LINUX_WSC
unsigned long w2hshmid=-1,h2wshmid=-1;
SHM_STRUCT *w2hshm=NULL,*h2wshm=NULL;
#endif

#ifdef JUMPSTART
static int hostapd_setup_interface(struct hostapd_data *hapd);
#endif /* JUMPSTART */

void hostapd_logger(hostapd *hapd, u8 *addr, unsigned int module, int level,
		    char *fmt, ...)
{
	char *format, *module_str;
	int maxlen;
	va_list ap;
	int conf_syslog_level, conf_stdout_level;
	unsigned int conf_syslog, conf_stdout;

	maxlen = strlen(fmt) + 100;
	format = malloc(maxlen);
	if (!format)
		return;

	va_start(ap, fmt);

	if (hapd && hapd->conf) {
		conf_syslog_level = hapd->conf->logger_syslog_level;
		conf_stdout_level = hapd->conf->logger_stdout_level;
		conf_syslog = hapd->conf->logger_syslog;
		conf_stdout = hapd->conf->logger_stdout;
	} else {
		conf_syslog_level = conf_stdout_level = 0;
		conf_syslog = conf_stdout = (unsigned int) -1;
	}

	switch (module) {
	case HOSTAPD_MODULE_IEEE80211:
		module_str = "IEEE 802.11";
		break;
	case HOSTAPD_MODULE_IEEE8021X:
		module_str = "IEEE 802.1X";
		break;
	case HOSTAPD_MODULE_RADIUS:
		module_str = "RADIUS";
		break;
	case HOSTAPD_MODULE_WPA:
		module_str = "WPA";
		break;
	case HOSTAPD_MODULE_DRIVER:
		module_str = "DRIVER";
		break;
	case HOSTAPD_MODULE_IAPP:
		module_str = "IAPP";
		break;
#ifdef JUMPSTART
	case HOSTAPD_MODULE_JS:
		module_str = "JUMPSTART";
		break;
#endif
	default:
		module_str = NULL;
		break;
	}

	if (hapd && hapd->conf && addr)
		snprintf(format, maxlen, "%s: STA " MACSTR "%s%s: %s",
			 hapd->conf->iface, MAC2STR(addr),
			 module_str ? " " : "", module_str, fmt);
	else if (hapd && hapd->conf)
		snprintf(format, maxlen, "%s:%s%s %s",
			 hapd->conf->iface, module_str ? " " : "",
			 module_str, fmt);
	else if (addr)
		snprintf(format, maxlen, "STA " MACSTR "%s%s: %s",
			 MAC2STR(addr), module_str ? " " : "",
			 module_str, fmt);
	else
		snprintf(format, maxlen, "%s%s%s",
			 module_str, module_str ? ": " : "", fmt);

	if ((conf_stdout & module) && level >= conf_stdout_level) {
		vprintf(format, ap);
		printf("\n");
	}

	if ((conf_syslog & module) && level >= conf_syslog_level) {
		int priority;
		switch (level) {
		case HOSTAPD_LEVEL_DEBUG_VERBOSE:
		case HOSTAPD_LEVEL_DEBUG:
			priority = LOG_DEBUG;
			break;
		case HOSTAPD_LEVEL_INFO:
			priority = LOG_INFO;
			break;
		case HOSTAPD_LEVEL_NOTICE:
			priority = LOG_NOTICE;
			break;
		case HOSTAPD_LEVEL_WARNING:
			priority = LOG_WARNING;
			break;
		default:
			priority = LOG_INFO;
			break;
		}
		vsyslog(priority, format, ap);
	}

	free(format);

	va_end(ap);
}


static void hostapd_deauth_all_stas(hostapd *hapd)
{
#if 0
	u8 addr[ETH_ALEN];

	memset(addr, 0xff, ETH_ALEN);
	hostapd_sta_deauth(hapd, addr, WLAN_REASON_PREV_AUTH_NOT_VALID);
#else
	/* New Prism2.5/3 STA firmware versions seem to have issues with this
	 * broadcast deauth frame. This gets the firmware in odd state where
	 * nothing works correctly, so let's skip sending this for a while
	 * until the issue has been resolved. */
#endif
}


/* This function will be called whenever a station associates with the AP */
void hostapd_new_assoc_sta(hostapd *hapd, struct sta_info *sta)
{
	if (hapd->tkip_countermeasures) {
		hostapd_sta_deauth(hapd, sta->addr,
				WLAN_REASON_MICHAEL_MIC_FAILURE);
		return;
	}

	/* IEEE 802.11F (IAPP) */
	if (hapd->conf->ieee802_11f)
		iapp_new_station(hapd->iapp, sta);

	/* Start accounting here, if IEEE 802.1X is not used. IEEE 802.1X code
	 * will start accounting after the station has been authorized. */
	if (!hapd->conf->ieee802_1x)
		accounting_sta_start(hapd, sta);

#ifdef JUMPSTART
	if (hapd->conf->js_p1) {
		/* Only one STA at a time to attempt Jumpstart */
		if (!hapd->jsw_profile->p1_in_progress) {
			hapd->jsw_profile->p1_in_progress = 1;
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, 
				      "JUMPSTART: " MACSTR 
				      " %s: starting P1\n",
				       MAC2STR(sta->addr), __func__); 
			js_p1_new_station(hapd, sta);
			/* Start the JS state machine */
			smSendEvent(sta->js_session, JSW_EVENT_ASSOC);
			
		} else {
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, 
				      "JUMPSTART: " MACSTR
				      "%s: P1 running with another STA."
				      " Disassoc\n",
				       MAC2STR(sta->addr), __func__); 
			hostapd_sta_disassoc(hapd, sta->addr, 
					     WLAN_REASON_UNSPECIFIED);
		}	
		return;
	}
#endif /* JUMPSTART */

	/* Start IEEE 802.1x authentication process for new stations */
	ieee802_1x_new_station(hapd, sta);
	wpa_new_station(hapd, sta);
}

#ifdef LINUX_WSC
void upnp_free_shm(void)
{
	if(w2hshm)
		shmdt(w2hshm);
	if(h2wshm)
		shmdt(h2wshm);
}
extern 	int netlink_skfd;
#endif
static void handle_term(int sig, void *eloop_ctx, void *signal_ctx)
{
	printf("Signal %d received - terminating\n", sig);
	eloop_terminate();
#ifdef LINUX_WSC
	if(wsc_enable())
	{		
		wsc_free_shm();
		upnp_free_shm();		
	}
	if(netlink_skfd>0)
		close(netlink_skfd);
#endif		
}


static void handle_reload(int sig, void *eloop_ctx, void *signal_ctx)
{
	struct hapd_interfaces *hapds = (struct hapd_interfaces *) eloop_ctx;
	struct hostapd_config *newconf;
	int i;

	printf("Signal %d received - reloading configuration\n", sig);

	for (i = 0; i < hapds->count; i++) {
		hostapd *hapd = hapds->hapd[i];
		newconf = hostapd_config_read(hapd->config_fname);
		if (newconf == NULL) {
			printf("Failed to read new configuration file - "
			       "continuing with old.\n");
			continue;
		}
		/* TODO: update dynamic data based on changed configuration
		 * items (e.g., open/close sockets, remove stations added to
		 * deny list, etc.) */
		radius_client_flush(hapd->radius);
		hostapd_config_free(hapd->conf);
		hapd->conf = newconf;
#ifdef JUMPSTART
		hostapd_setup_interface(hapd);
#endif /* JUMSTART */
	}
}


#ifdef HOSTAPD_DUMP_STATE
static void hostapd_dump_state(hostapd *hapd)
{
	FILE *f;
	time_t now;
	struct sta_info *sta;
	int i;
	char *buf;

	if (!hapd->conf->dump_log_name) {
		printf("Dump file not defined - ignoring dump request\n");
		return;
	}

	printf("Dumping hostapd state to '%s'\n", hapd->conf->dump_log_name);
	f = fopen(hapd->conf->dump_log_name, "w");
	if (f == NULL) {
		printf("Could not open dump file '%s' for writing.\n",
		       hapd->conf->dump_log_name);
		return;
	}

	time(&now);
	fprintf(f, "hostapd state dump - %s", ctime(&now));

	for (sta = hapd->sta_list; sta != NULL; sta = sta->next) {
		fprintf(f, "\nSTA=" MACSTR "\n", MAC2STR(sta->addr));

		fprintf(f,
			"  AID=%d flags=0x%x %s%s%s%s%s%s\n"
			"  capability=0x%x listen_interval=%d\n",
			sta->aid,
			sta->flags,
			(sta->flags & WLAN_STA_AUTH ? "[AUTH]" : ""),
			(sta->flags & WLAN_STA_ASSOC ? "[ASSOC]" : ""),
			(sta->flags & WLAN_STA_PS ? "[PS]" : ""),
			(sta->flags & WLAN_STA_TIM ? "[TIM]" : ""),
			(sta->flags & WLAN_STA_PERM ? "[PERM]" : ""),
			(sta->flags & WLAN_STA_AUTHORIZED ? "[AUTHORIZED]" :
			 ""),
			sta->capability,
			sta->listen_interval);

		fprintf(f, "  supported_rates=");
		for (i = 0; i < sizeof(sta->supported_rates); i++)
			if (sta->supported_rates[i] != 0)
				fprintf(f, "%02x ", sta->supported_rates[i]);
		fprintf(f, "%s%s%s%s\n",
			(sta->tx_supp_rates & WLAN_RATE_1M ? "[1M]" : ""),
			(sta->tx_supp_rates & WLAN_RATE_2M ? "[2M]" : ""),
			(sta->tx_supp_rates & WLAN_RATE_5M5 ? "[5.5M]" : ""),
			(sta->tx_supp_rates & WLAN_RATE_11M ? "[11M]" : ""));

		fprintf(f,
			"  timeout_next=%s\n",
			(sta->timeout_next == STA_NULLFUNC ? "NULLFUNC POLL" :
			 (sta->timeout_next == STA_DISASSOC ? "DISASSOC" :
			  "DEAUTH")));

		ieee802_1x_dump_state(f, "  ", sta);
	}

	buf = malloc(4096);
	if (buf) {
		int count = radius_client_get_mib(hapd->radius, buf, 4096);
		if (count < 0)
			count = 0;
		else if (count > 4095)
			count = 4095;
		buf[count] = '\0';
		fprintf(f, "%s", buf);

		count = radius_server_get_mib(hapd->radius_srv, buf, 4096);
		if (count < 0)
			count = 0;
		else if (count > 4095)
			count = 4095;
		buf[count] = '\0';
		fprintf(f, "%s", buf);
		free(buf);
	}
	fclose(f);
}
#endif /* HOSTAPD_DUMP_STATE */


#ifdef LINUX_WSC
/* ************************************************
 * add by pacino to process shared mem used to be in
 * communication with wscupnp which want to call the
 * function in libwsc.so
 * ************************************************/


static void handle_user_set(int sig, void *eloop_ctx, void *signal_ctx)
{
	SHM_STRUCT tmpbuf;
	unsigned char mac[6],tmpmac[6];
	char databuf[WFA_VAL_MAXLEN+512];
	int datalen;

	memcpy((void *)&tmpbuf,w2hshm,sizeof(SHM_STRUCT));

	w2hshm->type=W2H_SHM_TYPE_IDLE;

	switch(tmpbuf.type)
	{
		case W2H_SHM_TYPE_GetDeviceInfo:
						
			memcpy(mac,tmpbuf.data,6);
			memset(&tmpbuf,0,sizeof(SHM_STRUCT));
			wsc_UPNPGetDeviceInfoHandler(mac, tmpbuf.data, &(tmpbuf.len));
			
			tmpbuf.type=H2W_SHM_TYPE_GetDeviceInfoResp;
			memcpy(h2wshm,&tmpbuf,sizeof(SHM_STRUCT));

			break;
		case W2H_SHM_TYPE_PutMessage:
			memcpy(mac,tmpbuf.data,6);
			wsc_UPNPPutMessageHandler(mac, tmpbuf.data+6, tmpbuf.len-6, databuf, &datalen);

			tmpbuf.type=H2W_SHM_TYPE_PutMessageResp;
			tmpbuf.len=datalen;
			
			memcpy(tmpbuf.data,databuf,datalen);
			memcpy(h2wshm,&tmpbuf,sizeof(SHM_STRUCT));
			
			break;
		case W2H_SHM_TYPE_PutWLANResponse:

			memcpy(mac,tmpbuf.data,6);
			memcpy(tmpmac,tmpbuf.data+6,6);
			wsc_UPNPWLANResponseeHandler(mac, tmpmac, tmpbuf.data+12, tmpbuf.len-12);		

			break;
				
		case W2H_SHM_TYPE_SetSelectedRegistrar:

			memcpy(mac,tmpbuf.data,6);
			
			wsc_setSelectedRegistrarHandler(mac, tmpbuf.data+6, tmpbuf.len-6);

			break;
			
	}

}
#endif
static void handle_dump_state(int sig, void *eloop_ctx, void *signal_ctx)
{
#ifdef HOSTAPD_DUMP_STATE
	struct hapd_interfaces *hapds = (struct hapd_interfaces *) eloop_ctx;
	int i;

	for (i = 0; i < hapds->count; i++) {
		hostapd *hapd = hapds->hapd[i];
		hostapd_dump_state(hapd);
	}
#endif /* HOSTAPD_DUMP_STATE */
}


static void hostapd_cleanup(struct hostapd_data *hapd)
{
	hostapd_ctrl_iface_deinit(hapd);

	free(hapd->default_wep_key);
	hapd->default_wep_key = NULL;
	iapp_deinit(hapd->iapp);
	accounting_deinit(hapd);
	wpa_deinit(hapd);
	ieee802_1x_deinit(hapd);
	hostapd_acl_deinit(hapd);
#ifdef JUMPSTART
	jsw_deinit(hapd);
#endif /* JUMPSTART */
	radius_client_deinit(hapd->radius);
	hapd->radius = NULL;
	radius_server_deinit(hapd->radius_srv);
	hapd->radius_srv = NULL;

	hostapd_wireless_event_deinit(hapd);

	if (hapd->driver)
		hostapd_driver_deinit(hapd);

	hostapd_config_free(hapd->conf);
	hapd->conf = NULL;

	free(hapd->config_fname);

#ifdef EAP_TLS_FUNCS
	if (hapd->ssl_ctx) {
		tls_deinit(hapd->ssl_ctx);
		hapd->ssl_ctx = NULL;
	}
#endif /* EAP_TLS_FUNCS */

	if (hapd->eap_sim_db_priv)
		eap_sim_db_deinit(hapd->eap_sim_db_priv);
}


static int hostapd_flush_old_stations(hostapd *hapd)
{
	int ret = 0;

	printf("Flushing old station entries\n");
	if (hostapd_flush(hapd)) {
		printf("Could not connect to kernel driver.\n");
		ret = -1;
	}
	printf("Deauthenticate all stations\n");
	hostapd_deauth_all_stas(hapd);

	return ret;
}


static int hostapd_setup_interface(struct hostapd_data *hapd)
{
	struct hostapd_config *conf = hapd->conf;
	u8 ssid[HOSTAPD_SSID_LEN + 1];
	int ssid_len, set_ssid;
	int ret = 0;

	if (hostapd_driver_init(hapd)) {
		printf("%s driver initialization failed.\n",
			hapd->driver ? hapd->driver->name : "Unknown");
		hapd->driver = NULL;
		return -1;
	}
#ifdef JUMPSTART
	/* Create SSID */
	if (hapd->conf->js_p1) {
		js_create_ssid(hapd, JSW_P1_DEF_SSID_PREF);
		set_ssid = 1;
		goto set_js_ssid;
	}
	if (hapd->conf->js_p2) {
		js_create_ssid(hapd, JSW_P2_DEF_SSID_PREF);
		set_ssid = 1;
		goto set_js_ssid;
	}
#endif /* JUMPSTART */	

	/*
	 * Fetch the SSID from the system and use it or,
	 * if one was specified in the config file, verify they
	 * match.
	 */
	ssid_len = hostapd_get_ssid(hapd, ssid, sizeof(ssid));
	if (ssid_len < 0) {
		printf("Could not read SSID from system\n");
		return -1;
	}
	if (conf->ssid_set) {
		/*
		 * If SSID is specified in the config file and it differs
		 * from what is being used then force installation of the
		 * new SSID.
		 */
		set_ssid = (conf->ssid_len != ssid_len ||
			    memcmp(conf->ssid, ssid, ssid_len) != 0);
	} else {
		/*
		 * No SSID in the config file; just use the one we got
		 * from the system.
		 */
		set_ssid = 0;
		conf->ssid_len = ssid_len;
		memcpy(conf->ssid, ssid, conf->ssid_len);
		conf->ssid[conf->ssid_len] = '\0';
	}
#ifdef JUMPSTART
set_js_ssid:
#endif /* JUMPSTART */
	printf("Using interface %s with hwaddr " MACSTR " and ssid '%s'\n",
	       hapd->conf->iface, MAC2STR(hapd->own_addr), hapd->conf->ssid);

	if (hostapd_setup_wpa_psk(conf)) {
		printf("WPA-PSK setup failed.\n");
		return -1;
	}

	/* Set SSID for the kernel driver (to be used in beacon and probe
	 * response frames) */
	if (set_ssid && hostapd_set_ssid(hapd, (u8 *) conf->ssid,
					 conf->ssid_len)) {
		printf("Could not set SSID for kernel driver\n");
		return -1;
	}

	hapd->radius = radius_client_init(hapd);
	if (hapd->radius == NULL) {
		printf("RADIUS client initialization failed.\n");
		return -1;
	}
	if (conf->radius_server_clients) {
		struct radius_server_conf srv;
		memset(&srv, 0, sizeof(srv));
		srv.client_file = conf->radius_server_clients;
		srv.auth_port = conf->radius_server_auth_port;
		srv.hostapd_conf = conf;
		srv.eap_sim_db_priv = hapd->eap_sim_db_priv;
		srv.ssl_ctx = hapd->ssl_ctx;
		hapd->radius_srv = radius_server_init(&srv);
		if (hapd->radius_srv == NULL) {
			printf("RADIUS server initialization failed.\n");
			return -1;
		}
	}
	if (hostapd_acl_init(hapd)) {
		printf("ACL initialization failed.\n");
		return -1;
	}
	if (ieee802_1x_init(hapd)) {
		printf("IEEE 802.1X initialization failed.\n");
		return -1;
	}

	if (hapd->conf->wpa && wpa_init(hapd)) {
		printf("WPA initialization failed.\n");
		return -1;
	}

	if (accounting_init(hapd)) {
		printf("Accounting initialization failed.\n");
		return -1;
	}

	if (hapd->conf->ieee802_11f &&
	    (hapd->iapp = iapp_init(hapd, hapd->conf->iapp_iface)) == NULL) {
		printf("IEEE 802.11F (IAPP) initialization failed.\n");
		return -1;
	}

	if (hostapd_wireless_event_init(hapd) < 0)
		return -1;

	if (hostapd_flush_old_stations(hapd))
		return -1;

	if (hostapd_ctrl_iface_init(hapd)) {
		printf("Failed to setup control interface\n");
		ret = -1;
	}

#ifdef JUMPSTART
	if ((hapd->conf->js_p1 || hapd->conf->js_p2) && jsw_init(hapd)) {
		printf("Jumpstart initilization failed\n");
		return -1;
	}
#endif
	return ret;
}


struct driver {
	struct driver *next;
	char *name;
	const struct driver_ops *ops;
};
static struct driver *drivers = NULL;

void driver_register(const char *name, const struct driver_ops *ops)
{
	struct driver *d;

	d = malloc(sizeof(struct driver));
	if (d == NULL) {
		printf("Failed to register driver %s!\n", name);
		return;
	}
	d->name = strdup(name);
	if (d->name == NULL) {
		printf("Failed to register driver %s!\n", name);
		free(d);
		return;
	}
	d->ops = ops;

	d->next = drivers;
	drivers = d;
}


void driver_unregister(const char *name)
{
	struct driver *p, **pp;

	for (pp = &drivers; (p = *pp) != NULL; pp = &p->next) {
		if (strcasecmp(p->name, name) == 0) {
			*pp = p->next;
			p->next = NULL;
			free(p->name);
			free(p);
			break;
		}
	}
}


static void driver_unregister_all(void)
{
	struct driver *p, *pp;
	p = drivers;
	drivers = NULL;
	while (p) {
		pp = p;
		p = p->next;
		free(pp->name);
		free(pp);
	}
}


const struct driver_ops * driver_lookup(const char *name)
{
	struct driver *p;

	if (strcmp(name, "default") == 0) {
		p = drivers;
		while (p && p->next)
			p = p->next;
		return p->ops;
	}

	for (p = drivers; p != NULL; p = p->next) {
		if (strcasecmp(p->name, name) == 0)
			return p->ops;
	}

	return NULL;
}


static void show_version(void)
{
	fprintf(stderr,
		"hostapd v" VERSION_STR "\n"
		"Host AP user space daemon for management functionality of "
		"Host AP kernel driver\n"
		"Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi> "
		"and contributors\n");
}


static void usage(void)
{
	show_version();
	fprintf(stderr,
		"\n"
		"usage: hostapd [-hdB] <configuration file(s)>\n"
		"\n"
		"options:\n"
		"   -h   show this usage\n"
		"   -d   show more debug messages (-dd for even more)\n"
		"   -B   run daemon in the background\n"
		"   -K   include key data in debug messages\n"
		"   -t   include timestamps in some debug messages\n"
		"   -v   show hostapd version\n");

	exit(1);
}


static hostapd * hostapd_init(const char *config_file)
{
	hostapd *hapd;

	hapd = malloc(sizeof(*hapd));
	if (hapd == NULL) {
		printf("Could not allocate memory for hostapd data\n");
		goto fail;
	}
	memset(hapd, 0, sizeof(*hapd));

#ifdef JUMPSTART
	hapd->config_fname = rel2abs_path(config_file);
#else
	hapd->config_fname = strdup(config_file);
#endif
	if (hapd->config_fname == NULL) {
		printf("Could not allocate memory for config_fname\n");
		goto fail;
	}
	
	hapd->conf = hostapd_config_read(hapd->config_fname);
	if (hapd->conf == NULL) {
		goto fail;
	}

	if (hapd->conf->individual_wep_key_len > 0) {
		/* use key0 in individual key and key1 in broadcast key */
		hapd->default_wep_key_idx = 1;
	}

#ifdef EAP_TLS_FUNCS
	if (hapd->conf->eap_authenticator &&
	    (hapd->conf->ca_cert || hapd->conf->server_cert)) {
		hapd->ssl_ctx = tls_init();
		if (hapd->ssl_ctx == NULL) {
			printf("Failed to initialize TLS\n");
			goto fail;
		}
		if (tls_global_ca_cert(hapd->ssl_ctx, hapd->conf->ca_cert)) {
			printf("Failed to load CA certificate (%s)\n",
				hapd->conf->ca_cert);
			goto fail;
		}
		if (tls_global_client_cert(hapd->ssl_ctx,
					   hapd->conf->server_cert)) {
			printf("Failed to load server certificate (%s)\n",
				hapd->conf->server_cert);
			goto fail;
		}
		if (tls_global_private_key(hapd->ssl_ctx,
					   hapd->conf->private_key,
					   hapd->conf->private_key_passwd)) {
			printf("Failed to load private key (%s)\n",
			       hapd->conf->private_key);
		}
	}
#endif /* EAP_TLS_FUNCS */

	if (hapd->conf->eap_sim_db) {
		hapd->eap_sim_db_priv =
			eap_sim_db_init(hapd->conf->eap_sim_db);
		if (hapd->eap_sim_db_priv == NULL) {
			printf("Failed to initialize EAP-SIM database "
			       "interface\n");
			goto fail;
		}
	}

	if (hapd->conf->assoc_ap)
		hapd->assoc_ap_state = WAIT_BEACON;

	/* FIX: need to fix this const vs. not */
	hapd->driver = (struct driver_ops *) hapd->conf->driver;

	return hapd;

fail:
	if (hapd) {
		if (hapd->ssl_ctx)
			tls_deinit(hapd->ssl_ctx);
		if (hapd->conf)
			hostapd_config_free(hapd->conf);
		free(hapd->config_fname);
		free(hapd);
	}
	return NULL;
}


void register_drivers(void);

#ifdef LINUX_WSC
struct hapd_interfaces interfaces;

/* for f/w to send eapol packet */
int wsc_send_eapol(u8 *addr, u8 *data, size_t data_len, int encrypt)
{
	int ret = 0;
	ret = hostapd_send_eapol(interfaces.hapd[0], addr, data, data_len, encrypt);
	
	return ret;
}

#endif



int main(int argc, char *argv[])
{
#ifndef LINUX_WSC
	struct hapd_interfaces interfaces;
#endif	
	int ret = 1, i, j;
	int c, debug = 0, daemonize = 0;

	for (;;) {
		c = getopt(argc, argv, "BdhKtv");
		if (c < 0)
			break;
		switch (c) {
		case 'h':
			usage();
			break;
		case 'd':
			debug++;
			break;
		case 'B':
			daemonize++;
			break;
		case 'K':
			wpa_debug_show_keys++;
			break;
		case 't':
			wpa_debug_timestamp++;
			break;
		case 'v':
			show_version();
			exit(1);
			break;

		default:
			usage();
			break;
		}
	}

	if (optind == argc)
		usage();

	register_drivers();		/* NB: generated by Makefile */

	interfaces.count = argc - optind;

	interfaces.hapd = malloc(interfaces.count * sizeof(hostapd *));
	if (interfaces.hapd == NULL) {
		printf("malloc failed\n");
		exit(1);
	}

	eloop_init(&interfaces);
	eloop_register_signal(SIGHUP, handle_reload, NULL);
	eloop_register_signal(SIGINT, handle_term, NULL);
	eloop_register_signal(SIGTERM, handle_term, NULL);
	eloop_register_signal(SIGUSR1, handle_dump_state, NULL);
#ifdef LINUX_WSC
    wsc_debug(PRE, "start hostapd\n");
	eloop_register_signal(SIGUSR2, handle_user_set, NULL);
	if(wsc_enable())
	{		
	wsc_init();
		/* create share memory */
	w2hshmid=shmget(W2H_SHM_KEY,sizeof(SHM_STRUCT),IPC_CREAT);
    	if(w2hshmid == -1)
    	{
    	    perror("hostapd: shmget error\n");
    	    exit(1);
        }
	h2wshmid=shmget(H2W_SHM_KEY,sizeof(SHM_STRUCT),IPC_CREAT);
    	if( h2wshmid == -1)
        {
            perror("hostapd: shmget error\n");
    		exit(1);
    	}
	w2hshm=(SHM_STRUCT *)shmat(w2hshmid,NULL,0);
    	if( w2hshm == NULL)
        {
            perror("hostapd: shmget error\n");
            exit(1); 
        }
	h2wshm=(SHM_STRUCT *)shmat(h2wshmid,NULL,0);
    	if(h2wshm == NULL)
    	{
    	    perror("hostapd: shmget error\n");
    		exit(1); 
        }
	w2hshm->type = W2H_SHM_TYPE_IDLE;
	h2wshm->type = H2W_SHM_TYPE_IDLE;
		
	}
#endif	
	for (i = 0; i < interfaces.count; i++) {
		printf("Configuration file: %s\n", argv[optind + i]);
		interfaces.hapd[i] = hostapd_init(argv[optind + i]);
		if (!interfaces.hapd[i])
			goto out;
		for (j = 0; j < debug; j++) {
			if (interfaces.hapd[i]->conf->logger_stdout_level > 0)
				interfaces.hapd[i]->conf->
					logger_stdout_level--;
			interfaces.hapd[i]->conf->debug++;
		}
		if (hostapd_setup_interface(interfaces.hapd[i]))
			goto out;
		wpa_debug_level -= interfaces.hapd[0]->conf->debug;
	}
#ifndef LINUX_WSC
	if (daemonize && daemon(0, 0)) {
		perror("daemon");
		goto out;
	}
#endif
	openlog("hostapd", 0, LOG_DAEMON);
#ifdef LINUX_WSC
	/*  *****************************************
	 *  add by pacino: if the wireless security mode 
	 *  is not "wep", we must make the ath0 up after 
	 *  init wsc config action
	 *  Note: Please see rc code for wlan
	 *  *****************************************/
	system("/sbin/ifconfig ath0 up");	
#endif	
	eloop_run();

	for (i = 0; i < interfaces.count; i++) {
		hostapd_free_stas(interfaces.hapd[i]);
		hostapd_flush_old_stations(interfaces.hapd[i]);
	}

	ret = 0;

 out:
	for (i = 0; i < interfaces.count; i++) {
		if (!interfaces.hapd[i])
			continue;

		hostapd_cleanup(interfaces.hapd[i]);
		free(interfaces.hapd[i]);
	}
	free(interfaces.hapd);

	eloop_destroy();

	closelog();

	driver_unregister_all();
#ifdef LINUX_WSC
	if(wsc_enable())
	{
		wsc_free_shm();
		upnp_free_shm();
		if(netlink_skfd>0)
			close(netlink_skfd);

	}
#endif	
	return ret;
}
