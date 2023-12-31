/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / RADIUS client
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
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "hostapd.h"
#include "radius.h"
#include "radius_client.h"
#include "eloop.h"

/* Defaults for RADIUS retransmit values (exponential backoff) */
#define RADIUS_CLIENT_FIRST_WAIT 3 /* seconds */
#define RADIUS_CLIENT_MAX_WAIT 120 /* seconds */
#define RADIUS_CLIENT_MAX_RETRIES 10 /* maximum number of retransmit attempts
				      * before entry is removed from retransmit
				      * list */
#define RADIUS_CLIENT_MAX_ENTRIES 30 /* maximum number of entries in retransmit
				      * list (oldest will be removed, if this
				      * limit is exceeded) */
#define RADIUS_CLIENT_NUM_FAILOVER 4 /* try to change RADIUS server after this
				      * many failed retry attempts */


struct radius_rx_handler {
	RadiusRxResult (*handler)(struct radius_msg *msg,
				  struct radius_msg *req,
				  u8 *shared_secret, size_t shared_secret_len,
				  void *data);
	void *data;
};


/* RADIUS message retransmit list */
struct radius_msg_list {
	u8 addr[ETH_ALEN]; /* STA/client address; used to find RADIUS messages
			    * for the same STA. */
	struct radius_msg *msg;
	RadiusType msg_type;
	time_t first_try;
	time_t next_try;
	int attempts;
	int next_wait;
	struct timeval last_attempt;

	u8 *shared_secret;
	size_t shared_secret_len;

	/* TODO: server config with failover to backup server(s) */

	struct radius_msg_list *next;
};


struct radius_client_data {
	struct hostapd_data *hapd;

	int auth_serv_sock; /* socket for authentication RADIUS messages */
	int acct_serv_sock; /* socket for accounting RADIUS messages */

	struct radius_rx_handler *auth_handlers;
	size_t num_auth_handlers;
	struct radius_rx_handler *acct_handlers;
	size_t num_acct_handlers;

	struct radius_msg_list *msgs;
	size_t num_msgs;

	u8 next_radius_identifier;
};


static int
radius_change_server(struct radius_client_data *radius,
		     struct hostapd_radius_server *nserv,
		     struct hostapd_radius_server *oserv,
		     int sock, int auth);
static int radius_client_init_acct(struct radius_client_data *radius);
static int radius_client_init_auth(struct radius_client_data *radius);


static void radius_client_msg_free(struct radius_msg_list *req)
{
	radius_msg_free(req->msg);
	free(req->msg);
	free(req);
}


int radius_client_register(struct radius_client_data *radius,
			   RadiusType msg_type,
			   RadiusRxResult (*handler)(struct radius_msg *msg,
						     struct radius_msg *req,
						     u8 *shared_secret,
						     size_t shared_secret_len,
						     void *data),
			   void *data)
{
	struct radius_rx_handler **handlers, *newh;
	size_t *num;

	if (msg_type == RADIUS_ACCT) {
		handlers = &radius->acct_handlers;
		num = &radius->num_acct_handlers;
	} else {
		handlers = &radius->auth_handlers;
		num = &radius->num_auth_handlers;
	}

	newh = (struct radius_rx_handler *)
		realloc(*handlers,
			(*num + 1) * sizeof(struct radius_rx_handler));
	if (newh == NULL)
		return -1;

	newh[*num].handler = handler;
	newh[*num].data = data;
	(*num)++;
	*handlers = newh;

	return 0;
}


static void radius_client_handle_send_error(struct radius_client_data *radius,
					    int s, RadiusType msg_type)
{
	struct hostapd_data *hapd = radius->hapd;
	int _errno = errno;
	perror("send[RADIUS]");
	if (_errno == ENOTCONN || _errno == EDESTADDRREQ || _errno == EINVAL) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_INFO,
			       "Send failed - maybe interface status changed -"
			       " try to connect again");
		eloop_unregister_read_sock(s);
		close(s);
		if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM)
			radius_client_init_acct(radius);
		else
			radius_client_init_auth(radius);
	}
}


static int radius_client_retransmit(struct radius_client_data *radius,
				    struct radius_msg_list *entry, time_t now)
{
	struct hostapd_data *hapd = radius->hapd;
	int s;

	if (entry->msg_type == RADIUS_ACCT ||
	    entry->msg_type == RADIUS_ACCT_INTERIM) {
		s = radius->acct_serv_sock;
		if (entry->attempts == 0)
			hapd->conf->acct_server->requests++;
		else {
			hapd->conf->acct_server->timeouts++;
			hapd->conf->acct_server->retransmissions++;
		}
	} else {
		s = radius->auth_serv_sock;
		if (entry->attempts == 0)
			hapd->conf->auth_server->requests++;
		else {
			hapd->conf->auth_server->timeouts++;
			hapd->conf->auth_server->retransmissions++;
		}
	}

	/* retransmit; remove entry if too many attempts */
	entry->attempts++;
	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "Resending RADIUS message (id=%d)"
		      "\n", entry->msg->hdr->identifier);

	gettimeofday(&entry->last_attempt, NULL);
	if (send(s, entry->msg->buf, entry->msg->buf_used, 0) < 0)
		radius_client_handle_send_error(radius, s, entry->msg_type);

	entry->next_try = now + entry->next_wait;
	entry->next_wait *= 2;
	if (entry->next_wait > RADIUS_CLIENT_MAX_WAIT)
		entry->next_wait = RADIUS_CLIENT_MAX_WAIT;
	if (entry->attempts >= RADIUS_CLIENT_MAX_RETRIES) {
		printf("Removing un-ACKed RADIUS message due to too many "
		       "failed retransmit attempts\n");
		return 1;
	}

	return 0;
}


static void radius_client_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct radius_client_data *radius = eloop_ctx;
	struct hostapd_data *hapd = radius->hapd;
	time_t now, first;
	struct radius_msg_list *entry, *prev, *tmp;
	int auth_failover = 0, acct_failover = 0;

	entry = radius->msgs;
	if (!entry)
		return;

	time(&now);
	first = 0;

	prev = NULL;
	while (entry) {
		if (now >= entry->next_try &&
		    radius_client_retransmit(radius, entry, now)) {
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;

			tmp = entry;
			entry = entry->next;
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			continue;
		}

		if (entry->attempts > RADIUS_CLIENT_NUM_FAILOVER) {
			if (entry->msg_type == RADIUS_ACCT ||
			    entry->msg_type == RADIUS_ACCT_INTERIM)
				acct_failover++;
			else
				auth_failover++;
		}

		if (first == 0 || entry->next_try < first)
			first = entry->next_try;

		prev = entry;
		entry = entry->next;
	}

	if (radius->msgs) {
		if (first < now)
			first = now;
		eloop_register_timeout(first - now, 0,
				       radius_client_timer, radius, NULL);
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "Next RADIUS client "
			      "retransmit in %ld seconds\n",
			      (long int) (first - now));

	}

	if (auth_failover && hapd->conf->num_auth_servers > 1) {
		struct hostapd_radius_server *next, *old;
		old = hapd->conf->auth_server;
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_NOTICE,
			       "No response from Authentication server "
			       "%s:%d - failover",
			       inet_ntoa(old->addr), old->port);

		for (entry = radius->msgs; entry; entry = entry->next) {
			if (entry->msg_type == RADIUS_AUTH)
				old->timeouts++;
		}

		next = old + 1;
		if (next > &(hapd->conf->auth_servers
			     [hapd->conf->num_auth_servers - 1]))
			next = hapd->conf->auth_servers;
		hapd->conf->auth_server = next;
		radius_change_server(radius, next, old,
				     radius->auth_serv_sock, 1);
	}

	if (acct_failover && hapd->conf->num_acct_servers > 1) {
		struct hostapd_radius_server *next, *old;
		old = hapd->conf->acct_server;
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_NOTICE,
			       "No response from Accounting server "
			       "%s:%d - failover",
			       inet_ntoa(old->addr), old->port);

		for (entry = radius->msgs; entry; entry = entry->next) {
			if (entry->msg_type == RADIUS_ACCT ||
			    entry->msg_type == RADIUS_ACCT_INTERIM)
				old->timeouts++;
		}

		next = old + 1;
		if (next > &hapd->conf->acct_servers
		    [hapd->conf->num_acct_servers - 1])
			next = hapd->conf->acct_servers;
		hapd->conf->acct_server = next;
		radius_change_server(radius, next, old,
				     radius->acct_serv_sock, 0);
	}
}


static void radius_client_update_timeout(struct radius_client_data *radius)
{
	struct hostapd_data *hapd = radius->hapd;
	time_t now, first;
	struct radius_msg_list *entry;

	eloop_cancel_timeout(radius_client_timer, radius, NULL);

	if (radius->msgs == NULL) {
		return;
	}

	first = 0;
	for (entry = radius->msgs; entry; entry = entry->next) {
		if (first == 0 || entry->next_try < first)
			first = entry->next_try;
	}

	time(&now);
	if (first < now)
		first = now;
	eloop_register_timeout(first - now, 0, radius_client_timer, radius,
			       NULL);
	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "Next RADIUS client retransmit in"
		      " %ld seconds\n", (long int) (first - now));
}


static void radius_client_list_add(struct radius_client_data *radius,
				   struct radius_msg *msg,
				   RadiusType msg_type, u8 *shared_secret,
				   size_t shared_secret_len, u8 *addr)
{
	struct radius_msg_list *entry, *prev;

	if (eloop_terminated()) {
		/* No point in adding entries to retransmit queue since event
		 * loop has already been terminated. */
		radius_msg_free(msg);
		free(msg);
		return;
	}

	entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		printf("Failed to add RADIUS packet into retransmit list\n");
		radius_msg_free(msg);
		free(msg);
		return;
	}

	memset(entry, 0, sizeof(*entry));
	if (addr)
		memcpy(entry->addr, addr, ETH_ALEN);
	entry->msg = msg;
	entry->msg_type = msg_type;
	entry->shared_secret = shared_secret;
	entry->shared_secret_len = shared_secret_len;
	time(&entry->first_try);
	entry->next_try = entry->first_try + RADIUS_CLIENT_FIRST_WAIT;
	entry->attempts = 1;
	gettimeofday(&entry->last_attempt, NULL);
	entry->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;
	entry->next = radius->msgs;
	radius->msgs = entry;
	radius_client_update_timeout(radius);

	if (radius->num_msgs >= RADIUS_CLIENT_MAX_ENTRIES) {
		printf("Removing the oldest un-ACKed RADIUS packet due to "
		       "retransmit list limits.\n");
		prev = NULL;
		while (entry->next) {
			prev = entry;
			entry = entry->next;
		}
		if (prev) {
			prev->next = NULL;
			radius_client_msg_free(entry);
		}
	} else
		radius->num_msgs++;
}


static void radius_client_list_del(struct radius_client_data *radius,
				   RadiusType msg_type, u8 *addr)
{
	struct hostapd_data *hapd = radius->hapd;
	struct radius_msg_list *entry, *prev, *tmp;

	if (addr == NULL)
		return;

	entry = radius->msgs;
	prev = NULL;
	while (entry) {
		if (entry->msg_type == msg_type &&
		    memcmp(entry->addr, addr, ETH_ALEN) == 0) {
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;
			tmp = entry;
			entry = entry->next;
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
				      "Removing matching RADIUS message for "
				      MACSTR "\n", MAC2STR(addr));
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			continue;
		}
		prev = entry;
		entry = entry->next;
	}
}


int radius_client_send(struct radius_client_data *radius,
		       struct radius_msg *msg, RadiusType msg_type, u8 *addr)
{
	struct hostapd_data *hapd = radius->hapd;
	u8 *shared_secret;
	size_t shared_secret_len;
	char *name;
	int s, res;

	if (msg_type == RADIUS_ACCT_INTERIM) {
		/* Remove any pending interim acct update for the same STA. */
		radius_client_list_del(radius, msg_type, addr);
	}

	if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM) {
		shared_secret = hapd->conf->acct_server->shared_secret;
		shared_secret_len = hapd->conf->acct_server->shared_secret_len;
		radius_msg_finish_acct(msg, shared_secret, shared_secret_len);
		name = "accounting";
		s = radius->acct_serv_sock;
		hapd->conf->acct_server->requests++;
	} else {
		shared_secret = hapd->conf->auth_server->shared_secret;
		shared_secret_len = hapd->conf->auth_server->shared_secret_len;
		radius_msg_finish(msg, shared_secret, shared_secret_len);
		name = "authentication";
		s = radius->auth_serv_sock;
		hapd->conf->auth_server->requests++;
	}

	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "Sending RADIUS message to %s server\n", name);
	if (HOSTAPD_DEBUG_COND(HOSTAPD_DEBUG_MSGDUMPS))
		radius_msg_dump(msg);

	res = send(s, msg->buf, msg->buf_used, 0);
	if (res < 0)
		radius_client_handle_send_error(radius, s, msg_type);

	radius_client_list_add(radius, msg, msg_type, shared_secret,
			       shared_secret_len, addr);

	return res;
}


static void radius_client_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct radius_client_data *radius = eloop_ctx;
	struct hostapd_data *hapd = radius->hapd;
	RadiusType msg_type = (RadiusType) sock_ctx;
	int len, i, roundtrip;
	unsigned char buf[3000];
	struct radius_msg *msg;
	struct radius_rx_handler *handlers;
	size_t num_handlers;
	struct radius_msg_list *req, *prev_req;
	struct timeval tv;
	struct hostapd_radius_server *rconf;
	int invalid_authenticator = 0;

	if (msg_type == RADIUS_ACCT) {
		handlers = radius->acct_handlers;
		num_handlers = radius->num_acct_handlers;
		rconf = hapd->conf->acct_server;
	} else {
		handlers = radius->auth_handlers;
		num_handlers = radius->num_auth_handlers;
		rconf = hapd->conf->auth_server;
	}

	len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
	if (len < 0) {
		perror("recv[RADIUS]");
		return;
	}
	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "Received %d bytes from RADIUS server\n", len);
	if (len == sizeof(buf)) {
		printf("Possibly too long UDP frame for our buffer - "
		       "dropping it\n");
		return;
	}

	msg = radius_msg_parse(buf, len);
	if (msg == NULL) {
		printf("Parsing incoming RADIUS frame failed\n");
		rconf->malformed_responses++;
		return;
	}

	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "Received RADIUS message\n");
	if (HOSTAPD_DEBUG_COND(HOSTAPD_DEBUG_MSGDUMPS))
		radius_msg_dump(msg);

	switch (msg->hdr->code) {
	case RADIUS_CODE_ACCESS_ACCEPT:
		rconf->access_accepts++;
		break;
	case RADIUS_CODE_ACCESS_REJECT:
		rconf->access_rejects++;
		break;
	case RADIUS_CODE_ACCESS_CHALLENGE:
		rconf->access_challenges++;
		break;
	case RADIUS_CODE_ACCOUNTING_RESPONSE:
		rconf->responses++;
		break;
	}

	prev_req = NULL;
	req = radius->msgs;
	while (req) {
		/* TODO: also match by src addr:port of the packet when using
		 * alternative RADIUS servers (?) */
		if ((req->msg_type == msg_type ||
		     (req->msg_type == RADIUS_ACCT_INTERIM &&
		      msg_type == RADIUS_ACCT)) &&
		    req->msg->hdr->identifier == msg->hdr->identifier)
			break;

		prev_req = req;
		req = req->next;
	}

	if (req == NULL) {
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
			      "No matching RADIUS request found (type=%d "
			      "id=%d) - dropping packet\n",
			      msg_type, msg->hdr->identifier);
		goto fail;
	}

	gettimeofday(&tv, NULL);
	roundtrip = (tv.tv_sec - req->last_attempt.tv_sec) * 100 +
		(tv.tv_usec - req->last_attempt.tv_usec) / 10000;
	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "Received RADIUS packet matched "
		      "with a pending request, round trip time %d.%02d sec\n",
		      roundtrip / 100, roundtrip % 100);
	rconf->round_trip_time = roundtrip;

	/* Remove ACKed RADIUS packet from retransmit list */
	if (prev_req)
		prev_req->next = req->next;
	else
		radius->msgs = req->next;
	radius->num_msgs--;

	for (i = 0; i < num_handlers; i++) {
		RadiusRxResult res;
		res = handlers[i].handler(msg, req->msg, req->shared_secret,
					  req->shared_secret_len,
					  handlers[i].data);
		switch (res) {
		case RADIUS_RX_PROCESSED:
			radius_msg_free(msg);
			free(msg);
			/* continue */
		case RADIUS_RX_QUEUED:
			radius_client_msg_free(req);
			return;
		case RADIUS_RX_INVALID_AUTHENTICATOR:
			invalid_authenticator++;
			/* continue */
		case RADIUS_RX_UNKNOWN:
			/* continue with next handler */
			break;
		}
	}

	if (invalid_authenticator)
		rconf->bad_authenticators++;
	else
		rconf->unknown_types++;
	hostapd_logger(hapd, req->addr, HOSTAPD_MODULE_RADIUS,
		       HOSTAPD_LEVEL_DEBUG, "No RADIUS RX handler found "
		       "(type=%d code=%d id=%d)%s - dropping packet",
		       msg_type, msg->hdr->code, msg->hdr->identifier,
		       invalid_authenticator ? " [INVALID AUTHENTICATOR]" :
		       "");
	radius_client_msg_free(req);

 fail:
	radius_msg_free(msg);
	free(msg);
}


u8 radius_client_get_id(struct radius_client_data *radius)
{
	struct hostapd_data *hapd = radius->hapd;
	struct radius_msg_list *entry, *prev, *remove;
	u8 id = radius->next_radius_identifier++;

	/* remove entries with matching id from retransmit list to avoid
	 * using new reply from the RADIUS server with an old request */
	entry = radius->msgs;
	prev = NULL;
	while (entry) {
		if (entry->msg->hdr->identifier == id) {
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
				      "Removing pending RADIUS message, since "
				      "its id (%d) is reused\n", id);
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;
			remove = entry;
		} else
			remove = NULL;
		prev = entry;
		entry = entry->next;

		if (remove)
			radius_client_msg_free(remove);
	}

	return id;
}


void radius_client_flush(struct radius_client_data *radius)
{
	struct radius_msg_list *entry, *prev;

	if (!radius)
		return;

	eloop_cancel_timeout(radius_client_timer, radius, NULL);

	entry = radius->msgs;
	radius->msgs = NULL;
	radius->num_msgs = 0;
	while (entry) {
		prev = entry;
		entry = entry->next;
		radius_client_msg_free(prev);
	}
}


static int
radius_change_server(struct radius_client_data *radius,
		     struct hostapd_radius_server *nserv,
		     struct hostapd_radius_server *oserv,
		     int sock, int auth)
{
	struct hostapd_data *hapd = radius->hapd;
	struct sockaddr_in serv;

	hostapd_logger(hapd, NULL, HOSTAPD_MODULE_RADIUS, HOSTAPD_LEVEL_INFO,
		       "%s server %s:%d",
		       auth ? "Authentication" : "Accounting",
		       inet_ntoa(nserv->addr), nserv->port);

	if (!oserv || nserv->shared_secret_len != oserv->shared_secret_len ||
	    memcmp(nserv->shared_secret, oserv->shared_secret,
		   nserv->shared_secret_len) != 0) {
		/* Pending RADIUS packets used different shared
		 * secret, so they would need to be modified. Could
		 * update all message authenticators and
		 * User-Passwords, etc. and retry with new server. For
		 * now, just drop all pending packets. */
		radius_client_flush(radius);
	} else {
		/* Reset retry counters for the new server */
		struct radius_msg_list *entry;
		entry = radius->msgs;
		while (entry) {
			entry->next_try = entry->first_try +
				RADIUS_CLIENT_FIRST_WAIT;
			entry->attempts = 0;
			entry->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;
			entry = entry->next;
		}
		if (radius->msgs) {
			eloop_cancel_timeout(radius_client_timer, radius,
					     NULL);
			eloop_register_timeout(RADIUS_CLIENT_FIRST_WAIT, 0,
					       radius_client_timer, radius,
					       NULL);
		}
	}

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = nserv->addr.s_addr;
	serv.sin_port = htons(nserv->port);

	if (connect(sock, (struct sockaddr *) &serv, sizeof(serv)) < 0) {
		perror("connect[radius]");
		return -1;
	}

	return 0;
}


static void radius_retry_primary_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct radius_client_data *radius = eloop_ctx;
	struct hostapd_data *hapd = radius->hapd;
	struct hostapd_radius_server *oserv;

	if (radius->auth_serv_sock >= 0 && hapd->conf->auth_servers &&
	    hapd->conf->auth_server != hapd->conf->auth_servers) {
		oserv = hapd->conf->auth_server;
		hapd->conf->auth_server = hapd->conf->auth_servers;
		radius_change_server(radius, hapd->conf->auth_server, oserv,
				     radius->auth_serv_sock, 1);
	}

	if (radius->acct_serv_sock >= 0 && hapd->conf->acct_servers &&
	    hapd->conf->acct_server != hapd->conf->acct_servers) {
		oserv = hapd->conf->acct_server;
		hapd->conf->acct_server = hapd->conf->acct_servers;
		radius_change_server(radius, hapd->conf->acct_server, oserv,
				     radius->acct_serv_sock, 0);
	}

	if (hapd->conf->radius_retry_primary_interval)
		eloop_register_timeout(hapd->conf->
				       radius_retry_primary_interval, 0,
				       radius_retry_primary_timer, radius,
				       NULL);
}


static int radius_client_init_auth(struct radius_client_data *radius)
{
	struct hostapd_data *hapd = radius->hapd;
	radius->auth_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (radius->auth_serv_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	radius_change_server(radius, hapd->conf->auth_server, NULL,
			     radius->auth_serv_sock, 1);

	if (eloop_register_read_sock(radius->auth_serv_sock,
				     radius_client_receive, radius,
				     (void *) RADIUS_AUTH)) {
		printf("Could not register read socket for authentication "
		       "server\n");
		return -1;
	}

	return 0;
}


static int radius_client_init_acct(struct radius_client_data *radius)
{
	struct hostapd_data *hapd = radius->hapd;
	radius->acct_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (radius->acct_serv_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	radius_change_server(radius, hapd->conf->acct_server, NULL,
			     radius->acct_serv_sock, 0);

	if (eloop_register_read_sock(radius->acct_serv_sock,
				     radius_client_receive, radius,
				     (void *) RADIUS_ACCT)) {
		printf("Could not register read socket for accounting "
		       "server\n");
		return -1;
	}

	return 0;
}


struct radius_client_data * radius_client_init(struct hostapd_data *hapd)
{
	struct radius_client_data *radius;

	radius = malloc(sizeof(struct radius_client_data));
	if (radius == NULL)
		return NULL;

	memset(radius, 0, sizeof(struct radius_client_data));
	radius->hapd = hapd;
	radius->auth_serv_sock = radius->acct_serv_sock = -1;

	if (hapd->conf->auth_server && radius_client_init_auth(radius)) {
		radius_client_deinit(radius);
		return NULL;
	}

	if (hapd->conf->acct_server && radius_client_init_acct(radius)) {
		radius_client_deinit(radius);
		return NULL;
	}

	if (hapd->conf->radius_retry_primary_interval)
		eloop_register_timeout(hapd->conf->
				       radius_retry_primary_interval, 0,
				       radius_retry_primary_timer, radius,
				       NULL);

	return radius;
}


void radius_client_deinit(struct radius_client_data *radius)
{
	if (!radius)
		return;

	eloop_cancel_timeout(radius_retry_primary_timer, radius, NULL);

	radius_client_flush(radius);
	free(radius->auth_handlers);
	free(radius->acct_handlers);
	free(radius);
}


void radius_client_flush_auth(struct radius_client_data *radius, u8 *addr)
{
	struct hostapd_data *hapd = radius->hapd;
	struct radius_msg_list *entry, *prev, *tmp;

	prev = NULL;
	entry = radius->msgs;
	while (entry) {
		if (entry->msg_type == RADIUS_AUTH &&
		    memcmp(entry->addr, addr, ETH_ALEN) == 0) {
			hostapd_logger(hapd, addr, HOSTAPD_MODULE_RADIUS,
				       HOSTAPD_LEVEL_DEBUG,
				       "Removing pending RADIUS authentication"
				       " message for removed client");

			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;

			tmp = entry;
			entry = entry->next;
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			continue;
		}

		prev = entry;
		entry = entry->next;
	}
}


static int radius_client_dump_auth_server(char *buf, size_t buflen,
					  struct hostapd_radius_server *serv,
					  struct radius_client_data *cli)
{
	int pending = 0;
	struct radius_msg_list *msg;

	if (cli) {
		for (msg = cli->msgs; msg; msg = msg->next) {
			if (msg->msg_type == RADIUS_AUTH)
				pending++;
		}
	}

	return snprintf(buf, buflen,
			"radiusAuthServerIndex=%d\n"
			"radiusAuthServerAddress=%s\n"
			"radiusAuthClientServerPortNumber=%d\n"
			"radiusAuthClientRoundTripTime=%d\n"
			"radiusAuthClientAccessRequests=%u\n"
			"radiusAuthClientAccessRetransmissions=%u\n"
			"radiusAuthClientAccessAccepts=%u\n"
			"radiusAuthClientAccessRejects=%u\n"
			"radiusAuthClientAccessChallenges=%u\n"
			"radiusAuthClientMalformedAccessResponses=%u\n"
			"radiusAuthClientBadAuthenticators=%u\n"
			"radiusAuthClientPendingRequests=%u\n"
			"radiusAuthClientTimeouts=%u\n"
			"radiusAuthClientUnknownTypes=%u\n"
			"radiusAuthClientPacketsDropped=%u\n",
			serv->index,
			inet_ntoa(serv->addr),
			serv->port,
			serv->round_trip_time,
			serv->requests,
			serv->retransmissions,
			serv->access_accepts,
			serv->access_rejects,
			serv->access_challenges,
			serv->malformed_responses,
			serv->bad_authenticators,
			pending,
			serv->timeouts,
			serv->unknown_types,
			serv->packets_dropped);
}


static int radius_client_dump_acct_server(char *buf, size_t buflen,
					  struct hostapd_radius_server *serv,
					  struct radius_client_data *cli)
{
	int pending = 0;
	struct radius_msg_list *msg;

	if (cli) {
		for (msg = cli->msgs; msg; msg = msg->next) {
			if (msg->msg_type == RADIUS_ACCT ||
			    msg->msg_type == RADIUS_ACCT_INTERIM)
				pending++;
		}
	}

	return snprintf(buf, buflen,
			"radiusAccServerIndex=%d\n"
			"radiusAccServerAddress=%s\n"
			"radiusAccClientServerPortNumber=%d\n"
			"radiusAccClientRoundTripTime=%d\n"
			"radiusAccClientRequests=%u\n"
			"radiusAccClientRetransmissions=%u\n"
			"radiusAccClientResponses=%u\n"
			"radiusAccClientMalformedResponses=%u\n"
			"radiusAccClientBadAuthenticators=%u\n"
			"radiusAccClientPendingRequests=%u\n"
			"radiusAccClientTimeouts=%u\n"
			"radiusAccClientUnknownTypes=%u\n"
			"radiusAccClientPacketsDropped=%u\n",
			serv->index,
			inet_ntoa(serv->addr),
			serv->port,
			serv->round_trip_time,
			serv->requests,
			serv->retransmissions,
			serv->responses,
			serv->malformed_responses,
			serv->bad_authenticators,
			pending,
			serv->timeouts,
			serv->unknown_types,
			serv->packets_dropped);
}


int radius_client_get_mib(struct radius_client_data *radius, char *buf,
			  size_t buflen)
{
	struct hostapd_data *hapd = radius->hapd;
	int i;
	struct hostapd_radius_server *serv;
	int count = 0;

	if (hapd->conf->auth_servers) {
		for (i = 0; i < hapd->conf->num_auth_servers; i++) {
			serv = &hapd->conf->auth_servers[i];
			count += radius_client_dump_auth_server(
				buf + count, buflen - count, serv,
				serv == hapd->conf->auth_server ?
				radius : NULL);
		}
	}

	if (hapd->conf->acct_servers) {
		for (i = 0; i < hapd->conf->num_acct_servers; i++) {
			serv = &hapd->conf->acct_servers[i];
			count += radius_client_dump_acct_server(
				buf + count, buflen - count, serv,
				serv == hapd->conf->acct_server ?
				radius : NULL);
		}
	}

	return count;
}
