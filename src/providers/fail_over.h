/*
   SSSD

   Fail over helper functions.

   Authors:
        Martin Nagy <mnagy@redhat.com>

   Copyright (C) Red Hat, Inc 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __FAIL_OVER_H__
#define __FAIL_OVER_H__

#include <stdbool.h>
#include <talloc.h>

#include "resolv/async_resolv.h"
#include "providers/fail_over_srv.h"

#define FO_PROTO_TCP "tcp"
#define FO_PROTO_UDP "udp"

/* Some forward declarations that don't have to do anything with fail over. */
struct hostent;
struct tevent_context;
struct tevent_req;

enum port_status {
    PORT_NEUTRAL,    /* We didn't try this port yet. */
    PORT_WORKING,    /* This port was reported to work. */
    PORT_NOT_WORKING /* This port was reported to not work. */
};

enum server_status {
    SERVER_NAME_NOT_RESOLVED, /* We didn't yet resolved the host name. */
    SERVER_RESOLVING_NAME,    /* Name resolving is in progress. */
    SERVER_NAME_RESOLVED,     /* We resolved the host name but didn't try to connect. */
    SERVER_SECOND_FAMILY,    /* We should try second protocol */
    SERVER_WORKING,           /* We successfully connected to the server. */
    SERVER_NOT_WORKING        /* We tried and failed to connect to the server. */
};

struct fo_ctx;
struct fo_service;
struct fo_server;

/*
 * Failover settings.
 *
 * The 'retry_timeout' member specifies the
 * duration in seconds of how long a server or port will be considered
 * non-working after being marked as such.
 *
 * The 'service_resolv_timeout' member specifies how long we wait for
 * service resolution. When this timeout is reached, the resolve request
 * is cancelled with an error
 *
 * The 'srv_retry_timeout' member specifies how long a SRV lookup
 * is considered valid until we ask the server again.
 *
 * The 'srv_retry_neg_timeout' member specifies how long a SRV lookup
 * waits before previously failed lookup is tried again.
 *
 * The 'use_search_list' member specifies whether DNS lookup should perform
 * the search as specified in /etc/resolv.conf or not.
 *
 * The family_order member specifies the order of address families to
 * try when looking up the service.
 */
struct fo_options {
    time_t srv_retry_neg_timeout;
    time_t retry_timeout;
    time_t primary_timeout;
    int service_resolv_timeout;
    bool use_search_list;
    enum restrict_family family_order;
};

void dump_fo_server(const struct fo_server *srv);
void dump_fo_server_list(const struct fo_server *srv);

/*
 * Create a new fail over context based on options passed in the
 * opts parameter
 */
struct fo_ctx *fo_context_init(TALLOC_CTX *mem_ctx,
                               struct fo_options *opts);

typedef int (*datacmp_fn)(void*, void*);

/*
 * Create a new service structure for 'ctx', saving it to the location pointed
 * to by '_service'. The needed memory will be allocated from 'ctx'.
 * Service name will be set to 'name'.
 *
 * Function pointed by user_data_cmp returns 0 if user_data is equal
 * or nonzero value if not. Set to NULL if no user data comparison
 * is needed in fail over duplicate servers detection.
 */
int fo_new_service(struct fo_ctx *ctx,
                   const char *name,
                   datacmp_fn user_data_cmp,
                   struct fo_service **_service);

/*
 * Look up service named 'name' from the 'ctx' service list. Target of
 * '_service' will be set to the service if it was found.
 */
int fo_get_service(struct fo_ctx *ctx,
                   const char *name,
                   struct fo_service **_service);

/*
 * Get number of servers registered for the 'service'.
 */
int fo_get_server_count(struct fo_service *service);

/*
 * Adds a server 'name' to the 'service'. Port 'port' will be used for
 * connection. If 'name' is NULL, no server resolution will be done.
 */
int fo_add_server(struct fo_service *service,
                  const char *name, int port,
                  void *user_data, bool primary);

int fo_add_srv_server(struct fo_service *service,
                      const char *srv,
                      const char *discovery_domain,
                      const char *sssd_domain,
                      const char *proto,
                      void *user_data);

/*
 * Request the first server from the service's list of servers. It is only
 * considered if it is not marked as not working (or the retry interval already
 * passed). If the server address wasn't resolved yet, it will be done.
 */
struct tevent_req *fo_resolve_service_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct resolv_ctx *resolv,
                                           struct fo_ctx *ctx,
                                           struct fo_service *service);

int fo_resolve_service_recv(struct tevent_req *req,
                            TALLOC_CTX *ref_ctx,
                            struct fo_server **server);


/* To be used by async consumers of fo_resolve_service. If a server should be returned
 * to an outer request, it should be referenced by a memory from that outer request,
 * because the failover's server list might change with a subsequent call (see upstream
 * bug #2829)
 */
void fo_ref_server(TALLOC_CTX *ref_ctx, struct fo_server *server);

/*
 * Set feedback about 'server'. Caller should use this to indicate a problem
 * with the server itself, not only with the service on that server. This
 * should be used, for example, when the IP address of the server can't be
 * reached. This setting can affect other services as well, since they can
 * share the same server.
 */
void fo_set_server_status(struct fo_server *server,
                          enum server_status status);

/*
 * Set feedback about the port status. This function should be used when
 * the server itself is working but the service is not. When status is set
 * to PORT_WORKING, 'server' is also marked as an "active server" for its
 * service. When the next fo_resolve_service_send() function is called, this
 * server will be preferred. This will hold as long as it is not marked as
 * not-working.
 */
void fo_set_port_status(struct fo_server *server,
                        enum port_status status);

/*
 * Instruct fail-over to try next server on the next connect attempt.
 * Should be used after connection to service was unexpectedly dropped
 * but there is no authoritative information on whether active server is down.
 */
void fo_try_next_server(struct fo_service *service);

void *fo_get_server_user_data(struct fo_server *server);

int fo_get_server_port(struct fo_server *server);

/*
 * Get curently used/resolved inet family.
 * Function returns AF_INET, AF_INET6 or 0 in case that
 * name is not resolved yet.
 */
int fo_get_server_family(struct fo_server *server);

/*
 * Get secondary inet family if exists.
 * Function returns AF_INET, AF_INET6 or 0 in case that there is no
 * secondary family (for example if IPV4_ONLY is set). Note that
 * this function returns what is configured, not what is actually used.
 */
int fo_get_server_secondary_family(struct fo_server *server);

const char *fo_get_server_name(struct fo_server *server);

const char *fo_get_server_str_name(struct fo_server *server);

struct resolv_hostent *fo_get_server_hostent(struct fo_server *server);

bool fo_is_server_primary(struct fo_server *server);

time_t fo_get_server_hostname_last_change(struct fo_server *server);

int fo_is_srv_lookup(struct fo_server *s);

time_t fo_get_service_retry_timeout(struct fo_service *svc);

time_t fo_get_primary_retry_timeout(struct fo_service *svc);

bool fo_get_use_search_list(struct fo_server *server);

void fo_reset_services(struct fo_ctx *fo_ctx);

void fo_reset_servers(struct fo_service *svc);

struct fo_server *fo_get_active_server(struct fo_service *service);

bool fo_svc_has_server(struct fo_service *service, struct fo_server *server);

const char **fo_svc_server_list(TALLOC_CTX *mem_ctx,
                                struct fo_service *service,
                                size_t *_count);

/*
 * Folowing functions allow to iterate trough list of servers.
 */
struct fo_server *fo_server_first(struct fo_server *server);

struct fo_server *fo_server_next(struct fo_server *server);

size_t fo_server_count(struct fo_server *server);

/*
 * pvt will be talloc_stealed to ctx
 */
bool fo_set_srv_lookup_plugin(struct fo_ctx *ctx,
                              fo_srv_lookup_plugin_send_t send_fn,
                              fo_srv_lookup_plugin_recv_t recv_fn,
                              void *pvt);

#endif /* !__FAIL_OVER_H__ */
