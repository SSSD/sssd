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

/* Some forward declarations that don't have to do anything with fail over. */
struct hostent;
struct resolv_ctx;
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
    SERVER_WORKING,           /* We successfully connected to the server. */
    SERVER_NOT_WORKING        /* We tried and failed to connect to the server. */
};

struct fo_ctx;
struct fo_service;
struct fo_server;

/*
 * Create a new fail over context. The 'retry_timeout' argument specifies the
 * duration in seconds of how long a server or port will be considered
 * non-working after being marked as such.
 */
struct fo_ctx *fo_context_init(TALLOC_CTX *mem_ctx,
                               time_t retry_timeout);

/*
 * Create a new service structure for 'ctx', saving it to the location pointed
 * to by '_service'. The needed memory will be allocated from 'ctx'.
 * Service name will be set to 'name'.
 */
int fo_new_service(struct fo_ctx *ctx,
                   const char *name,
                   struct fo_service **_service);

/*
 * Look up service named 'name' from the 'ctx' service list. Target of
 * '_service' will be set to the service if it was found.
 */
int fo_get_service(struct fo_ctx *ctx,
                   const char *name,
                   struct fo_service **_service);

/*
 * Adds a server 'name' to the 'service'. Port 'port' will be used for
 * connection. If 'name' is NULL, no server resolution will be done.
 */
int fo_add_server(struct fo_service *service,
                  const char *name,
                  int port,
                  void *user_data);

/*
 * Request the first server from the service's list of servers. It is only
 * considered if it is not marked as not working (or the retry interval already
 * passed). If the server address wasn't resolved yet, it will be done.
 */
struct tevent_req *fo_resolve_service_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct resolv_ctx *resolv,
                                           struct fo_service *service);

int fo_resolve_service_recv(struct tevent_req *req,
                            struct fo_server **server);

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


void *fo_get_server_user_data(struct fo_server *server);

int fo_get_server_port(struct fo_server *server);

const char *fo_get_server_name(struct fo_server *server);

struct hostent *fo_get_server_hostent(struct fo_server *server);

#endif /* !__FAIL_OVER_H__ */
