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

#include <sys/time.h>

#include <errno.h>
#include <stdbool.h>
#include <strings.h>
#include <talloc.h>

#include "util/dlinklist.h"
#include "util/refcount.h"
#include "util/util.h"
#include "providers/fail_over.h"
#include "resolv/async_resolv.h"

#define STATUS_DIFF(p, now) ((now).tv_sec - (p)->last_status_change.tv_sec)
#define SERVER_NAME(s) ((s)->common ? (s)->common->name : "(no name)")

#define DEFAULT_PORT_STATUS PORT_NEUTRAL
#define DEFAULT_SERVER_STATUS SERVER_NAME_NOT_RESOLVED

struct fo_ctx {
    struct fo_service *service_list;
    struct server_common *server_common_list;

    /* Settings. */
    time_t retry_timeout;
};

struct fo_service {
    struct fo_service *prev;
    struct fo_service *next;

    struct fo_ctx *ctx;
    char *name;
    struct fo_server *active_server;
    struct fo_server *last_tried_server;
    struct fo_server *server_list;
};

struct fo_server {
    struct fo_server *prev;
    struct fo_server *next;

    void *user_data;
    int port;
    int port_status;
    struct fo_service *service;
    struct timeval last_status_change;
    struct server_common *common;
};

struct server_common {
    REFCOUNT_COMMON;

    struct server_common *prev;
    struct server_common *next;

    char *name;
    struct hostent *hostent;
    struct resolve_service_request *request_list;
    int server_status;
    struct timeval last_status_change;
};

struct resolve_service_request {
    struct resolve_service_request *prev;
    struct resolve_service_request *next;

    struct server_common *server_common;
    struct tevent_req *req;
};

struct status {
    int value;
    struct timeval last_change;
};

struct fo_ctx *
fo_context_init(TALLOC_CTX *mem_ctx, time_t retry_timeout)
{
    struct fo_ctx *ctx;

    ctx = talloc_zero(mem_ctx, struct fo_ctx);
    if (ctx == NULL) {
        DEBUG(1, ("No memory\n"));
        return NULL;
    }

    ctx->retry_timeout = retry_timeout;

    DEBUG(3, ("Created new fail over context, retry timeout is %d\n",
              retry_timeout));
    return ctx;
}

static const char *
str_port_status(enum port_status status)
{
    switch (status) {
    case PORT_NEUTRAL:
        return "neutral";
    case PORT_WORKING:
        return "working";
    case PORT_NOT_WORKING:
        return "not working";
    }

    return "unknown port status";
}

static const char *
str_server_status(enum server_status status)
{
    switch (status) {
    case SERVER_NAME_NOT_RESOLVED:
        return "name not resolved";
    case SERVER_RESOLVING_NAME:
        return "resolving name";
    case SERVER_NAME_RESOLVED:
        return "name resolved";
    case SERVER_WORKING:
        return "working";
    case SERVER_NOT_WORKING:
        return "not working";
    }

    return "unknown server status";
}

/*
 * This function will return the status of the server. If the status was
 * last updated a long time ago, we will first reset the status.
 */
static enum server_status
get_server_status(struct fo_server *server)
{
    struct timeval tv;
    time_t timeout;

    if (server->common == NULL)
        return SERVER_NAME_RESOLVED;

    DEBUG(7, ("Status of server '%s' is '%s'\n", SERVER_NAME(server),
              str_server_status(server->common->server_status)));

    timeout = server->service->ctx->retry_timeout;
    if (timeout != 0 && server->common->server_status == SERVER_NOT_WORKING) {
        gettimeofday(&tv, NULL);
        if (STATUS_DIFF(server->common, tv) > timeout) {
            DEBUG(4, ("Reseting the server status of '%s'\n",
                      SERVER_NAME(server)));
            server->common->server_status = SERVER_NAME_NOT_RESOLVED;
            server->last_status_change.tv_sec = 0;
        }
    }

    return server->common->server_status;
}

/*
 * This function will return the status of the service. If the status was
 * last updated a long time ago, we will first reset the status.
 */
static enum port_status
get_port_status(struct fo_server *server)
{
    struct timeval tv;
    time_t timeout;

    DEBUG(7, ("Port status of port %d for server '%s' is '%s'\n", server->port,
              SERVER_NAME(server), str_port_status(server->port_status)));

    timeout = server->service->ctx->retry_timeout;
    if (timeout != 0 && server->port_status == PORT_NOT_WORKING) {
        gettimeofday(&tv, NULL);
        if (STATUS_DIFF(server, tv) > timeout) {
            DEBUG(4, ("Reseting the status of port %d for server '%s'\n",
                      server->port, SERVER_NAME(server)));
            server->port_status = PORT_NEUTRAL;
            server->last_status_change.tv_sec = tv.tv_sec;
        }
    }

    return server->port_status;
}

static int
server_works(struct fo_server *server)
{
    if (get_server_status(server) == SERVER_NOT_WORKING)
        return 0;

    return 1;
}

static int
service_works(struct fo_server *server)
{
    if (!server_works(server))
        return 0;
    if (get_port_status(server) == PORT_NOT_WORKING)
        return 0;

    return 1;
}

static int
service_destructor(struct fo_service *service)
{
    DLIST_REMOVE(service->ctx->service_list, service);
    return 0;
}

int
fo_new_service(struct fo_ctx *ctx, const char *name,
               struct fo_service **_service)
{
    struct fo_service *service;
    int ret;

    DEBUG(3, ("Creating new service '%s'\n", name));
    ret = fo_get_service(ctx, name, &service);
    if (ret == EOK) {
        DEBUG(5, ("Service '%s' already exists\n", name));
        if (_service) {
                *_service = service;
        }
        return EEXIST;
    } else if (ret != ENOENT) {
        return ret;
    }

    service = talloc_zero(ctx, struct fo_service);
    if (service == NULL)
        return ENOMEM;

    service->name = talloc_strdup(service, name);
    if (service->name == NULL) {
        talloc_free(service);
        return ENOMEM;
    }

    service->ctx = ctx;
    DLIST_ADD(ctx->service_list, service);

    talloc_set_destructor(service, service_destructor);
    if (_service) {
        *_service = service;
    }

    return EOK;
}

int
fo_get_service(struct fo_ctx *ctx, const char *name,
               struct fo_service **_service)
{
    struct fo_service *service;

    DLIST_FOR_EACH(service, ctx->service_list) {
        if (!strcmp(name, service->name)) {
            *_service = service;
            return EOK;
        }
    }

    return ENOENT;
}

static int
get_server_common(TALLOC_CTX *mem_ctx, struct fo_ctx *ctx, const char *name,
                  struct server_common **_common)
{
    struct server_common *common;

    DLIST_FOR_EACH(common, ctx->server_common_list) {
        if (!strcmp(name, common->name)) {
            *_common = rc_reference(mem_ctx, struct server_common, common);
            if (_common == NULL)
                return ENOMEM;
            return EOK;
        }
    }

    return ENOENT;
}

static struct server_common *
create_server_common(TALLOC_CTX *mem_ctx, struct fo_ctx *ctx, const char *name)
{
    struct server_common *common;

    common = rc_alloc(mem_ctx, struct server_common);
    if (common == NULL)
        return NULL;

    common->name = talloc_strdup(common, name);
    if (common->name == NULL) {
        talloc_free(common);
        return NULL;
    }

    common->prev = NULL;
    common->next = NULL;
    common->hostent = NULL;
    common->request_list = NULL;
    common->server_status = DEFAULT_SERVER_STATUS;
    common->last_status_change.tv_sec = 0;
    common->last_status_change.tv_usec = 0;

    DLIST_ADD_END(ctx->server_common_list, common, struct server_common *);
    return common;
}

int
fo_add_server(struct fo_service *service, const char *name, int port,
              void *user_data)
{
    struct fo_server *server;
    int ret;

    DEBUG(3, ("Adding new server '%s', to service '%s'\n",
              name ? name : "(no name)", service->name));
    DLIST_FOR_EACH(server, service->server_list) {
        if (server->port != port || server->user_data != user_data)
            continue;
        if (name == NULL && server->common == NULL) {
            return EEXIST;
        } else if (name != NULL && server->common != NULL) {
            if (!strcmp(name, server->common->name))
                return EEXIST;
        }
    }

    server = talloc_zero(service, struct fo_server);
    if (server == NULL)
        return ENOMEM;

    server->port = port;
    server->user_data = user_data;
    server->service = service;
    server->port_status = DEFAULT_PORT_STATUS;

    if (name != NULL) {
        ret = get_server_common(server, service->ctx, name, &server->common);
        if (ret == ENOENT) {
            server->common = create_server_common(server, service->ctx, name);
            if (server->common == NULL) {
                talloc_free(server);
                return ENOMEM;
            }
        } else if (ret != EOK) {
            talloc_free(server);
            return ret;
        }
    }

    DLIST_ADD_END(service->server_list, server, struct fo_server *);

    return EOK;
}

static int
get_first_server_entity(struct fo_service *service, struct fo_server **_server)
{
    struct fo_server *server;

    /* If we already have a working server, use that one. */
    server = service->active_server;
    if (server != NULL) {
        if (service_works(server)) {
            goto done;
        }
        service->active_server = NULL;
    }

    /*
     * Otherwise iterate through the server list.
     */

    /* First, try servers after the last one we tried. */
    if (service->last_tried_server != NULL) {
        DLIST_FOR_EACH(server, service->last_tried_server->next) {
            if (service_works(server)) {
                goto done;
            }
        }
    }

    /* If none were found, try at the start. */
    DLIST_FOR_EACH(server, service->server_list) {
        if (service_works(server)) {
            goto done;
        }
        if (server == service->last_tried_server) {
            break;
        }
    }

    service->last_tried_server = NULL;
    return ENOENT;

done:
    service->last_tried_server = server;
    *_server = server;
    return EOK;
}

static int
resolve_service_request_destructor(struct resolve_service_request *request)
{
    DLIST_REMOVE(request->server_common->request_list, request);
    return 0;
}

static int
set_lookup_hook(struct fo_server *server, struct tevent_req *req)
{
    struct resolve_service_request *request;

    request = talloc(req, struct resolve_service_request);
    if (request == NULL) {
        DEBUG(1, ("No memory\n"));
        talloc_free(request);
        return ENOMEM;
    }
    request->server_common = server->common;
    request->req = req;
    DLIST_ADD(server->common->request_list, request);
    talloc_set_destructor(request, resolve_service_request_destructor);

    return EOK;
}

/*******************************************************************
 * Get server to connect to.                                       *
 *******************************************************************/

struct resolve_service_state {
    struct fo_server *server;
};

static void fo_resolve_service_done(struct tevent_req *subreq);

struct tevent_req *
fo_resolve_service_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                        struct resolv_ctx *resolv, struct fo_service *service)
{
    int ret;
    struct fo_server *server;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct resolve_service_state *state;

    DEBUG(4, ("Trying to resolve service '%s'\n", service->name));
    req = tevent_req_create(mem_ctx, &state, struct resolve_service_state);
    if (req == NULL)
        return NULL;

    ret = get_first_server_entity(service, &server);
    if (ret != EOK) {
        DEBUG(1, ("No available servers for service '%s'\n", service->name));
        goto done;
    }

    state->server = server;

    if (server->common == NULL) {
        /* This server doesn't have a name, we don't do name resolution. */
        tevent_req_done(req);
        tevent_req_post(req, ev);
        return req;
    }

    switch (get_server_status(server)) {
    case SERVER_NAME_NOT_RESOLVED: /* Request name resolution. */
        /* TODO: Enable IPv6. */
        subreq = resolv_gethostbyname_send(server->common, ev, resolv,
                                           server->common->name, AF_INET);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, fo_resolve_service_done, server->common);
        fo_set_server_status(server, SERVER_RESOLVING_NAME);
        /* FALLTHROUGH */
    case SERVER_RESOLVING_NAME:
        /* Name resolution is already under way. Just add ourselves into the
         * waiting queue so we get notified after the operation is finished. */
        ret = set_lookup_hook(server, req);
        if (ret != EOK)
            goto done;
        break;
    default: /* The name is already resolved. Return immediately. */
        tevent_req_done(req);
        tevent_req_post(req, ev);
        break;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void set_server_common_status(struct server_common *common,
                                     enum server_status status);

static void
fo_resolve_service_done(struct tevent_req *subreq)
{
    int resolv_status;
    struct resolve_service_request *request;
    struct server_common *common;
    int ret;

    common = tevent_req_callback_data(subreq, struct server_common);

    if (common->hostent != NULL) {
        talloc_zfree(common->hostent);
    }

    ret = resolv_gethostbyname_recv(subreq, common,
                                    &resolv_status, NULL, &common->hostent);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Failed to resolve server '%s': %s\n", common->name,
              resolv_strerror(resolv_status)));
        set_server_common_status(common, SERVER_NOT_WORKING);
    } else {
        set_server_common_status(common, SERVER_NAME_RESOLVED);
    }

    /* Take care of all requests for this server. */
    while ((request = common->request_list) != NULL) {
        DLIST_REMOVE(common->request_list, request);
        if (resolv_status) {
            /* FIXME FIXME: resolv_status is an ARES error.
             * but any caller will expect classic error codes.
             * also the send() function may return ENOENT, so this mix
             * IS explosive (ENOENT = 2 = ARES_EFORMER) */
            tevent_req_error(request->req, resolv_status);
        } else {
            tevent_req_done(request->req);
        }
    }
}

int
fo_resolve_service_recv(struct tevent_req *req, struct fo_server **server)
{
    struct resolve_service_state *state;

    state = tevent_req_data(req, struct resolve_service_state);

    /* always return the server if asked for, otherwise the caller
     * cannot mark it as faulty in case we return an error */
    if (server)
        *server = state->server;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void
set_server_common_status(struct server_common *common,
                         enum server_status status)
{
    DEBUG(4, ("Marking server '%s' as '%s'\n", common->name,
              str_server_status(status)));

    common->server_status = status;
    gettimeofday(&common->last_status_change, NULL);
}

void
fo_set_server_status(struct fo_server *server, enum server_status status)
{
    if (server->common == NULL) {
        DEBUG(1, ("Bug: Trying to set server status of a name-less server\n"));
        return;
    }

    set_server_common_status(server->common, status);
}

void
fo_set_port_status(struct fo_server *server, enum port_status status)
{
    DEBUG(4, ("Marking port %d of server '%s' as '%s'\n", server->port,
              SERVER_NAME(server), str_port_status(status)));

    server->port_status = status;
    gettimeofday(&server->last_status_change, NULL);
    if (status == PORT_WORKING) {
        fo_set_server_status(server, SERVER_WORKING);
        server->service->active_server = server;
    }
}

void *
fo_get_server_user_data(struct fo_server *server)
{
    return server->user_data;
}

int
fo_get_server_port(struct fo_server *server)
{
    return server->port;
}

const char *fo_get_server_name(struct fo_server *server)
{
    return server->common->name;
}

struct hostent *
fo_get_server_hostent(struct fo_server *server)
{
    if (server->common == NULL) {
        DEBUG(1, ("Bug: Trying to get hostent from a name-less server\n"));
        return NULL;
    }
    return server->common->hostent;
}
