/*
   SSSD

   Fail over helper functions.

   Authors:
        Martin Nagy <mnagy@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2010

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
#define DEFAULT_SRV_STATUS SRV_NEUTRAL

enum srv_lookup_status {
    SRV_NEUTRAL,        /* We didn't try this SRV lookup yet */
    SRV_RESOLVED,       /* This SRV lookup is resolved       */
    SRV_RESOLVE_ERROR,   /* Could not resolve this SRV lookup */
    SRV_EXPIRED         /* Need to refresh the SRV query     */
};

struct fo_ctx {
    struct fo_service *service_list;
    struct server_common *server_common_list;

    struct fo_options *opts;
};

struct fo_service {
    struct fo_service *prev;
    struct fo_service *next;

    struct fo_ctx *ctx;
    char *name;
    struct fo_server *active_server;
    struct fo_server *last_tried_server;
    struct fo_server *server_list;

    /* Function pointed by user_data_cmp returns 0 if user_data is equal
     * or nonzero value if not. Set to NULL if no user data comparison
     * is needed in fail over duplicate servers detection.
     */
    datacmp_fn user_data_cmp;
};

struct fo_server {
    struct fo_server *prev;
    struct fo_server *next;

    bool primary;
    void *user_data;
    int port;
    enum port_status port_status;
    struct srv_data *srv_data;
    struct fo_service *service;
    struct timeval last_status_change;
    struct server_common *common;
};

struct server_common {
    REFCOUNT_COMMON;

    struct fo_ctx *ctx;

    struct server_common *prev;
    struct server_common *next;

    char *name;
    struct resolv_hostent *rhostent;
    struct resolve_service_request *request_list;
    enum server_status server_status;
    struct timeval last_status_change;
};

struct srv_data {
    char *dns_domain;
    char *discovery_domain;
    char *sssd_domain;
    char *proto;
    char *srv;

    struct fo_server *meta;

    int srv_lookup_status;
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
fo_context_init(TALLOC_CTX *mem_ctx, struct fo_options *opts)
{
    struct fo_ctx *ctx;

    ctx = talloc_zero(mem_ctx, struct fo_ctx);
    if (ctx == NULL) {
        DEBUG(1, ("No memory\n"));
        return NULL;
    }
    ctx->opts = talloc_zero(ctx, struct fo_options);
    if (ctx->opts == NULL) {
        DEBUG(1, ("No memory\n"));
        return NULL;
    }

    ctx->opts->srv_retry_timeout = opts->srv_retry_timeout;
    ctx->opts->retry_timeout = opts->retry_timeout;
    ctx->opts->family_order  = opts->family_order;
    ctx->opts->service_resolv_timeout = opts->service_resolv_timeout;

    DEBUG(SSSDBG_TRACE_FUNC, ("Created new fail over context, retry timeout is %d\n",
                              ctx->opts->retry_timeout));
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
str_srv_data_status(enum srv_lookup_status status)
{
    switch (status) {
    case SRV_NEUTRAL:
        return "neutral";
    case SRV_RESOLVED:
        return "resolved";
    case SRV_RESOLVE_ERROR:
        return "not resolved";
    case SRV_EXPIRED:
        return "expired";
    }

    return "unknown SRV lookup status";
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

int fo_is_srv_lookup(struct fo_server *s)
{
    return s && s->srv_data;
}

static char *
get_srv_query(TALLOC_CTX *mem_ctx, struct fo_server *server)
{
    char *query;

    if (!fo_is_srv_lookup(server)) {
        return NULL;
    }

    query = talloc_asprintf(mem_ctx, "_%s._%s.%s", server->srv_data->srv,
                                                   server->srv_data->proto,
                                                   server->srv_data->dns_domain);
    return query;
}

static struct fo_server *
collapse_srv_lookup(struct fo_server *server)
{
    struct fo_server *tmp, *meta;

    meta = server->srv_data->meta;
    DEBUG(4, ("Need to refresh SRV lookup for domain %s\n",
              meta->srv_data->dns_domain));

    if (server != meta) {
        while (server->prev && server->prev->srv_data == meta->srv_data) {
            tmp = server->prev;
            DLIST_REMOVE(server->service->server_list, tmp);
            talloc_zfree(tmp);
        }
        while (server->next && server->next->srv_data == meta->srv_data) {
            tmp = server->next;
            DLIST_REMOVE(server->service->server_list, tmp);
            talloc_zfree(tmp);
        }

        if (server == server->service->active_server) {
            server->service->active_server = NULL;
        }
        if (server == server->service->last_tried_server) {
            server->service->last_tried_server = meta;
        }

        /* add back the meta server to denote SRV lookup */
        DLIST_ADD_AFTER(server->service->server_list, meta, server);
        DLIST_REMOVE(server->service->server_list, server);
        talloc_zfree(server);
    }

    meta->srv_data->srv_lookup_status = SRV_NEUTRAL;
    meta->srv_data->last_status_change.tv_sec = 0;

    return meta;
}

static enum srv_lookup_status
get_srv_data_status(struct srv_data *data)
{
    struct timeval tv;
    time_t timeout;

    timeout = data->meta->service->ctx->opts->srv_retry_timeout;
    gettimeofday(&tv, NULL);

    if (timeout && STATUS_DIFF(data, tv) > timeout) {
        switch(data->srv_lookup_status) {
        case SRV_EXPIRED:
        case SRV_NEUTRAL:
            break;
        case SRV_RESOLVED:
            data->srv_lookup_status = SRV_EXPIRED;
            data->last_status_change.tv_sec = 0;
            break;
        case SRV_RESOLVE_ERROR:
            data->srv_lookup_status = SRV_NEUTRAL;
            data->last_status_change.tv_sec = 0;
            break;
        default:
            DEBUG(1, ("Unknown state for SRV server!\n"));
        }
    }

    return data->srv_lookup_status;
}

static void
set_srv_data_status(struct srv_data *data, enum srv_lookup_status status)
{
    DEBUG(4, ("Marking SRV lookup of service '%s' as '%s'\n",
              data->meta->service->name, str_srv_data_status(status)));

    gettimeofday(&data->last_status_change, NULL);
    data->srv_lookup_status = status;
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

    timeout = server->service->ctx->opts->retry_timeout;
    gettimeofday(&tv, NULL);
    if (timeout != 0 && server->common->server_status == SERVER_NOT_WORKING) {
        if (STATUS_DIFF(server->common, tv) > timeout) {
            DEBUG(4, ("Reseting the server status of '%s'\n",
                      SERVER_NAME(server)));
            server->common->server_status = SERVER_NAME_NOT_RESOLVED;
            server->common->last_status_change.tv_sec = tv.tv_sec;
        }
    }

    if (server->common->rhostent && STATUS_DIFF(server->common, tv) >
        server->common->rhostent->addr_list[0]->ttl) {
        DEBUG(4, ("Hostname resolution expired, resetting the server "
                  "status of '%s'\n", SERVER_NAME(server)));
        fo_set_server_status(server, SERVER_NAME_NOT_RESOLVED);
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

    timeout = server->service->ctx->opts->retry_timeout;
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
               datacmp_fn user_data_cmp,
               struct fo_service **_service)
{
    struct fo_service *service;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, ("Creating new service '%s'\n", name));
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

    service->user_data_cmp = user_data_cmp;

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
        if (!strcasecmp(name, common->name)) {
            *_common = rc_reference(mem_ctx, struct server_common, common);
            if (*_common == NULL)
                return ENOMEM;
            return EOK;
        }
    }

    return ENOENT;
}

static int server_common_destructor(void *memptr)
{
    struct server_common *common;

    common = talloc_get_type(memptr, struct server_common);
    if (common->request_list) {
        DEBUG(1, ("BUG: pending requests still associated with this server\n"));
        return -1;
    }
    DLIST_REMOVE(common->ctx->server_common_list, common);

    return 0;
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

    common->ctx = ctx;
    common->prev = NULL;
    common->next = NULL;
    common->rhostent = NULL;
    common->request_list = NULL;
    common->server_status = DEFAULT_SERVER_STATUS;
    common->last_status_change.tv_sec = 0;
    common->last_status_change.tv_usec = 0;

    talloc_set_destructor((TALLOC_CTX *) common, server_common_destructor);
    DLIST_ADD_END(ctx->server_common_list, common, struct server_common *);
    return common;
}

int
fo_add_srv_server(struct fo_service *service, const char *srv,
                  const char *discovery_domain, const char *sssd_domain,
                  const char *proto, void *user_data)
{
    struct fo_server *server;

    DEBUG(SSSDBG_TRACE_FUNC, ("Adding new SRV server in domain '%s', to service '%s' using %s\n",
                              discovery_domain ? discovery_domain : "unknown",
                              service->name, proto));

    DLIST_FOR_EACH(server, service->server_list) {
        /* Compare user data only if user_data_cmp and both arguments
         * are not NULL.
         */
        if (server->service->user_data_cmp && user_data && server->user_data) {
            if (server->service->user_data_cmp(server->user_data, user_data)) {
                continue;
            }
        }

        if (fo_is_srv_lookup(server)) {
            if (((discovery_domain == NULL &&
                    server->srv_data->dns_domain == NULL) ||
                 (discovery_domain != NULL &&
                         server->srv_data->dns_domain != NULL &&
                  strcasecmp(server->srv_data->dns_domain, discovery_domain) == 0)) &&
                strcasecmp(server->srv_data->proto, proto) == 0) {
                return EEXIST;
            }
        }
    }

    server = talloc_zero(service, struct fo_server);
    if (server == NULL)
        return ENOMEM;

    server->user_data = user_data;
    server->service = service;
    server->port_status = DEFAULT_PORT_STATUS;
    server->primary = true; /* SRV servers are never back up */

    /* add the SRV-specific data */
    server->srv_data = talloc_zero(service, struct srv_data);
    if (server->srv_data == NULL)
        return ENOMEM;

    server->srv_data->proto = talloc_strdup(server->srv_data, proto);
    server->srv_data->srv = talloc_strdup(server->srv_data, srv);
    if (server->srv_data->proto == NULL ||
        server->srv_data->srv == NULL)
        return ENOMEM;

    if (discovery_domain) {
        server->srv_data->discovery_domain = talloc_strdup(server->srv_data,
                                                           discovery_domain);
        if (server->srv_data->discovery_domain == NULL)
            return ENOMEM;
        server->srv_data->dns_domain =
                server->srv_data->discovery_domain;
    }

    server->srv_data->sssd_domain =
            talloc_strdup(server->srv_data, sssd_domain);
    if (server->srv_data->sssd_domain == NULL)
        return ENOMEM;

    server->srv_data->meta = server;
    server->srv_data->srv_lookup_status = DEFAULT_SRV_STATUS;
    server->srv_data->last_status_change.tv_sec = 0;

    DLIST_ADD_END(service->server_list, server, struct fo_server *);
    return EOK;
}

static struct fo_server *
create_fo_server(struct fo_service *service, const char *name,
                 int port, void *user_data, bool primary)
{
    struct fo_server *server;
    int ret;

    server = talloc_zero(service, struct fo_server);
    if (server == NULL)
        return NULL;

    server->port = port;
    server->user_data = user_data;
    server->service = service;
    server->port_status = DEFAULT_PORT_STATUS;
    server->primary = primary;

    if (name != NULL) {
        ret = get_server_common(server, service->ctx, name, &server->common);
        if (ret == ENOENT) {
            server->common = create_server_common(server, service->ctx, name);
            if (server->common == NULL) {
                talloc_free(server);
                return NULL;
            }
        } else if (ret != EOK) {
            talloc_free(server);
            return NULL;
        }
    }

    return server;
}

int
fo_get_server_count(struct fo_service *service)
{
    struct fo_server *server;
    int count = 0;

    DLIST_FOR_EACH(server, service->server_list) {
        count++;
    }

    return count;
}

static bool fo_server_match(struct fo_server *server,
                           const char *name,
                           int port,
                           void *user_data)
{
    if (server->port != port) {
        return false;
    }

    /* Compare user data only if user_data_cmp and both arguments
     * are not NULL.
     */
    if (server->service->user_data_cmp && server->user_data && user_data) {
        if (server->service->user_data_cmp(server->user_data, user_data)) {
            return false;
        }
    }

    if (name == NULL && server->common == NULL) {
        return true;
    }

    if (name != NULL && server->common != NULL) {
        if (!strcasecmp(name, server->common->name))
            return true;
    }

    return false;
}

int
fo_add_server(struct fo_service *service, const char *name, int port,
              void *user_data, bool primary)
{
    struct fo_server *server;

    DEBUG(3, ("Adding new server '%s', to service '%s'\n",
              name ? name : "(no name)", service->name));
    DLIST_FOR_EACH(server, service->server_list) {
        if (fo_server_match(server, name, port, user_data)) {
            return EEXIST;
        }
    }

    server = create_fo_server(service, name, port, user_data, primary);
    if (!server) {
        return ENOMEM;
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
        if (service_works(server) && fo_is_server_primary(server)) {
            goto done;
        }
        service->active_server = NULL;
    }

    /*
     * Otherwise iterate through the server list.
     */

    /* First, try primary servers after the last one we tried.
     * (only if the last one was primary as well)
     */
    if (service->last_tried_server != NULL &&
        service->last_tried_server->primary) {
        if (service->last_tried_server->port_status == PORT_NEUTRAL &&
            server_works(service->last_tried_server)) {
            server = service->last_tried_server;
            goto done;
        }

        DLIST_FOR_EACH(server, service->last_tried_server->next) {
            /* Go only through primary servers */
            if (!server->primary) continue;

            if (service_works(server)) {
                goto done;
            }
        }
    }

    /* If none were found, try at the start, primary first */
    DLIST_FOR_EACH(server, service->server_list) {
        /* First iterate only over primary servers */
        if (!server->primary) continue;

        if (service_works(server)) {
            goto done;
        }
        if (server == service->last_tried_server) {
            break;
        }
    }

    DLIST_FOR_EACH(server, service->server_list) {
        /* Now iterate only over backup servers */
        if (server->primary) continue;

        if (service_works(server)) {
            goto done;
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
    request->server_common = rc_reference(request, struct server_common,
                                          server->common);
    if (request->server_common == NULL) {
        talloc_free(request);
        return ENOMEM;
    }
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

    struct resolv_ctx *resolv;
    struct tevent_context *ev;
    struct tevent_timer *timeout_handler;
    struct fo_ctx *fo_ctx;
};

static errno_t fo_resolve_service_activate_timeout(struct tevent_req *req,
            struct tevent_context *ev, const unsigned long timeout_seconds);
static void fo_resolve_service_cont(struct tevent_req *subreq);
static void fo_resolve_service_done(struct tevent_req *subreq);
static bool fo_resolve_service_server(struct tevent_req *req);

/* Forward declarations for SRV resolving */
static struct tevent_req *
resolve_srv_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                    struct resolv_ctx *resolv, struct fo_ctx *ctx,
                    struct fo_server *server);
static int
resolve_srv_recv(struct tevent_req *req, struct fo_server **server);

struct tevent_req *
fo_resolve_service_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                        struct resolv_ctx *resolv, struct fo_ctx *ctx,
                        struct fo_service *service)
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

    state->resolv = resolv;
    state->ev = ev;
    state->fo_ctx = ctx;

    ret = get_first_server_entity(service, &server);
    if (ret != EOK) {
        DEBUG(1, ("No available servers for service '%s'\n", service->name));
        goto done;
    }

    /* Activate per-service timeout handler */
    ret = fo_resolve_service_activate_timeout(req, ev,
                                        ctx->opts->service_resolv_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not set service timeout\n"));
        goto done;
    }

    if (fo_is_srv_lookup(server)) {
        /* Don't know the server yet, must do a SRV lookup */
        subreq = resolve_srv_send(state, ev, resolv,
                                  ctx, server);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq,
                                fo_resolve_service_cont,
                                req);
        return req;
    }

    /* This is a regular server, just do hostname lookup */
    state->server = server;
    if (fo_resolve_service_server(req)) {
        tevent_req_post(req, ev);
    }

    ret = EOK;
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
fo_resolve_service_timeout(struct tevent_context *ev,
                           struct tevent_timer *te,
                           struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);

    DEBUG(SSSDBG_MINOR_FAILURE, ("Service resolving timeout reached\n"));
    tevent_req_error(req, ETIMEDOUT);
}

static errno_t
fo_resolve_service_activate_timeout(struct tevent_req *req,
                                    struct tevent_context *ev,
                                    const unsigned long timeout_seconds)
{
    struct timeval tv;
    struct resolve_service_state *state = tevent_req_data(req,
                                        struct resolve_service_state);

    tv = tevent_timeval_current();
    tv = tevent_timeval_add(&tv, timeout_seconds, 0);
    state->timeout_handler = tevent_add_timer(ev, state, tv,
                                           fo_resolve_service_timeout, req);
    if (state->timeout_handler == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_add_timer failed.\n"));
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Resolve timeout set to %lu seconds\n",
          timeout_seconds));
    return EOK;
}

/* SRV resolving finished, see if we got server to work with */
static void
fo_resolve_service_cont(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct resolve_service_state *state = tevent_req_data(req,
                                        struct resolve_service_state);
    int ret;

    ret = resolve_srv_recv(subreq, &state->server);
    talloc_zfree(subreq);

    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    fo_resolve_service_server(req);
}

static bool
fo_resolve_service_server(struct tevent_req *req)
{
    struct resolve_service_state *state = tevent_req_data(req,
                                        struct resolve_service_state);
    struct tevent_req *subreq;
    int ret;

    switch (get_server_status(state->server)) {
    case SERVER_NAME_NOT_RESOLVED: /* Request name resolution. */
        subreq = resolv_gethostbyname_send(state->server->common,
                                           state->ev, state->resolv,
                                           state->server->common->name,
                                           state->fo_ctx->opts->family_order,
                                           default_host_dbs);
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return true;
        }
        tevent_req_set_callback(subreq, fo_resolve_service_done,
                                state->server->common);
        fo_set_server_status(state->server, SERVER_RESOLVING_NAME);
        /* FALLTHROUGH */
    case SERVER_RESOLVING_NAME:
        /* Name resolution is already under way. Just add ourselves into the
         * waiting queue so we get notified after the operation is finished. */
        ret = set_lookup_hook(state->server, req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return true;
        }
        break;
    default: /* The name is already resolved. Return immediately. */
        tevent_req_done(req);
        return true;
    }

    return false;
}

static void
fo_resolve_service_done(struct tevent_req *subreq)
{
    struct server_common *common = tevent_req_callback_data(subreq,
                                                        struct server_common);
    int resolv_status;
    struct resolve_service_request *request;
    int ret;

    if (common->rhostent != NULL) {
        talloc_zfree(common->rhostent);
    }

    ret = resolv_gethostbyname_recv(subreq, common,
                                    &resolv_status, NULL,
                                    &common->rhostent);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Failed to resolve server '%s': %s\n",
                  common->name,
                  resolv_strerror(resolv_status)));
        /* If the resolver failed to resolve a hostname but did not
         * encounter an error, tell the caller to retry another server.
         *
         * If there are no more servers to try, the next request would
         * just shortcut with ENOENT.
         */
        if (ret == ENOENT) {
            ret = EAGAIN;
        }
        set_server_common_status(common, SERVER_NOT_WORKING);
    } else {
        set_server_common_status(common, SERVER_NAME_RESOLVED);
    }

    /* Take care of all requests for this server. */
    while ((request = common->request_list) != NULL) {
        DLIST_REMOVE(common->request_list, request);
        if (ret) {
            tevent_req_error(request->req, ret);
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

/*******************************************************************
 * Resolve the server to connect to using a SRV query.             *
 *******************************************************************/

static void resolve_srv_done(struct tevent_req *subreq);
static void resolve_srv_cont(struct tevent_req *req);

struct tevent_req *resolve_get_domain_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct fo_ctx *foctx,
                                           struct resolv_ctx *resolv);

static void resolve_getsrv_domain_done(struct tevent_req *req);
int resolve_get_domain_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            char **dns_domain);

struct resolve_srv_state {
    struct fo_server *meta;
    struct fo_service *service;

    struct fo_server *out;

    struct resolv_ctx *resolv;
    struct tevent_context *ev;
    struct fo_ctx *fo_ctx;
};

static struct tevent_req *
resolve_srv_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                 struct resolv_ctx *resolv, struct fo_ctx *ctx,
                 struct fo_server *server)
{
    int ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct resolve_srv_state *state;
    int status;

    req = tevent_req_create(mem_ctx, &state, struct resolve_srv_state);
    if (req == NULL)
        return NULL;

    state->service = server->service;
    state->ev = ev;
    state->resolv = resolv;
    state->fo_ctx = ctx;
    state->meta = server->srv_data->meta;

    status = get_srv_data_status(server->srv_data);
    DEBUG(SSSDBG_FUNC_DATA, ("The status of SRV lookup is %s\n",
          str_srv_data_status(status)));
    switch(status) {
    case SRV_EXPIRED: /* Need a refresh */
        state->meta = collapse_srv_lookup(server);
        /* FALLTHROUGH.
         * "server" might be invalid now if the SRV
         * query collapsed
         * */
    case SRV_NEUTRAL: /* Request SRV lookup */
        if (state->meta->srv_data->dns_domain == NULL) {
            /* we need to look up our DNS domain first */
            subreq = resolve_get_domain_send(state, ev, ctx, resolv);
            if (subreq == NULL) {
                ret = ENOMEM;
                goto done;
            }
            tevent_req_set_callback(subreq, resolve_getsrv_domain_done, req);
            break;
        }
        /* we know the DNS domain, just do the lookup */
        resolve_srv_cont(req);
        break;
    case SRV_RESOLVE_ERROR: /* query could not be resolved but don't retry yet */
        ret = EIO;
        goto done;
    case SRV_RESOLVED:  /* The query is resolved and valid. Return. */
        state->out = server;
        tevent_req_done(req);
        tevent_req_post(req, state->ev);
        return req;
    default:
        DEBUG(1, ("Unexpected status %d for a SRV server\n", status));
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void
resolve_getsrv_domain_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct resolve_srv_state *state = tevent_req_data(req,
                                                struct resolve_srv_state);
    int ret;

    ret = resolve_get_domain_recv(subreq, state->meta->srv_data,
                                  &state->meta->srv_data->dns_domain);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    resolve_srv_cont(req);
}

static void
resolve_srv_cont(struct tevent_req *req)
{
    struct resolve_srv_state *state = tevent_req_data(req,
                                                struct resolve_srv_state);
    char *query;
    struct tevent_req *subreq;

    query = get_srv_query(state, state->meta);
    if (!query) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    DEBUG(4, ("Searching for servers via SRV query '%s'\n", query));

    subreq = resolv_getsrv_send(state, state->ev, state->resolv, query);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, resolve_srv_done, req);
}

static void
resolve_srv_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct resolve_srv_state *state = tevent_req_data(req,
                                                struct resolve_srv_state);
    struct ares_srv_reply *reply_list;
    struct ares_srv_reply *reply;
    struct fo_server *server = NULL;
    struct fo_server *srv_list = NULL;
    int ret;
    int resolv_status;

    ret = resolv_getsrv_recv(state, subreq,
                             &resolv_status, NULL, &reply_list);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(1, ("SRV query failed: [%s]\n",
                  resolv_strerror(resolv_status)));
        if (resolv_status == ARES_ENOTFOUND &&
                state->meta->srv_data->dns_domain !=
                    state->meta->srv_data->discovery_domain &&
                state->meta->srv_data->dns_domain !=
                    state->meta->srv_data->sssd_domain) {
            /* The domain name could not be identified
             * If the domain wasn't specified in the config
             * file, also check whether the SSSD domain
             * works.
             *
             * Programming note: It is safe to compare
             * pointers here, because we're not copying
             * the data, we're just reassigning the pointer
             * for the active domain.
             */
            talloc_free(state->meta->srv_data->dns_domain);
            state->meta->srv_data->dns_domain =
                    state->meta->srv_data->sssd_domain;
            resolve_srv_cont(req);
            return;
        }

        /* We need to make sure we reset this to NULL
         * so that if we go online later, we re-check
         * the DNS domain
         */
        if (!state->meta->srv_data->discovery_domain) {
            state->meta->srv_data->dns_domain = NULL;
        }

        fo_set_port_status(state->meta, PORT_NOT_WORKING);
        goto fail;
    }

    ret = resolv_sort_srv_reply(state, &reply_list);
    if (ret != EOK) {
        DEBUG(1, ("Could not sort the answers from DNS [%d]: %s\n",
                  ret, strerror(ret)));
        fo_set_port_status(state->meta, PORT_NOT_WORKING);
        goto fail;
    }

    for (reply = reply_list; reply; reply = reply->next) {
        server = create_fo_server(state->service, reply->host,
                                  reply->port, state->meta->user_data,
                                  true);
        if (!server) {
            ret = ENOMEM;
            goto fail;
        }
        server->srv_data = state->meta->srv_data;

        DLIST_ADD_END(srv_list, server, struct fo_server *);
        DEBUG(6, ("Inserted server '%s:%d' for service %s\n",
                  server->common->name,
                  server->port,
                  state->service->name));
    }

    if (srv_list) {
        DLIST_ADD_LIST_AFTER(state->service->server_list, state->meta,
                             srv_list, struct fo_server *);

        DLIST_REMOVE(state->service->server_list, state->meta);
        if (state->service->last_tried_server == state->meta) {
            state->service->last_tried_server = srv_list;
        }

        state->out = srv_list;
        set_srv_data_status(state->meta->srv_data, SRV_RESOLVED);
        tevent_req_done(req);
        return;
    } else {
        ret = EIO;
        goto fail;
    }

fail:
    state->out = state->meta;
    set_srv_data_status(state->meta->srv_data, SRV_RESOLVE_ERROR);
    tevent_req_error(req, ret);
}

static int
resolve_srv_recv(struct tevent_req *req, struct fo_server **server)
{
    struct resolve_srv_state *state = tevent_req_data(req,
                                                struct resolve_srv_state);

    /* always return the server if asked for, otherwise the caller
     * cannot mark it as faulty in case we return an error */
    if (server) {
        *server = state->out;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/*******************************************************************
 *     Get Fully Qualified Domain Name of the host machine         *
 *******************************************************************/
struct resolve_get_domain_state {
    char *fqdn;
    char hostname[HOST_NAME_MAX];
};

static void resolve_get_domain_done(struct tevent_req *subreq);

struct tevent_req *
resolve_get_domain_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct fo_ctx *foctx,
                      struct resolv_ctx *resolv)
{
    int ret;
    struct resolve_get_domain_state *state;
    struct tevent_req *req, *subreq;

    req = tevent_req_create(mem_ctx, &state, struct resolve_get_domain_state);
    if (!req) {
        return NULL;
    }

    ret = gethostname(state->hostname, HOST_NAME_MAX);
    if (ret) {
        ret = errno;
        DEBUG(2, ("gethostname() failed: [%d]: %s\n",ret, strerror(ret)));
        return NULL;
    }
    state->hostname[HOST_NAME_MAX-1] = '\0';
    DEBUG(7, ("Host name is: %s\n", state->hostname));

    subreq = resolv_gethostbyname_send(state, ev, resolv,
                                       state->hostname,
                                       foctx->opts->family_order,
                                       default_host_dbs);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, resolve_get_domain_done, req);

    return req;
}

static void resolve_get_domain_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct resolve_get_domain_state *state = tevent_req_data(req,
                                                      struct resolve_get_domain_state);
    struct resolv_hostent *rhostent;
    int ret;
    int resolv_status;

    ret = resolv_gethostbyname_recv(subreq, req, &resolv_status,
                                    NULL, &rhostent);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not get fully qualified name for host name %s "
               "error [%d]: %s, resolver returned: [%d]: %s\n",
               state->hostname, ret, strerror(ret), resolv_status,
               resolv_strerror(resolv_status)));
        /* We'll proceed with hostname in this case */
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, ("The full FQDN is: %s\n", rhostent->name));
        state->fqdn = rhostent->name;
    }
    tevent_req_done(req);
}

int resolve_get_domain_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            char **dns_domain)
{
    struct resolve_get_domain_state *state = tevent_req_data(req,
                                                    struct resolve_get_domain_state);
    char *fqdn;
    char *domptr;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    fqdn = state->fqdn ? state->fqdn : state->hostname;
    domptr = strchr(fqdn, '.');

    if (!domptr || (*(domptr+1) == '\0')) {
        /* If the FQDN did not contain a dot or the dot was the last character
        * (broken DNS server perhaps */
        *dns_domain = talloc_strdup(mem_ctx, fqdn);
    } else {
        domptr++;
        *dns_domain = talloc_strdup(mem_ctx, domptr);
    }

    if (*dns_domain == NULL) {
        return ENOMEM;
    }

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
    struct fo_server *siter;

    DEBUG(4, ("Marking port %d of server '%s' as '%s'\n", server->port,
              SERVER_NAME(server), str_port_status(status)));

    server->port_status = status;
    gettimeofday(&server->last_status_change, NULL);
    if (status == PORT_WORKING) {
        fo_set_server_status(server, SERVER_WORKING);
        server->service->active_server = server;
    }

    if (!server->common || !server->common->name) return;

    /* It is possible to introduce duplicates when expanding SRV results
     * into fo_server structures. Find the duplicates and set the same
     * status */
    DLIST_FOR_EACH(siter, server->service->server_list) {
        if (siter == server) continue;
        if (!siter->common || !siter->common->name) continue;

        if (siter->port == server->port &&
            (strcasecmp(siter->common->name, server->common->name) == 0)) {
            DEBUG(7, ("Marking port %d of duplicate server '%s' as '%s'\n",
                      siter->port, SERVER_NAME(siter),
                      str_port_status(status)));
            siter->port_status = status;
            gettimeofday(&siter->last_status_change, NULL);
        }
    }
}

void fo_try_next_server(struct fo_service *service)
{
    struct fo_server *server;

    if (!service) {
        DEBUG(1, ("Bug: No service supplied\n"));
        return;
    }

    server = service->active_server;
    if (!server) {
        return;
    }

    service->active_server = 0;

    if (server->port_status == PORT_WORKING) {
        server->port_status = PORT_NEUTRAL;
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

const char *
fo_get_server_name(struct fo_server *server)
{
    if (!server->common) {
        return NULL;
    }
    return server->common->name;
}

const char *fo_get_server_str_name(struct fo_server *server)
{
    if (!server->common) {
        if (fo_is_srv_lookup(server)) {
            return "SRV lookup meta-server";
        }
        return "unknown name";
    }

    return server->common->name;
}

struct resolv_hostent *
fo_get_server_hostent(struct fo_server *server)
{
    if (server->common == NULL) {
        DEBUG(1, ("Bug: Trying to get hostent from a name-less server\n"));
        return NULL;
    }

    return server->common->rhostent;
}

bool
fo_is_server_primary(struct fo_server *server)
{
    return server->primary;
}

time_t
fo_get_server_hostname_last_change(struct fo_server *server)
{
    if (server->common == NULL) {
        return 0;
    }
    return server->common->last_status_change.tv_sec;
}

void fo_reset_services(struct fo_ctx *fo_ctx)
{
    struct fo_service *service;
    struct fo_server *server;

    DLIST_FOR_EACH(service, fo_ctx->service_list) {
        DLIST_FOR_EACH(server, service->server_list) {
            if (server->srv_data != NULL) {
                set_srv_data_status(server->srv_data, SRV_NEUTRAL);
            } else {
                fo_set_server_status(server, SERVER_NAME_NOT_RESOLVED);
                fo_set_port_status(server, PORT_NEUTRAL);
            }
        }
    }
}

bool fo_svc_has_server(struct fo_service *service, struct fo_server *server)
{
    struct fo_server *srv;

    DLIST_FOR_EACH(srv, service->server_list) {
        if (srv == server) return true;
    }

    return false;
}
