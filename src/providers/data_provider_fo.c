/*
    SSSD

    Data Provider Helpers

    Copyright (C) Simo Sorce <ssorce@redhat.com> 2009

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

#include <netdb.h>
#include <arpa/inet.h>
#include "providers/dp_backend.h"
#include "resolv/async_resolv.h"

struct be_svc_callback {
    struct be_svc_callback *prev;
    struct be_svc_callback *next;

    struct be_svc_data *svc;

    be_svc_callback_fn_t *fn;
    void *private_data;
};

struct be_svc_data {
    struct be_svc_data *prev;
    struct be_svc_data *next;

    const char *name;
    struct fo_service *fo_service;

    struct fo_server *last_good_srv;
    bool run_callbacks;

    struct be_svc_callback *callbacks;
};

struct be_failover_ctx {
    struct fo_ctx *fo_ctx;
    struct resolv_ctx *resolv;

    struct be_svc_data *svcs;
};

int be_fo_is_srv_identifier(const char *server)
{
    return server && strcasecmp(server, BE_SRV_IDENTIFIER) == 0;
}

static int be_fo_get_options(TALLOC_CTX *mem_ctx, struct be_ctx *ctx,
                             struct fo_options *opts)
{
    char *str_opt;
    int ret;

    /* todo get timeout from configuration */
    opts->retry_timeout = 30;
    opts->srv_retry_timeout = 14400;

    ret = confdb_get_string(ctx->cdb, mem_ctx, ctx->conf_path,
                            CONFDB_DOMAIN_FAMILY_ORDER,
                            "ipv4_first", &str_opt);
    if (ret != EOK) {
        return ret;
    }

    DEBUG(7, ("Lookup order: %s\n", str_opt));

    if (strcasecmp(str_opt, "ipv4_first") == 0) {
        opts->family_order = IPV4_FIRST;
    } else if (strcasecmp(str_opt, "ipv4_only") == 0) {
        opts->family_order = IPV4_ONLY;
    } else if (strcasecmp(str_opt, "ipv6_first") == 0) {
        opts->family_order = IPV6_FIRST;
    } else if (strcasecmp(str_opt, "ipv6_only") == 0) {
        opts->family_order = IPV6_ONLY;
    } else {
        DEBUG(1, ("Unknown value for option %s: %s\n",
                  CONFDB_DOMAIN_FAMILY_ORDER, str_opt));
        talloc_free(str_opt);
        return EINVAL;
    }

    talloc_free(str_opt);
    return EOK;
}

int be_init_failover(struct be_ctx *ctx)
{
    int ret;
    int fo_timeout;
    struct fo_options fopts;

    if (ctx->be_fo != NULL) {
        return EOK;
    }

    ctx->be_fo = talloc_zero(ctx, struct be_failover_ctx);
    if (!ctx->be_fo) {
        return ENOMEM;
    }

    ret = confdb_get_int(ctx->cdb, ctx, ctx->conf_path,
                         CONFDB_DOMAIN_RESOLV_TIMEOUT,
                         5, &fo_timeout);
    if (ret != EOK) {
        return ret;
    }

    ret = resolv_init(ctx, ctx->ev, fo_timeout, &ctx->be_fo->resolv);
    if (ret != EOK) {
        talloc_zfree(ctx->be_fo);
        return ret;
    }

    ret = be_fo_get_options(ctx->be_fo, ctx, &fopts);
    if (ret != EOK) {
        talloc_zfree(ctx->be_fo);
        return ret;
    }

    ctx->be_fo->fo_ctx = fo_context_init(ctx->be_fo, &fopts);
    if (!ctx->be_fo->fo_ctx) {
        talloc_zfree(ctx->be_fo);
        return ENOMEM;
    }

    return EOK;
}

static int be_svc_data_destroy(void *memptr)
{
    struct be_svc_data *svc;

    svc = talloc_get_type(memptr, struct be_svc_data);

    while (svc->callbacks) {
        /* callbacks removes themselves from the list,
         * so this while will freem them all and then terminate */
        talloc_free(svc->callbacks);
    }

    return 0;
}

int be_fo_add_service(struct be_ctx *ctx, const char *service_name)
{
    struct fo_service *service;
    struct be_svc_data *svc;
    int ret;

    DLIST_FOR_EACH(svc, ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            DEBUG(6, ("Failover service already initialized!\n"));
            /* we already have a service up and configured,
             * can happen when using both id and auth provider
             */
            return EOK;
        }
    }

    /* if not in the be service list, try to create new one */

    ret = fo_new_service(ctx->be_fo->fo_ctx, service_name, &service);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(1, ("Failed to create failover service!\n"));
        return ret;
    }

    svc = talloc_zero(ctx->be_fo, struct be_svc_data);
    if (!svc) {
        return ENOMEM;
    }
    talloc_set_destructor((TALLOC_CTX *)svc, be_svc_data_destroy);

    svc->name = talloc_strdup(svc, service_name);
    if (!svc->name) {
        talloc_zfree(svc);
        return ENOMEM;
    }
    svc->fo_service = service;

    DLIST_ADD(ctx->be_fo->svcs, svc);

    return EOK;
}

static int be_svc_callback_destroy(void *memptr)
{
    struct be_svc_callback *callback;

    callback = talloc_get_type(memptr, struct be_svc_callback);

    if (callback->svc) {
        DLIST_REMOVE(callback->svc->callbacks, callback);
    }

    return 0;
}

int be_fo_service_add_callback(TALLOC_CTX *memctx,
                               struct be_ctx *ctx, const char *service_name,
                               be_svc_callback_fn_t *fn, void *private_data)
{
    struct be_svc_callback *callback;
    struct be_svc_data *svc;

    DLIST_FOR_EACH(svc, ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            break;
        }
    }
    if (NULL == svc) {
        return ENOENT;
    }

    callback = talloc_zero(memctx, struct be_svc_callback);
    if (!callback) {
        return ENOMEM;
    }
    talloc_set_destructor((TALLOC_CTX *)callback, be_svc_callback_destroy);

    callback->svc = svc;
    callback->fn = fn;
    callback->private_data = private_data;

    DLIST_ADD(svc->callbacks, callback);

    return EOK;
}

int be_fo_add_srv_server(struct be_ctx *ctx, const char *service_name,
                         const char *query_service, const char *proto,
                         const char *domain, void *user_data)
{
    struct be_svc_data *svc;
    int ret;

    DLIST_FOR_EACH(svc, ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            break;
        }
    }
    if (NULL == svc) {
        return ENOENT;
    }

    ret = fo_add_srv_server(svc->fo_service, query_service,
                            domain, proto, user_data);
    if (ret && ret != EEXIST) {
        DEBUG(1, ("Failed to add SRV lookup reference to failover service\n"));
        return ret;
    }

    return EOK;
}

int be_fo_add_server(struct be_ctx *ctx, const char *service_name,
                     const char *server, int port, void *user_data)
{
    struct be_svc_data *svc;
    int ret;

    DLIST_FOR_EACH(svc, ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            break;
        }
    }
    if (NULL == svc) {
        return ENOENT;
    }

    ret = fo_add_server(svc->fo_service, server, port, user_data);
    if (ret && ret != EEXIST) {
        DEBUG(1, ("Failed to add server to failover service\n"));
        return ret;
    }

    return EOK;
}

struct be_resolve_server_state {
    struct tevent_context *ev;
    struct be_ctx *ctx;

    struct be_svc_data *svc;
    int attempts;

    struct fo_server *srv;
};

static void be_resolve_server_done(struct tevent_req *subreq);

struct tevent_req *be_resolve_server_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct be_ctx *ctx,
                                          const char *service_name)
{
    struct tevent_req *req, *subreq;
    struct be_resolve_server_state *state;
    struct be_svc_data *svc;

    req = tevent_req_create(memctx, &state, struct be_resolve_server_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    DLIST_FOR_EACH(svc, ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            state->svc = svc;
            break;
        }
    }

    if (NULL == svc) {
        tevent_req_error(req, EINVAL);
        tevent_req_post(req, ev);
        return req;
    }

    state->attempts = 0;

    subreq = fo_resolve_service_send(state, ev,
                                     ctx->be_fo->resolv,
                                     ctx->be_fo->fo_ctx,
                                     svc->fo_service);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, be_resolve_server_done, req);

    return req;
}

static void be_resolve_server_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct be_resolve_server_state *state = tevent_req_data(req,
                                             struct be_resolve_server_state);
    struct be_svc_callback *callback;
    int ret;

    ret = fo_resolve_service_recv(subreq, &state->srv);
    talloc_zfree(subreq);
    switch (ret) {
    case EOK:
        if (!state->srv) {
            tevent_req_error(req, EFAULT);
            return;
        }
        break;

    case ENOENT:
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, EIO);
        return;

    default:
        /* mark server as bad and retry */
        if (!state->srv) {
            tevent_req_error(req, EFAULT);
            return;
        }
        DEBUG(6, ("Couldn't resolve server (%s), resolver returned (%d)\n",
                  fo_get_server_name(state->srv), ret));

        state->attempts++;
        if (state->attempts >= 10) {
            DEBUG(2, ("Failed to find a server after 10 attempts\n"));
            tevent_req_error(req, EIO);
            return;
        }

        /* now try next one */
        DEBUG(6, ("Trying with the next one!\n"));
        subreq = fo_resolve_service_send(state, state->ev,
                                         state->ctx->be_fo->resolv,
                                         state->ctx->be_fo->fo_ctx,
                                         state->svc->fo_service);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, be_resolve_server_done, req);

        return;
    }

    /* all fine we got the server */

    if (debug_level >= 4) {
        struct hostent *srvaddr;
        char ipaddr[128];
        srvaddr = fo_get_server_hostent(state->srv);
        inet_ntop(srvaddr->h_addrtype, srvaddr->h_addr_list[0],
                  ipaddr, 128);

        DEBUG(4, ("Found address for server %s: [%s]\n",
                  fo_get_server_name(state->srv), ipaddr));
    }

    /* now call all svc callbacks if server changed or if it is explicitly
     * requested */
    if (state->srv != state->svc->last_good_srv || state->svc->run_callbacks) {
        state->svc->last_good_srv = state->srv;
        state->svc->run_callbacks = false;

        DLIST_FOR_EACH(callback, state->svc->callbacks) {
            callback->fn(callback->private_data, state->srv);
        }
    }

    tevent_req_done(req);
}

int be_resolve_server_recv(struct tevent_req *req, struct fo_server **srv)
{
    struct be_resolve_server_state *state = tevent_req_data(req,
                                             struct be_resolve_server_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (srv) {
        *srv = state->srv;
    }

    return EOK;
}

int be_fo_run_callbacks_at_next_request(struct be_ctx *ctx,
                                        const char *service_name)
{
    struct be_svc_data *svc;

    DLIST_FOR_EACH(svc, ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            break;
        }
    }
    if (NULL == svc) {
        return ENOENT;
    }

    svc->run_callbacks = true;

    return EOK;
}
