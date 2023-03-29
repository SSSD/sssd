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
#include "providers/backend.h"
#include "resolv/async_resolv.h"

struct be_svc_callback {
    struct be_svc_callback *prev;
    struct be_svc_callback *next;

    struct be_svc_data *svc;

    be_svc_callback_fn_t *fn;
    void *private_data;
};

static const char *proto_table[] = { FO_PROTO_TCP, FO_PROTO_UDP, NULL };

int be_fo_is_srv_identifier(const char *server)
{
    return server && strcasecmp(server, BE_SRV_IDENTIFIER) == 0;
}

static int be_fo_get_options(struct be_ctx *ctx,
                             struct fo_options *opts)
{
    opts->service_resolv_timeout = dp_opt_get_int(ctx->be_res->opts,
                                                  DP_RES_OPT_RESOLVER_TIMEOUT);
    opts->use_search_list = dp_opt_get_bool(ctx->be_res->opts,
                                            DP_RES_OPT_RESOLVER_USE_SEARCH_LIST);
    opts->retry_timeout = 30;
    opts->srv_retry_neg_timeout = 15;
    opts->family_order = ctx->be_res->family_order;

    return EOK;
}

int be_init_failover(struct be_ctx *ctx)
{
    int ret;
    struct fo_options fopts;

    if (ctx->be_fo != NULL) {
        return EOK;
    }

    ctx->be_fo = talloc_zero(ctx, struct be_failover_ctx);
    if (ctx->be_fo == NULL) {
        return ENOMEM;
    }

    ret = be_res_init(ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing resolver context\n");
        talloc_zfree(ctx->be_fo);
        return ret;
    }
    ctx->be_fo->be_res = ctx->be_res;

    ret = be_fo_get_options(ctx, &fopts);
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

/*
 * Find registered be_svc_data by service name.
 */
static struct be_svc_data *be_fo_find_svc_data(struct be_ctx *ctx,
                                               const char *service_name)
{
    struct be_svc_data *svc;

    if (!ctx || !ctx->be_fo) {
        return 0;
    }

    DLIST_FOR_EACH(svc, ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            return svc;
        }
    }

    return 0;
}

int be_fo_add_service(struct be_ctx *ctx, const char *service_name,
                      datacmp_fn user_data_cmp)
{
    struct fo_service *service;
    struct be_svc_data *svc;
    int ret;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (svc) {
        DEBUG(SSSDBG_TRACE_FUNC, "Failover service already initialized!\n");
        /* we already have a service up and configured,
         * can happen when using both id and auth provider
         */
        return EOK;
    }

    /* if not in the be service list, try to create new one */

    ret = fo_new_service(ctx->be_fo->fo_ctx, service_name, user_data_cmp,
                         &service);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create failover service!\n");
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

    svc = be_fo_find_svc_data(ctx, service_name);
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

void be_fo_set_srv_lookup_plugin(struct be_ctx *ctx,
                                 fo_srv_lookup_plugin_send_t send_fn,
                                 fo_srv_lookup_plugin_recv_t recv_fn,
                                 void *pvt,
                                 const char *plugin_name)
{
    bool bret;

    DEBUG(SSSDBG_TRACE_FUNC, "Trying to set SRV lookup plugin to %s\n",
                              plugin_name);

    bret = fo_set_srv_lookup_plugin(ctx->be_fo->fo_ctx, send_fn, recv_fn, pvt);
    if (bret) {
        DEBUG(SSSDBG_TRACE_FUNC, "SRV lookup plugin is now %s\n",
                                  plugin_name);
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to set SRV lookup plugin, "
              "another plugin may be already in place\n");
    }
}

errno_t be_fo_set_dns_srv_lookup_plugin(struct be_ctx *be_ctx,
                                        const char *hostname)
{
    struct fo_resolve_srv_dns_ctx *srv_ctx = NULL;
    char resolved_hostname[HOST_NAME_MAX + 1];
    errno_t ret;

    if (hostname == NULL) {
        ret = gethostname(resolved_hostname, sizeof(resolved_hostname));
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "gethostname() failed: [%d]: %s\n", ret, strerror(ret));
            return ret;
        }
        resolved_hostname[HOST_NAME_MAX] = '\0';
        hostname = resolved_hostname;
    }

    srv_ctx = fo_resolve_srv_dns_ctx_init(be_ctx, be_ctx->be_res->resolv,
                                          be_ctx->be_res->family_order,
                                          default_host_dbs, hostname,
                                          be_ctx->domain->name);
    if (srv_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
        return ENOMEM;
    }

    be_fo_set_srv_lookup_plugin(be_ctx, fo_resolve_srv_dns_send,
                                fo_resolve_srv_dns_recv, srv_ctx, "DNS");

    return EOK;
}

int be_fo_add_srv_server(struct be_ctx *ctx,
                         const char *service_name,
                         const char *query_service,
                         const char *default_discovery_domain,
                         enum be_fo_protocol proto,
                         bool proto_fallback, void *user_data)
{
    struct be_svc_data *svc;
    const char *domain;
    int ret;
    int i;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (NULL == svc) {
        return ENOENT;
    }

    domain = dp_opt_get_string(ctx->be_res->opts, DP_RES_OPT_DNS_DOMAIN);
    if (!domain) {
        domain = default_discovery_domain;
    }

    /* Add the first protocol as the primary lookup */
    ret = fo_add_srv_server(svc->fo_service, query_service,
                            domain, ctx->domain->name,
                            proto_table[proto], user_data);
    if (ret && ret != EEXIST) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add SRV lookup reference to failover service "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    if (proto_fallback) {
        i = (proto + 1) % BE_FO_PROTO_SENTINEL;
        /* All the rest as fallback */
        while (i != proto) {
            ret = fo_add_srv_server(svc->fo_service, query_service,
                                    domain, ctx->domain->name,
                                    proto_table[i], user_data);
            if (ret && ret != EEXIST) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to add SRV lookup reference to failover "
                      "service [%d]: %s\n", ret, sss_strerror(ret));
                return ret;
            }

            i = (i + 1) % BE_FO_PROTO_SENTINEL;
        }
    }

    return EOK;
}

int be_fo_get_server_count(struct be_ctx *ctx, const char *service_name)
{
    struct be_svc_data *svc_data;

    svc_data = be_fo_find_svc_data(ctx, service_name);
    if (!svc_data) {
        return 0;
    }

    return fo_get_server_count(svc_data->fo_service);
}

int be_fo_add_server(struct be_ctx *ctx, const char *service_name,
                     const char *server, int port, void *user_data,
                     bool primary)
{
    struct be_svc_data *svc;
    int ret;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (NULL == svc) {
        return ENOENT;
    }

    ret = fo_add_server(svc->fo_service, server, port,
                        user_data, primary);
    if (ret && ret != EEXIST) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add server to failover service [%d]: %s\n",
              ret, sss_strerror(ret));
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
    bool first_try;
};

struct be_primary_server_ctx {
    struct be_ctx *bctx;
    struct tevent_context *ev;

    struct be_svc_data *svc;
    unsigned long timeout;

    int attempts;
};

errno_t be_resolve_server_process(struct tevent_req *subreq,
                                  struct be_resolve_server_state *state,
                                  struct tevent_req **new_subreq);
static void be_primary_server_done(struct tevent_req *subreq);
static errno_t
be_primary_server_timeout_activate(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *bctx,
                                   struct be_svc_data *svc,
                                   const unsigned long timeout_seconds);

static void
be_primary_server_timeout(struct tevent_context *ev,
                          struct tevent_timer *te,
                          struct timeval tv, void *pvt)
{
    struct be_primary_server_ctx *ctx = talloc_get_type(pvt, struct be_primary_server_ctx);
    struct tevent_req *subreq;

    ctx->bctx->be_fo->primary_server_handler = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Looking for primary server!\n");
    subreq = fo_resolve_service_send(ctx->bctx, ctx->ev,
                                     ctx->bctx->be_fo->be_res->resolv,
                                     ctx->bctx->be_fo->fo_ctx,
                                     ctx->svc->fo_service);
    if (subreq == NULL) {
        return;
    }
    tevent_req_set_callback(subreq, be_primary_server_done, ctx);
}

static void be_primary_server_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct be_primary_server_ctx *ctx;
    struct be_resolve_server_state *resolve_state;
    struct tevent_req *new_subreq;

    ctx = tevent_req_callback_data(subreq, struct be_primary_server_ctx);

    resolve_state = talloc_zero(ctx->bctx, struct be_resolve_server_state);
    if (resolve_state == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return;
    }

    resolve_state->attempts = ctx->attempts;
    resolve_state->ctx = ctx->bctx;
    resolve_state->ev = ctx->ev;
    resolve_state->first_try = true;
    resolve_state->srv = NULL;
    resolve_state->svc = ctx->svc;

    ret = be_resolve_server_process(subreq, resolve_state, &new_subreq);
    talloc_free(subreq);
    if (ret == EAGAIN) {
        ctx->attempts++;
        tevent_req_set_callback(new_subreq, be_primary_server_done, ctx);
        return;
    } else if (ret == EIO || (ret == EOK &&
        !fo_is_server_primary(resolve_state->srv))) {

        /* Schedule another lookup
         * (either no server could be found or it was not primary)
         */
        ret = be_primary_server_timeout_activate(ctx->bctx, ctx->ev, ctx->bctx,
                                                 ctx->svc, ctx->timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not schedule primary server lookup [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
    } else if (ret == EOK) {
        be_run_reconnect_cb(ctx->bctx);
    }
    talloc_zfree(ctx);

    /* If an error occurred just end the routine */
}

static errno_t
be_primary_server_timeout_activate(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *bctx,
                                   struct be_svc_data *svc,
                                   const unsigned long timeout_seconds)
{
    struct timeval tv;
    struct be_primary_server_ctx *ctx;
    struct be_failover_ctx *fo_ctx = bctx->be_fo;

    if (fo_ctx->primary_server_handler != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "The primary server reconnection "
                                  "is already scheduled\n");
        return EOK;
    }

    ctx = talloc_zero(mem_ctx, struct be_primary_server_ctx);
    if (ctx == NULL) {
        return ENOMEM;
    }

    ctx->bctx = bctx;
    ctx->ev = ev;
    ctx->svc = svc;
    ctx->timeout = timeout_seconds;

    tv = tevent_timeval_current();
    tv = tevent_timeval_add(&tv, timeout_seconds, 0);
    fo_ctx->primary_server_handler = tevent_add_timer(ev, bctx, tv,
                                          be_primary_server_timeout, ctx);
    if (fo_ctx->primary_server_handler == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
        talloc_free(ctx);
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Primary server reactivation timeout set "
                                  "to %lu seconds\n", timeout_seconds);
    return EOK;
}


static void be_resolve_server_done(struct tevent_req *subreq);

struct tevent_req *be_resolve_server_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct be_ctx *ctx,
                                          const char *service_name,
                                          bool first_try)
{
    struct tevent_req *req, *subreq;
    struct be_resolve_server_state *state;
    struct be_svc_data *svc;

    req = tevent_req_create(memctx, &state, struct be_resolve_server_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (NULL == svc) {
        tevent_req_error(req, EINVAL);
        tevent_req_post(req, ev);
        return req;
    }

    state->svc = svc;
    state->attempts = 0;
    state->first_try = first_try;

    subreq = fo_resolve_service_send(state, ev,
                                     ctx->be_fo->be_res->resolv,
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
    struct tevent_req *new_subreq;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct be_resolve_server_state *state = tevent_req_data(req,
                                             struct be_resolve_server_state);
    time_t timeout = fo_get_service_retry_timeout(state->svc->fo_service) + 1;
    int ret;

    ret = be_resolve_server_process(subreq, state, &new_subreq);
    talloc_zfree(subreq);
    if (ret == EAGAIN) {
        tevent_req_set_callback(new_subreq, be_resolve_server_done, req);
        return;
    } else if (ret != EOK) {
        goto fail;
    }

    if (!fo_is_server_primary(state->srv)) {
        /* FIXME: make the timeout configurable */
        ret = be_primary_server_timeout_activate(state->ctx, state->ev,
                                                 state->ctx, state->svc,
                                                 timeout);
        if (ret != EOK) {
            goto fail;
        }
    }

    tevent_req_done(req);
    return;

fail:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Server resolution failed: [%d]: All servers down\n", ret);
    } else if (ret == EFAULT || ret == EIO || ret == EPERM) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Server [%s] resolution failed: [%d]: %s\n",
              state->srv ? fo_get_server_name(state->srv) : "NULL",
              ret, sss_strerror(ret));

    } else {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Server resolution failed: [%d]: %s\n", ret, sss_strerror(ret));
    }
    state->svc->first_resolved = NULL;
    tevent_req_error(req, ret);
}

static void dump_be_svc_data(const struct be_svc_data *svc)
{
    DEBUG(SSSDBG_OP_FAILURE, "be_svc_data: name=[%s] last_good_srv=[%s] "
                             "last_good_port=[%d] last_status_change=[%"SPRItime"]\n",
                             svc->name, svc->last_good_srv, svc->last_good_port,
                             svc->last_status_change);
}

errno_t be_resolve_server_process(struct tevent_req *subreq,
                                  struct be_resolve_server_state *state,
                                  struct tevent_req **new_subreq)
{
    errno_t ret;
    time_t srv_status_change;
    struct be_svc_callback *callback;
    char *srvname;

    ret = fo_resolve_service_recv(subreq, state, &state->srv);
    switch (ret) {
    case EOK:
        if (!state->srv) {
            return EFAULT;
        }
        break;

    case ENOENT:
        /* all servers have been tried and none
         * was found good, go offline */
        return EIO;

    default:
        /* mark server as bad and retry */
        if (!state->srv) {
            return EFAULT;
        }
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Couldn't resolve server (%s), resolver returned [%d]: %s\n",
              fo_get_server_str_name(state->srv), ret, sss_strerror(ret));

        state->attempts++;
        if (state->attempts >= 10) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to find a server after 10 attempts\n");
            return EIO;
        }

        /* now try next one */
        DEBUG(SSSDBG_TRACE_LIBS, "Trying with the next one!\n");
        subreq = fo_resolve_service_send(state, state->ev,
                                         state->ctx->be_fo->be_res->resolv,
                                         state->ctx->be_fo->fo_ctx,
                                         state->svc->fo_service);
        if (!subreq) {
            return ENOMEM;
        }

        if (new_subreq) {
            *new_subreq = subreq;
        }

        return EAGAIN;
    }

    /* all fine we got the server */
    if (state->svc->first_resolved == NULL || state->first_try == true) {
        DEBUG(SSSDBG_TRACE_LIBS, "Saving the first resolved server\n");
        state->svc->first_resolved = state->srv;
    } else if (state->svc->first_resolved == state->srv) {
        DEBUG(SSSDBG_OP_FAILURE,
              "The fail over cycled through all available servers\n");
        return ENOENT;
    }

    if (fo_get_server_name(state->srv)) {
        struct resolv_hostent *srvaddr;
        srvaddr = fo_get_server_hostent(state->srv);
        if (!srvaddr) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "No hostent available for server (%s)\n",
                  fo_get_server_str_name(state->srv));
            return EFAULT;
        }

        if (!srvaddr->addr_list[0]) {
            DEBUG(SSSDBG_FUNC_DATA, "Found socket for server %s: [%s]\n",
                  fo_get_server_str_name(state->srv), srvaddr->name);
        }
        else {
            char ipaddr[128];
            inet_ntop(srvaddr->family, srvaddr->addr_list[0]->ipaddr,
                      ipaddr, 128);

            DEBUG(SSSDBG_FUNC_DATA, "Found address for server %s: [%s] TTL %d\n",
                  fo_get_server_str_name(state->srv), ipaddr,
                  srvaddr->addr_list[0]->ttl);
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing server name.\n");
        dump_be_svc_data(state->svc);
        dump_fo_server(state->srv);
        dump_fo_server_list(state->srv);
        return ENOENT;
    }

    srv_status_change = fo_get_server_hostname_last_change(state->srv);

    /* now call all svc callbacks if server changed or if it is explicitly
     * requested or if the server is the same but changed status since last time*/
    if (state->svc->last_good_srv == NULL ||
        strcmp(fo_get_server_name(state->srv), state->svc->last_good_srv) != 0 ||
        fo_get_server_port(state->srv) != state->svc->last_good_port ||
        state->svc->run_callbacks ||
        srv_status_change > state->svc->last_status_change) {
        state->svc->last_status_change = srv_status_change;
        state->svc->run_callbacks = false;

        srvname = talloc_strdup(state->svc, fo_get_server_name(state->srv));
        if (srvname == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to copy server name\n");
            return ENOMEM;
        }

        talloc_free(state->svc->last_good_srv);
        state->svc->last_good_srv = srvname;
        state->svc->last_good_port = fo_get_server_port(state->srv);

        DLIST_FOR_EACH(callback, state->svc->callbacks) {
            callback->fn(callback->private_data, state->srv);
        }
    }

    return EOK;
}

int be_resolve_server_recv(struct tevent_req *req,
                           TALLOC_CTX *ref_ctx,
                           struct fo_server **srv)
{
    struct be_resolve_server_state *state = tevent_req_data(req,
                                             struct be_resolve_server_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (srv) {
        fo_ref_server(ref_ctx, state->srv);
        *srv = state->srv;
    }

    return EOK;
}

void be_fo_try_next_server(struct be_ctx *ctx, const char *service_name)
{
    struct be_svc_data *svc;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (svc) {
        fo_try_next_server(svc->fo_service);
    }
}

const char *be_fo_get_active_server_name(struct be_ctx *ctx,
                                         const char *service_name)
{
    struct be_svc_data *svc;
    struct fo_server *server;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (svc != NULL) {
        server = fo_get_active_server(svc->fo_service);
        if (server != NULL) {
            return fo_get_server_name(server);
        }
    }

    return NULL;
}

int be_fo_run_callbacks_at_next_request(struct be_ctx *ctx,
                                        const char *service_name)
{
    struct be_svc_data *svc;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (NULL == svc) {
        return ENOENT;
    }

    svc->run_callbacks = true;

    return EOK;
}

void reset_fo(struct be_ctx *be_ctx)
{
    fo_reset_services(be_ctx->be_fo->fo_ctx);
}

void be_fo_reset_svc(struct be_ctx *be_ctx,
                     const char *svc_name)
{
    struct fo_service *service;
    int ret;

    DEBUG(SSSDBG_TRACE_LIBS,
          "Resetting all servers in service %s\n", svc_name);

    ret = fo_get_service(be_ctx->be_fo->fo_ctx, svc_name, &service);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot retrieve service [%s]\n", svc_name);
        return;
    }

    fo_reset_servers(service);
}

void _be_fo_set_port_status(struct be_ctx *ctx,
                            const char *service_name,
                            struct fo_server *server,
                            enum port_status status,
                            int line,
                            const char *file,
                            const char *function)
{
    struct be_svc_data *be_svc;

    /* Print debug info */
    switch (status) {
    case PORT_NEUTRAL:
        DEBUG(SSSDBG_BE_FO,
              "Setting status: PORT_NEUTRAL. Called from: %s: %s: %d\n",
              file, function, line);
        break;
    case PORT_WORKING:
        DEBUG(SSSDBG_BE_FO,
              "Setting status: PORT_WORKING. Called from: %s: %s: %d\n",
              file, function, line);
        break;
    case PORT_NOT_WORKING:
        DEBUG(SSSDBG_BE_FO,
              "Setting status: PORT_NOT_WORKING. Called from: %s: %s: %d\n",
              file, function, line);
        break;
    }

    be_svc = be_fo_find_svc_data(ctx, service_name);
    if (be_svc == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "No service associated with name %s\n", service_name);
        return;
    }

    if (!fo_svc_has_server(be_svc->fo_service, server)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "The server %p is not valid anymore, cannot set its status\n",
               server);
        return;
    }

    /* Now we know that the server is valid */
    fo_set_port_status(server, status);

    if (status == PORT_WORKING) {
        /* We were successful in connecting to the server. Cycle through all
         * available servers next time */
        be_svc->first_resolved = NULL;
    }
}

/* Resolver back end interface */
static struct dp_option dp_res_default_opts[] = {
    { "lookup_family_order", DP_OPT_STRING, { "ipv4_first" }, NULL_STRING },
    { "dns_resolver_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "dns_resolver_op_timeout", DP_OPT_NUMBER, { .number = 3 }, NULL_NUMBER },
    { "dns_resolver_server_timeout", DP_OPT_NUMBER, { .number = 1000 }, NULL_NUMBER },
    { "dns_resolver_use_search_list", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "dns_discovery_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    DP_OPTION_TERMINATOR
};

static errno_t be_res_get_opts(struct be_resolv_ctx *res_ctx,
                               struct confdb_ctx *cdb,
                               const char *conf_path)
{
    errno_t ret;
    const char *str_family;

    ret = dp_get_options(res_ctx, cdb, conf_path,
                         dp_res_default_opts,
                         DP_RES_OPTS,
                         &res_ctx->opts);
    if (ret != EOK) {
        return ret;
    }

    str_family = dp_opt_get_string(res_ctx->opts, DP_RES_OPT_FAMILY_ORDER);
    DEBUG(SSSDBG_CONF_SETTINGS, "Lookup order: %s\n", str_family);

    if (strcasecmp(str_family, "ipv4_first") == 0) {
        res_ctx->family_order = IPV4_FIRST;
    } else if (strcasecmp(str_family, "ipv4_only") == 0) {
        res_ctx->family_order = IPV4_ONLY;
    } else if (strcasecmp(str_family, "ipv6_first") == 0) {
        res_ctx->family_order = IPV6_FIRST;
    } else if (strcasecmp(str_family, "ipv6_only") == 0) {
        res_ctx->family_order = IPV6_ONLY;
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown value for option %s: %s\n",
              dp_res_default_opts[DP_RES_OPT_FAMILY_ORDER].opt_name, str_family);
        return EINVAL;
    }

    return EOK;
}

errno_t be_res_init(struct be_ctx *ctx)
{
    errno_t ret;

    if (ctx->be_res != NULL) {
        return EOK;
    }

    ctx->be_res = talloc_zero(ctx, struct be_resolv_ctx);
    if (ctx->be_res == NULL) {
        return ENOMEM;
    }

    ret = be_res_get_opts(ctx->be_res, ctx->cdb, ctx->conf_path);
    if (ret != EOK) {
        talloc_zfree(ctx->be_res);
        return ret;
    }

    ret = resolv_init(ctx, ctx->ev,
                      dp_opt_get_int(ctx->be_res->opts,
                                     DP_RES_OPT_RESOLVER_OP_TIMEOUT),
                      dp_opt_get_int(ctx->be_res->opts,
                                     DP_RES_OPT_RESOLVER_SERVER_TIMEOUT),
                      dp_opt_get_bool(ctx->be_res->opts,
                                      DP_RES_OPT_RESOLVER_USE_SEARCH_LIST),
                      &ctx->be_res->resolv);
    if (ret != EOK) {
        talloc_zfree(ctx->be_res);
        return ret;
    }

    return EOK;
}
