/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <talloc.h>
#include <tevent.h>
#include <string.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include "responder/ifp/ifp_domains.h"
#include "responder/ifp/ifp_iface/ifp_iface_async.h"
#include "sss_iface/sss_iface_async.h"

#define RETURN_DOM_PROP(dbus_req, ctx, out, property) ({                    \
    struct sss_domain_info *__dom;                                          \
    errno_t __ret;                                                          \
                                                                            \
    __dom = get_domain_info_from_req((dbus_req), (ctx));                    \
    if (__dom == NULL) {                                                    \
        __ret = ERR_DOMAIN_NOT_FOUND;                                       \
    } else {                                                                \
        *(out) = __dom->property;                                           \
        __ret = EOK;                                                        \
    }                                                                       \
    __ret;                                                                  \
})


struct ifp_list_domains_state {
    struct ifp_ctx *ifp_ctx;
    const char **paths;
};

static void ifp_list_domains_done(struct tevent_req *subreq);

struct tevent_req *
ifp_list_domains_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct sbus_request *sbus_req,
                      struct ifp_ctx *ifp_ctx)
{
    struct ifp_list_domains_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_list_domains_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->ifp_ctx = ifp_ctx;

    subreq = sss_dp_get_domains_send(state, ifp_ctx->rctx, false, NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_list_domains_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_list_domains_done(struct tevent_req *subreq)
{
    struct ifp_list_domains_state *state;
    struct sss_domain_info *dom;
    struct tevent_req *req;
    size_t num_domains;
    size_t pi;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_list_domains_state);

    ret = sss_dp_get_domains_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to refresh domain objects\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_master_domain_update(state->ifp_ctx->rctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to refresh subdomain list\n");
        tevent_req_error(req, ret);
        return;
    }

    num_domains = 0;
    for (dom = state->ifp_ctx->rctx->domains;
            dom != NULL;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        num_domains++;
    }

    state->paths = talloc_zero_array(state, const char *, num_domains + 1);
    if (state->paths == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    pi = 0;
    for (dom = state->ifp_ctx->rctx->domains;
            dom != NULL;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        state->paths[pi] = sbus_opath_compose(state->paths, IFP_PATH_DOMAINS, dom->name);
        if (state->paths[pi] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not create path for dom %s\n",
                  dom->name);
            tevent_req_error(req, ENOMEM);
            return;
        }
        pi++;
    }

    tevent_req_done(req);
    return;
}

errno_t ifp_list_domains_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              const char ***_paths)
{
    struct ifp_list_domains_state *state;
    state = tevent_req_data(req, struct ifp_list_domains_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_paths = talloc_steal(mem_ctx, state->paths);

    return EOK;
}

struct ifp_find_domain_by_name_state {
    struct ifp_ctx *ifp_ctx;
    const char *name;
    const char *path;
};

static void ifp_find_domain_by_name_done(struct tevent_req *subreq);

struct tevent_req *
ifp_find_domain_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ifp_ctx,
                             const char *name)
{
    struct ifp_find_domain_by_name_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_find_domain_by_name_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->ifp_ctx = ifp_ctx;
    state->name = name;

    subreq = sss_dp_get_domains_send(state, ifp_ctx->rctx, false, NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_find_domain_by_name_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_find_domain_by_name_done(struct tevent_req *subreq)
{
    struct ifp_find_domain_by_name_state *state;
    struct sss_domain_info *iter;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_find_domain_by_name_state);

    ret = sss_dp_get_domains_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to refresh domain objects\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_master_domain_update(state->ifp_ctx->rctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to refresh subdomain list\n");
        tevent_req_error(req, ret);
        return;
    }

    /* Reply with the domain that was asked for */
    for (iter = state->ifp_ctx->rctx->domains;
            iter != NULL;
            iter = get_next_domain(iter, SSS_GND_DESCEND)) {
        if (strcasecmp(iter->name, state->name) == 0) {
            break;
        }
    }

    if (iter == NULL) {
         DEBUG(SSSDBG_MINOR_FAILURE, "Domain not found: %s\n", state->name);
         tevent_req_error(req, ERR_DOMAIN_NOT_FOUND);
         return;
    }

    state->path = sbus_opath_compose(state, IFP_PATH_DOMAINS, iter->name);
    if (state->path == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not create path for domain %s, skipping\n", iter->name);
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_find_domain_by_name_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             const char **_path)
{
    struct ifp_find_domain_by_name_state *state;
    state = tevent_req_data(req, struct ifp_find_domain_by_name_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_path = talloc_steal(mem_ctx, state->path);

    return EOK;
}

static struct sss_domain_info *
get_domain_info_from_req(struct sbus_request *dbus_req,
                         struct ifp_ctx *ctx)
{
    struct sss_domain_info *domains = NULL;
    struct sss_domain_info *iter = NULL;
    char *name = NULL;

    name = sbus_opath_object_name(NULL, dbus_req->path, IFP_PATH_DOMAINS);
    if (name == NULL) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Looking for domain %s\n", name);

    domains = ctx->rctx->domains;
    for (iter = domains; iter != NULL;
            iter = get_next_domain(iter, SSS_GND_DESCEND)) {
        if (strcasecmp(iter->name, name) == 0) {
            break;
        }
    }

    talloc_free(name);
    return iter;
}

static errno_t
get_server_list(TALLOC_CTX *mem_ctx,
                struct sbus_request *dbus_req,
                struct ifp_ctx *ctx,
                const char ***_out,
                bool backup)
{
    TALLOC_CTX *tmp_ctx;
    static const char *srv[] = {"_srv_", NULL};
    struct sss_domain_info *dom = NULL;
    char *conf_path = NULL;
    const char *option = NULL;
    const char **out = NULL;
    char **servers = NULL;
    int num_servers;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    dom = get_domain_info_from_req(dbus_req, ctx);
    if (dom == NULL) {
        return ERR_DOMAIN_NOT_FOUND;
    }

    if (dom->parent != NULL) {
        /* subdomains are not present in configuration */
        ret = ENOENT;
        goto done;
    }

    conf_path = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL, dom->name);
    if (conf_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* TODO: replace hardcoded values with option names from the provider */
    if (strcasecmp(dom->provider, "ldap") == 0) {
        option = backup == false ? "ldap_uri" : "ldap_backup_uri";
    } else if (strcasecmp(dom->provider, "ipa") == 0) {
        option = backup == false ? "ipa_server" : "ipa_backup_server";
    } else if (strcasecmp(dom->provider, "ad") == 0) {
        option = backup == false ? "ad_server" : "ad_backup_server";
    } else {
        ret = EINVAL;
        goto done;
    }

    ret = confdb_get_string_as_list(ctx->rctx->cdb, tmp_ctx, conf_path,
                                    option, &servers);
    if (ret != EOK) {
        goto done;
    }

    for (num_servers = 0; servers[num_servers] != NULL; num_servers++);

    if (num_servers == 0) {
        ret = ENOENT;
        goto done;
    }

    out = talloc_zero_array(mem_ctx, const char *, num_servers + 1);
    if (out == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_servers; i++) {
        out[i] = talloc_steal(out, servers[i]);
    }

    *_out = out;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret == ENOENT) {
        *_out = srv;
    }

    return ret;
}

errno_t
ifp_dom_get_name(TALLOC_CTX *mem_ctx,
                 struct sbus_request *sbus_req,
                 struct ifp_ctx *ctx,
                 const char **_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, name);
}

errno_t
ifp_dom_get_provider(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct ifp_ctx *ctx,
                     const char **_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, provider);
}

errno_t
ifp_dom_get_primary_servers(TALLOC_CTX *mem_ctx,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char ***_out)
{
    return get_server_list(mem_ctx, sbus_req, ctx, _out, false);
}

errno_t
ifp_dom_get_backup_servers(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           const char ***_out)
{
    return get_server_list(mem_ctx, sbus_req, ctx, _out, true);
}

errno_t
ifp_dom_get_min_id(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           uint32_t *_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, id_min);
}

errno_t
ifp_dom_get_max_id(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           uint32_t *_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, id_max);
}

errno_t
ifp_dom_get_realm(TALLOC_CTX *mem_ctx,
                  struct sbus_request *sbus_req,
                  struct ifp_ctx *ctx,
                  const char **_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, realm);
}

errno_t
ifp_dom_get_forest(TALLOC_CTX *mem_ctx,
                   struct sbus_request *sbus_req,
                   struct ifp_ctx *ctx,
                   const char **_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, forest);
}

errno_t
ifp_dom_get_login_format(TALLOC_CTX *mem_ctx,
                         struct sbus_request *sbus_req,
                         struct ifp_ctx *ctx,
                         const char **_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, names->re_pattern);
}

errno_t
ifp_dom_get_fqdn_format(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct ifp_ctx *ctx,
                        const char **_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, names->fq_fmt);
}

errno_t
ifp_dom_get_enumerable(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct ifp_ctx *ctx,
                       bool *_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, enumerate);
}

errno_t
ifp_dom_get_use_fqdn(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct ifp_ctx *ctx,
                     bool *_out)
{
    return RETURN_DOM_PROP(sbus_req, ctx, _out, fqnames);
}

errno_t
ifp_dom_get_subdomain(TALLOC_CTX *mem_ctx,
                      struct sbus_request *sbus_req,
                      struct ifp_ctx *ctx,
                      bool *_out)
{
    struct sss_domain_info *dom;

    dom = get_domain_info_from_req(sbus_req, ctx);
    if (dom == NULL) {
        return ERR_DOMAIN_NOT_FOUND;
    }

    *_out = dom->parent != NULL ? true : false;

    return EOK;
}

errno_t
ifp_dom_get_parent_domain(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          const char **_out)
{
    struct sss_domain_info *dom;
    const char *path;

    dom = get_domain_info_from_req(sbus_req, ctx);
    if (dom == NULL) {
        return ERR_DOMAIN_NOT_FOUND;
    }

    if (dom->parent == NULL) {
        *_out = "/";
        return EOK;
    }

    path = sbus_opath_compose(mem_ctx, IFP_PATH_DOMAINS, dom->parent->name);
    if (path == NULL) {
        return ENOMEM;
    }

    *_out = path;

    return EOK;
}

struct ifp_domains_domain_is_online_state {
    bool is_online;
};

static void ifp_domains_domain_is_online_done(struct tevent_req *subreq);

struct tevent_req *
ifp_domains_domain_is_online_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sbus_request *sbus_req,
                                  struct ifp_ctx *ifp_ctx)
{
    struct ifp_domains_domain_is_online_state *state;
    struct sss_domain_info *dom;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ifp_domains_domain_is_online_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    dom = get_domain_info_from_req(sbus_req, ifp_ctx);
    if (dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    if (ifp_ctx->rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        ret = ENOENT;
        goto done;
    }

    subreq = sbus_call_dp_backend_IsOnline_send(state, ifp_ctx->rctx->sbus_conn,
                dom->conn_name, SSS_BUS_PATH, dom->name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_domains_domain_is_online_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_domains_domain_is_online_done(struct tevent_req *subreq)
{
    struct ifp_domains_domain_is_online_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_domains_domain_is_online_state);

    ret = sbus_call_dp_backend_IsOnline_recv(subreq, &state->is_online);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_domains_domain_is_online_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  bool *_is_online)
{
    struct ifp_domains_domain_is_online_state *state;
    state = tevent_req_data(req, struct ifp_domains_domain_is_online_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_is_online = state->is_online;

    return EOK;
}

struct ifp_domains_domain_list_services_state {
    const char **services;
};

static void ifp_domains_domain_list_services_done(struct tevent_req *subreq);

struct tevent_req *
ifp_domains_domain_list_services_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sbus_request *sbus_req,
                                      struct ifp_ctx *ifp_ctx)
{
    struct ifp_domains_domain_list_services_state *state;
    struct sss_domain_info *dom;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ifp_domains_domain_list_services_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    dom = get_domain_info_from_req(sbus_req, ifp_ctx);
    if (dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    if (ifp_ctx->rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        ret = ENOENT;
        goto done;
    }

    subreq = sbus_call_dp_failover_ListServices_send(state, ifp_ctx->rctx->sbus_conn,
                dom->conn_name, SSS_BUS_PATH, dom->name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_domains_domain_list_services_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_domains_domain_list_services_done(struct tevent_req *subreq)
{
    struct ifp_domains_domain_list_services_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_domains_domain_list_services_state);

    ret = sbus_call_dp_failover_ListServices_recv(state, subreq, &state->services);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_domains_domain_list_services_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      const char ***_services)
{
    struct ifp_domains_domain_list_services_state *state;
    state = tevent_req_data(req, struct ifp_domains_domain_list_services_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_services = talloc_steal(mem_ctx, state->services);

    return EOK;
}

struct ifp_domains_domain_active_server_state {
    const char *server;
};

static void ifp_domains_domain_active_server_done(struct tevent_req *subreq);

struct tevent_req *
ifp_domains_domain_active_server_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sbus_request *sbus_req,
                                      struct ifp_ctx *ifp_ctx,
                                      const char *service)
{
    struct ifp_domains_domain_active_server_state *state;
    struct sss_domain_info *dom;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ifp_domains_domain_active_server_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    dom = get_domain_info_from_req(sbus_req, ifp_ctx);
    if (dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    if (ifp_ctx->rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        ret = ENOENT;
        goto done;
    }

    subreq = sbus_call_dp_failover_ActiveServer_send(state, ifp_ctx->rctx->sbus_conn,
                dom->conn_name, SSS_BUS_PATH, service);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_domains_domain_active_server_done, req);

    ret = EAGAIN;

done:
if (ret != EAGAIN) {
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
}

    return req;
}

static void ifp_domains_domain_active_server_done(struct tevent_req *subreq)
{
    struct ifp_domains_domain_active_server_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_domains_domain_active_server_state);

    ret = sbus_call_dp_failover_ActiveServer_recv(state, subreq, &state->server);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_domains_domain_active_server_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      const char **_server)
{
    struct ifp_domains_domain_active_server_state *state;
    state = tevent_req_data(req, struct ifp_domains_domain_active_server_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_server = talloc_steal(mem_ctx, state->server);

    return EOK;
}

struct ifp_domains_domain_list_servers_state {
    const char **servers;
};

static void ifp_domains_domain_list_servers_done(struct tevent_req *subreq);

struct tevent_req *
ifp_domains_domain_list_servers_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sbus_request *sbus_req,
                                     struct ifp_ctx *ifp_ctx,
                                     const char *service)
{
    struct ifp_domains_domain_list_servers_state *state;
    struct sss_domain_info *dom;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ifp_domains_domain_list_servers_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    dom = get_domain_info_from_req(sbus_req, ifp_ctx);
    if (dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    if (ifp_ctx->rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        ret = ENOENT;
        goto done;
    }

    subreq = sbus_call_dp_failover_ListServers_send(state, ifp_ctx->rctx->sbus_conn,
                dom->conn_name, SSS_BUS_PATH, service);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_domains_domain_list_servers_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_domains_domain_list_servers_done(struct tevent_req *subreq)
{
    struct ifp_domains_domain_list_servers_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_domains_domain_list_servers_state);

    ret = sbus_call_dp_failover_ListServers_recv(state, subreq, &state->servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_domains_domain_list_servers_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      const char ***_servers)
{
    struct ifp_domains_domain_list_servers_state *state;
    state = tevent_req_data(req, struct ifp_domains_domain_list_servers_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_servers = talloc_steal(mem_ctx, state->servers);

    return EOK;
}

struct ifp_domains_domain_refresh_access_rules_state {
    int dummy;
};

static void ifp_domains_domain_refresh_access_rules_done(struct tevent_req *subreq);

struct tevent_req *
ifp_domains_domain_refresh_access_rules_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sbus_request *sbus_req,
                                             struct ifp_ctx *ifp_ctx)
{
    struct ifp_domains_domain_refresh_access_rules_state *state;
    struct sss_domain_info *dom;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ifp_domains_domain_refresh_access_rules_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    dom = get_domain_info_from_req(sbus_req, ifp_ctx);
    if (dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    if (ifp_ctx->rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        ret = ENOENT;
        goto done;
    }

    subreq = sbus_call_dp_access_RefreshRules_send(state, ifp_ctx->rctx->sbus_conn,
                dom->conn_name, SSS_BUS_PATH);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_domains_domain_refresh_access_rules_done, req);

    ret = EAGAIN;

done:
if (ret != EAGAIN) {
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
}

    return req;
}

static void ifp_domains_domain_refresh_access_rules_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sbus_call_dp_access_RefreshRules_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_domains_domain_refresh_access_rules_recv(TALLOC_CTX *mem_ctx,
                                             struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
