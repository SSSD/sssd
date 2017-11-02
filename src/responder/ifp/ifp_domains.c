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
#include "responder/common/data_provider/rdp.h"
#include "sbus/sssd_dbus_errors.h"
#include "providers/data_provider/dp_responder_iface.h"

#define RETURN_DOM_PROP_AS_STRING(dbus_req, pvt_data, out, property) do { \
    struct sss_domain_info *__dom;                                        \
                                                                          \
    *(out) = NULL;                                                        \
                                                                          \
    __dom = get_domain_info_from_req((dbus_req), (pvt_data));             \
    if (__dom == NULL) {                                                  \
        return;                                                           \
    }                                                                     \
                                                                          \
    *(out) = __dom->property;                                             \
} while (0)

static void ifp_list_domains_process(struct tevent_req *req);

int ifp_list_domains(struct sbus_request *dbus_req,
                     void *data)
{
    struct ifp_ctx *ifp_ctx;
    struct ifp_req *ireq;
    struct tevent_req *req;
    DBusError *error;
    errno_t ret;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "Invalid ifp context!");
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    ret = ifp_req_create(dbus_req, ifp_ctx, &ireq);
    if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "%s", sss_strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    req = sss_dp_get_domains_send(ireq, ifp_ctx->rctx, false, NULL);
    if (req == NULL) {
        return sbus_request_finish(ireq->dbus_req, NULL);
    }

    tevent_req_set_callback(req, ifp_list_domains_process, ireq);

    return EOK;
}

static void ifp_list_domains_process(struct tevent_req *req)
{
    struct sss_domain_info *dom;
    struct ifp_req *ireq;
    const char **paths;
    char *p;
    DBusError *error;
    size_t num_domains;
    size_t pi;
    errno_t ret;

    ireq = tevent_req_callback_data(req, struct ifp_req);

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        error = sbus_error_new(ireq->dbus_req, DBUS_ERROR_FAILED,
                               "Failed to refresh domain objects\n");
        sbus_request_fail_and_finish(ireq->dbus_req, error);
        return;
    }

    ret = sysdb_master_domain_update(ireq->ifp_ctx->rctx->domains);
    if (ret != EOK) {
        error = sbus_error_new(ireq->dbus_req, DBUS_ERROR_FAILED,
                               "Failed to refresh subdomain list\n");
        sbus_request_fail_and_finish(ireq->dbus_req, error);
        return;
    }

    num_domains = 0;
    for (dom = ireq->ifp_ctx->rctx->domains;
            dom != NULL;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        num_domains++;
    }

    paths = talloc_zero_array(ireq, const char *, num_domains);
    if (paths == NULL) {
        sbus_request_finish(ireq->dbus_req, NULL);
        return;
    }

    pi = 0;
    for (dom = ireq->ifp_ctx->rctx->domains;
            dom != NULL;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        p = sbus_opath_compose(ireq, IFP_PATH_DOMAINS, dom->name);
        if (p == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not create path for dom %s, skipping\n", dom->name);
            continue;
        }
        paths[pi] = p;
        pi++;
    }

    ret = iface_ifp_ListDomains_finish(ireq->dbus_req, paths, num_domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not finish request!\n");
    }
}

struct ifp_get_domain_state {
    const char *name;
    struct ifp_req *ireq;
};

static void ifp_find_domain_by_name_process(struct tevent_req *req);

int ifp_find_domain_by_name(struct sbus_request *dbus_req,
                            void *data,
                            const char *arg_name)
{
    struct ifp_ctx *ifp_ctx;
    struct ifp_req *ireq;
    struct tevent_req *req;
    struct ifp_get_domain_state *state;
    DBusError *error;
    errno_t ret;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "Invalid ifp context!");
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    ret = ifp_req_create(dbus_req, ifp_ctx, &ireq);
    if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "%s", sss_strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    state = talloc_zero(ireq, struct ifp_get_domain_state);
    if (state == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    state->name = arg_name;
    state->ireq = ireq;

    req = sss_dp_get_domains_send(ireq, ifp_ctx->rctx, false, NULL);
    if (req == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    tevent_req_set_callback(req, ifp_find_domain_by_name_process, state);
    return EOK;
}

static void ifp_find_domain_by_name_process(struct tevent_req *req)
{
    errno_t ret;
    struct ifp_req *ireq;
    struct ifp_get_domain_state *state;
    struct sss_domain_info *iter;
    const char *path;
    DBusError *error;

    state = tevent_req_callback_data(req, struct ifp_get_domain_state);
    ireq = state->ireq;

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        error = sbus_error_new(ireq->dbus_req, DBUS_ERROR_FAILED,
                               "Failed to refresh domain objects\n");
        sbus_request_fail_and_finish(ireq->dbus_req, error);
        return;
    }

    ret = sysdb_master_domain_update(ireq->ifp_ctx->rctx->domains);
    if (ret != EOK) {
        error = sbus_error_new(ireq->dbus_req, DBUS_ERROR_FAILED,
                               "Failed to refresh subdomain list\n");
        sbus_request_fail_and_finish(ireq->dbus_req, error);
        return;
    }

    /* Reply with the domain that was asked for */
    for (iter = ireq->ifp_ctx->rctx->domains;
            iter != NULL;
            iter = get_next_domain(iter, SSS_GND_DESCEND)) {
        if (strcasecmp(iter->name, state->name) == 0) {
            break;
        }
    }

    if (iter == NULL) {
        error = sbus_error_new(ireq->dbus_req, DBUS_ERROR_FAILED,
                               "No such domain\n");
        sbus_request_fail_and_finish(ireq->dbus_req, error);
        return;
    }

    path = sbus_opath_compose(ireq, IFP_PATH_DOMAINS, iter->name);
    if (path == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "Could not create path for domain %s, skipping\n", iter->name);
        sbus_request_finish(ireq->dbus_req, NULL);
        return;
    }

    ret = iface_ifp_FindDomainByName_finish(ireq->dbus_req, path);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not finish request!\n");
    }
}

static struct sss_domain_info *
get_domain_info_from_req(struct sbus_request *dbus_req, void *data)
{
    struct ifp_ctx *ctx = NULL;
    struct sss_domain_info *domains = NULL;
    struct sss_domain_info *iter = NULL;
    char *name = NULL;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return NULL;
    }

    name = sbus_opath_get_object_name(dbus_req, dbus_req->path,
                                      IFP_PATH_DOMAINS);
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

static void get_server_list(struct sbus_request *dbus_req,
                            void *data,
                            const char ***_out,
                            int *_out_len,
                            bool backup)
{
    static const char *srv[] = {"_srv_"};
    struct sss_domain_info *dom = NULL;
    struct ifp_ctx *ctx = NULL;
    const char *conf_path = NULL;
    const char *option = NULL;
    const char **out = NULL;
    char **servers = NULL;
    int num_servers;
    errno_t ret;
    int i;

    *_out = NULL;
    *_out_len = 0;

    dom = get_domain_info_from_req(dbus_req, data);
    if (dom == NULL) {
        return;
    }

    if (dom->parent != NULL) {
        /* subdomains are not present in configuration */
        ret = ENOENT;
        goto done;
    }

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        ret = ENOMEM;
        goto done;
    }

    conf_path = talloc_asprintf(dbus_req, CONFDB_DOMAIN_PATH_TMPL, dom->name);
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

    ret = confdb_get_string_as_list(ctx->rctx->cdb, dbus_req, conf_path,
                                    option, &servers);
    if (ret != EOK) {
        goto done;
    }

    for (num_servers = 0; servers[num_servers] != NULL; num_servers++);

    if (num_servers == 0) {
        ret = ENOENT;
        goto done;
    }

    out = talloc_zero_array(dbus_req, const char*, num_servers);
    if (out == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_servers; i++) {
        out[i] = talloc_steal(out, servers[i]);
    }

    *_out = out;
    *_out_len = num_servers;

    ret = EOK;

done:
    if (ret == ENOENT) {
        *_out = srv;
        *_out_len = 1;
    }

    return;
}

void ifp_dom_get_name(struct sbus_request *dbus_req,
                      void *data,
                      const char **_out)
{
    RETURN_DOM_PROP_AS_STRING(dbus_req, data, _out, name);
}

void ifp_dom_get_provider(struct sbus_request *dbus_req,
                          void *data,
                          const char **_out)
{
    RETURN_DOM_PROP_AS_STRING(dbus_req, data, _out, provider);
}

void ifp_dom_get_primary_servers(struct sbus_request *dbus_req,
                                 void *data,
                                 const char ***_out,
                                 int *_out_len)
{
    get_server_list(dbus_req, data, _out, _out_len, false);
}

void ifp_dom_get_backup_servers(struct sbus_request *dbus_req,
                                void *data,
                                const char ***_out,
                                int *_out_len)
{
    get_server_list(dbus_req, data, _out, _out_len, true);
}

void ifp_dom_get_min_id(struct sbus_request *dbus_req,
                        void *data,
                        uint32_t *_out)
{
    struct sss_domain_info *dom;

    *_out = 1;

    dom = get_domain_info_from_req(dbus_req, data);
    if (dom == NULL) {
        return;
    }

    *_out = dom->id_min;
}

void ifp_dom_get_max_id(struct sbus_request *dbus_req,
                        void *data,
                        uint32_t *_out)
{
    struct sss_domain_info *dom;

    *_out = 0;

    dom = get_domain_info_from_req(dbus_req, data);
    if (dom == NULL) {
        return;
    }

    *_out = dom->id_max;
}

void ifp_dom_get_realm(struct sbus_request *dbus_req,
                       void *data,
                       const char **_out)
{
    RETURN_DOM_PROP_AS_STRING(dbus_req, data, _out, realm);
}

void ifp_dom_get_forest(struct sbus_request *dbus_req,
                        void *data,
                        const char **_out)
{
    RETURN_DOM_PROP_AS_STRING(dbus_req, data, _out, forest);
}

void ifp_dom_get_login_format(struct sbus_request *dbus_req,
                              void *data,
                              const char **_out)
{
    RETURN_DOM_PROP_AS_STRING(dbus_req, data, _out, names->re_pattern);
}

void ifp_dom_get_fqdn_format(struct sbus_request *dbus_req,
                             void *data,
                             const char **_out)
{
    RETURN_DOM_PROP_AS_STRING(dbus_req, data, _out, names->fq_fmt);
}

void ifp_dom_get_enumerable(struct sbus_request *dbus_req,
                            void *data,
                            bool *_out)
{
    struct sss_domain_info *dom;

    *_out = false;

    dom = get_domain_info_from_req(dbus_req, data);
    if (dom == NULL) {
        return;
    }

    *_out = dom->enumerate;
}

void ifp_dom_get_use_fqdn(struct sbus_request *dbus_req,
                          void *data,
                          bool *_out)
{
    struct sss_domain_info *dom;

    *_out = false;

    dom = get_domain_info_from_req(dbus_req, data);
    if (dom == NULL) {
        return;
    }

    *_out = dom->fqnames;
}

void ifp_dom_get_subdomain(struct sbus_request *dbus_req,
                           void *data,
                           bool *_out)
{
    struct sss_domain_info *dom;

    *_out = false;

    dom = get_domain_info_from_req(dbus_req, data);
    if (dom == NULL) {
        return;
    }

    *_out = dom->parent ? true : false;
}

void ifp_dom_get_parent_domain(struct sbus_request *dbus_req,
                              void *data,
                              const char **_out)
{
    struct sss_domain_info *dom;

    *_out = NULL;

    dom = get_domain_info_from_req(dbus_req, data);
    if (dom == NULL) {
        return;
    }

    if (dom->parent == NULL) {
        *_out = "/";
        return;
    }

    *_out = sbus_opath_compose(dbus_req, IFP_PATH_DOMAINS,
                               dom->parent->name);
}

int ifp_domains_domain_is_online(struct sbus_request *sbus_req,
                                 void *data)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *dom;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);

    dom = get_domain_info_from_req(sbus_req, data);
    if (dom == NULL) {
        sbus_request_reply_error(sbus_req, SBUS_ERROR_UNKNOWN_DOMAIN,
                                 "Unknown domain");
        return EOK;
    }

    rdp_message_send_and_reply(sbus_req, ifp_ctx->rctx, dom, DP_PATH,
                               IFACE_DP_BACKEND, IFACE_DP_BACKEND_ISONLINE,
                               DBUS_TYPE_STRING, &dom->name);

    return EOK;
}

int ifp_domains_domain_list_services(struct sbus_request *sbus_req,
                                     void *data)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *dom;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);

    dom = get_domain_info_from_req(sbus_req, data);
    if (dom == NULL) {
        sbus_request_reply_error(sbus_req, SBUS_ERROR_UNKNOWN_DOMAIN,
                                 "Unknown domain");
        return EOK;
    }

    rdp_message_send_and_reply(sbus_req, ifp_ctx->rctx, dom, DP_PATH,
                               IFACE_DP_FAILOVER,
                               IFACE_DP_FAILOVER_LISTSERVICES,
                               DBUS_TYPE_STRING, &dom->name);

    return EOK;
}

int ifp_domains_domain_active_server(struct sbus_request *sbus_req,
                                     void *data,
                                     const char *service)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *dom;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);

    dom = get_domain_info_from_req(sbus_req, data);
    if (dom == NULL) {
        sbus_request_reply_error(sbus_req, SBUS_ERROR_UNKNOWN_DOMAIN,
                                 "Unknown domain");
        return EOK;
    }

    rdp_message_send_and_reply(sbus_req, ifp_ctx->rctx, dom, DP_PATH,
                               IFACE_DP_FAILOVER,
                               IFACE_DP_FAILOVER_ACTIVESERVER,
                               DBUS_TYPE_STRING, &service);

    return EOK;
}

int ifp_domains_domain_list_servers(struct sbus_request *sbus_req,
                                    void *data,
                                    const char *service)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *dom;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);

    dom = get_domain_info_from_req(sbus_req, data);
    if (dom == NULL) {
        sbus_request_reply_error(sbus_req, SBUS_ERROR_UNKNOWN_DOMAIN,
                                 "Unknown domain");
        return EOK;
    }

    rdp_message_send_and_reply(sbus_req, ifp_ctx->rctx, dom, DP_PATH,
                               IFACE_DP_FAILOVER,
                               IFACE_DP_FAILOVER_LISTSERVERS,
                               DBUS_TYPE_STRING, &service);

    return EOK;
}

int ifp_domains_domain_refresh_access_rules(struct sbus_request *sbus_req,
                                            void *data)
{
    struct ifp_ctx *ifp_ctx;
    struct sss_domain_info *dom;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);

    dom = get_domain_info_from_req(sbus_req, data);
    if (dom == NULL) {
        sbus_request_reply_error(sbus_req, SBUS_ERROR_UNKNOWN_DOMAIN,
                                 "Unknown domain");
        return EOK;
    }

    rdp_message_send_and_reply(sbus_req, ifp_ctx->rctx, dom, DP_PATH,
                               IFACE_DP_ACCESS_CONTROL,
                               IFACE_DP_ACCESS_CONTROL_REFRESHRULES);

    return EOK;
}
