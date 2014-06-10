/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include <string.h>
#include <talloc.h>
#include <tevent.h>
#include <ndr.h>
#include <ndr/ndr_nbt.h>

#include "util/util.h"
#include "util/sss_ldap.h"
#include "resolv/async_resolv.h"
#include "providers/dp_backend.h"
#include "providers/ad/ad_srv.h"
#include "providers/ad/ad_common.h"
#include "providers/fail_over.h"
#include "providers/fail_over_srv.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"

#define AD_SITE_DOMAIN_FMT "%s._sites.%s"

static errno_t ad_sort_servers_by_dns(TALLOC_CTX *mem_ctx,
                                      const char *domain,
                                      struct fo_server_info **_srv,
                                      size_t num)
{
    struct fo_server_info *out = NULL;
    struct fo_server_info *srv = NULL;
    struct fo_server_info in_domain[num];
    struct fo_server_info out_domain[num];
    size_t srv_index = 0;
    size_t in_index = 0;
    size_t out_index = 0;
    size_t i, j;

    if (_srv == NULL) {
        return EINVAL;
    }

    srv = *_srv;

    if (num <= 1) {
        return EOK;
    }

    out = talloc_zero_array(mem_ctx, struct fo_server_info, num);
    if (out == NULL) {
        return ENOMEM;
    }

    /* When several servers share priority, we will prefer the one that
     * is located in the same domain as client (e.g. child domain instead
     * of forest root) but obey their weight. We will use the fact that
     * the servers are already sorted by priority. */

    for (i = 0; i < num; i++) {
        if (is_host_in_domain(srv[i].host, domain)) {
            /* this is a preferred server, push it to the in domain list */
            in_domain[in_index] = srv[i];
            in_index++;
        } else {
            /* this is a normal server, push it to the out domain list */
            out_domain[out_index] = srv[i];
            out_index++;
        }

        if (i + 1 == num || srv[i].priority != srv[i + 1].priority) {
            /* priority has changed or we have reached the end of the srv list,
             * we will merge the list into final list and start over with
             * next priority */
            for (j = 0; j < in_index; j++) {
                out[srv_index] = in_domain[j];
                talloc_steal(out, out[srv_index].host);
                srv_index++;
            }

            for (j = 0; j < out_index; j++) {
                out[srv_index] = out_domain[j];
                talloc_steal(out, out[srv_index].host);
                srv_index++;
            }

            in_index = 0;
            out_index = 0;
        }
    }

    talloc_free(*_srv);
    *_srv = out;
    return EOK;
}

struct ad_get_dc_servers_state {
    struct fo_server_info *servers;
    size_t num_servers;
};

static void ad_get_dc_servers_done(struct tevent_req *subreq);

static struct tevent_req *ad_get_dc_servers_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct resolv_ctx *resolv_ctx,
                                                 const char *domain)
{
    struct ad_get_dc_servers_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    const char **domains = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_get_dc_servers_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    domains = talloc_zero_array(state, const char *, 2);
    if (domains == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    domains[0] = talloc_strdup(domains, domain);
    if (domains[0] == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Looking up domain controllers in domain %s\n",
                              domain);

    subreq = fo_discover_srv_send(state, ev, resolv_ctx,
                                  "ldap", FO_PROTO_TCP, domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_get_dc_servers_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ad_get_dc_servers_done(struct tevent_req *subreq)
{
    struct ad_get_dc_servers_state *state = NULL;
    struct tevent_req *req = NULL;
    char *domain = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_get_dc_servers_state);

    ret = fo_discover_srv_recv(state, subreq, &domain,
                               &state->servers, &state->num_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Found %zu domain controllers in domain %s\n",
                              state->num_servers, domain);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int ad_get_dc_servers_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  struct fo_server_info **_dcs,
                                  size_t *_num_dcs)
{
    struct ad_get_dc_servers_state *state = NULL;
    state = tevent_req_data(req, struct ad_get_dc_servers_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_dcs = talloc_steal(mem_ctx, state->servers);
    *_num_dcs = state->num_servers;

    return EOK;
}

struct ad_get_client_site_state {
    struct tevent_context *ev;
    struct be_resolv_ctx *be_res;
    enum host_database *host_db;
    struct sdap_options *opts;
    const char *ad_domain;
    struct fo_server_info *dcs;
    size_t num_dcs;
    size_t dc_index;
    struct fo_server_info dc;

    struct sdap_handle *sh;
    char *site;
    char *forest;
};

static errno_t ad_get_client_site_next_dc(struct tevent_req *req);
static void ad_get_client_site_connect_done(struct tevent_req *subreq);
static void ad_get_client_site_done(struct tevent_req *subreq);

struct tevent_req *ad_get_client_site_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct be_resolv_ctx *be_res,
                                           enum host_database *host_db,
                                           struct sdap_options *opts,
                                           const char *ad_domain,
                                           struct fo_server_info *dcs,
                                           size_t num_dcs)
{
    struct ad_get_client_site_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_get_client_site_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (be_res == NULL || host_db == NULL || opts == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->ev = ev;
    state->be_res = be_res;
    state->host_db = host_db;
    state->opts = opts;
    state->ad_domain = ad_domain;
    state->dcs = dcs;
    state->num_dcs = num_dcs;

    state->dc_index = 0;
    ret = ad_get_client_site_next_dc(req);
    if (ret == EOK) {
        ret = ENOENT;
        goto immediately;
    } else if (ret != EAGAIN) {
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t ad_get_client_site_next_dc(struct tevent_req *req)
{
    struct ad_get_client_site_state *state = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct ad_get_client_site_state);

    if (state->dc_index >= state->num_dcs) {
        ret = EOK;
        goto done;
    }

    state->dc = state->dcs[state->dc_index];

    subreq = sdap_connect_host_send(state, state->ev, state->opts,
                                    state->be_res->resolv,
                                    state->be_res->family_order,
                                    state->host_db, "ldap", state->dc.host,
                                    state->dc.port, false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_get_client_site_connect_done, req);

    state->dc_index++;
    ret = EAGAIN;

done:
    return ret;
}

static void ad_get_client_site_connect_done(struct tevent_req *subreq)
{
    struct ad_get_client_site_state *state = NULL;
    struct tevent_req *req = NULL;
    static const char *attrs[] = {AD_AT_NETLOGON, NULL};
    char *filter = NULL;
    char *ntver = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_get_client_site_state);

    ret = sdap_connect_host_recv(state, subreq, &state->sh);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to connect to domain controller "
              "[%s:%d]\n", state->dc.host, state->dc.port);

        ret = ad_get_client_site_next_dc(req);
        if (ret == EOK) {
            ret = ENOENT;
        }

        goto done;
    }

    ntver = sss_ldap_encode_ndr_uint32(state, NETLOGON_NT_VERSION_5EX |
                                       NETLOGON_NT_VERSION_WITH_CLOSEST_SITE);
    if (ntver == NULL) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(%s=%s))",
                             AD_AT_DNS_DOMAIN, state->ad_domain,
                             AD_AT_NT_VERSION, ntver);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   "", LDAP_SCOPE_BASE, filter,
                                   attrs, NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_get_client_site_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t ad_get_client_site_parse_ndr(TALLOC_CTX *mem_ctx,
                                            uint8_t *data,
                                            size_t length,
                                            char **_site_name,
                                            char **_forest_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ndr_pull *ndr_pull = NULL;
    struct netlogon_samlogon_response response;
    enum ndr_err_code ndr_err;
    char *site = NULL;
    char *forest = NULL;
    DATA_BLOB blob;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    blob.data = data;
    blob.length = length;

    ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);
    if (ndr_pull == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_init_blob() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ndr_err = ndr_pull_netlogon_samlogon_response(ndr_pull, NDR_SCALARS,
                                                  &response);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_netlogon_samlogon_response() "
                                  "failed [%d]\n", ndr_err);
        ret = EBADMSG;
        goto done;
    }

    if (!(response.ntver & NETLOGON_NT_VERSION_5EX)) {
        DEBUG(SSSDBG_OP_FAILURE, "This NT version does not provide site "
                                  "information [%x]\n", response.ntver);
        ret = EBADMSG;
        goto done;
    }

    if (response.data.nt5_ex.client_site != NULL
        && response.data.nt5_ex.client_site[0] != '\0') {
        site = talloc_strdup(tmp_ctx, response.data.nt5_ex.client_site);
    } else if (response.data.nt5_ex.next_closest_site != NULL
               && response.data.nt5_ex.next_closest_site[0] != '\0') {
        site = talloc_strdup(tmp_ctx, response.data.nt5_ex.next_closest_site);
    } else {
        ret = ENOENT;
        goto done;
    }

    if (response.data.nt5_ex.forest != NULL
            && response.data.nt5_ex.forest[0] != '\0') {
        forest = talloc_strdup(tmp_ctx, response.data.nt5_ex.forest);
    } else {
        ret = ENOENT;
        goto done;
    }


    if (site == NULL || forest == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_site_name = talloc_steal(mem_ctx, site);
    *_forest_name = talloc_steal(mem_ctx, forest);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void ad_get_client_site_done(struct tevent_req *subreq)
{
    struct ad_get_client_site_state *state = NULL;
    struct tevent_req *req = NULL;
    struct ldb_message_element *el = NULL;
    struct sysdb_attrs **reply = NULL;
    size_t reply_count;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_get_client_site_state);

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);

    /* we're done with this LDAP, close connection */
    talloc_zfree(state->sh);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get netlogon information\n");

        ret = ad_get_client_site_next_dc(req);
        if (ret == EOK) {
            ret = ENOENT;
        }
        goto done;
    }

    if (reply_count == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "No netlogon information retrieved\n");
        ret = ENOENT;
        goto done;
    }

    ret = sysdb_attrs_get_el(reply[0], AD_AT_NETLOGON, &el);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el() failed\n");
        goto done;
    }

    if (el->num_values == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "netlogon has no value\n");
        ret = ENOENT;
        goto done;
    } else if (el->num_values > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "More than one netlogon value?\n");
        ret = EIO;
        goto done;
    }

    ret = ad_get_client_site_parse_ndr(state, el->values[0].data,
                                       el->values[0].length, &state->site,
                                       &state->forest);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve site name [%d]: %s\n",
                                  ret, strerror(ret));
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Found site: %s\n", state->site);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int ad_get_client_site_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            char **_site,
                            char **_forest)
{
    struct ad_get_client_site_state *state = NULL;
    state = tevent_req_data(req, struct ad_get_client_site_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_site = talloc_steal(mem_ctx, state->site);
    *_forest = talloc_steal(mem_ctx, state->forest);

    return EOK;
}

struct ad_srv_plugin_ctx {
    struct be_resolv_ctx *be_res;
    enum host_database *host_dbs;
    struct sdap_options *opts;
    const char *hostname;
    const char *ad_domain;
};

struct ad_srv_plugin_ctx *
ad_srv_plugin_ctx_init(TALLOC_CTX *mem_ctx,
                       struct be_resolv_ctx *be_res,
                       enum host_database *host_dbs,
                       struct sdap_options *opts,
                       const char *hostname,
                       const char *ad_domain)
{
    struct ad_srv_plugin_ctx *ctx = NULL;

    ctx = talloc_zero(mem_ctx, struct ad_srv_plugin_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->be_res = be_res;
    ctx->host_dbs = host_dbs;
    ctx->opts = opts;

    ctx->hostname = talloc_strdup(ctx, hostname);
    if (ctx->hostname == NULL) {
        goto fail;
    }

    ctx->ad_domain = talloc_strdup(ctx, ad_domain);
    if (ctx->ad_domain == NULL) {
        goto fail;
    }

    return ctx;

fail:
    talloc_free(ctx);
    return NULL;
}

struct ad_srv_plugin_state {
    struct tevent_context *ev;
    struct ad_srv_plugin_ctx *ctx;
    const char *service;
    const char *protocol;
    const char *discovery_domain;

    char *site;
    char *dns_domain;
    char *forest;
    struct fo_server_info *primary_servers;
    size_t num_primary_servers;
    struct fo_server_info *backup_servers;
    size_t num_backup_servers;
};

static void ad_srv_plugin_dcs_done(struct tevent_req *subreq);
static void ad_srv_plugin_site_done(struct tevent_req *subreq);
static void ad_srv_plugin_servers_done(struct tevent_req *subreq);

/* 1. Do a DNS lookup to find any DC in domain
 *    _ldap._tcp.domain.name
 * 2. Send a CLDAP ping to the found DC to get the desirable site
 * 3. Do a DNS lookup to find SRV in the site (a)
 *    _service._protocol.site-name._sites.domain.name
 * 4. Do a DNS lookup to find global SRV records (b)
 *    _service._protocol.domain.name
 * 5. If the site is found, use (a) as primary and (b) as backup servers,
 *    otherwise use (b) as primary servers
 */
struct tevent_req *ad_srv_plugin_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       const char *service,
                                       const char *protocol,
                                       const char *discovery_domain,
                                       void *pvt)
{
    struct ad_srv_plugin_state *state = NULL;
    struct ad_srv_plugin_ctx *ctx = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_srv_plugin_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    ctx = talloc_get_type(pvt, struct ad_srv_plugin_ctx);
    if (ctx == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->ev = ev;
    state->ctx = ctx;

    state->service = talloc_strdup(state, service);
    if (state->service == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->protocol = talloc_strdup(state, protocol);
    if (state->protocol == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (discovery_domain != NULL) {
        state->discovery_domain = talloc_strdup(state, discovery_domain);
    } else {
        state->discovery_domain = talloc_strdup(state, ctx->ad_domain);
    }
    if (state->discovery_domain == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "About to find domain controllers\n");

    subreq = ad_get_dc_servers_send(state, ev, ctx->be_res->resolv,
                                    state->discovery_domain);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_srv_plugin_dcs_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void ad_srv_plugin_dcs_done(struct tevent_req *subreq)
{
    struct ad_srv_plugin_state *state = NULL;
    struct tevent_req *req = NULL;
    struct fo_server_info *dcs = NULL;
    size_t num_dcs = 0;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_srv_plugin_state);

    ret = ad_get_dc_servers_recv(state, subreq, &dcs, &num_dcs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "About to locate suitable site\n");

    subreq = ad_get_client_site_send(state, state->ev,
                                     state->ctx->be_res,
                                     state->ctx->host_dbs,
                                     state->ctx->opts,
                                     state->discovery_domain,
                                     dcs, num_dcs);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_srv_plugin_site_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void ad_srv_plugin_site_done(struct tevent_req *subreq)
{
    struct ad_srv_plugin_state *state = NULL;
    struct tevent_req *req = NULL;
    const char *primary_domain = NULL;
    const char *backup_domain = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_srv_plugin_state);

    ret = ad_get_client_site_recv(state, subreq, &state->site, &state->forest);
    talloc_zfree(subreq);
    if (ret == EOK) {
        if (strcmp(state->service, "gc") == 0) {
            primary_domain = talloc_asprintf(state, AD_SITE_DOMAIN_FMT,
                                             state->site, state->forest);
            if (primary_domain == NULL) {
                ret = ENOMEM;
                goto done;
            }

            backup_domain = state->forest;
        } else {
            primary_domain = talloc_asprintf(state, AD_SITE_DOMAIN_FMT,
                                             state->site, state->discovery_domain);
            if (primary_domain == NULL) {
                ret = ENOMEM;
                goto done;
            }

            backup_domain = state->discovery_domain;
        }
    } else if (ret == ENOENT) {
        primary_domain = state->discovery_domain;
        backup_domain = NULL;
    } else {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "About to discover primary and "
                              "backup servers\n");

    subreq = fo_discover_servers_send(state, state->ev,
                                      state->ctx->be_res->resolv,
                                      state->service, state->protocol,
                                      primary_domain, backup_domain);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_srv_plugin_servers_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void ad_srv_plugin_servers_done(struct tevent_req *subreq)
{
    struct ad_srv_plugin_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_srv_plugin_state);

    ret = fo_discover_servers_recv(state, subreq, &state->dns_domain,
                                   &state->primary_servers,
                                   &state->num_primary_servers,
                                   &state->backup_servers,
                                   &state->num_backup_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got %zu primary and %zu backup servers\n",
          state->num_primary_servers, state->num_backup_servers);

    ret = ad_sort_servers_by_dns(state, state->discovery_domain,
                                 &state->primary_servers,
                                 state->num_primary_servers);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to sort primary servers by DNS"
                                     "[%d]: %s\n", ret, sss_strerror(ret));
        /* continue */
    }

    ret = ad_sort_servers_by_dns(state, state->discovery_domain,
                                 &state->backup_servers,
                                 state->num_backup_servers);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to sort backup servers by DNS"
                                     "[%d]: %s\n", ret, sss_strerror(ret));
        /* continue */
    }

    tevent_req_done(req);
}

errno_t ad_srv_plugin_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           char **_dns_domain,
                           struct fo_server_info **_primary_servers,
                           size_t *_num_primary_servers,
                           struct fo_server_info **_backup_servers,
                           size_t *_num_backup_servers)
{
    struct ad_srv_plugin_state *state = NULL;
    state = tevent_req_data(req, struct ad_srv_plugin_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_primary_servers) {
        *_primary_servers = talloc_steal(mem_ctx, state->primary_servers);
    }

    if (_num_primary_servers) {
        *_num_primary_servers = state->num_primary_servers;
    }

    if (_backup_servers) {
        *_backup_servers = talloc_steal(mem_ctx, state->backup_servers);
    }

    if (_num_backup_servers) {
        *_num_backup_servers = state->num_backup_servers;
    }

    if (_dns_domain) {
        *_dns_domain = talloc_steal(mem_ctx, state->dns_domain);
    }


    return EOK;
}
