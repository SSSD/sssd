/*
    SSSD

    AD Domain Info Module

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include <errno.h>
#include <tevent.h>
#include <ctype.h>
#include <ndr.h>
#include <ndr/ndr_nbt.h>

#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ad/ad_domain_info.h"
#include "providers/ad/ad_common.h"
#include "util/util.h"

errno_t netlogon_get_domain_info(TALLOC_CTX *mem_ctx,
                                 struct sysdb_attrs *reply,
                                 bool check_next_nearest_site_as_well,
                                 char **_flat_name,
                                 char **_site,
                                 char **_forest)
{
    errno_t ret;
    struct ldb_message_element *el;
    DATA_BLOB blob;
    struct ndr_pull *ndr_pull = NULL;
    enum ndr_err_code ndr_err;
    struct netlogon_samlogon_response response;
    TALLOC_CTX *tmp_ctx;

    ret = sysdb_attrs_get_el(reply, AD_AT_NETLOGON, &el);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el() failed\n");
        return ret;
    }

    if (el->num_values == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "netlogon has no value\n");
        return ENOENT;
    } else if (el->num_values > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "More than one netlogon value?\n");
        return EIO;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    blob.data = el->values[0].data;
    blob.length = el->values[0].length;

    /* The ndr_pull_* calls do not use ndr_pull as a talloc context to
     * allocate memory but the second argument of ndr_pull_init_blob(). To
     * make sure no memory is leaked here a temporary talloc context is
     * needed. */
    ndr_pull = ndr_pull_init_blob(&blob, tmp_ctx);
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
        DEBUG(SSSDBG_OP_FAILURE, "Wrong version returned [%x]\n",
                                  response.ntver);
        ret = EBADMSG;
        goto done;
    }

    /* get flat domain name */
    if (_flat_name != NULL) {
        if (response.data.nt5_ex.domain_name != NULL &&
            *response.data.nt5_ex.domain_name != '\0') {
            *_flat_name = talloc_strdup(mem_ctx,
                                        response.data.nt5_ex.domain_name);
            if (*_flat_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No netlogon flat domain name data available.\n");
            *_flat_name = NULL;
        }
    }


    /* get forest */
    if (_forest != NULL) {
        if (response.data.nt5_ex.forest != NULL &&
            *response.data.nt5_ex.forest != '\0') {
            *_forest = talloc_strdup(mem_ctx, response.data.nt5_ex.forest);
            if (*_forest == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "No netlogon forest data available.\n");
            *_forest = NULL;
        }
    }

    /* get site name */
    if (_site != NULL) {
        if (response.data.nt5_ex.client_site != NULL
            && response.data.nt5_ex.client_site[0] != '\0') {
            *_site = talloc_strdup(mem_ctx, response.data.nt5_ex.client_site);
            if (*_site == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No netlogon site name data available.\n");
            *_site = NULL;

            if (check_next_nearest_site_as_well) {
                if (response.data.nt5_ex.next_closest_site != NULL
                        && response.data.nt5_ex.next_closest_site[0] != '\0') {
                    *_site = talloc_strdup(mem_ctx,
                                        response.data.nt5_ex.next_closest_site);
                    if (*_site == NULL) {
                        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                        ret = ENOMEM;
                        goto done;
                    }
                } else {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "No netlogon next closest site name data "
                          "available.\n");
                }
            }
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

struct ad_domain_info_state {
    struct tevent_context *ev;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *id_op;
    struct sdap_id_ctx *id_ctx;
    struct sdap_options *opts;
    struct sdap_domain *sdom;

    const char *dom_name;
    int base_iter;

    char *flat;
    char *site;
    char *forest;
    char *sid;
};

static errno_t ad_domain_info_next(struct tevent_req *req);
static void ad_domain_info_next_done(struct tevent_req *subreq);
static void ad_domain_info_netlogon_done(struct tevent_req *req);

struct tevent_req *
ad_domain_info_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct sdap_id_conn_ctx *conn,
                    struct sdap_id_op *op,
                    const char *dom_name)
{
    errno_t ret;
    struct tevent_req *req;
    struct ad_domain_info_state *state;

    req = tevent_req_create(mem_ctx, &state, struct ad_domain_info_state);
    if (!req) return NULL;

    state->ev = ev;
    state->id_op = op;
    state->conn = conn;
    state->id_ctx = conn->id_ctx;
    state->opts = conn->id_ctx->opts;
    state->dom_name = dom_name;
    state->sdom = sdap_domain_get_by_name(state->opts, state->dom_name);
    /* The first domain in the list is the domain configured in sssd.conf and
     * here it might be possible that the domain name from the config file and
     * the DNS domain name do not match. All other sub-domains are discovered
     * at runtime with the help of DNS lookups so it is expected that the
     * names matches. Hence it makes sense to fall back to the first entry in
     * the list if no matching domain was found since it is most probably
     * related to the configured domain. */
    if (state->sdom == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No internal domain data found for [%s], "
                                 "falling back to first domain.\n",
                                 state->dom_name);
        state->sdom = state->opts->sdom;
    }
    if (state->sdom == NULL || state->sdom->search_bases == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Missing internal domain data for domain [%s].\n",
              state->dom_name);
        ret = EINVAL;
        goto immediate;
    }


    ret = ad_domain_info_next(req);
    if (ret != EOK && ret != EAGAIN) {
        goto immediate;
    }

    return req;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t
ad_domain_info_next(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_search_base *base;
    const char *master_sid_attrs[] = {AD_AT_OBJECT_SID, NULL};

    struct ad_domain_info_state *state =
        tevent_req_data(req, struct ad_domain_info_state);

    base = state->sdom->search_bases[state->base_iter];
    if (base == NULL) {
        return EOK;
    }

    subreq = sdap_get_generic_send(state, state->ev,
                                   state->id_ctx->opts,
                                   sdap_id_op_handle(state->id_op),
                                   base->basedn, LDAP_SCOPE_BASE,
                                   MASTER_DOMAIN_SID_FILTER, master_sid_attrs,
                                   NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ad_domain_info_next_done, req);

    return EAGAIN;
}

static void
ad_domain_info_next_done(struct tevent_req *subreq)
{
    errno_t ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ldb_message_element *el;
    char *sid_str;
    enum idmap_error_code err;
    static const char *attrs[] = {AD_AT_NETLOGON, NULL};
    char *filter;
    char *ntver;

    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_domain_info_state *state =
        tevent_req_data(req, struct ad_domain_info_state);

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send request failed.\n");
        goto done;
    }

    if (reply_count == 0) {
        state->base_iter++;
        ret = ad_domain_info_next(req);
        if (ret == EAGAIN) {
            /* Async request will get us back here again */
            return;
        } else if (ret != EOK) {
            goto done;
        }

        /* EOK */
        tevent_req_done(req);
        return;
    } else if (reply_count == 1) {
        ret = sysdb_attrs_get_el(reply[0], AD_AT_OBJECT_SID, &el);
        if (ret != EOK || el->num_values != 1) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_attrs_get_el failed.\n");
            goto done;
        }

        err = sss_idmap_bin_sid_to_sid(state->opts->idmap_ctx->map,
                                       el->values[0].data,
                                       el->values[0].length,
                                       &sid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not convert SID: [%s].\n", idmap_error_string(err));
            ret = EFAULT;
            goto done;
        }

        state->sid = talloc_steal(state, sid_str);
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "More than one result for domain SID found.\n");
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Found SID [%s].\n", state->sid);

    ntver = sss_ldap_encode_ndr_uint32(state, NETLOGON_NT_VERSION_5EX |
                                       NETLOGON_NT_VERSION_WITH_CLOSEST_SITE);
    if (ntver == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_ldap_encode_ndr_uint32 failed.\n");
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(%s=%s))",
                             AD_AT_DNS_DOMAIN, state->dom_name,
                             AD_AT_NT_VERSION, ntver);
    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_get_generic_send(state, state->ev,
                                   state->id_ctx->opts,
                                   sdap_id_op_handle(state->id_op),
                                   "", LDAP_SCOPE_BASE, filter, attrs, NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_domain_info_netlogon_done, req);
    return;

done:
    tevent_req_error(req, ret);
}

static void
ad_domain_info_netlogon_done(struct tevent_req *subreq)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;

    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_domain_info_state *state =
        tevent_req_data(req, struct ad_domain_info_state);

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send request failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    /* Failure to get the flat name is not fatal. Just quit. */
    if (reply_count == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No netlogon data available. Flat name " \
                                     "might not be usable\n");
        goto done;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "More than one netlogon info returned.\n");
        goto done;
    }

    /* Exactly one flat name. Carry on */

    ret = netlogon_get_domain_info(state, reply[0], false, &state->flat,
                                   &state->site, &state->forest);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not get the flat name or forest: %d:[%s]\n",
              ret, sss_strerror(ret));
        /* Not fatal. Just quit. */
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Found flat name [%s].\n", state->flat);
    DEBUG(SSSDBG_TRACE_FUNC, "Found site [%s].\n", state->site);
    DEBUG(SSSDBG_TRACE_FUNC, "Found forest [%s].\n", state->forest);

done:
    tevent_req_done(req);
    return;
}

errno_t
ad_domain_info_recv(struct tevent_req *req,
                    TALLOC_CTX *mem_ctx,
                    char **_flat,
                    char **_id,
                    char **_site,
                    char **_forest)
{
    struct ad_domain_info_state *state = tevent_req_data(req,
                                              struct ad_domain_info_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_flat) {
        *_flat = talloc_steal(mem_ctx, state->flat);
    }

    if (_site) {
        *_site = talloc_steal(mem_ctx, state->site);
    }

    if (_forest) {
        *_forest = talloc_steal(mem_ctx, state->forest);
    }

    if (_id) {
        *_id = talloc_steal(mem_ctx, state->sid);
    }

    return EOK;
}
