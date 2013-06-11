/*
    SSSD

    AD Subdomains Module

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

#include "providers/ldap/sdap_async.h"
#include "providers/ad/ad_subdomains.h"
#include <ctype.h>
#include <ndr.h>
#include <ndr/ndr_nbt.h>

#define AD_AT_OBJECT_SID "objectSID"
#define AD_AT_DNS_DOMAIN "DnsDomain"
#define AD_AT_NT_VERSION "NtVer"
#define AD_AT_NETLOGON "netlogon"

/* Attributes of AD trusted domains */
#define AD_AT_FLATNAME      "flatName"
#define AD_AT_SID           "securityIdentifier"
#define AD_AT_TRUST_TYPE    "trustType"
#define AD_AT_TRUST_PARTNER "trustPartner"
#define AD_AT_TRUST_ATTRS   "trustAttributes"

#define MASTER_DOMAIN_SID_FILTER "objectclass=domain"

/* trustType=2 denotes uplevel (NT5 and later) trusted domains. See
 * http://msdn.microsoft.com/en-us/library/windows/desktop/ms680342%28v=vs.85%29.aspx
 * for example.
 *
 * The absence of msDS-TrustForestTrustInfo attribute denotes a domain from
 * the same forest. See http://msdn.microsoft.com/en-us/library/cc223786.aspx
 * for more information.
 */
#define SLAVE_DOMAIN_FILTER "(&(objectclass=trustedDomain)(trustType=2)(!(msDS-TrustForestTrustInfo=*)))"

/* do not refresh more often than every 5 seconds for now */
#define AD_SUBDOMAIN_REFRESH_LIMIT 5

/* refresh automatically every 4 hours */
#define AD_SUBDOMAIN_REFRESH_PERIOD (3600 * 4)

struct ad_subdomains_ctx {
    struct be_ctx *be_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *ldap_ctx;
    struct sss_idmap_ctx *idmap_ctx;
    char *domain_name;

    time_t last_refreshed;
    struct tevent_timer *timer_event;
};

struct ad_subdomains_req_ctx {
    struct be_req *be_req;
    struct ad_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;

    char *current_filter;
    size_t base_iter;

    size_t reply_count;
    struct sysdb_attrs **reply;

    char *master_sid;
    char *flat_name;
};

static errno_t
ads_store_sdap_subdom(struct ad_subdomains_ctx *ctx,
                      struct sss_domain_info *parent)
{
    struct sss_domain_info *dom;
    struct sdap_domain *sdom, *sditer;
    char *basedn;
    errno_t ret;

    for (dom = get_next_domain(parent, true);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, false)) {

        DLIST_FOR_EACH(sditer, ctx->sdom) {
            if (sditer->dom == dom) {
                break;
            }
        }

        if (sditer == NULL) {
            /* New sdap domain */
            DEBUG(SSSDBG_TRACE_FUNC, ("subdomain %s is a new one, will "
                  "create a new sdap domain object\n", dom->name));

            ret = sdap_domain_add(ctx->sdap_id_ctx->opts, dom, &sdom);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                    ("Cannot add new sdap domain for domain %s [%d]: %s\n",
                    parent->name, ret, strerror(ret)));
                return ret;
            }
            sditer = sdom;
        }

        /* Convert the domain name into search base */
        ret = domain_to_basedn(sditer, sditer->dom->name, &basedn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                ("Cannot convert domain name [%s] to base DN [%d]: %s\n",
                dom->name, ret, strerror(ret)));
            talloc_free(basedn);
            return ret;
        }

        /* Update search bases */
        talloc_zfree(sdom->search_bases);
        sdom->search_bases = talloc_array(sdom, struct sdap_search_base *, 2);
        if (sdom->search_bases == NULL) {
            return ret;
        }
        sdom->search_bases[1] = NULL;

        ret = sdap_create_search_base(sdom, basedn, LDAP_SCOPE_SUBTREE, NULL,
                                      &sdom->search_bases[0]);
        talloc_free(basedn);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Cannot create new sdap search base\n"));
            return ret;
        }

        sdom->user_search_bases = sdom->search_bases;
        sdom->group_search_bases = sdom->search_bases;
        sdom->netgroup_search_bases = sdom->search_bases;
        sdom->sudo_search_bases = sdom->search_bases;
        sdom->service_search_bases = sdom->search_bases;
        sdom->autofs_search_bases = sdom->search_bases;
    }

    return EOK;
}

static errno_t
ad_subdom_store(struct ad_subdomains_ctx *ctx,
                struct sss_domain_info *domain,
                struct sysdb_attrs *subdom_attrs)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    char *realm;
    const char *flat;
    errno_t ret;
    enum idmap_error_code err;
    struct ldb_message_element *el;
    char *sid_str;
    uint32_t trust_type;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_uint32_t(subdom_attrs, AD_AT_TRUST_TYPE,
                                   &trust_type);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_uint32_t failed.\n"));
        goto done;
    }

    ret = sysdb_attrs_get_string(subdom_attrs, AD_AT_TRUST_PARTNER, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("failed to get subdomain name\n"));
        goto done;
    }

    realm = get_uppercase_realm(tmp_ctx, name);
    if (!realm) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_string(subdom_attrs, AD_AT_FLATNAME, &flat);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("failed to get flat name of subdomain %s\n",
                                  name));
        goto done;
    }

    ret = sysdb_attrs_get_el(subdom_attrs, AD_AT_SID, &el);
    if (ret != EOK || el->num_values != 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_attrs_get_el failed.\n"));
        goto done;
    }

    err = sss_idmap_bin_sid_to_sid(ctx->idmap_ctx,
                                   el->values[0].data,
                                   el->values[0].length,
                                   &sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not convert SID: [%s].\n", idmap_error_string(err)));
        ret = EFAULT;
        goto done;
    }

    ret = sysdb_subdomain_store(domain->sysdb, name, realm, flat, sid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_subdomain_store failed.\n"));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t ad_subdomains_refresh(struct ad_subdomains_ctx *ctx,
                                     int count, struct sysdb_attrs **reply,
                                     bool *changes)
{
    struct sss_domain_info *domain, *dom;
    bool handled[count];
    const char *value;
    int c, h;
    int ret;

    domain = ctx->be_ctx->domain;
    memset(handled, 0, sizeof(bool) * count);
    h = 0;

    /* check existing subdomains */
    for (dom = get_next_domain(domain, true);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, false)) {
        for (c = 0; c < count; c++) {
            if (handled[c]) {
                continue;
            }
            ret = sysdb_attrs_get_string(reply[c], AD_AT_TRUST_PARTNER, &value);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
                goto done;
            }
            if (strcmp(value, dom->name) == 0) {
                break;
            }
        }

        if (c >= count) {
            /* ok this subdomain does not exist anymore, let's clean up */
            dom->disabled = true;
            ret = sysdb_subdomain_delete(dom->sysdb, dom->name);
            if (ret != EOK) {
                goto done;
            }

            /* Remove the subdomain from the list of LDAP domains */
            sdap_domain_remove(ctx->sdap_id_ctx->opts, dom);
        } else {
            /* ok let's try to update it */
            ret = ad_subdom_store(ctx, domain, reply[c]);
            if (ret) {
                /* Nothing we can do about the error. Let's at least try
                 * to reuse the existing domains
                 */
                DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to parse subdom data, "
                      "will try to use cached subdomain\n"));
            }
            handled[c] = true;
            h++;
        }
    }

    if (count == h) {
        /* all domains were already accounted for and have been updated */
        ret = EOK;
        goto done;
    }

    /* if we get here it means we have changes to the subdomains list */
    *changes = true;

    for (c = 0; c < count; c++) {
        if (handled[c]) {
            continue;
        }
        /* Nothing we can do about the error. Let's at least try
         * to reuse the existing domains.
         */
        ret = ad_subdom_store(ctx, domain, reply[c]);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to parse subdom data, "
                  "will try to use cached subdomain\n"));
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        ctx->last_refreshed = 0;
    } else {
        ctx->last_refreshed = time(NULL);
    }

    return ret;
}

static void ad_subdomains_get_conn_done(struct tevent_req *req);
static errno_t ad_subdomains_get_master_sid(struct ad_subdomains_req_ctx *ctx);
static void ad_subdomains_get_master_sid_done(struct tevent_req *req);
static void ad_subdomains_get_netlogon_done(struct tevent_req *req);
static errno_t ad_subdomains_get_slave(struct ad_subdomains_req_ctx *ctx);

static void ad_subdomains_retrieve(struct ad_subdomains_ctx *ctx,
                                   struct be_req *be_req)
{
    struct ad_subdomains_req_ctx *req_ctx = NULL;
    struct tevent_req *req;
    int dp_error = DP_ERR_FATAL;
    int ret;

    req_ctx = talloc(be_req, struct ad_subdomains_req_ctx);
    if (req_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    req_ctx->be_req = be_req;
    req_ctx->sd_ctx = ctx;
    req_ctx->current_filter = NULL;
    req_ctx->base_iter = 0;
    req_ctx->reply_count = 0;
    req_ctx->reply = NULL;

    req_ctx->sdap_op = sdap_id_op_create(req_ctx,
                                         ctx->ldap_ctx->conn_cache);
    if (req_ctx->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    req = sdap_id_op_connect_send(req_ctx->sdap_op, req_ctx, &ret);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret)));
        goto done;
    }

    tevent_req_set_callback(req, ad_subdomains_get_conn_done, req_ctx);

    return;

done:
    talloc_free(req_ctx);
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    be_req_terminate(be_req, dp_error, ret, NULL);
}

static void ad_subdomains_get_conn_done(struct tevent_req *req)
{
    int ret;
    int dp_error = DP_ERR_FATAL;
    struct ad_subdomains_req_ctx *ctx;

    ctx = tevent_req_callback_data(req, struct ad_subdomains_req_ctx);

    ret = sdap_id_op_connect_recv(req, &dp_error);
    talloc_zfree(req);
    if (ret) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("No AD server is available, cannot get the "
                   "subdomain list while offline\n"));
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to connect to AD server: [%d](%s)\n",
                   ret, strerror(ret)));
        }

        goto fail;
    }

    ret = ad_subdomains_get_master_sid(ctx);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_OP_FAILURE, ("No search base available.\n"));
    ret = EINVAL;

fail:
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static errno_t ad_subdomains_get_master_sid(struct ad_subdomains_req_ctx *ctx)
{
    struct tevent_req *req;
    struct sdap_search_base *base;
    const char *master_sid_attrs[] = {AD_AT_OBJECT_SID, NULL};


    base = ctx->sd_ctx->sdom->search_bases[ctx->base_iter];
    if (base == NULL) {
        return EOK;
    }

    req = sdap_get_generic_send(ctx, ctx->sd_ctx->be_ctx->ev,
                           ctx->sd_ctx->sdap_id_ctx->opts,
                           sdap_id_op_handle(ctx->sdap_op),
                           base->basedn, LDAP_SCOPE_BASE,
                           MASTER_DOMAIN_SID_FILTER, master_sid_attrs,
                           NULL, 0,
                           dp_opt_get_int(ctx->sd_ctx->sdap_id_ctx->opts->basic,
                                          SDAP_SEARCH_TIMEOUT),
                           false);

    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        return ENOMEM;
    }

    tevent_req_set_callback(req, ad_subdomains_get_master_sid_done, ctx);

    return EAGAIN;
}

static void ad_subdomains_get_master_sid_done(struct tevent_req *req)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ad_subdomains_req_ctx *ctx;
    struct ldb_message_element *el;
    char *sid_str;
    enum idmap_error_code err;
    static const char *attrs[] = {AD_AT_NETLOGON, NULL};
    char *filter;
    char *ntver;

    ctx = tevent_req_callback_data(req, struct ad_subdomains_req_ctx);

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send request failed.\n"));
        goto done;
    }

    if (reply_count == 0) {
        ctx->base_iter++;
        ret = ad_subdomains_get_master_sid(ctx);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            goto done;
        }
    } else if (reply_count == 1) {
        ret = sysdb_attrs_get_el(reply[0], AD_AT_OBJECT_SID, &el);
        if (ret != EOK || el->num_values != 1) {
            DEBUG(SSSDBG_OP_FAILURE, ("sdap_attrs_get_el failed.\n"));
            goto done;
        }

        err = sss_idmap_bin_sid_to_sid(ctx->sd_ctx->idmap_ctx,
                                       el->values[0].data,
                                       el->values[0].length,
                                       &sid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not convert SID: [%s].\n", idmap_error_string(err)));
            ret = EFAULT;
            goto done;
        }

        ctx->master_sid = talloc_steal(ctx, sid_str);
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              ("More than one result for domain SID found.\n"));
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Found SID [%s].\n", ctx->master_sid));

    ntver = sss_ldap_encode_ndr_uint32(ctx, NETLOGON_NT_VERSION_5EX |
                                       NETLOGON_NT_VERSION_WITH_CLOSEST_SITE);
    if (ntver == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sss_ldap_encode_ndr_uint32 failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(ctx, "(&(%s=%s)(%s=%s))",
                             AD_AT_DNS_DOMAIN, ctx->sd_ctx->domain_name,
                             AD_AT_NT_VERSION, ntver);
    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_asprintf failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    req = sdap_get_generic_send(ctx, ctx->sd_ctx->be_ctx->ev,
                           ctx->sd_ctx->sdap_id_ctx->opts,
                           sdap_id_op_handle(ctx->sdap_op),
                           "", LDAP_SCOPE_BASE, filter, attrs, NULL, 0,
                           dp_opt_get_int(ctx->sd_ctx->sdap_id_ctx->opts->basic,
                                          SDAP_SEARCH_TIMEOUT),
                           false);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, ad_subdomains_get_netlogon_done, ctx);
    return;

done:
    be_req_terminate(ctx->be_req, DP_ERR_FATAL, ret, NULL);
}

static void ad_subdomains_get_netlogon_done(struct tevent_req *req)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ad_subdomains_req_ctx *ctx;
    struct ldb_message_element *el;
    DATA_BLOB blob;
    enum ndr_err_code ndr_err;
    struct ndr_pull *ndr_pull = NULL;
    struct netlogon_samlogon_response response;
    int dp_error = DP_ERR_FATAL;

    ctx = tevent_req_callback_data(req, struct ad_subdomains_req_ctx);

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send request failed.\n"));
        goto done;
    }

    if (reply_count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No netlogon data available.\n"));
        ret = ENOENT;
        goto done;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("More than one netlogon info returned.\n"));
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_attrs_get_el(reply[0], AD_AT_NETLOGON, &el);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_el() failed\n"));
        goto done;
    }

    if (el->num_values == 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("netlogon has no value\n"));
        ret = ENOENT;
        goto done;
    } else if (el->num_values > 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("More than one netlogon value?\n"));
        ret = EIO;
        goto done;
    }

    blob.data =  el->values[0].data;
    blob.length = el->values[0].length;

    ndr_pull = ndr_pull_init_blob(&blob, ctx);
    if (ndr_pull == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ndr_pull_init_blob() failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    ndr_err = ndr_pull_netlogon_samlogon_response(ndr_pull, NDR_SCALARS,
                                                  &response);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        DEBUG(SSSDBG_OP_FAILURE, ("ndr_pull_netlogon_samlogon_response() "
                                  "failed [%d]\n", ndr_err));
        ret = EBADMSG;
        goto done;
    }

    if (!(response.ntver & NETLOGON_NT_VERSION_5EX)) {
        DEBUG(SSSDBG_OP_FAILURE, ("Wrong version returned [%x]\n",
                                  response.ntver));
        ret = EBADMSG;
        goto done;
    }

    if (response.data.nt5_ex.domain_name != NULL &&
        *response.data.nt5_ex.domain_name != '\0') {
        ctx->flat_name = talloc_strdup(ctx, response.data.nt5_ex.domain_name);
        if (ctx->flat_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Found flat name [%s].\n", ctx->flat_name));

    ret = sysdb_master_domain_add_info(ctx->sd_ctx->be_ctx->domain,
                                       NULL, ctx->flat_name, ctx->master_sid);

    ret = ad_subdomains_get_slave(ctx);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

done:
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static void ad_subdomains_get_slave_domain_done(struct tevent_req *req);

static errno_t ad_subdomains_get_slave(struct ad_subdomains_req_ctx *ctx)
{
    struct tevent_req *req;
    struct sdap_search_base *base;
    const char *slave_dom_attrs[] = { AD_AT_FLATNAME, AD_AT_TRUST_PARTNER,
                                      AD_AT_SID, AD_AT_TRUST_TYPE,
                                      AD_AT_TRUST_ATTRS, NULL };

    base = ctx->sd_ctx->sdap_id_ctx->opts->sdom->search_bases[ctx->base_iter];
    if (base == NULL) {
        return EOK;
    }

    req = sdap_get_generic_send(ctx, ctx->sd_ctx->be_ctx->ev,
                           ctx->sd_ctx->sdap_id_ctx->opts,
                           sdap_id_op_handle(ctx->sdap_op),
                           base->basedn, LDAP_SCOPE_SUBTREE,
                           SLAVE_DOMAIN_FILTER, slave_dom_attrs,
                           NULL, 0,
                           dp_opt_get_int(ctx->sd_ctx->sdap_id_ctx->opts->basic,
                                          SDAP_SEARCH_TIMEOUT),
                           false);

    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        return ENOMEM;
    }

    tevent_req_set_callback(req, ad_subdomains_get_slave_domain_done, ctx);
    return EAGAIN;
}

static void ad_subdomains_get_slave_domain_done(struct tevent_req *req)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ad_subdomains_req_ctx *ctx;
    int dp_error = DP_ERR_FATAL;
    bool refresh_has_changes = false;

    ctx = tevent_req_callback_data(req, struct ad_subdomains_req_ctx);

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send request failed.\n"));
        goto done;
    }

    if (reply_count) {
        ctx->reply = talloc_realloc(ctx, ctx->reply, struct sysdb_attrs *,
                                    ctx->reply_count + reply_count);
        if (ctx->reply == NULL) {
            ret = ENOMEM;
            goto done;
        }
        memcpy(ctx->reply+ctx->reply_count, reply,
               reply_count * sizeof(struct sysdb_attrs *));
        ctx->reply_count += reply_count;
    }

    ctx->base_iter++;
    ret = ad_subdomains_get_slave(ctx);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

    /* Got all the subdomains, let's process them */
    ret = ad_subdomains_refresh(ctx->sd_ctx, ctx->reply_count, ctx->reply,
                                &refresh_has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to refresh subdomains.\n"));
        goto done;
    }

    if (refresh_has_changes) {
        ret = sysdb_update_subdomains(ctx->sd_ctx->be_ctx->domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_update_subdomains failed.\n"));
            goto done;
        }

        ret = ads_store_sdap_subdom(ctx->sd_ctx, ctx->sd_ctx->be_ctx->domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("ads_store_sdap_subdom failed.\n"));
            goto done;
        }
    }

    ret = EOK;
done:
    if (ret == EOK) {
        ctx->sd_ctx->last_refreshed = time(NULL);
        dp_error = DP_ERR_OK;
    }
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static void ad_subdom_online_cb(void *pvt);

static void ad_subdom_timer_refresh(struct tevent_context *ev,
                                     struct tevent_timer *te,
                                     struct timeval current_time,
                                     void *pvt)
{
    ad_subdom_online_cb(pvt);
}

static void ad_subdom_be_req_callback(struct be_req *be_req,
                                       int dp_err, int dp_ret,
                                       const char *errstr)
{
    talloc_free(be_req);
}

static void ad_subdom_online_cb(void *pvt)
{
    struct ad_subdomains_ctx *ctx;
    struct be_req *be_req;
    struct timeval tv;

    ctx = talloc_get_type(pvt, struct ad_subdomains_ctx);
    if (!ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Bad private pointer\n"));
        return;
    }

    be_req = be_req_create(ctx, NULL, ctx->be_ctx,
                           ad_subdom_be_req_callback, NULL);
    if (be_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("be_req_create() failed.\n"));
        return;
    }

    ad_subdomains_retrieve(ctx, be_req);

    tv = tevent_timeval_current_ofs(AD_SUBDOMAIN_REFRESH_PERIOD, 0);
    ctx->timer_event = tevent_add_timer(ctx->be_ctx->ev, ctx, tv,
                                        ad_subdom_timer_refresh, ctx);
    if (!ctx->timer_event) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to add subdom timer event\n"));
    }
}

static void ad_subdom_offline_cb(void *pvt)
{
    struct ad_subdomains_ctx *ctx;

    ctx = talloc_get_type(pvt, struct ad_subdomains_ctx);

    if (ctx) {
        talloc_zfree(ctx->timer_event);
    }
}

void ad_subdomains_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct ad_subdomains_ctx *ctx;
    time_t now;

    ctx = talloc_get_type(be_ctx->bet_info[BET_SUBDOMAINS].pvt_bet_data,
                          struct ad_subdomains_ctx);
    if (!ctx) {
        be_req_terminate(be_req, DP_ERR_FATAL, EINVAL, NULL);
        return;
    }

    now = time(NULL);

    if (ctx->last_refreshed > now - AD_SUBDOMAIN_REFRESH_LIMIT) {
        be_req_terminate(be_req, DP_ERR_OK, EOK, NULL);
        return;
    }

    ad_subdomains_retrieve(ctx, be_req);
}

struct bet_ops ad_subdomains_ops = {
    .handler = ad_subdomains_handler,
    .finalize = NULL
};

static void *idmap_talloc(size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void idmap_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

int ad_subdom_init(struct be_ctx *be_ctx,
                   struct ad_id_ctx *id_ctx,
                   const char *ad_domain,
                   struct bet_ops **ops,
                   void **pvt_data)
{
    struct ad_subdomains_ctx *ctx;
    int ret;
    enum idmap_error_code err;

    ctx = talloc_zero(id_ctx, struct ad_subdomains_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ctx->be_ctx = be_ctx;
    ctx->sdom = id_ctx->sdap_id_ctx->opts->sdom;
    ctx->ldap_ctx = id_ctx->ldap_ctx;
    ctx->sdap_id_ctx = id_ctx->sdap_id_ctx;
    ctx->domain_name = talloc_strdup(ctx, ad_domain);
    if (ctx->domain_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
        return ENOMEM;
    }
    *ops = &ad_subdomains_ops;
    *pvt_data = ctx;

    ret = be_add_online_cb(ctx, be_ctx, ad_subdom_online_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to add subdom online callback"));
    }

    ret = be_add_offline_cb(ctx, be_ctx, ad_subdom_offline_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to add subdom offline callback"));
    }

    err = sss_idmap_init(idmap_talloc, ctx, idmap_free, &ctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to initialize idmap context.\n"));
        return EFAULT;
    }

    return EOK;
}
