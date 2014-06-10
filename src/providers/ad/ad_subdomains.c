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
#include "providers/ad/ad_domain_info.h"
#include "providers/ad/ad_srv.h"
#include "providers/ad/ad_common.h"

#include "providers/ldap/sdap_idmap.h"
#include "util/util_sss_idmap.h"
#include <ctype.h>
#include <ndr.h>
#include <ndr/ndr_nbt.h>

/* Attributes of AD trusted domains */
#define AD_AT_FLATNAME      "flatName"
#define AD_AT_SID           "securityIdentifier"
#define AD_AT_TRUST_TYPE    "trustType"
#define AD_AT_TRUST_PARTNER "trustPartner"
#define AD_AT_TRUST_ATTRS   "trustAttributes"

/* trustType=2 denotes uplevel (NT5 and later) trusted domains. See
 * http://msdn.microsoft.com/en-us/library/windows/desktop/ms680342%28v=vs.85%29.aspx
 * for example.
 *
 * The absence of msDS-TrustForestTrustInfo attribute denotes a domain from
 * the same forest. See http://msdn.microsoft.com/en-us/library/cc223786.aspx
 * for more information.
 */
#define SLAVE_DOMAIN_FILTER_BASE "(objectclass=trustedDomain)(trustType=2)(!(msDS-TrustForestTrustInfo=*))"
#define SLAVE_DOMAIN_FILTER      "(&"SLAVE_DOMAIN_FILTER_BASE")"
#define FOREST_ROOT_FILTER_FMT   "(&"SLAVE_DOMAIN_FILTER_BASE"(cn=%s))"

/* do not refresh more often than every 5 seconds for now */
#define AD_SUBDOMAIN_REFRESH_LIMIT 5

struct ad_subdomains_ctx {
    struct be_ctx *be_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx *ldap_ctx;
    struct sss_idmap_ctx *idmap_ctx;
    char *domain_name;

    time_t last_refreshed;
    struct tevent_timer *timer_event;
    struct ad_id_ctx *ad_id_ctx;
};

struct ad_subdomains_req_ctx {
    struct be_req *be_req;
    struct ad_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;

    char *current_filter;
    size_t base_iter;

    struct ad_id_ctx *root_id_ctx;
    struct sdap_id_op *root_op;
    size_t root_base_iter;
    struct sysdb_attrs *root_domain;

    size_t reply_count;
    struct sysdb_attrs **reply;

    char *master_sid;
    char *flat_name;
    char *site;
    char *forest;
};

static errno_t
ad_subdom_ad_ctx_new(struct be_ctx *be_ctx,
                     struct ad_id_ctx *id_ctx,
                     struct sss_domain_info *subdom,
                     struct ad_id_ctx **_subdom_id_ctx)
{
    struct ad_options *ad_options;
    struct ad_id_ctx *ad_id_ctx;
    const char *gc_service_name;
    struct ad_srv_plugin_ctx *srv_ctx;
    char *ad_domain;
    struct sdap_domain *sdom;
    errno_t ret;
    const char *realm;
    const char *hostname;

    realm = dp_opt_get_cstring(id_ctx->ad_options->basic, AD_KRB5_REALM);
    hostname = dp_opt_get_cstring(id_ctx->ad_options->basic, AD_HOSTNAME);
    if (realm == NULL || hostname == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Missing realm or hostname.\n");
        return EINVAL;
    }

    ad_options = ad_create_default_options(id_ctx, realm, hostname);
    if (ad_options == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD options\n");
        talloc_free(ad_options);
        return ENOMEM;
    }

    ad_domain = subdom->name;

    ret = dp_opt_set_string(ad_options->basic, AD_DOMAIN, ad_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set AD domain\n");
        talloc_free(ad_options);
        return ret;
    }

    gc_service_name = talloc_asprintf(ad_options, "%s%s", "gc_", subdom->name);
    if (gc_service_name == NULL) {
        talloc_free(ad_options);
        return ENOMEM;
    }

    ret = ad_failover_init(ad_options, be_ctx, NULL, NULL, realm,
                           subdom->name, gc_service_name,
                           subdom->name, &ad_options->service);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD failover\n");
        talloc_free(ad_options);
        return ret;
    }

    ad_id_ctx = ad_id_ctx_init(ad_options, be_ctx);
    if (ad_id_ctx == NULL) {
        talloc_free(ad_options);
        return ENOMEM;
    }
    ad_id_ctx->sdap_id_ctx->opts = ad_options->id;
    ad_options->id_ctx = ad_id_ctx;

    /* use AD plugin */
    srv_ctx = ad_srv_plugin_ctx_init(be_ctx, be_ctx->be_res,
                                     default_host_dbs,
                                     ad_id_ctx->ad_options->id,
                                     hostname,
                                     ad_domain);
    if (srv_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
        return ENOMEM;
    }
    be_fo_set_srv_lookup_plugin(be_ctx, ad_srv_plugin_send,
                                ad_srv_plugin_recv, srv_ctx, "AD");

    ret = sdap_domain_subdom_add(ad_id_ctx->sdap_id_ctx,
                                 ad_id_ctx->sdap_id_ctx->opts->sdom,
                                 subdom->parent);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize sdap domain\n");
        talloc_free(ad_options);
        return ret;
    }

    sdom = sdap_domain_get(ad_id_ctx->sdap_id_ctx->opts, subdom);
    if (sdom == NULL) {
        return EFAULT;
    }

    /* Set up the ID mapping object */
    ad_id_ctx->sdap_id_ctx->opts->idmap_ctx =
        id_ctx->sdap_id_ctx->opts->idmap_ctx;

    *_subdom_id_ctx = ad_id_ctx;
    return EOK;
}

static errno_t
ads_store_sdap_subdom(struct ad_subdomains_ctx *ctx,
                      struct sss_domain_info *parent)
{
    int ret;
    struct sdap_domain *sditer;
    struct ad_id_ctx *subdom_id_ctx;

    ret = sdap_domain_subdom_add(ctx->sdap_id_ctx, ctx->sdom, parent);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_domain_subdom_add failed.\n");
        return ret;
    }

    DLIST_FOR_EACH(sditer, ctx->sdom) {
        if (IS_SUBDOMAIN(sditer->dom) && sditer->pvt == NULL) {
            ret = ad_subdom_ad_ctx_new(ctx->be_ctx, ctx->ad_id_ctx,
                                       sditer->dom, &subdom_id_ctx);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "ad_subdom_ad_ctx_new failed.\n");
            } else {
                sditer->pvt = subdom_id_ctx;
            }
        }
    }

    return EOK;
}

static errno_t ad_subdom_enumerates(struct sss_domain_info *parent,
                                    struct sysdb_attrs *attrs,
                                    bool *_enumerates)
{
    errno_t ret;
    const char *name;

    ret = sysdb_attrs_get_string(attrs, AD_AT_TRUST_PARTNER, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        return ret;
    }

    *_enumerates = subdomain_enumerates(parent, name);
    return EOK;
}

static errno_t
ad_subdom_store(struct ad_subdomains_ctx *ctx,
                struct sss_domain_info *domain,
                struct sysdb_attrs *subdom_attrs,
                bool enumerate)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    char *realm;
    const char *flat;
    errno_t ret;
    enum idmap_error_code err;
    struct ldb_message_element *el;
    char *sid_str = NULL;
    uint32_t trust_type;
    bool mpg;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_uint32_t(subdom_attrs, AD_AT_TRUST_TYPE,
                                   &trust_type);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_uint32_t failed.\n");
        goto done;
    }

    ret = sysdb_attrs_get_string(subdom_attrs, AD_AT_TRUST_PARTNER, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to get subdomain name\n");
        goto done;
    }

    realm = get_uppercase_realm(tmp_ctx, name);
    if (!realm) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_string(subdom_attrs, AD_AT_FLATNAME, &flat);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to get flat name of subdomain %s\n",
                                  name);
        goto done;
    }

    ret = sysdb_attrs_get_el(subdom_attrs, AD_AT_SID, &el);
    if (ret != EOK || el->num_values != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_attrs_get_el failed.\n");
        goto done;
    }

    err = sss_idmap_bin_sid_to_sid(ctx->idmap_ctx,
                                   el->values[0].data,
                                   el->values[0].length,
                                   &sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not convert SID: [%s].\n", idmap_error_string(err));
        ret = EFAULT;
        goto done;
    }

    mpg = sdap_idmap_domain_has_algorithmic_mapping(
                                             ctx->sdap_id_ctx->opts->idmap_ctx,
                                             name,
                                             sid_str);

    ret = sysdb_subdomain_store(domain->sysdb, name, realm, flat, sid_str,
                                mpg, enumerate, domain->forest);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_subdomain_store failed.\n");
        goto done;
    }

    ret = EOK;
done:
    sss_idmap_free_sid(ctx->sdap_id_ctx->opts->idmap_ctx->map, sid_str);
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t ad_subdomains_refresh(struct ad_subdomains_ctx *ctx,
                                     int count, bool root_domain,
                                     struct sysdb_attrs **reply,
                                     bool *changes)
{
    struct sdap_domain *sdom;
    struct sss_domain_info *domain, *dom;
    bool handled[count];
    const char *value;
    const char *root_name = NULL;
    int c, h;
    int ret;
    bool enumerate;

    domain = ctx->be_ctx->domain;
    memset(handled, 0, sizeof(bool) * count);
    h = 0;

    if (root_domain) {
        ret = sysdb_attrs_get_string(reply[0], AD_AT_TRUST_PARTNER,
                                     &root_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
    }

    /* check existing subdomains */
    for (dom = get_next_domain(domain, true);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, false)) {

        /* If we are handling root domain, skip all the other domains. We don't
         * want to accidentally remove non-root domains
         */
        if (root_name && strcmp(root_name, dom->name) != 0) {
            continue;
        }

        for (c = 0; c < count; c++) {
            if (handled[c]) {
                continue;
            }
            ret = sysdb_attrs_get_string(reply[c], AD_AT_TRUST_PARTNER, &value);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
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

            sdom = sdap_domain_get(ctx->sdap_id_ctx->opts, dom);
            if (sdom == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Domain does not exist?\n");
                continue;
            }

            /* Remove the subdomain from the list of LDAP domains */
            sdap_domain_remove(ctx->sdap_id_ctx->opts, dom);

            be_ptask_destroy(&sdom->enum_task);
            be_ptask_destroy(&sdom->cleanup_task);

            /* terminate all requests for this subdomain so we can free it */
            be_terminate_domain_requests(ctx->be_ctx, dom->name);
            talloc_zfree(sdom);
        } else {
            /* ok let's try to update it */
            ret = ad_subdom_enumerates(domain, reply[c], &enumerate);
            if (ret != EOK) {
                goto done;
            }

            ret = ad_subdom_store(ctx, domain, reply[c], enumerate);
            if (ret) {
                /* Nothing we can do about the error. Let's at least try
                 * to reuse the existing domains
                 */
                DEBUG(SSSDBG_MINOR_FAILURE, "Failed to parse subdom data, "
                      "will try to use cached subdomain\n");
            }
            handled[c] = true;
            h++;
        }
    }

    if (count == h) {
        /* all domains were already accounted for and have been updated */
        ret = EOK;
        *changes = false;
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
        ret = ad_subdom_enumerates(domain, reply[c], &enumerate);
        if (ret != EOK) {
            goto done;
        }

        ret = ad_subdom_store(ctx, domain, reply[c], enumerate);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to parse subdom data, "
                  "will try to use cached subdomain\n");
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

static errno_t ad_subdom_reinit(struct ad_subdomains_ctx *ctx)
{
    errno_t ret;

    ret = sysdb_update_subdomains(ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_subdomains failed.\n");
        return ret;
    }

    ret = sss_write_domain_mappings(ctx->be_ctx->domain, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_krb5_write_mappings failed.\n");
        /* Just continue */
    }

    ret = ads_store_sdap_subdom(ctx, ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ads_store_sdap_subdom failed.\n");
        return ret;
    }

    return EOK;
}

static void ad_subdomains_get_conn_done(struct tevent_req *req);
static void ad_subdomains_master_dom_done(struct tevent_req *req);
static errno_t ad_subdomains_get_root(struct ad_subdomains_req_ctx *ctx);
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
    req_ctx->root_base_iter = 0;
    req_ctx->root_id_ctx = NULL;
    req_ctx->root_op = NULL;
    req_ctx->root_domain = NULL;
    req_ctx->reply_count = 0;
    req_ctx->reply = NULL;

    req_ctx->sdap_op = sdap_id_op_create(req_ctx,
                                         ctx->ldap_ctx->conn_cache);
    if (req_ctx->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        ret = ENOMEM;
        goto done;
    }

    req = sdap_id_op_connect_send(req_ctx->sdap_op, req_ctx, &ret);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
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
                  "No AD server is available, cannot get the "
                   "subdomain list while offline\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to AD server: [%d](%s)\n",
                   ret, strerror(ret));
        }

        goto fail;
    }

    req = ad_master_domain_send(ctx, ctx->sd_ctx->be_ctx->ev,
                                ctx->sd_ctx->ldap_ctx,
                                ctx->sdap_op,
                                ctx->sd_ctx->domain_name);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_master_domain_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, ad_subdomains_master_dom_done, ctx);
    return;

fail:
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static void ad_subdomains_master_dom_done(struct tevent_req *req)
{
    struct ad_subdomains_req_ctx *ctx;
    errno_t ret;

    ctx = tevent_req_callback_data(req, struct ad_subdomains_req_ctx);

    ret = ad_master_domain_recv(req, ctx,
                                &ctx->flat_name, &ctx->master_sid,
                                &ctx->site, &ctx->forest);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot retrieve master domain info\n");
        goto done;
    }

    ret = sysdb_master_domain_add_info(ctx->sd_ctx->be_ctx->domain,
                                       ctx->flat_name, ctx->master_sid,
                                       ctx->forest);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot save master domain info\n");
        goto done;
    }

    if (ctx->forest == NULL ||
          strcasecmp(ctx->sd_ctx->be_ctx->domain->name, ctx->forest) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "SSSD needs to look up the forest root domain\n");
        ret = ad_subdomains_get_root(ctx);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Connected to forest root, looking up child domains..\n");

        ctx->root_op = ctx->sdap_op;
        ctx->root_id_ctx = ctx->sd_ctx->ad_id_ctx;

        ret = ad_subdomains_get_slave(ctx);
    }

    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

done:
    be_req_terminate(ctx->be_req, DP_ERR_FATAL, ret, NULL);
}

static void ad_subdomains_get_root_domain_done(struct tevent_req *req);

static errno_t ad_subdomains_get_root(struct ad_subdomains_req_ctx *ctx)
{
    struct tevent_req *req;
    struct sdap_search_base *base;
    struct sdap_id_ctx *sdap_id_ctx;
    char *filter;
    const char *forest_root_attrs[] = { AD_AT_FLATNAME, AD_AT_TRUST_PARTNER,
                                        AD_AT_SID, AD_AT_TRUST_TYPE,
                                        AD_AT_TRUST_ATTRS, NULL };

    sdap_id_ctx = ctx->sd_ctx->sdap_id_ctx;
    base = sdap_id_ctx->opts->sdom->search_bases[ctx->root_base_iter];
    if (base == NULL) {
        return EOK;
    }

    filter = talloc_asprintf(ctx, FOREST_ROOT_FILTER_FMT, ctx->forest);
    if (filter == NULL) {
        return ENOMEM;
    }

    req = sdap_get_generic_send(ctx, ctx->sd_ctx->be_ctx->ev,
                                sdap_id_ctx->opts,
                                sdap_id_op_handle(ctx->sdap_op),
                                base->basedn, LDAP_SCOPE_SUBTREE,
                                filter, forest_root_attrs,
                                NULL, 0,
                                dp_opt_get_int(sdap_id_ctx->opts->basic,
                                                SDAP_SEARCH_TIMEOUT),
                                false);

    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, ad_subdomains_get_root_domain_done, ctx);
    return EAGAIN;
}

static struct ad_id_ctx *ads_get_root_id_ctx(struct ad_subdomains_req_ctx *ctx);
static void ad_subdomains_root_conn_done(struct tevent_req *req);

static void ad_subdomains_get_root_domain_done(struct tevent_req *req)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ad_subdomains_req_ctx *ctx;
    int dp_error = DP_ERR_FATAL;
    bool has_changes = false;

    ctx = tevent_req_callback_data(req, struct ad_subdomains_req_ctx);

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send request failed.\n");
        goto fail;
    }

    if (reply_count == 0) {
        /* If no root domain was found in the default search base, try the
         * next one, if available
         */
        ctx->root_base_iter++;
        ret = ad_subdomains_get_root(ctx);
        if (ret == EAGAIN) {
            return;
        }

        goto fail;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Multiple results for root domain search, "
              "domain list might be incomplete!\n");

        ctx->root_op = ctx->sdap_op;
        ctx->root_id_ctx = ctx->sd_ctx->ad_id_ctx;

        ret = ad_subdomains_get_slave(ctx);
        if (ret == EAGAIN) {
            return;
        }

        goto fail;
    }
    /* Exactly one result, good. */

    /* We won't use the operation to the local LDAP anymore, but
     * read from the forest root
     */
    ret = sdap_id_op_done(ctx->sdap_op, ret, &dp_error);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No AD server is available, cannot get the "
                   "subdomain list while offline\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to search the AD server: [%d](%s)\n",
                  ret, strerror(ret));
        }
        goto fail;
    }

    ret = ad_subdomains_refresh(ctx->sd_ctx, 1, true, reply, &has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_subdomains_refresh failed.\n");
        goto fail;
    }

    if (has_changes) {
        ret = ad_subdom_reinit(ctx->sd_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not reinitialize subdomains\n");
            goto fail;
        }
    }

    ctx->root_domain = reply[0];
    ctx->root_id_ctx = ads_get_root_id_ctx(ctx);
    if (ctx->root_id_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot create id ctx for the root domain\n");
        ret = EFAULT;
        goto fail;
    }

    ctx->root_op = sdap_id_op_create(ctx,
                                     ctx->root_id_ctx->ldap_ctx->conn_cache);
    if (ctx->root_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    req = sdap_id_op_connect_send(ctx->root_op, ctx, &ret);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
        goto fail;
    }

    tevent_req_set_callback(req, ad_subdomains_root_conn_done, ctx);
    return;

fail:
    if (ret == EOK) {
        ctx->sd_ctx->last_refreshed = time(NULL);
        dp_error = DP_ERR_OK;
    }
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static struct ad_id_ctx *ads_get_root_id_ctx(struct ad_subdomains_req_ctx *ctx)
{
    errno_t ret;
    const char *name;
    struct sss_domain_info *root;
    struct sdap_domain *sdom;
    struct ad_id_ctx *root_id_ctx;

    ret = sysdb_attrs_get_string(ctx->root_domain, AD_AT_TRUST_PARTNER, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        return NULL;
    }

    /* With a subsequent run, the root should already be known */
    root = find_subdomain_by_name(ctx->sd_ctx->be_ctx->domain,
                                  name, false);
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not find the root domain\n");
        return NULL;
    }

    sdom = sdap_domain_get(ctx->sd_ctx->ad_id_ctx->sdap_id_ctx->opts, root);
    if (sdom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the sdom for %s!\n", root->name);
        return NULL;
    }

    if (sdom->pvt == NULL) {
        ret = ad_subdom_ad_ctx_new(ctx->sd_ctx->be_ctx,
                                   ctx->sd_ctx->ad_id_ctx,
                                   root,
                                   &root_id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ad_subdom_ad_ctx_new failed.\n");
            return NULL;
        }
        sdom->pvt = root_id_ctx;
    } else {
        root_id_ctx = sdom->pvt;
    }

    return root_id_ctx;
}

static void ad_subdomains_root_conn_done(struct tevent_req *req)
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
                  "No AD server is available, cannot get the "
                  "subdomain list while offline\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to AD server: [%d](%s)\n",
                  ret, strerror(ret));
        }

        goto fail;
    }

    ret = ad_subdomains_get_slave(ctx);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto fail;
    }

fail:
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

    base = ctx->root_id_ctx->sdap_id_ctx->opts->sdom->search_bases[ctx->base_iter];
    if (base == NULL) {
        return EOK;
    }

    req = sdap_get_generic_send(ctx, ctx->sd_ctx->be_ctx->ev,
                           ctx->root_id_ctx->sdap_id_ctx->opts,
                           sdap_id_op_handle(ctx->root_op),
                           base->basedn, LDAP_SCOPE_SUBTREE,
                           SLAVE_DOMAIN_FILTER, slave_dom_attrs,
                           NULL, 0,
                           dp_opt_get_int(ctx->root_id_ctx->sdap_id_ctx->opts->basic,
                                          SDAP_SEARCH_TIMEOUT),
                           false);

    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, ad_subdomains_get_slave_domain_done, ctx);
    return EAGAIN;
}

static errno_t ad_subdomains_process(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     size_t nsd, struct sysdb_attrs **sd,
                                     struct sysdb_attrs *root,
                                     size_t *_nsd_out,
                                     struct sysdb_attrs ***_sd_out)
{
    size_t i, sdi;
    struct sysdb_attrs **sd_out;
    const char *sd_name;
    errno_t ret;

    if (root == NULL) {
        /* We are connected directly to the root domain. The 'sd'
         * list is complete and we can just use it
         */
        *_nsd_out = nsd;
        *_sd_out = sd;
        return EOK;
    }

    /* If we searched for root separately, we must:
     *  a) treat the root domain as a subdomain
     *  b) filter the subdomain we are connected to from the subdomain
     *     list, from our point of view, it's the master domain
     */
    sd_out = talloc_zero_array(mem_ctx, struct sysdb_attrs *, nsd+1);
    if (sd_out == NULL) {
        return ENOMEM;
    }

    sdi = 0;
    for (i = 0; i < nsd; i++) {
        ret = sysdb_attrs_get_string(sd[i], AD_AT_TRUST_PARTNER, &sd_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto fail;
        }

        if (strcasecmp(sd_name, domain->name) == 0) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Not including primary domain %s in the subdomain list\n",
                  domain->name);
            continue;
        }

        sd_out[sdi] = talloc_steal(sd_out, sd[i]);
        sdi++;
    }

    /* Now include the root */
    sd_out[sdi] = talloc_steal(sd_out, root);

    *_nsd_out = sdi+1;
    *_sd_out = sd_out;
    return EOK;

fail:
    talloc_free(sd_out);
    return ret;
}

static void ad_subdomains_get_slave_domain_done(struct tevent_req *req)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ad_subdomains_req_ctx *ctx;
    int dp_error = DP_ERR_FATAL;
    bool refresh_has_changes = false;
    size_t nsubdoms;
    struct sysdb_attrs **subdoms;

    ctx = tevent_req_callback_data(req, struct ad_subdomains_req_ctx);

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send request failed.\n");
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
        /* Search in progress */
        return;
    }

    ret = sdap_id_op_done(ctx->root_op, ret, &dp_error);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No AD server is available, cannot get the "
                   "subdomain list while offline\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to search the AD server: [%d](%s)\n",
                  ret, strerror(ret));
        }
        tevent_req_error(req, ret);
        return;
    }

    /* Based on whether we are connected to the forest root or not, we might
     * need to exclude the subdomain we are connected to from the list of
     * subdomains
     */
    ret = ad_subdomains_process(ctx, ctx->sd_ctx->be_ctx->domain,
                                ctx->reply_count, ctx->reply,
                                ctx->root_domain, &nsubdoms, &subdoms);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot process subdomain list\n"));
        tevent_req_error(req, ret);
        return;
    }

    /* Got all the subdomains, let's process them */
    ret = ad_subdomains_refresh(ctx->sd_ctx, nsubdoms, false, subdoms,
                                &refresh_has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to refresh subdomains.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "There are %schanges\n",
                    refresh_has_changes ? "" : "no ");

    if (refresh_has_changes) {
        ret = ad_subdom_reinit(ctx->sd_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not reinitialize subdomains\n");
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
    uint32_t refresh_interval;

    ctx = talloc_get_type(pvt, struct ad_subdomains_ctx);
    if (!ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bad private pointer\n");
        return;
    }

    refresh_interval = ctx->be_ctx->domain->subdomain_refresh_interval;

    be_req = be_req_create(ctx, NULL, ctx->be_ctx,
                           ad_subdom_be_req_callback, NULL);
    if (be_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_req_create() failed.\n");
        return;
    }

    ad_subdomains_retrieve(ctx, be_req);

    tv = tevent_timeval_current_ofs(refresh_interval, 0);
    ctx->timer_event = tevent_add_timer(ctx->be_ctx->ev, ctx, tv,
                                        ad_subdom_timer_refresh, ctx);
    if (!ctx->timer_event) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add subdom timer event\n");
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
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ctx->be_ctx = be_ctx;
    ctx->sdom = id_ctx->sdap_id_ctx->opts->sdom;
    ctx->ldap_ctx = id_ctx->ldap_ctx;
    ctx->sdap_id_ctx = id_ctx->sdap_id_ctx;
    ctx->domain_name = talloc_strdup(ctx, ad_domain);
    if (ctx->domain_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        return ENOMEM;
    }
    ctx->ad_id_ctx = id_ctx;
    *ops = &ad_subdomains_ops;
    *pvt_data = ctx;

    ret = be_add_online_cb(ctx, be_ctx, ad_subdom_online_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add subdom online callback");
    }

    ret = be_add_offline_cb(ctx, be_ctx, ad_subdom_offline_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add subdom offline callback");
    }

    err = sss_idmap_init(sss_idmap_talloc, ctx, sss_idmap_talloc_free,
                         &ctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize idmap context.\n");
        return EFAULT;
    }

    ret = ad_subdom_reinit(ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not reinitialize subdomains. "
              "Users from trusted domains might not be resolved correctly\n");
        /* Ignore this error and try to discover the subdomains later */
    }

    return EOK;
}
