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
#include "providers/ldap/sdap_ops.h"
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

static errno_t ad_get_enabled_domains(TALLOC_CTX *mem_ctx,
                                      struct ad_id_ctx *ad_id_ctx,
                                      const char *ad_domain,
                                      const char ***_ad_enabled_domains)
{
    int ret;
    const char *str;
    const char *option_name;
    const char **domains = NULL;
    int count;
    bool is_ad_in_domains;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    str = dp_opt_get_cstring(ad_id_ctx->ad_options->basic, AD_ENABLED_DOMAINS);
    if (str == NULL) {
        *_ad_enabled_domains = NULL;
        ret = EOK;
        goto done;
    }

    count = 0;
    ret = split_on_separator(tmp_ctx, str, ',', true, true,
                             discard_const_p(char **, &domains), &count);
    if (ret != EOK) {
        option_name = ad_id_ctx->ad_options->basic[AD_ENABLED_DOMAINS].opt_name;
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse option [%s], [%i] [%s]!\n",
                                   option_name, ret, sss_strerror(ret));
        ret = EINVAL;
        goto done;
    }

    is_ad_in_domains = false;
    for (int i = 0; i < count; i++) {
        is_ad_in_domains += strcmp(ad_domain, domains[i]) == 0 ? true : false;
    }

    if (is_ad_in_domains == false) {
        domains = talloc_realloc(tmp_ctx, domains, const char*, count + 2);
        if (domains == NULL) {
            ret = ENOMEM;
            goto done;
        }

        domains[count] = talloc_strdup(domains, ad_domain);
        if (domains[count] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        domains[count + 1] = NULL;
    } else {
        domains = talloc_realloc(tmp_ctx, domains, const char*, count + 1);
        if (domains == NULL) {
            ret = ENOMEM;
            goto done;
        }

        domains[count] = NULL;
    }

    *_ad_enabled_domains = talloc_steal(mem_ctx, domains);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static bool is_domain_enabled(const char *domain,
                              const char **enabled_doms)
{
    if (enabled_doms == NULL) {
        return true;
    }

    return string_in_list(domain, discard_const_p(char *, enabled_doms), false);
}

static errno_t
update_parent_sdap_list(struct sdap_domain *parent_list,
                        struct sdap_domain *child_sdap)
{
    struct sdap_domain *sditer;

    DLIST_FOR_EACH(sditer, parent_list) {
        if (sditer->dom == child_sdap->dom) {
            break;
        }
    }

    if (sditer == NULL) {
        /* Nothing to do */
        return EOK;
    }

    /* Update the search bases */
    sdap_domain_copy_search_bases(sditer, child_sdap);

    return EOK;
}

static errno_t
ad_subdom_ad_ctx_new(struct be_ctx *be_ctx,
                     struct ad_id_ctx *id_ctx,
                     struct sss_domain_info *subdom,
                     struct ad_id_ctx **_subdom_id_ctx)
{
    struct ad_options *ad_options;
    struct ad_id_ctx *ad_id_ctx;
    const char *gc_service_name;
    const char *service_name;
    struct ad_srv_plugin_ctx *srv_ctx;
    char *ad_domain;
    char *ad_site_override;
    struct sdap_domain *sdom;
    errno_t ret;
    const char *realm;
    const char *servers;
    const char *backup_servers;
    const char *hostname;
    const char *keytab;
    char *subdom_conf_path;

    realm = dp_opt_get_cstring(id_ctx->ad_options->basic, AD_KRB5_REALM);
    hostname = dp_opt_get_cstring(id_ctx->ad_options->basic, AD_HOSTNAME);
    keytab = dp_opt_get_cstring(id_ctx->ad_options->basic, AD_KEYTAB);
    ad_domain = subdom->name;
    if (realm == NULL || hostname == NULL || ad_domain == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Missing realm or hostname.\n");
        return EINVAL;
    }

    subdom_conf_path = subdomain_create_conf_path(id_ctx, subdom);
    if (subdom_conf_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "subdom_conf_path failed\n");
        return ENOMEM;
    }

    ad_options = ad_create_2way_trust_options(id_ctx, be_ctx->cdb,
                                              subdom_conf_path, realm, subdom,
                                              hostname, keytab);
    talloc_free(subdom_conf_path);
    if (ad_options == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD options\n");
        talloc_free(ad_options);
        return ENOMEM;
    }

    ad_site_override = dp_opt_get_string(ad_options->basic, AD_SITE);

    gc_service_name = talloc_asprintf(ad_options, "sd_gc_%s", subdom->name);
    if (gc_service_name == NULL) {
        talloc_free(ad_options);
        return ENOMEM;
    }

    service_name = talloc_asprintf(ad_options, "sd_%s", subdom->name);
    if (service_name == NULL) {
        talloc_free(ad_options);
        return ENOMEM;
    }

    servers = dp_opt_get_string(ad_options->basic, AD_SERVER);
    backup_servers = dp_opt_get_string(ad_options->basic, AD_BACKUP_SERVER);

    ret = ad_failover_init(ad_options, be_ctx, servers, backup_servers, realm,
                           service_name, gc_service_name,
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
                                     ad_domain,
                                     ad_site_override);
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

    sdap_inherit_options(subdom->parent->sd_inherit,
                         id_ctx->sdap_id_ctx->opts,
                         ad_id_ctx->sdap_id_ctx->opts);

    /* Set up the ID mapping object */
    ad_id_ctx->sdap_id_ctx->opts->idmap_ctx =
        id_ctx->sdap_id_ctx->opts->idmap_ctx;

    ret = ad_set_search_bases(ad_options->id, sdom);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to set LDAP search bases for "
              "domain '%s'. Will try to use automatically detected search "
              "bases.", subdom->name);
    }

    ret = update_parent_sdap_list(id_ctx->sdap_id_ctx->opts->sdom,
                                  sdom);
    if (ret != EOK) {
        return ret;
    }

    *_subdom_id_ctx = ad_id_ctx;
    return EOK;
}

struct ad_subdomains_ctx {
    struct be_ctx *be_ctx;
    struct ad_id_ctx *ad_id_ctx;
    struct sdap_id_ctx *sdap_id_ctx;

    struct sdap_domain *sdom;
    char *domain_name;
    const char **ad_enabled_domains;

    time_t last_refreshed;
};

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
ad_subdom_store(struct sdap_idmap_ctx *idmap_ctx,
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

    err = sss_idmap_bin_sid_to_sid(idmap_ctx->map, el->values[0].data,
                                   el->values[0].length, &sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not convert SID: [%s].\n", idmap_error_string(err));
        ret = EFAULT;
        goto done;
    }

    mpg = sdap_idmap_domain_has_algorithmic_mapping(idmap_ctx, name, sid_str);

    ret = sysdb_subdomain_store(domain->sysdb, name, realm, flat, sid_str,
                                mpg, enumerate, domain->forest, 0, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_subdomain_store failed.\n");
        goto done;
    }

    ret = EOK;
done:
    sss_idmap_free_sid(idmap_ctx->map, sid_str);
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t ad_subdomains_refresh(struct be_ctx *be_ctx,
                                     struct sdap_idmap_ctx *idmap_ctx,
                                     struct sdap_options *opts,
                                     struct sysdb_attrs **subdomains,
                                     size_t num_subdomains,
                                     bool root_domain,
                                     time_t *_last_refreshed,
                                     bool *_changes)
{
    struct sdap_domain *sdom;
    struct sss_domain_info *domain;
    struct sss_domain_info *dom;
    bool handled[num_subdomains];
    const char *value;
    const char *root_name = NULL;
    size_t c, h;
    int ret;
    bool enumerate;

    domain = be_ctx->domain;
    memset(handled, 0, sizeof(bool) * num_subdomains);
    h = 0;

    if (root_domain) {
        ret = sysdb_attrs_get_string(subdomains[0], AD_AT_TRUST_PARTNER,
                                     &root_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
    }

    /* check existing subdomains */
    for (dom = get_next_domain(domain, SSS_GND_DESCEND);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, 0)) {

        /* If we are handling root domain, skip all the other domains. We don't
         * want to accidentally remove non-root domains
         */
        if (root_name && strcmp(root_name, dom->name) != 0) {
            continue;
        }

        for (c = 0; c < num_subdomains; c++) {
            if (handled[c]) {
                continue;
            }
            ret = sysdb_attrs_get_string(subdomains[c], AD_AT_TRUST_PARTNER,
                                         &value);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
                goto done;
            }
            if (strcmp(value, dom->name) == 0) {
                break;
            }
        }

        if (c >= num_subdomains) {
            /* ok this subdomain does not exist anymore, let's clean up */
            sss_domain_set_state(dom, DOM_DISABLED);

            /* Just disable the forest root but do not remove sdap data */
            if (sss_domain_is_forest_root(dom)) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Skipping removal of forest root sdap data.\n");
                continue;
            }

            ret = sysdb_subdomain_delete(dom->sysdb, dom->name);
            if (ret != EOK) {
                goto done;
            }

            sdom = sdap_domain_get(opts, dom);
            if (sdom == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Domain does not exist?\n");
                continue;
            }

            /* Remove the subdomain from the list of LDAP domains */
            sdap_domain_remove(opts, dom);

            be_ptask_destroy(&sdom->enum_task);
            be_ptask_destroy(&sdom->cleanup_task);

            /* terminate all requests for this subdomain so we can free it */
            dp_terminate_domain_requests(be_ctx->provider, dom->name);
            talloc_zfree(sdom);
        } else {
            /* ok let's try to update it */
            ret = ad_subdom_enumerates(domain, subdomains[c], &enumerate);
            if (ret != EOK) {
                goto done;
            }

            ret = ad_subdom_store(idmap_ctx, domain, subdomains[c], enumerate);
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

    if (num_subdomains == h) {
        /* all domains were already accounted for and have been updated */
        ret = EOK;
        *_changes = false;
        goto done;
    }

    /* if we get here it means we have changes to the subdomains list */
    *_changes = true;

    for (c = 0; c < num_subdomains; c++) {
        if (handled[c]) {
            continue;
        }
        /* Nothing we can do about the error. Let's at least try
         * to reuse the existing domains.
         */
        ret = ad_subdom_enumerates(domain, subdomains[c], &enumerate);
        if (ret != EOK) {
            goto done;
        }

        ret = ad_subdom_store(idmap_ctx, domain, subdomains[c], enumerate);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to parse subdom data, "
                  "will try to use cached subdomain\n");
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        *_last_refreshed = 0;
    } else {
        *_last_refreshed = time(NULL);
    }

    return ret;
}

static errno_t ad_subdomains_process(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     const char **enabled_domains_list,
                                     size_t nsd, struct sysdb_attrs **sd,
                                     struct sysdb_attrs *root,
                                     size_t *_nsd_out,
                                     struct sysdb_attrs ***_sd_out)
{
    size_t i, sdi;
    struct sysdb_attrs **sd_out;
    const char *sd_name;
    const char *root_name;
    errno_t ret;

    if (root == NULL && enabled_domains_list == NULL) {
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

        if (is_domain_enabled(sd_name, enabled_domains_list) == false) {
            DEBUG(SSSDBG_TRACE_FUNC, "Disabling subdomain %s\n", sd_name);
            continue;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Enabling subdomain %s\n", sd_name);
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
    if (root != NULL) {
        ret = sysdb_attrs_get_string(root, AD_AT_TRUST_PARTNER, &root_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto fail;
        }

        if (is_domain_enabled(root_name, enabled_domains_list) == true) {
            sd_out[sdi] = talloc_steal(sd_out, root);
            sdi++;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Disabling forest root domain %s\n",
                                     root_name);
        }
    }

    *_nsd_out = sdi;
    *_sd_out = sd_out;
    return EOK;

fail:
    talloc_free(sd_out);
    return ret;
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

    ret = ad_set_search_bases(ctx->ad_id_ctx->ad_options->id, ctx->sdom);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "failed to set ldap search bases for "
              "domain '%s'. will try to use automatically detected search "
              "bases.", ctx->sdom->dom->name);
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

static errno_t ad_subdom_reinit(struct ad_subdomains_ctx *subdoms_ctx)
{
    const char *path;
    errno_t ret;
    bool canonicalize = false;
    struct sss_domain_info *dom;

    path = dp_opt_get_string(subdoms_ctx->ad_id_ctx->ad_options->basic,
                             AD_KRB5_CONFD_PATH);

    if (subdoms_ctx->ad_id_ctx->ad_options->auth_ctx != NULL
            && subdoms_ctx->ad_id_ctx->ad_options->auth_ctx->opts != NULL) {
        canonicalize = dp_opt_get_bool(
                             subdoms_ctx->ad_id_ctx->ad_options->auth_ctx->opts,
                             KRB5_CANONICALIZE);
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "Auth provider data is not available, "
                                    "most probably because the auth provider "
                                    "is not 'ad'. Kerberos configuration "
                                    "snippet to set the 'canonicalize' option "
                                    "will not be created.\n");
    }

    ret = sss_write_krb5_conf_snippet(path, canonicalize, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_write_krb5_conf_snippet failed.\n");
        /* Just continue */
    }

    ret = sysdb_update_subdomains(subdoms_ctx->be_ctx->domain,
                                  subdoms_ctx->be_ctx->cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_subdomains failed.\n");
        return ret;
    }

    ret = sss_write_domain_mappings(subdoms_ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_krb5_write_mappings failed.\n");
        /* Just continue */
    }

    ret = ads_store_sdap_subdom(subdoms_ctx, subdoms_ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ads_store_sdap_subdom failed.\n");
        return ret;
    }

    /* Make sure disabled domains are not re-enabled accidentially */
    if (subdoms_ctx->ad_enabled_domains != NULL) {
        for (dom = subdoms_ctx->be_ctx->domain->subdomains; dom;
                                            dom = get_next_domain(dom, false)) {
            if (!is_domain_enabled(dom->name,
                                   subdoms_ctx->ad_enabled_domains)) {
                sss_domain_set_state(dom, DOM_DISABLED);
            }
        }
    }

    return EOK;
}

struct ad_get_slave_domain_state {
    struct tevent_context *ev;
    struct ad_subdomains_ctx *sd_ctx;
    struct be_ctx *be_ctx;
    struct sdap_options *opts;
    struct sdap_idmap_ctx *idmap_ctx;
    struct sysdb_attrs *root_attrs;
    struct sdap_id_op *sdap_op;
};

static errno_t ad_get_slave_domain_retry(struct tevent_req *req);
static void ad_get_slave_domain_connect_done(struct tevent_req *subreq);
static void ad_get_slave_domain_done(struct tevent_req *subreq);

static struct tevent_req *
ad_get_slave_domain_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct ad_subdomains_ctx *sd_ctx,
                         struct sysdb_attrs *root_attrs,
                         struct ad_id_ctx *root_id_ctx)
{
    struct ad_get_slave_domain_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_get_slave_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->sd_ctx = sd_ctx;
    state->be_ctx = sd_ctx->be_ctx;
    state->opts = root_id_ctx->sdap_id_ctx->opts;
    state->idmap_ctx = root_id_ctx->sdap_id_ctx->opts->idmap_ctx;
    state->root_attrs = root_attrs;

    state->sdap_op = sdap_id_op_create(state, root_id_ctx->ldap_ctx->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    ret = ad_get_slave_domain_retry(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t ad_get_slave_domain_retry(struct tevent_req *req)
{
    struct ad_get_slave_domain_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct ad_get_slave_domain_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, ad_get_slave_domain_connect_done, req);

    return EAGAIN;
}

static void ad_get_slave_domain_connect_done(struct tevent_req *subreq)
{
    struct ad_get_slave_domain_state *state;
    struct tevent_req *req = NULL;
    int dp_error;
    errno_t ret;
    const char *attrs[] = { AD_AT_FLATNAME, AD_AT_TRUST_PARTNER,
                            AD_AT_SID, AD_AT_TRUST_TYPE,
                            AD_AT_TRUST_ATTRS, NULL };

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_get_slave_domain_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to LDAP "
              "[%d]: %s\n", ret, sss_strerror(ret));
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE, "No AD server is available, "
                  "cannot get the subdomain list while offline\n");
            ret = ERR_OFFLINE;
        }
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_search_bases_send(state, state->ev, state->opts,
                                    sdap_id_op_handle(state->sdap_op),
                                    state->opts->sdom->search_bases,
                                    NULL, false, 0,
                                    SLAVE_DOMAIN_FILTER, attrs);
    if (subreq == NULL) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_set_callback(subreq, ad_get_slave_domain_done, req);
    return;
}

static void ad_get_slave_domain_done(struct tevent_req *subreq)
{
    struct ad_get_slave_domain_state *state;
    struct tevent_req *req;
    struct sysdb_attrs **reply;
    size_t reply_count;
    struct sysdb_attrs **subdoms;
    size_t nsubdoms;
    bool has_changes;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_get_slave_domain_state);

    ret = sdap_search_bases_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup slave domain data "
              "[%d]: %s\n", ret, sss_strerror(ret));
        /* We continue to finish sdap_id_op. */
    }

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ad_get_slave_domain_retry(req);
        if (ret != EOK) {
            goto done;
        }
        return;
    } else if (dp_error == DP_ERR_OFFLINE) {
        ret = ERR_OFFLINE;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    /* Based on whether we are connected to the forest root or not, we might
     * need to exclude the subdomain we are connected to from the list of
     * subdomains.
     */
    ret = ad_subdomains_process(state, state->be_ctx->domain,
                                state->sd_ctx->ad_enabled_domains,
                                reply_count, reply, state->root_attrs,
                                &nsubdoms, &subdoms);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot process subdomain list\n");
        tevent_req_error(req, ret);
        return;
    }

    /* Got all the subdomains, let's process them. */
    ret = ad_subdomains_refresh(state->be_ctx, state->idmap_ctx, state->opts,
                                subdoms, nsubdoms, false,
                                &state->sd_ctx->last_refreshed,
                                &has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to refresh subdomains.\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "There are %schanges\n",
          has_changes ? "" : "no ");

    if (has_changes) {
        ret = ad_subdom_reinit(state->sd_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not reinitialize subdomains\n");
            goto done;
        }
    }

    state->sd_ctx->last_refreshed = time(NULL);
    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ad_get_slave_domain_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static struct sss_domain_info *
ads_get_root_domain(struct be_ctx *be_ctx, struct sysdb_attrs *attrs)
{
    struct sss_domain_info *dom;
    const char *name;
    errno_t ret;

    ret = sysdb_attrs_get_string(attrs, AD_AT_TRUST_PARTNER, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        return NULL;
    }

    /* With a subsequent run, the root should already be known */
    for (dom = be_ctx->domain; dom != NULL;
         dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {

        if (strcasecmp(dom->name, name) == 0) {
            /* The forest root is special, although it might be disabled for
             * general lookups we still want to try to get the domains in the
             * forest from a DC of the forest root */
            if (sss_domain_get_state(dom) == DOM_DISABLED
                    && !sss_domain_is_forest_root(dom)) {
                return NULL;
            }
            return dom;
        }
    }

    return NULL;
}

static struct ad_id_ctx *
ads_get_root_id_ctx(struct be_ctx *be_ctx,
                    struct ad_id_ctx *ad_id_ctx,
                    struct sss_domain_info *root_domain,
                    struct sdap_options *opts)
{
    errno_t ret;
    struct sdap_domain *sdom;
    struct ad_id_ctx *root_id_ctx;

    sdom = sdap_domain_get(opts, root_domain);
    if (sdom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the sdom for %s!\n", root_domain->name);
        return NULL;
    }

    if (sdom->pvt == NULL) {
        ret = ad_subdom_ad_ctx_new(be_ctx, ad_id_ctx, root_domain,
                                   &root_id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ad_subdom_ad_ctx_new failed.\n");
            return NULL;
        }

        sdom->pvt = root_id_ctx;
    } else {
        root_id_ctx = sdom->pvt;
    }

    root_id_ctx->ldap_ctx->ignore_mark_offline = true;
    return root_id_ctx;
}

struct ad_get_root_domain_state {
    struct ad_subdomains_ctx *sd_ctx;
    struct be_ctx *be_ctx;
    struct sdap_idmap_ctx *idmap_ctx;
    struct sdap_options *opts;

    struct ad_id_ctx *root_id_ctx;
    struct sysdb_attrs *root_domain_attrs;
};

static void ad_get_root_domain_done(struct tevent_req *subreq);

static struct tevent_req *
ad_get_root_domain_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        const char *domain,
                        const char *forest,
                        struct sdap_handle *sh,
                        struct ad_subdomains_ctx *sd_ctx)
{
    struct ad_get_root_domain_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    struct sdap_options *opts;
    errno_t ret;
    const char *filter;
    const char *attrs[] = { AD_AT_FLATNAME, AD_AT_TRUST_PARTNER,
                            AD_AT_SID, AD_AT_TRUST_TYPE,
                            AD_AT_TRUST_ATTRS, NULL };

    req = tevent_req_create(mem_ctx, &state, struct ad_get_root_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (forest != NULL && strcasecmp(domain, forest) == 0) {
        state->root_id_ctx = sd_ctx->ad_id_ctx;
        state->root_domain_attrs = NULL;
        ret = EOK;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Looking up the forest root domain.\n");

    state->sd_ctx = sd_ctx;
    state->opts = opts = sd_ctx->sdap_id_ctx->opts;
    state->be_ctx = sd_ctx->be_ctx;
    state->idmap_ctx = opts->idmap_ctx;

    filter = talloc_asprintf(state, FOREST_ROOT_FILTER_FMT, forest);
    if (filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_search_bases_return_first_send(state, ev, opts, sh,
                                                 opts->sdom->search_bases,
                                                 NULL, false, 0, filter, attrs);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_get_root_domain_done, req);

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

static void ad_get_root_domain_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_get_root_domain_state *state;
    struct sysdb_attrs **reply;
    struct sss_domain_info *root_domain;
    size_t reply_count;
    bool has_changes;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_get_root_domain_state);

    ret = sdap_search_bases_return_first_recv(subreq, state, &reply_count,
                                              &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to lookup forest root information "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    if (reply_count == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "No information provided for root domain\n");
        ret = ENOENT;
        goto done;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Multiple results for root domain search, "
              "domain list might be incomplete!\n");
        ret = ERR_MALFORMED_ENTRY;
        goto done;
    }

    ret = ad_subdomains_refresh(state->be_ctx, state->idmap_ctx, state->opts,
                                reply, reply_count, true,
                                &state->sd_ctx->last_refreshed,
                                &has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_subdomains_refresh failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (has_changes) {
        ret = ad_subdom_reinit(state->sd_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not reinitialize subdomains\n");
            goto done;
        }
    }

    state->root_domain_attrs = reply[0];
    root_domain = ads_get_root_domain(state->be_ctx, reply[0]);
    if (root_domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not find the root domain\n");
        ret = EFAULT;
        goto done;
    }

    state->root_id_ctx = ads_get_root_id_ctx(state->be_ctx,
                                             state->sd_ctx->ad_id_ctx,
                                             root_domain, state->opts);
    if (state->root_id_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot create id ctx for the root domain\n");
        ret = EFAULT;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ad_get_root_domain_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       struct sysdb_attrs **_attrs,
                                       struct ad_id_ctx **_id_ctx)
{
    struct ad_get_root_domain_state *state = NULL;
    state = tevent_req_data(req, struct ad_get_root_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_attrs = talloc_steal(mem_ctx, state->root_domain_attrs);
    *_id_ctx = state->root_id_ctx;

    return EOK;
}

struct ad_subdomains_refresh_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ad_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;
    struct sdap_id_ctx *id_ctx;
    struct ad_options *ad_options;
};

static errno_t ad_subdomains_refresh_retry(struct tevent_req *req);
static void ad_subdomains_refresh_connect_done(struct tevent_req *subreq);
static void ad_subdomains_refresh_master_done(struct tevent_req *subreq);
static void ad_subdomains_refresh_root_done(struct tevent_req *subreq);
static void ad_subdomains_refresh_done(struct tevent_req *subreq);

static struct tevent_req *
ad_subdomains_refresh_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ad_subdomains_ctx *sd_ctx)
{
    struct ad_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_subdomains_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = sd_ctx->be_ctx;
    state->sd_ctx = sd_ctx;
    state->id_ctx = sd_ctx->sdap_id_ctx;
    state->ad_options = sd_ctx->ad_id_ctx->ad_options;

    state->sdap_op = sdap_id_op_create(state,
                                       sd_ctx->sdap_id_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    ret = ad_subdomains_refresh_retry(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t ad_subdomains_refresh_retry(struct tevent_req *req)
{
    struct ad_subdomains_refresh_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct ad_subdomains_refresh_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, ad_subdomains_refresh_connect_done, req);

    return EAGAIN;
}

static void ad_subdomains_refresh_connect_done(struct tevent_req *subreq)
{
    struct ad_subdomains_refresh_state *state;
    struct tevent_req *req;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_subdomains_refresh_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to LDAP "
              "[%d]: %s\n", ret, sss_strerror(ret));
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE, "No AD server is available, "
                  "cannot get the subdomain list while offline\n");
            ret = ERR_OFFLINE;
        }
        tevent_req_error(req, ret);
        return;
    }

    /* connect to the DC we are a member of */
    subreq = ad_master_domain_send(state, state->ev, state->id_ctx->conn,
                                   state->sdap_op, state->sd_ctx->domain_name);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ad_subdomains_refresh_master_done, req);
    return;
}

static void ad_subdomains_refresh_master_done(struct tevent_req *subreq)
{
    struct ad_subdomains_refresh_state *state;
    struct tevent_req *req;
    const char *realm;
    const char *ad_domain;
    char *master_sid;
    char *flat_name;
    char *forest;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_subdomains_refresh_state);

    ret = ad_master_domain_recv(subreq, state, &flat_name, &master_sid,
                                NULL, &forest);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get master domain information "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    realm = dp_opt_get_cstring(state->ad_options->basic, AD_KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Missing realm.\n");
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_master_domain_add_info(state->be_ctx->domain, realm,
                                       flat_name, master_sid, forest, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot save master domain info [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /*
     * If ad_enabled_domains contains only master domain
     * we shouldn't lookup other domains.
     */
    if (state->sd_ctx->ad_enabled_domains != NULL) {
        if (talloc_array_length(state->sd_ctx->ad_enabled_domains) == 2) {
            if (strcasecmp(state->sd_ctx->ad_enabled_domains[0],
                           state->be_ctx->domain->name) == 0) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "No other enabled domain than master.\n");
                goto done;
            }
        }
    }

    ad_domain = dp_opt_get_cstring(state->ad_options->basic, AD_DOMAIN);
    if (ad_domain == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
             "Missing AD domain name, falling back to sssd domain name\n");
        ad_domain = state->sd_ctx->be_ctx->domain->name;
    }

    subreq = ad_get_root_domain_send(state, state->ev, ad_domain, forest,
                                     sdap_id_op_handle(state->sdap_op),
                                     state->sd_ctx);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_subdomains_refresh_root_done, req);
    return;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void ad_subdomains_refresh_root_done(struct tevent_req *subreq)
{
    struct ad_subdomains_refresh_state *state;
    struct tevent_req *req;
    struct ad_id_ctx *root_id_ctx;
    struct sysdb_attrs *root_attrs;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_subdomains_refresh_state);

    ret = ad_get_root_domain_recv(state, subreq, &root_attrs, &root_id_ctx);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get forest root [%d]: %s\n",
              ret, sss_strerror(ret));
        root_attrs = NULL;
        root_id_ctx = NULL;
        /* We continue to finish sdap_id_op. */
    }

    /* We finish sdap_id_op here since we connect
     * to forest root for slave domains. */
    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ad_subdomains_refresh_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    } else if (dp_error == DP_ERR_OFFLINE) {
        tevent_req_error(req, ERR_OFFLINE);
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = ad_get_slave_domain_send(state, state->ev, state->sd_ctx,
                                      root_attrs, root_id_ctx);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ad_subdomains_refresh_done, req);
    return;
}

static void ad_subdomains_refresh_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = ad_get_slave_domain_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get subdomains [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Unable to refresh subdomains [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Subdomains refreshed.\n");
    tevent_req_done(req);
}

static errno_t ad_subdomains_refresh_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ad_subdomains_handler_state {
    struct dp_reply_std reply;
};

static void ad_subdomains_handler_done(struct tevent_req *subreq);

static struct tevent_req *
ad_subdomains_handler_send(TALLOC_CTX *mem_ctx,
                           struct ad_subdomains_ctx *sd_ctx,
                           struct dp_subdomains_data *data,
                           struct dp_req_params *params)
{
    struct ad_subdomains_handler_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_subdomains_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }


    if (sd_ctx->last_refreshed > time(NULL) - AD_SUBDOMAIN_REFRESH_LIMIT) {
        DEBUG(SSSDBG_TRACE_FUNC, "Subdomains were recently refreshed, "
              "nothing to do\n");
        ret = EOK;
        goto immediately;
    }

    subreq = ad_subdomains_refresh_send(state, params->ev, sd_ctx);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_subdomains_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void ad_subdomains_handler_done(struct tevent_req *subreq)
{
    struct ad_subdomains_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_subdomains_handler_state);

    ret = ad_subdomains_refresh_recv(subreq);
    talloc_zfree(subreq);

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);
    tevent_req_done(req);
}

static errno_t ad_subdomains_handler_recv(TALLOC_CTX *mem_ctx,
                                          struct tevent_req *req,
                                          struct dp_reply_std *data)
{
   struct ad_subdomains_handler_state *state;

   state = tevent_req_data(req, struct ad_subdomains_handler_state);

   TEVENT_REQ_RETURN_ON_ERROR(req);

   *data = state->reply;

   return EOK;
}

static struct tevent_req *
ad_subdomains_ptask_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct be_ctx *be_ctx,
                         struct be_ptask *be_ptask,
                         void *pvt)
{
    struct ad_subdomains_ctx *sd_ctx;
    sd_ctx = talloc_get_type(pvt, struct ad_subdomains_ctx);

    return ad_subdomains_refresh_send(mem_ctx, ev, sd_ctx);
}

static errno_t
ad_subdomains_ptask_recv(struct tevent_req *req)
{
    return ad_subdomains_refresh_recv(req);
}

errno_t ad_subdomains_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           struct ad_id_ctx *ad_id_ctx,
                           struct dp_method *dp_methods)
{
    struct ad_subdomains_ctx *sd_ctx;
    const char *ad_domain;
    const char **ad_enabled_domains = NULL;
    time_t period;
    errno_t ret;

    ad_domain = dp_opt_get_string(ad_id_ctx->ad_options->basic, AD_DOMAIN);

    sd_ctx = talloc_zero(mem_ctx, struct ad_subdomains_ctx);
    if (sd_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ret = ad_get_enabled_domains(sd_ctx, ad_id_ctx, ad_domain,
                                 &ad_enabled_domains);
    if (ret != EOK) {
        return EINVAL;
    }

    sd_ctx->be_ctx = be_ctx;
    sd_ctx->sdom = ad_id_ctx->sdap_id_ctx->opts->sdom;
    sd_ctx->sdap_id_ctx = ad_id_ctx->sdap_id_ctx;
    sd_ctx->domain_name = talloc_strdup(sd_ctx, ad_domain);
    if (sd_ctx->domain_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        return ENOMEM;
    }
    sd_ctx->ad_enabled_domains = ad_enabled_domains;
    sd_ctx->ad_id_ctx = ad_id_ctx;

    dp_set_method(dp_methods, DPM_DOMAINS_HANDLER,
                  ad_subdomains_handler_send, ad_subdomains_handler_recv, sd_ctx,
                  struct ad_subdomains_ctx, struct dp_subdomains_data, struct dp_reply_std);

    period = be_ctx->domain->subdomain_refresh_interval;
    ret = be_ptask_create(sd_ctx, be_ctx, period, 0, 0, 0, period,
                          BE_PTASK_OFFLINE_DISABLE, 0,
                          ad_subdomains_ptask_send, ad_subdomains_ptask_recv, sd_ctx,
                          "Subdomains Refresh", NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup ptask "
              "[%d]: %s\n", ret, sss_strerror(ret));
        /* Ignore, responders will trigger refresh from time to time. */
    }

    ret = ad_subdom_reinit(sd_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not reinitialize subdomains. "
              "Users from trusted domains might not be resolved correctly\n");
        /* Ignore this error and try to discover the subdomains later */
    }

    return EOK;
}
