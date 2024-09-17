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
#include "providers/ipa/ipa_subdomains.h"

#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_ops.h"
#include "util/util_sss_idmap.h"
#include <ctype.h>
#include <ndr.h>
#include <ndr/ndr_nbt.h>

/* Avoid that ldb_val is overwritten by data_blob.h */
#undef ldb_val
#include <ldb.h>

/* Attributes of AD trusted domains */
#define AD_AT_FLATNAME      "flatName"
#define AD_AT_SID           "securityIdentifier"
#define AD_AT_TRUST_PARTNER "trustPartner"
#define AD_AT_TRUST_ATTRS   "trustAttributes"
#define AD_AT_DOMAIN_NAME   "cn"
#define AD_AT_TRUST_DIRECTION   "trustDirection"

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

/* Attributes of schema objects. See e.g.
 * https://docs.microsoft.com/en-us/windows/desktop/AD/characteristics-of-attributes
 * for more details
 */
#define AD_SCHEMA_AT_OC         "attributeSchema"
#define AD_AT_SCHEMA_NAME       "cn"
#define AD_AT_SCHEMA_IS_REPL    "isMemberOfPartialAttributeSet"

/* do not refresh more often than every 5 seconds for now */
#define AD_SUBDOMAIN_REFRESH_LIMIT 5

/* Flags of trustAttributes attribute, see MS-ADTS 6.1.6.7.9 for details */
#define TRUST_ATTRIBUTE_WITHIN_FOREST 0x00000020

/* Flags for trustDirection attribute, see MS-ADTS 6.1.6.7.12 for details */
#define TRUST_DIRECTION_OUTBOUND 0x00000002

static void
ad_disable_gc(struct ad_options *ad_options)
{
    errno_t ret;

    if (dp_opt_get_bool(ad_options->basic, AD_ENABLE_GC) == false) {
        return;
    }

    DEBUG(SSSDBG_IMPORTANT_INFO, "POSIX attributes were requested "
          "but are not present on the server side. Global Catalog "
          "lookups will be disabled\n");

    ret = dp_opt_set_bool(ad_options->basic,
                          AD_ENABLE_GC, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "Could not turn off GC support\n");
        /* Not fatal */
    }
}

static struct sss_domain_info *
ads_get_root_domain(struct be_ctx *be_ctx, struct sysdb_attrs *attrs)
{
    struct sss_domain_info *dom;
    const char *name;
    errno_t ret;

    if (attrs == NULL) {
        /* Clients joined to the forest root directly don't even discover
         * the root domain, so the attrs are expected to be NULL in this
         * case
         */
        return be_ctx->domain;
    }

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

static struct sdap_domain *
ads_get_root_sdap_domain(struct be_ctx *be_ctx,
                         struct sdap_options *opts,
                         struct sysdb_attrs *attrs)
{
    struct sdap_domain *root_sdom;
    struct sss_domain_info *root_dom;

    root_dom = ads_get_root_domain(be_ctx, attrs);
    if (root_dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ads_get_root_domain did not find the domain\n");
        return NULL;
    }

    root_sdom = sdap_domain_get(opts, root_dom);
    if (root_sdom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to find sdap_domain for the root domain\n");
        return NULL;
    }

    return root_sdom;
}

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
        is_ad_in_domains += strcasecmp(ad_domain, domains[i]) == 0 ? true : false;
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
    bool use_kdcinfo = false;
    size_t n_lookahead_primary = SSS_KRB5_LOOKAHEAD_PRIMARY_DEFAULT;
    size_t n_lookahead_backup = SSS_KRB5_LOOKAHEAD_BACKUP_DEFAULT;
    bool ad_use_ldaps = false;

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
        DEBUG(SSSDBG_CRIT_FAILURE, "subdomain_create_conf_path failed\n");
        return ENOMEM;
    }

    ad_options = ad_create_trust_options(id_ctx,
                                         be_ctx->cdb,
                                         subdom_conf_path,
                                         be_ctx->provider,
                                         subdom,
                                         realm,
                                         hostname,
                                         keytab,
                                         NULL);
    if (ad_options == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD options\n");
        talloc_free(ad_options);
        talloc_free(subdom_conf_path);
        return ENOMEM;
    }

    ret = subdom_inherit_opts_if_needed(id_ctx->ad_options->basic,
                                    ad_options->basic,
                                    be_ctx->cdb, subdom_conf_path,
                                    AD_USE_LDAPS);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to inherit option [%s] to sub-domain [%s]. "
              "This error is ignored but might cause issues or unexpected "
              "behavior later on.\n",
              id_ctx->ad_options->basic[AD_USE_LDAPS].opt_name,
              subdom->name);
    }

    if (dp_opt_get_bool(ad_options->basic, AD_USE_LDAPS)) {
        ad_set_ssf_and_mech_for_ldaps(ad_options->id);
    }

    ret = subdom_inherit_opts_if_needed(id_ctx->sdap_id_ctx->opts->basic,
                                    ad_options->id->basic,
                                    be_ctx->cdb, subdom_conf_path,
                                    SDAP_SASL_MECH);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to inherit option [%s] to sub-domain [%s]. "
              "This error is ignored but might cause issues or unexpected "
              "behavior later on.\n",
              id_ctx->ad_options->id->basic[SDAP_SASL_MECH].opt_name,
              subdom->name);
    }

    talloc_free(subdom_conf_path);

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
    ad_use_ldaps = dp_opt_get_bool(ad_options->basic, AD_USE_LDAPS);

    if (id_ctx->ad_options->auth_ctx != NULL
            && id_ctx->ad_options->auth_ctx->opts != NULL) {
        use_kdcinfo = dp_opt_get_bool(id_ctx->ad_options->auth_ctx->opts,
                                      KRB5_USE_KDCINFO);
        sss_krb5_parse_lookahead(
            dp_opt_get_string(id_ctx->ad_options->auth_ctx->opts,
                              KRB5_KDCINFO_LOOKAHEAD),
            &n_lookahead_primary,
            &n_lookahead_backup);
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Init failover for [%s][%s] with use_kdcinfo [%s].\n",
          subdom->name, subdom->realm, use_kdcinfo ? "true" : "false");

    ret = ad_failover_init(ad_options, be_ctx, servers, backup_servers,
                           subdom->realm, service_name, gc_service_name,
                           subdom->name, use_kdcinfo, ad_use_ldaps,
                           n_lookahead_primary,
                           n_lookahead_backup,
                           &ad_options->service);
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
    srv_ctx = ad_srv_plugin_ctx_init(be_ctx, be_ctx, be_ctx->be_res,
                                     default_host_dbs,
                                     ad_id_ctx->ad_options->id,
                                     ad_id_ctx->ad_options,
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

static enum sss_domain_mpg_mode
get_default_subdom_mpg_mode(struct sdap_idmap_ctx *idmap_ctx,
                            struct sss_domain_info *parent,
                            const char *subdom_name,
                            char *subdom_sid_str)
{
    bool use_id_mapping;
    bool inherit_option;
    enum sss_domain_mpg_mode default_mpg_mode;

    inherit_option = string_in_list(CONFDB_DOMAIN_AUTO_UPG,
                                    parent->sd_inherit, false);
    if (inherit_option) {
        return get_domain_mpg_mode(parent);
    }

    use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(idmap_ctx,
                                                               subdom_name,
                                                               subdom_sid_str);
    if (use_id_mapping == true) {
        default_mpg_mode = MPG_ENABLED;
    } else {
        /* Domains that use the POSIX attributes set by the admin must
         * inherit the MPG setting from the parent domain so that the
         * auto_private_groups options works for trusted domains as well
         */
        default_mpg_mode = get_domain_mpg_mode(parent);
    }

    return default_mpg_mode;
}

static enum sss_domain_mpg_mode
ad_subdom_mpg_mode(TALLOC_CTX *mem_ctx,
                   struct confdb_ctx *cdb,
                   struct sss_domain_info *parent,
                   enum sss_domain_mpg_mode default_mpg_mode,
                   const char *subdom_name)
{
    char *subdom_conf_path;
    char *mpg_str_opt;
    errno_t ret;
    enum sss_domain_mpg_mode ret_mode;

    subdom_conf_path = subdomain_create_conf_path_from_str(mem_ctx,
                                                           parent->name,
                                                           subdom_name);
    if (subdom_conf_path == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "subdom_conf_path failed, will use %s mode as fallback\n",
              str_domain_mpg_mode(default_mpg_mode));
        return default_mpg_mode;
    }

    ret = confdb_get_string(cdb, mem_ctx, subdom_conf_path,
                            CONFDB_DOMAIN_AUTO_UPG,
                            NULL,
                            &mpg_str_opt);
    talloc_free(subdom_conf_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "condb_get_string failed, will use %s mode as fallback\n",
              str_domain_mpg_mode(default_mpg_mode));
        return default_mpg_mode;
    }

    if (mpg_str_opt == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Subdomain MPG mode not set, using %s\n",
              str_domain_mpg_mode(default_mpg_mode));
        return default_mpg_mode;
    }

    ret_mode = str_to_domain_mpg_mode(mpg_str_opt);
    talloc_free(mpg_str_opt);
    return ret_mode;
}

static errno_t
ad_subdom_store(struct confdb_ctx *cdb,
                struct sdap_idmap_ctx *idmap_ctx,
                struct sss_domain_info *domain,
                struct sysdb_attrs *subdom_attrs,
                bool enumerate)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    char *realm;
    const char *flat;
    const char *dns;
    uint32_t trust_type;
    errno_t ret;
    enum idmap_error_code err;
    struct ldb_message_element *el;
    char *sid_str = NULL;
    enum sss_domain_mpg_mode mpg_mode;
    enum sss_domain_mpg_mode default_mpg_mode;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* AD trust type */
    trust_type = IPA_TRUST_AD;

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

    ret = sysdb_attrs_get_string(subdom_attrs, AD_AT_DOMAIN_NAME, &dns);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "failed to get dns name of subdomain %s\n",
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

    default_mpg_mode = get_default_subdom_mpg_mode(idmap_ctx, domain,
                                                   name, sid_str);

    mpg_mode = ad_subdom_mpg_mode(tmp_ctx, cdb, domain,
                                  default_mpg_mode, name);
    DEBUG(SSSDBG_CONF_SETTINGS, "MPG mode of %s is %s\n",
                                name, str_domain_mpg_mode(mpg_mode));

    ret = sysdb_subdomain_store(domain->sysdb, name, realm, flat, dns, sid_str,
                                mpg_mode, enumerate, domain->forest, 0, trust_type,
                                NULL);
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

/* When reading trusted domains from the local DC we are basically interested
 * in domains from the local forest we are trusting, i.e. users from this
 * domain can connect to us. To not unnecessarily bloat the list of domains
 * and make multi-domain searches slow we filter domains from other forest and
 * domains we do not trust.
 * In future we might add config options to broaden the scope and allow more
 * domains.
 * If ad_filter_domains() returns successfully with EOK in input array is not
 * valid anymore and should be freed by the caller. */
static errno_t ad_filter_domains(TALLOC_CTX *mem_ctx,
                                 struct sysdb_attrs **subdomains,
                                 size_t num_subdomains,
                                 struct sysdb_attrs ***_sd_out,
                                 size_t *_num_sd_out)
{
    int ret;
    size_t c;
    uint32_t tmp_uint32_t;
    const char *value;
    struct sysdb_attrs **sd_out;
    size_t num_sd_out = 0;

    sd_out = talloc_zero_array(mem_ctx, struct sysdb_attrs *,
                               num_subdomains + 1);
    if (sd_out == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to allocate memory for sub-domain list.\n");
        return ENOMEM;
    }

    for (c = 0; c < num_subdomains; c++) {
        ret = sysdb_attrs_get_string(subdomains[c], AD_AT_TRUST_PARTNER,
                                     &value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            talloc_free(sd_out);
            return ret;
        }

        /* Ignore direct trusts to domains from other forests
         * (TRUST_ATTRIBUTE_WITHIN_FOREST is not set) or domains we do not
         * trust (TRUST_DIRECTION_OUTBOUND is not set) */

        tmp_uint32_t = 0;
        ret = sysdb_attrs_get_uint32_t(subdomains[c], AD_AT_TRUST_ATTRS,
                                       &tmp_uint32_t);
        if (ret != EOK
                || (tmp_uint32_t & TRUST_ATTRIBUTE_WITHIN_FOREST) == 0) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "TRUST_ATTRIBUTE_WITHIN_FOREST not set for [%s].\n",
                  value);
            continue;
        }

        tmp_uint32_t = 0;
        ret = sysdb_attrs_get_uint32_t(subdomains[c], AD_AT_TRUST_DIRECTION,
                                       &tmp_uint32_t);
        if (ret != EOK
                || (tmp_uint32_t & TRUST_DIRECTION_OUTBOUND) == 0) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "TRUST_DIRECTION_OUTBOUND not set for [%s].\n",
                  value);
            continue;
        }

        sd_out[num_sd_out] = subdomains[c];
        num_sd_out++;
    }

    for (c = 0; c < num_sd_out; c++) {
        sd_out[c] = talloc_steal(sd_out, sd_out[c]);
    }

    *_sd_out = sd_out;
    *_num_sd_out = num_sd_out;

    return EOK;
}

/* How many times we keep a domain not found during searches before it will be
 * removed. */
#define MAX_NOT_FOUND 6

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
            DEBUG(SSSDBG_CONF_SETTINGS, "Domain [%s] not in current list.\n",
                                        dom->name);
            /* Since the forest root might not have trustedDomain objects for
             * each domain in the forest, especially e.g. for child-domains of
             * child-domains, we cannot reliable say if a domain is still
             * present or not.
             * Maybe it would work to check the crossRef objects in
             * CN=Partitions,CN=Configuration as well to understand if a
             * domain is still known in the forest or not.
             * For the time being we use a counter, if a domain was not found
             * after multiple attempts it will be deleted. */

            if (dom->not_found_counter++ < MAX_NOT_FOUND) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Domain [%s] was not found [%zu] times.\n", dom->name,
                      dom->not_found_counter);
                continue;
            }

            /* ok this subdomain does not exist anymore, let's clean up */
            sss_domain_set_state(dom, DOM_DISABLED);

            /* Just disable the forest root but do not remove sdap data */
            if (sss_domain_is_forest_root(dom)) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Skipping removal of forest root sdap data.\n");

                ret = sysdb_domain_set_enabled(dom->sysdb, dom->name, false);
                if (ret != EOK && ret != ENOENT) {
                    DEBUG(SSSDBG_OP_FAILURE, "Unable to disable domain %s "
                          "[%d]: %s\n", dom->name, ret, sss_strerror(ret));
                    goto done;
                }
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

            /* terminate all requests for this subdomain so we can free it */
            dp_terminate_domain_requests(be_ctx->provider, dom->name);
            talloc_zfree(sdom);

        } else {
            /* ok let's try to update it */
            ret = ad_subdom_enumerates(domain, subdomains[c], &enumerate);
            if (ret != EOK) {
                goto done;
            }

            dom->not_found_counter = 0;
            ret = ad_subdom_store(be_ctx->cdb, idmap_ctx, domain,
                                  subdomains[c], enumerate);
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

        ret = ad_subdom_store(be_ctx->cdb, idmap_ctx, domain,
                              subdomains[c], enumerate);
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

            /* The subdomain is now disabled in configuraiton file, we
             * need to delete its cached content so it is not returned
             * by responders. The subdomain shares sysdb with its parent
             * domain so it is OK to use domain->sysdb. */
            ret = sysdb_subdomain_delete(domain->sysdb, sd_name);
            if (ret != EOK) {
                goto fail;
            }
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
            ret = sysdb_domain_set_enabled(domain->sysdb, root_name, false);
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE, "Unable to disable domain %s "
                      "[%d]: %s\n", root_name, ret, sss_strerror(ret));
                goto fail;
            }
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

    /* Make sure disabled domains are not re-enabled accidentally */
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
    struct sdap_domain *root_sdom;
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
    state->root_sdom = ads_get_root_sdap_domain(state->be_ctx,
                                                state->opts,
                                                state->root_attrs);
    if (state->root_sdom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto immediately;
    }

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
                            AD_AT_SID, AD_AT_DOMAIN_NAME,
                            AD_AT_TRUST_ATTRS, AD_AT_TRUST_DIRECTION, NULL };

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
                                    state->root_sdom->search_bases,
                                    NULL, false, 0,
                                    SLAVE_DOMAIN_FILTER, attrs, NULL);
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

static struct ad_id_ctx *
ads_get_dom_id_ctx(struct be_ctx *be_ctx,
                   struct ad_id_ctx *ad_id_ctx,
                   struct sss_domain_info *domain,
                   struct sdap_options *opts)
{
    errno_t ret;
    struct sdap_domain *sdom;
    struct ad_id_ctx *dom_id_ctx;

    sdom = sdap_domain_get(opts, domain);
    if (sdom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the sdom for %s!\n", domain->name);
        return NULL;
    }

    if (sdom->pvt == NULL) {
        ret = ad_subdom_ad_ctx_new(be_ctx, ad_id_ctx, domain,
                                   &dom_id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ad_subdom_ad_ctx_new failed.\n");
            return NULL;
        }

        sdom->pvt = dom_id_ctx;
    } else {
        dom_id_ctx = sdom->pvt;
    }

    dom_id_ctx->ldap_ctx->ignore_mark_offline = true;
    return dom_id_ctx;
}

struct ad_get_root_domain_state {
    struct ad_subdomains_ctx *sd_ctx;
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct sdap_idmap_ctx *idmap_ctx;
    struct sdap_options *opts;
    const char *domain;
    const char *forest;

    struct sysdb_attrs **reply;
    size_t reply_count;
    struct ad_id_ctx *root_id_ctx;
    struct sysdb_attrs *root_domain_attrs;
};

static void ad_get_root_domain_done(struct tevent_req *subreq);
static void ad_check_root_domain_done(struct tevent_req *subreq);
static errno_t
ad_get_root_domain_refresh(struct ad_get_root_domain_state *state, bool refresh);

struct tevent_req *
ad_check_domain_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct be_ctx *be_ctx,
                     struct ad_id_ctx *ad_id_ctx,
                     const char *dom_name,
                     const char *parent_dom_name);
errno_t ad_check_domain_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             char **_flat,
                             char **_id,
                             char **_site,
                             char **_forest);

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
    const char *attrs[] = { AD_AT_FLATNAME, AD_AT_TRUST_PARTNER,
                            AD_AT_SID, AD_AT_TRUST_DIRECTION,
                            AD_AT_TRUST_ATTRS, AD_AT_DOMAIN_NAME, NULL };

    req = tevent_req_create(mem_ctx, &state, struct ad_get_root_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (forest == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Name of forest root domain not available, l"
                                 "using cached data, if available.\n");
        ret = EINVAL;
        goto immediately;
    } else if (strcasecmp(domain, forest) == 0) {
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
    state->ev = ev;
    state->domain = domain;
    state->forest = forest;

    subreq = sdap_search_bases_return_first_send(state, ev, opts, sh,
                                                 opts->sdom->search_bases,
                                                 NULL, false, 0,
                                                 SLAVE_DOMAIN_FILTER, attrs,
                                                 NULL);
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

static struct sysdb_attrs *find_domain(size_t count, struct sysdb_attrs **reply,
                                       const char *dom_name)
{
    size_t c;
    const char *name;
    int ret;

    for (c = 0; c < count; c++) {
        ret = sysdb_attrs_get_string(reply[c], AD_AT_DOMAIN_NAME, &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to find domain name, skipping");
            continue;
        }
        if (strcasecmp(name, dom_name) == 0) {
            return reply[c];
        }
    }

    return NULL;
}

static void ad_get_root_domain_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_get_root_domain_state *state;
    errno_t ret;
    bool has_changes = false;
    struct sysdb_attrs **unfiltered_reply;
    size_t unfiltered_reply_count;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_get_root_domain_state);

    ret = sdap_search_bases_return_first_recv(subreq, state,
                                              &unfiltered_reply_count,
                                              &unfiltered_reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to lookup forest root information "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    if (state->sd_ctx->ad_enabled_domains == NULL) {
        ret = ad_filter_domains(state, unfiltered_reply, unfiltered_reply_count,
                                &state->reply, &state->reply_count);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to filter list of returned domains.\n");
            goto done;
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL,
              "ad_enabled_domains is set, skipping domain filtering.\n");
        state->reply_count = unfiltered_reply_count;
        state->reply = unfiltered_reply;
    }

    if (state->reply_count == 0
            || find_domain(state->reply_count, state->reply,
                           state->forest) == NULL) {

        if (state->reply_count > 0) {
            /* refresh the other domains we have found before checking forest
             * root */
            ret = ad_subdomains_refresh(state->be_ctx, state->idmap_ctx,
                                        state->opts,
                                        state->reply, state->reply_count, false,
                                        &state->sd_ctx->last_refreshed,
                                        &has_changes);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "ad_subdomains_refresh failed [%d]: %s\n",
                      ret, sss_strerror(ret));
                goto done;
            }

            if (has_changes) {
                ret = ad_subdom_reinit(state->sd_ctx);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Could not reinitialize subdomains\n");
                    goto done;
                }
            }
        }

        DEBUG(SSSDBG_OP_FAILURE,
              "No information provided for root domain, trying directly.\n");
        subreq = ad_check_domain_send(state, state->ev, state->be_ctx,
                                      state->sd_ctx->ad_id_ctx, state->forest,
                                      state->domain);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ad_check_domain_send() failed.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ad_check_root_domain_done, req);
        return;
    }

    ret = ad_get_root_domain_refresh(state, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_get_root_domain_refresh() failed.\n");
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void ad_check_root_domain_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_get_root_domain_state *state;
    errno_t ret;
    char *flat = NULL;
    char *id = NULL;
    enum idmap_error_code err;
    struct ldb_val id_val;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_get_root_domain_state);

    ret = ad_check_domain_recv(state, subreq, &flat, &id, NULL, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to check forest root information "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    if (flat == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "NetBIOS name of forest root not available.\n");
        ret = EINVAL;
        goto done;
    }

    if (id == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Domain SID of forest root not available.\n");
        ret = EINVAL;
        goto done;
    }

    state->reply = talloc_array(state, struct sysdb_attrs *, 1);
    if (state->reply == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    state->reply[0] = sysdb_new_attrs(state->reply);
    if (state->reply[0] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(state->reply[0], AD_AT_FLATNAME, flat);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string() failed.\n");
        goto done;
    }

    ret = sysdb_attrs_add_string(state->reply[0], AD_AT_TRUST_PARTNER,
                                 state->forest);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string() failed.\n");
        goto done;
    }

    ret = sysdb_attrs_add_string(state->reply[0], AD_AT_DOMAIN_NAME,
                                 state->forest);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string() failed.\n");
        goto done;
    }

    err = sss_idmap_sid_to_bin_sid(state->idmap_ctx->map, id,
                                   &id_val.data, &id_val.length);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not convert SID: [%s].\n", idmap_error_string(err));
        ret = EFAULT;
        goto done;
    }

    ret = sysdb_attrs_add_val(state->reply[0], AD_AT_SID, &id_val);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string() failed.\n");
        goto done;
    }

    state->reply_count = 1;

    ret = ad_get_root_domain_refresh(state, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_get_root_domain_refresh() failed.\n");
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
ad_get_root_domain_refresh(struct ad_get_root_domain_state *state, bool refresh)
{
    struct sss_domain_info *root_domain;
    bool has_changes;
    errno_t ret;

    ret = ad_subdomains_refresh(state->be_ctx, state->idmap_ctx, state->opts,
                                state->reply, state->reply_count, false,
                                &state->sd_ctx->last_refreshed,
                                &has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_subdomains_refresh failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (has_changes || refresh) {
        ret = ad_subdom_reinit(state->sd_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not reinitialize subdomains\n");
            goto done;
        }
    }

    state->root_domain_attrs = find_domain(state->reply_count, state->reply,
                                           state->forest);
    root_domain = ads_get_root_domain(state->be_ctx, state->root_domain_attrs);
    if (root_domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not find the root domain\n");
        ret = EFAULT;
        goto done;
    }

    state->root_id_ctx = ads_get_dom_id_ctx(state->be_ctx,
                                            state->sd_ctx->ad_id_ctx,
                                            root_domain, state->opts);
    if (state->root_id_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot create id ctx for the root domain\n");
        ret = EFAULT;
        goto done;
    }

    ret = EOK;

done:
    return ret;
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

static void ad_check_gc_usability_search_done(struct tevent_req *subreq);

struct ad_check_gc_usability_state {
    struct sdap_options *sdap_opts;

    const char *attrs[3];

    bool is_gc_usable;
};

static struct tevent_req *
ad_check_gc_usability_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ad_options *ad_options,
                           struct sdap_options *sdap_opts,
                           struct sdap_id_op *op,
                           const char *domain_name,
                           const char *domain_sid)
{
    struct ad_check_gc_usability_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    const char *filter = NULL;
    errno_t ret;
    bool uses_id_mapping;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_check_gc_usability_state);
    if (req == NULL) {
        return NULL;
    }
    state->sdap_opts = sdap_opts;
    state->is_gc_usable = false;

    if (dp_opt_get_bool(ad_options->basic, AD_ENABLE_GC) == false) {
        DEBUG(SSSDBG_TRACE_FUNC, "GC explicitly disabled\n");
        state->is_gc_usable = false;
        ret = EOK;
        goto immediately;
    }

    uses_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                        sdap_opts->idmap_ctx,
                                                        domain_name,
                                                        domain_sid);
    if (uses_id_mapping == true) {
        DEBUG(SSSDBG_TRACE_FUNC, "GC always usable while ID mapping\n");
        state->is_gc_usable = true;
        ret = EOK;
        goto immediately;
    }

    /* The schema partition is replicated across all DCs in the forest, so
     * it's safe to use the baseDN even if e.g. joined to a child domain
     * even though the base DN "looks" like a part of the forest root
     * tree. On the other hand, it doesn't make sense to guess the value
     * if we can't detect it from the rootDSE.
     */
    if (state->sdap_opts->schema_basedn == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "No idea where to look for the schema, disabling GC\n");
        state->is_gc_usable = false;
        ret = EOK;
        goto immediately;
    }

    state->attrs[0] = AD_AT_SCHEMA_NAME;
    state->attrs[1] = AD_AT_SCHEMA_IS_REPL;
    state->attrs[2] = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Checking for POSIX attributes in GC\n");

    filter = talloc_asprintf(
                        state,
                        "(&(objectclass=%s)(|(%s=%s)(%s=%s)))",
                        AD_SCHEMA_AT_OC,
                        AD_AT_SCHEMA_NAME,
                        state->sdap_opts->user_map[SDAP_AT_USER_UID].name,
                        AD_AT_SCHEMA_NAME,
                        state->sdap_opts->group_map[SDAP_AT_GROUP_GID].name);
    if (filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_get_generic_send(state,
                                   ev,
                                   state->sdap_opts,
                                   sdap_id_op_handle(op),
                                   state->sdap_opts->schema_basedn,
                                   LDAP_SCOPE_SUBTREE,
                                   filter,
                                   state->attrs,
                                   NULL, 0,
                                   dp_opt_get_int(state->sdap_opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, ad_check_gc_usability_search_done, req);

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

static void ad_check_gc_usability_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_check_gc_usability_state *state = tevent_req_data(req,
                                          struct ad_check_gc_usability_state);
    errno_t ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    bool uid = false;
    bool gid = false;

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_get_generic_recv failed [%d]: %s\n",
              ret, strerror(ret));
        /* We continue to finish sdap_id_op. */
    }

    if (reply_count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Nothing found, so no POSIX attrs can exist\n");
        state->is_gc_usable = false;
        tevent_req_done(req);
        return;
    }

    for (size_t i = 0; i < reply_count; i++) {
        const char *name = NULL;
        const char *is_in_partial_set = NULL;
        bool *val = NULL;

        ret = sysdb_attrs_get_string(reply[i], AD_AT_SCHEMA_NAME, &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot get "AD_AT_SCHEMA_NAME"\n");
            continue;
        }

        if (strcasecmp(name, state->sdap_opts->user_map[SDAP_AT_USER_UID].name) == 0) {
            val = &uid;
        } else if (strcasecmp(name, state->sdap_opts->user_map[SDAP_AT_USER_GID].name) == 0) {
            val = &gid;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Unexpected attribute\n");
            continue;
        }

        ret = sysdb_attrs_get_string(reply[i],
                                     AD_AT_SCHEMA_IS_REPL,
                                     &is_in_partial_set);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot get "AD_AT_SCHEMA_IS_REPL"\n");
            continue;
        }

        if (strcasecmp(is_in_partial_set, "true") == 0) {
            *val = true;
        }
    }

    if (uid == true && gid == true) {
        state->is_gc_usable = true;
    }

    if (state->is_gc_usable == true) {
        DEBUG(SSSDBG_FUNC_DATA, "Server has POSIX attributes. Global Catalog will "
                                "be used for user and group lookups. Note that if "
                                "only a subset of POSIX attributes is present "
                                "in GC, the non-replicated attributes are "
                                "currently not read from the LDAP port\n");
    }

    tevent_req_done(req);
}

static errno_t ad_check_gc_usability_recv(struct tevent_req *req,
                                          bool *_is_gc_usable)
{
    struct ad_check_gc_usability_state *state = NULL;

    state = tevent_req_data(req, struct ad_check_gc_usability_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_is_gc_usable = state->is_gc_usable;
    return EOK;
}

struct ad_subdomains_refresh_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ad_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;
    struct sdap_id_ctx *id_ctx;
    struct ad_options *ad_options;

    char *forest;
};

static errno_t ad_subdomains_refresh_retry(struct tevent_req *req);
static void ad_subdomains_refresh_connect_done(struct tevent_req *subreq);
static void ad_subdomains_refresh_master_done(struct tevent_req *subreq);
static void ad_subdomains_refresh_gc_check_done(struct tevent_req *subreq);
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
    subreq = ad_domain_info_send(state, state->ev, state->id_ctx->conn,
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
    const char *dns;
    char *master_sid;
    char *flat_name;
    char *site = NULL;
    errno_t ret;
    char *ad_site_override = NULL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_subdomains_refresh_state);

    ret = ad_domain_info_recv(subreq, state, &flat_name, &master_sid,
                              &site, &state->forest);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get master domain information "
              "[%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->forest == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Forest name was not found, using the one "
                                    "which was already discovered [%s].\n",
                                    state->ad_options->current_forest != NULL ?
                                        state->ad_options->current_forest :
                                        "- not available-");
        if (state->ad_options->current_forest != NULL) {
            state->forest = talloc_strdup(state,
                                          state->ad_options->current_forest);
            if (state->forest == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to copy forest name.\n");
                tevent_req_error(req, ENOMEM);
                return;
            }
        }
    }

    /* If the site was not discovered during the DNS discovery, e.g. because
     * the server name was given explicitly in sssd.conf, we try to set the
     * site here. */
    if (state->ad_options->current_site == NULL) {
        /* Ignore AD site found in netlogon attribute if specific site is set in
         * configuration file. */
        ad_site_override = dp_opt_get_string(state->ad_options->basic, AD_SITE);
        if (ad_site_override != NULL) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Ignoring AD site found by DNS discovery: '%s', "
                  "using configured value: '%s' instead.\n",
                  site, ad_site_override);
            site = ad_site_override;
        }

        if (site != NULL) {
            ret = ad_options_switch_site(state->ad_options, state->be_ctx, site,
                                         state->forest);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to store forest and site name, "
                                         "will try again after a new lookup.\n");
            }
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Site name currently not available will try again later. "
                  "The site name can be added manually my setting 'ad_site' "
                  "in sssd.conf.\n");
        }
    }

    realm = dp_opt_get_cstring(state->ad_options->basic, AD_KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Missing realm.\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    dns = dp_opt_get_cstring(state->ad_options->basic, AD_DOMAIN);
    if (dns == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Missing domain name.\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    ret = sysdb_master_domain_add_info(state->be_ctx->domain, realm, flat_name,
                                       dns, master_sid, state->forest, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot save master domain info [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = ad_check_gc_usability_send(state,
                                        state->ev,
                                        state->ad_options,
                                        state->id_ctx->opts,
                                        state->sdap_op,
                                        state->be_ctx->domain->name,
                                        master_sid);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ad_subdomains_refresh_gc_check_done, req);
}

static void ad_subdomains_refresh_gc_check_done(struct tevent_req *subreq)
{
    struct ad_subdomains_refresh_state *state;
    struct tevent_req *req;
    const char **subdoms;
    const char *ad_domain;
    bool is_gc_usable;
    errno_t ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_subdomains_refresh_state);

    ret = ad_check_gc_usability_recv(subreq, &is_gc_usable);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to get GC usability status\n");
        is_gc_usable = false;
    }

    if (is_gc_usable == false) {
        ad_disable_gc(state->ad_options);
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

                ret = sysdb_list_subdomains(state, state->be_ctx->domain->sysdb,
                                            &subdoms);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "Unable to list subdomains "
                          "[%d]: %s\n", ret, sss_strerror(ret));
                    tevent_req_error(req, ret);
                    return;
                }

                for (i = 0; subdoms[i] != NULL; i++) {
                    ret = sysdb_subdomain_delete(state->be_ctx->domain->sysdb,
                                                 subdoms[i]);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE, "Unable to remove subdomain "
                              "[%d]: %s\n", ret, sss_strerror(ret));
                        tevent_req_error(req, ret);
                        return;
                    }
                }

                tevent_req_done(req);
                return;
            }
        }
    }

    ad_domain = dp_opt_get_cstring(state->ad_options->basic, AD_DOMAIN);
    if (ad_domain == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
             "Missing AD domain name, falling back to sssd domain name\n");
        ad_domain = state->sd_ctx->be_ctx->domain->name;
    }

    subreq = ad_get_root_domain_send(state, state->ev, ad_domain, state->forest,
                                     sdap_id_op_handle(state->sdap_op),
                                     state->sd_ctx);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ad_subdomains_refresh_root_done, req);
    return;
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

    /* Note: For clients joined to the root domain, root_attrs is NULL,
     * see ad_get_root_domain_send()
     */
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
    time_t offset;
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
    offset = be_ctx->domain->subdomain_refresh_interval_offset;
    ret = be_ptask_create(sd_ctx, be_ctx, period, 0, 0, offset, period, 0,
                          ad_subdomains_ptask_send, ad_subdomains_ptask_recv,
                          sd_ctx,
                          "Subdomains Refresh",
                          BE_PTASK_OFFLINE_DISABLE |
                          BE_PTASK_SCHEDULE_FROM_LAST,
                          NULL);
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

struct ad_check_domain_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct sdap_id_op *sdap_op;
    struct ad_id_ctx *dom_id_ctx;
    struct sdap_options *opts;

    const char *dom_name;
    struct sss_domain_info *dom;
    struct sss_domain_info *parent;
    struct sdap_domain *sdom;

    char *flat;
    char *site;
    char *forest;
    char *sid;
};

static void ad_check_domain_connect_done(struct tevent_req *subreq);
static void ad_check_domain_done(struct tevent_req *subreq);

static int ad_check_domain_destructor(void *mem)
{
    struct ad_check_domain_state *state = talloc_get_type(mem,
                                                  struct ad_check_domain_state);

    if (state->sdom != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Removing sdap domain [%s].\n",
                                state->dom->name);
        sdap_domain_remove(state->opts, state->dom);
        /* terminate all requests for this subdomain so we can free it */
        dp_terminate_domain_requests(state->be_ctx->provider, state->dom->name);
        talloc_zfree(state->sdom);
    }

    if (state->dom != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Removing domain [%s].\n", state->dom->name);
        sss_domain_set_state(state->dom, DOM_DISABLED);
        DLIST_REMOVE(state->be_ctx->domain->subdomains, state->dom);
        talloc_zfree(state->dom);
    }

    return 0;
}

struct tevent_req *
ad_check_domain_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct be_ctx *be_ctx,
                     struct ad_id_ctx *ad_id_ctx,
                     const char *dom_name,
                     const char *parent_dom_name)
{
    errno_t ret;
    uint32_t trust_type;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_check_domain_state *state;

    req = tevent_req_create(mem_ctx, &state, struct ad_check_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->opts = ad_id_ctx->sdap_id_ctx->opts;
    state->dom_name = dom_name;
    state->parent = NULL;
    state->sdom = NULL;

    /* AD trust type */
    trust_type = IPA_TRUST_AD;

    state->dom = find_domain_by_name(be_ctx->domain, dom_name, true);
    if (state->dom == NULL) {
        state->parent = find_domain_by_name(be_ctx->domain, parent_dom_name,
                                            true);
        if (state->parent == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to find domain object for domain [%s].\n",
                  parent_dom_name);
            ret = ENOENT;
            goto immediately;
        }

        state->dom = new_subdomain(state->parent, state->parent, dom_name,
                                   dom_name, NULL, NULL, NULL, MPG_DISABLED, false,
                                   state->parent->forest,
                                   NULL, 0, trust_type, be_ctx->cdb, true);
        if (state->dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "new_subdomain() failed.\n");
            ret = EINVAL;
            goto immediately;
        }

        talloc_set_destructor((TALLOC_CTX *) state, ad_check_domain_destructor);

        DLIST_ADD_END(state->parent->subdomains, state->dom,
                      struct sss_domain_info *);

        ret = sdap_domain_add(state->opts, state->dom, &state->sdom);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_domain_subdom_add failed.\n");
            goto immediately;
        }

        ret = ad_set_search_bases(ad_id_ctx->ad_options->id, state->sdom);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "failed to set ldap search bases for "
                  "domain '%s'. Will try to use automatically detected search "
                  "bases.", state->sdom->dom->name);
        }

    }

    state->dom_id_ctx = ads_get_dom_id_ctx(be_ctx, ad_id_ctx, state->dom,
                                           state->opts);
    if (state->dom_id_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ads_get_dom_id_ctx() failed.\n");
        ret = EINVAL;
        goto immediately;
    }

    state->sdap_op = sdap_id_op_create(state,
                             state->dom_id_ctx->sdap_id_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
         ret = ENOMEM;
         goto immediately;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
         goto immediately;
    }

    tevent_req_set_callback(subreq, ad_check_domain_connect_done, req);

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

static void ad_check_domain_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_check_domain_state *state;
    int ret;
    int dp_error;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_check_domain_state);

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

    subreq = ad_domain_info_send(state, state->ev,
                                 state->dom_id_ctx->sdap_id_ctx->conn,
                                 state->sdap_op, state->dom_name);

    tevent_req_set_callback(subreq, ad_check_domain_done, req);

    return;
}

static void ad_check_domain_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_check_domain_state *state;
    errno_t ret;


    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_check_domain_state);

    ret = ad_domain_info_recv(subreq, state, &state->flat, &state->sid,
                              &state->site, &state->forest);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to lookup domain information "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL, "%s %s %s %s.\n", state->flat, state->sid,
                                              state->site, state->forest);

    /* New domain was successfully checked, remove destructor. */
    talloc_set_destructor(state, NULL);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t ad_check_domain_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             char **_flat,
                             char **_id,
                             char **_site,
                             char **_forest)
{
    struct ad_check_domain_state *state = tevent_req_data(req,
                                                  struct ad_check_domain_state);

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
