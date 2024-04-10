/*
    SSSD

    IPA Subdomains Module - server mode

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include "providers/ldap/sdap_idmap.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_srv.h"

/* These constants are defined in MS-ADTS 6.1.6.7.1
 *  https://msdn.microsoft.com/en-us/library/cc223768.aspx
 */
#define LSA_TRUST_DIRECTION_INBOUND  0x00000001
#define LSA_TRUST_DIRECTION_OUTBOUND 0x00000002
#define LSA_TRUST_DIRECTION_MASK (LSA_TRUST_DIRECTION_INBOUND | LSA_TRUST_DIRECTION_OUTBOUND)

/* See ipatrust_encode_type() method in freeipa ipaserver/dcerpc_common.py */
#define TRUST_TYPE_AD (1 << 4)
#define TRUST_TYPE_IPA (1 << 5)

static char *forest_keytab(TALLOC_CTX *mem_ctx, const char *forest)
{
    return talloc_asprintf(mem_ctx,
                           "%s/%s.keytab", IPA_TRUST_KEYTAB_DIR, forest);
}

static char *subdomain_trust_princ(TALLOC_CTX *mem_ctx,
                                   const char *forest_realm,
                                   struct sss_domain_info *sd)
{
    if (sd->parent->flat_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown flat name for parent %s\n", sd->parent->name);
        return NULL;
    }

    return talloc_asprintf(mem_ctx, "%s$@%s",
                           sd->parent->flat_name, forest_realm);
}

struct sdap_domain *
sdap_domain_get_by_trust_type(struct ipa_subdom_server_ctx *trust,
                              struct sss_domain_info *dom)
{
    struct sdap_domain *sdom = NULL;

    if (trust->type == IPA_TRUST_AD) {
        sdom = sdap_domain_get(trust->id_ctx.ad_id_ctx->sdap_id_ctx->opts,
                               dom);
    } else if (trust->type == IPA_TRUST_AD) {
        sdom = sdap_domain_get(trust->id_ctx.ipa_id_ctx->sdap_id_ctx->opts,
                               dom);
    }

    return sdom;
}

void
sdap_domain_remove_by_trust_type(struct ipa_subdom_server_ctx *trust,
                                 struct sss_domain_info *subdom)
{
    if (trust->type == IPA_TRUST_AD) {
        sdap_domain_remove(trust->id_ctx.ad_id_ctx->sdap_id_ctx->opts, subdom);
    } else if (trust->type == IPA_TRUST_IPA) {
        sdap_domain_remove(trust->id_ctx.ipa_id_ctx->sdap_id_ctx->opts, subdom);
    }
}

static uint32_t default_direction(TALLOC_CTX *mem_ctx,
                                  struct ldb_context *ldb_ctx,
                                  struct sysdb_attrs *attrs)
{
    struct ldb_dn *dn = NULL;
    uint32_t direction;

    dn = ipa_subdom_ldb_dn(mem_ctx, ldb_ctx, attrs);
    if (dn == NULL) {
        /* Shouldn't happen, but let's try system keytab in this case */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot determine subdomain DN, falling back to two-way trust\n");
        return (LSA_TRUST_DIRECTION_INBOUND|LSA_TRUST_DIRECTION_OUTBOUND);
    }

    if (ipa_subdom_is_member_dom(dn) == true) {
        /* It's expected member domains do not have the direction */
        direction = 0;
    } else {
        /* Old server? Default to 2way trust */
        direction = (LSA_TRUST_DIRECTION_INBOUND|LSA_TRUST_DIRECTION_OUTBOUND);
    }

    talloc_free(dn);
    return direction;
}

errno_t ipa_server_get_trust_direction(struct sysdb_attrs *sd,
                                       struct ldb_context *ldb_ctx,
                                       uint32_t *_direction)
{
    uint32_t ipa_trust_direction = 0;
    uint32_t direction;
    int ret;

    ret = sysdb_attrs_get_uint32_t(sd, IPA_TRUST_DIRECTION,
                                   &ipa_trust_direction);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Raw %s value: %d\n", IPA_TRUST_DIRECTION, ipa_trust_direction);
    if (ret == ENOENT) {
        direction = default_direction(sd, ldb_ctx, sd);
    } else if (ret == EOK) {
        /* Just store the AD value in SYSDB, we will check it while we're
         * trying to use the trust */
        direction = ipa_trust_direction;
    } else {
        return ret;
    }

    *_direction = direction;
    return EOK;
}

/* See ipatrust_encode_type() method in freeipa ipaserver/dcerpc_common.py
 *
 *      ipaTrustType attribute will encode:
 *      bits 0..1 -- direction of trust
 *         bit 0  -- one-way incoming trust
 *         bit 1  -- one-way outgoing trust
 *      bits 4..7 -- type of trust
 *         bit 4  -- trust to Active Directory
 *         bit 5  -- trust to IPA
 */
enum ipa_trust_type ipa_server_decode_trust_type(uint32_t type)
{
    enum ipa_trust_type trust_type;

    if (type & TRUST_TYPE_AD) {
        trust_type = IPA_TRUST_AD;
    } else if (type & TRUST_TYPE_IPA) {
        trust_type = IPA_TRUST_IPA;
    /* Always assume existing trusts are AD */
    } else {
        trust_type = IPA_TRUST_AD;
    }

    return trust_type;
}

errno_t ipa_server_get_trust_type(struct sysdb_attrs *sd,
                                  struct ldb_context *ldb_ctx,
                                  uint32_t *_type)
{
    uint32_t ipa_trust_type = 0;
    uint32_t type;
    int ret;

    ret = sysdb_attrs_get_uint32_t(sd, IPA_PARTNER_TRUST_TYPE,
                                   &ipa_trust_type);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Raw %s value: %d\n", IPA_PARTNER_TRUST_TYPE, ipa_trust_type);
    if (ret == ENOENT) {
        /* Always assume existing trusts (without IPA_PARTNER_TRUST_TYPE) are AD */
        type = IPA_TRUST_AD;
    } else if (ret == EOK) {
        /* Just store the value in SYSDB, we will check it while we're
         * trying to use the trust */
        type = ipa_server_decode_trust_type(ipa_trust_type);
    } else {
        return ret;
    }

    *_type = type;
    return EOK;
}

const char *ipa_trust_dir2str(uint32_t direction)
{
    if ((direction & LSA_TRUST_DIRECTION_OUTBOUND)
            && (direction & LSA_TRUST_DIRECTION_INBOUND)) {
        return "two-way trust";
    } else if (direction & LSA_TRUST_DIRECTION_OUTBOUND) {
        return "one-way outbound: local domain is trusted by remote domain";
    } else if (direction & LSA_TRUST_DIRECTION_INBOUND) {
        return "one-way inbound: local domain trusts the remote domain";
    } else if (direction == 0) {
        return "not set";
    }

    return "unknown";
}

const char *ipa_trust_type2str(uint32_t type)
{
    if (type == IPA_TRUST_AD) {
        return "Active Directory Trust";
    } else if (type == IPA_TRUST_IPA) {
        return "IPA Trust";
    } else if (type == 0) {
        return "not set";
    }

    return "unknown";
}

#ifndef IPA_GETKEYTAB_TIMEOUT
#define IPA_GETKEYTAB_TIMEOUT 5
#endif /* IPA_GETKEYTAB_TIMEOUT */

static struct ipa_options *
ipa_create_ipa_trust_ctx(struct ipa_id_ctx *id_ctx,
                         struct be_ctx *be_ctx,
                         const char *subdom_conf_path,
                         const char *forest,
                         const char *forest_realm,
                         struct sss_domain_info *subdom)
{
    char *keytab;
    char *principal;
    struct ipa_options *ipa_options;

    keytab = forest_keytab(id_ctx, forest);
    principal = subdomain_trust_princ(id_ctx, forest_realm, subdom);
    if (keytab == NULL || principal == NULL) {
        return NULL;
    }

    ipa_options = ipa_create_trust_options(id_ctx,
                                           be_ctx,
                                           be_ctx->cdb,
                                           subdom_conf_path,
                                           be_ctx->provider,
                                           subdom,
                                           keytab,
                                           principal);
    if (ipa_options == NULL) {
        talloc_free(keytab);
        talloc_free(principal);
        return NULL;
    }

    return ipa_options;
}

static struct ad_options *
ipa_create_ad_1way_trust_ctx(struct ipa_id_ctx *id_ctx,
                             struct be_ctx *be_ctx,
                             const char *subdom_conf_path,
                             const char *forest,
                             const char *forest_realm,
                             struct sss_domain_info *subdom)
{
    char *keytab;
    char *principal;
    struct ad_options *ad_options;

    keytab = forest_keytab(id_ctx, forest);
    principal = subdomain_trust_princ(id_ctx, forest_realm, subdom);
    if (keytab == NULL || principal == NULL) {
        return NULL;
    }

    ad_options = ad_create_trust_options(id_ctx,
                                         be_ctx->cdb,
                                         subdom_conf_path,
                                         be_ctx->provider,
                                         subdom,
                                         NULL,
                                         id_ctx->server_mode->hostname,
                                         keytab,
                                         principal);
    if (ad_options == NULL) {
        talloc_free(keytab);
        talloc_free(principal);
        return NULL;
    }

    return ad_options;
}

static struct ad_options *ipa_ad_options_new(struct be_ctx *be_ctx,
                                             struct ipa_id_ctx *id_ctx,
                                             struct sss_domain_info *subdom)
{
    struct ad_options *ad_options = NULL;
    uint32_t direction;
    const char *forest;
    const char *forest_realm;
    char *subdom_conf_path;
    int ret;

    /* Trusts are only established with forest roots */
    direction = subdom->forest_root->trust_direction;
    forest_realm = subdom->forest_root->realm;
    forest = subdom->forest_root->forest;

    subdom_conf_path = subdomain_create_conf_path(id_ctx, subdom);
    if (subdom_conf_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "subdom_conf_path failed\n");
        return NULL;
    }

    /* In both inbound and outbound trust cases we should be
     * using trusted domain object in a trusted domain space,
     * thus we always should be initializing principals/keytabs
     * as if we are running one-way trust */
    if (direction & LSA_TRUST_DIRECTION_MASK) {
        ad_options = ipa_create_ad_1way_trust_ctx(id_ctx, be_ctx,
                                                  subdom_conf_path, forest,
                                                  forest_realm, subdom);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported trust direction!\n");
        ad_options = NULL;
    }

    if (ad_options == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD options\n");
        talloc_free(subdom_conf_path);
        return NULL;
    }

    ret = subdom_inherit_opts_if_needed(id_ctx->ipa_options->id->basic,
                                        ad_options->id->basic, be_ctx->cdb,
                                        subdom_conf_path, SDAP_SASL_MECH);
    talloc_free(subdom_conf_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to inherit option [%s] to sub-domain [%s]. "
              "This error is ignored but might cause issues or unexpected "
              "behavior later on.\n",
              id_ctx->ipa_options->id->basic[SDAP_SASL_MECH].opt_name,
              subdom->name);

        return NULL;
    }

    return ad_options;
}

static struct ipa_options *ipa_options_new(struct be_ctx *be_ctx,
                                           struct ipa_id_ctx *id_ctx,
                                           struct sss_domain_info *subdom)
{
    struct ipa_options *ipa_options = NULL;
    uint32_t direction;
    const char *forest;
    const char *forest_realm;
    char *subdom_conf_path;
    int ret;

    /* Trusts are only established with forest roots */
    direction = subdom->forest_root->trust_direction;
    forest_realm = subdom->forest_root->realm;
    forest = subdom->forest_root->forest;

    subdom_conf_path = subdomain_create_conf_path(id_ctx, subdom);
    if (subdom_conf_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "subdom_conf_path failed\n");
        return NULL;
    }

    /* In both inbound and outbound trust cases we should be
     * using trusted domain object in a trusted domain space,
     * thus we always should be initializing principals/keytabs
     * as if we are running one-way trust */
    if (direction & LSA_TRUST_DIRECTION_MASK) {
        ipa_options = ipa_create_ipa_trust_ctx(id_ctx, be_ctx,
                                               subdom_conf_path, forest,
                                               forest_realm, subdom);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported trust direction!\n");
        ipa_options = NULL;
    }

    if (ipa_options == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize IPA options\n");
        talloc_free(subdom_conf_path);
        return NULL;
    }

    ret = subdom_inherit_opts_if_needed(id_ctx->ipa_options->id->basic,
                                        ipa_options->id->basic, be_ctx->cdb,
                                        subdom_conf_path, SDAP_SASL_MECH);
    talloc_free(subdom_conf_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to inherit option [%s] to sub-domain [%s]. "
              "This error is ignored but might cause issues or unexpected "
              "behavior later on.\n",
              id_ctx->ipa_options->id->basic[SDAP_SASL_MECH].opt_name,
              subdom->name);

        return NULL;
    }

    return ipa_options;
}


static errno_t
ipa_ad_ctx_new(struct be_ctx *be_ctx,
               struct ipa_id_ctx *id_ctx,
               struct sss_domain_info *subdom,
               struct ad_id_ctx **_ad_id_ctx)
{
    struct ad_options *ad_options;
    struct ad_id_ctx *ad_id_ctx;
    const char *gc_service_name;
    const char *service_name;
    struct ad_srv_plugin_ctx *srv_ctx;
    const char *ad_domain;
    const char *ad_site_override;
    const char *ad_servers;
    const char *ad_backup_servers;
    struct sdap_domain *sdom;
    errno_t ret;
    const char *extra_attrs;
    bool use_kdcinfo = false;
    size_t n_lookahead_primary = (size_t)-1;
    size_t n_lookahead_backup = (size_t)-1;

    ad_domain = subdom->name;
    DEBUG(SSSDBG_TRACE_LIBS, "Setting up AD subdomain %s\n", subdom->name);

    ad_options = ipa_ad_options_new(be_ctx, id_ctx, subdom);
    if (ad_options == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD options\n");
        talloc_free(ad_options);
        return ENOMEM;
    }

    extra_attrs = dp_opt_get_string(id_ctx->sdap_id_ctx->opts->basic,
                            SDAP_USER_EXTRA_ATTRS);
    if (extra_attrs != NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Setting extra attrs for subdomain [%s] to [%s].\n", ad_domain,
                                                                   extra_attrs);

        ret = dp_opt_set_string(ad_options->id->basic, SDAP_USER_EXTRA_ATTRS,
                                extra_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "dp_opt_set_string failed.\n");
            talloc_free(ad_options);
            return ret;
        }

        ret = sdap_extend_map_with_list(ad_options->id, ad_options->id,
                                        SDAP_USER_EXTRA_ATTRS,
                                        ad_options->id->user_map,
                                        SDAP_OPTS_USER,
                                        &ad_options->id->user_map,
                                        &ad_options->id->user_map_cnt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_extend_map_with_list failed.\n");
            talloc_free(ad_options);
            return ret;
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "No extra attrs set.\n");
    }

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

    ad_servers = dp_opt_get_string(ad_options->basic, AD_SERVER);
    ad_backup_servers = dp_opt_get_string(ad_options->basic, AD_BACKUP_SERVER);

    if (id_ctx->ipa_options != NULL && id_ctx->ipa_options->auth != NULL) {
        use_kdcinfo = dp_opt_get_bool(id_ctx->ipa_options->auth,
                                      KRB5_USE_KDCINFO);
        sss_krb5_parse_lookahead(
            dp_opt_get_string(id_ctx->ipa_options->auth, KRB5_KDCINFO_LOOKAHEAD),
            &n_lookahead_primary,
            &n_lookahead_backup);
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Init failover for [%s][%s] with use_kdcinfo [%s].\n",
          subdom->name, subdom->realm, use_kdcinfo ? "true" : "false");

    /* Set KRB5 realm to same as the one of IPA when IPA
     * is able to attach PAC. For testing, use hardcoded. */
    /* Why? */
    ret = ad_failover_init(ad_options, be_ctx, ad_servers, ad_backup_servers,
                           subdom->realm,
                           service_name, gc_service_name,
                           subdom->name, use_kdcinfo, false,
                           n_lookahead_primary, n_lookahead_backup,
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

    ad_site_override = dp_opt_get_string(ad_options->basic, AD_SITE);

    /* use AD plugin */
    srv_ctx = ad_srv_plugin_ctx_init(be_ctx, be_ctx, be_ctx->be_res,
                                     default_host_dbs,
                                     ad_id_ctx->ad_options->id,
                                     ad_id_ctx->ad_options,
                                     id_ctx->server_mode->hostname,
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

    ret = ad_set_search_bases(ad_options->id, sdom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD search bases\n");
        talloc_free(ad_options);
        return ret;
    }

    sdap_inherit_options(subdom->parent->sd_inherit,
                         id_ctx->sdap_id_ctx->opts,
                         ad_id_ctx->sdap_id_ctx->opts);

    ret = sdap_id_setup_tasks(be_ctx,
                              ad_id_ctx->sdap_id_ctx,
                              sdom,
                              ldap_id_enumeration_send,
                              ldap_id_enumeration_recv,
                              ad_id_ctx->sdap_id_ctx);
    if (ret != EOK) {
        talloc_free(ad_options);
        return ret;
    }

    sdom->pvt = ad_id_ctx;

    /* Set up the ID mapping object */
    ad_id_ctx->sdap_id_ctx->opts->idmap_ctx =
        id_ctx->sdap_id_ctx->opts->idmap_ctx;

    /* Set up the certificate mapping context */
    ad_id_ctx->sdap_id_ctx->opts->sdap_certmap_ctx =
        id_ctx->sdap_id_ctx->opts->sdap_certmap_ctx;

    *_ad_id_ctx = ad_id_ctx;
    return EOK;
}

static errno_t
ipa_ctx_new(struct be_ctx *be_ctx,
            struct ipa_id_ctx *id_ctx,
            struct sss_domain_info *subdom,
            struct ipa_id_ctx **_ipa_id_ctx)
{
    struct ipa_options *ipa_options = NULL;
    struct ipa_id_ctx *ipa_subdom_id_ctx;
    struct ipa_srv_plugin_ctx *srv_ctx;
    const char *ipa_domain;
    char *subdom_conf_path = NULL;
    char *basedn;
    struct sdap_domain *sdom;
    errno_t ret;
    const char *extra_attrs;

    ipa_domain = subdom->name;
    DEBUG(SSSDBG_TRACE_LIBS, "Setting up IPA subdomain %s\n", subdom->name);

    subdom_conf_path = subdomain_create_conf_path(id_ctx, subdom);
    if (subdom_conf_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "subdom_conf_path failed\n");
        ret = ENOMEM;
        goto done;
    }

    ipa_options = ipa_options_new(be_ctx, id_ctx, subdom);
    if (ipa_options == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD options\n");
        ret = ENOMEM;
        goto done;
    }

    extra_attrs = dp_opt_get_string(id_ctx->sdap_id_ctx->opts->basic,
                            SDAP_USER_EXTRA_ATTRS);
    if (extra_attrs != NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Setting extra attrs for subdomain [%s] to [%s].\n", ipa_domain,
                                                                   extra_attrs);

        ret = dp_opt_set_string(ipa_options->id->basic, SDAP_USER_EXTRA_ATTRS,
                                extra_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "dp_opt_set_string failed.\n");
            goto done;
        }

        ret = sdap_extend_map_with_list(ipa_options->id, ipa_options->id,
                                        SDAP_USER_EXTRA_ATTRS,
                                        ipa_options->id->user_map,
                                        SDAP_OPTS_USER,
                                        &ipa_options->id->user_map,
                                        &ipa_options->id->user_map_cnt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_extend_map_with_list failed.\n");
            goto done;
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "No extra attrs set.\n");
    }

    /* ipa_id_ctx and sdap_id_ctx for the ipa subdomain
     * are initialized in ipa_options_new() */
    ipa_subdom_id_ctx = ipa_options->id_ctx;
    ipa_subdom_id_ctx->sdap_id_ctx->opts = ipa_options->id;

    srv_ctx = ipa_srv_plugin_ctx_init(be_ctx, be_ctx->be_res->resolv,
                                      id_ctx->server_mode->hostname,
                                      ipa_domain);

    if (srv_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?\n");
        ret = ENOMEM;
        goto done;
    }
    be_fo_set_srv_lookup_plugin(be_ctx, ipa_srv_plugin_send,
                                ipa_srv_plugin_recv, srv_ctx, "IPA");

   ret = sdap_domain_subdom_add(ipa_subdom_id_ctx->sdap_id_ctx,
                                ipa_subdom_id_ctx->sdap_id_ctx->opts->sdom,
                                subdom->parent);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize sdap domain\n");
        goto done;
    }

    sdom = sdap_domain_get(ipa_subdom_id_ctx->sdap_id_ctx->opts, subdom);
    if (sdom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get sdap domain\n");
        ret = EFAULT;
        goto done;
    }

    ret = ipa_set_sdap_options(ipa_options, ipa_options->id);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set IPA sdap options\n");
        goto done;
    }

    ret = domain_to_basedn(be_ctx,
                           dp_opt_get_string(ipa_options->id->basic, IPA_KRB5_REALM),
                           &basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "domain_to_basedn failure\n");
        goto done;
    }

    ipa_set_search_bases(ipa_options,
                         be_ctx->cdb,
                         basedn,
                         subdom_conf_path,
                         sdom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set search bases\n");
        goto done;
    }

    sdap_inherit_options(subdom->parent->sd_inherit,
                         id_ctx->sdap_id_ctx->opts,
                         ipa_subdom_id_ctx->sdap_id_ctx->opts);

    ret = sdap_id_setup_tasks(be_ctx,
                              ipa_subdom_id_ctx->sdap_id_ctx,
                              sdom,
                              ldap_id_enumeration_send,
                              ldap_id_enumeration_recv,
                              ipa_subdom_id_ctx->sdap_id_ctx);
    if (ret != EOK) {
        goto done;
    }

    sdom->pvt = ipa_subdom_id_ctx;

    /* Set up the ID mapping object */
    ipa_subdom_id_ctx->sdap_id_ctx->opts->idmap_ctx =
        id_ctx->sdap_id_ctx->opts->idmap_ctx;

    /* Set up the certificate mapping context */
    ipa_subdom_id_ctx->sdap_id_ctx->opts->sdap_certmap_ctx =
        id_ctx->sdap_id_ctx->opts->sdap_certmap_ctx;

    *_ipa_id_ctx = ipa_subdom_id_ctx;

    ret = EOK;
done:

    if (ret != EOK) {
        if (subdom_conf_path != NULL) {
            talloc_free(subdom_conf_path);
        }
        if (ipa_options != NULL) {
            talloc_free(ipa_options);
        }
    }
    return ret;
}

struct ipa_getkeytab_state {
    int child_status;
    struct sss_child_ctx_old *child_ctx;
    struct tevent_timer *timeout_handler;
};

static void ipa_getkeytab_exec(const char *ccache,
                               const char *server,
                               const char *principal,
                               const char *keytab_path);
static void ipa_getkeytab_done(int child_status,
                               struct tevent_signal *sige,
                               void *pvt);
static void ipa_getkeytab_timeout(struct tevent_context *ev,
                                  struct tevent_timer *te,
                                  struct timeval tv, void *pvt);

static struct tevent_req *ipa_getkeytab_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             const char *ccache,
                                             const char *server,
                                             const char *principal,
                                             const char *keytab)


{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct ipa_getkeytab_state *state;
    pid_t child_pid;
    struct timeval tv;

    req = tevent_req_create(mem_ctx, &state, struct ipa_getkeytab_state);
    if (req == NULL) {
        return NULL;
    }
    state->child_status = EFAULT;

    if (server == NULL || principal == NULL || keytab == NULL) {
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Retrieving keytab for %s from %s into %s using ccache %s\n",
          principal, server, keytab, ccache);

    child_pid = fork();
    if (child_pid == 0) { /* child */
        ipa_getkeytab_exec(ccache, server, principal, keytab);
    } else if (child_pid > 0) { /* parent */
        /* Set up SIGCHLD handler */
        ret = child_handler_setup(ev, child_pid, ipa_getkeytab_done, req,
                                  &state->child_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not set up child handlers [%d]: %s\n",
                ret, sss_strerror(ret));
            ret = ERR_IPA_GETKEYTAB_FAILED;
            goto done;
        }

        /* Set up timeout handler */
        tv = tevent_timeval_current_ofs(IPA_GETKEYTAB_TIMEOUT, 0);
        state->timeout_handler = tevent_add_timer(ev, req, tv,
                                                  ipa_getkeytab_timeout, req);
        if(state->timeout_handler == NULL) {
            ret = ERR_IPA_GETKEYTAB_FAILED;
            goto done;
        }

        /* Now either wait for the timeout to fire or the child
         * to finish
         */
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fork failed [%d][%s].\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void ipa_getkeytab_exec(const char *ccache,
                               const char *server,
                               const char *principal,
                               const char *keytab_path)
{
    errno_t ret;
    int debug_fd;
    const char *gkt_env[3] = { NULL, "_SSS_LOOPS=NO", NULL };

    if (debug_level >= SSSDBG_TRACE_LIBS) {
        debug_fd = get_fd_from_debug_file();
        ret = dup2(debug_fd, STDERR_FILENO);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                "dup2 failed [%d][%s].\n", ret, sss_strerror(ret));
            /* stderr is not fatal */
        }
    }

    gkt_env[0] = talloc_asprintf(NULL, "KRB5CCNAME=%s", ccache);
    if (gkt_env[0] == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to format KRB5CCNAME\n");
        exit(1);
    }

    /* ipa-getkeytab cannot add keys to an empty file, let's unlink it and only
     * use the filename */
    ret = unlink(keytab_path);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to unlink the temporary ccname [%d][%s]\n",
              ret, sss_strerror(ret));
        exit(1);
    }

    errno = 0;
    ret = execle(IPA_GETKEYTAB_PATH, IPA_GETKEYTAB_PATH,
                 "-r", "-s", server, "-p", principal, "-k", keytab_path, NULL,
                 gkt_env);

    DEBUG(SSSDBG_FATAL_FAILURE,
          "execle returned %d, this shouldn't happen!\n", ret);

    /* The child should never end up here */
    ret = errno;
    DEBUG(SSSDBG_FATAL_FAILURE,
          "execle failed [%d][%s].\n", ret, sss_strerror(ret));
    exit(1);
}

static void ipa_getkeytab_done(int child_status,
                               struct tevent_signal *sige,
                               void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct ipa_getkeytab_state *state =
            tevent_req_data(req, struct ipa_getkeytab_state);

    state->child_status = child_status;

    if (WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa-getkeytab failed with status [%d]\n", child_status);
        tevent_req_error(req, ERR_IPA_GETKEYTAB_FAILED);
        return;
    }

    if (WIFSIGNALED(child_status)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa-getkeytab was terminated by signal [%d]\n",
               WTERMSIG(child_status));
        tevent_req_error(req, ERR_IPA_GETKEYTAB_FAILED);
        return;
    }

    tevent_req_done(req);
}

static void ipa_getkeytab_timeout(struct tevent_context *ev,
                                  struct tevent_timer *te,
                                  struct timeval tv, void *pvt)
{
    struct tevent_req *req =
            talloc_get_type(pvt, struct tevent_req);
    struct ipa_getkeytab_state *state =
            tevent_req_data(req, struct ipa_getkeytab_state);

    DEBUG(SSSDBG_CRIT_FAILURE, "Timeout reached for retrieving keytab from IPA server\n");
    child_handler_destroy(state->child_ctx);
    state->child_ctx = NULL;
    state->child_status = ETIMEDOUT;
    tevent_req_error(req, ERR_IPA_GETKEYTAB_FAILED);
}

static errno_t ipa_getkeytab_recv(struct tevent_req *req, int *child_status)
{
    struct ipa_getkeytab_state *state =
            tevent_req_data(req, struct ipa_getkeytab_state);

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "ipa-getkeytab status %d\n", state->child_status);
    if (child_status) {
        *child_status = state->child_status;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static errno_t ipa_check_keytab(const char *keytab,
                                uid_t kt_owner_uid,
                                gid_t kt_owner_gid)
{
    errno_t ret;

    ret = check_file(keytab, getuid(), getgid(), S_IFREG|0600, 0, NULL, false);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "Keytab %s is not present\n", keytab);
        goto done;
    } else if (ret != EOK) {
        if (kt_owner_uid) {
            ret = check_file(keytab, kt_owner_uid, kt_owner_gid,
                             S_IFREG|0600, 0, NULL, false);
        }

        if (ret != EOK) {
            if (ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to check for %s\n", keytab);
            } else {
                DEBUG(SSSDBG_TRACE_FUNC, "Keytab %s is not present\n", keytab);
            }
        }
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "keytab %s already exists\n", keytab);
    ret = EOK;
done:
    return ret;
}

struct ipa_server_trusted_dom_setup_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *id_ctx;
    struct sss_domain_info *subdom;

    uint32_t direction;
    const char *forest;
    const char *keytab;
    char *new_keytab;
    const char *principal;
    const char *forest_realm;
    const char *ccache;
};

static errno_t ipa_server_trusted_dom_setup_1way(struct tevent_req *req);
static void ipa_server_trust_1way_kt_done(struct tevent_req *subreq);

struct tevent_req *
ipa_server_trusted_dom_setup_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct ipa_id_ctx *id_ctx,
                                  struct sss_domain_info *subdom)
{
    struct tevent_req *req = NULL;
    struct ipa_server_trusted_dom_setup_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_server_trusted_dom_setup_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->be_ctx = be_ctx;
    state->id_ctx = id_ctx;
    state->subdom = subdom;

    /* Trusts are only established with forest roots */
    if (subdom->forest_root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Subdomain %s has no forest root?\n", subdom->name);
        ret = ERR_TRUST_FOREST_UNKNOWN;
        goto immediate;
    }

    state->direction = subdom->forest_root->trust_direction;
    state->forest = subdom->forest_root->forest;
    state->forest_realm = subdom->forest_root->realm;
    state->ccache = talloc_asprintf(state, "%s/ccache_%s",
                                    DB_PATH, subdom->parent->realm);
    if (state->ccache == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "Trust direction of subdom %s from forest %s is: %s\n",
          subdom->name, state->forest,
          ipa_trust_dir2str(state->direction));

    /* For both inbound and outbound trusts use a special keytab
     * as this allows us to reuse the same logic in FreeIPA for
     * both Microsoft AD and Samba AD */
    if (state->direction & LSA_TRUST_DIRECTION_MASK) {
        /* Need special keytab */
        ret = ipa_server_trusted_dom_setup_1way(req);
        if (ret == EAGAIN) {
            /* In progress.. */
            return req;
        } else if (ret == EOK) {
            /* Keytab available, shortcut */
            ret = EOK;
            goto immediate;
        }
    } else {
        /* Even unset is an error at this point */
        DEBUG(SSSDBG_OP_FAILURE,
              "Subdomain %s has trust direction %d\n",
              subdom->name, subdom->trust_direction);
        ret = ERR_TRUST_NOT_SUPPORTED;
    }

immediate:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not add trusted subdomain %s from forest %s\n",
              subdom->name, state->forest);
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ipa_server_trusted_dom_setup_1way(struct tevent_req *req)
{
    errno_t ret;
    struct tevent_req *subreq = NULL;
    struct ipa_server_trusted_dom_setup_state *state =
            tevent_req_data(req, struct ipa_server_trusted_dom_setup_state);
    const char *hostname;

    state->keytab = forest_keytab(state, state->forest);
    if (state->keytab == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot set up ipa_get_keytab\n");
        return EIO;
    }

    state->new_keytab = talloc_asprintf(state, "%sXXXXXX", state->keytab);
    if (state->new_keytab == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot set up ipa_get_keytab. talloc_asprintf() failed\n");
        return ENOMEM;
    }

    ret = sss_unique_filename(state, state->new_keytab);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create temporary keytab name\n");
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Will re-fetch keytab for %s\n", state->subdom->name);

    hostname = dp_opt_get_string(state->id_ctx->ipa_options->basic,
                                 IPA_HOSTNAME);

    state->principal = subdomain_trust_princ(state,
                                             state->forest_realm,
                                             state->subdom);
    if (state->principal == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot set up ipa_get_keytab\n");
        return EIO;
    }

    subreq = ipa_getkeytab_send(state->be_ctx, state->be_ctx->ev,
                                state->ccache,
                                hostname,
                                state->principal,
                                state->new_keytab);
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ipa_server_trust_1way_kt_done, req);
    return EAGAIN;
}

static void ipa_server_trust_1way_kt_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_server_trusted_dom_setup_state *state =
            tevent_req_data(req, struct ipa_server_trusted_dom_setup_state);

    ret = ipa_getkeytab_recv(subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* Do not fail here, but try to check and use the previous keytab,
         * if any */
        DEBUG(SSSDBG_MINOR_FAILURE, "ipa_getkeytab_recv failed: %d\n", ret);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Keytab successfully retrieved to %s\n", state->new_keytab);
    }

    ret = ipa_check_keytab(state->new_keytab,
                           state->id_ctx->server_mode->kt_owner_uid,
                           state->id_ctx->server_mode->kt_owner_gid);
    if (ret == EOK) {
        ret = rename(state->new_keytab, state->keytab);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                "rename failed [%d][%s].\n", ret, strerror(ret));
            tevent_req_error(req, ret);
            return;
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Keytab renamed to %s\n", state->keytab);
    } else if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Trying to recover and use the previous keytab, if available\n");
        ret = ipa_check_keytab(state->keytab,
                               state->id_ctx->server_mode->kt_owner_uid,
                               state->id_ctx->server_mode->kt_owner_gid);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "The previous keytab %s contains the expected principal\n",
                  state->keytab);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot use the old keytab: %d\n", ret);
            /* Nothing we can do now */
            tevent_req_error(req, ret);
            return;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Keytab %s contains the expected principals\n", state->new_keytab);

    DEBUG(SSSDBG_TRACE_FUNC,
          "Established trust context for %s\n", state->subdom->name);
    tevent_req_done(req);
}

errno_t ipa_server_trusted_dom_setup_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ipa_server_create_trusts_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *id_ctx;
    struct sss_domain_info *domiter;
};

static errno_t ipa_server_create_trusts_step(struct tevent_req *req);
static errno_t ipa_server_create_trusts_ctx(struct tevent_req *req);
static void ipa_server_create_trusts_done(struct tevent_req *subreq);

struct tevent_req *
ipa_server_create_trusts_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct be_ctx *be_ctx,
                              struct ipa_id_ctx *id_ctx,
                              struct sss_domain_info *parent)
{
    struct tevent_req *req = NULL;
    struct ipa_server_create_trusts_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_server_create_trusts_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->id_ctx = id_ctx;
    state->domiter = parent;

    ret = ipa_server_create_trusts_step(req);
    if (ret != EAGAIN) {
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

static errno_t ipa_server_create_trusts_step(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct ipa_subdom_server_ctx *trust_iter;
    struct ipa_subdom_server_ctx *trust_i;
    struct ipa_server_create_trusts_state *state = NULL;

    state = tevent_req_data(req, struct ipa_server_create_trusts_state);

    for (state->domiter = get_next_domain(state->domiter, SSS_GND_DESCEND);
         state->domiter && IS_SUBDOMAIN(state->domiter);
         state->domiter = get_next_domain(state->domiter, 0)) {

        /* Check if we already have an ID context for this subdomain */
        DLIST_FOR_EACH(trust_iter, state->id_ctx->server_mode->trusts) {
            if (trust_iter->dom == state->domiter) {
                break;
            }
        }

        /* Newly detected trust */
        if (trust_iter == NULL) {
            subreq = ipa_server_trusted_dom_setup_send(state,
                                                       state->ev,
                                                       state->be_ctx,
                                                       state->id_ctx,
                                                       state->domiter);
            if (subreq == NULL) {
                return ENOMEM;
            }
            tevent_req_set_callback(subreq, ipa_server_create_trusts_done, req);
            return EAGAIN;
        }
    }

    /* Refresh all sdap_dom lists in all ipa_subdom_server_ctx contexts */
    DLIST_FOR_EACH(trust_iter, state->id_ctx->server_mode->trusts) {
        struct sdap_domain *sdom_a;

        sdom_a = sdap_domain_get_by_trust_type(trust_iter, trust_iter->dom);
        if (sdom_a == NULL) {
            continue;
        }

        DLIST_FOR_EACH(trust_i, state->id_ctx->server_mode->trusts) {
            struct sdap_domain *sdom_b;

            if (strcmp(trust_iter->dom->name, trust_i->dom->name) == 0) {
                continue;
            }

            sdom_b = sdap_domain_get_by_trust_type(trust_i, sdom_a->dom);
            if (sdom_b == NULL) {
                continue;
            }

            /* Replace basedn and search bases from sdom_b with values
             * from sdom_a */
            sdap_domain_copy_search_bases(sdom_b, sdom_a);
        }
    }

    return EOK;
}

static void ipa_server_create_trusts_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    ret = ipa_server_trusted_dom_setup_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = ipa_server_create_trusts_ctx(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = ipa_server_create_trusts_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
        return;
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }

    /* Will cycle back */
}

static errno_t ipa_server_create_trusts_ctx(struct tevent_req *req)
{
    struct ipa_subdom_server_ctx *trust_ctx;
    struct ad_id_ctx *ad_id_ctx;
    struct ipa_id_ctx *ipa_id_ctx;
    errno_t ret;
    enum ipa_trust_type trust_type;
    struct ipa_server_create_trusts_state *state = NULL;

    state = tevent_req_data(req, struct ipa_server_create_trusts_state);

    trust_type = state->domiter->forest_root->trust_type;

    trust_ctx = talloc(state->id_ctx->server_mode, struct ipa_subdom_server_ctx);
    if (trust_ctx == NULL) {
        return ENOMEM;
    }
    trust_ctx->dom = state->domiter;
    trust_ctx->type = trust_type;

    /* Previously stored AD trusted domains dont contain trust type attr */
    if (trust_type != IPA_TRUST_AD && trust_type != IPA_TRUST_IPA) {
        trust_type = IPA_TRUST_AD;
    }

    if (trust_type == IPA_TRUST_AD) {
        ret = ipa_ad_ctx_new(state->be_ctx, state->id_ctx, state->domiter, &ad_id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot create ad_id_ctx for subdomain %s\n", state->domiter->name);
            return ret;
        }

        trust_ctx->id_ctx.ad_id_ctx = ad_id_ctx;
    } else if (trust_type == IPA_TRUST_IPA) {
        ret = ipa_ctx_new(state->be_ctx, state->id_ctx, state->domiter, &ipa_id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot create ipa_id_ctx for subdomain %s\n", state->domiter->name);
            return ret;
        }

        trust_ctx->id_ctx.ipa_id_ctx = ipa_id_ctx;
    }

    DLIST_ADD(state->id_ctx->server_mode->trusts, trust_ctx);
    return EOK;
}

errno_t ipa_server_create_trusts_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

void ipa_ad_subdom_remove(struct be_ctx *be_ctx,
                          struct ipa_id_ctx *id_ctx,
                          struct sss_domain_info *subdom)
{
    struct ipa_subdom_server_ctx *iter;
    struct sdap_domain *sdom;

    if (dp_opt_get_bool(id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        return;
    }

    DLIST_FOR_EACH(iter, id_ctx->server_mode->trusts) {
        if (iter->dom == subdom) break;
    }

    if (iter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No IPA-AD context for subdomain %s\n",
              subdom->name);
        return;
    }

    sdom = sdap_domain_get_by_trust_type(iter, subdom);
    if (sdom == NULL) return;

    sdap_domain_remove_by_trust_type(iter, subdom);
    DLIST_REMOVE(id_ctx->server_mode->trusts, iter);

    /* terminate all requests for this subdomain so we can free it */
    dp_terminate_domain_requests(be_ctx->provider, subdom->name);
    talloc_zfree(sdom);
}

struct ipa_trusted_subdom_reinit_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *id_ctx;
    struct sss_domain_info *parent;
};

static void create_trusts_at_startup_done(struct tevent_req *req)
{
    errno_t ret;

    ret = ipa_server_create_trusts_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ipa_server_create_trusts_send request failed [%d]: %s\n",
              ret, sss_strerror(ret));
    }
}

static void create_trusts_at_startup(struct tevent_context *ev,
                                     struct tevent_immediate *imm,
                                     void *pvt)
{
    struct tevent_req *req;
    struct ipa_trusted_subdom_reinit_state *state;

    state = talloc_get_type(pvt, struct ipa_trusted_subdom_reinit_state);

    req = ipa_server_create_trusts_send(state, state->ev, state->be_ctx,
                                        state->id_ctx, state->parent);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_server_create_trusts_send failed.\n");
        talloc_free(state);
        return;
    }

    tevent_req_set_callback(req, create_trusts_at_startup_done, state);
    return;
}

static errno_t ipa_trusted_subdom_reinit(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct be_ctx *be_ctx,
                                         struct ipa_id_ctx *id_ctx,
                                         struct sss_domain_info *parent)
{
    struct tevent_immediate *imm;
    struct ipa_trusted_subdom_reinit_state *state;

    state = talloc(mem_ctx, struct ipa_trusted_subdom_reinit_state);
    if (state == NULL) {
        return ENOMEM;
    }
    state->ev = ev;
    state->be_ctx = be_ctx;
    state->id_ctx = id_ctx;
    state->parent = parent;

    if (dp_opt_get_bool(id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        return EOK;
    }

    imm = tevent_create_immediate(mem_ctx);
    if (imm == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_create_immediate failed.\n");
        talloc_free(state);
        return ENOMEM;
    }

    tevent_schedule_immediate(imm, ev, create_trusts_at_startup, state);
    return EOK;
}

int ipa_trusted_subdom_init(struct be_ctx *be_ctx,
                            struct ipa_id_ctx *id_ctx)
{
    char *realm;
    char *hostname;
    errno_t ret;

    if (dp_opt_get_bool(id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        return EOK;
    }

    /* The IPA code relies on the default FQDN format to unparse user
     * names. Warn loudly if the full_name_format was customized on the
     * IPA server
     */
    if ((strcmp(be_ctx->domain->names->fq_fmt,
               CONFDB_DEFAULT_FULL_NAME_FORMAT) != 0)
            && (strcmp(be_ctx->domain->names->fq_fmt,
                       CONFDB_DEFAULT_FULL_NAME_FORMAT_INTERNAL) != 0)) {
        DEBUG(SSSDBG_FATAL_FAILURE, "%s is set to a non-default value [%s] " \
              "lookups of subdomain users will likely fail!\n",
              CONFDB_FULL_NAME_FORMAT, be_ctx->domain->names->fq_fmt);
        sss_log(SSS_LOG_ERR, "%s is set to a non-default value [%s] " \
                "lookups of subdomain users will likely fail!\n",
                CONFDB_FULL_NAME_FORMAT, be_ctx->domain->names->fq_fmt);
        /* Attempt to continue */
    }

    realm = dp_opt_get_string(id_ctx->ipa_options->basic, IPA_KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No Kerberos realm for IPA?\n");
        return EINVAL;
    }

    hostname = dp_opt_get_string(id_ctx->ipa_options->basic, IPA_HOSTNAME);
    if (hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No host name for IPA?\n");
        return EINVAL;
    }

    id_ctx->server_mode = talloc_zero(id_ctx, struct ipa_server_mode_ctx);
    if (id_ctx->server_mode == NULL) {
        return ENOMEM;
    }
    id_ctx->server_mode->realm = realm;
    id_ctx->server_mode->hostname = hostname;
    id_ctx->server_mode->trusts = NULL;
    id_ctx->server_mode->ext_groups = NULL;
    id_ctx->server_mode->kt_owner_uid = 0;
    id_ctx->server_mode->kt_owner_gid = 0;

    if (getuid() == 0) {
        /* We need to handle keytabs created by IPA oddjob script gracefully
         * even if we're running as root and IPA creates them as the SSSD user
         */
        ret = sss_user_by_name_or_uid(SSSD_USER,
                                      &id_ctx->server_mode->kt_owner_uid,
                                      &id_ctx->server_mode->kt_owner_gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to get ID of %s\n", SSSD_USER);
        }
    }

    ret = ipa_trusted_subdom_reinit(be_ctx, be_ctx->ev,
                               be_ctx, id_ctx, be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_trusted_subdom_reinit failed.\n");
        return ret;
    }

    return EOK;
}
