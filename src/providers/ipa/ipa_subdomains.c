/*
    SSSD

    IPA Subdomains Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include "providers/ldap/sdap_ops.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_opts.h"
#include "providers/ipa/ipa_config.h"
#ifdef BUILD_PASSKEY
#include "providers/ipa/ipa_subdomains_passkey.h"
#endif /* BUILD_PASSKEY */

#include <ctype.h>

#define SUBDOMAINS_FILTER "objectclass=ipaNTTrustedDomain"
#define MASTER_DOMAIN_FILTER "objectclass=ipaNTDomainAttrs"
#define RANGE_FILTER "objectclass=ipaIDRange"

#define IPA_FLATNAME "ipaNTFlatName"
#define IPA_SID "ipaNTSecurityIdentifier"
#define IPA_ADDITIONAL_SUFFIXES "ipaNTAdditionalSuffixes"
#define IPA_SID_BLACKLIST_INCOMING "ipaNTSIDBlacklistIncoming"

#define OBJECTCLASS "objectClass"

#define IPA_ASSIGNED_ID_VIEW "ipaAssignedIDView"

#define IPA_DOMAIN_RESOLUTION_ORDER "ipaDomainResolutionOrder"

/* do not refresh more often than every 5 seconds for now */
#define IPA_SUBDOMAIN_REFRESH_LIMIT 5

#define IPA_SUBDOMAIN_DISABLED_PERIOD 3600

#define IPA_OC_CERTMAP_CONFIG_OBJECT "ipaCertMapConfigObject"
#define IPA_CERTMAP_PROMPT_USERNAME "ipaCertMapPromptUserName"

#define IPA_OC_CERTMAP_RULE "ipaCertMapRule"
#define IPA_CERTMAP_MAPRULE "ipaCertMapMapRule"
#define IPA_CERTMAP_MATCHRULE "ipaCertMapMatchRule"
#define IPA_CERTMAP_PRIORITY "ipaCertMapPriority"
#define IPA_ENABLED_FLAG "ipaEnabledFlag"
#define IPA_TRUE_VALUE "TRUE"
#define IPA_ASSOCIATED_DOMAIN "associatedDomain"
#define IPA_PASSKEY_VERIFICATION "ipaRequireUserVerification"
#define IPA_PASSKEY_CONFIG_FILTER "cn=passkeyconfig"

#define OBJECTCLASS "objectClass"

#define CERTMAP_FILTER "(|(&("OBJECTCLASS"="IPA_OC_CERTMAP_RULE")" \
                              "("IPA_ENABLED_FLAG"="IPA_TRUE_VALUE"))" \
                          "("OBJECTCLASS"="IPA_OC_CERTMAP_CONFIG_OBJECT"))"

/* It doesn't make sense to resolve more servers than this from the SRV
 * lookup because kinit would time out before we are able to cycle
 * through the whole list
 */
#define MAX_SERVERS_FROM_SRV    5

struct ipa_sd_k5_svc_list {
    struct krb5_service *k5svc;

    struct ipa_sd_k5_svc_list *next;
    struct ipa_sd_k5_svc_list *prev;
};

static errno_t
ipa_subdom_reinit(struct ipa_subdomains_ctx *ctx)
{
    errno_t ret;
    bool canonicalize = false;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Re-initializing domain %s\n", ctx->be_ctx->domain->name);

    if (ctx->ipa_id_ctx->ipa_options->auth_ctx != NULL
          && ctx->ipa_id_ctx->ipa_options->auth_ctx->krb5_auth_ctx != NULL
          && ctx->ipa_id_ctx->ipa_options->auth_ctx->krb5_auth_ctx->opts != NULL
       ) {
        canonicalize = dp_opt_get_bool(
                    ctx->ipa_id_ctx->ipa_options->auth_ctx->krb5_auth_ctx->opts,
                    KRB5_CANONICALIZE);
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "Auth provider data is not available, "
                                    "most probably because the auth provider "
                                    "is not 'ipa'. Kerberos configuration "
                                    "snippet to set the 'canonicalize' option "
                                    "will not be created.\n");
    }

    ret = sss_write_krb5_conf_snippet(
                          dp_opt_get_string(ctx->ipa_id_ctx->ipa_options->basic,
                                            IPA_KRB5_CONFD_PATH),
                          canonicalize, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_write_krb5_conf_snippet failed.\n");
        /* Just continue */
    }

    ret = sysdb_master_domain_update(ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_master_domain_update failed.\n");
        return ret;
    }

    ret = sysdb_update_subdomains(ctx->be_ctx->domain, ctx->be_ctx->cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_subdomains failed.\n");
        return ret;
    }

    ret = sss_write_domain_mappings(ctx->be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "sss_krb5_write_mappings failed.\n");
        /* Just continue */
    }

    return EOK;
}

struct priv_sss_debug {
    int level;
};

static errno_t ipa_certmap_parse_results(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *domain,
                                         struct sdap_options *sdap_opts,
                                         size_t count,
                                         struct sysdb_attrs **reply,
                                         struct certmap_info ***_certmap_list)
{
    struct certmap_info **certmap_list = NULL;
    struct certmap_info *m;
    const char *value;
    const char **values;
    size_t c;
    size_t lc = 0;
    int ret;
    const char **ocs = NULL;
    bool user_name_hint = false;

    certmap_list = talloc_zero_array(mem_ctx, struct certmap_info *, count + 1);
    if (certmap_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    for (c = 0; c < count; c++) {
        ret = sysdb_attrs_get_string_array(reply[c], SYSDB_OBJECTCLASS, mem_ctx,
                                           &ocs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing objectclasses for config objects.\n");
            ret = EINVAL;
            goto done;
        }

        if (string_in_list(IPA_OC_CERTMAP_CONFIG_OBJECT, discard_const(ocs),
                           false)) {
            ret = sysdb_attrs_get_bool(reply[c], IPA_CERTMAP_PROMPT_USERNAME,
                                       &user_name_hint);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to read user name hint option, skipping.\n");
            }
            continue;
        }

        m = talloc_zero(certmap_list, struct certmap_info);
        if (m == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        m->name = talloc_strdup(m, value);
        if (m->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_CERTMAP_MATCHRULE, &value);
        if (ret == EOK) {
            m->match_rule = talloc_strdup(m, value);
            if (m->match_rule == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_CERTMAP_MAPRULE, &value);
        if (ret == EOK) {
            m->map_rule = talloc_strdup(m, value);
            if (m->map_rule == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string_array(reply[c], IPA_ASSOCIATED_DOMAIN, m,
                                           &values);
        if (ret == EOK) {
            m->domains = values;
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_CERTMAP_PRIORITY,
                                       &m->priority);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        } else if (ret == ENOENT) {
            m->priority = SSS_CERTMAP_MIN_PRIO;
        }

        certmap_list[lc++] = m;
    }

    certmap_list[lc] = NULL;

    ret = sdap_setup_certmap(sdap_opts->sdap_certmap_ctx, certmap_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_setup_certmap failed.\n");
        goto done;
    }

    ret = sysdb_update_certmap(domain->sysdb, certmap_list, user_name_hint);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_certmap failed.\n");
        goto done;
    }

    if (_certmap_list != NULL) {
        *_certmap_list = certmap_list;
    } else {
        talloc_free(certmap_list);
    }

    ret = EOK;

done:
    talloc_free(ocs);
    if (ret != EOK) {
        talloc_free(certmap_list);
    }

    return ret;
}

static errno_t ipa_subdom_enumerates(struct sss_domain_info *parent,
                                     struct sysdb_attrs *attrs,
                                     bool *_enumerates)
{
    errno_t ret;
    const char *name;

    ret = sysdb_attrs_get_string(attrs, IPA_CN, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        return ret;
    }

    *_enumerates = subdomain_enumerates(parent, name);
    return EOK;
}

static errno_t ipa_subdom_get_forest(TALLOC_CTX *mem_ctx,
                                     struct ldb_context *ldb_ctx,
                                     struct sysdb_attrs *attrs,
                                     char **_forest)
{
    int ret;
    struct ldb_dn *dn = NULL;
    const char *name;
    const struct ldb_val *val;
    char *forest = NULL;

    dn = ipa_subdom_ldb_dn(mem_ctx, ldb_ctx, attrs);
    if (dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_subdom_ldb_dn failed.\n");
        ret = EIO;
        goto done;
    }

    if (ipa_subdom_is_member_dom(dn) == false) {
        ret = sysdb_attrs_get_string(attrs, IPA_CN, &name);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        forest = talloc_strdup(mem_ctx, name);
        if (forest == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_INTERNAL, "The forest name is %s\n", forest);
        ret = EOK;
        goto done;
    }

    val = ldb_dn_get_component_val(dn, 1);
    forest = talloc_strndup(mem_ctx, (const char *) val->data, val->length);
    if (forest == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(dn);

    if (ret == EOK) {
        *_forest = forest;
    }

    return ret;
}

static errno_t ipa_get_sd_trust_direction(struct sysdb_attrs *sd,
                                          struct ipa_id_ctx *id_ctx,
                                          struct ldb_context *ldb_ctx,
                                          uint32_t *_direction)
{
    if (id_ctx->server_mode != NULL) {
        return ipa_server_get_trust_direction(sd, ldb_ctx, _direction);
    } else {
        /* Clients do not have access to the trust objects's trust direction
         * and don't generally care
         */
        *_direction = 0;
        return EOK;
    }
}

static errno_t ipa_get_sd_trust_type(struct sysdb_attrs *sd,
                                     struct ipa_id_ctx *id_ctx,
                                     struct ldb_context *ldb_ctx,
                                     uint32_t *_type)
{
    if (id_ctx->server_mode != NULL) {
        return ipa_server_get_trust_type(sd, ldb_ctx, _type);
    } else {
        /* Clients do not have access to the trust objects's trust type
         * and don't generally care
         */
        *_type = 0;
        return EOK;
    }
}

static errno_t ipa_subdom_store(struct sss_domain_info *parent,
                                struct ipa_id_ctx *id_ctx,
                                struct sdap_idmap_ctx *sdap_idmap_ctx,
                                struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    char *realm;
    const char *flat;
    const char *dns;
    const char *id;
    char *forest = NULL;
    int ret;
    bool use_id_mapping;
    enum sss_domain_mpg_mode mpg_mode;
    bool enumerate;
    uint32_t direction;
    uint32_t type;
    struct ldb_message_element *alternative_domain_suffixes = NULL;
    struct range_info *range;
    const char *forest_id;

    tmp_ctx = talloc_new(parent);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_attrs_get_string(attrs, IPA_CN, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }

    realm = get_uppercase_realm(tmp_ctx, name);
    if (!realm) {
        ret = ENOMEM;
        goto done;
    }

    dns = talloc_strdup(tmp_ctx, name);
    if (dns == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_string(attrs, IPA_FLATNAME, &flat);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }

    ret = sysdb_attrs_get_string(attrs, IPA_TRUSTED_DOMAIN_SID, &id);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }

    ret = sysdb_attrs_get_el_ext(attrs, IPA_ADDITIONAL_SUFFIXES, false,
                                 &alternative_domain_suffixes);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    ret = ipa_subdom_get_forest(tmp_ctx, sysdb_ctx_get_ldb(parent->sysdb),
                                attrs, &forest);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_subdom_enumerates(parent, attrs, &enumerate);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_get_sd_trust_direction(attrs, id_ctx,
                                     sysdb_ctx_get_ldb(parent->sysdb),
                                     &direction);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa_get_sd_trust_direction failed: %d\n", ret);
        goto done;
    }

    ret = ipa_get_sd_trust_type(attrs, id_ctx,
                                sysdb_ctx_get_ldb(parent->sysdb),
                                &type);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa_get_sd_trust_type failed: %d\n", ret);
        goto done;
    }

    if (id_ctx->server_mode != NULL) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Trust direction of [%s]: %s\n", name, ipa_trust_dir2str(direction));
        DEBUG(SSSDBG_FUNC_DATA,
              "Trust type of [%s]: %s\n", name, ipa_trust_type2str(type));
    }

    /* First see if there is an ID range for the domain. */
    ret = sysdb_get_range(tmp_ctx, parent->sysdb, id, &range);
    if (ret == ENOENT) {
        /* Check if there is ID range for the forest root. We need to find the
         * domain in sysdb since the sss_domain_info object might not be yet
         * created. */
        ret = sysdb_subdomain_get_id_by_name(tmp_ctx, parent->sysdb, forest,
                                             &forest_id);
        if (ret == EOK) {
            ret = sysdb_get_range(tmp_ctx, parent->sysdb, forest_id, &range);
        }
    }
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "Unable to find ID range for [%s] [%d]: %s\n",
              name, ret, sss_strerror(ret));
    }
    mpg_mode = ret == EOK ? range->mpg_mode : MPG_DEFAULT;

    DEBUG(SSSDBG_TRACE_FUNC, "Range mpg mode for %s: %s\n",
          name, str_domain_mpg_mode(mpg_mode));

    if (mpg_mode == MPG_DEFAULT) {
        use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                    sdap_idmap_ctx, name, id);
        if (use_id_mapping == true) {
            mpg_mode = MPG_ENABLED;
        } else {
            /* Domains that use the POSIX attributes set by the admin must
            * inherit the MPG setting from the parent domain so that the
            * auto_private_groups options works for trusted domains as well
            */
            mpg_mode = get_domain_mpg_mode(parent);
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Domain mpg mode for %s: %s\n",
          name, str_domain_mpg_mode(mpg_mode));

    ret = sysdb_subdomain_store(parent->sysdb, name, realm, flat, dns,
                                id, mpg_mode, enumerate, forest,
                                direction, type, alternative_domain_suffixes);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_subdomain_store failed.\n");
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static struct krb5_service *
ipa_subdom_get_k5_svc(struct ipa_subdomains_ctx *ctx,
                      struct sss_domain_info *dom,
                      bool use_kdcinfo)
{
    struct ipa_sd_k5_svc_list *k5svc_ent;

    /* get the service by realm */
    DLIST_FOR_EACH(k5svc_ent, ctx->k5svc_list) {
        if (strcasecmp(dom->realm, k5svc_ent->k5svc->realm) == 0) {
            break;
        }
    }

    if (k5svc_ent != NULL) {
        /* Already exists */
        return k5svc_ent->k5svc;
    }

    /* Create a new service */
    k5svc_ent = talloc_zero(ctx, struct ipa_sd_k5_svc_list);
    if (k5svc_ent == NULL) {
        return NULL;
    }

    k5svc_ent->k5svc = krb5_service_new(k5svc_ent,
                                        ctx->be_ctx,
                                        "IPA",
                                        dom->realm,
                                        use_kdcinfo,
                                        (size_t) -1,
                                        (size_t) -1);
    if (k5svc_ent->k5svc == NULL) {
        talloc_free(k5svc_ent);
        return NULL;
    }
    DLIST_ADD(ctx->k5svc_list, k5svc_ent);

    return k5svc_ent->k5svc;
}

static void ipa_subdom_remove_k5_svc(struct ipa_subdomains_ctx *ctx)
{
    /* Domain going away is such a rare operation that it makes
     * more sense to just throw away the whole k5svc_list and let
     * the write_kdcinfo request recreate them all again instead
     * of coding up complex logic..
     */
    talloc_zfree(ctx->k5svc_list);
}

static void ipa_subdom_remove_step(struct ipa_subdomains_ctx *ctx,
                                   struct sss_domain_info *dom)
{
    if (dp_opt_get_bool(ctx->ipa_id_ctx->ipa_options->basic,
                        IPA_SERVER_MODE) == false) {
        /* IPA clients keep track of krb5_service wrappers */
        return ipa_subdom_remove_k5_svc(ctx);
    } else {
        /* IPA servers keeps track of AD contexts */
        return ipa_ad_subdom_remove(ctx->be_ctx, ctx->ipa_id_ctx, dom);
    }

}

static void ipa_subdom_store_step(struct sss_domain_info *parent,
                                  struct ipa_id_ctx *id_ctx,
                                  struct sdap_idmap_ctx *sdap_idmap_ctx,
                                  struct sysdb_attrs *attrs)
{
    int ret;

    ret = ipa_subdom_store(parent, id_ctx, sdap_idmap_ctx, attrs);
    if (ret == ERR_TRUST_NOT_SUPPORTED) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unsupported trust type, skipping\n");
    } else if (ret) {
        /* Nothing we can do about the error. */
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to parse subdom data, "
              "will try to use cached subdomain\n");
    }
}

static errno_t add_dom_sids_to_list(TALLOC_CTX *mem_ctx, const char **sids,
                                    char ***list)
{
    size_t c;
    errno_t ret;

    for (c = 0; sids != NULL && sids[c] != NULL; c++) {
        if (is_domain_sid(sids[c])) {
            ret = add_string_to_list(mem_ctx, sids[c], list);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "add_string_to_list failed.\n");
                return ret;
            }
        }
    }

    return EOK;
}

static errno_t ipa_get_disabled_domain_sids(TALLOC_CTX *mem_ctx, size_t count,
                                            struct sysdb_attrs **reply,
                                            char ***disabled_domain_sids)
{
    size_t c;
    char **dom_sid_list = NULL;
    const char **tmp_list;
    int ret;

    for (c = 0; c < count; c++) {
        ret = sysdb_attrs_get_string_array(reply[c], IPA_SID_BLACKLIST_INCOMING,
                                           mem_ctx, &tmp_list);
        if (ret != EOK) {
            if (ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_get_string_array failed, list of disabled "
                      "domains might be incomplete.\n");
            }
            continue;
        }

        ret = add_dom_sids_to_list(mem_ctx, tmp_list, &dom_sid_list);
        talloc_free(tmp_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "add_dom_sids_to_list failed.\n");
            talloc_free(dom_sid_list);
            return ret;
        }
    }

    *disabled_domain_sids = dom_sid_list;

    return EOK;
}

static errno_t ipa_subdomains_check_domain_state(struct sss_domain_info *dom,
                                                 char **disabled_domain_sids)
{
    int ret;

    if (dom->domain_id == NULL) {
        return EINVAL;
    }

    if (disabled_domain_sids != NULL
            && string_in_list(dom->domain_id, disabled_domain_sids, true)) {
        DEBUG(SSSDBG_TRACE_ALL, "Domain [%s] is disabled on the server.\n",
                                dom->name);
        /* disable domain if not already disabled */
        if (sss_domain_get_state(dom) != DOM_DISABLED) {
            sss_domain_set_state(dom, DOM_DISABLED);
            ret = sysdb_domain_set_enabled(dom->sysdb, dom->name, false);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_domain_set_enabled failed.\n");
                return ret;
            }

            ret = sysdb_subdomain_content_delete(dom->sysdb, dom->name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_subdomain_content_delete failed.\n");
                return ret;
            }
        }
    } else {
        /* enabled domain if it was disabled */
        DEBUG(SSSDBG_TRACE_ALL, "Domain [%s] is enabled on the server.\n",
                                dom->name);
        if (sss_domain_get_state(dom) == DOM_DISABLED) {
            sss_domain_set_state(dom, DOM_ACTIVE);
            ret = sysdb_domain_set_enabled(dom->sysdb, dom->name, true);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_domain_set_enabled failed.\n");
                return ret;
            }
        }
    }

    return EOK;
}


static void ipa_subdomains_update_dom_state(struct sss_domain_info *parent,
                                               int count,
                                               struct sysdb_attrs **reply)
{
    int ret;
    struct sss_domain_info *dom;
    char **disabled_domain_sids = NULL;

    ret = ipa_get_disabled_domain_sids(reply, count, reply,
                                       &disabled_domain_sids);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_disabled_domain_sids failed, "
                                 "assuming no domain is disabled.\n");
        disabled_domain_sids = NULL;
    }

    for (dom = get_next_domain(parent, SSS_GND_DESCEND|SSS_GND_INCLUDE_DISABLED);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, SSS_GND_INCLUDE_DISABLED)) {

        /* check if domain should be disabled/enabled */
        ret = ipa_subdomains_check_domain_state(dom, disabled_domain_sids);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to check domain state, "
                  "state of domain [%s] might be wrong.\n", dom->name);
        }
    }
}

static errno_t ipa_subdomains_refresh(struct ipa_subdomains_ctx *ctx,
                                      int count, struct sysdb_attrs **reply,
                                      bool *changes)
{
    struct sss_domain_info *parent, *dom;
    bool handled[count];
    const char *value;
    int c, h;
    int ret;

    parent = ctx->be_ctx->domain;
    memset(handled, 0, sizeof(bool) * count);
    h = 0;

    if (changes == NULL) {
        return EINVAL;
    }
    *changes = false;

    /* check existing subdomains */
    for (dom = get_next_domain(parent, SSS_GND_DESCEND);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, 0)) {
        for (c = 0; c < count; c++) {
            if (handled[c]) {
                continue;
            }
            ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
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
            sss_domain_set_state(dom, DOM_DISABLED);
            ret = sysdb_subdomain_delete(dom->sysdb, dom->name);
            if (ret != EOK) {
                goto done;
            }

            ipa_subdom_remove_step(ctx, dom);
        } else {
            /* ok let's try to update it */
            ipa_subdom_store_step(parent, ctx->ipa_id_ctx,
                                  ctx->sdap_id_ctx->opts->idmap_ctx,
                                  reply[c]);
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

        ipa_subdom_store_step(parent, ctx->ipa_id_ctx,
                              ctx->sdap_id_ctx->opts->idmap_ctx,
                              reply[c]);
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

static void clean_view_name(struct sss_domain_info *domain)
{
    struct sss_domain_info *dom = domain;

    while (dom) {
        dom->has_views = false;
        talloc_free(discard_const(dom->view_name));
        dom->view_name = NULL;
        dom = get_next_domain(dom, SSS_GND_DESCEND);
    }
}

static errno_t ipa_apply_view(struct sss_domain_info *domain,
                              struct ipa_id_ctx *ipa_id_ctx,
                              const char *view_name,
                              bool read_at_init,
                              struct confdb_ctx *confdb)
{
    const char *current = ipa_id_ctx->view_name;
    struct sysdb_ctx *sysdb = domain->sysdb;
    bool in_transaction = false;
    errno_t sret;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_ALL, "read_at_init [%s] current view [%s]\n",
          read_at_init ? "true" : "false", ipa_id_ctx->view_name);

    if (current != NULL && strcmp(current, view_name) != 0 && read_at_init) {
        DEBUG(SSSDBG_CRIT_FAILURE, "View name changed, this is not supported "
              "at runtime. Please restart SSSD to get the new view applied.\n");
        return EOK;
    }

    if (current != NULL && strcmp(current, view_name) == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "View name did not change.\n");
        return EOK;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "View name changed to [%s].\n", view_name);

    /* View name changed. If there was a non-default non-local view
     * was used the tree in cache containing the override values is
     * removed. In all cases sysdb_invalidate_overrides() is called to
     * remove the override attribute from the cached user objects.
     *
     * Typically ctx->sd_ctx->id_ctx->view_name == NULL means that the
     * cache was empty but there was a bug in with caused that the
     * view name was not written to the cache at all. In this case the
     * cache must be invalidated if the new view is not the
     * default-view as well. */

    if (current != NULL || !is_default_view(view_name)) {
        ret = sysdb_transaction_start(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to start transaction "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        in_transaction = true;

        if (!is_default_view(current) && !is_local_view(current)) {
            /* Old view was not the default view, delete view tree */
            ret = sysdb_delete_view_tree(sysdb, current);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Unable to delete old view tree "
                      "[%d]: %s\n", ret, sss_strerror(ret));
                goto done;
            }
        }

        ret = sysdb_invalidate_overrides(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, " Unable to invalidate overrides "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        ret = sysdb_transaction_commit(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to commint transaction "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        in_transaction = false;
    }

    ret = sysdb_update_view_name(sysdb, view_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot update view name "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    talloc_free(ipa_id_ctx->view_name);
    ipa_id_ctx->view_name = talloc_strdup(ipa_id_ctx, view_name);
    if (ipa_id_ctx->view_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot copy view name.\n");
        ret = ENOMEM;
        goto done;
    }

    if (!read_at_init) {
        /* refresh view data of all domains at startup, since
         * sysdb_master_domain_update and sysdb_update_subdomains might have
         * been called earlier without the proper view name the name is
         * cleaned here before the calls. This is acceptable because this is
         * the initial setup (!read_at_init).  */
        clean_view_name(domain);
        ret = sysdb_master_domain_update(domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_master_domain_update failed "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        ret = sysdb_update_subdomains(domain, confdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_subdomains failed "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }

    return ret;
}

struct ipa_subdomains_ranges_state {
    struct sss_domain_info *domain;
};

static void ipa_subdomains_ranges_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_subdomains_ranges_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ipa_subdomains_ctx *sd_ctx,
                           struct sdap_handle *sh)
{
    struct ipa_subdomains_ranges_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;
    const char *attrs[] = { OBJECTCLASS, IPA_CN,
                            IPA_BASE_ID, IPA_BASE_RID, IPA_SECONDARY_BASE_RID,
                            IPA_ID_RANGE_SIZE, IPA_TRUSTED_DOMAIN_SID,
                            IPA_RANGE_TYPE, IPA_ID_RANGE_MPG, NULL };

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_ranges_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (sd_ctx->ranges_search_bases == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No search base is set\n");
        ret = EOK;
        goto immediately;
    }

    state->domain = sd_ctx->be_ctx->domain;

    subreq = sdap_search_bases_send(state, ev, sd_ctx->sdap_id_ctx->opts, sh,
                                    sd_ctx->ranges_search_bases, NULL, false,
                                    0, RANGE_FILTER, attrs, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_ranges_done, req);

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

static void ipa_subdomains_ranges_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_ranges_state *state;
    struct tevent_req *req;
    struct range_info **range_list;
    struct sysdb_attrs **reply;
    size_t reply_count;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_ranges_state);

    ret = sdap_search_bases_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get data from LDAP [%d]: %s\n",
                      ret, sss_strerror(ret));
        goto done;
    }

    ret = ipa_ranges_parse_results(state, state->domain->name,
                                   reply_count, reply, &range_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to parse range resulg [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_update_ranges(state->domain->sysdb, range_list);
    talloc_free(range_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to update ranges [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ipa_subdomains_ranges_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

#define IPA_CERTMAP_SEARCH_BASE_TEMPLATE "cn=certmap,%s"

struct ipa_subdomains_certmap_state {
    struct sss_domain_info *domain;
    struct sdap_options *sdap_opts;
};

static void ipa_subdomains_certmap_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_subdomains_certmap_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ipa_subdomains_ctx *sd_ctx,
                           struct sdap_handle *sh)
{
    struct ipa_subdomains_certmap_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;
    char *ldap_basedn;
    char *search_base;
    const char *attrs[] = { OBJECTCLASS, IPA_CN,
                            IPA_CERTMAP_MAPRULE, IPA_CERTMAP_MATCHRULE,
                            IPA_CERTMAP_PRIORITY, IPA_ASSOCIATED_DOMAIN,
                            IPA_CERTMAP_PROMPT_USERNAME,
                            NULL };

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_certmap_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->domain = sd_ctx->be_ctx->domain;
    state->sdap_opts = sd_ctx->sdap_id_ctx->opts;

    ret = domain_to_basedn(state, state->domain->name, &ldap_basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "domain_to_basedn failed.\n");
        goto immediately;
    }

    search_base = talloc_asprintf(state, IPA_CERTMAP_SEARCH_BASE_TEMPLATE,
                                  ldap_basedn);
    if (search_base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_get_generic_send(state, ev, sd_ctx->sdap_id_ctx->opts, sh,
                                   search_base, LDAP_SCOPE_SUBTREE,
                                   CERTMAP_FILTER,
                                   attrs, NULL, 0, 0, false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_certmap_done, req);

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

static void ipa_subdomains_certmap_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_certmap_state *state;
    struct tevent_req *req;
    struct sysdb_attrs **reply;
    size_t reply_count;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_certmap_state);

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get data from LDAP [%d]: %s\n",
                      ret, sss_strerror(ret));
        goto done;
    }

    ret = ipa_certmap_parse_results(state, state->domain,
                                    state->sdap_opts,
                                    reply_count, reply, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to parse certmap results [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ipa_subdomains_certmap_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_subdomains_master_state {
    struct sss_domain_info *domain;
    struct ipa_options *ipa_options;
};

static void ipa_subdomains_master_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_subdomains_master_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ipa_subdomains_ctx *sd_ctx,
                           struct sdap_handle *sh)
{
    struct ipa_subdomains_master_state *state;
    struct sss_domain_info *domain;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;
    const char *attrs[] = { IPA_CN, IPA_FLATNAME, IPA_SID,
                            IPA_ADDITIONAL_SUFFIXES, NULL };

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_master_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (sd_ctx->master_search_bases == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No search base is set\n");
        ret = EOK;
        goto immediately;
    }

    state->domain = domain = sd_ctx->be_ctx->domain;
    state->ipa_options = sd_ctx->ipa_id_ctx->ipa_options;

    ret = sysdb_master_domain_update(domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to update master domain [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediately;
    }

    if (domain->flat_name != NULL && domain->domain_id != NULL
            && domain->dns_name != NULL
            && domain->realm != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Master record is up to date.\n");
        ret = EOK;
        goto immediately;
    }

    subreq = sdap_search_bases_return_first_send(state, ev,
                                     sd_ctx->sdap_id_ctx->opts, sh,
                                     sd_ctx->master_search_bases, NULL, false,
                                     0, MASTER_DOMAIN_FILTER, attrs, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_master_done, req);

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

static void ipa_subdomains_master_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_master_state *state;
    struct tevent_req *req;
    struct sysdb_attrs **reply;
    size_t reply_count;
    const char *flat = NULL;
    const char *dns = NULL;
    const char *id = NULL;
    const char *realm = NULL;
    struct ldb_message_element *alternative_domain_suffixes = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_master_state);

    ret = sdap_search_bases_return_first_recv(subreq, state,
                                              &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get data from LDAP [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (reply_count > 0) {
        ret = sysdb_attrs_get_string(reply[0], IPA_FLATNAME, &flat);
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[0], IPA_SID, &id);
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_attrs_get_el_ext(reply[0], IPA_ADDITIONAL_SUFFIXES, false,
                                     &alternative_domain_suffixes);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }
    } else {
        /* All search paths are searched and no master domain record was
         * found.
         *
         * A default IPA installation will not have a master domain record,
         * this is only created by ipa-adtrust-install. Nevertheless we should
         * continue to read other data like the idview on IPA clients. */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Master domain record not found!\n");
    }

    realm = dp_opt_get_string(state->ipa_options->basic, IPA_KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No Kerberos realm for IPA?\n");
        ret = EINVAL;
        goto done;
    }

    dns = dp_opt_get_string(state->ipa_options->basic, IPA_DOMAIN);
    if (dns == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No domain name for IPA?\n");
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_master_domain_add_info(state->domain, realm, flat, dns, id, NULL,
                                       alternative_domain_suffixes);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add master domain info "
              "[%d]: %s\n", ret, sss_strerror(ret));
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

static errno_t ipa_subdomains_master_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_subdomains_slave_state {
    struct ipa_subdomains_ctx *sd_ctx;
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *ipa_id_ctx;
};

static void ipa_subdomains_slave_search_done(struct tevent_req *subreq);
static void ipa_subdomains_slave_trusts_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_subdomains_slave_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct ipa_subdomains_ctx *sd_ctx,
                          struct sdap_handle *sh)
{
    struct ipa_subdomains_slave_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;
    const char *attrs[] = { IPA_CN, IPA_FLATNAME, IPA_TRUSTED_DOMAIN_SID,
                            IPA_TRUST_DIRECTION, IPA_ADDITIONAL_SUFFIXES,
                            IPA_SID_BLACKLIST_INCOMING, IPA_PARTNER_TRUST_TYPE,
                            NULL };

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_slave_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (sd_ctx->search_bases == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No search base is set\n");
        ret = EOK;
        goto immediately;
    }

    state->sd_ctx = sd_ctx;
    state->be_ctx = sd_ctx->be_ctx;
    state->ipa_id_ctx = sd_ctx->ipa_id_ctx;

    subreq = sdap_search_bases_send(state, ev, sd_ctx->sdap_id_ctx->opts, sh,
                                    sd_ctx->search_bases, NULL, false,
                                    0, SUBDOMAINS_FILTER, attrs, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_slave_search_done, req);

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

static errno_t ipa_enable_enterprise_principals(struct be_ctx *be_ctx)
{
    int ret;
    struct sss_domain_info *d;
    TALLOC_CTX *tmp_ctx;
    char **vals = NULL;
    struct dp_module *auth;
    struct krb5_ctx *krb5_auth_ctx;

    d = get_domains_head(be_ctx->domain);

    while (d != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "checking [%s].\n", d->name);
        if (d->upn_suffixes != NULL) {
            break;
        }
        d = get_next_domain(d, SSS_GND_DESCEND);
    }

    if (d == NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "No UPN suffixes found, "
              "no need to enable enterprise principals.\n");
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = confdb_get_param(be_ctx->cdb, tmp_ctx, be_ctx->conf_path,
                     ipa_def_krb5_opts[KRB5_USE_ENTERPRISE_PRINCIPAL].opt_name,
                     &vals);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "confdb_get_param failed.\n");
        goto done;
    }

    if (vals[0]) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Parameter [%s] set in config file and will not be changed.\n",
              ipa_def_krb5_opts[KRB5_USE_ENTERPRISE_PRINCIPAL].opt_name);
        return EOK;
    }

    auth = dp_target_module(be_ctx->provider, DPT_AUTH);
    if (auth == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to find auth proivder.\n");
        ret = EINVAL;
        goto done;
    }

    krb5_auth_ctx = ipa_init_get_krb5_auth_ctx(dp_get_module_data(auth));
    if (krb5_auth_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to find auth proivder data.\n");
        ret = EINVAL;
        goto done;
    }

    ret = dp_opt_set_bool(krb5_auth_ctx->opts,
                          KRB5_USE_ENTERPRISE_PRINCIPAL, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "dp_opt_set_bool failed.\n");
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Enterprise principals enabled.\n");

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static void ipa_subdomains_slave_search_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_slave_state *state;
    struct tevent_req *req;
    struct sysdb_attrs **reply;
    size_t reply_count;
    bool has_changes = false;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_slave_state);

    ret = sdap_search_bases_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get data from LDAP [%d]: %s\n",
                      ret, sss_strerror(ret));
        goto done;
    }

    ret = ipa_subdomains_refresh(state->sd_ctx, reply_count, reply,
                                 &has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to refresh subdomains.\n");
        goto done;
    }

    ret = ipa_enable_enterprise_principals(state->sd_ctx->be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_enable_enterprise_principals failed. "
                                 "Enterprise principals might not work as "
                                 "expected.\n");
    }

    /* If there are no changes this step can be skipped, but
     * ipa_subdomains_update_dom_state() must be called after that in all case
     * to cover existing an newly added domains. Since the domain state is not
     * handled by a domain flag but by the blacklist has_changes does not
     * cover the state. */
    if (has_changes) {
        ret = ipa_subdom_reinit(state->sd_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not reinitialize subdomains\n");
            goto done;
        }
    }

    ipa_subdomains_update_dom_state(state->sd_ctx->be_ctx->domain,
                                    reply_count, reply);

    if (!has_changes || state->sd_ctx->ipa_id_ctx->server_mode == NULL) {
        ret = EOK;
        goto done;
    }

    subreq = ipa_server_create_trusts_send(state, state->be_ctx->ev,
                                           state->be_ctx, state->ipa_id_ctx,
                                           state->be_ctx->domain);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ipa_subdomains_slave_trusts_done, req);
    return;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void ipa_subdomains_slave_trusts_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = ipa_server_create_trusts_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create trusts [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ipa_subdomains_slave_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_subdomains_view_name_state {
    struct ipa_subdomains_ctx *sd_ctx;
};

static void ipa_subdomains_view_name_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_subdomains_view_name_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct ipa_subdomains_ctx *sd_ctx,
                              struct sdap_handle *sh)
{
    struct ipa_subdomains_view_name_state *state;
    struct sdap_attr_map_info *maps;
    struct tevent_req *subreq;
    struct tevent_req *req;
    struct ipa_options *ipa_options;
    const char *filter;
    const char *attrs[] = {IPA_CN, OBJECTCLASS, NULL};
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_view_name_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (sd_ctx->ipa_id_ctx->server_mode != NULL) {
        /* Only get view on clients, on servers it is always 'default'. */
        ret = EOK;
        goto immediately;
    }

    state->sd_ctx = sd_ctx;

    ipa_options = sd_ctx->ipa_id_ctx->ipa_options;

    maps = talloc_zero_array(state, struct sdap_attr_map_info, 2);
    if (maps == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero() failed\n");
        ret = ENOMEM;
        goto immediately;
    }
    maps[0].map = ipa_options->view_map;
    maps->num_attrs = IPA_OPTS_VIEW;

    filter = talloc_asprintf(state, "(&(objectClass=%s)(%s=%s))",
                             ipa_options->id->host_map[SDAP_OC_HOST].name,
                             ipa_options->id->host_map[SDAP_AT_HOST_FQDN].name,
                             dp_opt_get_string(ipa_options->basic, IPA_HOSTNAME));
    if (filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* We add SDAP_DEREF_FLG_SILENT because old IPA servers don't have
     * the attribute we dereference, causing the deref call to fail. */
    subreq = sdap_deref_bases_return_first_send(state, ev,
                 sd_ctx->sdap_id_ctx->opts, sh, sd_ctx->host_search_bases,
                 maps, filter, attrs, IPA_ASSIGNED_ID_VIEW,
                 SDAP_DEREF_FLG_SILENT, 0);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_view_name_done, req);

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

static void ipa_subdomains_view_name_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_view_name_state *state;
    struct tevent_req *req;
    size_t reply_count;
    struct sdap_deref_attrs **reply;
    const char *view_name;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_view_name_state);

    ret = sdap_deref_bases_return_first_recv(subreq, state,
                                             &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* Depending on the version 389ds return a different error code if the
         * search for the view name failed because our dereference attribute
         * ipaAssignedIDView is not known. Newer version return
         * LDAP_UNAVAILABLE_CRITICAL_EXTENSION(12) which is translated to
         * EOPNOTSUPP and older versions return LDAP_PROTOCOL_ERROR(2) which
         * is returned as EIO. In both cases we have to assume that the server
         * is not view aware and keep the view name unset. */
        if (ret == EOPNOTSUPP || ret == EIO) {
            DEBUG(SSSDBG_TRACE_FUNC, "Unable to get view name, looks " \
                                     "like server does not support views.\n");
            ret = EOK;
            goto done;
        }

        DEBUG(SSSDBG_OP_FAILURE, "Unable to get view name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (reply_count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No view found, using default.\n");
        view_name = SYSDB_DEFAULT_VIEW_NAME;
    } else if (reply_count == 1) {
        ret = sysdb_attrs_get_string(reply[0]->attrs, SYSDB_VIEW_NAME,
                                     &view_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one object returned.\n");
        ret = EINVAL;
        goto done;
    }

    ret = ipa_apply_view(state->sd_ctx->be_ctx->domain,
                         state->sd_ctx->ipa_id_ctx, view_name,
                         state->sd_ctx->view_read_at_init,
                         state->sd_ctx->be_ctx->cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set view [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    state->sd_ctx->view_read_at_init = true;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ipa_subdomains_view_name_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_subdomains_view_domain_resolution_order_state {
    struct sss_domain_info *domain;
    const char *view_name;
};

static void
ipa_subdomains_view_domain_resolution_order_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_subdomains_view_domain_resolution_order_send(
                                            TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct ipa_subdomains_ctx *sd_ctx,
                                            struct sdap_handle *sh)
{
    struct ipa_subdomains_view_domain_resolution_order_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char *attrs[] = { IPA_DOMAIN_RESOLUTION_ORDER, NULL };
    char *ldap_basedn;
    char *base;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                    struct ipa_subdomains_view_domain_resolution_order_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->domain = sd_ctx->be_ctx->domain;
    state->view_name = sd_ctx->ipa_id_ctx->view_name;

    ret = domain_to_basedn(state, sd_ctx->be_ctx->domain->name, &ldap_basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "domain_to_basedn failed.\n");
        goto immediately;
    }

    base = talloc_asprintf(state, "cn=%s,cn=views,cn=accounts,%s",
                           sd_ctx->ipa_id_ctx->view_name, ldap_basedn);
    if (base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_get_generic_send(
                            state, ev, sd_ctx->sdap_id_ctx->opts, sh,
                            base, LDAP_SCOPE_BASE, NULL, attrs, NULL, 0,
                            dp_opt_get_int(sd_ctx->sdap_id_ctx->opts->basic,
                                           SDAP_ENUM_SEARCH_TIMEOUT),
                            false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_view_domain_resolution_order_done,
                            req);

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

static void
ipa_subdomains_view_domain_resolution_order_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_view_domain_resolution_order_state *state;
    struct tevent_req *req;
    size_t reply_count;
    struct sysdb_attrs **reply;
    const char *domain_resolution_order;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req,
                    struct ipa_subdomains_view_domain_resolution_order_state);

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get view name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (reply_count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one object returned.\n");
        ret = EINVAL;
        goto done;
    } else if (reply_count == 0) {
        domain_resolution_order = NULL;
    } else {
        /* reply_count == 1 */
        ret = sysdb_attrs_get_string(reply[0], IPA_DOMAIN_RESOLUTION_ORDER,
                                     &domain_resolution_order);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to get the view domains' resolution order "
                  "configuration value for view [%s] [%d]: %s\n",
                  state->view_name, ret, sss_strerror(ret));
            goto done;
        } else if (ret == ENOENT) {
            domain_resolution_order = NULL;
        }
    }

    ret = sysdb_update_view_domain_resolution_order(state->domain->sysdb,
                                                    domain_resolution_order);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_update_view_domain_resolution_order() [%d]: [%s].\n",
              ret, sss_strerror(ret));
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

static errno_t
ipa_subdomains_view_domain_resolution_order_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_domain_resolution_order_state {
    struct sss_domain_info *domain;
};

static void ipa_domain_resolution_order_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_domain_resolution_order_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct ipa_subdomains_ctx *sd_ctx,
                                 struct sdap_handle *sh)
{
    struct ipa_domain_resolution_order_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char *attrs[] = {IPA_DOMAIN_RESOLUTION_ORDER, NULL};
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_domain_resolution_order_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->domain = sd_ctx->be_ctx->domain;

    subreq = ipa_get_config_send(state, ev, sh, sd_ctx->sdap_id_ctx->opts,
                                 state->domain->name, attrs, NULL, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    } else {
        tevent_req_set_callback(subreq, ipa_domain_resolution_order_done, req);
    }

    return req;
}

static void ipa_domain_resolution_order_done(struct tevent_req *subreq)
{
    struct ipa_domain_resolution_order_state *state;
    struct tevent_req *req;
    struct sysdb_attrs *config = NULL;
    const char *domain_resolution_order = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_domain_resolution_order_state);

    ret = ipa_get_config_recv(subreq, state, &config);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Failed to get the domains' resolution order configuration "
              "from the server [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (config != NULL) {
        ret = sysdb_attrs_get_string(config, IPA_DOMAIN_RESOLUTION_ORDER,
                                     &domain_resolution_order);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "Failed to get the domains' resolution order configuration "
                  "value [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        } else if (ret == ENOENT) {
            domain_resolution_order = NULL;
        }
    }

    ret = sysdb_domain_update_domain_resolution_order(
                        state->domain->sysdb, state->domain->name,
                        domain_resolution_order);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_domain_update_resolution_order() [%d]: [%s].\n",
              ret, sss_strerror(ret));
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

static errno_t ipa_domain_resolution_order_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct kdcinfo_from_server_list_state {
    struct resolv_hostport *hostport_list;
    enum host_database db[2];

    struct resolv_hostport_addr **rhp_addrs;
    size_t rhp_len;
};

static void kdcinfo_from_server_list_done(struct tevent_req *subreq);

static struct tevent_req *
kdcinfo_from_server_list_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct be_resolv_ctx *be_res,
                              const char *servers)
{
    struct kdcinfo_from_server_list_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;
    int server_list_len;
    char **server_list;

    req = tevent_req_create(mem_ctx, &state,
                            struct kdcinfo_from_server_list_state);
    if (req == NULL) {
        return NULL;
    }
    state->db[0] = DB_DNS;
    state->db[1] = DB_SENTINEL;

    if (servers == NULL) {
        ret = EOK;
        goto immediately;
    }

    ret = split_on_separator(state, servers, ',', true, true,
                             &server_list,
                             &server_list_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to parse server list!\n");
        goto immediately;
    }

    state->hostport_list = talloc_array(state,
                                        struct resolv_hostport,
                                        server_list_len);
    if (state->hostport_list == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    for (int i = 0; i < server_list_len; i++) {
        state->hostport_list[i].host = server_list[i];
        state->hostport_list[i].port = 0;
    }

    subreq = resolv_hostport_list_send(state,
                                       ev,
                                       be_res->resolv,
                                       state->hostport_list,
                                       server_list_len,
                                       0,
                                       be_res->family_order,
                                       state->db);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, kdcinfo_from_server_list_done, req);
    return req;

immediately:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

static void kdcinfo_from_server_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct kdcinfo_from_server_list_state *state = tevent_req_data(req,
                                        struct kdcinfo_from_server_list_state);

    ret = resolv_hostport_list_recv(subreq,
                                    state,
                                    &state->rhp_len,
                                    &state->rhp_addrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to resolve address list [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t kdcinfo_from_server_list_recv(TALLOC_CTX *mem_ctx,
                                             struct tevent_req *req,
                                             struct resolv_hostport_addr ***_rhp_addrs,
                                             size_t *_rhp_len)
{
    struct kdcinfo_from_server_list_state *state = tevent_req_data(req,
                                        struct kdcinfo_from_server_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_rhp_addrs != NULL) {
        *_rhp_addrs = talloc_steal(mem_ctx, state->rhp_addrs);
    }

    if (_rhp_len != NULL) {
        *_rhp_len = state->rhp_len;
    }

    return EOK;
}

struct kdcinfo_from_site_state {
    struct tevent_context *ev;
    struct be_resolv_ctx *be_res;

    const char *discovery_domains[2];
    struct resolv_hostport *hostport_list;
    enum host_database db[2];

    struct resolv_hostport_addr **rhp_addrs;
    size_t rhp_len;
};

static void kdcinfo_from_site_srv_done(struct tevent_req *subreq);
static void kdcinfo_from_site_server_list_done(struct tevent_req *subreq);

static struct tevent_req *
kdcinfo_from_site_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct be_resolv_ctx *be_res,
                       const char *site,
                       const char *domain)
{
    struct kdcinfo_from_site_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct kdcinfo_from_site_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->be_res = be_res;
    state->db[0] = DB_DNS;
    state->db[1] = DB_SENTINEL;

    state->discovery_domains[0] = ad_site_dns_discovery_domain(state,
                                                               site,
                                                               domain);
    if (state->discovery_domains[0] == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    state->discovery_domains[1] = NULL;

    subreq = fo_discover_srv_send(state,
                                  state->ev,
                                  state->be_res->resolv,
                                  "kerberos", "tcp",
                                  state->discovery_domains);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, kdcinfo_from_site_srv_done, req);
    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kdcinfo_from_site_srv_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct kdcinfo_from_site_state *state = tevent_req_data(req,
                                        struct kdcinfo_from_site_state);
    struct fo_server_info *servers;
    size_t num_servers;

    ret = fo_discover_srv_recv(state, subreq,
                               NULL, NULL, /* not interested in TTL etc */
                               &servers, &num_servers);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not resolve the site [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->hostport_list = talloc_array(state,
                                        struct resolv_hostport,
                                        num_servers);
    if (state->hostport_list == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    for (size_t i = 0; i < num_servers; i++) {
        state->hostport_list[i].host = servers[i].host;
        state->hostport_list[i].port = servers[i].port;
    }

    subreq = resolv_hostport_list_send(state,
                                       state->ev,
                                       state->be_res->resolv,
                                       state->hostport_list,
                                       num_servers,
                                       MAX_SERVERS_FROM_SRV,
                                       state->be_res->family_order,
                                       state->db);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kdcinfo_from_site_server_list_done, req);
}

static void kdcinfo_from_site_server_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct kdcinfo_from_site_state *state = tevent_req_data(req,
                                        struct kdcinfo_from_site_state);

    ret = resolv_hostport_list_recv(subreq,
                                    state,
                                    &state->rhp_len,
                                    &state->rhp_addrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to resolve address list [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}


static errno_t kdcinfo_from_site_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct resolv_hostport_addr ***_rhp_addrs,
                                      size_t *_rhp_len)
{
    struct kdcinfo_from_site_state *state = tevent_req_data(req,
                                        struct kdcinfo_from_site_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_rhp_addrs != NULL) {
        *_rhp_addrs = talloc_steal(mem_ctx, state->rhp_addrs);
    }

    if (_rhp_len != NULL) {
        *_rhp_len = state->rhp_len;
    }

    return EOK;
}

/* Anything per-domain in this request goes here so that we
 * can just free the whole struct without mixing data from
 * different domains or the overhead of another request
 */
struct ipa_sd_per_dom_kdcinfo_ctx {
    struct sss_domain_info *dom;

    const char *servers;
    const char *site;

    const char *discovery_domains[2];
    struct krb5_service *krb5_service;
};

struct ipa_subdomains_write_kdcinfo_state {
    struct tevent_context *ev;
    struct ipa_subdomains_ctx *ipa_sd_ctx;
    struct be_ctx *be_ctx;

    bool use_kdcinfo;
    struct ipa_sd_per_dom_kdcinfo_ctx *pdctx;
};

static errno_t ipa_subdomains_write_kdcinfo_domain_step(struct sss_domain_info *start_dom,
                                                        struct tevent_req *req);
static void ipa_subdomains_write_kdcinfo_domain_done(struct tevent_req *subreq);
static errno_t ipa_subdomains_write_kdcinfo_write_step(struct sss_domain_info *dom,
                                                       struct krb5_service *krb5_service,
                                                       struct resolv_hostport_addr **rhp_addrs,
                                                       size_t rhp_len);

static struct tevent_req *
ipa_subdomains_write_kdcinfo_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct ipa_subdomains_ctx *ipa_sd_ctx,
                                  struct be_ctx *be_ctx)
{
    struct ipa_subdomains_write_kdcinfo_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_write_kdcinfo_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->ipa_sd_ctx = ipa_sd_ctx;
    state->be_ctx = be_ctx;

    if (ipa_sd_ctx->ipa_id_ctx->server_mode != NULL) {
        /* This request is valid for clients only */
        ret = EOK;
        goto immediately;
    }

    state->use_kdcinfo = dp_opt_get_bool(ipa_sd_ctx->ipa_id_ctx->ipa_options->auth,
                                         KRB5_USE_KDCINFO);
    if (state->use_kdcinfo == false) {
        DEBUG(SSSDBG_CONF_SETTINGS, "kdcinfo creation disabled\n");
        ret = EOK;
        goto immediately;
    }

    if (be_ctx->domain->subdomains == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "No subdomains, done\n");
        ret = EOK;
        goto immediately;
    }

    ret = ipa_subdomains_write_kdcinfo_domain_step(be_ctx->domain->subdomains,
                                                   req);
    if (ret != EAGAIN) {
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

static errno_t ipa_subdomains_write_kdcinfo_domain_step(struct sss_domain_info *start_dom,
                                                        struct tevent_req *req)
{
    struct ipa_subdomains_write_kdcinfo_state *state = \
                tevent_req_data(req,
                                struct ipa_subdomains_write_kdcinfo_state);
    struct dp_option *ipa_ad_subdom_opts;
    struct tevent_req *subreq = NULL;
    char *subdom_conf_path;
    errno_t ret;
    const char *servers;
    const char *site;

    for (struct sss_domain_info *dom = start_dom;
            dom != NULL;
            dom = get_next_domain(dom, 0)) {

        talloc_zfree(state->pdctx);

        subdom_conf_path = subdomain_create_conf_path(state, dom);
        if (subdom_conf_path == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "subdom_conf_path failed for %s\n", dom->name);
            /* Not fatal */
            continue;
        }

        ret = dp_get_options(state, state->be_ctx->cdb,
                             subdom_conf_path,
                             ipa_cli_ad_subdom_opts,
                             IPA_OPTS_CLI_AD_SUBDOM,
                             &ipa_ad_subdom_opts);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot get options for %s: [%d]: %s\n",
                  dom->name, ret, sss_strerror(ret));
            /* Not fatal */
            continue;
        }

        servers = dp_opt_get_string(ipa_ad_subdom_opts, IPA_CLI_AD_SERVER);
        site = dp_opt_get_string(ipa_ad_subdom_opts, IPA_CLI_AD_SITE);

        if (servers == NULL && site == NULL) {
            /* If neither is set, just go to the next domain */
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "No site or server defined for %s, skipping\n",
                  dom->name);
            continue;
        }

        /* We will resolve this domain, create a per-domain context */
        state->pdctx = talloc_zero(state, struct ipa_sd_per_dom_kdcinfo_ctx);
        if (state->pdctx == NULL) {
            return ENOMEM;
        }
        state->pdctx->dom = dom;
        state->pdctx->servers = servers;
        state->pdctx->site = site;
        state->pdctx->krb5_service = ipa_subdom_get_k5_svc(state->ipa_sd_ctx,
                                                           dom,
                                                           state->use_kdcinfo);
        if (state->pdctx->krb5_service == NULL) {
            continue;
        }

        if (state->pdctx->servers != NULL) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Resolving servers [%s] for domain %s\n",
                  state->pdctx->servers, dom->name);

            subreq = kdcinfo_from_server_list_send(state,
                                                   state->ev,
                                                   state->be_ctx->be_res,
                                                   state->pdctx->servers);
        } else if (state->pdctx->site != NULL) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Resolving site %s for domain %s\n",
                  state->pdctx->site, dom->name);

            subreq = kdcinfo_from_site_send(state,
                                            state->ev,
                                            state->be_ctx->be_res,
                                            state->pdctx->site,
                                            state->pdctx->dom->name);
        } else {
            /* We should never get here */
            return EINVAL;
        }

        if (subreq == NULL) {
            return ENOMEM;
        }
        tevent_req_set_callback(subreq, ipa_subdomains_write_kdcinfo_domain_done, req);
        return EAGAIN;
    }

    return EOK;
}

static void ipa_subdomains_write_kdcinfo_domain_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_subdomains_write_kdcinfo_state *state = \
                tevent_req_data(req,
                                struct ipa_subdomains_write_kdcinfo_state);
    struct sss_domain_info *next_domain;
    struct resolv_hostport_addr **rhp_addrs = NULL;
    size_t rhp_len = 0;

    if (state->pdctx->servers != NULL) {
        ret = kdcinfo_from_server_list_recv(state->pdctx, subreq,
                                            &rhp_addrs, &rhp_len);
    } else if (state->pdctx->site != NULL) {
        ret = kdcinfo_from_site_recv(state->pdctx, subreq,
                                     &rhp_addrs, &rhp_len);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Neither site nor servers set\n");
        ret = EINVAL;
    }

    if (ret == EOK) {
        ret = ipa_subdomains_write_kdcinfo_write_step(state->pdctx->dom,
                                                      state->pdctx->krb5_service,
                                                      rhp_addrs, rhp_len);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not write kdcinfo file for %s\n", state->pdctx->dom->name);
            /* Not fatal, loop to the next domain below */
        }
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not get address list for %s\n", state->pdctx->dom->name);
        /* Not fatal, loop to the next domain below */
    }

    next_domain = get_next_domain(state->pdctx->dom, 0);
    ret = ipa_subdomains_write_kdcinfo_domain_step(next_domain, req);
    if (ret == EOK) {
        tevent_req_done(req);
        return;
    } else if (ret != EAGAIN) {
        /* the loop in ipa_subdomains_write_kdcinfo_domain_step already
         * tries to be quite permissive, so any error is fatal
         */
        tevent_req_error(req, ret);
        return;
    }

    /* Continue to the next domain */
}

static errno_t ipa_subdomains_write_kdcinfo_write_step(struct sss_domain_info *dom,
                                                       struct krb5_service *krb5_service,
                                                       struct resolv_hostport_addr **rhp_addrs,
                                                       size_t rhp_len)
{
    errno_t ret;
    char *address = NULL;
    char *safe_address = NULL;
    const char **safe_addr_list;
    int addr_index = 0;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    safe_addr_list = talloc_zero_array(tmp_ctx, const char *, rhp_len+1);
    if (safe_addr_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (size_t i = 0; i < rhp_len; i++) {
        address = resolv_get_string_address(tmp_ctx, rhp_addrs[i]->reply);
        if (address == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "resolv_get_string_address failed.\n");
            continue;
        }

        if (rhp_addrs[i]->origin.port != 0) {
            address = talloc_asprintf_append(address,
                                             ":%d",
                                             rhp_addrs[i]->origin.port);
        }

        safe_address = sss_escape_ip_address(tmp_ctx,
                                             rhp_addrs[i]->reply->family,
                                             address);
        talloc_zfree(address);
        if (safe_address == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_escape_ip_address failed.\n");
            continue;
        }

        DEBUG(SSSDBG_CONF_SETTINGS,
              "Will write [%s] for %s\n",
              safe_address, dom->name);

        safe_addr_list[addr_index] = talloc_steal(safe_addr_list,
                                                  safe_address);
        addr_index++;
    }

    ret = write_krb5info_file(krb5_service,
                              safe_addr_list,
                              SSS_KRB5KDC_FO_SRV);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "write to %s/kdcinfo.%s failed, authentication might fail.\n",
              PUBCONF_PATH, krb5_service->realm);
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t ipa_subdomains_write_kdcinfo_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ipa_subdomains_refresh_state {
    struct tevent_context *ev;
    struct ipa_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;
};

static errno_t ipa_subdomains_refresh_retry(struct tevent_req *req);
static void ipa_subdomains_refresh_connect_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_ranges_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_certmap_done(struct tevent_req *subreq);
#ifdef BUILD_PASSKEY
static void ipa_subdomains_refresh_passkey_done(struct tevent_req *subreq);
#endif /* BUILD_PASSKEY */
static void ipa_subdomains_refresh_master_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_slave_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_view_name_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_view_domain_resolution_order_done(
                                                    struct tevent_req *subreq);
static void ipa_domain_refresh_resolution_order_done(struct tevent_req *subreq);
static void ipa_domain_refresh_kdcinfo_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_subdomains_refresh_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct ipa_subdomains_ctx *sd_ctx)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->sd_ctx = sd_ctx;

    state->sdap_op = sdap_id_op_create(state,
                                       sd_ctx->sdap_id_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    ret = ipa_subdomains_refresh_retry(req);
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

static errno_t ipa_subdomains_refresh_retry(struct tevent_req *req)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_refresh_connect_done, req);

    return EAGAIN;
}

static void ipa_subdomains_refresh_connect_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to LDAP "
              "[%d]: %s\n", ret, sss_strerror(ret));
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE, "No IPA server is available, "
                  "cannot get the subdomain list while offline\n");
            ret = ERR_OFFLINE;
        }
        tevent_req_error(req, ret);
        return;
    }

    subreq = ipa_subdomains_ranges_send(state, state->ev, state->sd_ctx,
                                        sdap_id_op_handle(state->sdap_op));
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_refresh_ranges_done, req);
    return;
}

static void ipa_subdomains_refresh_ranges_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = ipa_subdomains_ranges_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get IPA ranges "
              "[%d]: %s\n", ret, sss_strerror(ret));
        /* Not good, but let's try to continue with other server side options */
    }

    subreq = ipa_subdomains_certmap_send(state, state->ev, state->sd_ctx,
                                         sdap_id_op_handle(state->sdap_op));
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_refresh_certmap_done, req);
    return;
}

static void ipa_subdomains_refresh_certmap_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = ipa_subdomains_certmap_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to read certificate mapping rules "
              "[%d]: %s\n", ret, sss_strerror(ret));
        /* Not good, but let's try to continue with other server side options */
    }

#ifdef BUILD_PASSKEY
    subreq = ipa_subdomains_passkey_send(state, state->ev, state->sd_ctx,
                                         sdap_id_op_handle(state->sdap_op));
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_refresh_passkey_done, req);
    return;
}

static void ipa_subdomains_refresh_passkey_done(struct tevent_req *subreq)
{

    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = ipa_subdomains_passkey_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to get passkey configuration "
              "[%d]: %s\n", ret, sss_strerror(ret));
        /* Not good, but let's try to continue with other server side options */
        DEBUG(SSSDBG_IMPORTANT_INFO, "Passkey feature is not configured "
                                     "on IPA server\n");
    }
#endif /* BUILD_PASSKEY */

    subreq = ipa_subdomains_master_send(state, state->ev, state->sd_ctx,
                                        sdap_id_op_handle(state->sdap_op));
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_refresh_master_done, req);
    return;
}

static void ipa_subdomains_refresh_master_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = ipa_subdomains_master_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get master domain "
              "[%d]: %s\n", ret, sss_strerror(ret));
        /* Not good, but let's try to continue with other server side options */
    }

    subreq = ipa_subdomains_slave_send(state, state->ev, state->sd_ctx,
                                       sdap_id_op_handle(state->sdap_op));
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_refresh_slave_done, req);
    return;
}

static void ipa_subdomains_refresh_slave_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = ipa_subdomains_slave_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get subdomains "
              "[%d]: %s\n", ret, sss_strerror(ret));
        /* Not good, but let's try to continue with other server side options */
    }

    subreq = ipa_subdomains_view_name_send(state, state->ev, state->sd_ctx,
                                           sdap_id_op_handle(state->sdap_op));
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_refresh_view_name_done,
                            req);
    return;
}

static void ipa_subdomains_refresh_view_name_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = ipa_subdomains_view_name_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to get view name [%d]: %s\n",
              ret, sss_strerror(ret));
        /* Not good, but let's try to continue with other server side options */
    }

    subreq = ipa_subdomains_view_domain_resolution_order_send(
                                            state,
                                            state->ev,
                                            state->sd_ctx,
                                            sdap_id_op_handle(state->sdap_op));
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq,
                    ipa_subdomains_refresh_view_domain_resolution_order_done,
                    req);
}

static void
ipa_subdomains_refresh_view_domain_resolution_order_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = ipa_subdomains_view_domain_resolution_order_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to get view domain_resolution order [%d]: %s\n",
              ret, sss_strerror(ret));
        /* Not good, but let's try to continue with other server side options */
    }

    subreq = ipa_domain_resolution_order_send(state, state->ev, state->sd_ctx,
                                            sdap_id_op_handle(state->sdap_op));
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq,
                            ipa_domain_refresh_resolution_order_done,
                            req);
}

static void
ipa_domain_refresh_resolution_order_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_refresh_state *state;
    struct tevent_req *req;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_refresh_state);

    ret = ipa_domain_resolution_order_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Unable to get the domains order resolution [%d]: %s\n",
              ret, sss_strerror(ret));
        /* Not good, but let's try to continue with other server side options */
    }

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ipa_subdomains_refresh_retry(req);
    } else if (dp_error == DP_ERR_OFFLINE) {
        ret = ERR_OFFLINE;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Unable to refresh subdomains [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = ipa_subdomains_write_kdcinfo_send(state,
                                               state->ev,
                                               state->sd_ctx,
                                               state->sd_ctx->be_ctx);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ipa_domain_refresh_kdcinfo_done, req);
}

static void
ipa_domain_refresh_kdcinfo_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = ipa_subdomains_write_kdcinfo_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Unable to write the kdc info files, authentication might "
              "fail or time out [%d]: %s\n",
              ret, sss_strerror(ret));
        /* Not fatal, let's hope DNS is set correctly */
    }

    tevent_req_done(req);
}

static errno_t ipa_subdomains_refresh_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_subdomains_handler_state {
    struct dp_reply_std reply;
};

static void ipa_subdomains_handler_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_subdomains_handler_send(TALLOC_CTX *mem_ctx,
                            struct ipa_subdomains_ctx *sd_ctx,
                            struct dp_subdomains_data *data,
                            struct dp_req_params *params)
{
    struct ipa_subdomains_handler_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }


    if (sd_ctx->last_refreshed > time(NULL) - IPA_SUBDOMAIN_REFRESH_LIMIT) {
        DEBUG(SSSDBG_TRACE_FUNC, "Subdomains were recently refreshed, "
              "nothing to do\n");
        ret = EOK;
        goto immediately;
    }

    subreq = ipa_subdomains_refresh_send(state, params->ev, sd_ctx);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void ipa_subdomains_handler_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_handler_state);

    ret = ipa_subdomains_refresh_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to refresh subdomains [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);
    tevent_req_done(req);
}

static errno_t ipa_subdomains_handler_recv(TALLOC_CTX *mem_ctx,
                                           struct tevent_req *req,
                                           struct dp_reply_std *data)
{
   struct ipa_subdomains_handler_state *state;

   state = tevent_req_data(req, struct ipa_subdomains_handler_state);

   TEVENT_REQ_RETURN_ON_ERROR(req);

   *data = state->reply;

   return EOK;
}

static struct tevent_req *
ipa_subdomains_ptask_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct be_ctx *be_ctx,
                          struct be_ptask *be_ptask,
                          void *pvt)
{
    struct ipa_subdomains_ctx *sd_ctx;
    sd_ctx = talloc_get_type(pvt, struct ipa_subdomains_ctx);

    return ipa_subdomains_refresh_send(mem_ctx, ev, sd_ctx);
}

static errno_t
ipa_subdomains_ptask_recv(struct tevent_req *req)
{
    return ipa_subdomains_refresh_recv(req);
}

errno_t ipa_subdomains_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            struct ipa_id_ctx *ipa_id_ctx,
                            struct dp_method *dp_methods)
{
    struct ipa_subdomains_ctx *sd_ctx;
    struct ipa_options *ipa_options;
    time_t period;
    time_t offset;
    errno_t ret;
    /* Delay the first ptask that refreshes the trusted domains so that a race between
     * the first responder-induced request and the ptask doesn't cause issues, see
     * also upstream ticket #3601
     */
    const time_t ptask_first_delay = 600;

    ipa_options = ipa_id_ctx->ipa_options;

    sd_ctx = talloc_zero(mem_ctx, struct ipa_subdomains_ctx);
    if (sd_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    sd_ctx->be_ctx = be_ctx;
    sd_ctx->ipa_id_ctx = ipa_id_ctx;
    sd_ctx->sdap_id_ctx = ipa_id_ctx->sdap_id_ctx;
    sd_ctx->search_bases = ipa_options->subdomains_search_bases;
    sd_ctx->master_search_bases = ipa_options->master_domain_search_bases;
    sd_ctx->ranges_search_bases = ipa_options->ranges_search_bases;
    sd_ctx->host_search_bases = ipa_options->id->sdom->host_search_bases;

    dp_set_method(dp_methods, DPM_DOMAINS_HANDLER,
                  ipa_subdomains_handler_send, ipa_subdomains_handler_recv, sd_ctx,
                  struct ipa_subdomains_ctx, struct dp_subdomains_data, struct dp_reply_std);

    period = be_ctx->domain->subdomain_refresh_interval;
    offset = be_ctx->domain->subdomain_refresh_interval_offset;
    ret = be_ptask_create(sd_ctx, be_ctx, period, ptask_first_delay, 0, offset,
                          period, 0,
                          ipa_subdomains_ptask_send, ipa_subdomains_ptask_recv, sd_ctx,
                          "Subdomains Refresh",
                          BE_PTASK_OFFLINE_DISABLE |
                          BE_PTASK_SCHEDULE_FROM_LAST,
                          NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup ptask "
              "[%d]: %s\n", ret, sss_strerror(ret));
        /* Ignore, responders will trigger refresh from time to time. */
    }

    ret = ipa_subdom_reinit(sd_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not reinitialize subdomains. "
              "Users from trusted domains might not be resolved correctly\n");
        /* Ignore this error and try to discover the subdomains later */
    }

    ret = ipa_trusted_subdom_init(be_ctx, ipa_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ipa_trusted_subdom_init() failed.\n");
        return ret;
    }

    return EOK;
}
