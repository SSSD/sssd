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

#include <ctype.h>

#define SUBDOMAINS_FILTER "objectclass=ipaNTTrustedDomain"
#define MASTER_DOMAIN_FILTER "objectclass=ipaNTDomainAttrs"
#define RANGE_FILTER "objectclass=ipaIDRange"

#define IPA_CN "cn"
#define IPA_FLATNAME "ipaNTFlatName"
#define IPA_SID "ipaNTSecurityIdentifier"
#define IPA_TRUSTED_DOMAIN_SID "ipaNTTrustedDomainSID"
#define IPA_RANGE_TYPE "ipaRangeType"
#define IPA_ADDITIONAL_SUFFIXES "ipaNTAdditionalSuffixes"

#define IPA_BASE_ID "ipaBaseID"
#define IPA_ID_RANGE_SIZE "ipaIDRangeSize"
#define IPA_BASE_RID "ipaBaseRID"
#define IPA_SECONDARY_BASE_RID "ipaSecondaryBaseRID"
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

#define OBJECTCLASS "objectClass"

#define CERTMAP_FILTER "(|(&("OBJECTCLASS"="IPA_OC_CERTMAP_RULE")" \
                              "("IPA_ENABLED_FLAG"="IPA_TRUE_VALUE"))" \
                          "("OBJECTCLASS"="IPA_OC_CERTMAP_CONFIG_OBJECT"))"


struct ipa_subdomains_ctx {
    struct be_ctx *be_ctx;
    struct ipa_id_ctx *ipa_id_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_search_base **search_bases;
    struct sdap_search_base **master_search_bases;
    struct sdap_search_base **ranges_search_bases;
    struct sdap_search_base **host_search_bases;

    time_t last_refreshed;
    bool view_read_at_init;
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
                          canonicalize);
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

static errno_t ipa_ranges_parse_results(TALLOC_CTX *mem_ctx,
                                        char *domain_name,
                                        size_t count,
                                        struct sysdb_attrs **reply,
                                        struct range_info ***_range_list)
{
    struct range_info **range_list = NULL;
    struct range_info *r;
    const char *value;
    size_t c;
    size_t d;
    int ret;
    enum idmap_error_code err;
    char *name1;
    char *name2;
    char *sid1;
    char *sid2;
    uint32_t rid1;
    uint32_t rid2;
    struct sss_idmap_range range1;
    struct sss_idmap_range range2;
    bool mapping1;
    bool mapping2;

    range_list = talloc_array(mem_ctx, struct range_info *, count + 1);
    if (range_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    for (c = 0; c < count; c++) {
        r = talloc_zero(range_list, struct range_info);
        if (r == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        r->name = talloc_strdup(r, value);
        if (r->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_TRUSTED_DOMAIN_SID, &value);
        if (ret == EOK) {
            r->trusted_dom_sid = talloc_strdup(r, value);
            if (r->trusted_dom_sid == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_BASE_ID,
                                       &r->base_id);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_ID_RANGE_SIZE,
                                       &r->id_range_size);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_BASE_RID,
                                       &r->base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_SECONDARY_BASE_RID,
                                       &r->secondary_base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_RANGE_TYPE, &value);
        if (ret == EOK) {
            r->range_type = talloc_strdup(r, value);
            if (r->range_type == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        } else if (ret == ENOENT) {
            /* Older IPA servers might not have the range_type attribute, but
             * only support local ranges and trusts with algorithmic mapping. */
            if (r->trusted_dom_sid == NULL) {
                r->range_type = talloc_strdup(r, IPA_RANGE_LOCAL);
            } else {
                r->range_type = talloc_strdup(r, IPA_RANGE_AD_TRUST);
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
        if (r->range_type == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = get_idmap_data_from_range(r, domain_name, &name1, &sid1, &rid1,
                                        &range1, &mapping1);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_idmap_data_from_range failed.\n");
            goto done;
        }
        for (d = 0; d < c; d++) {
            ret = get_idmap_data_from_range(range_list[d], domain_name, &name2,
                                            &sid2, &rid2, &range2, &mapping2);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "get_idmap_data_from_range failed.\n");
                goto done;
            }

            err = sss_idmap_check_collision_ex(name1, sid1, &range1, rid1,
                                               r->name, mapping1,
                                               name2, sid2, &range2, rid2,
                                               range_list[d]->name, mapping2);
            if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Collision of ranges [%s] and [%s] detected.\n",
                      r->name, range_list[d]->name);
                ret = EINVAL;
                goto done;
            }
        }

        range_list[c] = r;
    }

    range_list[c] = NULL;

    *_range_list = range_list;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(range_list);
    }

    return ret;
}

struct priv_sss_debug {
    int level;
};

void ext_debug(void *private, const char *file, long line, const char *function,
               const char *format, ...)
{
    va_list ap;
    struct priv_sss_debug *data = private;
    int level = SSSDBG_OP_FAILURE;

    if (data != NULL) {
        level = data->level;
    }

    if (DEBUG_IS_SET(level)) {
        va_start(ap, format);
        sss_vdebug_fn(file, line, function, level, APPEND_LINE_FEED,
                      format, ap);
        va_end(ap);
    }
}

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
    struct sss_certmap_ctx *certmap_ctx = NULL;
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

    ret = sss_certmap_init(mem_ctx, ext_debug, NULL, &certmap_ctx);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_certmap_init failed.\n");
        goto done;
    }

    for (c = 0; certmap_list[c] != NULL; c++) {
        DEBUG(SSSDBG_TRACE_ALL, "Trying to add rule [%s][%d][%s][%s].\n",
                                certmap_list[c]->name,
                                certmap_list[c]->priority,
                                certmap_list[c]->match_rule,
                                certmap_list[c]->map_rule);

        ret = sss_certmap_add_rule(certmap_ctx, certmap_list[c]->priority,
                                   certmap_list[c]->match_rule,
                                   certmap_list[c]->map_rule,
                                   certmap_list[c]->domains);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_certmap_add_rule failed for rule [%s], skipping. "
                  "Please check for typos and if rule syntax is supported.\n",
                  certmap_list[c]->name);
            goto done;
        }
    }

    ret = sysdb_update_certmap(domain->sysdb, certmap_list, user_name_hint);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_update_certmap failed");
        goto done;
    }

    sss_certmap_free_ctx(sdap_opts->certmap_ctx);
    sdap_opts->certmap_ctx = talloc_steal(sdap_opts, certmap_ctx);

    if (_certmap_list != NULL) {
        *_certmap_list = certmap_list;
    }
    ret = EOK;

done:
    talloc_free(ocs);
    if (ret != EOK) {
        sss_certmap_free_ctx(certmap_ctx);
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

static errno_t ipa_subdom_store(struct sss_domain_info *parent,
                                struct ipa_id_ctx *id_ctx,
                                struct sdap_idmap_ctx *sdap_idmap_ctx,
                                struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    char *realm;
    const char *flat;
    const char *id;
    char *forest = NULL;
    int ret;
    bool mpg;
    bool enumerate;
    uint32_t direction;
    struct ldb_message_element *alternative_domain_suffixes = NULL;

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

    mpg = sdap_idmap_domain_has_algorithmic_mapping(sdap_idmap_ctx, name, id);

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

    if (id_ctx->server_mode != NULL) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Trust type of [%s]: %s\n", name, ipa_trust_dir2str(direction));
    }

    ret = sysdb_subdomain_store(parent->sysdb, name, realm, flat,
                                id, mpg, enumerate, forest,
                                direction, alternative_domain_suffixes);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_subdomain_store failed.\n");
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
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

            /* Remove the AD ID ctx from the list of LDAP domains */
            ipa_ad_subdom_remove(ctx->be_ctx, ctx->ipa_id_ctx, dom);
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
        /* refresh view data of all domains at startup */
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
                            IPA_RANGE_TYPE, NULL };

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
                                    0, RANGE_FILTER, attrs);
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
            && domain->realm != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Master record is up to date.\n");
        ret = EOK;
        goto immediately;
    }

    subreq = sdap_search_bases_return_first_send(state, ev,
                                     sd_ctx->sdap_id_ctx->opts, sh,
                                     sd_ctx->master_search_bases, NULL, false,
                                     0, MASTER_DOMAIN_FILTER, attrs);
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

    ret = sysdb_master_domain_add_info(state->domain, realm, flat, id, NULL,
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
                                    0, SUBDOMAINS_FILTER, attrs);
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

    if (!has_changes) {
        ret = EOK;
        goto done;
    }

    ret = ipa_subdom_reinit(state->sd_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not reinitialize subdomains\n");
        goto done;
    }

    if (state->sd_ctx->ipa_id_ctx->server_mode == NULL) {
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
                        ipa_options->host_map[IPA_OC_HOST].name,
                        ipa_options->host_map[IPA_AT_HOST_FQDN].name,
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
                                 state->domain->name, attrs);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_domain_resolution_order_done, req);

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
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get the domains' resolution order configuration "
              "from the server [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (config != NULL) {
        ret = sysdb_attrs_get_string(config, IPA_DOMAIN_RESOLUTION_ORDER,
                                     &domain_resolution_order);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
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

struct ipa_subdomains_refresh_state {
    struct tevent_context *ev;
    struct ipa_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;
};

static errno_t ipa_subdomains_refresh_retry(struct tevent_req *req);
static void ipa_subdomains_refresh_connect_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_ranges_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_certmap_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_master_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_slave_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_view_name_done(struct tevent_req *subreq);
static void ipa_subdomains_refresh_view_domain_resolution_order_done(
                                                    struct tevent_req *subreq);
static void ipa_domain_refresh_resolution_order_done(struct tevent_req *subreq);

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
        tevent_req_error(req, ret);
        return;
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
        tevent_req_error(req, ret);
        return;
    }

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
        tevent_req_error(req, ret);
        return;
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
        tevent_req_error(req, ret);
        return;
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
        tevent_req_error(req, ret);
        return;
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
        tevent_req_error(req, ret);
        return;
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
        tevent_req_error(req, ret);
        return;
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
    errno_t ret;

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
    sd_ctx->host_search_bases = ipa_options->host_search_bases;

    dp_set_method(dp_methods, DPM_DOMAINS_HANDLER,
                  ipa_subdomains_handler_send, ipa_subdomains_handler_recv, sd_ctx,
                  struct ipa_subdomains_ctx, struct dp_subdomains_data, struct dp_reply_std);

    period = be_ctx->domain->subdomain_refresh_interval;
    ret = be_ptask_create(sd_ctx, be_ctx, period, 0, 0, 0, period,
                          BE_PTASK_OFFLINE_DISABLE, 0,
                          ipa_subdomains_ptask_send, ipa_subdomains_ptask_recv, sd_ctx,
                          "Subdomains Refresh", NULL);
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

    ret = ipa_ad_subdom_init(be_ctx, ipa_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ipa_ad_subdom_init() failed.\n");
        return ret;
    }

    return EOK;
}
