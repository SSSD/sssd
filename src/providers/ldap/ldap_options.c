/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2008-2010 Red Hat

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

#include "providers/ldap/ldap_common.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ldap/sdap_async_private.h"
#include "util/crypto/sss_crypto.h"

int ldap_get_options(TALLOC_CTX *memctx,
                     struct sss_domain_info *dom,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct data_provider *dp,
                     struct sdap_options **_opts)
{
    struct sdap_attr_map *default_attr_map;
    struct sdap_attr_map *default_user_map;
    struct sdap_attr_map *default_group_map;
    struct sdap_attr_map *default_netgroup_map;
    struct sdap_attr_map *default_host_map;
    struct sdap_attr_map *default_service_map;
    struct sdap_options *opts;
    char *schema;
    const char *search_base;
    const char *pwd_policy;
    int ret;
    int account_cache_expiration;
    int offline_credentials_expiration;
    const char *ldap_deref;
    int ldap_deref_val;
    int o;
    const char *authtok_type;
    struct dp_opt_blob authtok_blob;
    char *cleartext;
    const int search_base_options[] = { SDAP_USER_SEARCH_BASE,
                                        SDAP_GROUP_SEARCH_BASE,
                                        SDAP_NETGROUP_SEARCH_BASE,
                                        SDAP_HOST_SEARCH_BASE,
                                        SDAP_SERVICE_SEARCH_BASE,
                                        -1 };

    opts = talloc_zero(memctx, struct sdap_options);
    if (!opts) return ENOMEM;
    opts->dp = dp;

    ret = sdap_domain_add(opts, dom, NULL);
    if (ret != EOK) {
        goto done;
    }

    ret = dp_get_options(opts, cdb, conf_path,
                         default_basic_opts,
                         SDAP_OPTS_BASIC,
                         &opts->basic);
    if (ret != EOK) {
        goto done;
    }

    /* Handle search bases */
    search_base = dp_opt_get_string(opts->basic, SDAP_SEARCH_BASE);
    if (search_base != NULL) {
        /* set user/group/netgroup search bases if they are not */
        for (o = 0; search_base_options[o] != -1; o++) {
            if (NULL == dp_opt_get_string(opts->basic, search_base_options[o])) {
                ret = dp_opt_set_string(opts->basic, search_base_options[o],
                                        search_base);
                if (ret != EOK) {
                    goto done;
                }
                DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
                          opts->basic[search_base_options[o]].opt_name,
                          dp_opt_get_string(opts->basic,
                                            search_base_options[o]));
            }
        }
    } else {
        DEBUG(SSSDBG_FUNC_DATA,
              "Search base not set, trying to discover it later when "
                  "connecting to the LDAP server.\n");
    }

    /* Default search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_SEARCH_BASE,
                                 &opts->sdom->search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* User search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_USER_SEARCH_BASE,
                                 &opts->sdom->user_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Group search base */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_GROUP_SEARCH_BASE,
                                 &opts->sdom->group_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Netgroup search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_NETGROUP_SEARCH_BASE,
                                 &opts->sdom->netgroup_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Netgroup search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_HOST_SEARCH_BASE,
                                 &opts->sdom->host_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Service search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_SERVICE_SEARCH_BASE,
                                 &opts->sdom->service_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    pwd_policy = dp_opt_get_string(opts->basic, SDAP_PWD_POLICY);
    if (pwd_policy == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing password policy, this may not happen.\n");
        ret = EINVAL;
        goto done;
    }
    if (strcasecmp(pwd_policy, PWD_POL_OPT_NONE) != 0 &&
        strcasecmp(pwd_policy, PWD_POL_OPT_SHADOW) != 0 &&
        strcasecmp(pwd_policy, PWD_POL_OPT_MIT) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unsupported password policy [%s].\n", pwd_policy);
        ret = EINVAL;
        goto done;
    }

    /* account_cache_expiration must be >= than offline_credentials_expiration */
    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_CRED_TIMEOUT, 0,
                         &offline_credentials_expiration);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get value of %s from confdb \n",
                  CONFDB_PAM_CRED_TIMEOUT);
        goto done;
    }

    account_cache_expiration = dp_opt_get_int(opts->basic,
                                              SDAP_ACCOUNT_CACHE_EXPIRATION);

    /* account cache_expiration must not be smaller than
     * offline_credentials_expiration to prevent deleting entries that
     * still contain credentials valid for offline login.
     *
     * offline_credentials_expiration == 0 is a special case that says
     * that the cached credentials are valid forever. Therefore, the cached
     * entries must not be purged from cache.
     */
    if (!offline_credentials_expiration && account_cache_expiration) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Conflicting values for options %s (unlimited) "
                  "and %s (%d)\n",
                  opts->basic[SDAP_ACCOUNT_CACHE_EXPIRATION].opt_name,
                  CONFDB_PAM_CRED_TIMEOUT,
                  offline_credentials_expiration);
        ret = EINVAL;
        goto done;
    }
    if (offline_credentials_expiration && account_cache_expiration &&
        offline_credentials_expiration > account_cache_expiration) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Value of %s (now %d) must be larger "
                  "than value of %s (now %d)\n",
                  opts->basic[SDAP_ACCOUNT_CACHE_EXPIRATION].opt_name,
                  account_cache_expiration,
                  CONFDB_PAM_CRED_TIMEOUT,
                  offline_credentials_expiration);
        ret = EINVAL;
        goto done;
    }

    ldap_deref = dp_opt_get_string(opts->basic, SDAP_DEREF);
    if (ldap_deref != NULL) {
        ret = deref_string_to_val(ldap_deref, &ldap_deref_val);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to verify ldap_deref option.\n");
            goto done;
        }
    }

#ifndef HAVE_LDAP_CONNCB
    bool ldap_referrals;

    ldap_referrals = dp_opt_get_bool(opts->basic, SDAP_REFERRALS);
    if (ldap_referrals) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "LDAP referrals are not supported, because the LDAP library "
                  "is too old, see sssd-ldap(5) for details.\n");
        ret = dp_opt_set_bool(opts->basic, SDAP_REFERRALS, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
            goto done;
        }
    }
#endif

    /* schema type */
    schema = dp_opt_get_string(opts->basic, SDAP_SCHEMA);
    if (strcasecmp(schema, "rfc2307") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307;
        default_attr_map = generic_attr_map;
        default_user_map = rfc2307_user_map;
        default_group_map = rfc2307_group_map;
        default_netgroup_map = netgroup_map;
        default_host_map = host_map;
        default_service_map = service_map;
    } else
    if (strcasecmp(schema, "rfc2307bis") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307BIS;
        default_attr_map = generic_attr_map;
        default_user_map = rfc2307bis_user_map;
        default_group_map = rfc2307bis_group_map;
        default_netgroup_map = netgroup_map;
        default_host_map = host_map;
        default_service_map = service_map;
    } else
    if (strcasecmp(schema, "IPA") == 0) {
        opts->schema_type = SDAP_SCHEMA_IPA_V1;
        default_attr_map = gen_ipa_attr_map;
        default_user_map = rfc2307bis_user_map;
        default_group_map = rfc2307bis_group_map;
        default_netgroup_map = netgroup_map;
        default_host_map = host_map;
        default_service_map = service_map;
    } else
    if (strcasecmp(schema, "AD") == 0) {
        opts->schema_type = SDAP_SCHEMA_AD;
        default_attr_map = gen_ad_attr_map;
        default_user_map = gen_ad2008r2_user_map;
        default_group_map = gen_ad2008r2_group_map;
        default_netgroup_map = netgroup_map;
        default_host_map = host_map;
        default_service_map = service_map;
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unrecognized schema type: %s\n", schema);
        ret = EINVAL;
        goto done;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_attr_map,
                       SDAP_AT_GENERAL,
                       &opts->gen_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_user_map,
                       SDAP_OPTS_USER,
                       &opts->user_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_extend_map_with_list(opts, opts, SDAP_USER_EXTRA_ATTRS,
                                    opts->user_map, SDAP_OPTS_USER,
                                    &opts->user_map, &opts->user_map_cnt);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_group_map,
                       SDAP_OPTS_GROUP,
                       &opts->group_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_netgroup_map,
                       SDAP_OPTS_NETGROUP,
                       &opts->netgroup_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_host_map,
                       SDAP_OPTS_HOST,
                       &opts->host_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_service_map,
                       SDAP_OPTS_SERVICES,
                       &opts->service_map);
    if (ret != EOK) {
        goto done;
    }

    /* If there is no KDC, try the deprecated krb5_kdcip option, too */
    /* FIXME - this can be removed in a future version */
    ret = krb5_try_kdcip(cdb, conf_path, opts->basic, SDAP_KRB5_KDC);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_krb5_try_kdcip failed.\n");
        goto done;
    }

    authtok_type = dp_opt_get_string(opts->basic, SDAP_DEFAULT_AUTHTOK_TYPE);
    if (authtok_type != NULL &&
        strcasecmp(authtok_type,"obfuscated_password") == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Found obfuscated password, "
                  "trying to convert to cleartext.\n");

        authtok_blob = dp_opt_get_blob(opts->basic, SDAP_DEFAULT_AUTHTOK);
        if (authtok_blob.data == NULL || authtok_blob.length == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing obfuscated password string.\n");
            ret = EINVAL;
            goto done;
        }

        ret = sss_password_decrypt(memctx, (char *) authtok_blob.data,
                                   &cleartext);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot convert the obfuscated "
                      "password back to cleartext\n");
            goto done;
        }

        authtok_blob.data = (uint8_t *) cleartext;
        authtok_blob.length = strlen(cleartext);
        ret = dp_opt_set_blob(opts->basic, SDAP_DEFAULT_AUTHTOK, authtok_blob);
        talloc_free(cleartext);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
            goto done;
        }

        ret = dp_opt_set_string(opts->basic, SDAP_DEFAULT_AUTHTOK_TYPE,
                                "password");
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
            goto done;
        }
    }

    ret = EOK;
    *_opts = opts;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }
    return ret;
}

int ldap_get_sudo_options(struct confdb_ctx *cdb,
                          const char *conf_path,
                          struct sdap_options *opts,
                          bool *use_host_filter,
                          bool *include_regexp,
                          bool *include_netgroups)
{
    const char *search_base;
    int ret;

    /* search base */
    search_base = dp_opt_get_string(opts->basic, SDAP_SEARCH_BASE);
    if (search_base != NULL) {
        /* set sudo search bases if they are not */
        if (dp_opt_get_string(opts->basic, SDAP_SUDO_SEARCH_BASE) == NULL) {
            ret = dp_opt_set_string(opts->basic, SDAP_SUDO_SEARCH_BASE,
                                    search_base);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Could not set SUDO search base"
                      "to default value\n");
                return ret;
            }

            DEBUG(SSSDBG_FUNC_DATA, "Option %s set to %s\n",
                  opts->basic[SDAP_SUDO_SEARCH_BASE].opt_name,
                  dp_opt_get_string(opts->basic, SDAP_SUDO_SEARCH_BASE));
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Search base not set, trying to discover it later "
              "connecting to the LDAP server.\n");
    }

    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_SUDO_SEARCH_BASE,
                                 &opts->sdom->sudo_search_bases);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not parse SUDO search base\n");
        return ret;
    }

    /* attrs map */
    ret = sdap_get_map(opts, cdb, conf_path,
                       native_sudorule_map,
                       SDAP_OPTS_SUDO,
                       &opts->sudorule_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not get SUDO attribute map\n");
        return ret;
    }

    /* host filter */
    *use_host_filter = dp_opt_get_bool(opts->basic, SDAP_SUDO_USE_HOST_FILTER);
    *include_netgroups = dp_opt_get_bool(opts->basic, SDAP_SUDO_INCLUDE_NETGROUPS);
    *include_regexp = dp_opt_get_bool(opts->basic, SDAP_SUDO_INCLUDE_REGEXP);

    return EOK;
}

static bool has_defaults(struct confdb_ctx *cdb,
                         const char *conf_path,
                         const char *attrs[])
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *val;
    bool found_default = false;
    tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        return false;
    }

    for (size_t i = 0; attrs[i] != NULL; i++) {
        ret = confdb_get_string(cdb, tmp_ctx, conf_path,
                               attrs[i], NULL, &val);
        if (ret != EOK) {
            continue;
        }

        if (val == NULL) {
            found_default = true;
            break;
        }
    }

    talloc_free(tmp_ctx);
    return found_default;
}

/* Return true if rfc2307 schema is used and all autofs options use
 * defaults. Should be removed in future, see
 * https://fedorahosted.org/sssd/ticket/2858
 */
static bool ldap_rfc2307_autofs_defaults(struct confdb_ctx *cdb,
                                         const char *conf_path)
{
    char **services = NULL;
    errno_t ret;
    bool has_autofs_defaults = false;

    const char *attrs[] = {
        rfc2307_autofs_entry_map[SDAP_OC_AUTOFS_ENTRY].opt_name,
        /* SDAP_AT_AUTOFS_ENTRY_KEY missing on purpose, its value was
         * the same between the wrong and correct schema
         */
        rfc2307_autofs_entry_map[SDAP_AT_AUTOFS_ENTRY_VALUE].opt_name,
        rfc2307_autofs_mobject_map[SDAP_OC_AUTOFS_MAP].opt_name,
        rfc2307_autofs_mobject_map[SDAP_AT_AUTOFS_MAP_NAME].opt_name,
        NULL,
    };

    ret = confdb_get_string_as_list(cdb, cdb,
                                    CONFDB_MONITOR_CONF_ENTRY,
                                    CONFDB_MONITOR_ACTIVE_SERVICES, &services);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to read from confdb [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (string_in_list("autofs", services, true) == false) {
        goto done;
    }

    has_autofs_defaults = has_defaults(cdb, conf_path, attrs);
done:
    talloc_free(services);

    return has_autofs_defaults;
}

int ldap_get_autofs_options(TALLOC_CTX *memctx,
                            struct confdb_ctx *cdb,
                            const char *conf_path,
                            struct sdap_options *opts)
{
    const char *search_base;
    struct sdap_attr_map *default_entry_map;
    struct sdap_attr_map *default_mobject_map;
    int ret;

    /* search base */
    search_base = dp_opt_get_string(opts->basic, SDAP_SEARCH_BASE);
    if (search_base != NULL) {
        /* set autofs search bases if they are not */
        if (dp_opt_get_string(opts->basic, SDAP_AUTOFS_SEARCH_BASE) == NULL) {
            ret = dp_opt_set_string(opts->basic, SDAP_AUTOFS_SEARCH_BASE,
                                    search_base);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Could not set autofs search base"
                      "to default value\n");
                return ret;
            }

            DEBUG(SSSDBG_FUNC_DATA, "Option %s set to %s\n",
                  opts->basic[SDAP_AUTOFS_SEARCH_BASE].opt_name,
                  dp_opt_get_string(opts->basic, SDAP_AUTOFS_SEARCH_BASE));
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Search base not set, trying to discover it later "
              "connecting to the LDAP server.\n");
    }

    if (opts->schema_type == SDAP_SCHEMA_RFC2307 &&
            ldap_rfc2307_autofs_defaults(cdb, conf_path) == true) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Your configuration uses the autofs provider "
              "with schema set to rfc2307 and default attribute mappings. "
              "The default map has changed in this release, please make "
              "sure the configuration matches the server attributes.\n");
        sss_log(SSS_LOG_NOTICE,
                _("Your configuration uses the autofs provider "
                  "with schema set to rfc2307 and default attribute mappings. "
                  "The default map has changed in this release, please make "
                  "sure the configuration matches the server attributes.\n"));
    }

    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_AUTOFS_SEARCH_BASE,
                                 &opts->sdom->autofs_search_bases);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not parse autofs search base\n");
        return ret;
    }

    /* attribute maps */
    switch (opts->schema_type) {
        case SDAP_SCHEMA_RFC2307:
            default_mobject_map = rfc2307_autofs_mobject_map;
            default_entry_map = rfc2307_autofs_entry_map;
            break;
        case SDAP_SCHEMA_RFC2307BIS:
        case SDAP_SCHEMA_IPA_V1:
        case SDAP_SCHEMA_AD:
            default_mobject_map = rfc2307bis_autofs_mobject_map;
            default_entry_map = rfc2307bis_autofs_entry_map;
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknown LDAP schema!\n");
            return EINVAL;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_mobject_map,
                       SDAP_OPTS_AUTOFS_MAP,
                       &opts->autofs_mobject_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not get autofs map object attribute map\n");
        return ret;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_entry_map,
                       SDAP_OPTS_AUTOFS_ENTRY,
                       &opts->autofs_entry_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not get autofs entry object attribute map\n");
        return ret;
    }

    return EOK;
}

errno_t sdap_parse_search_base(TALLOC_CTX *mem_ctx,
                               struct dp_option *opts, int class,
                               struct sdap_search_base ***_search_bases)
{
    const char *class_name;
    char *unparsed_base;
    const char *old_filter = NULL;

    switch (class) {
    case SDAP_SEARCH_BASE:
        class_name = "DEFAULT";
        break;
    case SDAP_USER_SEARCH_BASE:
        class_name = "USER";
        old_filter = dp_opt_get_string(opts, SDAP_USER_SEARCH_FILTER);
        break;
    case SDAP_GROUP_SEARCH_BASE:
        class_name = "GROUP";
        old_filter = dp_opt_get_string(opts, SDAP_GROUP_SEARCH_FILTER);
        break;
    case SDAP_NETGROUP_SEARCH_BASE:
        class_name = "NETGROUP";
        break;
    case SDAP_HOST_SEARCH_BASE:
        class_name = "HOST";
        break;
    case SDAP_SUDO_SEARCH_BASE:
        class_name = "SUDO";
        break;
    case SDAP_SERVICE_SEARCH_BASE:
        class_name = "SERVICE";
        break;
    case SDAP_AUTOFS_SEARCH_BASE:
        class_name = "AUTOFS";
        break;
    default:
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Unknown search base type: [%d]\n", class);
        class_name = "UNKNOWN";
        /* Non-fatal */
        break;
    }

    unparsed_base = dp_opt_get_string(opts, class);
    if (!unparsed_base || unparsed_base[0] == '\0') return ENOENT;

    return common_parse_search_base(mem_ctx, unparsed_base,
                                    class_name, old_filter,
                                    _search_bases);
}

errno_t common_parse_search_base(TALLOC_CTX *mem_ctx,
                                 const char *unparsed_base,
                                 const char *class_name,
                                 const char *old_filter,
                                 struct sdap_search_base ***_search_bases)
{
    errno_t ret;
    struct sdap_search_base **search_bases;
    TALLOC_CTX *tmp_ctx;
    struct ldb_context *ldb;
    struct ldb_dn *ldn;
    struct ldb_parse_tree *tree;
    char **split_bases;
    char *filter;
    int count;
    int i, c;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    /* Create a throwaway LDB context for validating the DN */
    ldb = ldb_init(tmp_ctx, NULL);
    if (!ldb) {
        ret = ENOMEM;
        goto done;
    }

    ret = split_on_separator(tmp_ctx, unparsed_base, '?', false, false,
                             &split_bases, &count);
    if (ret != EOK) goto done;

    /* The split must be either exactly one value or a multiple of
     * three in order to be valid.
     * One value: just a base, backwards-compatible with pre-1.7.0 versions
     * Multiple: search_base?scope?filter[?search_base?scope?filter]*
     */
    if (count > 1 && (count % 3)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unparseable search base: [%s][%d]\n", unparsed_base, count);
        ret = EINVAL;
        goto done;
    }

    if (count == 1) {
        search_bases = talloc_array(tmp_ctx, struct sdap_search_base *, 2);
        if (!search_bases) {
            ret = ENOMEM;
            goto done;
        }

        if (old_filter != NULL) {
            /* Using a deprecated ldap_{user,group}_search_filter */
            DEBUG(SSSDBG_IMPORTANT_INFO, "WARNING: Using a deprecated filter "
                  "option for %s. Please see the documentation on LDAP search "
                  "bases to see how the obsolete option can be migrated\n",
                  class_name);
            sss_log(SSS_LOG_NOTICE, "WARNING: Using a deprecated filter option"
                    "for %s. Please see the documentation on LDAP search bases "
                    "to see how the obsolete option can be migrated\n",
                    class_name);
        }

        ret = sdap_create_search_base(search_bases, unparsed_base,
                                      LDAP_SCOPE_SUBTREE, old_filter,
                                      &search_bases[0]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot create new sdap search base\n");
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS,
              "Search base added: [%s][%s][%s][%s]\n",
               class_name,
               search_bases[0]->basedn,
               "SUBTREE",
               search_bases[0]->filter ? search_bases[0]->filter : "");

        search_bases[1] = NULL;
    } else {
        search_bases = talloc_array(tmp_ctx, struct sdap_search_base *,
                                    (count / 3) + 1);
        if (!search_bases) {
            ret = ENOMEM;
            goto done;
        }

        i = 0;
        for (c = 0; c < count; c += 3) {
            search_bases[i] = talloc_zero(search_bases,
                                          struct sdap_search_base);
            if (!search_bases[i]) {
                ret = ENOMEM;
                goto done;
            }

            if (split_bases[c][0] == '\0') {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Zero-length search base: [%s]\n", unparsed_base);
                ret = EINVAL;
                goto done;
            }

            /* Validate the basedn */
            ldn = ldb_dn_new(tmp_ctx, ldb, split_bases[c]);
            if (!ldn) {
                ret = ENOMEM;
                goto done;
            }

            if (!ldb_dn_validate(ldn)) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Invalid base DN [%s]\n",
                       split_bases[c]);
                ret = EINVAL;
                goto done;
            }
            talloc_zfree(ldn);

            /* Set the search base DN */
            search_bases[i]->basedn = talloc_strdup(search_bases[i],
                                                    split_bases[c]);
            if (!search_bases[i]->basedn) {
                ret = ENOMEM;
                goto done;
            }

            /* Set the search scope for this base DN */
            if ((split_bases[c+1][0] == '\0')
                    || strcasecmp(split_bases[c+1], "sub") == 0
                    || strcasecmp(split_bases[c+1], "subtree") == 0) {
                /* If unspecified, default to subtree */
                search_bases[i]->scope = LDAP_SCOPE_SUBTREE;
            } else if (strcasecmp(split_bases[c+1], "one") == 0
                    || strcasecmp(split_bases[c+1], "onelevel") == 0) {
                search_bases[i]->scope = LDAP_SCOPE_ONELEVEL;
            } else if (strcasecmp(split_bases[c+1], "base") == 0) {
                search_bases[i]->scope = LDAP_SCOPE_BASE;
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Unknown search scope: [%s]\n", split_bases[c+1]);
                ret = EINVAL;
                goto done;
            }

            /* Get a specialized filter if provided */
            if (split_bases[c+2][0] == '\0') {
                search_bases[i]->filter = NULL;
            } else {
                if (split_bases[c+2][0] != '(') {
                    /* Filters need to be enclosed in parentheses
                     * to be validated properly by ldb_parse_tree()
                     */
                    filter = talloc_asprintf(tmp_ctx, "(%s)",
                                             split_bases[c+2]);
                } else {
                    filter = talloc_strdup(tmp_ctx, split_bases[c+2]);
                }
                if (!filter) {
                    ret = ENOMEM;
                    goto done;
                }

                tree = ldb_parse_tree(tmp_ctx, filter);
                if(!tree) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Invalid search filter: [%s]\n", filter);
                    ret = EINVAL;
                    goto done;
                }
                talloc_zfree(tree);

                search_bases[i]->filter = talloc_steal(search_bases[i],
                                                       filter);
            }

            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Search base added: [%s][%s][%s][%s]\n",
                   class_name,
                   search_bases[i]->basedn,
                   split_bases[c+1][0] ? split_bases[c+1] : "SUBTREE",
                   search_bases[i]->filter ? search_bases[i]->filter : "");

            i++;
        }
        search_bases[i] = NULL;
    }

    *_search_bases = talloc_steal(mem_ctx, search_bases);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
