/*
    SSSD

    LDAP Provider Common Functions

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
#include "providers/fail_over.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/krb5/krb5_common.h"
#include "db/sysdb_sudo.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"

#include "util/sss_krb5.h"
#include "util/crypto/sss_crypto.h"

#include "providers/ldap/ldap_opts.h"
#include "providers/ldap/sdap_idmap.h"

/* a fd the child process would log into */
int ldap_child_debug_fd = -1;


int ldap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts)
{
    struct sdap_attr_map *default_attr_map;
    struct sdap_attr_map *default_user_map;
    struct sdap_attr_map *default_group_map;
    struct sdap_attr_map *default_netgroup_map;
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
                                        SDAP_SERVICE_SEARCH_BASE,
                                        -1 };

    opts = talloc_zero(memctx, struct sdap_options);
    if (!opts) return ENOMEM;

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
                DEBUG(6, ("Option %s set to %s\n",
                          opts->basic[search_base_options[o]].opt_name,
                          dp_opt_get_string(opts->basic,
                                            search_base_options[o])));
            }
        }
    } else {
        DEBUG(5, ("Search base not set, trying to discover it later when "
                  "connecting to the LDAP server.\n"));
    }

    /* Default search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_SEARCH_BASE,
                                 &opts->search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* User search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_USER_SEARCH_BASE,
                                 &opts->user_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Group search base */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_GROUP_SEARCH_BASE,
                                 &opts->group_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Netgroup search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_NETGROUP_SEARCH_BASE,
                                 &opts->netgroup_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Service search */
    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_SERVICE_SEARCH_BASE,
                                 &opts->service_search_bases);
    if (ret != EOK && ret != ENOENT) goto done;

    pwd_policy = dp_opt_get_string(opts->basic, SDAP_PWD_POLICY);
    if (pwd_policy == NULL) {
        DEBUG(1, ("Missing password policy, this may not happen.\n"));
        ret = EINVAL;
        goto done;
    }
    if (strcasecmp(pwd_policy, PWD_POL_OPT_NONE) != 0 &&
        strcasecmp(pwd_policy, PWD_POL_OPT_SHADOW) != 0 &&
        strcasecmp(pwd_policy, PWD_POL_OPT_MIT) != 0) {
        DEBUG(1, ("Unsupported password policy [%s].\n", pwd_policy));
        ret = EINVAL;
        goto done;
    }

    /* account_cache_expiration must be >= than offline_credentials_expiration */
    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_CRED_TIMEOUT, 0,
                         &offline_credentials_expiration);
    if (ret != EOK) {
        DEBUG(1, ("Cannot get value of %s from confdb \n",
                  CONFDB_PAM_CRED_TIMEOUT));
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
        DEBUG(1, ("Conflicting values for options %s (unlimited) "
                  "and %s (%d)\n",
                  opts->basic[SDAP_ACCOUNT_CACHE_EXPIRATION].opt_name,
                  CONFDB_PAM_CRED_TIMEOUT,
                  offline_credentials_expiration));
        ret = EINVAL;
        goto done;
    }
    if (offline_credentials_expiration && account_cache_expiration &&
        offline_credentials_expiration > account_cache_expiration) {
        DEBUG(1, ("Value of %s (now %d) must be larger "
                  "than value of %s (now %d)\n",
                  opts->basic[SDAP_ACCOUNT_CACHE_EXPIRATION].opt_name,
                  account_cache_expiration,
                  CONFDB_PAM_CRED_TIMEOUT,
                  offline_credentials_expiration));
        ret = EINVAL;
        goto done;
    }

    ldap_deref = dp_opt_get_string(opts->basic, SDAP_DEREF);
    if (ldap_deref != NULL) {
        ret = deref_string_to_val(ldap_deref, &ldap_deref_val);
        if (ret != EOK) {
            DEBUG(1, ("Failed to verify ldap_deref option.\n"));
            goto done;
        }
    }

#ifndef HAVE_LDAP_CONNCB
    bool ldap_referrals;

    ldap_referrals = dp_opt_get_bool(opts->basic, SDAP_REFERRALS);
    if (ldap_referrals) {
        DEBUG(1, ("LDAP referrals are not supported, because the LDAP library "
                  "is too old, see sssd-ldap(5) for details.\n"));
        ret = dp_opt_set_bool(opts->basic, SDAP_REFERRALS, false);
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
        default_service_map = service_map;
    } else
    if (strcasecmp(schema, "rfc2307bis") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307BIS;
        default_attr_map = generic_attr_map;
        default_user_map = rfc2307bis_user_map;
        default_group_map = rfc2307bis_group_map;
        default_netgroup_map = netgroup_map;
        default_service_map = service_map;
    } else
    if (strcasecmp(schema, "IPA") == 0) {
        opts->schema_type = SDAP_SCHEMA_IPA_V1;
        default_attr_map = gen_ipa_attr_map;
        default_user_map = rfc2307bis_user_map;
        default_group_map = rfc2307bis_group_map;
        default_netgroup_map = netgroup_map;
        default_service_map = service_map;
    } else
    if (strcasecmp(schema, "AD") == 0) {
        opts->schema_type = SDAP_SCHEMA_AD;
        default_attr_map = gen_ad_attr_map;
        default_user_map = gen_ad2008r2_user_map;
        default_group_map = gen_ad2008r2_group_map;
        default_netgroup_map = netgroup_map;
        default_service_map = service_map;
    } else {
        DEBUG(0, ("Unrecognized schema type: %s\n", schema));
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
        DEBUG(1, ("sss_krb5_try_kdcip failed.\n"));
        goto done;
    }

    authtok_type = dp_opt_get_string(opts->basic, SDAP_DEFAULT_AUTHTOK_TYPE);
    if (authtok_type != NULL &&
        strcasecmp(authtok_type,"obfuscated_password") == 0) {
        DEBUG(9, ("Found obfuscated password, "
                  "trying to convert to cleartext.\n"));

        authtok_blob = dp_opt_get_blob(opts->basic, SDAP_DEFAULT_AUTHTOK);
        if (authtok_blob.data == NULL || authtok_blob.length == 0) {
            DEBUG(1, ("Missing obfuscated password string.\n"));
            return EINVAL;
        }

        ret = sss_password_decrypt(memctx, (char *) authtok_blob.data,
                                   &cleartext);
        if (ret != EOK) {
            DEBUG(1, ("Cannot convert the obfuscated "
                      "password back to cleartext\n"));
            return ret;
        }

        authtok_blob.data = (uint8_t *) cleartext;
        authtok_blob.length = strlen(cleartext);
        ret = dp_opt_set_blob(opts->basic, SDAP_DEFAULT_AUTHTOK, authtok_blob);
        talloc_free(cleartext);
        if (ret != EOK) {
            DEBUG(1, ("dp_opt_set_string failed.\n"));
            return ret;
        }

        ret = dp_opt_set_string(opts->basic, SDAP_DEFAULT_AUTHTOK_TYPE,
                                "password");
        if (ret != EOK) {
            DEBUG(1, ("dp_opt_set_string failed.\n"));
            return ret;
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

int ldap_get_sudo_options(TALLOC_CTX *memctx,
                          struct confdb_ctx *cdb,
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
                DEBUG(SSSDBG_OP_FAILURE, ("Could not set SUDO search base"
                      "to default value\n"));
                return ret;
            }

            DEBUG(SSSDBG_FUNC_DATA, ("Option %s set to %s\n",
                  opts->basic[SDAP_SUDO_SEARCH_BASE].opt_name,
                  dp_opt_get_string(opts->basic, SDAP_SUDO_SEARCH_BASE)));
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, ("Search base not set, trying to discover it later "
              "connecting to the LDAP server.\n"));
    }

    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_SUDO_SEARCH_BASE,
                                 &opts->sudo_search_bases);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not parse SUDO search base\n"));
        return ret;
    }

    /* attrs map */
    ret = sdap_get_map(opts, cdb, conf_path,
                       native_sudorule_map,
                       SDAP_OPTS_SUDO,
                       &opts->sudorule_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not get SUDO attribute map\n"));
        return ret;
    }

    /* host filter */
    *use_host_filter = dp_opt_get_bool(opts->basic, SDAP_SUDO_USE_HOST_FILTER);
    *include_netgroups = dp_opt_get_bool(opts->basic, SDAP_SUDO_INCLUDE_NETGROUPS);
    *include_regexp = dp_opt_get_bool(opts->basic, SDAP_SUDO_INCLUDE_REGEXP);

    return EOK;
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
                DEBUG(SSSDBG_OP_FAILURE, ("Could not set autofs search base"
                      "to default value\n"));
                return ret;
            }

            DEBUG(SSSDBG_FUNC_DATA, ("Option %s set to %s\n",
                  opts->basic[SDAP_AUTOFS_SEARCH_BASE].opt_name,
                  dp_opt_get_string(opts->basic, SDAP_AUTOFS_SEARCH_BASE)));
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, ("Search base not set, trying to discover it later "
              "connecting to the LDAP server.\n"));
    }

    ret = sdap_parse_search_base(opts, opts->basic,
                                 SDAP_AUTOFS_SEARCH_BASE,
                                 &opts->autofs_search_bases);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not parse autofs search base\n"));
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
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unknown LDAP schema!\n"));
            return EINVAL;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_mobject_map,
                       SDAP_OPTS_AUTOFS_MAP,
                       &opts->autofs_mobject_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not get autofs map object attribute map\n"));
        return ret;
    }

    ret = sdap_get_map(opts, cdb, conf_path,
                       default_entry_map,
                       SDAP_OPTS_AUTOFS_ENTRY,
                       &opts->autofs_entry_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not get autofs entry object attribute map\n"));
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

    *_search_bases = NULL;

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
              ("Unknown search base type: [%d]\n", class));
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

    ret = split_on_separator(tmp_ctx, unparsed_base, '?', false,
                             &split_bases, &count);
    if (ret != EOK) goto done;

    /* The split must be either exactly one value or a multiple of
     * three in order to be valid.
     * One value: just a base, backwards-compatible with pre-1.7.0 versions
     * Multiple: search_base?scope?filter[?search_base?scope?filter]*
     */
    if (count > 1 && (count % 3)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unparseable search base: [%s][%d]\n", unparsed_base, count));
        ret = EINVAL;
        goto done;
    }

    if (count == 1) {
        search_bases = talloc_array(tmp_ctx, struct sdap_search_base *, 2);
        if (!search_bases) {
            ret = ENOMEM;
            goto done;
        }
        search_bases[0] = talloc_zero(search_bases, struct sdap_search_base);
        if (!search_bases[0]) {
            ret = ENOMEM;
            goto done;
        }

        search_bases[0]->basedn = talloc_strdup(search_bases[0],
                                                unparsed_base);
        if (!search_bases[0]->basedn) {
            ret = ENOMEM;
            goto done;
        }

        /* Validate the basedn */
        ldn = ldb_dn_new(tmp_ctx, ldb, unparsed_base);
        if (!ldn) {
            ret = ENOMEM;
            goto done;
        }

        if (!ldb_dn_validate(ldn)) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Invalid base DN [%s]\n",
                   unparsed_base));
            ret = EINVAL;
            goto done;
        }
        talloc_zfree(ldn);

        search_bases[0]->scope = LDAP_SCOPE_SUBTREE;

        /* Use a search filter specified in the old style if available */
        search_bases[0]->filter = old_filter;

        DEBUG(SSSDBG_CONF_SETTINGS,
              ("Search base added: [%s][%s][%s][%s]\n",
               class_name,
               search_bases[0]->basedn,
               "SUBTREE",
               search_bases[0]->filter ? search_bases[0]->filter : ""));

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
                      ("Zero-length search base: [%s]\n", unparsed_base));
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
                      ("Invalid base DN [%s]\n",
                       split_bases[c]));
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
                      ("Unknown search scope: [%s]\n", split_bases[c+1]));
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
                          ("Invalid search filter: [%s]\n", filter));
                    ret = EINVAL;
                    goto done;
                }
                talloc_zfree(tree);

                search_bases[i]->filter = talloc_steal(search_bases[i],
                                                       filter);
            }

            DEBUG(SSSDBG_CONF_SETTINGS,
                  ("Search base added: [%s][%s][%s][%s]\n",
                   class_name,
                   search_bases[i]->basedn,
                   split_bases[c+1][0] ? split_bases[c+1] : "SUBTREE",
                   search_bases[i]->filter ? search_bases[i]->filter : ""));

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

void sdap_handler_done(struct be_req *req, int dp_err,
                       int error, const char *errstr)
{
    return req->fn(req, dp_err, error, errstr);
}

void sdap_mark_offline(struct sdap_id_ctx *ctx)
{
    be_mark_offline(ctx->be);
}

int sdap_id_setup_tasks(struct sdap_id_ctx *ctx)
{
    struct timeval tv;
    int ret = EOK;
    int delay;
    bool has_enumerated;

    /* set up enumeration task */
    if (ctx->be->domain->enumerate) {
        /* If this is the first startup, we need to kick off
         * an enumeration immediately, to close a window where
         * clients requesting get*ent information won't get an
         * immediate reply with no entries
         */
        ret = sysdb_has_enumerated(ctx->be->sysdb, &has_enumerated);
        if (ret != EOK) {
            return ret;
        }
        if (has_enumerated) {
            /* At least one enumeration has previously run,
             * so clients will get cached data. We will delay
             * starting to enumerate by 10s so we don't slow
             * down the startup process if this is happening
             * during system boot.
             */
            tv = tevent_timeval_current_ofs(10, 0);
        } else {
            /* This is our first startup. Schedule the
             * enumeration to start immediately once we
             * enter the mainloop.
             */
            tv = tevent_timeval_current();
        }

        ret = ldap_id_enumerate_set_timer(ctx, tv);
    } else {
        /* the enumeration task, runs the cleanup process by itself,
         * but if enumeration is not running we need to schedule it */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_CACHE_PURGE_TIMEOUT);
        if (delay == 0) {
            /* Cleanup has been explicitly disabled, so we won't
             * schedule any cleanup tasks.
             */
            return EOK;
        }

        /* run the first one in a couple of seconds so that we have time to
         * finish initializations first*/
        tv = tevent_timeval_current_ofs(10, 0);
        ret = ldap_id_cleanup_set_timer(ctx, tv);
    }

    return ret;
}

static void sdap_uri_callback(void *private_data, struct fo_server *server)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sdap_service *service;
    struct resolv_hostent *srvaddr;
    struct sockaddr_storage *sockaddr;
    const char *tmp;
    const char *srv_name;
    char *new_uri;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed\n"));
        return;
    }

    service = talloc_get_type(private_data, struct sdap_service);
    if (!service) {
        talloc_free(tmp_ctx);
        return;
    }

    tmp = (const char *)fo_get_server_user_data(server);

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(1, ("FATAL: No hostent available for server (%s)\n",
                  fo_get_server_str_name(server)));
        talloc_free(tmp_ctx);
        return;
    }

    sockaddr = resolv_get_sockaddr_address(tmp_ctx, srvaddr,
                                           fo_get_server_port(server));
    if (sockaddr == NULL) {
        DEBUG(1, ("resolv_get_sockaddr_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    if (fo_is_srv_lookup(server)) {
        if (!tmp) {
            DEBUG(1, ("Unknown service, using ldap\n"));
            tmp = SSS_LDAP_SRV_NAME;
        }

        srv_name = fo_get_server_name(server);
        if (srv_name == NULL) {
            DEBUG(1, ("Could not get server host name\n"));
            talloc_free(tmp_ctx);
            return;
        }

        new_uri = talloc_asprintf(service, "%s://%s:%d",
                                  tmp, srv_name,
                                  fo_get_server_port(server));
    } else {
        new_uri = talloc_strdup(service, tmp);
    }

    if (!new_uri) {
        DEBUG(2, ("Failed to copy URI ...\n"));
        talloc_free(tmp_ctx);
        return;
    }

    DEBUG(6, ("Constructed uri '%s'\n", new_uri));

    /* free old one and replace with new one */
    talloc_zfree(service->uri);
    service->uri = new_uri;
    talloc_zfree(service->sockaddr);
    service->sockaddr = talloc_steal(service, sockaddr);
    talloc_free(tmp_ctx);
}

static void sdap_finalize(struct tevent_context *ev,
                          struct tevent_signal *se,
                          int signum,
                          int count,
                          void *siginfo,
                          void *private_data)
{
    char *realm = (char *) private_data;
    int ret;

    ret = remove_krb5_info_files(se, realm);
    if (ret != EOK) {
        DEBUG(1, ("remove_krb5_info_files failed.\n"));
    }

    sig_term(signum);
}

errno_t sdap_install_sigterm_handler(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     const char *realm)
{
    char *sig_realm;
    struct tevent_signal *sige;

    BlockSignals(false, SIGTERM);

    sig_realm = talloc_strdup(mem_ctx, realm);
    if (sig_realm == NULL) {
        DEBUG(1, ("talloc_strdup failed!\n"));
        return ENOMEM;
    }

    sige = tevent_add_signal(ev, mem_ctx, SIGTERM, SA_SIGINFO, sdap_finalize,
                             sig_realm);
    if (sige == NULL) {
        DEBUG(1, ("tevent_add_signal failed.\n"));
        talloc_free(sig_realm);
        return ENOMEM;
    }
    talloc_steal(sige, sig_realm);

    return EOK;
}

void sdap_remove_kdcinfo_files_callback(void *pvt)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct remove_info_files_ctx *ctx = talloc_get_type(pvt,
                                                  struct remove_info_files_ctx);

    ret = be_fo_run_callbacks_at_next_request(ctx->be_ctx,
                                              ctx->kdc_service_name);
    if (ret != EOK) {
        DEBUG(1, ("be_fo_run_callbacks_at_next_request failed, "
                  "krb5 info files will not be removed, because "
                  "it is unclear if they will be recreated properly.\n"));
        return;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed, cannot remove krb5 info files.\n"));
        return;
    }

    ret = remove_krb5_info_files(tmp_ctx, ctx->realm);
    if (ret != EOK) {
        DEBUG(1, ("remove_krb5_info_files failed.\n"));
    }

    talloc_zfree(tmp_ctx);
}


errno_t sdap_install_offline_callback(TALLOC_CTX *mem_ctx,
                                      struct be_ctx *be_ctx,
                                      const char *realm,
                                      const char *service_name)
{
    int ret;
    struct remove_info_files_ctx *ctx;

    ctx = talloc_zero(mem_ctx, struct remove_info_files_ctx);
    if (ctx == NULL) {
        DEBUG(1, ("talloc_zfree failed.\n"));
        return ENOMEM;
    }

    ctx->be_ctx = be_ctx;
    ctx->realm = talloc_strdup(ctx, realm);
    ctx->kdc_service_name = talloc_strdup(ctx, service_name);
    if (ctx->realm == NULL || ctx->kdc_service_name == NULL) {
        DEBUG(1, ("talloc_strdup failed!\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = be_add_offline_cb(ctx, be_ctx,
                            sdap_remove_kdcinfo_files_callback,
                            ctx, NULL);
    if (ret != EOK) {
        DEBUG(1, ("be_add_offline_cb failed.\n"));
        goto done;
    }

    ret = EOK;
done:
    if (ret != EOK) {
        talloc_zfree(ctx);
    }
    return ret;
}

static const char *
sdap_gssapi_get_default_realm(TALLOC_CTX *mem_ctx)
{
    char *krb5_realm = NULL;
    const char *realm = NULL;
    krb5_error_code krberr;
    krb5_context context = NULL;

    krberr = krb5_init_context(&context);
    if (krberr) {
        DEBUG(2, ("Failed to init kerberos context\n"));
        goto done;
    }

    krberr = krb5_get_default_realm(context, &krb5_realm);
    if (krberr) {
        DEBUG(2, ("Failed to get default realm name: %s\n",
                  sss_krb5_get_error_message(context, krberr)));
        goto done;
    }

    realm = talloc_strdup(mem_ctx, krb5_realm);
    krb5_free_default_realm(context, krb5_realm);
    if (!realm) {
        DEBUG(0, ("Out of memory\n"));
        goto done;
    }

    DEBUG(7, ("Will use default realm %s\n", realm));
done:
    if (context) krb5_free_context(context);
    return realm;
}

int sdap_gssapi_init(TALLOC_CTX *mem_ctx,
                     struct dp_option *opts,
                     struct be_ctx *bectx,
                     struct sdap_service *sdap_service,
                     struct krb5_service **krb5_service)
{
    int ret;
    const char *krb5_servers;
    const char *krb5_backup_servers;
    const char *krb5_realm;
    const char *krb5_opt_realm;
    struct krb5_service *service = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    krb5_servers = dp_opt_get_string(opts, SDAP_KRB5_KDC);
    krb5_backup_servers = dp_opt_get_string(opts, SDAP_KRB5_BACKUP_KDC);

    krb5_opt_realm = dp_opt_get_string(opts, SDAP_KRB5_REALM);
    if (krb5_opt_realm == NULL) {
        DEBUG(2, ("Missing krb5_realm option, will use libkrb default\n"));
        krb5_realm = sdap_gssapi_get_default_realm(tmp_ctx);
        if (krb5_realm == NULL) {
            DEBUG(0, ("Cannot determine the Kerberos realm, aborting\n"));
            ret = EIO;
            goto done;
        }
    } else {
        krb5_realm = talloc_strdup(tmp_ctx, krb5_opt_realm);
        if (krb5_realm == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = krb5_service_init(mem_ctx, bectx, SSS_KRB5KDC_FO_SRV, krb5_servers,
                            krb5_backup_servers, krb5_realm, &service);
    if (ret != EOK) {
        DEBUG(0, ("Failed to init KRB5 failover service!\n"));
        goto done;
    }

    ret = sdap_install_sigterm_handler(mem_ctx, bectx->ev, krb5_realm);
    if (ret != EOK) {
        DEBUG(0, ("Failed to install sigterm handler\n"));
        goto done;
    }

    ret = sdap_install_offline_callback(mem_ctx, bectx,
                                        krb5_realm, SSS_KRB5KDC_FO_SRV);
    if (ret != EOK) {
        DEBUG(0, ("Failed to install sigterm handler\n"));
        goto done;
    }

    sdap_service->kinit_service_name = talloc_strdup(sdap_service,
                                                     service->name);
    if (sdap_service->kinit_service_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
    *krb5_service = service;
done:
    talloc_free(tmp_ctx);
    if (ret != EOK) talloc_free(service);
    return ret;
}

errno_t sdap_urls_init(struct be_ctx *ctx,
                       struct sdap_service *service,
                       const char *service_name,
                       const char *dns_service_name,
                       const char *urls,
                       bool primary)
{
    TALLOC_CTX *tmp_ctx;
    char *srv_user_data;
    char **list = NULL;
    LDAPURLDesc *lud;
    errno_t ret = 0;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }


    /* split server parm into a list */
    ret = split_on_separator(tmp_ctx, urls, ',', true, &list, NULL);
    if (ret != EOK) {
        DEBUG(1, ("Failed to parse server list!\n"));
        goto done;
    }

    /* now for each URI add a new server to the failover service */
    for (i = 0; list[i]; i++) {
        if (be_fo_is_srv_identifier(list[i])) {
            if (!primary) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Failed to add server [%s] to failover service: "
                       "SRV resolution only allowed for primary servers!\n",
                       list[i]));
                continue;
            }

            if (!dns_service_name) {
                DEBUG(0, ("Missing DNS service name for service [%s].\n",
                          service_name));
                ret = EINVAL;
                goto done;
            }
            srv_user_data = talloc_strdup(service, dns_service_name);
            if (!srv_user_data) {
                ret = ENOMEM;
                goto done;
            }

            ret = be_fo_add_srv_server(ctx, service_name,
                                       dns_service_name, NULL,
                                       BE_FO_PROTO_TCP, false, srv_user_data);
            if (ret) {
                DEBUG(0, ("Failed to add server\n"));
                goto done;
            }

            DEBUG(6, ("Added service lookup\n"));
            continue;
        }

        ret = ldap_url_parse(list[i], &lud);
        if (ret != LDAP_SUCCESS) {
            DEBUG(0, ("Failed to parse ldap URI (%s)!\n", list[i]));
            ret = EINVAL;
            goto done;
        }

        if (lud->lud_host == NULL) {
            DEBUG(2, ("The LDAP URI (%s) did not contain a host name\n",
                      list[i]));
            ldap_free_urldesc(lud);
            continue;
        }

        DEBUG(6, ("Added URI %s\n", list[i]));

        talloc_steal(service, list[i]);

        /* It could be ipv6 address in square brackets. Remove
         * the brackets if needed. */
        ret = remove_ipv6_brackets(lud->lud_host);
        if (ret != EOK) {
            goto done;
        }

        ret = be_fo_add_server(ctx, service->name, lud->lud_host,
                               lud->lud_port, list[i], primary);
        ldap_free_urldesc(lud);
        if (ret) {
            goto done;
        }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int ldap_user_data_cmp(void *ud1, void *ud2)
{
    return strcasecmp((char*) ud1, (char*) ud2);
}

int sdap_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name, const char *dns_service_name,
                      const char *urls, const char *backup_urls,
                      struct sdap_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct sdap_service *service;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    service = talloc_zero(tmp_ctx, struct sdap_service);
    if (!service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(ctx, service_name, ldap_user_data_cmp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to create failover service!\n"));
        goto done;
    }

    service->name = talloc_strdup(service, service_name);
    if (!service->name) {
        ret = ENOMEM;
        goto done;
    }

    if (!urls) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              ("No primary servers defined, using service discovery\n"));
        urls = BE_SRV_IDENTIFIER;
    }

    ret = sdap_urls_init(ctx, service, service_name, dns_service_name,
                         urls, true);
    if (ret != EOK) {
        goto done;
    }

    if (backup_urls) {
        ret = sdap_urls_init(ctx, service, service_name, dns_service_name,
                             backup_urls, false);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = be_fo_service_add_callback(memctx, ctx, service->name,
                                     sdap_uri_callback, service);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to add failover callback!\n"));
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_service = talloc_steal(memctx, service);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t string_to_shadowpw_days(const char *s, long *d)
{
    long l;
    char *endptr;

    if (s == NULL || *s == '\0') {
        *d = -1;
        return EOK;
    }

    errno = 0;
    l = strtol(s, &endptr, 10);
    if (errno != 0) {
        DEBUG(1, ("strtol failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    if (*endptr != '\0') {
        DEBUG(1, ("Input string [%s] is invalid.\n", s));
        return EINVAL;
    }

    if (l < -1) {
        DEBUG(1, ("Input string contains not allowed negative value [%d].\n",
                  l));
        return EINVAL;
    }

    *d = l;

    return EOK;
}

errno_t get_sysdb_attr_name(TALLOC_CTX *mem_ctx,
                            struct sdap_attr_map *map,
                            size_t map_size,
                            const char *ldap_name,
                            char **sysdb_name)
{
    size_t i;

    for (i = 0; i < map_size; i++) {
        /* Skip map entries with no name (may depend on
         * schema selected)
         */
        if (!map[i].name) continue;

        /* Check if it is a mapped attribute */
        if(strcasecmp(ldap_name, map[i].name) == 0) break;
    }

    if (i < map_size) {
        /* We found a mapped name, return that */
        *sysdb_name = talloc_strdup(mem_ctx, map[i].sys_name);
    } else {
        /* Not mapped, use the same name */
        *sysdb_name = talloc_strdup(mem_ctx, ldap_name);
    }

    if (!*sysdb_name) {
        return ENOMEM;
    }

    return EOK;
}

errno_t list_missing_attrs(TALLOC_CTX *mem_ctx,
                           struct sdap_attr_map *map,
                           size_t map_size,
                           struct sysdb_attrs *recvd_attrs,
                           char ***missing_attrs)
{
    errno_t ret;
    size_t attr_count = 0;
    size_t i, j, k;
    char **missing = NULL;
    const char **expected_attrs;
    char *sysdb_name;
    TALLOC_CTX *tmp_ctx;

    if (!recvd_attrs || !missing_attrs) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = build_attrs_from_map(tmp_ctx, map, map_size, NULL,
                               &expected_attrs, &attr_count);
    if (ret != EOK) {
        goto done;
    }

    /* Allocate the maximum possible values for missing_attrs, to
     * be on the safe side
     */
    missing = talloc_array(tmp_ctx, char *, attr_count);
    if (!missing) {
        ret = ENOMEM;
        goto done;
    }

    k = 0;
    /* Check for each expected attribute */
    for (i = 0; i < attr_count; i++) {
        ret = get_sysdb_attr_name(tmp_ctx, map, map_size,
                                  expected_attrs[i],
                                  &sysdb_name);
        if (ret != EOK) {
            goto done;
        }

        /* objectClass is a special-case and we need to
         * check for it explicitly.
         */
        if (strcasecmp(sysdb_name, "objectClass") == 0) {
            talloc_free(sysdb_name);
            continue;
        }

        /* GECOS is another special case. Its value can come
         * either from the 'gecos' attribute or the 'cn'
         * attribute. It's best if we just never remove it.
         */
        if (strcasecmp(sysdb_name, SYSDB_GECOS) == 0) {
            talloc_free(sysdb_name);
            continue;
        }

        for (j = 0; j < recvd_attrs->num; j++) {
            /* Check whether this expected attribute appeared in the
             * received attributes and had a non-zero number of
             * values.
             */
            if ((strcasecmp(recvd_attrs->a[j].name, sysdb_name) == 0) &&
                (recvd_attrs->a[j].num_values > 0)) {
                break;
            }
        }

        if (j < recvd_attrs->num) {
            /* Attribute was found, therefore not missing */
            talloc_free(sysdb_name);
        } else {
            /* Attribute could not be found. Add to the missing list */
            missing[k] = talloc_steal(missing, sysdb_name);
            k++;
        }
    }

    if (k == 0) {
        *missing_attrs = NULL;
    } else {
        /* Terminate the list */
        missing[k] = NULL;
        *missing_attrs = talloc_steal(mem_ctx, missing);
    }
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

bool sdap_is_secure_uri(const char *uri)
{
    /* LDAPS URI's are secure channels */
    if (strncasecmp(uri, LDAP_SSL_URI, strlen(LDAP_SSL_URI)) == 0) {
        return true;
    }
    return false;
}

char *sdap_get_id_specific_filter(TALLOC_CTX *mem_ctx,
                                  const char *base_filter,
                                  const char *extra_filter)
{
    char *filter = NULL;

    if (!extra_filter) {
        return talloc_strdup(mem_ctx, base_filter);
    }

    if (extra_filter[0] == '(') {
        filter = talloc_asprintf(mem_ctx, "(&%s%s)",
                                 base_filter, extra_filter);
    } else {
        filter = talloc_asprintf(mem_ctx, "(&%s(%s))",
                                 base_filter, extra_filter);
    }
    return filter; /* NULL or not */
}

errno_t
sdap_attrs_get_sid_str(TALLOC_CTX *mem_ctx,
                       struct sdap_idmap_ctx *idmap_ctx,
                       struct sysdb_attrs *sysdb_attrs,
                       const char *sid_attr,
                       char **_sid_str)
{
    errno_t ret;
    enum idmap_error_code err;
    struct ldb_message_element *el;
    char *sid_str;

    ret = sysdb_attrs_get_el(sysdb_attrs, sid_attr, &el);
    if (ret != EOK || el->num_values != 1) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("No [%s] attribute while id-mapping. [%d][%s]\n",
               sid_attr, el->num_values, strerror(ret)));
        return ENOENT;
    }

    err = sss_idmap_bin_sid_to_sid(idmap_ctx->map,
                                   el->values[0].data,
                                   el->values[0].length,
                                   &sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not convert SID: [%s]\n",
               idmap_error_string(err)));
        return EIO;
    }

    *_sid_str = talloc_steal(mem_ctx, sid_str);

    return EOK;
}
