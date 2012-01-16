/*
    SSSD

    IPA Provider Common Functions

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <netdb.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "providers/ipa/ipa_common.h"
#include "providers/ldap/sdap_async_private.h"

struct dp_option ipa_basic_opts[] = {
    { "ipa_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_hostname", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_dyndns_update", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ipa_dyndns_iface", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ipa_hbac_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ipa_hbac_refresh", DP_OPT_NUMBER, { .number = 5 }, NULL_NUMBER },
    { "ipa_hbac_treat_deny_as", DP_OPT_STRING, { "DENY_ALL" }, NULL_STRING },
    { "ipa_hbac_support_srchost", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE }
};

struct dp_option ipa_def_ldap_opts[] = {
    { "ldap_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_bind_dn", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_authtok_type", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ldap_default_authtok", DP_OPT_BLOB, NULL_BLOB, NULL_BLOB },
    { "ldap_search_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "ldap_network_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "ldap_opt_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "ldap_tls_reqcert", DP_OPT_STRING, { "hard" }, NULL_STRING },
    { "ldap_user_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_user_search_scope", DP_OPT_STRING, { "sub" }, NULL_STRING },
    { "ldap_user_search_filter", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_group_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_group_search_scope", DP_OPT_STRING, { "sub" }, NULL_STRING },
    { "ldap_group_search_filter", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_schema", DP_OPT_STRING, { "ipa_v1" }, NULL_STRING },
    { "ldap_offline_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ldap_force_upper_case_realm", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_enumeration_refresh_timeout", DP_OPT_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "ldap_purge_cache_timeout", DP_OPT_NUMBER, { .number = 3600 }, NULL_NUMBER },
    { "entry_cache_timeout", DP_OPT_NUMBER, { .number = 1800 }, NULL_NUMBER },
    { "ldap_tls_cacert", DP_OPT_STRING, { "/etc/ipa/ca.crt" }, NULL_STRING },
    { "ldap_tls_cacertdir", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_key", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cipher_suite", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_id_use_start_tls", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_sasl_mech", DP_OPT_STRING, { "GSSAPI" } , NULL_STRING },
    { "ldap_sasl_authid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_init_creds", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    /* use the same parm name as the krb5 module so we set it only once */
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_pwd_policy", DP_OPT_STRING, { "none" } , NULL_STRING },
    { "ldap_referrals", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "account_cache_expiration", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    { "ldap_dns_service_name", DP_OPT_STRING, { SSS_LDAP_SRV_NAME }, NULL_STRING },
    { "ldap_krb5_ticket_lifetime", DP_OPT_NUMBER, { .number = (24 * 60 * 60) }, NULL_NUMBER },
    { "ldap_access_filter", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_netgroup_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_group_nesting_level", DP_OPT_NUMBER, { .number = 2 }, NULL_NUMBER },
    { "ldap_deref", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_account_expire_policy", DP_OPT_STRING, { "ipa" }, NULL_STRING },
    { "ldap_access_order", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_chpass_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_chpass_dns_service_name", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_enumeration_search_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    /* Do not include ldap_auth_disable_tls_never_use_in_production in the
     * manpages or SSSDConfig API
     */
    { "ldap_auth_disable_tls_never_use_in_production", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_page_size", DP_OPT_NUMBER, { .number = 1000 }, NULL_NUMBER },
    { "ldap_sasl_canonicalize", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_disable_paging", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE }
};

struct sdap_attr_map ipa_attr_map[] = {
    { "ldap_entry_usn", "entryUSN", SYSDB_USN, NULL },
    { "ldap_rootdse_last_usn", "lastUSN", SYSDB_HIGH_USN, NULL }
};

struct sdap_attr_map ipa_user_map[] = {
    { "ldap_user_object_class", "posixAccount", SYSDB_USER_CLASS, NULL },
    { "ldap_user_name", "uid", SYSDB_NAME, NULL },
    { "ldap_user_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_user_uid_number", "uidNumber", SYSDB_UIDNUM, NULL },
    { "ldap_user_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_user_gecos", "gecos", SYSDB_GECOS, NULL },
    { "ldap_user_home_directory", "homeDirectory", SYSDB_HOMEDIR, NULL },
    { "ldap_user_shell", "loginShell", SYSDB_SHELL, NULL },
    { "ldap_user_principal", "krbPrincipalName", SYSDB_UPN, NULL },
    { "ldap_user_fullname", "cn", SYSDB_FULLNAME, NULL },
    { "ldap_user_member_of", "memberOf", SYSDB_MEMBEROF, NULL },
    { "ldap_user_uuid", "nsUniqueId", SYSDB_UUID, NULL },
    { "ldap_user_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL },
    { "ldap_user_entry_usn", NULL, SYSDB_USN, NULL },
    { "ldap_user_shadow_last_change", "shadowLastChange", SYSDB_SHADOWPW_LASTCHANGE, NULL },
    { "ldap_user_shadow_min", "shadowMin", SYSDB_SHADOWPW_MIN, NULL },
    { "ldap_user_shadow_max", "shadowMax", SYSDB_SHADOWPW_MAX, NULL },
    { "ldap_user_shadow_warning", "shadowWarning", SYSDB_SHADOWPW_WARNING, NULL },
    { "ldap_user_shadow_inactive", "shadowInactive", SYSDB_SHADOWPW_INACTIVE, NULL },
    { "ldap_user_shadow_expire", "shadowExpire", SYSDB_SHADOWPW_EXPIRE, NULL },
    { "ldap_user_shadow_flag", "shadowFlag", SYSDB_SHADOWPW_FLAG, NULL },
    { "ldap_user_krb_last_pwd_change", "krbLastPwdChange", SYSDB_KRBPW_LASTCHANGE, NULL },
    { "ldap_user_krb_password_expiration", "krbPasswordExpiration", SYSDB_KRBPW_EXPIRATION, NULL },
    { "ldap_pwd_attribute", "pwdAttribute", SYSDB_PWD_ATTRIBUTE, NULL },
    { "ldap_user_authorized_service", "authorizedService", SYSDB_AUTHORIZED_SERVICE, NULL },
    { "ldap_user_ad_account_expires", "accountExpires", SYSDB_AD_ACCOUNT_EXPIRES, NULL},
    { "ldap_user_ad_user_account_control", "userAccountControl", SYSDB_AD_USER_ACCOUNT_CONTROL, NULL},
    { "ldap_ns_account_lock", "nsAccountLock", SYSDB_NS_ACCOUNT_LOCK, NULL}
};

struct sdap_attr_map ipa_group_map[] = {
    { "ldap_group_object_class", "posixGroup", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "cn", SYSDB_NAME, NULL },
    { "ldap_group_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "member", SYSDB_MEMBER, NULL },
    { "ldap_group_uuid", "nsUniqueId", SYSDB_UUID, NULL },
    { "ldap_group_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL },
    { "ldap_group_entry_usn", NULL, SYSDB_USN, NULL }
};

struct sdap_attr_map ipa_netgroup_map[] = {
    { "ldap_netgroup_object_class", "nisNetgroup", SYSDB_NETGROUP_CLASS, NULL },
    { "ldap_netgroup_name", "cn", SYSDB_NAME, NULL },
    { "ldap_netgroup_member", "memberNisNetgroup", SYSDB_ORIG_NETGROUP_MEMBER, NULL },
    { "ldap_netgroup_triple", "nisNetgroupTriple", SYSDB_NETGROUP_TRIPLE, NULL },
    { "ldap_netgroup_uuid", "nsUniqueId", SYSDB_UUID, NULL },
    { "ldap_netgroup_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL }
};

struct dp_option ipa_def_krb5_opts[] = {
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_ccachedir", DP_OPT_STRING, { "/tmp" }, NULL_STRING },
    { "krb5_ccname_template", DP_OPT_STRING, { "FILE:%d/krb5cc_%U_XXXXXX" }, NULL_STRING},
    { "krb5_auth_timeout", DP_OPT_NUMBER, { .number = 15 }, NULL_NUMBER },
    { "krb5_keytab", DP_OPT_STRING, { "/etc/krb5.keytab" }, NULL_STRING },
    { "krb5_validate", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_store_password_if_offline", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_renewable_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_renew_interval", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER },
    { "krb5_use_fast", DP_OPT_STRING, NULL_STRING, NULL_STRING }
};

int ipa_get_options(TALLOC_CTX *memctx,
                    struct confdb_ctx *cdb,
                    const char *conf_path,
                    struct sss_domain_info *dom,
                    struct ipa_options **_opts)
{
    struct ipa_options *opts;
    char *domain;
    char *server;
    char *realm;
    char *ipa_hostname;
    int ret;
    int i;
    char hostname[HOST_NAME_MAX + 1];

    opts = talloc_zero(memctx, struct ipa_options);
    if (!opts) return ENOMEM;

    ret = dp_get_options(opts, cdb, conf_path,
                         ipa_basic_opts,
                         IPA_OPTS_BASIC,
                         &opts->basic);
    if (ret != EOK) {
        goto done;
    }

    domain = dp_opt_get_string(opts->basic, IPA_DOMAIN);
    if (!domain) {
        ret = dp_opt_set_string(opts->basic, IPA_DOMAIN, dom->name);
        if (ret != EOK) {
            goto done;
        }
        domain = dom->name;
    }

    server = dp_opt_get_string(opts->basic, IPA_SERVER);
    if (!server) {
        DEBUG(1, ("No ipa server set, will use service discovery!\n"));
    }

    ipa_hostname = dp_opt_get_string(opts->basic, IPA_HOSTNAME);
    if (ipa_hostname == NULL) {
        ret = gethostname(hostname, HOST_NAME_MAX);
        if (ret != EOK) {
            DEBUG(1, ("gethostname failed [%d][%s].\n", errno,
                      strerror(errno)));
            ret = errno;
            goto done;
        }
        hostname[HOST_NAME_MAX] = '\0';
        DEBUG(9, ("Setting ipa_hostname to [%s].\n", hostname));
        ret = dp_opt_set_string(opts->basic, IPA_HOSTNAME, hostname);
        if (ret != EOK) {
            goto done;
        }
    }

    /* First check whether the realm has been manually specified */
    realm = dp_opt_get_string(opts->basic, IPA_KRB5_REALM);
    if (!realm) {
        /* No explicit krb5_realm, use the IPA domain */
        realm = talloc_strdup(opts, domain);
        if (!realm) {
            ret = ENOMEM;
            goto done;
        }

        /* Use the upper-case IPA domain for the kerberos realm */
        for (i = 0; realm[i]; i++) {
            realm[i] = toupper(realm[i]);
        }

        ret = dp_opt_set_string(opts->basic, IPA_KRB5_REALM,
                                realm);
        if (ret != EOK) {
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

int ipa_get_id_options(struct ipa_options *ipa_opts,
                       struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct sdap_options **_opts)
{
    TALLOC_CTX *tmpctx;
    char *hostname;
    char *basedn;
    char *realm;
    char *value;
    int ret;
    int i;

    /* self check test, this should never fail, unless someone forgot
     * to properly update the code after new ldap options have been added */
    if (SDAP_OPTS_BASIC != IPA_OPTS_BASIC_TEST) {
        DEBUG(0, ("Option numbers do not match (%d != %d)\n",
                   SDAP_OPTS_BASIC, IPA_OPTS_BASIC_TEST));
        abort();
    }

    tmpctx = talloc_new(ipa_opts);
    if (!tmpctx) {
        return ENOMEM;
    }

    ipa_opts->id = talloc_zero(ipa_opts, struct sdap_options);
    if (!ipa_opts->id) {
        ret = ENOMEM;
        goto done;
    }

    /* get sdap options */
    ret = dp_get_options(ipa_opts->id, cdb, conf_path,
                         ipa_def_ldap_opts,
                         SDAP_OPTS_BASIC,
                         &ipa_opts->id->basic);
    if (ret != EOK) {
        goto done;
    }

    ret = domain_to_basedn(tmpctx,
                           dp_opt_get_string(ipa_opts->basic, IPA_KRB5_REALM),
                           &basedn);
    if (ret != EOK) {
        goto done;
    }

    if (NULL == dp_opt_get_string(ipa_opts->id->basic, SDAP_SEARCH_BASE)) {
        /* FIXME: get values by querying IPA */
        /* set search base */
        value = talloc_asprintf(tmpctx, "cn=accounts,%s", basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_SEARCH_BASE, value);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic, SDAP_SEARCH_BASE)));
    }

    /* set the ldap_sasl_authid if the ipa_hostname override was specified */
    if (NULL == dp_opt_get_string(ipa_opts->id->basic, SDAP_SASL_AUTHID)) {
        hostname = dp_opt_get_string(ipa_opts->basic, IPA_HOSTNAME);
        if (hostname) {
            value = talloc_asprintf(tmpctx, "host/%s", hostname);
            if (!value) {
                ret = ENOMEM;
                goto done;
            }
            ret = dp_opt_set_string(ipa_opts->id->basic,
                                    SDAP_SASL_AUTHID, value);
            if (ret != EOK) {
                goto done;
            }
        }
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_SASL_AUTHID].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic, SDAP_SASL_AUTHID)));
    }

    /* set krb realm */
    if (NULL == dp_opt_get_string(ipa_opts->id->basic, SDAP_KRB5_REALM)) {
        realm = dp_opt_get_string(ipa_opts->basic, IPA_KRB5_REALM);
        value = talloc_strdup(tmpctx, realm);
        if (value == NULL) {
            DEBUG(1, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_KRB5_REALM, value);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_KRB5_REALM].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic, SDAP_KRB5_REALM)));
    }

    /* fix schema to IPAv1 for now */
    ipa_opts->id->schema_type = SDAP_SCHEMA_IPA_V1;

    /* set user/group search bases if they are not specified */
    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_USER_SEARCH_BASE)) {
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_USER_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_USER_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_USER_SEARCH_BASE)));
    }

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_GROUP_SEARCH_BASE)) {
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_GROUP_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_GROUP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_GROUP_SEARCH_BASE)));
    }

    if (NULL == dp_opt_get_string(ipa_opts->id->basic,
                                  SDAP_NETGROUP_SEARCH_BASE)) {
#if 0
        ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_NETGROUP_SEARCH_BASE,
                                dp_opt_get_string(ipa_opts->id->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }
#else
        /* We don't yet have support for the native representation
         * of netgroups in IPA. For now, we need to point at the
         * compat tree
         */
        value = talloc_asprintf(tmpctx, "cn=ng,cn=compat,%s", basedn);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }

        ret = dp_opt_set_string(ipa_opts->id->basic,
                                SDAP_NETGROUP_SEARCH_BASE,
                                value);
        if (ret != EOK) {
            goto done;
        }
#endif
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->id->basic[SDAP_NETGROUP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(ipa_opts->id->basic,
                                    SDAP_NETGROUP_SEARCH_BASE)));
    }

    value = dp_opt_get_string(ipa_opts->id->basic, SDAP_DEREF);
    if (value != NULL) {
        ret = deref_string_to_val(value, &i);
        if (ret != EOK) {
            DEBUG(1, ("Failed to verify ldap_deref option.\n"));
            goto done;
        }
    }

    ret = sdap_get_map(ipa_opts->id, cdb, conf_path,
                       ipa_attr_map,
                       SDAP_AT_GENERAL,
                       &ipa_opts->id->gen_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_user_map,
                       SDAP_OPTS_USER,
                       &ipa_opts->id->user_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_group_map,
                       SDAP_OPTS_GROUP,
                       &ipa_opts->id->group_map);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_get_map(ipa_opts->id,
                       cdb, conf_path,
                       ipa_netgroup_map,
                       SDAP_OPTS_NETGROUP,
                       &ipa_opts->id->netgroup_map);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
    *_opts = ipa_opts->id;

done:
    talloc_zfree(tmpctx);
    if (ret != EOK) {
        talloc_zfree(ipa_opts->id);
    }
    return ret;
}

int ipa_get_auth_options(struct ipa_options *ipa_opts,
                         struct confdb_ctx *cdb,
                         const char *conf_path,
                         struct dp_option **_opts)
{
    char *value;
    char *copy = NULL;
    int ret;

    /* self check test, this should never fail, unless someone forgot
     * to properly update the code after new ldap options have been added */
    if (KRB5_OPTS != IPA_KRB5_OPTS_TEST) {
        DEBUG(0, ("Option numbers do not match (%d != %d)\n",
                   KRB5_OPTS, IPA_KRB5_OPTS_TEST));
        abort();
    }

    ipa_opts->auth = talloc_zero(ipa_opts, struct dp_option);
    if (ipa_opts->auth == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* get krb5 options */
    ret = dp_get_options(ipa_opts, cdb, conf_path,
                         ipa_def_krb5_opts,
                         KRB5_OPTS, &ipa_opts->auth);
    if (ret != EOK) {
        goto done;
    }

    /* If there is no KDC, try the deprecated krb5_kdcip option, too */
    /* FIXME - this can be removed in a future version */
    ret = krb5_try_kdcip(ipa_opts, cdb, conf_path, ipa_opts->auth, KRB5_KDC);
    if (ret != EOK) {
        DEBUG(1, ("sss_krb5_try_kdcip failed.\n"));
        goto done;
    }

    /* set krb realm */
    if (NULL == dp_opt_get_string(ipa_opts->auth, KRB5_REALM)) {
        value = dp_opt_get_string(ipa_opts->basic, IPA_KRB5_REALM);
        if (!value) {
            ret = ENOMEM;
            goto done;
        }
        copy = talloc_strdup(ipa_opts->auth, value);
        if (copy == NULL) {
            DEBUG(1, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
        ret = dp_opt_set_string(ipa_opts->auth, KRB5_REALM, copy);
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  ipa_opts->auth[KRB5_REALM].opt_name,
                  dp_opt_get_string(ipa_opts->auth, KRB5_REALM)));
    }

    *_opts = ipa_opts->auth;
    ret = EOK;

done:
    talloc_free(copy);
    if (ret != EOK) {
        talloc_zfree(ipa_opts->auth);
    }
    return ret;
}

static void ipa_resolve_callback(void *private_data, struct fo_server *server)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ipa_service *service;
    struct resolv_hostent *srvaddr;
    struct sockaddr_storage *sockaddr;
    char *address;
    const char *safe_address;
    char *new_uri;
    const char *srv_name;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed\n"));
        return;
    }

    service = talloc_get_type(private_data, struct ipa_service);
    if (!service) {
        DEBUG(1, ("FATAL: Bad private_data\n"));
        talloc_free(tmp_ctx);
        return;
    }

    srvaddr = fo_get_server_hostent(server);
    if (!srvaddr) {
        DEBUG(1, ("FATAL: No hostent available for server (%s)\n",
                  fo_get_server_str_name(server)));
        talloc_free(tmp_ctx);
        return;
    }

    sockaddr = resolv_get_sockaddr_address(tmp_ctx, srvaddr, LDAP_PORT);
    if (sockaddr == NULL) {
        DEBUG(1, ("resolv_get_sockaddr_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    address = resolv_get_string_address(tmp_ctx, srvaddr);
    if (address == NULL) {
        DEBUG(1, ("resolv_get_string_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    safe_address = sss_ldap_escape_ip_address(tmp_ctx,
                                              srvaddr->family,
                                              address);
    if (safe_address == NULL) {
        DEBUG(1, ("sss_ldap_escape_ip_address failed.\n"));
        talloc_free(tmp_ctx);
        return;
    }

    srv_name = fo_get_server_name(server);
    if (srv_name == NULL) {
        DEBUG(1, ("Could not get server host name\n"));
        talloc_free(tmp_ctx);
        return;
    }

    new_uri = talloc_asprintf(service, "ldap://%s", srv_name);
    if (!new_uri) {
        DEBUG(2, ("Failed to copy URI ...\n"));
        talloc_free(tmp_ctx);
        return;
    }
    DEBUG(6, ("Constructed uri '%s'\n", new_uri));

    /* free old one and replace with new one */
    talloc_zfree(service->sdap->uri);
    service->sdap->uri = new_uri;
    talloc_zfree(service->sdap->sockaddr);
    service->sdap->sockaddr = talloc_steal(service, sockaddr);
    talloc_zfree(service->krb5_service->address);
    service->krb5_service->address = talloc_steal(service, address);

    ret = write_krb5info_file(service->krb5_service->realm, address,
                              SSS_KRB5KDC_FO_SRV);
    if (ret != EOK) {
        DEBUG(2, ("write_krb5info_file failed, authentication might fail.\n"));
    }

    talloc_free(tmp_ctx);
}

int ipa_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                     const char *servers,
                     struct ipa_options *options,
                     struct ipa_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct ipa_service *service;
    char **list = NULL;
    char *realm;
    int ret;
    int i;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    service = talloc_zero(tmp_ctx, struct ipa_service);
    if (!service) {
        ret = ENOMEM;
        goto done;
    }
    service->sdap = talloc_zero(service, struct sdap_service);
    if (!service->sdap) {
        ret = ENOMEM;
        goto done;
    }
    service->krb5_service = talloc_zero(service, struct krb5_service);
    if (!service->krb5_service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(ctx, "IPA");
    if (ret != EOK) {
        DEBUG(1, ("Failed to create failover service!\n"));
        goto done;
    }

    service->sdap->name = talloc_strdup(service, "IPA");
    if (!service->sdap->name) {
        ret = ENOMEM;
        goto done;
    }

    service->krb5_service->name = talloc_strdup(service, "IPA");
    if (!service->krb5_service->name) {
        ret = ENOMEM;
        goto done;
    }
    service->sdap->kinit_service_name = service->krb5_service->name;

    realm = dp_opt_get_string(options->basic, IPA_KRB5_REALM);
    if (!realm) {
        DEBUG(1, ("No Kerberos realm set\n"));
        ret = EINVAL;
        goto done;
    }
    service->krb5_service->realm =
        talloc_strdup(service->krb5_service, realm);
    if (!service->krb5_service->realm) {
        ret = ENOMEM;
        goto done;
    }

    if (!servers) {
        servers = BE_SRV_IDENTIFIER;
    }

    /* split server parm into a list */
    ret = split_on_separator(tmp_ctx, servers, ',', true, &list, NULL);
    if (ret != EOK) {
        DEBUG(1, ("Failed to parse server list!\n"));
        goto done;
    }

    /* now for each one add a new server to the failover service */
    for (i = 0; list[i]; i++) {

        talloc_steal(service, list[i]);

        if (be_fo_is_srv_identifier(list[i])) {
            ret = be_fo_add_srv_server(ctx, "IPA", "ldap",
                                       BE_FO_PROTO_TCP, false, NULL);
            if (ret) {
                DEBUG(0, ("Failed to add server\n"));
                goto done;
            }

            DEBUG(6, ("Added service lookup for service IPA\n"));
            continue;
        }

        ret = be_fo_add_server(ctx, "IPA", list[i], 0, NULL);
        if (ret && ret != EEXIST) {
            DEBUG(0, ("Failed to add server\n"));
            goto done;
        }

        DEBUG(6, ("Added Server %s\n", list[i]));
    }

    ret = be_fo_service_add_callback(memctx, ctx, "IPA",
                                     ipa_resolve_callback, service);
    if (ret != EOK) {
        DEBUG(1, ("Failed to add failover callback!\n"));
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

