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

#include <ctype.h>
#include "providers/ipa/ipa_common.h"

struct dp_option ipa_basic_opts[] = {
    { "ipa_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_hostname", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_search_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ipa_network_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "ipa_opt_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "ipa_offline_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ipa_enumeration_refresh_timeout", DP_OPT_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "ipa_stale_time", DP_OPT_NUMBER, { .number = 1800 }, NULL_NUMBER },
};

struct dp_option ipa_def_ldap_opts[] = {
    { "ldap_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_bind_dn", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_authtok_type", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ldap_default_authtok", DP_OPT_BLOB, NULL_BLOB, NULL_BLOB },
    { "ldap_search_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
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
    { "ldap_stale_time", DP_OPT_NUMBER, { .number = 1800 }, NULL_NUMBER },
    { "ldap_tls_cacert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cacertdir", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_id_use_start_tls", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_sasl_mech", DP_OPT_STRING, { "GSSAPI" } , NULL_STRING },
    { "ldap_sasl_authid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_init_creds", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    /* use the same parm name as the krb5 module so we set it only once */
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING }
};

struct sdap_id_map ipa_user_map[] = {
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
    { "ldap_user_shadow_last_change", "shadowLastChange", SYSDB_SHADOWPW_LASTCHANGE, NULL },
    { "ldap_user_shadow_min", "shadowMin", SYSDB_SHADOWPW_MIN, NULL },
    { "ldap_user_shadow_max", "shadowMax", SYSDB_SHADOWPW_MAX, NULL },
    { "ldap_user_shadow_warning", "shadowWarning", SYSDB_SHADOWPW_WARNING, NULL },
    { "ldap_user_shadow_inactive", "shadowInactive", SYSDB_SHADOWPW_INACTIVE, NULL },
    { "ldap_user_shadow_expire", "shadowExpire", SYSDB_SHADOWPW_EXPIRE, NULL },
    { "ldap_user_shadow_flag", "shadowFlag", SYSDB_SHADOWPW_FLAG, NULL },
    { "ldap_user_krb_last_pwd_change", "krbLastPwdChange", SYSDB_KRBPW_LASTCHANGE, NULL },
    { "ldap_user_krb_password_expiration", "krbPasswordExpiration", SYSDB_KRBPW_EXPIRATION, NULL },
    { "ldap_pwd_attribute", "pwdAttribute", SYSDB_PWD_ATTRIBUTE, NULL }
};

struct sdap_id_map ipa_group_map[] = {
    { "ldap_group_object_class", "posixGroup", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "cn", SYSDB_NAME, NULL },
    { "ldap_group_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "member", SYSDB_MEMBER, NULL },
    { "ldap_group_uuid", "nsUniqueId", SYSDB_UUID, NULL },
    { "ldap_group_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL }
};

struct dp_option ipa_def_krb5_opts[] = {
    { "krb5_kdcip", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_ccachedir", DP_OPT_STRING, { "/tmp" }, NULL_STRING },
    { "krb5_ccname_tmpl", DP_OPT_STRING, { "FILE:%d/krb5cc_%U_XXXXXX" }, NULL_STRING},
    { "krb5_changepw_princ", DP_OPT_STRING, { "kadmin/changepw" }, NULL_STRING },
    { "krb5_auth_timeout", DP_OPT_NUMBER, { .number = 15 }, NULL_NUMBER },
};

int domain_to_basedn(TALLOC_CTX *memctx, const char *domain, char **basedn)
{
    const char *s;
    char *dn;
    char *p;
    int l;

    s = domain;
    dn = talloc_strdup(memctx, "dc=");

    while ((p = strchr(s, '.'))) {
        l = p - s;
        dn = talloc_asprintf_append_buffer(dn, "%.*s,dc=", l, s);
        if (!dn) {
            return ENOMEM;
        }
        s = p + 1;
    }
    dn = talloc_strdup_append_buffer(dn, s);
    if (!dn) {
        return ENOMEM;
    }

    *basedn = dn;
    return EOK;
}

int ipa_get_options(TALLOC_CTX *memctx,
                    struct confdb_ctx *cdb,
                    const char *conf_path,
                    struct sss_domain_info *dom,
                    struct ipa_options **_opts)
{
    struct ipa_options *opts;
    char *domain;
    char *server;
    int ret;

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
    }

    /* FIXME: Make non-fatal once we have discovery */
    server = dp_opt_get_string(opts->basic, IPA_SERVER);
    if (!server) {
        DEBUG(0, ("Can't find ipa server, missing option!\n"));
        ret = EINVAL;
        goto done;
    }

    ret = EOK;
    *_opts = opts;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }
    return ret;
}

/* the following preprocessor code is used to keep track of
 * the options in the ldap module, so that if they change and ipa
 * is not updated correspondingly this will trigger a build error */
#if SDAP_OPTS_BASIC > 27
#error There are ldap options not accounted for
#endif

int ipa_get_id_options(TALLOC_CTX *memctx,
                       struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct ipa_options *ipa_opts,
                       struct sdap_options **_opts)
{
    TALLOC_CTX *tmpctx;
    char *hostname;
    char *basedn;
    char *realm;
    char *value;
    int ret;
    int i;

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    ipa_opts->id = talloc_zero(memctx, struct sdap_options);
    if (!ipa_opts->id) {
        ret = ENOMEM;
        goto done;
    }

    /* generate sdap options */
    ret = dp_copy_options(ipa_opts, ipa_def_ldap_opts,
                          SDAP_OPTS_BASIC, &ipa_opts->id->basic);
    if (ret != EOK) {
        goto done;
    }

    /* set ldap_uri */
    value = talloc_asprintf(tmpctx, "ldap://%s",
                            dp_opt_get_string(ipa_opts->basic, IPA_SERVER));
    if (!value) {
        ret = ENOMEM;
        goto done;
    }
    ret = dp_opt_set_string(ipa_opts->id->basic, SDAP_URI, value);
    if (ret != EOK) {
        goto done;
    }

    ret = domain_to_basedn(tmpctx,
                           dp_opt_get_string(ipa_opts->basic, IPA_DOMAIN),
                           &basedn);
    if (ret != EOK) {
        goto done;
    }

    /* FIXME: get values by querying IPA */
    /* set ldap_user_search_base */
    value = talloc_asprintf(tmpctx, "cn=users,cn=accounts,%s", basedn);
    if (!value) {
        ret = ENOMEM;
        goto done;
    }
    ret = dp_opt_set_string(ipa_opts->id->basic,
                            SDAP_USER_SEARCH_BASE, value);
    if (ret != EOK) {
        goto done;
    }

    /* set ldap_group_search_base */
    value = talloc_asprintf(tmpctx, "cn=groups,cn=accounts,%s", basedn);
    if (!value) {
        ret = ENOMEM;
        goto done;
    }
    ret = dp_opt_set_string(ipa_opts->id->basic,
                            SDAP_GROUP_SEARCH_BASE, value);
    if (ret != EOK) {
        goto done;
    }

    /* set the ldap_sasl_authid if the ipa_hostname override was specified */
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

    /* set krb realm */
    realm = dp_opt_get_string(ipa_opts->basic, IPA_DOMAIN);
    for (i = 0; realm[i]; i++) {
        realm[i] = toupper(realm[i]);
    }
    ret = dp_opt_set_string(ipa_opts->id->basic,
                            SDAP_KRB5_REALM, realm);
    if (ret != EOK) {
        goto done;
    }

    /* fix schema to IPAv1 for now */
    ipa_opts->id->schema_type = SDAP_SCHEMA_IPA_V1;

    /* copy over timeouts */
    ret = dp_opt_set_int(ipa_opts->id->basic,
                         SDAP_SEARCH_TIMEOUT,
                         dp_opt_get_int(ipa_opts->basic,
                                        IPA_SEARCH_TIMEOUT));
    ret = dp_opt_set_int(ipa_opts->id->basic,
                         SDAP_NETWORK_TIMEOUT,
                         dp_opt_get_int(ipa_opts->basic,
                                        IPA_NETWORK_TIMEOUT));
    ret = dp_opt_set_int(ipa_opts->id->basic,
                         SDAP_OPT_TIMEOUT,
                         dp_opt_get_int(ipa_opts->basic,
                                        IPA_OPT_TIMEOUT));
    ret = dp_opt_set_int(ipa_opts->id->basic,
                         SDAP_OFFLINE_TIMEOUT,
                         dp_opt_get_int(ipa_opts->basic,
                                        IPA_OFFLINE_TIMEOUT));
    ret = dp_opt_set_int(ipa_opts->id->basic,
                         SDAP_ENUM_REFRESH_TIMEOUT,
                         dp_opt_get_int(ipa_opts->basic,
                                        IPA_ENUM_REFRESH_TIMEOUT));
    ret = dp_opt_set_int(ipa_opts->id->basic,
                         SDAP_STALE_TIME,
                         dp_opt_get_int(ipa_opts->basic,
                                        IPA_STALE_TIME));

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

    ret = EOK;
    *_opts = ipa_opts->id;

done:
    talloc_zfree(tmpctx);
    if (ret != EOK) {
        talloc_zfree(ipa_opts->id);
    }
    return ret;
}

/* the following preprocessor code is used to keep track of
 * the options in the krb5 module, so that if they change and ipa
 * is not updated correspondingly this will trigger a build error */
#if KRB5_OPTS > 6
#error There are krb5 options not accounted for
#endif

int ipa_get_auth_options(TALLOC_CTX *memctx,
                         struct confdb_ctx *cdb,
                         const char *conf_path,
                         struct ipa_options *ipa_opts,
                         struct dp_option **_opts)
{
    int ret;
    int i;
    TALLOC_CTX *tmpctx;
    struct dp_option *opts;
    char *value;

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    opts = talloc_zero(memctx, struct dp_option);
    if (opts == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = dp_copy_options(ipa_opts, ipa_def_krb5_opts,
                          KRB5_OPTS, &opts);
    if (ret != EOK) {
        goto done;
    }

    value = dp_opt_get_string(ipa_opts->basic, IPA_SERVER);
    if (!value) {
        ret = ENOMEM;
        goto done;
    }
    ret = dp_opt_set_string(opts, KRB5_KDC, value);
    if (ret != EOK) {
        goto done;
    }


    value = dp_opt_get_string(ipa_opts->basic, IPA_DOMAIN);
    if (!value) {
        ret = ENOMEM;
        goto done;
    }
    for (i = 0; value[i]; i++) {
        value[i] = toupper(value[i]);
    }
    ret = dp_opt_set_string(opts, KRB5_REALM, value);
    if (ret != EOK) {
        goto done;
    }

    *_opts = opts;
    ret = EOK;

done:
    talloc_zfree(tmpctx);
    if (ret != EOK) {
        talloc_zfree(opts);
    }
    return ret;
}
