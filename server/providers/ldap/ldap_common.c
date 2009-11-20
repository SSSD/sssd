/*
    SSSD

    LDAP Provider Common Functions

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2008-2009 Red Hat

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

struct dp_option default_basic_opts[] = {
    { "ldap_uri", DP_OPT_STRING, { "ldap://localhost" }, NULL_STRING },
    { "ldap_search_base", DP_OPT_STRING, { "dc=example,dc=com" }, NULL_STRING },
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
    { "ldap_schema", DP_OPT_STRING, { "rfc2307" }, NULL_STRING },
    { "ldap_offline_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ldap_force_upper_case_realm", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_enumeration_refresh_timeout", DP_OPT_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "ldap_purge_cache_timeout", DP_OPT_NUMBER, { .number = 3600 }, NULL_NUMBER },
    { "entry_cache_timoeut", DP_OPT_NUMBER, { .number = 1800 }, NULL_NUMBER },
    { "ldap_tls_cacert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cacertdir", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_id_use_start_tls", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_sasl_mech", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sasl_authid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_init_creds", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    /* use the same parm name as the krb5 module so we set it only once */
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING }
};

struct sdap_attr_map generic_attr_map[] = {
    { "ldap_entry_usn", NULL, SYSDB_USN, NULL },
    { "ldap_rootdse_last_usn", NULL, SYSDB_USN, NULL }
};

struct sdap_attr_map gen_ipa_attr_map[] = {
    { "ldap_entry_usn", "entryUSN", SYSDB_USN, NULL },
    { "ldap_rootdse_last_usn", "lastUSN", SYSDB_HIGH_USN, NULL }
};

struct sdap_attr_map gen_ad_attr_map[] = {
    { "ldap_entry_usn", "uSNChanged", SYSDB_USN, NULL },
    { "ldap_rootdse_last_usn", "highestCommittedUSN", SYSDB_HIGH_USN, NULL }
};

struct sdap_attr_map rfc2307_user_map[] = {
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
    { "ldap_user_member_of", NULL, SYSDB_MEMBEROF, NULL },
    { "ldap_user_uuid", NULL, SYSDB_UUID, NULL },
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

struct sdap_attr_map rfc2307_group_map[] = {
    { "ldap_group_object_class", "posixGroup", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "cn", SYSDB_NAME, NULL },
    { "ldap_group_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "memberuid", SYSDB_MEMBER, NULL },
    { "ldap_group_uuid", NULL, SYSDB_UUID, NULL },
    { "ldap_group_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL }
};

struct sdap_attr_map rfc2307bis_user_map[] = {
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
    /* FIXME: this is 389ds specific */
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

struct sdap_attr_map rfc2307bis_group_map[] = {
    { "ldap_group_object_class", "posixGroup", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "cn", SYSDB_NAME, NULL },
    { "ldap_group_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "member", SYSDB_MEMBER, NULL },
    /* FIXME: this is 389ds specific */
    { "ldap_group_uuid", "nsUniqueId", SYSDB_UUID, NULL },
    { "ldap_group_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL }
};

int ldap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts)
{
    struct sdap_attr_map *default_attr_map;
    struct sdap_attr_map *default_user_map;
    struct sdap_attr_map *default_group_map;
    struct sdap_options *opts;
    char *schema;
    int ret;

    opts = talloc_zero(memctx, struct sdap_options);
    if (!opts) return ENOMEM;

    ret = dp_get_options(opts, cdb, conf_path,
                         default_basic_opts,
                         SDAP_OPTS_BASIC,
                         &opts->basic);
    if (ret != EOK) {
        goto done;
    }

    /* set user/group search bases if they are not */
    if (NULL == dp_opt_get_string(opts->basic, SDAP_USER_SEARCH_BASE)) {
        ret = dp_opt_set_string(opts->basic, SDAP_USER_SEARCH_BASE,
                                dp_opt_get_string(opts->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  opts->basic[SDAP_USER_SEARCH_BASE].opt_name,
                  dp_opt_get_string(opts->basic, SDAP_USER_SEARCH_BASE)));
    }

    if (NULL == dp_opt_get_string(opts->basic, SDAP_GROUP_SEARCH_BASE)) {
        ret = dp_opt_set_string(opts->basic, SDAP_GROUP_SEARCH_BASE,
                                dp_opt_get_string(opts->basic,
                                                  SDAP_SEARCH_BASE));
        if (ret != EOK) {
            goto done;
        }
        DEBUG(6, ("Option %s set to %s\n",
                  opts->basic[SDAP_GROUP_SEARCH_BASE].opt_name,
                  dp_opt_get_string(opts->basic, SDAP_GROUP_SEARCH_BASE)));
    }

    /* schema type */
    schema = dp_opt_get_string(opts->basic, SDAP_SCHEMA);
    if (strcasecmp(schema, "rfc2307") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307;
        default_attr_map = generic_attr_map;
        default_user_map = rfc2307_user_map;
        default_group_map = rfc2307_group_map;
    } else
    if (strcasecmp(schema, "rfc2307bis") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307BIS;
        default_attr_map = generic_attr_map;
        default_user_map = rfc2307bis_user_map;
        default_group_map = rfc2307bis_group_map;
    } else
    if (strcasecmp(schema, "IPA") == 0) {
        opts->schema_type = SDAP_SCHEMA_IPA_V1;
        default_attr_map = gen_ipa_attr_map;
        default_user_map = rfc2307bis_user_map;
        default_group_map = rfc2307bis_group_map;
    } else
    if (strcasecmp(schema, "AD") == 0) {
        opts->schema_type = SDAP_SCHEMA_AD;
        default_attr_map = gen_ad_attr_map;
        default_user_map = rfc2307bis_user_map;
        default_group_map = rfc2307bis_group_map;
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

    ret = EOK;
    *_opts = opts;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }
    return ret;
}

void sdap_handler_done(struct be_req *req, int dp_err,
                       int error, const char *errstr)
{
    return req->fn(req, dp_err, error, errstr);
}

bool sdap_connected(struct sdap_id_ctx *ctx)
{
    if (ctx->gsh) {
        return ctx->gsh->connected;
    }

    return false;
}

void sdap_mark_offline(struct sdap_id_ctx *ctx)
{
    if (ctx->gsh) {
        /* make sure we mark the connection as gone when we go offline so that
         * we do not try to reuse a bad connection by mistale later */
        talloc_zfree(ctx->gsh);
    }

    be_mark_offline(ctx->be);
}


int sdap_id_setup_tasks(struct sdap_id_ctx *ctx)
{
    struct timeval tv;
    int ret = EOK;

    /* set up enumeration task */
    if (ctx->be->domain->enumerate) {
        /* run the first one in a couple of seconds so that we have time to
         * finish initializations first*/
        tv = tevent_timeval_current_ofs(10, 0);
        ret = ldap_id_enumerate_set_timer(ctx, tv);
    } else {
        /* the enumeration task, runs the cleanup process by itself,
         * but if enumeration is not runnig we need to schedule it */

        /* run the first one in a couple of seconds so that we have time to
         * finish initializations first*/
        tv = tevent_timeval_current_ofs(10, 0);
        ret = ldap_id_cleanup_set_timer(ctx, tv);
    }

    return ret;
}
