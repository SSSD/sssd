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

#include "util/sss_krb5.h"

/* a fd the child process would log into */
int ldap_child_debug_fd = -1;

struct dp_option default_basic_opts[] = {
    { "ldap_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_search_base", DP_OPT_STRING, { "dc=example,dc=com" }, NULL_STRING },
    { "ldap_default_bind_dn", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_authtok_type", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ldap_default_authtok", DP_OPT_BLOB, NULL_BLOB, NULL_BLOB },
    { "ldap_search_timeout", DP_OPT_NUMBER, { .number = 5 }, NULL_NUMBER },
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
    { "ldap_force_upper_case_realm", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_enumeration_refresh_timeout", DP_OPT_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "ldap_purge_cache_timeout", DP_OPT_NUMBER, { .number = 10800 }, NULL_NUMBER },
    { "entry_cache_timeout", DP_OPT_NUMBER, { .number = 5400 }, NULL_NUMBER },
    { "ldap_tls_cacert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cacertdir", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_id_use_start_tls", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_sasl_mech", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sasl_authid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_init_creds", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    /* use the same parm name as the krb5 module so we set it only once */
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_pwd_policy", DP_OPT_STRING, { "none" } , NULL_STRING },
    { "ldap_referrals", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "account_cache_expiration", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    { "ldap_dns_service_name", DP_OPT_STRING, { SSS_LDAP_SRV_NAME }, NULL_STRING },
    { "ldap_access_filter", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_ticket_lifetime", DP_OPT_NUMBER, { .number = (24 * 60 * 60) }, NULL_NUMBER }
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
    const char *pwd_policy;
    int ret;
    int account_cache_expiration;
    int offline_credentials_expiration;

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
    ret = confdb_get_int(cdb, memctx, CONFDB_PAM_CONF_ENTRY,
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
        ctx->gsh->connected = false;
    }

    be_mark_offline(ctx->be);
}

bool sdap_check_gssapi_reconnect(struct sdap_id_ctx *ctx)
{
    int ret;
    bool result = false;
    const char *mech;
    const char *realm;
    char *ccname = NULL;
    krb5_context context = NULL;
    krb5_ccache ccache = NULL;
    krb5_error_code krberr;
    TALLOC_CTX *tmp_ctx = NULL;
    krb5_creds mcred;
    krb5_creds cred;
    char *server_name = NULL;
    char *client_princ_str = NULL;
    char *full_princ = NULL;
    krb5_principal client_principal = NULL;
    krb5_principal server_principal = NULL;
    char hostname[512];
    int l_errno;


    mech = dp_opt_get_string(ctx->opts->basic, SDAP_SASL_MECH);
    if (mech == NULL || strcasecmp(mech, "GSSAPI") != 0) {
        return false;
    }

    realm = dp_opt_get_string(ctx->opts->basic, SDAP_KRB5_REALM);
    if (realm == NULL) {
        DEBUG(3, ("Kerberos realm not available.\n"));
        return false;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return false;
    }

    ccname = talloc_asprintf(tmp_ctx, "FILE:%s/ccache_%s", DB_PATH, realm);
    if (ccname == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        goto done;
    }

    krberr = krb5_init_context(&context);
    if (krberr) {
        DEBUG(1, ("Failed to init kerberos context\n"));
        goto done;
    }

    krberr = krb5_cc_resolve(context, ccname, &ccache);
    if (krberr != 0) {
        DEBUG(1, ("krb5_cc_resolve failed.\n"));
        goto done;
    }

    server_name = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s", realm, realm);
    if (server_name == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        goto done;
    }

    krberr = krb5_parse_name(context, server_name, &server_principal);
    if (krberr != 0) {
        DEBUG(1, ("krb5_parse_name failed.\n"));
        goto done;
    }

    client_princ_str = dp_opt_get_string(ctx->opts->basic, SDAP_SASL_AUTHID);
    if (client_princ_str) {
        if (!strchr(client_princ_str, '@')) {
            full_princ = talloc_asprintf(tmp_ctx, "%s@%s", client_princ_str,
                                         realm);
        } else {
            full_princ = talloc_strdup(tmp_ctx, client_princ_str);
        }
    } else {
        ret = gethostname(hostname, sizeof(hostname)-1);
        if (ret == -1) {
            l_errno = errno;
            DEBUG(1, ("gethostname failed [%d][%s].\n", l_errno,
                                                        strerror(l_errno)));
            goto done;
        }
        hostname[sizeof(hostname)-1] = '\0';

        full_princ = talloc_asprintf(tmp_ctx, "host/%s@%s", hostname, realm);
    }
    if (!full_princ) {
        DEBUG(1, ("Client principal not available.\n"));
        goto done;
    }
    DEBUG(7, ("Client principal name is: [%s]\n", full_princ));
    krberr = krb5_parse_name(context, full_princ, &client_principal);
    if (krberr != 0) {
        DEBUG(1, ("krb5_parse_name failed.\n"));
        goto done;
    }

    memset(&mcred, 0, sizeof(mcred));
    memset(&cred, 0, sizeof(mcred));
    mcred.client = client_principal;
    mcred.server = server_principal;

    krberr = krb5_cc_retrieve_cred(context, ccache, 0, &mcred, &cred);
    if (krberr != 0) {
        DEBUG(1, ("krb5_cc_retrieve_cred failed.\n"));
        goto done;
    }

    DEBUG(7, ("TGT end time [%d].\n", cred.times.endtime));

    if (cred.times.endtime <= time(NULL)) {
        DEBUG(3, ("TGT is expired.\n"));
        result = true;
    }
    krb5_free_cred_contents(context, &cred);

done:
    if (client_principal != NULL) {
        krb5_free_principal(context, client_principal);
    }
    if (server_principal != NULL) {
        krb5_free_principal(context, server_principal);
    }
    if (ccache != NULL) {
        if (result) {
            krb5_cc_destroy(context, ccache);
        } else {
            krb5_cc_close(context, ccache);
        }
    }
    if (context != NULL) krb5_free_context(context);
    talloc_free(tmp_ctx);
    return result;
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

static void sdap_uri_callback(void *private_data, struct fo_server *server)
{
    struct sdap_service *service;
    const char *tmp;
    char *new_uri;

    service = talloc_get_type(private_data, struct sdap_service);
    if (!service) return;

    tmp = (const char *)fo_get_server_user_data(server);

    if (fo_is_srv_lookup(server)) {
        if (!tmp) {
            DEBUG(1, ("Unknown service, using ldap\n"));
            tmp = SSS_LDAP_SRV_NAME;
        }
        new_uri = talloc_asprintf(service, "%s://%s:%d",
                                  tmp,
                                  fo_get_server_name(server),
                                  fo_get_server_port(server));
    } else {
        if (tmp && ldap_is_ldap_url(tmp)) {
            new_uri = talloc_strdup(service, tmp);
        } else {
            new_uri = talloc_asprintf(service, "ldap://%s",
                                    fo_get_server_name(server));
        }
    }

    if (!new_uri) {
        DEBUG(2, ("Failed to copy URI ...\n"));
        return;
    }

    DEBUG(6, ("Constructed uri '%s'\n", new_uri));

    /* free old one and replace with new one */
    talloc_zfree(service->uri);
    service->uri = new_uri;
}

int sdap_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name, const char *dns_service_name,
                      const char *urls, struct sdap_service **_service)
{
    TALLOC_CTX *tmp_ctx;
    struct sdap_service *service;
    LDAPURLDesc *lud;
    char **list = NULL;
    char *srv_user_data;
    int ret;
    int i;

    tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    service = talloc_zero(tmp_ctx, struct sdap_service);
    if (!service) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_fo_add_service(ctx, service_name);
    if (ret != EOK) {
        DEBUG(1, ("Failed to create failover service!\n"));
        goto done;
    }

    service->name = talloc_strdup(service, service_name);
    if (!service->name) {
        ret = ENOMEM;
        goto done;
    }

    if (!urls) {
        urls = BE_SRV_IDENTIFIER;
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
            srv_user_data = talloc_strdup(service, dns_service_name);
            if (!srv_user_data) {
                ret = ENOMEM;
                goto done;
            }

            ret = be_fo_add_srv_server(ctx, service_name,
                                       dns_service_name, FO_PROTO_TCP,
                                       ctx->domain->name,
                                       srv_user_data);
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

        DEBUG(6, ("Added URI %s\n", list[i]));

        talloc_steal(service, list[i]);

        ret = be_fo_add_server(ctx, service->name,
                               lud->lud_host, lud->lud_port, list[i]);
        if (ret) {
            goto done;
        }
        ldap_free_urldesc(lud);
    }

    ret = be_fo_service_add_callback(memctx, ctx, service->name,
                                     sdap_uri_callback, service);
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

void sdap_gsh_disconnect_callback(void *pvt)
{
    struct sdap_id_ctx *ctx = talloc_get_type(pvt, struct sdap_id_ctx);

    if (ctx->gsh) {
        ctx->gsh->connected = false;
    }
}
