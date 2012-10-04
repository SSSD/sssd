/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef AD_OPTS_H_
#define AD_OPTS_H_

#include "src/providers/data_provider.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"

struct dp_option ad_basic_opts[] = {
    { "ad_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_hostname", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    DP_OPTION_TERMINATOR
};

struct dp_option ad_def_ldap_opts[] = {
    { "ldap_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_backup_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_bind_dn", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_authtok_type", DP_OPT_STRING, { "password" }, NULL_STRING},
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
    { "ldap_service_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sudo_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sudo_full_refresh_interval", DP_OPT_NUMBER, { .number = 21600 }, NULL_NUMBER }, /* 360 mins */
    { "ldap_sudo_smart_refresh_interval", DP_OPT_NUMBER, { .number = 900 }, NULL_NUMBER }, /* 15 mins */
    { "ldap_sudo_use_host_filter", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_sudo_hostnames", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sudo_ip", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sudo_include_netgroups", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_sudo_include_regexp", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_autofs_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_schema", DP_OPT_STRING, { "ad" }, NULL_STRING },
    { "ldap_offline_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ldap_force_upper_case_realm", DP_OPT_BOOL, BOOL_TRUE, BOOL_FALSE },
    { "ldap_enumeration_refresh_timeout", DP_OPT_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "ldap_purge_cache_timeout", DP_OPT_NUMBER, { .number = 10800 }, NULL_NUMBER },
    { "ldap_tls_cacert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cacertdir", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_key", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cipher_suite", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_id_use_start_tls", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_id_mapping", DP_OPT_BOOL, BOOL_TRUE, BOOL_FALSE },
    { "ldap_sasl_mech", DP_OPT_STRING, { "gssapi" }, NULL_STRING },
    { "ldap_sasl_authid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sasl_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sasl_minssf", DP_OPT_NUMBER, { .number = -1 }, NULL_NUMBER },
    { "ldap_krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_init_creds", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    /* use the same parm name as the krb5 module so we set it only once */
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_canonicalize", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_pwd_policy", DP_OPT_STRING, { "none" }, NULL_STRING },
    { "ldap_referrals", DP_OPT_BOOL, BOOL_FALSE, BOOL_TRUE },
    { "account_cache_expiration", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    { "ldap_dns_service_name", DP_OPT_STRING, { SSS_LDAP_SRV_NAME }, NULL_STRING },
    { "ldap_krb5_ticket_lifetime", DP_OPT_NUMBER, { .number = (24 * 60 * 60) }, NULL_NUMBER },
    { "ldap_access_filter", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_netgroup_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_group_nesting_level", DP_OPT_NUMBER, { .number = 2 }, NULL_NUMBER },
    { "ldap_deref", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_account_expire_policy", DP_OPT_STRING, { "ad" }, NULL_STRING },
    { "ldap_access_order", DP_OPT_STRING, { "filter" }, NULL_STRING },
    { "ldap_chpass_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_chpass_backup_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_chpass_dns_service_name", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_chpass_update_last_change", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_enumeration_search_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    /* Do not include ldap_auth_disable_tls_never_use_in_production in the
     * manpages or SSSDConfig API
     */
    { "ldap_auth_disable_tls_never_use_in_production", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_page_size", DP_OPT_NUMBER, { .number = 1000 }, NULL_NUMBER },
    { "ldap_deref_threshold", DP_OPT_NUMBER, { .number = 10 }, NULL_NUMBER },
    { "ldap_sasl_canonicalize", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_connection_expire_timeout", DP_OPT_NUMBER, { .number = 900 }, NULL_NUMBER },
    { "ldap_disable_paging", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_idmap_range_min", DP_OPT_NUMBER, { .number = 200000 }, NULL_NUMBER },
    { "ldap_idmap_range_max", DP_OPT_NUMBER, { .number = 2000200000LL }, NULL_NUMBER },
    { "ldap_idmap_range_size", DP_OPT_NUMBER, { .number = 200000 }, NULL_NUMBER },
    { "ldap_idmap_autorid_compat", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_idmap_default_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_idmap_default_domain_sid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_groups_use_matching_rule_in_chain", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_initgroups_use_matching_rule_in_chain", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    DP_OPTION_TERMINATOR
};

struct dp_option ad_def_krb5_opts[] = {
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_ccachedir", DP_OPT_STRING, { DEFAULT_CCACHE_DIR }, NULL_STRING },
    { "krb5_ccname_template", DP_OPT_STRING, { DEFAULT_CCNAME_TEMPLATE }, NULL_STRING},
    { "krb5_auth_timeout", DP_OPT_NUMBER, { .number = 15 }, NULL_NUMBER },
    { "krb5_keytab", DP_OPT_STRING, { "/etc/krb5.keytab" }, NULL_STRING },
    { "krb5_validate", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_store_password_if_offline", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_renewable_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_renew_interval", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER },
    { "krb5_use_fast", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_fast_principal", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_canonicalize", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    DP_OPTION_TERMINATOR
};

struct sdap_attr_map ad_2008r2_attr_map[] = {
    { "ldap_entry_usn", SDAP_AD_USN, SYSDB_USN, NULL },
    { "ldap_rootdse_last_usn", SDAP_AD_LAST_USN, SYSDB_HIGH_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_2008r2_user_map[] = {
    { "ldap_user_object_class", "user", SYSDB_USER_CLASS, NULL },
    { "ldap_user_name", "sAMAccountName", SYSDB_NAME, NULL },
    { "ldap_user_pwd", "unixUserPassword", SYSDB_PWD, NULL },
    { "ldap_user_uid_number", "uidNumber", SYSDB_UIDNUM, NULL },
    { "ldap_user_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_user_gecos", "gecos", SYSDB_GECOS, NULL },
    { "ldap_user_home_directory", "unixHomeDirectory", SYSDB_HOMEDIR, NULL },
    { "ldap_user_shell", "loginShell", SYSDB_SHELL, NULL },
    { "ldap_user_principal", "userPrincipalName", SYSDB_UPN, NULL },
    { "ldap_user_fullname", "name", SYSDB_FULLNAME, NULL },
    { "ldap_user_member_of", "memberOf", SYSDB_MEMBEROF, NULL },
    { "ldap_user_uuid", "objectGUID", SYSDB_UUID, NULL },
    { "ldap_user_objectsid", "objectSID", SYSDB_SID, NULL },
    { "ldap_user_primary_group", "primaryGroupID", SYSDB_PRIMARY_GROUP, NULL },
    { "ldap_user_modify_timestamp", "whenChanged", SYSDB_ORIG_MODSTAMP, NULL },
    { "ldap_user_entry_usn", SDAP_AD_USN, SYSDB_USN, NULL },
    { "ldap_user_shadow_last_change", NULL, SYSDB_SHADOWPW_LASTCHANGE, NULL },
    { "ldap_user_shadow_min", NULL, SYSDB_SHADOWPW_MIN, NULL },
    { "ldap_user_shadow_max", NULL, SYSDB_SHADOWPW_MAX, NULL },
    { "ldap_user_shadow_warning", NULL, SYSDB_SHADOWPW_WARNING, NULL },
    { "ldap_user_shadow_inactive", NULL, SYSDB_SHADOWPW_INACTIVE, NULL },
    { "ldap_user_shadow_expire", NULL, SYSDB_SHADOWPW_EXPIRE, NULL },
    { "ldap_user_shadow_flag", NULL, SYSDB_SHADOWPW_FLAG, NULL },
    { "ldap_user_krb_last_pwd_change", NULL, SYSDB_KRBPW_LASTCHANGE, NULL },
    { "ldap_user_krb_password_expiration", NULL, SYSDB_KRBPW_EXPIRATION, NULL },
    { "ldap_pwd_attribute", NULL, SYSDB_PWD_ATTRIBUTE, NULL },
    { "ldap_user_authorized_service", NULL, SYSDB_AUTHORIZED_SERVICE, NULL },
    { "ldap_user_ad_account_expires", "accountExpires", SYSDB_AD_ACCOUNT_EXPIRES, NULL},
    { "ldap_user_ad_user_account_control", "userAccountControl", SYSDB_AD_USER_ACCOUNT_CONTROL, NULL},
    { "ldap_ns_account_lock", NULL, SYSDB_NS_ACCOUNT_LOCK, NULL},
    { "ldap_user_authorized_host", NULL, SYSDB_AUTHORIZED_HOST, NULL },
    { "ldap_user_nds_login_disabled", NULL, SYSDB_NDS_LOGIN_DISABLED, NULL },
    { "ldap_user_nds_login_expiration_time", NULL, SYSDB_NDS_LOGIN_EXPIRATION_TIME, NULL },
    { "ldap_user_nds_login_allowed_time_map", NULL, SYSDB_NDS_LOGIN_ALLOWED_TIME_MAP, NULL },
    { "ldap_user_ssh_public_key", NULL, SYSDB_SSH_PUBKEY, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_2008r2_group_map[] = {
    { "ldap_group_object_class", "group", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "name", SYSDB_NAME, NULL },
    { "ldap_group_pwd", NULL, SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "member", SYSDB_MEMBER, NULL },
    { "ldap_group_uuid", "objectGUID", SYSDB_UUID, NULL },
    { "ldap_group_objectsid", "objectSID", SYSDB_SID, NULL },
    { "ldap_group_modify_timestamp", "whenChanged", SYSDB_ORIG_MODSTAMP, NULL },
    { "ldap_group_entry_usn", SDAP_AD_USN, SYSDB_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_netgroup_map[] = {
    { "ldap_netgroup_object_class", "nisNetgroup", SYSDB_NETGROUP_CLASS, NULL },
    { "ldap_netgroup_name", "cn", SYSDB_NAME, NULL },
    { "ldap_netgroup_member", "memberNisNetgroup", SYSDB_ORIG_NETGROUP_MEMBER, NULL },
    { "ldap_netgroup_triple", "nisNetgroupTriple", SYSDB_NETGROUP_TRIPLE, NULL },
    /* FIXME: this is 389ds specific */
    { "ldap_netgroup_uuid", "nsUniqueId", SYSDB_UUID, NULL },
    { "ldap_netgroup_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_service_map[] = {
    { "ldap_service_object_class", "ipService", SYSDB_SVC_CLASS, NULL },
    { "ldap_service_name", "cn", SYSDB_NAME, NULL },
    { "ldap_service_port", "ipServicePort", SYSDB_SVC_PORT, NULL },
    { "ldap_service_proto", "ipServiceProtocol", SYSDB_SVC_PROTO, NULL },
    { "ldap_service_entry_usn", NULL, SYSDB_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_autofs_mobject_map[] = {
    { "ldap_autofs_map_object_class", "nisMap", SYSDB_AUTOFS_MAP_OC, NULL },
    { "ldap_autofs_map_name", "nisMapName", SYSDB_AUTOFS_MAP_NAME, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_autofs_entry_map[] = {
    { "ldap_autofs_entry_object_class", "nisObject", SYSDB_AUTOFS_ENTRY_OC, NULL },
    { "ldap_autofs_entry_key", "cn", SYSDB_AUTOFS_ENTRY_KEY, NULL },
    { "ldap_autofs_entry_value", "nisMapEntry", SYSDB_AUTOFS_ENTRY_VALUE, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

#endif /* AD_OPTS_H_ */
