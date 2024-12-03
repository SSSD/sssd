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

#include "src/providers/data_provider.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"
#include "db/sysdb_sudo.h"
#include "db/sysdb_iphosts.h"
#include "db/sysdb_ipnetworks.h"
#include "providers/ldap/ldap_common.h"
#include "config.h"

struct dp_option ad_basic_opts[] = {
    { "ad_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_enabled_domains", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_hostname", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ad_enable_dns_sites", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ad_access_filter", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ad_enable_gc", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ad_gpo_access_control", DP_OPT_STRING, { AD_GPO_ACCESS_MODE_DEFAULT }, NULL_STRING },
    { "ad_gpo_implicit_deny", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ad_gpo_ignore_unreadable", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ad_gpo_cache_timeout", DP_OPT_NUMBER, { .number = 5 }, NULL_NUMBER },
    { "ad_gpo_map_interactive", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_gpo_map_remote_interactive", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_gpo_map_network", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_gpo_map_batch", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_gpo_map_service", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_gpo_map_permit", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_gpo_map_deny", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_gpo_default_right", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_site", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_confd_path", DP_OPT_STRING, { KRB5_MAPPING_DIR }, NULL_STRING },
    { "ad_maximum_machine_account_password_age", DP_OPT_NUMBER, { .number = 30 }, NULL_NUMBER },
    { "ad_machine_account_password_renewal_opts", DP_OPT_STRING, { "86400:750:300" }, NULL_STRING },
    { "ad_update_samba_machine_account_password", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ad_use_ldaps", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
#ifdef BUILD_ALLOW_REMOTE_DOMAIN_LOCAL_GROUPS
    { "ad_allow_remote_domain_local_groups", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
#endif
    DP_OPTION_TERMINATOR
};

struct dp_option ad_def_ldap_opts[] = {
    { "ldap_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_backup_uri", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_bind_dn", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_authtok_type", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ldap_default_authtok", DP_OPT_BLOB, NULL_BLOB, NULL_BLOB },
    { "ldap_search_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "ldap_network_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "ldap_opt_timeout", DP_OPT_NUMBER, { .number = 8 }, NULL_NUMBER },
    { "ldap_tls_reqcert", DP_OPT_STRING, { "hard" }, NULL_STRING },
    { "ldap_user_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_user_search_scope", DP_OPT_STRING, { "sub" }, NULL_STRING },
    { "ldap_user_search_filter", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_user_extra_attrs", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_group_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_group_search_scope", DP_OPT_STRING, { "sub" }, NULL_STRING },
    { "ldap_group_search_filter", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_host_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_service_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sudo_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sudo_full_refresh_interval", DP_OPT_NUMBER, { .number = 21600 }, NULL_NUMBER }, /* 360 mins */
    { "ldap_sudo_smart_refresh_interval", DP_OPT_NUMBER, { .number = 900 }, NULL_NUMBER }, /* 15 mins */
    { "ldap_sudo_random_offset", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER }, /* disabled */
    { "ldap_sudo_use_host_filter", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_sudo_hostnames", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sudo_ip", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sudo_include_netgroups", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_sudo_include_regexp", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_autofs_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_autofs_map_master_name", DP_OPT_STRING, { "auto.master" }, NULL_STRING },
    { "ldap_iphost_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_ipnetwork_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_schema", DP_OPT_STRING, { "ad" }, NULL_STRING },
    { "ldap_pwmodify_mode", DP_OPT_STRING, { "exop" }, NULL_STRING },
    { "ldap_offline_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ldap_force_upper_case_realm", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_enumeration_refresh_timeout", DP_OPT_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "ldap_enumeration_refresh_offset", DP_OPT_NUMBER, { .number = 30 }, NULL_NUMBER },
    { "ldap_purge_cache_timeout", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    { "ldap_purge_cache_offset", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    { "ldap_tls_cacert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cacertdir", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_key", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cipher_suite", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_id_use_start_tls", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_id_mapping", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_sasl_mech", DP_OPT_STRING, { "GSS-SPNEGO" }, NULL_STRING },
    { "ldap_sasl_authid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sasl_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sasl_minssf", DP_OPT_NUMBER, { .number = -1 }, NULL_NUMBER },
    { "ldap_sasl_maxssf", DP_OPT_NUMBER, { .number = -1 }, NULL_NUMBER },
    { "ldap_krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_init_creds", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    /* use the same parm name as the krb5 module so we set it only once */
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_canonicalize", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_use_kdcinfo", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kdcinfo_lookahead", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_pwd_policy", DP_OPT_STRING, { "none" }, NULL_STRING },
    { "ldap_referrals", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
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
    { "ldap_ignore_unreadable_references", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_sasl_canonicalize", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_connection_expire_timeout", DP_OPT_NUMBER, { .number = 900 }, NULL_NUMBER },
    { "ldap_connection_expire_offset", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    { "ldap_connection_idle_timeout", DP_OPT_NUMBER, { .number = 900 }, NULL_NUMBER },
    { "ldap_disable_paging", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_idmap_range_min", DP_OPT_NUMBER, { .number = 200000 }, NULL_NUMBER },
    { "ldap_idmap_range_max", DP_OPT_NUMBER, { .number = 2000200000LL }, NULL_NUMBER },
    { "ldap_idmap_range_size", DP_OPT_NUMBER, { .number = 200000 }, NULL_NUMBER },
    { "ldap_idmap_autorid_compat", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_idmap_default_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_idmap_default_domain_sid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_idmap_helper_table_size", DP_OPT_NUMBER, { .number = 10 }, NULL_NUMBER },
    { "ldap_use_tokengroups", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE},
    { "ldap_rfc2307_fallback_to_local_users", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_disable_range_retrieval", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_min_id", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER},
    { "ldap_max_id", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER},
    { "ldap_pwdlockout_dn", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "wildcard_limit", DP_OPT_NUMBER, { .number = 1000 }, NULL_NUMBER},
    { "ldap_library_debug_level", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER},
    { "ldap_use_ppolicy", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_ppolicy_pwd_change_threshold", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    DP_OPTION_TERMINATOR
};

struct dp_option ad_def_krb5_opts[] = {
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_ccachedir", DP_OPT_STRING, { DEFAULT_CCACHE_DIR }, NULL_STRING },
    { "krb5_ccname_template", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "krb5_auth_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_validate", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_store_password_if_offline", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_renewable_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_renew_interval", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_use_fast", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_fast_principal", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_fast_use_anonymous_pkinit", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_canonicalize", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_use_enterprise_principal", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_use_kdcinfo", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kdcinfo_lookahead", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_map_user", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_use_subdomain_realm", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
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
    { "ldap_user_authorized_rhost", NULL, SYSDB_AUTHORIZED_RHOST, NULL },
    { "ldap_user_nds_login_disabled", NULL, SYSDB_NDS_LOGIN_DISABLED, NULL },
    { "ldap_user_nds_login_expiration_time", NULL, SYSDB_NDS_LOGIN_EXPIRATION_TIME, NULL },
    { "ldap_user_nds_login_allowed_time_map", NULL, SYSDB_NDS_LOGIN_ALLOWED_TIME_MAP, NULL },
    { "ldap_user_ssh_public_key", NULL, SYSDB_SSH_PUBKEY, NULL },
    { "ldap_user_auth_type", NULL, SYSDB_AUTH_TYPE, NULL },
    { "ldap_user_certificate", "userCertificate;binary", SYSDB_USER_CERT, NULL },
    { "ldap_user_email", "mail", SYSDB_USER_EMAIL, NULL },
    { SDAP_ATTR_MAP_NO_OPT, "sAMAccountName", SYSDB_AD_SAMACCOUNTNAME, NULL },
    { "ldap_user_passkey", "altSecurityIdentities", SYSDB_USER_PASSKEY, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_2008r2_group_map[] = {
    { "ldap_group_object_class", "group", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_object_class_alt", NULL, SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "sAMAccountName", SYSDB_NAME, NULL },
    { "ldap_group_pwd", NULL, SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "member", SYSDB_MEMBER, NULL },
    { "ldap_group_uuid", "objectGUID", SYSDB_UUID, NULL },
    { "ldap_group_objectsid", "objectSID", SYSDB_SID, NULL },
    { "ldap_group_modify_timestamp", "whenChanged", SYSDB_ORIG_MODSTAMP, NULL },
    { "ldap_group_entry_usn", SDAP_AD_USN, SYSDB_USN, NULL },
    { "ldap_group_type", "groupType", SYSDB_GROUP_TYPE, NULL },
    { "ldap_group_external_member", NULL, SYSDB_EXTERNAL_MEMBER, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_netgroup_map[] = {
    { "ldap_netgroup_object_class", "nisNetgroup", SYSDB_NETGROUP_CLASS, NULL },
    { "ldap_netgroup_name", "cn", SYSDB_NAME, NULL },
    { "ldap_netgroup_member", "memberNisNetgroup", SYSDB_ORIG_NETGROUP_MEMBER, NULL },
    { "ldap_netgroup_triple", "nisNetgroupTriple", SYSDB_NETGROUP_TRIPLE, NULL },
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

struct sdap_attr_map ad_iphost_map[] = {
    { "ldap_iphost_object_class", "device", SYSDB_IP_HOST_CLASS, NULL },
    { "ldap_iphost_name", "cn", SYSDB_NAME, NULL },
    { "ldap_iphost_number", "ipHostNumber", SYSDB_IP_HOST_ATTR_ADDRESS, NULL },
    { "ldap_iphost_entry_usn", NULL, SYSDB_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ad_ipnetwork_map[] = {
    { "ldap_ipnetwork_object_class", "ipNetwork", SYSDB_IP_NETWORK_CLASS, NULL },
    { "ldap_ipnetwork_name", "cn", SYSDB_NAME, NULL },
    { "ldap_ipnetwork_number", "ipNetworkNumber", SYSDB_IP_NETWORK_ATTR_NUMBER, NULL },
    { "ldap_ipnetwork_entry_usn", NULL, SYSDB_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct dp_option ad_dyndns_opts[] = {
    { "dyndns_update", DP_OPT_BOOL, BOOL_TRUE, BOOL_FALSE },
    { "dyndns_update_per_family", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "dyndns_refresh_interval", DP_OPT_NUMBER, { .number = 86400 }, NULL_NUMBER },
    { "dyndns_refresh_interval_offset", DP_OPT_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "dyndns_iface", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_ttl", DP_OPT_NUMBER, { .number = 3600 }, NULL_NUMBER },
    { "dyndns_update_ptr", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "dyndns_force_tcp", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "dyndns_auth", DP_OPT_STRING, { "gss-tsig" }, NULL_STRING },
    { "dyndns_auth_ptr", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_dot_cacert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_dot_cert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_dot_key", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    DP_OPTION_TERMINATOR
};

struct sdap_attr_map ad_sudorule_map[] = {
    { "ldap_sudorule_object_class", "sudoRole", SYSDB_SUDO_CACHE_OC, NULL },
    { "ldap_sudorule_object_class_attr", "objectCategory", SYSDB_OBJECTCATEGORY, NULL },
    { "ldap_sudorule_name", "cn", SYSDB_SUDO_CACHE_AT_CN, NULL },
    { "ldap_sudorule_command", "sudoCommand", SYSDB_SUDO_CACHE_AT_COMMAND, NULL },
    { "ldap_sudorule_host", "sudoHost", SYSDB_SUDO_CACHE_AT_HOST, NULL },
    { "ldap_sudorule_user", "sudoUser", SYSDB_SUDO_CACHE_AT_USER, NULL },
    { "ldap_sudorule_option", "sudoOption", SYSDB_SUDO_CACHE_AT_OPTION, NULL },
    { "ldap_sudorule_runas", "sudoRunAs", SYSDB_SUDO_CACHE_AT_RUNAS, NULL },
    { "ldap_sudorule_runasuser", "sudoRunAsUser", SYSDB_SUDO_CACHE_AT_RUNASUSER, NULL },
    { "ldap_sudorule_runasgroup", "sudoRunAsGroup", SYSDB_SUDO_CACHE_AT_RUNASGROUP, NULL },
    { "ldap_sudorule_notbefore", "sudoNotBefore", SYSDB_SUDO_CACHE_AT_NOTBEFORE, NULL },
    { "ldap_sudorule_notafter", "sudoNotAfter", SYSDB_SUDO_CACHE_AT_NOTAFTER, NULL },
    { "ldap_sudorule_order", "sudoOrder", SYSDB_SUDO_CACHE_AT_ORDER, NULL },
    { "ldap_sudorule_entry_usn", NULL, SYSDB_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};
