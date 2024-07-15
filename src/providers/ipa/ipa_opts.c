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
#include "db/sysdb.h"
#include "db/sysdb_sudo.h"
#include "db/sysdb_autofs.h"
#include "db/sysdb_services.h"
#include "db/sysdb_selinux.h"
#include "db/sysdb_subid.h"
#include "providers/ldap/ldap_common.h"

struct dp_option ipa_basic_opts[] = {
    { "ipa_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_hostname", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_hbac_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ipa_host_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_selinux_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_subdomains_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_master_domain_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "ipa_hbac_refresh", DP_OPT_NUMBER, { .number = 5 }, NULL_NUMBER },
    { "ipa_selinux_refresh", DP_OPT_NUMBER, { .number = 5 }, NULL_NUMBER },
    { "ipa_hbac_support_srchost", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ipa_automount_location", DP_OPT_STRING, { "default" }, NULL_STRING },
    { "ipa_ranges_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_enable_dns_sites", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ipa_server_mode", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ipa_views_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_confd_path", DP_OPT_STRING, { KRB5_MAPPING_DIR }, NULL_STRING },
    { "ipa_deskprofile_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_deskprofile_refresh", DP_OPT_NUMBER, { .number = 5 }, NULL_NUMBER },
    { "ipa_deskprofile_request_interval", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ipa_subid_ranges_search_base", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ipa_access_order", DP_OPT_STRING, { "expire" }, NULL_STRING },
    DP_OPTION_TERMINATOR
};

struct dp_option ipa_dyndns_opts[] = {
    { "dyndns_update", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "dyndns_update_per_family", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "dyndns_refresh_interval", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER },
    { "dyndns_refresh_interval_offset", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER },
    { "dyndns_iface", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_ttl", DP_OPT_NUMBER, { .number = 1200 }, NULL_NUMBER },
    { "dyndns_update_ptr", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "dyndns_force_tcp", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "dyndns_auth", DP_OPT_STRING, { "gss-tsig" }, NULL_STRING },
    { "dyndns_auth_ptr", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    DP_OPTION_TERMINATOR
};

struct dp_option ipa_def_ldap_opts[] = {
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
    { "ldap_sudo_full_refresh_interval", DP_OPT_NUMBER, { .number = 21600 }, NULL_NUMBER },
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
    { "ldap_schema", DP_OPT_STRING, { "ipa_v1" }, NULL_STRING },
    { "ldap_pwmodify_mode", DP_OPT_STRING, { "exop" }, NULL_STRING },
    { "ldap_offline_timeout", DP_OPT_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ldap_force_upper_case_realm", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "ldap_enumeration_refresh_timeout", DP_OPT_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "ldap_enumeration_refresh_offset", DP_OPT_NUMBER, { .number = 30 }, NULL_NUMBER },
    { "ldap_purge_cache_timeout", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    { "ldap_purge_cache_offset", DP_OPT_NUMBER, { .number = 0 }, NULL_NUMBER },
    { "ldap_tls_cacert", DP_OPT_STRING, { "/etc/ipa/ca.crt" }, NULL_STRING },
    { "ldap_tls_cacertdir", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cert", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_key", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cipher_suite", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_id_use_start_tls", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_id_mapping", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_sasl_mech", DP_OPT_STRING, { "GSSAPI" } , NULL_STRING },
    { "ldap_sasl_authid", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sasl_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_sasl_minssf", DP_OPT_NUMBER, { .number = 56 }, NULL_NUMBER },
    { "ldap_sasl_maxssf", DP_OPT_NUMBER, { .number = -1 }, NULL_NUMBER },
    { "ldap_krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ldap_krb5_init_creds", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    /* use the same parm name as the krb5 module so we set it only once */
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_canonicalize", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_use_kdcinfo", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kdcinfo_lookahead", DP_OPT_STRING, NULL_STRING, NULL_STRING },
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

struct sdap_attr_map ipa_attr_map[] = {
    { "ldap_entry_usn", "entryUSN", SYSDB_USN, NULL },
    { "ldap_rootdse_last_usn", "lastUSN", SYSDB_HIGH_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
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
    { "ldap_user_uuid", "ipaUniqueID", SYSDB_UUID, NULL },
    { "ldap_user_objectsid", "ipaNTSecurityIdentifier", SYSDB_SID_STR, NULL },
    { "ldap_user_primary_group", NULL, SYSDB_PRIMARY_GROUP, NULL },
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
    { "ldap_ns_account_lock", "nsAccountLock", SYSDB_NS_ACCOUNT_LOCK, NULL},
    { "ldap_user_authorized_host", "host", SYSDB_AUTHORIZED_HOST, NULL },
    { "ldap_user_authorized_rhost", NULL, SYSDB_AUTHORIZED_RHOST, NULL },
    { "ldap_user_nds_login_disabled", "loginDisabled", SYSDB_NDS_LOGIN_DISABLED, NULL },
    { "ldap_user_nds_login_expiration_time", "loginExpirationTime", SYSDB_NDS_LOGIN_EXPIRATION_TIME, NULL },
    { "ldap_user_nds_login_allowed_time_map", "loginAllowedTimeMap", SYSDB_NDS_LOGIN_ALLOWED_TIME_MAP, NULL },
    { "ldap_user_ssh_public_key", "ipaSshPubKey", SYSDB_SSH_PUBKEY, NULL },
    { "ldap_user_auth_type", "ipaUserAuthType", SYSDB_AUTH_TYPE, NULL },
    { "ldap_user_certificate", "userCertificate;binary", SYSDB_USER_CERT, NULL },
    { "ldap_user_email", "mail", SYSDB_USER_EMAIL, NULL },
    { SDAP_ATTR_MAP_NO_OPT, "sAMAccountName", SYSDB_AD_SAMACCOUNTNAME, NULL },
    { "ldap_user_passkey", "ipaPassKey", SYSDB_USER_PASSKEY, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_group_map[] = {
    { "ldap_group_object_class", "ipaUserGroup", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_object_class_alt", "posixGroup", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "cn", SYSDB_NAME, NULL },
    { "ldap_group_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "member", SYSDB_MEMBER, NULL },
    { "ldap_group_uuid", "ipaUniqueID", SYSDB_UUID, NULL },
    { "ldap_group_objectsid", "ipaNTSecurityIdentifier", SYSDB_SID_STR, NULL },
    { "ldap_group_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL },
    { "ldap_group_entry_usn", NULL, SYSDB_USN, NULL },
    { "ldap_group_type", NULL, SYSDB_GROUP_TYPE, NULL },
    { "ldap_group_external_member", "ipaExternalMember", SYSDB_EXTERNAL_MEMBER, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_netgroup_map[] = {
    { "ipa_netgroup_object_class", "ipaNisNetgroup", SYSDB_NETGROUP_CLASS, NULL },
    { "ipa_netgroup_name", "cn", SYSDB_NAME, NULL },
    { "ipa_netgroup_member", "member", SYSDB_ORIG_NETGROUP_MEMBER, NULL },
    { "ipa_netgroup_member_of", "memberOf", SYSDB_MEMBEROF, NULL },
    { "ipa_netgroup_member_user", "memberUser", SYSDB_ORIG_MEMBER_USER, NULL },
    { "ipa_netgroup_member_host", "memberHost", SYSDB_ORIG_MEMBER_HOST, NULL },
    { "ipa_netgroup_member_ext_host", "externalHost", SYSDB_ORIG_NETGROUP_EXTERNAL_HOST, NULL },
    { "ipa_netgroup_domain", "nisDomainName", SYSDB_NETGROUP_DOMAIN, NULL },
    { "ipa_netgroup_uuid", "ipaUniqueID", SYSDB_UUID, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_subid_map[] = {
    { "ipa_subuid_object_class", "ipasubordinateid", SYSDB_SUBID_RANGE_OC, NULL },
    { "ipa_subuid_count", "ipaSubUidCount", SYSDB_SUBID_UID_COUND, NULL },
    { "ipa_subgid_count", "ipaSubGidCount", SYSDB_SUBID_GID_COUNT, NULL },
    { "ipa_subuid_number", "ipaSubUidNumber", SYSDB_SUBID_UID_NUMBER, NULL },
    { "ipa_subgid_number", "ipaSubGidNumber", SYSDB_SUBID_GID_NUMBER, NULL },
    { "ipa_owner", "ipaOwner", SYSDB_SUBID_OWNER, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_host_map[] = {
    { "ipa_host_object_class", "ipaHost", SYSDB_HOST_CLASS, NULL },
    { "ipa_host_name", "cn", SYSDB_NAME, NULL },
    { "ipa_host_fqdn", "fqdn", SYSDB_FQDN, NULL },
    { "ipa_host_serverhostname", "serverHostname", SYSDB_SERVERHOSTNAME, NULL },
    { "ipa_host_member_of", "memberOf", SYSDB_ORIG_MEMBEROF, NULL },
    { "ipa_host_ssh_public_key", "ipaSshPubKey", SYSDB_SSH_PUBKEY, NULL },
    { "ipa_host_uuid", "ipaUniqueID", SYSDB_UUID, NULL},
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_hostgroup_map[] = {
    { "ipa_hostgroup_objectclass", "ipaHostgroup", SYSDB_HOSTGROUP_CLASS, NULL},
    { "ipa_hostgroup_name", "cn", SYSDB_NAME, NULL},
    { "ipa_hostgroup_memberof", "memberOf", SYSDB_ORIG_MEMBEROF, NULL},
    { "ipa_hostgroup_uuid", "ipaUniqueID", SYSDB_UUID, NULL},
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_selinux_user_map[] = {
    { "ipa_selinux_usermap_object_class", "ipaselinuxusermap", SYSDB_SELINUX_USERMAP_CLASS, NULL},
    { "ipa_selinux_usermap_name", "cn", SYSDB_NAME, NULL},
    { "ipa_selinux_usermap_member_user", "memberUser", SYSDB_ORIG_MEMBER_USER, NULL},
    { "ipa_selinux_usermap_member_host", "memberHost", SYSDB_ORIG_MEMBER_HOST, NULL},
    { "ipa_selinux_usermap_see_also", "seeAlso", SYSDB_SELINUX_SEEALSO, NULL},
    { "ipa_selinux_usermap_selinux_user", "ipaSELinuxUser", SYSDB_SELINUX_USER, NULL},
    { "ipa_selinux_usermap_enabled", "ipaEnabledFlag", SYSDB_SELINUX_ENABLED, NULL},
    { "ipa_selinux_usermap_user_category", "userCategory", SYSDB_USER_CATEGORY, NULL},
    { "ipa_selinux_usermap_host_category", "hostCategory", SYSDB_HOST_CATEGORY, NULL},
    { "ipa_selinux_usermap_uuid", "ipaUniqueID", SYSDB_UUID, NULL},
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_view_map[] = {
    { "ipa_view_class", "nsContainer", SYSDB_VIEW_CLASS, NULL},
    { "ipa_view_name", "cn", SYSDB_VIEW_NAME, NULL},
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_override_map[] = {
    { "ipa_override_object_class", "ipaOverrideAnchor", SYSDB_OVERRIDE_CLASS, NULL},
    { "ipa_anchor_uuid", "ipaAnchorUUID", SYSDB_OVERRIDE_ANCHOR_UUID, NULL},
    { "ipa_user_override_object_class", "ipaUserOverride", SYSDB_OVERRIDE_USER_CLASS, NULL},
    { "ipa_group_override_object_class", "ipaGroupOverride", SYSDB_OVERRIDE_GROUP_CLASS, NULL},
    { "ldap_user_name", "uid", SYSDB_NAME, NULL },
    { "ldap_user_uid_number", "uidNumber", SYSDB_UIDNUM, NULL },
    { "ldap_user_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_user_gecos", "gecos", SYSDB_GECOS, NULL },
    { "ldap_user_home_directory", "homeDirectory", SYSDB_HOMEDIR, NULL },
    { "ldap_user_shell", "loginShell", SYSDB_SHELL, NULL },
    { "ldap_group_name", "cn", SYSDB_NAME, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_user_ssh_public_key", "ipaSshPubKey", SYSDB_SSH_PUBKEY, NULL },
    { "ldap_user_certificate", "userCertificate;binary", SYSDB_USER_CERT, NULL },
    { "", "objectClass", SYSDB_ORIG_OBJECTCLASS, NULL }, /* We don't want this to be configurable */
    SDAP_ATTR_MAP_TERMINATOR
};

struct dp_option ipa_def_krb5_opts[] = {
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_ccachedir", DP_OPT_STRING, { DEFAULT_CCACHE_DIR }, NULL_STRING },
    { "krb5_ccname_template", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "krb5_auth_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "krb5_keytab", DP_OPT_STRING, { "/etc/krb5.keytab" }, NULL_STRING },
    { "krb5_validate", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_store_password_if_offline", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_renewable_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_renew_interval", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_use_fast", DP_OPT_STRING, { "try" }, NULL_STRING },
    { "krb5_fast_principal", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_fast_use_anonymous_pkinit", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_canonicalize", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_use_enterprise_principal", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_use_kdcinfo", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kdcinfo_lookahead", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_map_user", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_use_subdomain_realm", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    DP_OPTION_TERMINATOR
};

struct sdap_attr_map ipa_service_map[] = {
    { "ldap_service_object_class", "ipService", SYSDB_SVC_CLASS, NULL },
    { "ldap_service_name", "cn", SYSDB_NAME, NULL },
    { "ldap_service_port", "ipServicePort", SYSDB_SVC_PORT, NULL },
    { "ldap_service_proto", "ipServiceProtocol", SYSDB_SVC_PROTO, NULL },
    { "ldap_service_entry_usn", NULL, SYSDB_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_autofs_mobject_map[] = {
    { "ldap_autofs_map_object_class", "automountMap", SYSDB_AUTOFS_MAP_OC, NULL },
    { "ldap_autofs_map_name", "automountMapName", SYSDB_AUTOFS_MAP_NAME, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_autofs_entry_map[] = {
    { "ldap_autofs_entry_object_class", "automount", SYSDB_AUTOFS_ENTRY_OC, NULL },
    { "ldap_autofs_entry_key", "automountKey", SYSDB_AUTOFS_ENTRY_KEY, NULL },
    { "ldap_autofs_entry_value", "automountInformation", SYSDB_AUTOFS_ENTRY_VALUE, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_sudorule_map[] = {
    { "ipa_sudorule_object_class", "ipasudorule", SYSDB_IPA_SUDORULE_OC, NULL },
    { "ipa_sudorule_name", "cn", SYSDB_NAME, NULL },
    { "ipa_sudorule_uuid", "ipaUniqueID", SYSDB_UUID, NULL },
    { "ipa_sudorule_enabled_flag", "ipaEnabledFlag", SYSDB_IPA_SUDORULE_ENABLED, NULL },
    { "ipa_sudorule_option", "ipaSudoOpt", SYSDB_IPA_SUDORULE_OPTION, NULL },
    { "ipa_sudorule_runasuser", "ipaSudoRunAs", SYSDB_IPA_SUDORULE_RUNASUSER, NULL },
    { "ipa_sudorule_runasgroup", "ipaSudoRunAsGroup", SYSDB_IPA_SUDORULE_RUNASGROUP, NULL },
    { "ipa_sudorule_allowcmd", "memberAllowCmd", SYSDB_IPA_SUDORULE_ALLOWCMD, NULL },
    { "ipa_sudorule_denycmd", "memberDenyCmd", SYSDB_IPA_SUDORULE_DENYCMD, NULL },
    { "ipa_sudorule_host", "memberHost", SYSDB_IPA_SUDORULE_HOST, NULL },
    { "ipa_sudorule_user", "memberUser", SYSDB_IPA_SUDORULE_USER, NULL },
    { "ipa_sudorule_notafter", "sudoNotAfter", SYSDB_IPA_SUDORULE_NOTAFTER, NULL },
    { "ipa_sudorule_notbefore", "sudoNotBefore", SYSDB_IPA_SUDORULE_NOTBEFORE, NULL },
    { "ipa_sudorule_sudoorder", "sudoOrder", SYSDB_IPA_SUDORULE_SUDOORDER, NULL },
    { "ipa_sudorule_cmdcategory", "cmdCategory", SYSDB_IPA_SUDORULE_CMDCATEGORY, NULL },
    { "ipa_sudorule_hostcategory", "hostCategory", SYSDB_IPA_SUDORULE_HOSTCATEGORY, NULL },
    { "ipa_sudorule_usercategory", "userCategory", SYSDB_IPA_SUDORULE_USERCATEGORY, NULL },
    { "ipa_sudorule_runasusercategory", "ipaSudoRunAsUserCategory", SYSDB_IPA_SUDORULE_RUNASUSERCATEGORY, NULL },
    { "ipa_sudorule_runasgroupcategory", "ipaSudoRunAsGroupCategory", SYSDB_IPA_SUDORULE_RUNASGROUPCATEGORY, NULL },
    { "ipa_sudorule_runasextuser", "ipaSudoRunAsExtUser", SYSDB_IPA_SUDORULE_RUNASEXTUSER, NULL },
    { "ipa_sudorule_runasextgroup", "ipaSudoRunAsExtGroup", SYSDB_IPA_SUDORULE_RUNASEXTGROUP, NULL },
    { "ipa_sudorule_runasextusergroup", "ipaSudoRunAsExtUserGroup", SYSDB_IPA_SUDORULE_RUNASEXTUSERGROUP, NULL },
    { "ipa_sudorule_externaluser", "externalUser", SYSDB_IPA_SUDORULE_EXTUSER, NULL },
    { "ipa_sudorule_entry_usn", "entryUSN", SYSDB_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_sudocmdgroup_map[] = {
    { "ipa_sudocmdgroup_object_class", "ipasudocmdgrp", SYSDB_IPA_SUDOCMDGROUP_OC, NULL },
    { "ipa_sudocmdgroup_uuid", "ipaUniqueID", SYSDB_UUID, NULL },
    { "ipa_sudocmdgroup_name", "cn", SYSDB_NAME, NULL },
    { "ipa_sudocmdgroup_member", "member", SYSDB_MEMBER, NULL },
    { "ipa_sudocmdgroup_entry_usn", "entryUSN", SYSDB_USN, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct sdap_attr_map ipa_sudocmd_map[] = {
    { "ipa_sudocmd_object_class", "ipasudocmd", SYSDB_IPA_SUDOCMD_OC, NULL },
    { "ipa_sudocmd_uuid", "ipaUniqueID", SYSDB_UUID, NULL },
    { "ipa_sudocmd_sudoCmd", "sudoCmd", SYSDB_IPA_SUDOCMD_SUDOCMD, NULL },
    { "ipa_sudocmd_memberof", "memberOf", SYSDB_MEMBEROF, NULL },
    SDAP_ATTR_MAP_TERMINATOR
};

struct dp_option ipa_cli_ad_subdom_opts [] = {
    { "ad_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "ad_site", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    DP_OPTION_TERMINATOR
};
