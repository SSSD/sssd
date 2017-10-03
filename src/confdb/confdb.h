/*
   SSSD

   SSSD Configuration DB

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#ifndef _CONF_DB_H
#define _CONF_DB_H

#include <stdbool.h>
#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <ldb_errors.h>

#include "config.h"

/**
 * @defgroup sss_confdb The ConfDB API
 * The ConfDB is an interface for data providers to
 * access the configuration information provided in
 * the sssd.conf
 * @{
 */

#define CONFDB_DEFAULT_CFG_FILE_VER 2
#define CONFDB_FILE "config.ldb"
#define SSSD_CONFIG_FILE SSSD_CONF_DIR"/sssd.conf"
#define CONFDB_DEFAULT_CONFIG_DIR SSSD_CONF_DIR"/conf.d"
#define SSSD_MIN_ID 1
#define SSSD_LOCAL_MINID 1000
#define CONFDB_DEFAULT_SHELL_FALLBACK "/bin/sh"


/* Configuration options */

/* Services */
#define CONFDB_SERVICE_PATH_TMPL "config/%s"
#define CONFDB_SERVICE_COMMAND "command"
#define CONFDB_SERVICE_DEBUG_LEVEL "debug_level"
#define CONFDB_SERVICE_DEBUG_LEVEL_ALIAS "debug"
#define CONFDB_SERVICE_DEBUG_TIMESTAMPS "debug_timestamps"
#define CONFDB_SERVICE_DEBUG_MICROSECONDS "debug_microseconds"
#define CONFDB_SERVICE_DEBUG_TO_FILES "debug_to_files"
#define CONFDB_SERVICE_RECON_RETRIES "reconnection_retries"
#define CONFDB_SERVICE_FD_LIMIT "fd_limit"
#define CONFDB_SERVICE_ALLOWED_UIDS "allowed_uids"

/* Monitor */
#define CONFDB_MONITOR_CONF_ENTRY "config/sssd"
#define CONFDB_MONITOR_SBUS_TIMEOUT "sbus_timeout"
#define CONFDB_MONITOR_ACTIVE_SERVICES "services"
#define CONFDB_MONITOR_ACTIVE_DOMAINS "domains"
#define CONFDB_MONITOR_TRY_INOTIFY "try_inotify"
#define CONFDB_MONITOR_KRB5_RCACHEDIR "krb5_rcache_dir"
#define CONFDB_MONITOR_DEFAULT_DOMAIN "default_domain_suffix"
#define CONFDB_MONITOR_OVERRIDE_SPACE "override_space"
#define CONFDB_MONITOR_USER_RUNAS "user"
#define CONFDB_MONITOR_CERT_VERIFICATION "certificate_verification"
#define CONFDB_MONITOR_DISABLE_NETLINK "disable_netlink"
#define CONFDB_MONITOR_ENABLE_FILES_DOM "enable_files_domain"
#define CONFDB_MONITOR_DOMAIN_RESOLUTION_ORDER "domain_resolution_order"

/* Both monitor and domains */
#define CONFDB_NAME_REGEX   "re_expression"
#define CONFDB_FULL_NAME_FORMAT "full_name_format"
#define CONFDB_DEFAULT_FULL_NAME_FORMAT_INTERNAL  "%1$s@%2$s%3$s"
#define CONFDB_DEFAULT_FULL_NAME_FORMAT           "%1$s@%2$s"

/* Responders */
#define CONFDB_RESPONDER_GET_DOMAINS_TIMEOUT "get_domains_timeout"
#define CONFDB_RESPONDER_CLI_IDLE_TIMEOUT "client_idle_timeout"
#define CONFDB_RESPONDER_CLI_IDLE_DEFAULT_TIMEOUT 60
#define CONFDB_RESPONDER_LOCAL_NEG_TIMEOUT "local_negative_timeout"
#define CONFDB_RESPONDER_LOCAL_NEG_TIMEOUT_DEFAULT 14400
#define CONFDB_RESPONDER_IDLE_TIMEOUT "responder_idle_timeout"
#define CONFDB_RESPONDER_IDLE_DEFAULT_TIMEOUT 300
#define CONFDB_RESPONDER_CACHE_FIRST "cache_first"

/* NSS */
#define CONFDB_NSS_CONF_ENTRY "config/nss"
#define CONFDB_NSS_ENUM_CACHE_TIMEOUT "enum_cache_timeout"
#define CONFDB_NSS_ENTRY_CACHE_NOWAIT_PERCENTAGE "entry_cache_nowait_percentage"
#define CONFDB_NSS_ENTRY_NEG_TIMEOUT "entry_negative_timeout"
#define CONFDB_NSS_FILTER_USERS_IN_GROUPS "filter_users_in_groups"
#define CONFDB_NSS_FILTER_USERS "filter_users"
#define CONFDB_NSS_FILTER_GROUPS "filter_groups"
#define CONFDB_NSS_PWFIELD  "pwfield"
#define CONFDB_NSS_OVERRIDE_HOMEDIR "override_homedir"
#define CONFDB_NSS_FALLBACK_HOMEDIR "fallback_homedir"
#define CONFDB_NSS_OVERRIDE_SHELL  "override_shell"
#define CONFDB_NSS_VETOED_SHELL  "vetoed_shells"
#define CONFDB_NSS_ALLOWED_SHELL "allowed_shells"
#define CONFDB_NSS_SHELL_FALLBACK "shell_fallback"
#define CONFDB_NSS_DEFAULT_SHELL "default_shell"
#define CONFDB_MEMCACHE_TIMEOUT "memcache_timeout"
#define CONFDB_NSS_HOMEDIR_SUBSTRING "homedir_substring"
#define CONFDB_DEFAULT_HOMEDIR_SUBSTRING "/home"

/* PAM */
#define CONFDB_PAM_CONF_ENTRY "config/pam"
#define CONFDB_PAM_CRED_TIMEOUT "offline_credentials_expiration"
#define CONFDB_PAM_FAILED_LOGIN_ATTEMPTS "offline_failed_login_attempts"
#define CONFDB_DEFAULT_PAM_FAILED_LOGIN_ATTEMPTS 0
#define CONFDB_PAM_FAILED_LOGIN_DELAY "offline_failed_login_delay"
#define CONFDB_DEFAULT_PAM_FAILED_LOGIN_DELAY 5
#define CONFDB_PAM_VERBOSITY "pam_verbosity"
#define CONFDB_PAM_RESPONSE_FILTER "pam_response_filter"
#define CONFDB_PAM_ID_TIMEOUT "pam_id_timeout"
#define CONFDB_PAM_PWD_EXPIRATION_WARNING "pam_pwd_expiration_warning"
#define CONFDB_PAM_TRUSTED_USERS "pam_trusted_users"
#define CONFDB_PAM_PUBLIC_DOMAINS "pam_public_domains"
#define CONFDB_PAM_ACCOUNT_EXPIRED_MESSAGE "pam_account_expired_message"
#define CONFDB_PAM_ACCOUNT_LOCKED_MESSAGE "pam_account_locked_message"
#define CONFDB_PAM_CERT_AUTH "pam_cert_auth"
#define CONFDB_PAM_CERT_DB_PATH "pam_cert_db_path"
#define CONFDB_PAM_P11_CHILD_TIMEOUT "p11_child_timeout"
#define CONFDB_PAM_APP_SERVICES "pam_app_services"
#define CONFDB_PAM_P11_ALLOWED_SERVICES "pam_p11_allowed_services"

/* SUDO */
#define CONFDB_SUDO_CONF_ENTRY "config/sudo"
#define CONFDB_SUDO_CACHE_TIMEOUT "sudo_cache_timeout"
#define CONFDB_DEFAULT_SUDO_CACHE_TIMEOUT 180
#define CONFDB_SUDO_TIMED "sudo_timed"
#define CONFDB_DEFAULT_SUDO_TIMED false
#define CONFDB_SUDO_INVERSE_ORDER "sudo_inverse_order"
#define CONFDB_DEFAULT_SUDO_INVERSE_ORDER false
#define CONFDB_SUDO_THRESHOLD "sudo_threshold"
#define CONFDB_DEFAULT_SUDO_THRESHOLD 50

/* autofs */
#define CONFDB_AUTOFS_CONF_ENTRY "config/autofs"
#define CONFDB_AUTOFS_MAP_NEG_TIMEOUT "autofs_negative_timeout"

/* SSH */
#define CONFDB_SSH_CONF_ENTRY "config/ssh"
#define CONFDB_SSH_HASH_KNOWN_HOSTS "ssh_hash_known_hosts"
#define CONFDB_DEFAULT_SSH_HASH_KNOWN_HOSTS true
#define CONFDB_SSH_KNOWN_HOSTS_TIMEOUT "ssh_known_hosts_timeout"
#define CONFDB_DEFAULT_SSH_KNOWN_HOSTS_TIMEOUT 180
#define CONFDB_SSH_CA_DB "ca_db"
#ifdef HAVE_NSS
#define CONFDB_DEFAULT_SSH_CA_DB SYSCONFDIR"/pki/nssdb"
#else
#define CONFDB_DEFAULT_SSH_CA_DB SYSCONFDIR"/sssd/pki/sssd_auth_ca_db.pem"
#endif
#define CONFDB_SSH_USE_CERT_KEYS "ssh_use_certificate_keys"
#define CONFDB_DEFAULT_SSH_USE_CERT_KEYS true

/* PAC */
#define CONFDB_PAC_CONF_ENTRY "config/pac"
#define CONFDB_PAC_LIFETIME "pac_lifetime"

/* InfoPipe */
#define CONFDB_IFP_CONF_ENTRY "config/ifp"
#define CONFDB_IFP_USER_ATTR_LIST "user_attributes"
#define CONFDB_IFP_WILDCARD_LIMIT "wildcard_limit"

/* Session Recording */
#define CONFDB_SESSION_RECORDING_CONF_ENTRY "config/session_recording"
#define CONFDB_SESSION_RECORDING_SCOPE "scope"
#define CONFDB_SESSION_RECORDING_USERS "users"
#define CONFDB_SESSION_RECORDING_GROUPS "groups"

/* Domains */
#define CONFDB_DOMAIN_PATH_TMPL "config/domain/%s"
#define CONFDB_DOMAIN_BASEDN "cn=domain,cn=config"
#define CONFDB_APP_DOMAIN_BASEDN "cn=application,cn=config"
#define CONFDB_DOMAIN_ID_PROVIDER "id_provider"
#define CONFDB_DOMAIN_AUTH_PROVIDER "auth_provider"
#define CONFDB_DOMAIN_ACCESS_PROVIDER "access_provider"
#define CONFDB_DOMAIN_CHPASS_PROVIDER "chpass_provider"
#define CONFDB_DOMAIN_SUDO_PROVIDER "sudo_provider"
#define CONFDB_DOMAIN_AUTOFS_PROVIDER "autofs_provider"
#define CONFDB_DOMAIN_SELINUX_PROVIDER "selinux_provider"
#define CONFDB_DOMAIN_HOSTID_PROVIDER "hostid_provider"
#define CONFDB_DOMAIN_SUBDOMAINS_PROVIDER "subdomains_provider"
#define CONFDB_DOMAIN_SESSION_PROVIDER "session_provider"
#define CONFDB_DOMAIN_COMMAND "command"
#define CONFDB_DOMAIN_TIMEOUT "timeout"
#define CONFDB_DOMAIN_ATTR "cn"
#define CONFDB_DOMAIN_ENUMERATE "enumerate"
#define CONFDB_SUBDOMAIN_ENUMERATE "subdomain_enumerate"
#define CONFDB_DEFAULT_SUBDOMAIN_ENUMERATE "none"
#define CONFDB_DOMAIN_MINID "min_id"
#define CONFDB_DOMAIN_MAXID "max_id"
#define CONFDB_DOMAIN_CACHE_CREDS "cache_credentials"
#define CONFDB_DOMAIN_CACHE_CREDS_MIN_FF_LENGTH \
                                 "cache_credentials_minimal_first_factor_length"
#define CONFDB_DEFAULT_CACHE_CREDS_MIN_FF_LENGTH 8
#define CONFDB_DOMAIN_AUTO_UPG "auto_private_groups"
#define CONFDB_DOMAIN_FQ "use_fully_qualified_names"
#define CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT "entry_cache_timeout"
#define CONFDB_DOMAIN_ACCOUNT_CACHE_EXPIRATION "account_cache_expiration"
#define CONFDB_DOMAIN_OVERRIDE_GID "override_gid"
#define CONFDB_DOMAIN_CASE_SENSITIVE "case_sensitive"
#define CONFDB_DOMAIN_SUBDOMAIN_HOMEDIR "subdomain_homedir"
#define CONFDB_DOMAIN_DEFAULT_SUBDOMAIN_HOMEDIR "/home/%d/%u"
#define CONFDB_DOMAIN_IGNORE_GROUP_MEMBERS "ignore_group_members"
#define CONFDB_DOMAIN_SUBDOMAIN_REFRESH "subdomain_refresh_interval"
#define CONFDB_DOMAIN_SUBDOMAIN_REFRESH_DEFAULT_VALUE 14400

#define CONFDB_DOMAIN_USER_CACHE_TIMEOUT "entry_cache_user_timeout"
#define CONFDB_DOMAIN_GROUP_CACHE_TIMEOUT "entry_cache_group_timeout"
#define CONFDB_DOMAIN_NETGROUP_CACHE_TIMEOUT "entry_cache_netgroup_timeout"
#define CONFDB_DOMAIN_SERVICE_CACHE_TIMEOUT "entry_cache_service_timeout"
#define CONFDB_DOMAIN_AUTOFS_CACHE_TIMEOUT "entry_cache_autofs_timeout"
#define CONFDB_DOMAIN_SUDO_CACHE_TIMEOUT "entry_cache_sudo_timeout"
#define CONFDB_DOMAIN_SSH_HOST_CACHE_TIMEOUT "entry_cache_ssh_host_timeout"
#define CONFDB_DOMAIN_PWD_EXPIRATION_WARNING "pwd_expiration_warning"
#define CONFDB_DOMAIN_REFRESH_EXPIRED_INTERVAL "refresh_expired_interval"
#define CONFDB_DOMAIN_OFFLINE_TIMEOUT "offline_timeout"
#define CONFDB_DOMAIN_SUBDOMAIN_INHERIT "subdomain_inherit"
#define CONFDB_DOMAIN_CACHED_AUTH_TIMEOUT "cached_auth_timeout"
#define CONFDB_DOMAIN_TYPE "domain_type"
#define CONFDB_DOMAIN_TYPE_POSIX "posix"
#define CONFDB_DOMAIN_TYPE_APP "application"
#define CONFDB_DOMAIN_INHERIT_FROM "inherit_from"

/* Local Provider */
#define CONFDB_LOCAL_DEFAULT_SHELL   "default_shell"
#define CONFDB_LOCAL_DEFAULT_BASEDIR "base_directory"
#define CONFDB_LOCAL_CREATE_HOMEDIR  "create_homedir"
#define CONFDB_LOCAL_REMOVE_HOMEDIR  "remove_homedir"
#define CONFDB_LOCAL_UMASK           "homedir_umask"
#define CONFDB_LOCAL_SKEL_DIR        "skel_dir"
#define CONFDB_LOCAL_MAIL_DIR        "mail_dir"
#define CONFDB_LOCAL_USERDEL_CMD     "userdel_cmd"

/* Proxy Provider */
#define CONFDB_PROXY_LIBNAME "proxy_lib_name"
#define CONFDB_PROXY_PAM_TARGET "proxy_pam_target"
#define CONFDB_PROXY_FAST_ALIAS "proxy_fast_alias"
#define CONFDB_PROXY_MAX_CHILDREN "proxy_max_children"

/* Files Provider */
#define CONFDB_FILES_PASSWD "passwd_files"
#define CONFDB_FILES_GROUP "group_files"

/* Secrets Service */
#define CONFDB_SEC_CONF_ENTRY "config/secrets"
#define CONFDB_SEC_CONTAINERS_NEST_LEVEL "containers_nest_level"
#define CONFDB_SEC_MAX_SECRETS "max_secrets"
#define CONFDB_SEC_MAX_UID_SECRETS "max_uid_secrets"
#define CONFDB_SEC_MAX_PAYLOAD_SIZE "max_payload_size"

/* KCM Service */
#define CONFDB_KCM_CONF_ENTRY "config/kcm"
#define CONFDB_KCM_SOCKET "socket_path"
#define CONFDB_KCM_DB "ccache_storage" /* Undocumented on purpose */

struct confdb_ctx;
struct config_file_ctx;

/** sssd domain state */
enum sss_domain_state {
    /** Domain is usable by both responders and providers. This
     * is the default state after creating a new domain
     */
    DOM_ACTIVE,
    /** Domain was removed, should not be used be neither responders
     * not providers.
     */
    DOM_DISABLED,
    /** Domain cannot be contacted. Providers return an offline error code
     * when receiving request for inactive domain, but responders should
     * return cached data
     */
    DOM_INACTIVE,
    /** Domain is being updated. Responders should ignore cached data and
     * always contact the DP
     */
    DOM_INCONSISTENT,
};

/** Whether the domain only supports looking up POSIX entries */
enum sss_domain_type {
    /** This is the default domain type. It resolves only entries
     * with the full POSIX set of attributes
     */
    DOM_TYPE_POSIX,
    /** In this mode, entries are typically resolved only by name */
    DOM_TYPE_APPLICATION,
};

/**
 * Data structure storing all of the basic features
 * of a domain.
 */
struct sss_domain_info {
    enum sss_domain_type type;

    char *name;
    char *conn_name;
    char *provider;
    int timeout;
    bool enumerate;
    char **sd_enumerate;
    bool fqnames;
    bool mpg;
    bool ignore_group_members;
    uint32_t id_min;
    uint32_t id_max;
    const char *pwfield;

    bool cache_credentials;
    uint32_t cache_credentials_min_ff_length;
    bool case_sensitive;
    bool case_preserve;

    gid_t override_gid;
    const char *override_homedir;
    const char *fallback_homedir;
    const char *subdomain_homedir;
    const char *homedir_substr;
    const char *override_shell;
    const char *default_shell;

    uint32_t user_timeout;
    uint32_t group_timeout;
    uint32_t netgroup_timeout;
    uint32_t service_timeout;
    uint32_t autofsmap_timeout;
    uint32_t sudo_timeout;
    uint32_t ssh_host_timeout;

    uint32_t refresh_expired_interval;
    uint32_t subdomain_refresh_interval;
    uint32_t cached_auth_timeout;

    int pwd_expiration_warning;

    struct sysdb_ctx *sysdb;
    struct sss_names_ctx *names;

    struct sss_domain_info *parent;
    struct sss_domain_info *subdomains;
    char *realm;
    char *flat_name;
    char *domain_id;
    uint32_t trust_direction;
    struct timeval subdomains_last_checked;

    bool has_views;
    const char *view_name;

    struct sss_domain_info *prev;
    struct sss_domain_info *next;

    enum sss_domain_state state;
    char **sd_inherit;

    /* Do not use the forest pointer directly in new code, but rather the
     * forest_root pointer. sss_domain_info will be more opaque in the future
     */
    char *forest;
    struct sss_domain_info *forest_root;
    const char **upn_suffixes;

    struct certmap_info **certmaps;
    bool user_name_hint;

    /* Do not use the _output_fqnames property directly in new code, but rather
     * use sss_domain_info_{get,set}_output_fqnames(). */
    bool output_fqnames;
};

/**
 * Initialize the connection to the ConfDB
 *
 * @param[in]  mem_ctx The parent memory context for the confdb_ctx
 * @param[out] cdb_ctx The newly-created connection object
 * @param[in]  confdb_location The absolute path to the ConfDB file on the
 *             filesystem
 *
 * @return 0 - Connection succeeded and cdb_ctx was populated
 * @return ENOMEM - There was not enough memory to create the cdb_ctx
 * @return EIO - There was an I/O error communicating with the ConfDB file
 */
int confdb_init(TALLOC_CTX *mem_ctx,
                struct confdb_ctx **cdb_ctx,
                const char *confdb_location);

/**
 * Get a domain object for the named domain
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] name The name of the domain to retrieve
 * @param[out] domain A pointer to a domain object for the domain given by
 *                    name
 *
 * @return 0 - Lookup succeeded and domain was populated
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return ENOENT - The named domain does not exist or is not set active
 */
int confdb_get_domain(struct confdb_ctx *cdb,
                      const char *name,
                      struct sss_domain_info **domain);

/**
 * Get a null-terminated linked-list of active domain objects
 * @param[in] cdb The connection object to the confdb
 * @param[out] domains A pointer to the first entry of a linked-list of domain
 *                     objects
 *
 * @return 0 - Lookup succeeded and all active domains are in the list
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return ENOENT - No active domains are configured
 */
int confdb_get_domains(struct confdb_ctx *cdb,
                       struct sss_domain_info **domains);

int confdb_ensure_files_domain(struct confdb_ctx *cdb,
                               const char *implicit_files_dom_name);

int confdb_expand_app_domains(struct confdb_ctx *cdb);

/**
 * Get a null-terminated linked-list of all domain names
 * @param[in] mem_ctx The parent memory context for the value list
 * @param[in] cdb The connection object to the confdb
 * @param[out] _names Output list
 *
 * @return 0 - Lookup succeeded and all domain names are in the list
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return ENOENT - No active domains are configured
 * @return EIO - There was an I/O error communicating with the ConfDB file
 * @return EINVAL - Corrupted confdb object
 */
int confdb_list_all_domain_names(TALLOC_CTX *mem_ctx,
                                 struct confdb_ctx *cdb,
                                 char ***_names);


/**
 * @brief Add an arbitrary parameter to the confdb.
 *
 * This is mostly useful
 * for testing, as they will not persist between SSSD restarts. For
 * persistence, make changes to the sssd.conf file.
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] replace If replace is set to true, pre-existing values will be
 *                    overwritten.
 *                    If it is false, the provided values will be added to the
 *                    attribute.
 * @param[in] section The ConfDB section to update. This is constructed from
 *                    the format of the sssd.conf file. All sections start
 *                    with 'config/'. Subsections are separated by slashes.
 *                    e.g. [domain/LDAP] in sssd.conf would translate to
 *                    config/domain/LDAP
 * @param[in] attribute The name of the attribute to update
 * @param[in] values A null-terminated array of values to add to the attribute
 *
 * @return 0 - Successfully added the provided value(s)
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return EINVAL - The section could not be parsed
 * @return EIO - An I/O error occurred communicating with the ConfDB
 */
int confdb_add_param(struct confdb_ctx *cdb,
                     bool replace,
                     const char *section,
                     const char *attribute,
                     const char **values);

/**
 * @brief Retrieve all values for an attribute
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] mem_ctx The parent memory context for the value list
 * @param[in] section The ConfDB section to update. This is constructed from
 *                    the format of the sssd.conf file. All sections start
 *                    with 'config/'. Subsections are separated by slashes.
 *                    e.g. [domain/LDAP] in sssd.conf would translate to
 *                    config/domain/LDAP
 * @param[in] attribute The name of the attribute to update
 * @param[out] values A null-terminated array of cstrings containing all
 *                    values for this attribute
 *
 * @return 0 - Successfully retrieved the value(s)
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return EINVAL - The section could not be parsed
 * @return EIO - An I/O error occurred while communicating with the ConfDB
 */
int confdb_get_param(struct confdb_ctx *cdb,
                     TALLOC_CTX *mem_ctx,
                     const char *section,
                     const char *attribute,
                     char ***values);

/**
 * @brief Convenience function to retrieve a single-valued attribute as a
 * string
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] ctx The parent memory context for the returned string
 * @param[in] section The ConfDB section to update. This is constructed from
 *                    the format of the sssd.conf file. All sections start
 *                    with 'config/'. Subsections are separated by slashes.
 *                    e.g. [domain/LDAP] in sssd.conf would translate to
 *                    config/domain/LDAP
 * @param[in] attribute The name of the attribute to update
 * @param[in] defstr If not NULL, the string to use if the attribute does not
 *                   exist in the ConfDB
 * @param[out] result A pointer to the retrieved (or default) string
 *
 * @return 0 - Successfully retrieved the entry (or used the default)
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return EINVAL - The section could not be parsed, or the attribute was not
 *                  single-valued.
 * @return EIO - An I/O error occurred while communicating with the ConfDB
 */
int confdb_get_string(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                      const char *section, const char *attribute,
                      const char *defstr, char **result);

/**
 * @brief Convenience function to retrieve a single-valued attribute as an
 * integer
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] section The ConfDB section to update. This is constructed from
 *                    the format of the sssd.conf file. All sections start
 *                    with 'config/'. Subsections are separated by slashes.
 *                    e.g. [domain/LDAP] in sssd.conf would translate to
 *                    config/domain/LDAP
 * @param[in] attribute The name of the attribute to update
 * @param[in] defval If not NULL, the integer to use if the attribute does not
 *                   exist in the ConfDB
 * @param[out] result A pointer to the retrieved (or default) integer
 *
 * @return 0 - Successfully retrieved the entry (or used the default)
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return EINVAL - The section could not be parsed, or the attribute was not
 *                  single-valued.
 * @return EIO - An I/O error occurred while communicating with the ConfDB
 * @return ERANGE - The value stored in the ConfDB was outside the range
 *                  [INT_MIN..INT_MAX]
 */
int confdb_get_int(struct confdb_ctx *cdb,
                   const char *section, const char *attribute,
                   int defval, int *result);

/**
 * @brief Convenience function to retrieve a single-valued attribute as a
 * boolean
 *
 * This function will read (in a case-insensitive manner) a "true" or "false"
 * value from the ConfDB and convert it to an integral bool value.
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] section The ConfDB section to update. This is constructed from
 *                    the format of the sssd.conf file. All sections start
 *                    with 'config/'. Subsections are separated by slashes.
 *                    e.g. [domain/LDAP] in sssd.conf would translate to
 *                    config/domain/LDAP
 * @param[in] attribute The name of the attribute to update
 * @param[in] defval If not NULL, the boolean state to use if the attribute
 *                   does not exist in the ConfDB
 * @param[out] result A pointer to the retrieved (or default) bool
 *
 * @return 0 - Successfully retrieved the entry (or used the default)
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return EINVAL - The section could not be parsed, the attribute was not
 *                  single-valued, or the value was not a boolean.
 * @return EIO - An I/O error occurred while communicating with the ConfDB
 */
int confdb_get_bool(struct confdb_ctx *cdb,
                    const char *section, const char *attribute,
                    bool defval, bool *result);

/**
 * @brief Convenience function to set a single-valued attribute as a string
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] section The ConfDB section to update. This is constructed from
 *                    the format of the sssd.conf file. All sections start
 *                    with 'config/'. Subsections are separated by slashes.
 *                    e.g. [domain/LDAP] in sssd.conf would translate to
 *                    config/domain/LDAP
 * @param[in] attribute The name of the attribute to update
 * @param[in] val New value of the attribute.
 *
 * @return 0 - Successfully retrieved the entry (or used the default)
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return EINVAL - The section could not be parsed
 * @return EIO - An I/O error occurred while communicating with the ConfDB
 */
int confdb_set_string(struct confdb_ctx *cdb,
                      const char *section,
                      const char *attribute,
                      const char *val);

/**
 * @brief Convenience function to retrieve a single-valued attribute as a
 * null-terminated array of strings
 *
 * This function will automatically split a comma-separated string in an
 * attribute into a null-terminated array of strings. This is useful for
 * storing and retrieving ordered lists, as ConfDB multivalued attributes do
 * not guarantee retrieval order.
 *
 * @param[in] cdb The connection object to the confdb
 * @param[in] ctx The parent memory context for the returned string
 * @param[in] section The ConfDB section to update. This is constructed from
 *                    the format of the sssd.conf file. All sections start
 *                    with 'config/'. Subsections are separated by slashes.
 *                    e.g. [domain/LDAP] in sssd.conf would translate to
 *                    config/domain/LDAP
 * @param[in] attribute The name of the attribute to update
 * @param[out] result A pointer to the retrieved array of strings
 *
 * @return 0 - Successfully retrieved the entry (or used the default)
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return EINVAL - The section could not be parsed, or the attribute was not
 *                  single-valued.
 * @return ENOENT - The attribute was not found.
 * @return EIO - An I/O error occurred while communicating with the ConfDB
 */
int confdb_get_string_as_list(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                              const char *section, const char *attribute,
                              char ***result);

/**
 * @brief Convenience function to retrieve a list of subsections given a
 * configuration section name
 *
 * @param[in] mem_ctx The parent memory context for the returned list
 * @param[in] cdb The connection object to the confdb
 * @param[in] section The ConfDB section to look for.
 *                    All sections should start with 'config/'.
 *                    Subsections are separated by slashes.
 * @param[out] sections Names of the subsections relative to the section
 *                      requested. If "a/b" is requested then "c/d" is
 *                      returned for the section named [a/b/c/d]
 * @param[out] num_sections Number of section names returned
 *
 * @return 0 - Successfully retrieved the entry (or used the default)
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return EINVAL - The section could not be parsed.
 * @return ENOENT - No section was found.
 * @return EIO - An I/O error occurred while communicating with the ConfDB
 */
int confdb_get_sub_sections(TALLOC_CTX *mem_ctx,
                            struct confdb_ctx *cdb,
                            const char *section,
                            char ***sections,
                            int *num_sections);
/**
 * @}
 */
#endif
