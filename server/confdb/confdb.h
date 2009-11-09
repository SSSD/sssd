/*
   SSSD

   NSS Configuratoin DB

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
#include "talloc.h"
#include "tevent.h"
#include "ldb.h"
#include "ldb_errors.h"
#include "config.h"

#define CONFDB_FILE "config.ldb"
#define CONFDB_DEFAULT_CONFIG_FILE SSSD_CONF_DIR"/sssd.conf"
#define SSSD_MIN_ID 1000

/* Configuration options */

/* Services */
#define CONFDB_SERVICE_PATH_TMPL "config/%s"
#define CONFDB_SERVICE_COMMAND "command"
#define CONFDB_SERVICE_DEBUG_LEVEL "debug_level"
#define CONFDB_SERVICE_DEBUG_TIMESTAMPS "debug_timestamps"
#define CONFDB_SERVICE_DEBUG_TO_FILES "debug_to_files"
#define CONFDB_SERVICE_TIMEOUT "timeout"
#define CONFDB_SERVICE_RECON_RETRIES "reconnection_retries"

/* Monitor */
#define CONFDB_MONITOR_CONF_ENTRY "config/sssd"
#define CONFDB_MONITOR_SBUS_TIMEOUT "sbus_timeout"
#define CONFDB_MONITOR_ACTIVE_SERVICES "services"
#define CONFDB_MONITOR_ACTIVE_DOMAINS "domains"
#define CONFDB_MONITOR_NAME_REGEX   "re_expression"
#define CONFDB_MONITOR_FULL_NAME_FORMAT "full_name_format"

/* NSS */
#define CONFDB_NSS_CONF_ENTRY "config/nss"
#define CONFDB_NSS_ENUM_CACHE_TIMEOUT "enum_cache_timeout"
#define CONFDB_NSS_ENTRY_CACHE_NOWAIT_PERCENTAGE "entry_cache_nowait_percentage"
#define CONFDB_NSS_ENTRY_NEG_TIMEOUT "entry_negative_timeout"
#define CONFDB_NSS_FILTER_USERS_IN_GROUPS "filter_users_in_groups"
#define CONFDB_NSS_FILTER_USERS "filter_users"
#define CONFDB_NSS_FILTER_GROUPS "filter_groups"
#define CONFDB_NSS_PWFIELD  "pwfield"

/* PAM */
#define CONFDB_PAM_CONF_ENTRY "config/pam"
#define CONFDB_PAM_CRED_TIMEOUT "offline_credentials_expiration"

/* Data Provider */
#define CONFDB_DP_CONF_ENTRY "config/dp"

/* Domains */
#define CONFDB_DOMAIN_PATH_TMPL "config/domain/%s"
#define CONFDB_DOMAIN_BASEDN "cn=domain,cn=config"
#define CONFDB_DOMAIN_ID_PROVIDER "id_provider"
#define CONFDB_DOMAIN_AUTH_PROVIDER "auth_provider"
#define CONFDB_DOMAIN_ACCESS_PROVIDER "access_provider"
#define CONFDB_DOMAIN_CHPASS_PROVIDER "chpass_provider"
#define CONFDB_DOMAIN_COMMAND "command"
#define CONFDB_DOMAIN_TIMEOUT "timeout"
#define CONFDB_DOMAIN_ATTR "cn"
#define CONFDB_DOMAIN_ENUMERATE "enumerate"
#define CONFDB_DOMAIN_MINID "min_id"
#define CONFDB_DOMAIN_MAXID "max_id"
#define CONFDB_DOMAIN_CACHE_CREDS "cache_credentials"
#define CONFDB_DOMAIN_LEGACY_PASS "store_legacy_passwords"
#define CONFDB_DOMAIN_MPG "magic_private_groups"
#define CONFDB_DOMAIN_FQ "use_fully_qualified_names"
#define CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT "entry_cache_timeout"

/* Local Provider */
#define CONFDB_LOCAL_DEFAULT_SHELL   "default_shell"
#define CONFDB_LOCAL_DEFAULT_BASEDIR "base_directory"
#define CONFDB_LOCAL_CREATE_HOMEDIR  "create_homedir"
#define CONFDB_LOCAL_REMOVE_HOMEDIR  "remove_homedir"
#define CONFDB_LOCAL_UMASK           "homedir_umask"
#define CONFDB_LOCAL_SKEL_DIR        "skel_dir"
#define CONFDB_LOCAL_MAIL_DIR        "mail_dir"

/* Proxy Provider */
#define CONFDB_PROXY_LIBNAME "proxy_lib_name"
#define CONFDB_PROXY_PAM_TARGET "proxy_pam_target"

/* KRB5 Provider */
#define CONFDB_KRB5_KDCIP "krb5_kdcip"
#define CONFDB_KRB5_REALM "krb5_realm"
#define CONFDB_KRB5_CCACHEDIR "krb5_ccachedir"
#define CONFDB_KRB5_CCNAME_TMPL "krb5_ccname_template"
#define CONFDB_KRB5_CHANGEPW_PRINC "krb5_changepw_principal"
#define CONFDB_KRB5_AUTH_TIMEOUT "krb5_auth_timeout"

struct confdb_ctx;
struct config_file_ctx;

struct sss_domain_info {
    char *name;
    char *provider;
    int timeout;
    bool enumerate;
    bool fqnames;
    uint32_t id_min;
    uint32_t id_max;

    bool cache_credentials;
    bool legacy_passwords;

    struct sss_domain_info *next;
};

int confdb_add_param(struct confdb_ctx *cdb,
                     bool replace,
                     const char *section,
                     const char *attribute,
                     const char **values);


int confdb_get_param(struct confdb_ctx *cdb,
                     TALLOC_CTX *mem_ctx,
                     const char *section,
                     const char *attribute,
                     char ***values);

int confdb_get_string(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                      const char *section, const char *attribute,
                      const char *defstr, char **result);

int confdb_get_int(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                   const char *section, const char *attribute,
                   int defval, int *result);

int confdb_get_bool(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                    const char *section, const char *attribute,
                    bool defval, bool *result);

int confdb_get_string_as_list(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                              const char *section, const char *attribute,
                              char ***result);

int confdb_init(TALLOC_CTX *mem_ctx,
                struct confdb_ctx **cdb_ctx,
                char *confdb_location);

int confdb_get_domain(struct confdb_ctx *cdb,
                      const char *name,
                      struct sss_domain_info **domain);

int confdb_get_domains(struct confdb_ctx *cdb,
                       struct sss_domain_info **domains);

#endif
