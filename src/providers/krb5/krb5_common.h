/*
    SSSD

    Kerberos Backend, common header file

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef __KRB5_COMMON_H__
#define __KRB5_COMMON_H__

#include "config.h"
#include <stdbool.h>

#include "providers/backend.h"
#include "util/util.h"
#include "util/sss_krb5.h"

#define KDCINFO_TMPL PUBCONF_PATH"/kdcinfo.%s"
#define KPASSWDINFO_TMPL PUBCONF_PATH"/kpasswdinfo.%s"

#define SSS_KRB5KDC_FO_SRV "KERBEROS"
#define SSS_KRB5KPASSWD_FO_SRV "KPASSWD"
#define SSS_KRB5_LOOKAHEAD_PRIMARY_DEFAULT 3
#define SSS_KRB5_LOOKAHEAD_BACKUP_DEFAULT 1

enum krb5_opts {
    KRB5_KDC = 0,
    KRB5_BACKUP_KDC,
    KRB5_REALM,
    KRB5_CCACHEDIR,
    KRB5_CCNAME_TMPL,
    KRB5_AUTH_TIMEOUT,
    KRB5_KEYTAB,
    KRB5_VALIDATE,
    KRB5_KPASSWD,
    KRB5_BACKUP_KPASSWD,
    KRB5_STORE_PASSWORD_IF_OFFLINE,
    KRB5_RENEWABLE_LIFETIME,
    KRB5_LIFETIME,
    KRB5_RENEW_INTERVAL,
    KRB5_USE_FAST,
    KRB5_FAST_PRINCIPAL,
    KRB5_FAST_USE_ANONYMOUS_PKINIT,
    KRB5_CANONICALIZE,
    KRB5_USE_ENTERPRISE_PRINCIPAL,
    KRB5_USE_KDCINFO,
    KRB5_KDCINFO_LOOKAHEAD,
    KRB5_MAP_USER,
    KRB5_USE_SUBDOMAIN_REALM,

    KRB5_OPTS
};

typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

struct krb5_service {
    struct be_ctx *be_ctx;
    char *name;
    char *realm;
    bool write_kdcinfo;
    size_t lookahead_primary;
    size_t lookahead_backup;
    bool removal_callback_available;
};

struct fo_service;
struct deferred_auth_ctx;
struct renew_tgt_ctx;

enum krb5_config_type {
    K5C_GENERIC,
    K5C_IPA_CLIENT,
    K5C_IPA_SERVER
};

struct map_id_name_to_krb_primary {
    const char *id_name;
    const char* krb_primary;
};

struct krb5_ctx {
    /* opts taken from kinit */
    /* in seconds */
    krb5_deltat starttime;
    krb5_deltat lifetime;
    char *lifetime_str;
    krb5_deltat rlife;
    char *rlife_str;

    int forwardable;
    int proxiable;
    int addresses;

    int not_forwardable;
    int not_proxiable;
    int no_addresses;

    int verbose;

    char* principal_name;
    char* service_name;
    char* keytab_name;
    char* k5_cache_name;
    char* k4_cache_name;

    action_type action;

    struct dp_option *opts;
    struct krb5_service *service;
    struct krb5_service *kpasswd_service;

    sss_regexp_t *illegal_path_re;

    struct deferred_auth_ctx *deferred_auth_ctx;
    struct renew_tgt_ctx *renew_tgt_ctx;
    struct kcm_renew_tgt_ctx *kcm_renew_tgt_ctx;
    bool use_fast;
    bool sss_creds_password;

    hash_table_t *wait_queue_hash;
    hash_table_t *io_table;

    enum krb5_config_type config_type;

    struct map_id_name_to_krb_primary *name_to_primary;

    char *realm;

    const char *use_fast_str;
    const char *fast_principal;
    bool fast_use_anonymous_pkinit;
    uint32_t check_pac_flags;

    bool canonicalize;
};

struct remove_info_files_ctx {
    char *realm;
    struct be_ctx *be_ctx;
    const char *kdc_service_name;
    const char *kpasswd_service_name;
    struct krb5_service *krb5_service;
};

errno_t sss_krb5_check_options(struct dp_option *opts,
                               struct sss_domain_info *dom,
                               struct krb5_ctx *krb5_ctx);

errno_t krb5_try_kdcip(struct confdb_ctx *cdb, const char *conf_path,
                       struct dp_option *opts, int opt_id);

errno_t sss_krb5_get_options(TALLOC_CTX *memctx, struct confdb_ctx *cdb,
                             const char *conf_path, struct dp_option **_opts);

void sss_krb5_parse_lookahead(const char *param, size_t *primary, size_t *backup);

errno_t write_krb5info_file(struct krb5_service *krb5_service,
                            const char **server_list,
                            const char *service);

errno_t write_krb5info_file_from_fo_server(struct krb5_service *krb5_service,
                                           struct fo_server *server,
                                           bool force_default_port,
                                           const char *service,
                                           bool (*filter)(struct fo_server *));

struct krb5_service *krb5_service_new(TALLOC_CTX *mem_ctx,
                                      struct be_ctx *be_ctx,
                                      const char *service_name,
                                      const char *realm,
                                      bool use_kdcinfo,
                                      size_t n_lookahead_primary,
                                      size_t n_lookahead_backup);

int krb5_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name,
                      const char *primary_servers,
                      const char *backup_servers,
                      const char *realm,
                      bool use_kdcinfo,
                      size_t n_lookahead_primary,
                      size_t n_lookahead_backup,
                      struct krb5_service **_service);

void remove_krb5_info_files_callback(void *pvt);

errno_t remove_krb5_info_files(TALLOC_CTX *mem_ctx, const char *realm);

errno_t krb5_get_simple_upn(TALLOC_CTX *mem_ctx, struct krb5_ctx *krb5_ctx,
                            struct sss_domain_info *dom, const char *username,
                            const char *user_dom, char **_upn);

errno_t compare_principal_realm(const char *upn, const char *realm,
                                bool *different_realm);

/* from krb5_keytab.c */

/**
 * @brief Copy given keytab into a MEMORY keytab
 *
 * @param[in] mem_ctx Talloc memory context the new keytab name should be
 *                    allocated on
 * @param[in] kctx Kerberos context
 * @param[in] inp_keytab_file Existing keytab, if set to NULL the default
 *                            keytab will be used
 * @param[out] _mem_name Name of the new MEMORY keytab
 * @param[out] _mem_keytab Krb5 keytab handle for the new MEMORY keytab, NULL
 *                         may be passed here if the caller has no use for the
 *                         handle
 *
 * The memory for the MEMORY keytab is handled by libkrb5 internally and
 * a reference counter is used. If the reference counter of the specific
 * MEMORY keytab reaches 0, i.e. no open ones are left, the memory is free.
 * This means we cannot call krb5_kt_close() for the new MEMORY keytab  in
 * copy_keytab_into_memory() because this would destroy it immediately. Hence
 * we have to return the handle so that the caller can safely remove the
 * MEMORY keytab if the is not needed anymore. Since libkrb5 frees the
 * internal memory when the library is unloaded short running processes can
 * safely pass NULL as the 5th argument because on exit all memory is freed.
 * Long running processes which need more control over the memory consumption
 * should close the handle for free the memory at runtime.
 */
krb5_error_code copy_keytab_into_memory(TALLOC_CTX *mem_ctx, krb5_context kctx,
                                        const char *inp_keytab_file,
                                        char **_mem_name,
                                        krb5_keytab *_mem_keytab);

errno_t set_extra_args(TALLOC_CTX *mem_ctx, struct krb5_ctx *krb5_ctx,
                       struct sss_domain_info *domain,
                       const char ***krb5_child_extra_args);
#endif /* __KRB5_COMMON_H__ */
