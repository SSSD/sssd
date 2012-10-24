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

#include "providers/dp_backend.h"
#include "util/util.h"
#include "util/sss_krb5.h"

#define SSSD_KRB5_KDC "SSSD_KRB5_KDC"
#define SSSD_KRB5_REALM "SSSD_KRB5_REALM"
#define SSSD_KRB5_RENEWABLE_LIFETIME "SSSD_KRB5_RENEWABLE_LIFETIME"
#define SSSD_KRB5_LIFETIME "SSSD_KRB5_LIFETIME"
#define SSSD_KRB5_USE_FAST "SSSD_KRB5_USE_FAST"
#define SSSD_KRB5_FAST_PRINCIPAL "SSSD_KRB5_FAST_PRINCIPAL"
#define SSSD_KRB5_CANONICALIZE "SSSD_KRB5_CANONICALIZE"

#define KDCINFO_TMPL PUBCONF_PATH"/kdcinfo.%s"
#define KPASSWDINFO_TMPL PUBCONF_PATH"/kpasswdinfo.%s"

#define SSS_KRB5KDC_FO_SRV "KERBEROS"
#define SSS_KRB5KPASSWD_FO_SRV "KPASSWD"

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
    KRB5_CANONICALIZE,

    KRB5_OPTS
};

typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

struct tgt_times {
    time_t authtime;
    time_t starttime;
    time_t endtime;
    time_t renew_till;
};

struct krb5_service {
    char *name;
    char *realm;
};

struct fo_service;
struct deferred_auth_ctx;
struct renew_tgt_ctx;
struct sss_krb5_cc_be;

struct krb5_ctx {
    /* opts taken from kinit */
    /* in seconds */
    krb5_deltat starttime;
    krb5_deltat lifetime;
    krb5_deltat rlife;

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
    int child_debug_fd;

    struct sss_krb5_cc_be *cc_be;
    pcre *illegal_path_re;

    struct deferred_auth_ctx *deferred_auth_ctx;
    struct renew_tgt_ctx *renew_tgt_ctx;
    bool use_fast;

    hash_table_t *wait_queue_hash;
};

struct remove_info_files_ctx {
    char *realm;
    struct be_ctx *be_ctx;
    const char *kdc_service_name;
    const char *kpasswd_service_name;
};

errno_t check_and_export_options(struct dp_option *opts,
                                 struct sss_domain_info *dom,
                                 struct krb5_ctx *krb5_ctx);

errno_t krb5_try_kdcip(struct confdb_ctx *cdb, const char *conf_path,
                       struct dp_option *opts, int opt_id);

errno_t krb5_get_options(TALLOC_CTX *memctx, struct confdb_ctx *cdb,
                         const char *conf_path, struct dp_option **_opts);

errno_t write_krb5info_file(const char *realm, const char *kdc,
                            const char *service);

int krb5_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name,
                      const char *primary_servers,
                      const char *backup_servers,
                      const char *realm, struct krb5_service **_service);

void remove_krb5_info_files_callback(void *pvt);

void krb5_finalize(struct tevent_context *ev,
                   struct tevent_signal *se,
                   int signum,
                   int count,
                   void *siginfo,
                   void *private_data);

errno_t krb5_install_offline_callback(struct be_ctx *be_ctx,
                                      struct krb5_ctx *krb_ctx);

errno_t krb5_install_sigterm_handler(struct tevent_context *ev,
                                     struct krb5_ctx *krb5_ctx);

errno_t write_krb5info_file(const char *realm, const char *kdc,
                            const char *service);

errno_t remove_krb5_info_files(TALLOC_CTX *mem_ctx, const char *realm);

errno_t krb5_get_simple_upn(TALLOC_CTX *mem_ctx, struct krb5_ctx *krb5_ctx,
                            const char *domain_name, const char *username,
                            const char *user_dom, char **_upn);

errno_t compare_principal_realm(const char *upn, const char *realm,
                                bool *different_realm);


int sssm_krb5_auth_init(struct be_ctx *bectx,
                        struct bet_ops **ops,
                        void **pvt_auth_data);

#endif /* __KRB5_COMMON_H__ */
