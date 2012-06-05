/*
    SSSD

    LDAP Common utility code

    Copyright (C) Simo Sorce <ssorce@redhat.com> 2009

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

#ifndef _LDAP_COMMON_H_
#define _LDAP_COMMON_H_

#include "providers/dp_backend.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_id_op.h"
#include "providers/fail_over.h"
#include "providers/krb5/krb5_common.h"
#include "lib/idmap/sss_idmap.h"

#define PWD_POL_OPT_NONE "none"
#define PWD_POL_OPT_SHADOW "shadow"
#define PWD_POL_OPT_MIT "mit_kerberos"

#define SSS_LDAP_SRV_NAME "ldap"

#define LDAP_STANDARD_URI "ldap://"
#define LDAP_SSL_URI "ldaps://"
#define LDAP_LDAPI_URI "ldapi://"

/* a fd the child process would log into */
extern int ldap_child_debug_fd;

struct sdap_id_ctx {
    struct be_ctx *be;
    struct sdap_options *opts;
    struct fo_service *fo_service;
    struct sdap_service *service;

    /* If using GSSAPI */
    struct krb5_service *krb5_service;

    /* LDAP connection cache */
    struct sdap_id_conn_cache *conn_cache;

    /* enumeration loop timer */
    struct timeval last_enum;
    /* cleanup loop timer */
    struct timeval last_purge;

    struct sdap_server_opts *srv_opts;
};

struct sdap_auth_ctx {
    struct be_ctx *be;
    struct sdap_options *opts;
    struct sdap_service *service;
    struct sdap_service *chpass_service;
};

int sssm_ldap_id_init(struct be_ctx *bectx,
                      struct bet_ops **ops,
                      void **pvt_data);

void sdap_check_online(struct be_req *breq);
void sdap_do_online_check(struct be_req *be_req, struct sdap_id_ctx *ctx);

/* id */
void sdap_account_info_handler(struct be_req *breq);
void sdap_handle_account_info(struct be_req *breq, struct sdap_id_ctx *ctx);
int sdap_id_setup_tasks(struct sdap_id_ctx *ctx);

/* auth */
void sdap_pam_auth_handler(struct be_req *breq);

/* chpass */
void sdap_pam_chpass_handler(struct be_req *breq);

/* access */
void sdap_pam_access_handler(struct be_req *breq);

/* autofs */
void sdap_autofs_handler(struct be_req *breq);

void sdap_handler_done(struct be_req *req, int dp_err,
                       int error, const char *errstr);

int sdap_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name, const char *dns_service_name,
                      const char *urls, const char *backup_urls,
                      struct sdap_service **_service);

int sdap_gssapi_init(TALLOC_CTX *mem_ctx,
                     struct dp_option *opts,
                     struct be_ctx *bectx,
                     struct sdap_service *sdap_service,
                     struct krb5_service **krb5_service);

errno_t sdap_install_offline_callback(TALLOC_CTX *mem_ctx,
                                      struct be_ctx *be_ctx,
                                      const char *realm,
                                      const char *service_name);

errno_t sdap_install_sigterm_handler(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     const char *realm);

void sdap_remove_kdcinfo_files_callback(void *pvt);

/* options parser */
int ldap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts);

int ldap_get_sudo_options(TALLOC_CTX *memctx,
                          struct confdb_ctx *cdb,
                          const char *conf_path,
                          struct sdap_options *opts,
                          bool *use_host_filter,
                          bool *include_regexp,
                          bool *include_netgroups);

int ldap_get_autofs_options(TALLOC_CTX *memctx,
                            struct confdb_ctx *cdb,
                            const char *conf_path,
                            struct sdap_options *opts);

int ldap_id_enumerate_set_timer(struct sdap_id_ctx *ctx, struct timeval tv);
int ldap_id_cleanup_set_timer(struct sdap_id_ctx *ctx, struct timeval tv);

void sdap_mark_offline(struct sdap_id_ctx *ctx);

struct tevent_req *users_get_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_id_ctx *ctx,
                                  const char *name,
                                  int filter_type,
                                  int attrs_type);
int users_get_recv(struct tevent_req *req, int *dp_error_out);

struct tevent_req *groups_get_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_id_ctx *ctx,
                                   const char *name,
                                   int filter_type,
                                   int attrs_type);
int groups_get_recv(struct tevent_req *req, int *dp_error_out);


struct tevent_req *ldap_netgroup_get_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct sdap_id_ctx *ctx,
                                          const char *name);
int ldap_netgroup_get_recv(struct tevent_req *req, int *dp_error_out);

struct tevent_req *
services_get_send(TALLOC_CTX *mem_ctx,
                  struct tevent_context *ev,
                  struct sdap_id_ctx *id_ctx,
                  const char *name,
                  const char *protocol,
                  int filter_type);

errno_t
services_get_recv(struct tevent_req *req, int *dp_error_out);

/* setup child logging */
int setup_child(struct sdap_id_ctx *ctx);


errno_t string_to_shadowpw_days(const char *s, long *d);

errno_t get_sysdb_attr_name(TALLOC_CTX *mem_ctx,
                            struct sdap_attr_map *map,
                            size_t map_size,
                            const char *ldap_name,
                            char **sysdb_name);

errno_t list_missing_attrs(TALLOC_CTX *mem_ctx,
                           struct sdap_attr_map *map,
                           size_t map_size,
                           struct sysdb_attrs *recvd_attrs,
                           char ***missing_attrs);

bool sdap_is_secure_uri(const char *uri);

char *sdap_get_id_specific_filter(TALLOC_CTX *mem_ctx,
                                  const char *base_filter,
                                  const char *extra_filter);

errno_t msgs2attrs_array(TALLOC_CTX *mem_ctx, size_t count,
                         struct ldb_message **msgs,
                         struct sysdb_attrs ***attrs);

errno_t sdap_parse_search_base(TALLOC_CTX *mem_ctx,
                               struct dp_option *opts, int class,
                               struct sdap_search_base ***_search_bases);
errno_t common_parse_search_base(TALLOC_CTX *mem_ctx,
                                 const char *unparsed_base,
                                 const char *class_name,
                                 const char *old_filter,
                                 struct sdap_search_base ***_search_bases);

errno_t
sdap_attrs_get_sid_str(TALLOC_CTX *mem_ctx,
                       struct sdap_idmap_ctx *idmap_ctx,
                       struct sysdb_attrs *sysdb_attrs,
                       const char *sid_attr,
                       char **_sid_str);
#endif /* _LDAP_COMMON_H_ */
