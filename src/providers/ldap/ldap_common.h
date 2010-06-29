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

#define PWD_POL_OPT_NONE "none"
#define PWD_POL_OPT_SHADOW "shadow"
#define PWD_POL_OPT_MIT "mit_kerberos"

#define SSS_LDAP_SRV_NAME "ldap"

/* a fd the child process would log into */
extern int ldap_child_debug_fd;

struct sdap_id_ctx {
    struct be_ctx *be;
    struct sdap_options *opts;
    struct fo_service *fo_service;
    struct sdap_service *service;

    /* LDAP connection cache */
    struct sdap_id_conn_cache *conn_cache;

    /* enumeration loop timer */
    struct timeval last_enum;
    /* cleanup loop timer */
    struct timeval last_purge;

    char *max_user_timestamp;
    char *max_group_timestamp;
};

struct sdap_auth_ctx {
    struct be_ctx *be;
    struct sdap_options *opts;
    struct fo_service *fo_service;
    struct sdap_service *service;
};

/* id */
void sdap_account_info_handler(struct be_req *breq);
int sdap_id_setup_tasks(struct sdap_id_ctx *ctx);

/* auth */
void sdap_pam_auth_handler(struct be_req *breq);

/* chpass */
void sdap_pam_chpass_handler(struct be_req *breq);

/* access */
void sdap_pam_access_handler(struct be_req *breq);



void sdap_handler_done(struct be_req *req, int dp_err,
                       int error, const char *errstr);

int sdap_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                      const char *service_name, const char *dns_service_name,
                      const char *urls, struct sdap_service **_service);

/* options parser */
int ldap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts);

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

/* setup child logging */
int setup_child(struct sdap_id_ctx *ctx);

#endif /* _LDAP_COMMON_H_ */
