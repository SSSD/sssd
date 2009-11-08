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

struct sdap_id_ctx {
    struct be_ctx *be;

    struct sdap_options *opts;

    /* what rootDSE returns */
    struct sysdb_attrs *rootDSE;

    /* global sdap handler */
    struct sdap_handle *gsh;

    /* enumeration loop timer */
    struct timeval last_run;

    char *max_user_timestamp;
    char *max_group_timestamp;
};

struct sdap_auth_ctx {
    struct be_ctx *be;
    struct sdap_options *opts;
};

/* id */
void sdap_account_info_handler(struct be_req *breq);
int sdap_id_setup_tasks(struct sdap_id_ctx *ctx);

/* auth */
void sdap_pam_auth_handler(struct be_req *breq);

/* chpass */
void sdap_pam_chpass_handler(struct be_req *breq);



void sdap_handler_done(struct be_req *req, int dp_err,
                       int error, const char *errstr);

/* options parser */
int ldap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts);

int ldap_id_enumerate_set_timer(struct sdap_id_ctx *ctx, struct timeval tv);
int ldap_id_cleanup_set_timer(struct sdap_id_ctx *ctx, struct timeval tv);

bool sdap_connected(struct sdap_id_ctx *ctx);
void sdap_mark_offline(struct sdap_id_ctx *ctx);

struct tevent_req *users_get_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_id_ctx *ctx,
                                  const char *name,
                                  int filter_type,
                                  int attrs_type);
int users_get_recv(struct tevent_req *req);

struct tevent_req *groups_get_send(TALLOC_CTX *memctx,
                                   struct tevent_context *ev,
                                   struct sdap_id_ctx *ctx,
                                   const char *name,
                                   int filter_type,
                                   int attrs_type);
int groups_get_recv(struct tevent_req *req);

#endif /* _LDAP_COMMON_H_ */
