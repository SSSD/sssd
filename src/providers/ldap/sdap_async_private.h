/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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

#ifndef _SDAP_ASYNC_PRIVATE_H_
#define _SDAP_ASYNC_PRIVATE_H_

#include "config.h"
#include "util/sss_krb5.h"
#include "providers/ldap/sdap_async.h"

struct dn_item {
    const char *dn;
    /* Parent netgroup containing this record */
    struct sysdb_attrs *netgroup;
    char *cn;
    struct dn_item *next;
    struct dn_item *prev;
};

bool is_dn(const char *str);
errno_t update_dn_list(struct dn_item *dn_list,
                       const size_t count,
                       struct ldb_message **res,
                       bool *all_resolved);

void make_realm_upper_case(const char *upn);
struct sdap_handle *sdap_handle_create(TALLOC_CTX *memctx);

void sdap_ldap_result(struct tevent_context *ev, struct tevent_fd *fde,
                      uint16_t flags, void *pvt);

int setup_ldap_connection_callbacks(struct sdap_handle *sh,
                                    struct tevent_context *ev);
int remove_ldap_connection_callbacks(struct sdap_handle *sh);

int get_fd_from_ldap(LDAP *ldap, int *fd);

errno_t sdap_set_connected(struct sdap_handle *sh, struct tevent_context *ev);

errno_t sdap_call_conn_cb(const char *uri,int fd, struct sdap_handle *sh);

int sdap_op_add(TALLOC_CTX *memctx, struct tevent_context *ev,
                struct sdap_handle *sh, int msgid,
                sdap_op_callback_t *callback, void *data,
                int timeout, struct sdap_op **_op);

struct tevent_req *sdap_get_rootdse_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh);
int sdap_get_rootdse_recv(struct tevent_req *req,
                          TALLOC_CTX *memctx,
                          struct sysdb_attrs **rootdse);

errno_t deref_string_to_val(const char *str, int *val);

/* from sdap_child_helpers.c */

struct tevent_req *sdap_get_tgt_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     const char *realm_str,
                                     const char *princ_str,
                                     const char *keytab_name,
                                     int32_t lifetime,
                                     int timeout);

int sdap_get_tgt_recv(struct tevent_req *req,
                      TALLOC_CTX *mem_ctx,
                      int  *result,
                      krb5_error_code *kerr,
                      char **ccname,
                      time_t *expire_time_out);

int sdap_save_users(TALLOC_CTX *memctx,
                    struct sysdb_ctx *sysdb,
                    struct sss_domain_info *dom,
                    struct sdap_options *opts,
                    struct sysdb_attrs **users,
                    int num_users,
                    char **_usn_value);

int sdap_initgr_common_store(struct sysdb_ctx *sysdb,
                             struct sdap_options *opts,
                             const char *name,
                             enum sysdb_member_type type,
                             char **sysdb_grouplist,
                             struct sysdb_attrs **ldap_groups,
                             int ldap_groups_count);

errno_t get_sysdb_grouplist(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            const char *name,
                            char ***grouplist);

#endif /* _SDAP_ASYNC_PRIVATE_H_ */
