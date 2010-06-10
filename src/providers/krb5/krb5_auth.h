/*
    SSSD

    Kerberos Backend, private header file

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

#ifndef __KRB5_AUTH_H__
#define __KRB5_AUTH_H__

#include <pcre.h>

#include "util/sss_krb5.h"
#include "providers/dp_backend.h"
#include "providers/krb5/krb5_common.h"

#define CCACHE_ENV_NAME "KRB5CCNAME"

#define ILLEGAL_PATH_PATTERN "//|/\\./|/\\.\\./"

struct krb5child_req {
    pid_t child_pid;
    int read_from_child_fd;
    int write_to_child_fd;

    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;

    struct tevent_timer *timeout_handler;

    const char *ccname;
    const char *old_ccname;
    const char *homedir;
    const char *upn;
    uid_t uid;
    gid_t gid;
    bool is_offline;
    struct fo_server *srv;
    struct fo_server *kpasswd_srv;
    bool active_ccache_present;
    bool valid_tgt_present;
};

void krb5_pam_handler(struct be_req *be_req);

struct tevent_req *krb5_auth_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct pam_data *pd,
                                  struct krb5_ctx *krb5_ctx);
int krb5_auth_recv(struct tevent_req *req, int *pam_status, int *dp_err);

errno_t add_user_to_delayed_online_authentication(struct krb5_ctx *krb5_ctx,
                                                  struct pam_data *pd,
                                                  uid_t uid);
errno_t init_delayed_online_authentication(struct krb5_ctx *krb5_ctx,
                                           struct be_ctx *be_ctx,
                                           struct tevent_context *ev);
#endif /* __KRB5_AUTH_H__ */
