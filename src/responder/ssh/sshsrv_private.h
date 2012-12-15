/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

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

#ifndef _SSHSRV_PRIVATE_H_
#define _SSHSRV_PRIVATE_H_

#include "responder/common/responder.h"

#define SSS_SSH_KNOWN_HOSTS_PATH PUBCONF_PATH"/known_hosts"
#define SSS_SSH_KNOWN_HOSTS_TEMP_TMPL PUBCONF_PATH"/.known_hosts.XXXXXX"

struct ssh_ctx {
    struct resp_ctx *rctx;

    bool hash_known_hosts;
    int known_hosts_timeout;
};

struct ssh_cmd_ctx {
    struct cli_ctx *cctx;
    char *name;
    char *alias;
    char *domname;

    struct sss_domain_info *domain;
    bool check_next;

    struct ldb_message *result;
};

struct sss_cmd_table *get_ssh_cmds(void);

struct tevent_req *
sss_dp_get_ssh_host_send(TALLOC_CTX *mem_ctx,
                         struct resp_ctx *rctx,
                         struct sss_domain_info *dom,
                         bool fast_reply,
                         const char *name,
                         const char *alias);

errno_t
sss_dp_get_ssh_host_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         dbus_uint16_t *dp_err,
                         dbus_uint32_t *dp_ret,
                         char **err_msg);

#endif /* _SSHSRV_PRIVATE_H_ */
