/*
   SSSD

   SSS Client Responder, header file

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

#ifndef __SSSSRV_CMD_H__
#define __SSSSRV_CMD_H__

#include <stdint.h>
#include <sys/un.h>
#include "talloc.h"
#include "tevent.h"
#include "ldb.h"
#include "../sss_client/sss_cli.h"

/* needed until nsssrv.h is updated */
#ifndef __NSSSRV_H__
struct cli_request {

    /* original request from the wire */
    struct sss_packet *in;

    /* reply data */
    struct sss_packet *out;
};

struct nss_ctx {
    struct tevent_context *ev;
    struct tevent_fd *lfde;
    int lfd;
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *cdb;
    char *sock_name;
    struct service_sbus_ctx *ss_ctx;
    struct service_sbus_ctx *dp_ctx;
    struct btreemap *domain_map;
    char *default_domain;

    int cache_timeout;

    struct sbus_method *sss_sbus_methods;
    struct sss_cmd_table *sss_cmds;
    const char *sss_pipe_name;
    const char *confdb_socket_path;
    struct sbus_method *dp_methods;
};


struct cli_ctx {
    struct tevent_context *ev;
    struct nss_ctx *nctx;
    int cfd;
    struct tevent_fd *cfde;
    struct sockaddr_un addr;
    struct cli_request *creq;
    struct getent_ctx *gctx;
};
#endif

struct sss_cmd_ctx {
    struct cli_ctx *cctx;
    const char *domain;
    const char *name;
    uid_t id;
    bool check_expiration;
};

struct sss_cmd_table {
    enum sss_cli_command cmd;
    int (*fn)(struct cli_ctx *cctx);
};

int sss_cmd_execute(struct cli_ctx *cctx, struct sss_cmd_table *sss_cmds);
void sss_cmd_done(struct sss_cmd_ctx *nctx);
int sss_cmd_get_version(struct cli_ctx *cctx);

#endif /* __SSSSRV_CMD_H__ */
