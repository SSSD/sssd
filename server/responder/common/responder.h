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

#ifndef __SSS_RESPONDER_H__
#define __SSS_RESPONDER_H__

#include <stdint.h>
#include <sys/un.h>
#include <pcre.h>
#include "config.h"
#include "talloc.h"
#include "tevent.h"
#include "ldb.h"
#include "sbus/sssd_dbus.h"
#include "../sss_client/sss_cli.h"
#include "util/btreemap.h"

/* needed until nsssrv.h is updated */
struct cli_request {

    /* original request from the wire */
    struct sss_packet *in;

    /* reply data */
    struct sss_packet *out;
};

struct sss_names_ctx {
    char *re_pattern;
    char *fq_fmt;

    pcre *re;
};

struct resp_ctx {
    struct tevent_context *ev;
    struct tevent_fd *lfde;
    int lfd;
    struct tevent_fd *priv_lfde;
    int priv_lfd;
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *cdb;
    const char *sock_name;
    const char *priv_sock_name;
    struct service_sbus_ctx *ss_ctx;
    struct service_sbus_ctx *dp_ctx;

    struct btreemap *domain_map;
    char *default_domain;

    struct sbus_method *sss_sbus_methods;
    struct sss_cmd_table *sss_cmds;
    const char *sss_pipe_name;
    const char *confdb_service_path;
    struct sbus_method *dp_methods;

    struct sss_names_ctx *names;

    void *pvt_ctx;
};

struct cli_ctx {
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    int cfd;
    struct tevent_fd *cfde;
    struct sockaddr_un addr;
    struct cli_request *creq;
    int priv;
};

struct sss_cmd_table {
    enum sss_cli_command cmd;
    int (*fn)(struct cli_ctx *cctx);
};

/* responder_common.c */
int sss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb,
                     struct sbus_method sss_sbus_methods[],
                     struct sss_cmd_table sss_cmds[],
                     const char *sss_pipe_name,
                     const char *sss_priv_pipe_name,
                     const char *confdb_service_path,
                     struct sbus_method dp_methods[],
                     struct resp_ctx **responder_ctx);

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **domain, char **name);

/* responder_cmd.c */
int sss_cmd_execute(struct cli_ctx *cctx, struct sss_cmd_table *sss_cmds);
void sss_cmd_done(struct cli_ctx *cctx, void *freectx);
int sss_cmd_get_version(struct cli_ctx *cctx);

/* responder_dp.c */
int sss_dp_init(struct resp_ctx *rctx, struct sbus_method dp_methods[]);

#endif /* __SSS_RESPONDER_H__ */
