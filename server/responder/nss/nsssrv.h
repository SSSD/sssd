/*
   SSSD

   NSS Responder, header file

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

#ifndef __NSSSRV_H__
#define __NSSSRV_H__

#include <stdint.h>
#include <sys/un.h>
#include "config.h"
#include "talloc.h"
#include "tevent.h"
#include "ldb.h"
#include "../sss_client/sss_cli.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder_cmd.h"

#define NSS_SBUS_SERVICE_VERSION 0x0001
#define NSS_SBUS_SERVICE_NAME "nss"

#define NSS_PACKET_MAX_RECV_SIZE 1024

/* NSS_DOMAIN_DELIM can be specified in config.h */
#ifndef NSS_DOMAIN_DELIM
#define NSS_DOMAIN_DELIM '@'
#endif

#define NSS_ENUM_USERS 0x01
#define NSS_ENUM_GROUPS 0x02
#define NSS_ENUM_ALL 0x03

struct sysdb_ctx;
struct getent_ctx;

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

struct nss_packet;

struct cli_request {

    /* original request from the wire */
    struct sss_packet *in;

    /* reply data */
    struct sss_packet *out;
};

int nss_cmd_execute(struct cli_ctx *cctx);

/* from nsssrv_dp.c */
#define NSS_DP_USER 1
#define NSS_DP_GROUP 2
#define NSS_DP_INITGROUPS 3

typedef void (*nss_dp_callback_t)(uint16_t err_maj, uint32_t err_min,
                                  const char *err_msg, void *ptr);

int nss_dp_send_acct_req(struct nss_ctx *nctx, TALLOC_CTX *memctx,
                         nss_dp_callback_t callback, void *callback_ctx,
                         int timeout, const char *domain, int type,
                         const char *opt_name, uint32_t opt_id);
int nss_dp_init(struct nss_ctx *nctx);

#endif /* __NSSSRV_H__ */
