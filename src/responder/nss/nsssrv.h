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
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"

#define NSS_SBUS_SERVICE_VERSION 0x0001
#define NSS_SBUS_SERVICE_NAME "nss"

#define NSS_PACKET_MAX_RECV_SIZE 1024

struct getent_ctx;
struct sss_mc_ctx;

struct nss_ctx {
    struct resp_ctx *rctx;

    int neg_timeout;
    struct sss_nc_ctx *ncache;

    int cache_refresh_percent;

    int enum_cache_timeout;

    struct getent_ctx *pctx;
    struct getent_ctx *gctx;
    struct getent_ctx *svcctx;
    hash_table_t *netgroups;

    bool filter_users_in_groups;

    char *pwfield;

    char *override_homedir;
    char *fallback_homedir;
    char **allowed_shells;
    char *override_shell;
    char **vetoed_shells;
    char **etc_shells;
    char *shell_fallback;
    char *default_shell;

    struct sss_mc_ctx *pwd_mc_ctx;
    struct sss_mc_ctx *grp_mc_ctx;
};

struct nss_packet;

int nss_cmd_execute(struct cli_ctx *cctx);

struct sss_cmd_table *get_nss_cmds(void);

#endif /* __NSSSRV_H__ */
