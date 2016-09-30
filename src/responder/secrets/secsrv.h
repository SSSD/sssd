/*
   SSSD

   Secrets Responder, header file

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016

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

#ifndef __SECSRV_H__
#define __SECSRV_H__

#include "config.h"

#include <stdint.h>
#include <sys/un.h>
#include <talloc.h>
#include <tevent.h>
#include <ldb.h>

#define SEC_NET_TIMEOUT 5

struct resctx;

struct sec_ctx {
    struct resolv_ctx *resctx;
    struct resp_ctx *rctx;
    int fd_limit;
    int containers_nest_level;
    int max_secrets;

    struct provider_handle **providers;
};

int sec_connection_setup(struct cli_ctx *cctx);

#endif /* __SECSRV_H__ */
