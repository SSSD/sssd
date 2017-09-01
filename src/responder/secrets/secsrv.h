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

struct sec_quota {
    int max_secrets;
    int max_uid_secrets;
    int max_payload_size;
    int containers_nest_level;
};

struct sec_hive_config {
    const char *confdb_section;

    struct sec_quota quota;
};

struct sec_ctx {
    struct resp_ctx *rctx;
    int fd_limit;

    struct sec_hive_config sec_config;
    struct sec_hive_config kcm_config;
    int max_payload_size;

    struct provider_handle **providers;
};

int sec_connection_setup(struct cli_ctx *cctx);

#endif /* __SECSRV_H__ */
