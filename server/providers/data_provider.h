/*
   SSSD

   Data Provider, private header file

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

#ifndef __DATA_PROVIDER_H__
#define __DATA_PROVIDER_H__

#include <stdint.h>
#include <sys/un.h>
#include "talloc.h"
#include "events.h"
#include "ldb.h"

#define DATA_PROVIDER_VERSION 0x0001
#define DATA_PROVIDER_SERVICE_NAME "dp"
#define DATA_PROVIDER_ADDRESS "unix:path=/var/lib/sss/pipes/private/dbus-dp"

#define DATA_PROVIDER_DEF_DB_FILE "/var/lib/sss/db/sssd.ldb"
#define DATA_PROVIDER_DB_CONF_SEC "config/services/nss"

#define DATA_PROVIDER_PLUGINS_PATH "/usr/lib/sssd"

struct dp_mod_ops {
    int (*check_online)(void *pvt_data, int *reply);
};

typedef int (*sssm_init_fn_t)(TALLOC_CTX *, struct dp_mod_ops **, void **);

struct dp_module {
    const char *name;
    const char *domain;
    struct dp_mod_ops *ops;
    void *pvt_data;
};

struct dp_sbus_ctx {
    struct event_context *ev;
    struct sbus_method_ctx *sm_ctx;
    struct sbus_conn_ctx *scon_ctx;
};

struct dp_ctx {
    struct event_context *ev;
    struct confdb_ctx *cdb;
    struct ldb_context *ldb;
    struct dp_sbus_ctx *sbus_ctx;
    struct dp_module **modules;
};

struct dp_client {
    struct dp_ctx *dpctx;
    DBusConnection *conn;
};

#endif /* __DATA_PROVIDER_ */
