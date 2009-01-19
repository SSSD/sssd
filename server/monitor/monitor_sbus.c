/*
   SSSD

   Data Provider Helpers

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include "util/util.h"
#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "monitor/monitor_sbus.h"
#include "monitor/monitor_interfaces.h"

int monitor_get_sbus_address(TALLOC_CTX *mem_ctx, struct confdb_ctx *confdb, char **address)
{
    int ret;
    char *default_address;

    *address = NULL;
    default_address = talloc_asprintf(mem_ctx, "unix:path=%s/%s",
                                      PIPE_PATH, SSSD_SERVICE_PIPE);
    if (default_address == NULL) {
        return ENOMEM;
    }

    if (confdb == NULL) {
        /* If the confdb isn't specified, fall to the default */
        *address = default_address;
        talloc_steal(mem_ctx, default_address);
        ret = EOK;
        goto done;
    }

    ret = confdb_get_string(confdb, mem_ctx,
                            "config/services/monitor", "sbusAddress",
                            default_address, address);

done:
    talloc_free(default_address);
    return ret;
}

int monitor_init_sbus_methods(TALLOC_CTX *mem_ctx, struct sbus_method *methods,
                              struct sbus_method_ctx **sm_ctx)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct sbus_method_ctx *method_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    method_ctx = talloc_zero(tmp_ctx, struct sbus_method_ctx);
    if (method_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    method_ctx->interface = talloc_strdup(method_ctx, SERVICE_INTERFACE);
    if (method_ctx->interface == NULL) {
        ret = ENOMEM;
        goto done;
    }

    method_ctx->path = talloc_strdup(method_ctx, SERVICE_PATH);
    if (method_ctx->path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    method_ctx->methods = methods;
    method_ctx->message_handler = sbus_message_handler;

    *sm_ctx = method_ctx;
    talloc_steal(mem_ctx, method_ctx);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
