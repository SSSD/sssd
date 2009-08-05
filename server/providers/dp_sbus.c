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

#include "config.h"
#include "talloc.h"
#include "tevent.h"
#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "providers/data_provider.h"
#include "providers/dp_sbus.h"
#include "providers/dp_interfaces.h"

int dp_get_sbus_address(TALLOC_CTX *mem_ctx, struct confdb_ctx *confdb, char **address)
{
    int ret;
    char *default_address;

    *address = NULL;
    default_address = talloc_asprintf(mem_ctx, "unix:path=%s/%s",
                                      PIPE_PATH, DATA_PROVIDER_PIPE);
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
                            "config/services/dp", "sbusAddress",
                            default_address, address);

done:
    talloc_free(default_address);
    return ret;
}

