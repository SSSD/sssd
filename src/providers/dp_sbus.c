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

int dp_get_sbus_address(TALLOC_CTX *mem_ctx,
                        char **address, const char *domain_name)
{
    char *default_address;

    *address = NULL;
    default_address = talloc_asprintf(mem_ctx, "unix:path=%s/%s_%s",
                                      PIPE_PATH, DATA_PROVIDER_PIPE,
                                      domain_name);
    if (default_address == NULL) {
        return ENOMEM;
    }

    *address = default_address;
    return EOK;
}

