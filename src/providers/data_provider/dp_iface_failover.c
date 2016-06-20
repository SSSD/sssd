/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <talloc.h>
#include <tevent.h>

#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_errors.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

errno_t dp_failover_list_services(struct sbus_request *sbus_req,
                                  void *dp_cli,
                                  const char *domname)
{
    struct be_ctx *be_ctx;
    struct be_svc_data *svc;
    const char **services;
    int num_services;

    be_ctx = dp_client_be(dp_cli);

    num_services = 0;
    DLIST_FOR_EACH(svc, be_ctx->be_fo->svcs) {
        num_services++;
    }

    services = talloc_zero_array(sbus_req, const char *, num_services);
    if (services == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        return ENOMEM;
    }

    num_services = 0;
    DLIST_FOR_EACH(svc, be_ctx->be_fo->svcs) {
        services[num_services] = talloc_strdup(services, svc->name);
        if (services[num_services] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            talloc_free(services);
            return ENOMEM;
        }
        num_services++;
    }

    iface_dp_failover_ListServices_finish(sbus_req, services, num_services);
    return EOK;
}
