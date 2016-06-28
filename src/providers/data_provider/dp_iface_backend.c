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

errno_t dp_backend_is_online(struct sbus_request *sbus_req,
                             void *dp_cli,
                             const char *domname)
{
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;
    bool online;

    be_ctx = dp_client_be(dp_cli);

    if (SBUS_IS_STRING_EMPTY(domname)) {
        domain = be_ctx->domain;
    } else {
        domain = find_domain_by_name(be_ctx->domain, domname, false);
        if (domain == NULL) {
            sbus_request_reply_error(sbus_req, SBUS_ERROR_UNKNOWN_DOMAIN,
                                     "Unknown domain %s", domname);
            return EOK;
        }
    }

    if (domain == be_ctx->domain) {
        online = be_is_offline(be_ctx) == false;
    } else {
        online = domain->state == DOM_ACTIVE;
    }

    iface_dp_backend_IsOnline_finish(sbus_req, online);
    return EOK;
}
