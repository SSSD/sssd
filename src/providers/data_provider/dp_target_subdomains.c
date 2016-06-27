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
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

errno_t dp_subdomains_handler(struct sbus_request *sbus_req,
                              void *dp_cli,
                              const char *domain_hint)
{
    struct dp_subdomains_data *data;
    const char *key;

    data = talloc_zero(sbus_req, struct dp_subdomains_data);
    if (data == NULL) {
        return ENOMEM;
    }

    data->domain_hint = domain_hint;
    key = SBUS_IS_STRING_EMPTY(domain_hint) ? "<ALL>" : domain_hint;

    dp_req_with_reply(dp_cli, NULL, "Subdomains", key, sbus_req,
                      DPT_SUBDOMAINS, DPM_DOMAINS_HANDLER, 0, data,
                      dp_req_reply_std, struct dp_reply_std);

    return EOK;
}
