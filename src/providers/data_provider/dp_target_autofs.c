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
#include "responder/common/responder.h"

errno_t dp_autofs_handler(struct sbus_request *sbus_req,
                          void *dp_cli,
                          uint32_t dp_flags,
                          uint32_t method,
                          const char *mapname,
                          const char *entryname)
{
    struct dp_autofs_data *data;
    const char *key;
    enum dp_methods dp_method;


    if (mapname == NULL) {
        return EINVAL;
    }

    data = talloc_zero(sbus_req, struct dp_autofs_data);
    if (data == NULL) {
        return ENOMEM;
    }

    data->mapname = mapname;
    data->entryname = entryname;

    key = talloc_asprintf(sbus_req, "%u:%s:%s", method, mapname, entryname);
    if (key == NULL) {
        return ENOMEM;
    }

    switch (method) {
    case SSS_DP_AUTOFS_ENUMERATE:
        dp_method = DPM_AUTOFS_ENUMERATE;
        break;
    case SSS_DP_AUTOFS_GET_MAP:
        dp_method = DPM_AUTOFS_GET_MAP;
        break;
    case SSS_DP_AUTOFS_GET_ENTRY:
        dp_method = DPM_AUTOFS_GET_ENTRY;
        break;
    }

    dp_req_with_reply(dp_cli, NULL, "AutoFS", key, sbus_req, DPT_AUTOFS,
                      dp_method, dp_flags, data,
                      dp_req_reply_std, struct dp_reply_std);

    return EOK;
}
