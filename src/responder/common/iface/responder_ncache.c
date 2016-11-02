/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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
#include "sbus/sssd_dbus.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "responder/common/iface/responder_iface.h"

int sss_resp_reset_ncache_users(struct sbus_request *req, void *data)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);

    sss_ncache_reset_users(rctx->ncache);
    return iface_responder_ncache_ResetUsers_finish(req);
}

int sss_resp_reset_ncache_groups(struct sbus_request *req, void *data)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);

    sss_ncache_reset_groups(rctx->ncache);
    return iface_responder_ncache_ResetGroups_finish(req);
}
