/*
    SSSD

    proxy_common.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "providers/proxy/proxy.h"

void proxy_reply(struct be_req *req, int dp_err,
                 int error, const char *errstr)
{
    if (!req->be_ctx->offstat.offline) {
        /* This action took place online.
         * Fire any online callbacks if necessary.
         * Note: we're checking the offline value directly,
         * because if the activity took a long time to
         * complete, calling be_is_offline() might report false
         * incorrectly.
         */
        be_run_online_cb(req->be_ctx);
    }
    return req->fn(req, dp_err, error, errstr);
}
