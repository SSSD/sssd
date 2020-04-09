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

#include "sbus/sbus_request.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

errno_t
dp_backend_is_online(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct be_ctx *be_ctx,
                     const char *domname,
                     bool *_is_online)
{
    struct sss_domain_info *domain;

    if (SBUS_REQ_STRING_IS_EMPTY(domname)) {
        domain = be_ctx->domain;
    } else {
        domain = find_domain_by_name(be_ctx->domain, domname, false);
        if (domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }
    }

    /**
     * FIXME: https://github.com/SSSD/sssd/issues/4825
     * domain->state is set only for subdomains not for the main domain
     */
    if (be_ctx->domain == domain) {
        *_is_online = be_is_offline(be_ctx) == false;
    } else {
        *_is_online = domain->state == DOM_ACTIVE;
    }

    return EOK;
}
