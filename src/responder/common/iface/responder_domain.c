/*
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

#include <string.h>
#include <errno.h>

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder.h"
#include "responder/common/iface/responder_iface.h"

static void set_domain_state_by_name(struct resp_ctx *rctx,
                                     const char *domain_name,
                                     enum sss_domain_state state)
{
    struct sss_domain_info *dom;

    if (domain_name == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "BUG: NULL domain name\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Setting state of domain %s\n", domain_name);

    for (dom = rctx->domains;
         dom != NULL;
         dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {

        if (strcasecmp(dom->name, domain_name) == 0) {
            break;
        }
    }

    if (dom != NULL) {
        sss_domain_set_state(dom, state);
    }
}

int sss_resp_domain_active(struct sbus_request *req,
                           void *data,
                           const char *domain_name)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);

    DEBUG(SSSDBG_TRACE_LIBS, "Enabling domain %s\n", domain_name);
    set_domain_state_by_name(rctx, domain_name, DOM_ACTIVE);
    return iface_responder_domain_SetActive_finish(req);
}

int sss_resp_domain_inconsistent(struct sbus_request *req,
                                 void *data,
                                 const char *domain_name)
{
    struct resp_ctx *rctx = talloc_get_type(data, struct resp_ctx);

    DEBUG(SSSDBG_TRACE_LIBS, "Disabling domain %s\n", domain_name);
    set_domain_state_by_name(rctx, domain_name, DOM_INCONSISTENT);
    return iface_responder_domain_SetInconsistent_finish(req);
}
