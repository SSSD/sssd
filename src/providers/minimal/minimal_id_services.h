/*
    SSSD

    minimal Identity Backend Module

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2025 Red Hat

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


#ifndef _MINIMAL_ID_SERVICES_H_
#define _MINIMAL_ID_SERVICES_H_

#include "config.h"
#include <talloc.h>
#include <tevent.h>

#include "providers/backend.h"
#include "providers/ldap/ldap_common.h"
#include "util/util.h"
#include "providers/failover/failover.h"

struct tevent_req *
minimal_services_get_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct sss_failover_ctx *fctx,
                          struct sdap_id_ctx *id_ctx,
                          struct sdap_domain *sdom,
                          const char *name,
                          const char *protocol,
                          int filter_type,
                          bool noexist_delete);

errno_t
minimal_services_get_recv(struct tevent_req *req);

#endif
