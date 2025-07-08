/*
    SSSD

    sdap_dyndns.h: LDAP specific dynamic DNS update

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

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

#ifndef SDAP_DYNDNS_H_
#define SDAP_DYNDNS_H_

#include "util/util.h"
#include "providers/backend.h"
#include "providers/be_dyndns.h"
#include "providers/ldap/ldap_common.h"

struct tevent_req *
sdap_dyndns_update_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct be_ctx *be_ctx,
                        struct dp_option *opts,
                        struct sdap_id_ctx *sdap_ctx,
                        enum be_nsupdate_auth auth_type,
                        enum be_nsupdate_auth auth_ptr_type,
                        const char *ifname_filter,
                        const char *network_filter,
                        const char *hostname,
                        const char *realm,
                        const int ttl,
                        bool check_diff);

errno_t sdap_dyndns_update_recv(struct tevent_req *req);

#endif /* SDAP_DYNDNS_H_ */
