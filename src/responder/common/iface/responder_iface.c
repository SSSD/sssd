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

#include "sbus/sssd_dbus.h"
#include "responder/common/iface/responder_iface.h"
#include "responder/common/responder.h"

struct iface_responder_domain iface_responder_domain = {
    { &iface_responder_domain_meta, 0 },
    .SetActive = sss_resp_domain_active,
    .SetInconsistent = sss_resp_domain_inconsistent,
};

struct iface_responder_ncache iface_responder_ncache = {
    { &iface_responder_ncache_meta, 0 },
    .ResetUsers = sss_resp_reset_ncache_users,
    .ResetGroups = sss_resp_reset_ncache_groups,
};

static struct sbus_iface_map iface_map[] = {
    { RESPONDER_PATH, &iface_responder_domain.vtable },
    { RESPONDER_PATH, &iface_responder_ncache.vtable },
    { NULL, NULL }
};

struct sbus_iface_map *responder_get_sbus_interface(void)
{
    return iface_map;
}
