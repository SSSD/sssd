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

#include "sbus/sssd_dbus.h"
#include "responder/nss/nss_iface.h"
#include "responder/nss/nsssrv.h"

struct iface_nss_memorycache iface_nss_memorycache = {
    { &iface_nss_memorycache_meta, 0 },
    .UpdateInitgroups = nss_memorycache_update_initgroups
};

static struct sbus_iface_map iface_map[] = {
    { NSS_MEMORYCACHE_PATH, &iface_nss_memorycache.vtable },
    { NULL, NULL }
};

struct sbus_iface_map *nss_get_sbus_interface()
{
    return iface_map;
}
