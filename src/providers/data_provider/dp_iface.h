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

#ifndef DP_IFACE_H_
#define DP_IFACE_H_

#include "sbus/sssd_dbus.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_responder_iface.h"
#include "providers/data_provider/dp.h"

#define DP_PATH "/org/freedesktop/sssd/dataprovider"

errno_t dp_register_sbus_interface(struct sbus_connection *conn,
                                   struct dp_client *pvt);

#endif /* DP_IFACE_H_ */
