/*
   SSSD

   Data Provider Helpers

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com> 2009

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

#ifndef SBUS_CLIENT_H_
#define SBUS_CLIENT_H_

#include "tevent.h"
#include "sbus/sssd_dbus.h"

int sbus_client_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     const char *server_address,
                     struct sbus_interface *intf,
                     struct sbus_connection **_conn,
                     sbus_conn_destructor_fn destructor,
                     void *conn_pvt_data);

#endif /* SBUS_CLIENT_H_ */
