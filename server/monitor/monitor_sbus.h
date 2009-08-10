/*
   SSSD

   Data Provider Helpers

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#ifndef MONITOR_SBUS_H_
#define MONITOR_SBUS_H_

int monitor_get_sbus_address(TALLOC_CTX *mem_ctx, struct confdb_ctx *confdb,
                             char **address);
int monitor_common_send_id(struct sbus_connection *conn,
                           const char *name, uint16_t version);
int monitor_common_pong(DBusMessage *message,
                        struct sbus_connection *conn);
int monitor_common_res_init(DBusMessage *message,
                            struct sbus_connection *conn);

#endif /* MONITOR_SBUS_H_ */
