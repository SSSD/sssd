/*
   SSSD

   Sbus Interfaces

   Copyright (C) Simo Sorce			2008

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

#include "monitor/monitor_iface_generated.h"

/*** Monitor ***/

#define MONITOR_VERSION 0x0001

/*** Monitor SRV Interface ***/
#define MON_SRV_PATH "/org/freedesktop/sssd/monitor"

/*** Monitor CLI Interface ***/
#define MONITOR_PATH "/org/freedesktop/sssd/service"

#define SSSD_SERVICE_PIPE "private/sbus-monitor"

int monitor_get_sbus_address(TALLOC_CTX *mem_ctx, char **address);
int monitor_common_send_id(struct sbus_connection *conn,
                           const char *name, uint16_t version);
int monitor_common_pong(struct sbus_request *dbus_req, void *data);
int monitor_common_res_init(struct sbus_request *dbus_req, void *data);
int monitor_common_rotate_logs(struct confdb_ctx *confdb,
                               const char *conf_entry);

errno_t sss_monitor_init(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct mon_cli_iface *mon_iface,
                         const char *svc_name,
                         uint16_t svc_version,
                         void *pvt,
                         struct sbus_connection **mon_conn);
