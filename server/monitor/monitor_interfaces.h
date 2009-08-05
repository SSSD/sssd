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

/*** Monitor ***/

#define MONITOR_VERSION "0.1"
#define MONITOR_DBUS_INTERFACE "org.freedesktop.sssd.monitor"
#define MONITOR_DBUS_PATH "/org/freedesktop/sssd/monitor"

/* Monitor SRV Methods */
#define MON_SRV_METHOD_VERSION "getVersion"

/*** Monitor Interface ***/

#define MONITOR_PATH "/org/freedesktop/sssd/service"
#define MONITOR_INTERFACE "org.freedesktop.sssd.service"

/* Monitor CLI Methods */
#define MON_CLI_METHOD_IDENTITY "getIdentity"
#define MON_CLI_METHOD_PING "ping"
#define MON_CLI_METHOD_RELOAD "reloadConfig"
#define MON_CLI_METHOD_SHUTDOWN "shutDown"
#define MON_CLI_METHOD_RES_INIT "resInit"

#define SSSD_SERVICE_PIPE "private/sbus-monitor"
