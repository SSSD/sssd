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
#define MONITOR_DBUS_INTERFACE "org.freeipa.sssd.monitor"
#define MONITOR_DBUS_PATH "/org/freeipa/sssd/monitor"

/* Monitor Methods */
#define MONITOR_METHOD_VERSION "getVersion"


/*** Services ***/

#define SERVICE_PATH "/org/freeipa/sssd/service"
#define SERVICE_INTERFACE "org.freeipa.sssd.service"

/* Service Methods */
#define SERVICE_METHOD_IDENTITY "getIdentity"

