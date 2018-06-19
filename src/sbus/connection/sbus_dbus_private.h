/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2018 Red Hat

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

#ifndef _SBUS_DBUS_PRIVATE_H_
#define _SBUS_DBUS_PRIVATE_H_

#include <dbus/dbus.h>

/* Get D-Bus connection to a D-Bus system or session bus. */
DBusConnection *sbus_dbus_connect_bus(DBusBusType bus, const char *name);

/* Get D-Bus connection to a D-Bus address. */
DBusConnection *sbus_dbus_connect_address(const char *address,
                                          const char *name,
                                          bool init);

#endif /* _SBUS_DBUS_PRIVATE_H_ */
