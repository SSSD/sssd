/*
   SSSD

   SystemBus Helpers

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

#ifndef SYSBUS_H_
#define SYSBUS_H_

#define SYSBUS_GET_PARAM "getParam"

struct sysbus_ctx;

int sysbus_init(TALLOC_CTX *mem_ctx, struct sysbus_ctx **sysbus, struct sbus_method *methods);

int sysbus_get_param(DBusMessage *message, void *data, DBusMessage **r);

#endif /* SYSBUS_H_ */
