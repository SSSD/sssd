/*
   SSSD

   InfoPipe

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
#include <dbus/dbus.h>
#include "util/util.h"
#include "infopipe.h"

int infp_users_get_cached(DBusMessage *message, struct sbus_message_ctx *reply)
{
    reply->reply_message = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");
    return EOK;
}

int infp_users_create(DBusMessage *message, struct sbus_message_ctx *reply)
{
    reply->reply_message = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");
    return EOK;
}

int infp_users_delete(DBusMessage *message, struct sbus_message_ctx *reply)
{
    reply->reply_message = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");
    return EOK;
}

int infp_users_get_attr(DBusMessage *message, struct sbus_message_ctx *reply)
{
    reply->reply_message = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");
    return EOK;
}

int infp_users_set_attr(DBusMessage *message, struct sbus_message_ctx *reply)
{
    reply->reply_message = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");
    return EOK;
}

int infp_users_set_uid(DBusMessage *message, struct sbus_message_ctx *reply)
{
    reply->reply_message = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");
    return EOK;
}
