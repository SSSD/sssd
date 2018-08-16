/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <errno.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_sync.h"
#include "sbus/sbus_sync_private.h"
#include "sbus/sbus_message.h"

errno_t
sbus_sync_call_method(TALLOC_CTX *mem_ctx,
                      struct sbus_sync_connection *conn,
                      DBusMessage *raw_message,
                      sbus_invoker_writer_fn writer,
                      const char *bus,
                      const char *path,
                      const char *iface,
                      const char *method,
                      void *input,
                      DBusMessage **_reply)
{
    TALLOC_CTX *tmp_ctx;
    DBusMessage *reply;
    DBusMessage *msg;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    msg = sbus_create_method_call(tmp_ctx, raw_message, writer, bus, path,
                                  iface, method, input);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_sync_message_send(tmp_ctx, conn, msg, SBUS_MESSAGE_TIMEOUT,
                                 &reply);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_message_bound_steal(mem_ctx, reply);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to steal message [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    *_reply = reply;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

void
sbus_sync_call_signal(struct sbus_sync_connection *conn,
                      DBusMessage *raw_message,
                      sbus_invoker_writer_fn writer,
                      const char *path,
                      const char *iface,
                      const char *signal_name,
                      void *input)
{
    DBusMessage *msg;

    msg = sbus_create_signal_call(NULL, raw_message, writer, path, iface,
                                  signal_name, input);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create signal message!\n");
        return;
    }

    sbus_sync_emit_signal(conn, msg);
}
