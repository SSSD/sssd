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

#include <talloc.h>
#include <dbus/dbus.h>
#include <errno.h>

#include "util/util.h"
#include "tools/sssctl/sssctl.h"

#define SSS_SYSTEMD_BUS   "org.freedesktop.systemd1"
#define SSS_SYSTEMD_PATH  "/org/freedesktop/systemd1"
#define SSS_SYSTEMD_IFACE "org.freedesktop.systemd1.Manager"
#define SSS_SYSTEMD_UNIT  "sssd.service"
#define SSS_SYSTEMD_MODE  "replace" /* replace queued job if present */

static DBusConnection *
sssctl_systemd_connect(void)
{
    DBusConnection *conn;
    DBusError error;

    dbus_error_init(&error);

    conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    if (dbus_error_is_set(&error)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to systemd D-Bus "
              "[%s]: %s\n", error.name, error.message);
        conn = NULL;
        goto done;
    }

done:
    dbus_error_free(&error);
    return conn;
}

static errno_t sssctl_systemd_call(const char *method)
{
    DBusConnection *conn = NULL;
    DBusMessage *reply = NULL;
    DBusMessage *msg = NULL;
    DBusError error;
    const char *unit = SSS_SYSTEMD_UNIT;
    const char *mode = SSS_SYSTEMD_MODE;
    const char *job;
    errno_t ret;

    dbus_error_init(&error);

    conn = sssctl_systemd_connect();
    if (conn == NULL) {
        ret = EIO;
        goto done;
    }

    msg = sbus_create_message(NULL, SSS_SYSTEMD_BUS, SSS_SYSTEMD_PATH,
                              SSS_SYSTEMD_IFACE, method,
                              DBUS_TYPE_STRING, &unit,
                              DBUS_TYPE_STRING, &mode);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create D-Bus Message!\n");
        ret = ENOMEM;
        goto done;
    }

    reply = dbus_connection_send_with_reply_and_block(conn, msg, 5000, &error);
    if (dbus_error_is_set(&error)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send D-Bus message "
                      "[%s]: %s\n", error.name, error.message);
        ret = EIO;
        goto done;
    }

    ret = sbus_parse_message(reply, DBUS_TYPE_OBJECT_PATH, &job);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get D-Bus reply [%d]: %s!\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "New systemd job created: %s\n", job);

done:
    if (msg != NULL) {
        dbus_message_unref(msg);
    }

    if (reply != NULL) {
        dbus_message_unref(reply);
    }

    if (conn != NULL) {
        dbus_connection_unref(conn);
    }

    return ret;
}

errno_t sssctl_systemd_start(void)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Starting SSSD via systemd...\n");

    return sssctl_systemd_call("StartUnit");
}

errno_t sssctl_systemd_stop(void)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Stopping SSSD via systemd...\n");

    return sssctl_systemd_call("StopUnit");
}

errno_t sssctl_systemd_restart(void)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Restarting SSSD via systemd...\n");

    return sssctl_systemd_call("RestartUnit");
}
