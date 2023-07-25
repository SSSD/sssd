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
#include "sss_iface/sss_iface_sync.h"

#define SSS_SYSTEMD_BUS   "org.freedesktop.systemd1"
#define SSS_SYSTEMD_PATH  "/org/freedesktop/systemd1"
#define SSS_SYSTEMD_UNIT  "sssd.service"
#define SSS_SYSTEMD_MODE  "replace" /* replace queued job if present */

typedef errno_t
(*systemd_method)(TALLOC_CTX *, struct sbus_sync_connection *,
                  const char *, const char *, const char *, const char *,
                  const char **);

static errno_t sssctl_systemd_call(systemd_method method)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_sync_connection *conn;
    const char *job;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    conn = sbus_sync_connect_system(tmp_ctx, NULL);
    if (conn == NULL) {
        ERROR("Unable to connect to system bus!\n");
        ret = EIO;
        goto done;
    }

    ret = method(tmp_ctx, conn, SSS_SYSTEMD_BUS,
                 SSS_SYSTEMD_PATH, SSS_SYSTEMD_UNIT,
                 SSS_SYSTEMD_MODE, &job);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "systemd operation failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "New systemd job created: %s\n", job);

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sssctl_systemd_start(void)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Starting SSSD via systemd...\n");

    return sssctl_systemd_call(sbus_call_systemd_StartUnit);
}

errno_t sssctl_systemd_stop(void)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Stopping SSSD via systemd...\n");

    return sssctl_systemd_call(sbus_call_systemd_StopUnit);
}

errno_t sssctl_systemd_restart(void)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Restarting SSSD via systemd...\n");

    return sssctl_systemd_call(sbus_call_systemd_RestartUnit);
}
