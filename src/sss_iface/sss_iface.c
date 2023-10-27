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

#include <unistd.h>
#include <sys/stat.h>

#include "util/util.h"
#include "sbus/sbus.h"
#include "sbus/sbus_opath.h"
#include "sss_iface/sss_iface_async.h"

char *
sss_iface_proxy_bus(TALLOC_CTX *mem_ctx,
                    uint32_t id)
{
    /* Parts of bus names must not start with digit thus we concatenate
     * the name with underscore instead of period. */
    return talloc_asprintf(mem_ctx, "sssd.proxy_%"PRIu32, id);
}

static errno_t
sss_iface_connect_address(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          const char *conn_name,
                          const char *address,
                          time_t *last_request_time,
                          struct sbus_connection **_conn)
{
    struct sbus_connection *conn;
    const char *filename;
    errno_t ret;
    uid_t check_uid;
    gid_t check_gid;

    if (address == NULL) {
        return EINVAL;
    }

    filename = strchr(address, '/');
    if (filename == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected dbus address [%s].\n", address);
        return EIO;
    }

    check_uid = geteuid();
    check_gid = getegid();

    /* Ignore ownership checks when the server runs as root. This is the
     * case when privileged monitor is setting up sockets for unprivileged
     * responders */
    if (check_uid == 0) check_uid = -1;
    if (check_gid == 0) check_gid = -1;

    ret = check_file(filename, check_uid, check_gid,
                     S_IFSOCK|S_IRUSR|S_IWUSR, 0, NULL, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_file failed for [%s].\n", filename);
        return EIO;
    }

    conn = sbus_connect_private(mem_ctx, ev, address,
                                conn_name, last_request_time);
    if (conn == NULL) { /* most probably sbus_dbus_connect_address() failed */
        return EFAULT;
    }

    *_conn = conn;

    return EOK;
}

errno_t
sss_sbus_connect(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 const char *conn_name,
                 time_t *last_request_time,
                 struct sbus_connection **_conn)
{
    struct sbus_connection *conn;
    errno_t ret;

    ret = sss_iface_connect_address(mem_ctx, ev, conn_name, SSS_BUS_ADDRESS,
                                    last_request_time, &conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to connect to SSSD D-Bus server "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    *_conn = conn;

    return EOK;
}

static void
sss_monitor_register_service_done(struct tevent_req *req);

errno_t
sss_monitor_register_service(TALLOC_CTX *mem_ctx,
                             struct sbus_connection *conn,
                             const char *svc_name,
                             uint16_t svc_version,
                             uint16_t svc_type)
{
    struct tevent_req *req;

    req = sbus_call_monitor_RegisterService_send(conn, conn, SSS_BUS_MONITOR,
                                                 SSS_BUS_PATH, svc_name,
                                                 svc_version, svc_type);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, sss_monitor_register_service_done, conn);

    return EOK;
}

static void
sss_monitor_register_service_done(struct tevent_req *req)
{
    uint16_t version;
    errno_t ret;

    ret = sbus_call_monitor_RegisterService_recv(req, &version);
    talloc_zfree(req);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register client in monitor "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Got id ack and version (%d) from Monitor\n",
          version);
}
