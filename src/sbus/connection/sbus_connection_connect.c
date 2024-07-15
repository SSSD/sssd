/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>
        Simo Sorce <ssorce@redhat.com>

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
#include <tevent.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/connection/sbus_dbus_private.h"
#include "sbus/sbus_private.h"
#include "sbus/interface_dbus/sbus_dbus_client_async.h"

struct sbus_connect_init_state {
    struct sbus_connection *conn;
    const char *name;
};

static void sbus_connect_init_hello_done(struct tevent_req *subreq);
static void sbus_connect_init_done(struct tevent_req *subreq);

struct tevent_req *
sbus_connect_init_send(TALLOC_CTX *mem_ctx,
                       struct sbus_connection *conn,
                       const char *name)
{
    struct sbus_connect_init_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct sbus_connect_init_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->conn = conn;
    state->name = name;

    subreq = sbus_call_DBus_Hello_send(state, conn, DBUS_SERVICE_DBUS,
                                       DBUS_PATH_DBUS);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        tevent_req_error(req, ENOMEM);
        tevent_req_post(req, conn->ev);
        return req;
    }

    tevent_req_set_callback(subreq, sbus_connect_init_hello_done, req);

    arm_watchdog();

    return req;
}

static void sbus_connect_init_hello_done(struct tevent_req *subreq)
{
    struct sbus_connect_init_state *state;
    const char *unique_name;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_connect_init_state);

    ret = sbus_call_DBus_Hello_recv(state, subreq, &unique_name);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->name == NULL) {
        tevent_req_done(req);
        return;
    }

    subreq = sbus_call_DBus_RequestName_send(state, state->conn,
                 DBUS_SERVICE_DBUS, DBUS_PATH_DBUS, state->name,
                 DBUS_NAME_FLAG_DO_NOT_QUEUE);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, sbus_connect_init_done, req);
    return;
}

static void sbus_connect_init_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    uint32_t res;
    errno_t ret;

    disarm_watchdog();

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sbus_call_DBus_RequestName_recv(subreq, &res);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    switch (res) {
    case DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER:
    case DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER:
        tevent_req_done(req);
        return;
    case DBUS_REQUEST_NAME_REPLY_EXISTS:
        tevent_req_error(req, EEXIST);
        return;
    default:
        tevent_req_error(req, EIO);
        return;
    }
}

errno_t sbus_connect_init_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sbus_connection *
sbus_connect_system(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    const char *dbus_name,
                    time_t *last_activity_time)
{
    struct sbus_connection *sbus_conn;
    DBusConnection *dbus_conn;
    errno_t ret;

    dbus_conn = sbus_dbus_connect_bus(DBUS_BUS_SYSTEM, dbus_name);
    if (dbus_conn == NULL) {
        return NULL;
    }

    sbus_conn = sbus_connection_init(mem_ctx, ev, dbus_conn, NULL, dbus_name,
                                     SBUS_CONNECTION_SYSBUS,
                                     last_activity_time);
    dbus_connection_unref(dbus_conn);
    if (sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create connection context!\n");
        return NULL;
    }

    ret = sbus_register_standard_signals(sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register signal listeners "
              "[%d]: %s\n", ret, sss_strerror(ret));
        talloc_free(sbus_conn);
        return NULL;
    }

    return sbus_conn;
}

struct sbus_connection *
sbus_connect_private(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     const char *address,
                     const char *dbus_name,
                     time_t *last_activity_time)
{
    struct sbus_connection *sbus_conn;
    DBusConnection *dbus_conn;
    errno_t ret;

    dbus_conn = sbus_dbus_connect_address(address, dbus_name, true);
    if (dbus_conn == NULL) {
        return NULL;
    }

    sbus_conn = sbus_connection_init(mem_ctx, ev, dbus_conn, address, dbus_name,
                                     SBUS_CONNECTION_ADDRESS,
                                     last_activity_time);
    dbus_connection_unref(dbus_conn);
    if (sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create connection context!\n");
        return NULL;
    }

    ret = sbus_register_standard_signals(sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register signal listeners "
              "[%d]: %s\n", ret, sss_strerror(ret));
        talloc_free(sbus_conn);
        return NULL;
    }

    return sbus_conn;
}

struct sbus_connect_private_state {
    struct sbus_connection *conn;
    const char *dbus_name;
    int retry_count;
};

static void sbus_connect_private_done(struct tevent_req *subreq);

static struct tevent_req *
sbus_connect_private_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          const char *address,
                          const char *dbus_name,
                          time_t *last_activity_time)
{
    struct sbus_connect_private_state *state;
    DBusConnection *dbus_conn;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sbus_connect_private_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    if (dbus_name != NULL) {
        state->dbus_name = talloc_strdup(state, dbus_name);
        if (state->dbus_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup() failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }
    state->retry_count = 1;

    dbus_conn = sbus_dbus_connect_address(address, dbus_name, false);
    if (dbus_conn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->conn = sbus_connection_init(state, ev, dbus_conn, address,
                                       dbus_name, SBUS_CONNECTION_ADDRESS,
                                       last_activity_time);
    dbus_connection_unref(dbus_conn);
    if (state->conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create connection context!\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = sbus_connect_init_send(state, state->conn, dbus_name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_connect_private_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sbus_connect_private_done(struct tevent_req *subreq)
{
    struct sbus_connect_private_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_connect_private_state);

    ret = sbus_connect_init_recv(subreq);
    talloc_zfree(subreq);
    if (ret == ERR_SBUS_NO_REPLY && state->retry_count-- > 0) {
        DEBUG(SSSDBG_IMPORTANT_INFO, "No Hello reply received, retrying.\n");

        subreq = sbus_connect_init_send(state, state->conn, state->dbus_name);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
            tevent_req_error(req, ENOMEM);
            return;
        }

        tevent_req_set_callback(subreq, sbus_connect_private_done, req);

        return;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize connection "
              "[%d]: %s\n", ret, sss_strerror(ret));
        talloc_free(state->conn);
        tevent_req_error(req, ret);
        return;
    }

    ret = sbus_register_standard_signals(state->conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register signal listeners "
              "[%d]: %s\n", ret, sss_strerror(ret));
        talloc_zfree(state->conn);
        tevent_req_error(req, ret);
        return;
    }

    if (state->conn->wellknown_name == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Connected to %s bus as anonymous\n",
              state->conn->address);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Connected to %s bus as %s\n",
              state->conn->address, state->conn->wellknown_name);
    }

    tevent_req_done(req);
    return;
}

static errno_t
sbus_connect_private_recv(TALLOC_CTX *mem_ctx,
                          struct tevent_req *req,
                          struct sbus_connection **_conn)
{
    struct sbus_connect_private_state *state;
    state = tevent_req_data(req, struct sbus_connect_private_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_conn = talloc_steal(mem_ctx, state->conn);

    return EOK;
}

struct sbus_server_create_and_connect_state {
    struct sbus_server *server;
    struct sbus_connection *conn;
};

static void sbus_server_create_and_connect_done(struct tevent_req *subreq);

struct tevent_req *
sbus_server_create_and_connect_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    const char *dbus_name,
                                    time_t *last_activity_time,
                                    const char *address,
                                    bool use_symlink,
                                    uint32_t max_connections,
                                    sbus_server_on_connection_cb on_conn_cb,
                                    sbus_server_on_connection_data on_conn_data)
{
    struct sbus_server_create_and_connect_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_server_create_and_connect_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->server = sbus_server_create(state, ev, address, use_symlink,
                                       max_connections, on_conn_cb, on_conn_data);
    if (state->server == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = sbus_connect_private_send(state, ev, address, dbus_name,
                                       last_activity_time);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_server_create_and_connect_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sbus_server_create_and_connect_done(struct tevent_req *subreq)
{
    struct sbus_server_create_and_connect_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_server_create_and_connect_state);

    ret = sbus_connect_private_recv(state, subreq, &state->conn);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
sbus_server_create_and_connect_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct sbus_server **_server,
                                    struct sbus_connection **_conn)
{
    struct sbus_server_create_and_connect_state *state;
    state = tevent_req_data(req, struct sbus_server_create_and_connect_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_server = talloc_steal(mem_ctx, state->server);
    *_conn = talloc_steal(mem_ctx, state->conn);

    return EOK;
}
