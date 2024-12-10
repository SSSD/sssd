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

#include <time.h>
#include <errno.h>
#include <dhash.h>
#include <tevent.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/connection/sbus_dbus_private.h"
#include "sbus/sbus_private.h"

struct sbus_connection_access {
    const char *name;
    sbus_connection_access_check_fn check_fn;
    sbus_connection_access_check_data data;
};

struct sbus_connection_destructor {
    const char *name;
    sbus_connection_destructor_fn destructor;
    sbus_connection_destructor_data data;
};

static void
sbus_connection_release(struct sbus_connection *conn)
{
    /* Now release the connection. */
    if (conn->type == SBUS_CONNECTION_CLIENT) {
        /* Client connections must be closed explicitly. */
        dbus_connection_close(conn->connection);
    }

    /* All connection must be unreferenced. */
    dbus_connection_unref(conn->connection);
}

static int
sbus_connection_destructor(struct sbus_connection *conn)
{
    conn->disconnecting = true;

    /* First, disable reconnection and tevent integration
     * so we don't handle any more messages. */
    sbus_reconnect_disable(conn);
    sbus_connection_tevent_disable(conn);

    /* Remove router data. */
    talloc_zfree(conn->router);

    /* Release D-Bus connection. */
    sbus_connection_release(conn);

    if (conn->destructor->destructor != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Calling custom connection destructor '%s'\n",
              conn->destructor->name);
        conn->destructor->destructor(conn->destructor->data);
    }

    return 0;
}

static errno_t
sbus_connection_data_init(struct sbus_connection *conn)
{
    conn->senders = sbus_senders_init(conn);
    if (conn->senders == NULL) {
        goto fail;
    }

    conn->requests = sbus_active_requests_init(conn);
    if (conn->requests == NULL) {
        goto fail;
    }

    conn->reconnect = sbus_reconnect_init(conn);
    if (conn->reconnect == NULL) {
        goto fail;
    }

    conn->router = sbus_router_init(conn, conn);
    if (conn->router == NULL) {
        goto fail;
    }

    conn->access = talloc_zero(conn, struct sbus_connection_access);
    if (conn->access == NULL) {
        goto fail;
    }

    conn->destructor = talloc_zero(conn, struct sbus_connection_destructor);
    if (conn->destructor == NULL) {
        goto fail;
    }

    return EOK;

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
    return ENOMEM;
}

struct sbus_connection *
sbus_connection_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     DBusConnection *dbus_conn,
                     const char *address,
                     const char *dbus_name,
                     enum sbus_connection_type type,
                     time_t *last_activity_time)
{
    struct sbus_connection *sbus_conn;
    errno_t ret;

    /* We do not want to exit if the connection is dropped. */
    dbus_connection_set_exit_on_disconnect(dbus_conn, FALSE);

    /* Create a new sbus connection */
    sbus_conn = talloc_zero(mem_ctx, struct sbus_connection);
    if (sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    sbus_conn->ev = ev;
    sbus_conn->connection = dbus_connection_ref(dbus_conn);
    sbus_conn->type = type;
    sbus_conn->last_activity = last_activity_time;

    if (address != NULL) {
        sbus_conn->address = talloc_strdup(sbus_conn, address);
        if (sbus_conn->address == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (dbus_name != NULL) {
        sbus_conn->wellknown_name = talloc_strdup(sbus_conn, dbus_name);
        if (sbus_conn->wellknown_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sbus_connection_data_init(sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize internal connection "
              "data [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sbus_connection_tevent_enable(sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to integrate with tevent [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    talloc_set_destructor(sbus_conn, sbus_connection_destructor);

    /* Mark this connection as active. */
    sbus_connection_mark_active(sbus_conn);

    /* Dispatch events that happend on the bus before we setup the dispatcher,
     * if the queue is empty, this will do nothing. */
    sbus_dispatch_now(sbus_conn);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sbus_conn);
        return NULL;
    }

    return sbus_conn;
}

errno_t
sbus_connection_replace(struct sbus_connection *sbus_conn,
                        DBusConnection *dbus_conn)
{
    errno_t ret;

    if (dbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: dbus_conn must not be NULL!\n");
        return ERR_INTERNAL;
    }

    sbus_connection_release(sbus_conn);
    sbus_conn->connection = dbus_connection_ref(dbus_conn);

    /* Do not unreference the dbus connection so it is available in
     * sbus connection for further use, even thought it is not
     * initialized properly. */

    ret = sbus_router_reset(sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to reset the router [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = sbus_connection_tevent_enable(sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to integrate with tevent [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

errno_t sbus_connection_tevent_enable(struct sbus_connection *conn)
{
    errno_t ret;

    ret = sbus_watch_connection(conn, conn->ev, conn->connection,
                                &conn->watch);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup D-Bus watch [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    sbus_dispatcher_setup(conn);

    return EOK;
}

void sbus_connection_tevent_disable(struct sbus_connection *conn)
{
    sbus_dispatcher_disable(conn);
    talloc_zfree(conn->watch);
}

void sbus_connection_mark_active(struct sbus_connection *conn)
{
    if (conn->last_activity != NULL) {
        *conn->last_activity = time(NULL);
    }
}

errno_t sbus_connection_add_path(struct sbus_connection *conn,
                                 const char *path,
                                 struct sbus_interface *iface)
{
    return sbus_router_add_path(conn->router, path, iface);
}

errno_t sbus_connection_add_path_map(struct sbus_connection *conn,
                                     struct sbus_path *map)
{
    return sbus_router_add_path_map(conn->router, map);
}

const char * sbus_connection_get_name(struct sbus_connection *conn)
{
    if (conn == NULL) {
        return NULL;
    }

    if (conn->wellknown_name != NULL) {
        return conn->wellknown_name;
    }

    if  (conn->unique_name != NULL) {
        return conn->unique_name;
    }

    return ":not.active.yet";
}

errno_t sbus_connection_set_name(struct sbus_connection *conn,
                                 const char *name)
{
    const char *dup;

    dup = talloc_strdup(conn, name);
    if (dup == NULL && name == NULL) {
        return ENOMEM;
    }

    talloc_zfree(conn->wellknown_name);
    conn->wellknown_name = dup;

    return EOK;
}

void _sbus_connection_set_destructor(struct sbus_connection *conn,
                                     const char *name,
                                     sbus_connection_destructor_fn destructor,
                                     sbus_connection_destructor_data data)
{
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: connection is NULL\n");
        return;
    }

    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name is NULL\n");
        return;
    }

    if (destructor == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Unsetting connection %p ('%s':'%s') destructor\n",
              conn,
              conn->address ? conn->address : "-",
              conn->wellknown_name ? conn->wellknown_name : "-");
        conn->destructor->destructor = NULL;
        conn->destructor->data = NULL;
        conn->destructor->name = NULL;
        return;
    }

    if (conn->destructor->destructor != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Bug: destructor for connection %p ('%s':'%s') is already set to '%s'\n",
              conn,
              conn->address ? conn->address : "-",
              conn->wellknown_name ? conn->wellknown_name : "-",
              conn->destructor->name);
        return;
    }

    conn->destructor->destructor = destructor;
    conn->destructor->data = data;
    conn->destructor->name = name;
    DEBUG(SSSDBG_TRACE_FUNC, "Set connection %p ('%s':'%s') destructor to '%s'\n",
          conn,
          conn->address ? conn->address : "-",
          conn->wellknown_name ? conn->wellknown_name : "-",
          name);
}

void _sbus_connection_set_access_check(struct sbus_connection *conn,
                                       const char *name,
                                       sbus_connection_access_check_fn check_fn,
                                       sbus_connection_access_check_data data)
{
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: connection is NULL\n");
        return;
    }

    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: name is NULL\n");
        return;
    }

    if (check_fn == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Unsetting access check function\n");
        conn->access->check_fn = NULL;
        conn->access->data = NULL;
        conn->access->name = NULL;
        return;
    }

    if (conn->access->check_fn != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: access check function is "
              "already set to %s\n", conn->access->name);
        return;
    }

    conn->access->check_fn = check_fn;
    conn->access->data = data;
    conn->access->name = name;
}

void sbus_connection_set_data(struct sbus_connection *conn,
                              void *data)
{
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: connection is NULL\n");
        return;
    }

    conn->data = data;
}

void *_sbus_connection_get_data(struct sbus_connection *conn)
{
    if (conn == NULL) {
        return NULL;
    }

    return conn->data;
}

errno_t
sbus_check_access(struct sbus_connection *conn,
                 struct sbus_request *sbus_req)
{
    errno_t ret;

    if (conn->access->check_fn == NULL) {
        return EOK;
    }

    ret = conn->access->check_fn(sbus_req, conn->access->data);
    if (ret == EPERM || ret == EACCES) {
        if (sbus_req->sender == NULL) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "%s.%s: permission denied for unknown sender\n",
                  sbus_req->interface, sbus_req->member);
        } else {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "%s.%s: permission denied for sender %s with uid %"PRIi64"\n",
                  sbus_req->interface, sbus_req->member,
                  sbus_req->sender->name, sbus_req->sender->uid);
        }
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to perform access check [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

static void
sbus_connection_free_handler(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval tv,
                             void *data)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Releasing connection %p\n", data);
    talloc_free(data);
}

void sbus_connection_free(struct sbus_connection *conn)
{
    struct tevent_timer *te;
    struct timeval tv;

    conn->disconnecting = true;
    sbus_reconnect_disable(conn);
    sbus_connection_tevent_disable(conn);

    tv = tevent_timeval_current();
    te = tevent_add_timer(conn->ev, conn, tv, sbus_connection_free_handler,
                          conn);
    if (te == NULL) {
        /* We can't do anything about it. */
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to set up free event!\n");
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "Connection %p will be freed during next loop!\n",
              conn);
    }
}

void
sbus_connection_terminate_member_requests(struct sbus_connection *conn,
                                          const char *member)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Terminating outgoing chained requests for: %s\n",
          member);

    sbus_requests_terminate_member(conn->requests->outgoing, member,
                                   ERR_TERMINATED);

    DEBUG(SSSDBG_TRACE_FUNC, "Terminating incoming chained requests from: %s\n",
          member);

    sbus_requests_terminate_member(conn->requests->incoming, member,
                                   ERR_TERMINATED);
}
