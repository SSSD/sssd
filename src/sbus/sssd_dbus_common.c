/*
    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <sys/time.h>
#include "tevent.h"
#include "dbus/dbus.h"
#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

/* =Watches=============================================================== */

/* DBUS may ask us to add a watch to a file descriptor that already had a watch
 * associated. Need to check if that's the case */
static struct sbus_watch_ctx *fd_to_watch(struct sbus_watch_ctx *list, int fd)
{
    struct sbus_watch_ctx *watch_iter;

    watch_iter = list;
    while (watch_iter != NULL) {
        if (watch_iter->fd == fd) {
            return watch_iter;
        }

        watch_iter = watch_iter->next;
    }

    return NULL;
}

static int watch_destructor(void *mem)
{
    struct sbus_watch_ctx *watch;

    watch = talloc_get_type(mem, struct sbus_watch_ctx);
    DLIST_REMOVE(watch->conn->watch_list, watch);

    return 0;
}

/*
 * watch_handler
 * Callback for D-BUS to handle messages on a file-descriptor
 */
static void sbus_watch_handler(struct tevent_context *ev,
                               struct tevent_fd *fde,
                               uint16_t flags, void *data)
{
    struct sbus_watch_ctx *watch = talloc_get_type(data,
                                                   struct sbus_watch_ctx);
    enum dbus_conn_type type;
    union dbus_conn_pointer dbus_p;

    /* conn may get freed inside a handle, save the data we need for later */
    type = watch->conn->type;
    dbus_p = watch->conn->dbus;

    /* Take a reference while handling watch */
    if (type == SBUS_SERVER) {
        dbus_server_ref(dbus_p.server);
    } else {
        dbus_connection_ref(dbus_p.conn);
    }

    /* Fire if readable */
    if (flags & TEVENT_FD_READ) {
        if (watch->dbus_read_watch) {
            dbus_watch_handle(watch->dbus_read_watch, DBUS_WATCH_READABLE);
        }
    }

    /* Fire if writeable */
    if (flags & TEVENT_FD_WRITE) {
        if (watch->dbus_write_watch) {
            dbus_watch_handle(watch->dbus_write_watch, DBUS_WATCH_WRITABLE);
        }
    }

    /* Release reference once done */
    if (type == SBUS_SERVER) {
        dbus_server_unref(dbus_p.server);
    } else {
        dbus_connection_unref(dbus_p.conn);
    }
}

/*
 * add_watch
 * Set up hooks into the libevents mainloop for
 * D-BUS to add file descriptor-based events
 */
dbus_bool_t sbus_add_watch(DBusWatch *dbus_watch, void *data)
{
    unsigned int flags;
    uint16_t event_flags;
    struct sbus_connection *conn;
    struct sbus_watch_ctx *watch;
    dbus_bool_t enabled;
    int fd;

    conn = talloc_get_type(data, struct sbus_connection);

#ifdef HAVE_DBUS_WATCH_GET_UNIX_FD
    fd = dbus_watch_get_unix_fd(dbus_watch);
#else
    fd = dbus_watch_get_fd(dbus_watch);
#endif

    watch = fd_to_watch(conn->watch_list, fd);
    if (!watch) {
        /* does not exist, allocate new one */
        watch = talloc_zero(conn, struct sbus_watch_ctx);
        if (!watch) {
            DEBUG(0, ("Out of Memory!\n"));
            return FALSE;
        }
        watch->conn = conn;
        watch->fd = fd;
    }

    enabled = dbus_watch_get_enabled(dbus_watch);
    flags = dbus_watch_get_flags(dbus_watch);

    /* Save the event to the watch object so it can be found later */
    if (flags & DBUS_WATCH_READABLE) {
        watch->dbus_read_watch = dbus_watch;
    }
    if (flags & DBUS_WATCH_WRITABLE) {
        watch->dbus_write_watch = dbus_watch;
    }
    dbus_watch_set_data(dbus_watch, watch, NULL);

    if (watch->fde) {
        /* pre-existing event, just toggle flags */
        sbus_toggle_watch(dbus_watch, data);
        return TRUE;
    }

    event_flags = 0;
    if (enabled) {
        if (flags & DBUS_WATCH_READABLE) {
            event_flags |= TEVENT_FD_READ;
        }
        if (flags & DBUS_WATCH_WRITABLE) {
            event_flags |= TEVENT_FD_WRITE;
        }
    }

    /* Add the file descriptor to the event loop */
    watch->fde = tevent_add_fd(conn->ev,
                               watch, fd, event_flags,
                               sbus_watch_handler, watch);
    if (!watch->fde) {
        DEBUG(0, ("Failed to set up fd event!\n"));
        talloc_zfree(watch);
        return FALSE;
    }

    DLIST_ADD(conn->watch_list, watch);
    talloc_set_destructor((TALLOC_CTX *)watch, watch_destructor);

    DEBUG(8, ("%p/%p (%d), %s/%s (%s)\n",
              watch, dbus_watch, fd,
              ((flags & DBUS_WATCH_READABLE)?"R":"-"),
              ((flags & DBUS_WATCH_WRITABLE)?"W":"-"),
              enabled?"enabled":"disabled"));

    return TRUE;
}

/*
 * toggle_watch
 * Hook for D-BUS to toggle the enabled/disabled state of
 * an event in the mainloop
 */
void sbus_toggle_watch(DBusWatch *dbus_watch, void *data)
{
    struct sbus_watch_ctx *watch;
    unsigned int flags;
    dbus_bool_t enabled;
    void *watch_data;
    int fd;

    enabled = dbus_watch_get_enabled(dbus_watch);
    flags = dbus_watch_get_flags(dbus_watch);

    watch_data = dbus_watch_get_data(dbus_watch);
    watch = talloc_get_type(watch_data, struct sbus_watch_ctx);
    if (!watch) {
        DEBUG(2, ("[%p] does not carry watch context?!\n", dbus_watch));
        /* abort ? */
        return;
    }

    if (enabled) {
        if (flags & DBUS_WATCH_READABLE) {
            TEVENT_FD_READABLE(watch->fde);
        }
        if (flags & DBUS_WATCH_WRITABLE) {
            TEVENT_FD_WRITEABLE(watch->fde);
        }
    } else {
        if (flags & DBUS_WATCH_READABLE) {
            TEVENT_FD_NOT_READABLE(watch->fde);
        }
        if (flags & DBUS_WATCH_WRITABLE) {
            TEVENT_FD_NOT_WRITEABLE(watch->fde);
        }
    }

    if (debug_level >= 8) {
#ifdef HAVE_DBUS_WATCH_GET_UNIX_FD
        fd = dbus_watch_get_unix_fd(dbus_watch);
#else
        fd = dbus_watch_get_fd(dbus_watch);
#endif
    }
    DEBUG(8, ("%p/%p (%d), %s/%s (%s)\n",
              watch, dbus_watch, fd,
              ((flags & DBUS_WATCH_READABLE)?"R":"-"),
              ((flags & DBUS_WATCH_WRITABLE)?"W":"-"),
              enabled?"enabled":"disabled"));
}

/*
 * sbus_remove_watch
 * Hook for D-BUS to remove file descriptor-based events
 * from the libevents mainloop
 */
void sbus_remove_watch(DBusWatch *dbus_watch, void *data)
{
    struct sbus_watch_ctx *watch;
    void *watch_data;

    watch_data = dbus_watch_get_data(dbus_watch);
    watch = talloc_get_type(watch_data, struct sbus_watch_ctx);

    DEBUG(8, ("%p/%p\n", watch, dbus_watch));

    if (!watch) {
        DEBUG(2, ("DBUS trying to remove unknown watch!\n"));
        return;
    }

    /* remove dbus watch data */
    dbus_watch_set_data(dbus_watch, NULL, NULL);

    /* check which watch to remove, or free if none left */
    if (watch->dbus_read_watch == dbus_watch) {
        watch->dbus_read_watch = NULL;
    }
    if (watch->dbus_write_watch == dbus_watch) {
        watch->dbus_write_watch = NULL;
    }
    if (!watch->dbus_read_watch && !watch->dbus_write_watch) {
        talloc_free(watch);
    }
}

/* =Timeouts============================================================== */

static struct timeval _get_interval_tv(int interval) {
    struct timeval tv;
    struct timeval rightnow;

    gettimeofday(&rightnow,NULL);

    tv.tv_sec = interval / 1000 + rightnow.tv_sec;
    tv.tv_usec = (interval % 1000) * 1000 + rightnow.tv_usec;
    return tv;
}

/*
 * timeout_handler
 * Callback for D-BUS to handle timed events
 */
static void sbus_timeout_handler(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval t, void *data)
{
    struct sbus_timeout_ctx *timeout;
    timeout = talloc_get_type(data, struct sbus_timeout_ctx);

    dbus_timeout_handle(timeout->dbus_timeout);
}

/*
 * add_timeout
 * Hook for D-BUS to add time-based events to the mainloop
 */
dbus_bool_t sbus_add_timeout(DBusTimeout *dbus_timeout, void *data)
{
    struct sbus_connection *conn;
    struct sbus_timeout_ctx *timeout;
    struct timeval tv;

    DEBUG(8, ("%p\n", dbus_timeout));

    if (!dbus_timeout_get_enabled(dbus_timeout)) {
        return TRUE;
    }

    conn = talloc_get_type(data, struct sbus_connection);

    timeout = talloc_zero(conn, struct sbus_timeout_ctx);
    if (!timeout) {
        DEBUG(0, ("Out of Memory!\n"));
        return FALSE;
    }
    timeout->dbus_timeout = dbus_timeout;

    tv = _get_interval_tv(dbus_timeout_get_interval(dbus_timeout));
    timeout->te = tevent_add_timer(conn->ev, timeout, tv,
                                   sbus_timeout_handler, timeout);
    if (!timeout->te) {
        DEBUG(0, ("Failed to set up timeout event!\n"));
        return FALSE;
    }

    /* Save the event to the watch object so it can be removed later */
    dbus_timeout_set_data(timeout->dbus_timeout, timeout, NULL);

    return TRUE;
}

/*
 * sbus_toggle_timeout
 * Hook for D-BUS to toggle the enabled/disabled state of a mainloop
 * event
 */
void sbus_toggle_timeout(DBusTimeout *dbus_timeout, void *data)
{
    DEBUG(8, ("%p\n", dbus_timeout));

    if (dbus_timeout_get_enabled(dbus_timeout)) {
        sbus_add_timeout(dbus_timeout, data);
    } else {
        sbus_remove_timeout(dbus_timeout, data);
    }
}

/*
 * sbus_remove_timeout
 * Hook for D-BUS to remove time-based events from the mainloop
 */
void sbus_remove_timeout(DBusTimeout *dbus_timeout, void *data)
{
    void *timeout;

    DEBUG(8, ("%p\n", dbus_timeout));

    timeout = dbus_timeout_get_data(dbus_timeout);

    /* remove dbus timeout data */
    dbus_timeout_set_data(dbus_timeout, NULL, NULL);

    /* Freeing the event object will remove it from the event loop */
    talloc_free(timeout);

}

/* =Helpers=============================================================== */

int sbus_is_dbus_fixed_type(int dbus_type)
{
    switch (dbus_type) {
    case DBUS_TYPE_BYTE:
    case DBUS_TYPE_BOOLEAN:
    case DBUS_TYPE_INT16:
    case DBUS_TYPE_UINT16:
    case DBUS_TYPE_INT32:
    case DBUS_TYPE_UINT32:
    case DBUS_TYPE_INT64:
    case DBUS_TYPE_UINT64:
    case DBUS_TYPE_DOUBLE:
        return true;
    }
    return false;
}

int sbus_is_dbus_string_type(int dbus_type)
{
    switch(dbus_type) {
    case DBUS_TYPE_STRING:
    case DBUS_TYPE_OBJECT_PATH:
    case DBUS_TYPE_SIGNATURE:
        return true;
    }
    return false;
}

size_t sbus_get_dbus_type_size(int dbus_type)
{
    size_t ret;

    switch(dbus_type) {
    /* 1-byte types */
    case DBUS_TYPE_BYTE:
        ret = 1;
        break;

     /* 2-byte types */
    case DBUS_TYPE_INT16:
    case DBUS_TYPE_UINT16:
        ret = 2;
        break;

    /* 4-byte types */
    case DBUS_TYPE_BOOLEAN:
    case DBUS_TYPE_INT32:
    case DBUS_TYPE_UINT32:
        ret = 4;
        break;

    /* 8-byte types */
    case DBUS_TYPE_INT64:
    case DBUS_TYPE_UINT64:
    case DBUS_TYPE_DOUBLE:
        ret = 8;
        break;

    default:
        ret = 0;
    }
    return ret;
}
