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

#include <tevent.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/dlinklist.h"
#include "sbus/sbus_private.h"

#ifdef HAVE_DBUS_WATCH_GET_UNIX_FD
#define sbus_watch_get_fd(dbus_watch) dbus_watch_get_unix_fd(dbus_watch)
#else
#define sbus_watch_get_fd(dbus_watch) dbus_watch_get_fd(dbus_watch)
#endif

/**
 * These types definition are here so we can manipulate both D-Bus
 * connection and server with one API.
 */

typedef dbus_bool_t
(*sbus_dbus_set_watch_fn)(void *conn_or_server,
                          DBusAddWatchFunction,
                          DBusRemoveWatchFunction,
                          DBusWatchToggledFunction,
                          void *data,
                          DBusFreeFunction);

typedef dbus_bool_t
(*sbus_dbus_set_timeout_fn)(void *conn_or_server,
                            DBusAddTimeoutFunction,
                            DBusRemoveTimeoutFunction,
                            DBusTimeoutToggledFunction,
                            void *data,
                            DBusFreeFunction);

typedef void *
(*sbus_dbus_ref_fn)(void *conn_or_server);

typedef void
(*sbus_dbus_unref_fn)(void *conn_or_server);

/**
 * D-Bus watch is a mechanism to notify D-Bus every time a read or write event
 * occurs on D-Bus connection file descriptor.
 *
 * D-Bus provides add, remove and toggle function to create/remove a file
 * descriptor event listener and to switch between enabled and disabled
 * states when a file descriptor is kept opened for a longer period of time
 * to safe allocations.
 *
 * We incorporate this watch mechanism into a tevent file handler.
 */

enum sbus_watch_type {
    SBUS_WATCH_CONNECTION,
    SBUS_WATCH_SERVER
};

struct sbus_watch_control {
    void *dbus_ctx;
    sbus_dbus_set_watch_fn set_watch;
    sbus_dbus_set_timeout_fn set_timeout;
    sbus_dbus_ref_fn ref;
    sbus_dbus_unref_fn unref;
};

struct sbus_watch {
    struct tevent_context *ev;
    enum sbus_watch_type type;
    struct sbus_watch_control control;
    struct sbus_watch_fd *watch_list;
};

struct sbus_watch_fd {
    struct sbus_watch *sbus_watch;

    struct {
        DBusWatch *read;
        DBusWatch *write;
    } dbus_watch;

    int fd;
    struct tevent_fd *fdevent;
    struct tevent_immediate *im_event;

    struct sbus_watch_fd *prev;
    struct sbus_watch_fd *next;
};

static void
sbus_watch_handler(struct tevent_context *ev,
                   struct tevent_fd *fde,
                   uint16_t flags,
                   void *data)
{
    struct sbus_watch_control control;
    struct sbus_watch_fd *watch_fd;

    watch_fd = talloc_get_type(data, struct sbus_watch_fd);

    /**
     * Watch context may get freed if it's associated memory context
     * (connection or server) is freed inside a handle. We need to remember
     * it and increase reference to the connection or server so we can safely
     * issue both read and write handlers.
     */
    control = watch_fd->sbus_watch->control;

    control.ref(control.dbus_ctx);

    /* Fire if readable */
    if (flags & TEVENT_FD_READ && watch_fd->dbus_watch.read != NULL) {
        dbus_watch_handle(watch_fd->dbus_watch.read, DBUS_WATCH_READABLE);
    }

    /* Fire if writable */
    if (flags & TEVENT_FD_WRITE && watch_fd->dbus_watch.write != NULL) {
        dbus_watch_handle(watch_fd->dbus_watch.write, DBUS_WATCH_WRITABLE);
    }

    control.unref(control.dbus_ctx);
}

static int
sbus_watch_fd_destructor(struct sbus_watch_fd *watch_fd)
{
    if (watch_fd->sbus_watch == NULL) {
        return 0;
    }

    DLIST_REMOVE(watch_fd->sbus_watch->watch_list, watch_fd);

    return 0;
}

static struct sbus_watch_fd *
sbus_watch_get_by_fd(TALLOC_CTX *mem_ctx,
                     struct sbus_watch *watch,
                     int fd)
{
    struct sbus_watch_fd *watch_fd;

    /**
     * D-Bus may ask us to add a watch to a file descriptor that already had
     * a watch associated. If this is the case we return the existing context.
     */
    DLIST_FOR_EACH(watch_fd, watch->watch_list) {
        if (watch_fd->fd == fd) {
            return watch_fd;
        }
    }

    /* Create new one otherwise. */
    watch_fd = talloc_zero(mem_ctx, struct sbus_watch_fd);
    if (watch_fd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    watch_fd->im_event = tevent_create_immediate(watch_fd);
    if (watch_fd->im_event == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of Memory!\n");
        talloc_free(watch_fd);
        return NULL;
    }

    talloc_set_destructor(watch_fd, sbus_watch_fd_destructor);

    watch_fd->sbus_watch = watch;
    watch_fd->fd = fd;

    return watch_fd;
}

static void
sbus_watch_toggle(DBusWatch *dbus_watch, void *data);

static dbus_bool_t
sbus_watch_add(DBusWatch *dbus_watch, void *data)
{
    struct sbus_watch *sbus_watch;
    struct sbus_watch_fd *watch_fd;
    unsigned int watch_flags;
    dbus_bool_t is_enabled;
    uint16_t ev_flags;
    int fd;

    sbus_watch = talloc_get_type(data, struct sbus_watch);
    fd = sbus_watch_get_fd(dbus_watch);

    watch_fd = sbus_watch_get_by_fd(sbus_watch, sbus_watch, fd);
    if (watch_fd == NULL) {
        return FALSE;
    }

    is_enabled = dbus_watch_get_enabled(dbus_watch);
    watch_flags = dbus_watch_get_flags(dbus_watch);
    ev_flags = 0;

    /* Remember the D-Bus watch and its context. */
    if (watch_flags & DBUS_WATCH_READABLE) {
        watch_fd->dbus_watch.read = dbus_watch;
        if (is_enabled) {
            ev_flags |= TEVENT_FD_READ;
        }
    }

    if (watch_flags & DBUS_WATCH_WRITABLE) {
        watch_fd->dbus_watch.write = dbus_watch;
        if (is_enabled) {
            ev_flags |= TEVENT_FD_WRITE;
        }
    }

    dbus_watch_set_data(dbus_watch, watch_fd, NULL);

    /* Just update flags if an event handler already exists. */
    if (watch_fd->fdevent) {
        sbus_watch_toggle(dbus_watch, data);
        return TRUE;
    }

    /* Create new one otherwise. */
    watch_fd->fdevent = tevent_add_fd(sbus_watch->ev, watch_fd, fd, ev_flags,
                                      sbus_watch_handler, watch_fd);
    if (watch_fd->fdevent == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up fd event!\n");
        talloc_zfree(watch_fd);
        return FALSE;
    }

    DLIST_ADD(sbus_watch->watch_list, watch_fd);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Created a %s %s/%s watch on %d\n",
          is_enabled ? "enabled" : "disabled",
          (watch_flags & DBUS_WATCH_READABLE) ? "R" : "-",
          (watch_flags & DBUS_WATCH_WRITABLE) ? "W" : "-",
          fd);

    return TRUE;
}

static void
free_sbus_watch(struct tevent_context *ev, struct tevent_immediate *im,
                void *data)
{
    struct sbus_watch_fd *w = talloc_get_type(data, struct sbus_watch_fd);
    talloc_free(w); /* this will free attached 'im' as well */
}

static void
sbus_watch_remove(DBusWatch *dbus_watch, void *data)
{
    struct sbus_watch_fd *watch_fd;

    watch_fd = talloc_get_type(dbus_watch_get_data(dbus_watch),
                               struct sbus_watch_fd);
    if (watch_fd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "D-Bus is trying to remove an unknown watch!\n");
        return;
    }

    /* Remove D-Bus watch data. */
    dbus_watch_set_data(dbus_watch, NULL, NULL);

    /* Check which watch to remove, or free if none left. */
    if (watch_fd->dbus_watch.read == dbus_watch) {
        watch_fd->dbus_watch.read = NULL;
    }

    if (watch_fd->dbus_watch.write == dbus_watch) {
        watch_fd->dbus_watch.write = NULL;
    }

    if (watch_fd->dbus_watch.read == NULL
            && watch_fd->dbus_watch.write == NULL) {
        /* libdbus doesn't need this watch{fd} anymore, so associated
         * tevent_fd should be removed from monitoring at the spot.
         */
        talloc_zfree(watch_fd->fdevent);
        /* watch_fd itself can't be freed yet as it still may be referenced
         * in the current context (for example in sbus_watch_handler())
         * so instead schedule immediate event to delete it.
         */
        tevent_schedule_immediate(watch_fd->im_event, watch_fd->sbus_watch->ev,
                                  free_sbus_watch, watch_fd);
    }
}

static void
sbus_watch_toggle(DBusWatch *dbus_watch, void *data)
{
    struct sbus_watch_fd *watch_fd;
    dbus_bool_t is_enabled;
    unsigned int flags;
    int fd;

    is_enabled = dbus_watch_get_enabled(dbus_watch);
    flags = dbus_watch_get_flags(dbus_watch);

    watch_fd = talloc_get_type(dbus_watch_get_data(dbus_watch),
                               struct sbus_watch_fd);
    if (watch_fd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "D-Bus watch [%p] does not carry "
              "a watch context?\n", dbus_watch);
        return;
    }

    /* Toggle state. */
    if (is_enabled) {
        if (flags & DBUS_WATCH_READABLE) {
            TEVENT_FD_READABLE(watch_fd->fdevent);
        }
        if (flags & DBUS_WATCH_WRITABLE) {
            TEVENT_FD_WRITEABLE(watch_fd->fdevent);
        }
    } else {
        if (flags & DBUS_WATCH_READABLE) {
            TEVENT_FD_NOT_READABLE(watch_fd->fdevent);
        }
        if (flags & DBUS_WATCH_WRITABLE) {
            TEVENT_FD_NOT_WRITEABLE(watch_fd->fdevent);
        }
    }

    fd = sbus_watch_get_fd(dbus_watch);

    DEBUG(SSSDBG_TRACE_ALL, "Toggle to %s %s/%s watch on %d\n",
          is_enabled ? "enabled" : "disabled",
          (flags & DBUS_WATCH_READABLE) ? "R" : "-",
          (flags & DBUS_WATCH_WRITABLE) ? "W" : "-",
          fd);
}

/**
 * D-Bus timeout is a mechanism to notify D-Bus every time a requested timeout
 * is reached for a D-Bus connection.
 *
 * D-Bus provides add, remove and toggle function to create/remove a timer
 * event and to switch between enabled and disabled states when a specific
 * timer is being reused.
 *
 * We incorporate this watch mechanism into a tevent timer.
 */

struct sbus_timeout_ctx {
    DBusTimeout *dbus_timeout;
    struct tevent_timer *timed_event;
};

static void sbus_timeout_handler(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval t,
                                 void *data)
{
    struct sbus_timeout_ctx *timeout;

    timeout = talloc_get_type(data, struct sbus_timeout_ctx);

    dbus_timeout_handle(timeout->dbus_timeout);
}

static errno_t
sbus_timer_schedule(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct sbus_timeout_ctx *timeout_ctx)
{
    struct timeval tv;
    int interval;

    /* Get interval in milliseconds and use it to compute timeval. */
    interval = dbus_timeout_get_interval(timeout_ctx->dbus_timeout);
    tv = tevent_timeval_current_ofs(interval / 1000, interval % 1000);

    timeout_ctx->timed_event = tevent_add_timer(ev, mem_ctx, tv,
                                                sbus_timeout_handler,
                                                timeout_ctx);
    if (timeout_ctx->timed_event == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to set up timeout event!\n");
        return ENOMEM;
    }

    return EOK;
}

static dbus_bool_t
sbus_timer_add(DBusTimeout *dbus_timeout, void *data)
{
    struct sbus_watch *watch;
    struct sbus_timeout_ctx *timeout_ctx;
    errno_t ret;

    if (!dbus_timeout_get_enabled(dbus_timeout)) {
        return TRUE;
    }

    watch = talloc_get_type(data, struct sbus_watch);

    /* Create a timeout context. */
    timeout_ctx = talloc_zero(watch, struct sbus_timeout_ctx);
    if (timeout_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return FALSE;
    }

    timeout_ctx->dbus_timeout = dbus_timeout;

    ret = sbus_timer_schedule(timeout_ctx, watch->ev, timeout_ctx);
    if (ret != EOK) {
        return FALSE;
    }

    /* Save the event to the watch object so it can be removed later. */
    dbus_timeout_set_data(timeout_ctx->dbus_timeout, timeout_ctx, NULL);

    return TRUE;
}

static void
sbus_timer_remove(DBusTimeout *dbus_timeout, void *data)
{
    void *timeout = dbus_timeout_get_data(dbus_timeout);

    /* Remove D-Bus timeout data. */
    dbus_timeout_set_data(dbus_timeout, NULL, NULL);

    /* Free the event object. */
    talloc_free(timeout);
}

static void
sbus_timer_toggle(DBusTimeout *dbus_timeout, void *data)
{
    if (dbus_timeout_get_enabled(dbus_timeout)) {
        sbus_timer_add(dbus_timeout, data);
    } else {
        sbus_timer_remove(dbus_timeout, data);
    }
}

/**
 * Setup tevent integration on sbus connection and server.
 */

static struct sbus_watch_control
sbus_watch_control_setup(enum sbus_watch_type type,
                         DBusConnection *conn,
                         DBusServer *server)
{
    struct sbus_watch_control control;

    switch (type) {
    case SBUS_WATCH_CONNECTION:
        control.dbus_ctx = conn;
        control.set_watch = (sbus_dbus_set_watch_fn)dbus_connection_set_watch_functions;
        control.set_timeout = (sbus_dbus_set_timeout_fn)dbus_connection_set_timeout_functions;
        control.ref = (sbus_dbus_ref_fn)dbus_connection_ref;
        control.unref = (sbus_dbus_unref_fn)dbus_connection_unref;
        break;
    case SBUS_WATCH_SERVER:
        control.dbus_ctx = server;
        control.set_watch = (sbus_dbus_set_watch_fn)dbus_server_set_watch_functions;
        control.set_timeout = (sbus_dbus_set_timeout_fn)dbus_server_set_timeout_functions;
        control.ref = (sbus_dbus_ref_fn)dbus_server_ref;
        control.unref = (sbus_dbus_unref_fn)dbus_server_unref;
        break;
    }

    return control;
}

static int
sbus_watch_destructor(struct sbus_watch *watch)
{
    struct sbus_watch_control control = watch->control;

    /* Disable watch. */
    control.set_timeout(control.dbus_ctx, NULL, NULL, NULL, NULL, NULL);
    control.set_watch(control.dbus_ctx, NULL, NULL, NULL, NULL, NULL);

    return 0;
}


static struct sbus_watch *
sbus_watch_create(TALLOC_CTX *mem_ctx,
                  struct tevent_context *ev,
                  enum sbus_watch_type type,
                  DBusConnection *conn,
                  DBusServer *server)
{
    struct sbus_watch *watch;

    switch (type) {
    case SBUS_WATCH_CONNECTION:
        if (conn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: conn pointer is NULL!\n");
            return NULL;
        }
        break;
    case SBUS_WATCH_SERVER:
        if (server == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: server pointer is NULL!\n");
            return NULL;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown watch type!\n");
        return NULL;
    }

    watch = talloc_zero(mem_ctx, struct sbus_watch);
    if (watch == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    watch->ev = ev;
    watch->type = type;
    watch->control = sbus_watch_control_setup(type, conn, server);

    talloc_set_destructor(watch, sbus_watch_destructor);

    return watch;
}

static errno_t
sbus_watch_setup(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 enum sbus_watch_type type,
                 DBusConnection *conn,
                 DBusServer *server,
                 struct sbus_watch **_watch)
{
    struct sbus_watch *watch;
    dbus_bool_t dbret;
    errno_t ret;

    if (_watch == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No context pointer to set!\n");
        return ERR_INTERNAL;
    }

    if (*_watch != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Watch context is already set!\n");
        return ERR_INTERNAL;
    }

    watch = sbus_watch_create(mem_ctx, ev, type, conn, server);
    if (watch == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create watch context!\n");
        return ENOMEM;
    }

    dbret = watch->control.set_watch(watch->control.dbus_ctx,
                                     sbus_watch_add,
                                     sbus_watch_remove,
                                     sbus_watch_toggle,
                                     watch, NULL);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup D-Bus watch functions!\n");
        ret = EIO;
        goto done;
    }

    dbret = watch->control.set_timeout(watch->control.dbus_ctx,
                                       sbus_timer_add,
                                       sbus_timer_remove,
                                       sbus_timer_toggle,
                                       watch, NULL);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE,"Unable to setup D-Bus timeout functions\n");
        ret = EIO;
        goto done;
    }

    *_watch = watch;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(watch);
    }

    return ret;
}

errno_t
sbus_watch_connection(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      DBusConnection *conn,
                      struct sbus_watch **_watch)
{
    return sbus_watch_setup(mem_ctx, ev, SBUS_WATCH_CONNECTION,
                            conn, NULL, _watch);
}

errno_t
sbus_watch_server(TALLOC_CTX *mem_ctx,
                  struct tevent_context *ev,
                  DBusServer *server,
                  struct sbus_watch **_watch)
{
    return sbus_watch_setup(mem_ctx, ev, SBUS_WATCH_SERVER,
                            NULL, server, _watch);
}
