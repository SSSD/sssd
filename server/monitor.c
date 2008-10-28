/* 
   SSSD

   Service monitor

   Copyright (C) Simo Sorce			2008

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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include "../events/events.h"
#include "util/util.h"
#include "service.h"
#include "confdb/confdb.h"
#include "monitor.h"
#include "dbus/dbus.h"
#include "dbus/sssd_dbus.h"


/* TODO: get this value from LDB */
#define DBUS_ADDRESS "unix:path=/var/lib/sss/pipes/private/dbus"

struct mt_ctx {
    struct event_context *ev;
    struct confdb_ctx *cdb;
    char **services;
};

struct mt_srv {
    const char *name;
    struct mt_ctx *mt_ctx;
    pid_t pid;
    time_t last_restart;
    int restarts;
};

/* dbus_get_monitor_version
 * Return the monitor version over D-BUS */
static int dbus_get_monitor_version(DBusMessage *message,
                                    void *data,
                                    DBusMessage **r)
{
    const char *version = MONITOR_VERSION;
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply, DBUS_TYPE_STRING,
                                   &version, DBUS_TYPE_INVALID);

    if (!ret) {
        return EIO;
    }

    *r = reply;
    return EOK;
}

struct sssd_dbus_method monitor_methods[] = {
    { MONITOR_METHOD_VERSION, dbus_get_monitor_version},
    {NULL, NULL}
};

/* monitor_dbus_init
 * Set up the monitor service as a D-BUS Server */
static int monitor_dbus_init(struct mt_ctx *ctx)
{
    struct sssd_dbus_ctx *sd_ctx;
    int ret;

    sd_ctx = talloc(ctx, struct sssd_dbus_ctx);
    if (!sd_ctx) {
        return ENOMEM;
    }

    sd_ctx->ev = ctx->ev;
    sd_ctx->name = talloc_strdup(sd_ctx, MONITOR_DBUS_INTERFACE);
    if (!sd_ctx->name) {
        talloc_free(sd_ctx);
        return ENOMEM;
    }
    sd_ctx->path = talloc_strdup(sd_ctx, MONITOR_DBUS_PATH);
    if (!sd_ctx->path) {
        talloc_free(sd_ctx);
        return ENOMEM;
    }
    sd_ctx->methods = monitor_methods;

    ret = sssd_new_dbus_server(sd_ctx, DBUS_ADDRESS);

    return ret;
}


static void set_tasks_checker(struct mt_srv *srv);

static void tasks_check_handler(struct event_context *ev,
                                struct timed_event *te,
                                struct timeval t, void *ptr)
{
    struct mt_srv *srv = talloc_get_type(ptr, struct mt_srv);
    time_t now = time(NULL);
    int status;
    pid_t pid;
    int ret;

    pid = waitpid(srv->pid, &status, WNOHANG);
    if (pid == 0) {
        set_tasks_checker(srv);
        return;
    }

    if (pid != srv->pid) {
        DEBUG(1, ("bad return (%d) from waitpid() waiting for %d\n",
                  pid, srv->pid));
        /* TODO: what do we do now ? */
    }

    if (WIFEXITED(status)) { /* children exited on it's own ?? */
        /* TODO: check configuration to see if it was removed
         * from the list of process to run */
        DEBUG(0,("Process [%s] exited on it's own ?!\n", srv->name));
    }

    if (srv->last_restart != 0) {
        if ((now - srv->last_restart) > 30) { /* TODO: get val from config */
            /* it was long ago reset restart threshold */
            srv->restarts = 0;
        }
    }

    /* restart the process */
    if (srv->restarts < 3) { /* TODO: get val from config */

        ret = server_service_init(srv->name, srv->mt_ctx->ev, &srv->pid);
        if (ret != EOK) {
            DEBUG(0,("Failed to restart service '%s'\n", srv->name));
            talloc_free(srv);
            return;
        }

        srv->restarts++;
        srv->last_restart = now;

        set_tasks_checker(srv);
        return;
    }

    DEBUG(0, ("Process [%s], definitely stopped!\n", srv->name));
    talloc_free(srv);
}

static void set_tasks_checker(struct mt_srv *srv)
{
    struct timed_event *te = NULL;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    tv.tv_sec += 2;
    tv.tv_usec = 0;
    te = event_add_timed(srv->mt_ctx->ev, srv, tv, tasks_check_handler, srv);
    if (te == NULL) {
        DEBUG(0, ("failed to add event, monitor offline for [%s]!\n",
                  srv->name));
        /* FIXME: shutdown ? */
    }
}

int start_monitor(TALLOC_CTX *mem_ctx,
                  struct event_context *event_ctx,
                  struct confdb_ctx *cdb)
{
    struct mt_ctx *ctx;
    struct mt_srv *srv;
    int ret, i;

    ctx = talloc_zero(mem_ctx, struct mt_ctx);
    if (!ctx) {
        DEBUG(0, ("fatal error initializing monitor!\n"));
        return ENOMEM;
    }
    ctx->ev = event_ctx;

    ret = confdb_get_param(cdb, mem_ctx, "config.services",
                           "activeServices", &ctx->services);

    if (ctx->services[0] == NULL) {
        DEBUG(0, ("No services configured!\n"));
        return EINVAL;
    }

    for (i = 0; ctx->services[i]; i++) {

        srv = talloc_zero(ctx, struct mt_srv);
        if (!srv) {
            talloc_free(ctx);
            return ENOMEM;
        }
        srv->name = ctx->services[i];
        srv->mt_ctx = ctx;

        ret = server_service_init(srv->name, event_ctx, &srv->pid);
        if (ret != EOK) {
            DEBUG(0,("Failed to restart service '%s'\n", srv->name));
            talloc_free(srv);
        }

        set_tasks_checker(srv);
    }

    /* Initialize D-BUS Server
     * The monitor will act as a D-BUS server for all
     * SSSD processes */
    ret = monitor_dbus_init(ctx);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

