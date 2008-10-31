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

/* TODO: Get these values from LDB */
#define SERVICE_PATH "/org/freeipa/sssd/service"
#define SERVICE_INTERFACE "org.freeipa.sssd.service"
#define SERVICE_METHOD_IDENTITY "getIdentity"

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

static int dbus_service_init(struct dbus_connection_toplevel_context *dct_ctx);
static void identity_check(DBusPendingCall *pending, void *data);

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
    struct sssd_dbus_method_ctx *sd_ctx;
    int ret;

    sd_ctx = talloc_zero(ctx, struct sssd_dbus_method_ctx);
    if (!sd_ctx) {
        return ENOMEM;
    }

    /* Set up globally-available D-BUS methods */
    sd_ctx->interface = talloc_strdup(sd_ctx, MONITOR_DBUS_INTERFACE);
    if (!sd_ctx->interface) {
        talloc_free(sd_ctx);
        return ENOMEM;
    }
    sd_ctx->path = talloc_strdup(sd_ctx, MONITOR_DBUS_PATH);
    if (!sd_ctx->path) {
        talloc_free(sd_ctx);
        return ENOMEM;
    }
    sd_ctx->methods = monitor_methods;
    sd_ctx->message_handler = NULL; /* Use the default message_handler */

    ret = sssd_new_dbus_server(ctx->ev, sd_ctx, DBUS_ADDRESS, dbus_service_init);

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

/*
 * dbus_service_init
 * This function should initiate a query to the newly connected
 * service to discover the service's identity (invoke the getIdentity
 * method on the new client). The reply callback for this request
 * should set the connection destructor appropriately.
 */
static int dbus_service_init(struct dbus_connection_toplevel_context *dct_ctx) {
    DBusMessage *msg;
    DBusPendingCall *pending_reply;
    DBusConnection *conn;
    DBusError dbus_error;
    dbus_bool_t dbret;
    
    DEBUG(0,("Initializing D-BUS Service"));
    conn = sssd_get_dbus_connection(dct_ctx);
    dbus_error_init(&dbus_error);

    /* 
     * Set up identity request 
     * This should be a well-known path and method
     * for all services
     */
    msg = dbus_message_new_method_call(NULL,
            SERVICE_PATH,
            SERVICE_INTERFACE,
            SERVICE_METHOD_IDENTITY);
    dbret = dbus_connection_send_with_reply(conn, msg, &pending_reply, -1);
    if (!dbret) {
        /*
         * Critical Failure
         * We can't communicate on this connection
         * We'll drop it using the default destructor.
         */
        DEBUG(0, ("D-BUS send failed.\n"));
        talloc_free(dct_ctx);
    }
    
    /* Set up the reply handler */
    dbus_pending_call_set_notify(pending_reply, identity_check, dct_ctx, NULL);
    dbus_message_unref(msg);

    return EOK;
}

static void identity_check(DBusPendingCall *pending, void *data) {
    struct dbus_connection_toplevel_context *dct_ctx;
    DBusMessage *reply;
    DBusError dbus_error;
    int type;

    dct_ctx = talloc_get_type(data, struct dbus_connection_toplevel_context);
    dbus_error_init(&dbus_error);
    
    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(0, ("Serious error. A reply callback was called but no reply was received and no timeout occurred\n"));
        
        /* Destroy this connection */
        sssd_dbus_disconnect(dct_ctx);
        return;
    }
    
    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        /* Got the service name and version */
        /* Extract the name and version from the message */
        /* Set up the destructor for this service */
        break;
    case DBUS_MESSAGE_TYPE_ERROR:
        DEBUG(0,("getIdentity returned an error %s, closing connection.\n", dbus_message_get_error_name(reply)));
        /* Falling through to default intentionally*/
    default:
        /*
         * Timeout or other error occurred or something
         * unexpected happened.
         * It doesn't matter which, because either way we 
         * know that this connection isn't trustworthy.
         * We'll destroy it now.
         */
        sssd_dbus_disconnect(dct_ctx);
        break;
    }
}
