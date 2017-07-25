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

#include "util/util.h"
#include "util/child_common.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/param.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <popt.h>
#include <tevent.h>
#include <dbus/dbus.h>

/* Needed for res_init() */
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "confdb/confdb.h"
#include "confdb/confdb_setup.h"
#include "db/sysdb.h"
#include "monitor/monitor.h"
#include "sbus/sssd_dbus.h"
#include "monitor/monitor_interfaces.h"
#include "responder/common/responder_sbus.h"
#include "util/inotify.h"

#ifdef USE_KEYRING
#include <keyutils.h>
#endif

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

/* terminate the child after this interval by default if it
 * doesn't shutdown on receiving SIGTERM */
#define MONITOR_DEF_FORCE_TIME 60

/* TODO: get the restart related values from config */
#define MONITOR_RESTART_CNT_INTERVAL_RESET   30
/* maximum allowed number of service restarts if the restarts
 * were less than MONITOR_RESTART_CNT_INTERVAL_RESET apart, which would
 * indicate a crash after startup or after every request */
#define MONITOR_MAX_SVC_RESTARTS    2
/* The services are restarted with a delay in case the restart was
 * hitting a race condition where the DP is not ready yet either.
 * The MONITOR_MAX_RESTART_DELAY defines the maximum delay between
 * restarts.
 */
#define MONITOR_MAX_RESTART_DELAY   4

/* name of the monitor server instance */
#define MONITOR_NAME        "sssd"

/* Special value to leave the Kerberos Replay Cache set to use
 * the libkrb5 defaults
 */
#define KRB5_RCACHE_DIR_DISABLE "__LIBKRB5_DEFAULTS__"

/* Warning messages */
#define CONF_FILE_PERM_ERROR_MSG "Cannot read config file %s. Please check "\
                                 "that the file is accessible only by the "\
                                 "owner and owned by root.root.\n"

/* SSSD domain name that is used for the auto-configured files domain */
#define IMPLICIT_FILES_DOMAIN_NAME "implicit_files"

int cmdline_debug_level;
int cmdline_debug_timestamps;
int cmdline_debug_microseconds;

struct svc_spy;

struct mt_svc {
    struct mt_svc *prev;
    struct mt_svc *next;
    enum mt_svc_type type;

    struct sbus_connection *conn;
    struct svc_spy *conn_spy;

    struct mt_ctx *mt_ctx;

    char *provider;
    char *command;
    char *name;
    char *identity;
    pid_t pid;

    int kill_time;

    bool svc_started;
    bool socket_activated; /* also used for dbus-activated services */

    int restarts;
    time_t last_restart;
    DBusPendingCall *pending;

    int debug_level;

    struct sss_child_ctx *child_ctx;
};

typedef int (*monitor_reconf_fn)(struct config_file_ctx *file_ctx,
                                 const char *filename);

struct config_file_callback {
    int wd;
    monitor_reconf_fn fn;
    char *filename;
    time_t modified;
    struct config_file_callback *next;
    struct config_file_callback *prev;
};

struct config_file_ctx {
    struct config_file_inotify_check {
        struct snotify_ctx *snctx;
    } inotify_check;

    struct config_file_poll_check {
        TALLOC_CTX *parent_ctx;
        struct tevent_timer *timer;
        struct config_file_callback *callbacks;
    } poll_check;

    monitor_reconf_fn fn;
    struct mt_ctx *mt_ctx;
};

struct mt_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    struct sss_domain_info *domains;
    char **services;
    int num_services;
    int started_services;
    struct mt_svc *svc_list;
    struct sbus_connection *sbus_srv;
    struct config_file_ctx *file_ctx;
    int service_id_timeout;
    bool check_children;
    bool services_started;
    struct netlink_ctx *nlctx;
    const char *conf_path;
    struct sss_sigchild_ctx *sigchld_ctx;
    bool pid_file_created;
    bool is_daemon;
    pid_t parent_pid;

    /* For running unprivileged services */
    uid_t uid;
    gid_t gid;
};

static int start_service(struct mt_svc *mt_svc);

static int monitor_service_init(struct sbus_connection *conn, void *data);

static int monitor_service_shutdown(struct sbus_connection *conn, void *data);

static int service_signal_reset_offline(struct mt_svc *svc);

static int get_service_config(struct mt_ctx *ctx, const char *name,
                              struct mt_svc **svc_cfg);
static int get_provider_config(struct mt_ctx *ctx, const char *name,
                              struct mt_svc **svc_cfg);
static int add_new_service(struct mt_ctx *ctx,
                           const char *name,
                           int restarts);
static int add_new_provider(struct mt_ctx *ctx,
                            const char *name,
                            int restarts);

static char *check_service(char *service);

static int mark_service_as_started(struct mt_svc *svc);

static int monitor_cleanup(void);

static void network_status_change_cb(void *cb_data)
{
    struct mt_svc *iter;
    struct mt_ctx *ctx = (struct mt_ctx *) cb_data;

    DEBUG(SSSDBG_TRACE_INTERNAL, "A networking status change detected "
          "signaling providers to reset offline status\n");
    for (iter = ctx->svc_list; iter; iter = iter->next) {
        /* Don't signal services, only providers */
        if (iter->provider) {
            service_signal_reset_offline(iter);
        }
    }
}

/* dbus_get_monitor_version
 * Return the monitor version over D-BUS */
static int get_monitor_version(struct sbus_request *dbus_req, void *data)
{
    dbus_uint16_t version = MONITOR_VERSION;

    return sbus_request_return_and_finish(dbus_req,
                                          DBUS_TYPE_UINT16, &version,
                                          DBUS_TYPE_INVALID);
}

struct mon_init_conn {
    struct mt_ctx *ctx;
    struct sbus_connection *conn;
    struct tevent_timer *timeout;
};

static int add_svc_conn_spy(struct mt_svc *svc);

static int service_not_found(char *svc_name,
                             struct mt_svc **_svc)
{
    DEBUG(SSSDBG_FATAL_FAILURE,
          "Unable to find peer [%s] in list of services, "
          "killing connection!\n", svc_name);

    *_svc = NULL;
    return ENOENT;
}

#ifdef HAVE_SYSTEMD
static int socket_activated_service_not_found(struct mon_init_conn *mini,
                                              char *svc_name,
                                              bool is_provider,
                                              struct mt_svc **_svc)
{
    struct mt_svc *svc = NULL;
    int ret;

    if (is_provider) {
        return service_not_found(svc_name, _svc);
    }

    /* As the service is a responder and wasn't part of the services' list, it means
     * the service has been socket/dbus activated and has to be configured and added
     * to the services' list now */

    *_svc = NULL;

    if (check_service(svc_name) != NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Invalid service %s\n", svc_name);
        return EINVAL;
    }

    mini->ctx->services_started = true;
    mini->ctx->num_services++;

    ret = get_service_config(mini->ctx, svc_name, &svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to get the configuration for the service: %s\n",
              svc_name);
        return ret;
    }
    svc->restarts = 0;
    svc->socket_activated = true;

    DLIST_ADD(mini->ctx->svc_list, svc);

    *_svc = svc;
    return EOK;
}
#endif

static int get_service_in_the_list(struct mon_init_conn *mini,
                                   char *svc_name,
                                   bool is_provider,
                                   struct mt_svc **_svc)
{
    struct mt_svc *svc;

    for (svc = mini->ctx->svc_list; svc != NULL; svc = svc->next) {
        if (strcasecmp(svc->identity, svc_name) == 0) {
            svc->socket_activated = false;
            *_svc = svc;
            return EOK;
        }
    }

#ifdef HAVE_SYSTEMD
    return socket_activated_service_not_found(mini, svc_name, is_provider,
                                              _svc);
#else
    return service_not_found(svc_name, _svc);
#endif
}

static int sbus_connection_destructor(struct sbus_connection *conn)
{
    return monitor_service_shutdown(conn,
                                    sbus_connection_get_destructor_data(conn));
}

/* registers a new client.
 * if operation is successful also sends back the Monitor version */
static int client_registration(struct sbus_request *dbus_req, void *data)
{
    dbus_uint16_t version = MONITOR_VERSION;
    struct mon_init_conn *mini;
    struct mt_svc *svc = NULL;
    DBusError dbus_error;
    dbus_uint16_t svc_ver;
    dbus_uint16_t svc_type;
    char *svc_name;
    dbus_bool_t dbret;
    int ret;

    mini = talloc_get_type(data, struct mon_init_conn);
    if (!mini) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Connection holds no valid init data\n");
        return EINVAL;
    }

    /* First thing, cancel the timeout */
    talloc_zfree(mini->timeout);

    dbus_error_init(&dbus_error);

    dbret = dbus_message_get_args(dbus_req->message, &dbus_error,
                                  DBUS_TYPE_STRING, &svc_name,
                                  DBUS_TYPE_UINT16, &svc_ver,
                                  DBUS_TYPE_UINT16, &svc_type,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse message, killing connection\n");
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        sbus_disconnect(dbus_req->conn);
        sbus_request_finish(dbus_req, NULL);
        /* FIXME: should we just talloc_zfree(conn) ? */
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Received ID registration: (%s,%d)\n", svc_name, svc_ver);

    /* search this service in the list */
    ret = get_service_in_the_list(mini, svc_name, svc_type == MT_SVC_PROVIDER,
                                  &svc);
    if (ret != EOK) {
        sbus_disconnect(dbus_req->conn);
        sbus_request_finish(dbus_req, NULL);
        /* FIXME: should we just talloc_zfree(conn) ? */

        goto done;
    }

    /* Fill in svc structure with connection data */
    svc->conn = mini->conn;

    /* For {dbus,socket}-activated services we will have to unregister then
     * when the sbus_connection is freed. That's the reason we have to
     * hook up on its destructor function, do the service unregistration
     * from there and set the destructor back to NULL just before freeing
     * the service itself. */
    if (svc->socket_activated) {
        talloc_set_destructor(svc->conn, sbus_connection_destructor);
    }

    ret = mark_service_as_started(svc);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to mark service [%s]!\n", svc_name);
        goto done;
    }

    /* reply that all is ok */
    sbus_request_return_and_finish(dbus_req,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_INVALID);

done:
    /* init complete, get rid of temp init context */
    talloc_zfree(mini);

    return EOK;
}

struct svc_spy {
    struct mt_svc *svc;
};

static int svc_destructor(void *mem)
{
    struct mt_svc *svc = talloc_get_type(mem, struct mt_svc);
    if (!svc) {
        /* ?!?!? */
        return 0;
    }

    /* try to delist service */
    if (svc->mt_ctx) {
        DLIST_REMOVE(svc->mt_ctx->svc_list, svc);
    }

    /* Cancel any pending calls */
    if (svc->pending) {
        dbus_pending_call_cancel(svc->pending);
    }

    /* svc is being freed, neutralize the spy */
    if (svc->conn_spy) {
        talloc_set_destructor((TALLOC_CTX *)svc->conn_spy, NULL);
        talloc_zfree(svc->conn_spy);
    }

    if (svc->type == MT_SVC_SERVICE && svc->svc_started
            && svc->mt_ctx != NULL && svc->mt_ctx->started_services > 0) {
        svc->mt_ctx->started_services--;
    }

    return 0;
}

static int svc_spy_destructor(void *mem)
{
    struct svc_spy *spy = talloc_get_type(mem, struct svc_spy);
    if (!spy) {
        /* ?!?!? */
        return 0;
    }

    /* svc->conn has been freed, NULL the pointer in svc */
    spy->svc->conn_spy = NULL;
    spy->svc->conn = NULL;
    return 0;
}

static int add_svc_conn_spy(struct mt_svc *svc)
{
    struct svc_spy *spy;

    spy = talloc(svc->conn, struct svc_spy);
    if (!spy) return ENOMEM;

    spy->svc = svc;
    talloc_set_destructor((TALLOC_CTX *)spy, svc_spy_destructor);
    svc->conn_spy = spy;

    return EOK;
}


static void svc_child_info(struct mt_svc *svc, int wait_status)
{
    if (WIFEXITED(wait_status)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Child [%d] exited with code [%d]\n",
               svc->pid, WEXITSTATUS(wait_status));
    } else if (WIFSIGNALED(wait_status)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Child [%d] terminated with signal [%d]\n",
               svc->pid, WTERMSIG(wait_status));
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Child [%d] did not exit cleanly\n", svc->pid);
        /* Forcibly kill this child, just in case */
        kill(svc->pid, SIGKILL);

        /* Let us get caught by another
         * call to the SIGCHLD handler
         */
    }
}

static int notify_startup(void)
{
#ifdef HAVE_SYSTEMD
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Sending startup notification to systemd\n");
    ret = sd_notify(0, "READY=1");
    if (ret < 0) {
        ret = -ret;
        DEBUG(SSSDBG_CRIT_FAILURE,
                "Error sending notification to systemd %d: %s\n",
                ret, sss_strerror(ret));

       return ret;
    }
#endif

    return EOK;
}

static int mark_service_as_started(struct mt_svc *svc)
{
    struct mt_ctx *ctx = svc->mt_ctx;
    struct mt_svc *iter;
    int ret;
    int i;

    DEBUG(SSSDBG_FUNC_DATA, "Marking %s as started.\n", svc->name);
    svc->svc_started = true;

    /* we need to attach a spy to the connection structure so that if some code
     * frees it we can zero it out in the service structure. Otherwise we may
     * try to access or even free, freed memory. */
    ret = add_svc_conn_spy(svc);
    if (ret) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to attch spy\n");
        goto done;
    }

    if (!ctx->services_started) {

        /* check if all providers are up */
        for (iter = ctx->svc_list; iter; iter = iter->next) {
            if (iter->provider && !iter->svc_started) {
                DEBUG(SSSDBG_FUNC_DATA,
                      "Still waiting on %s provider.\n", iter->name);
                break;
            }
        }

        if (iter) {
            /* there are still unstarted providers */
            goto done;
        }

        if (ctx->services != NULL) {
            ctx->services_started = true;

            DEBUG(SSSDBG_CONF_SETTINGS, "Now starting services!\n");
            /* then start all services */
            for (i = 0; ctx->services[i]; i++) {
                add_new_service(ctx, ctx->services[i], 0);
            }
        }
    }

    if (svc->type == MT_SVC_SERVICE) {
        ctx->started_services++;
    }

    /* create the pid file if all services are alive */
    if (!ctx->pid_file_created && ctx->started_services == ctx->num_services) {
        if (svc->socket_activated) {
            /* There's no reason for trying to terminate the parent process
             * when the responder was socket-activated. */
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "All services have successfully started, creating pid file\n");
        ret = pidfile(PID_PATH, MONITOR_NAME);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Error creating pidfile: %s/%s.pid! (%d [%s])\n",
                  PID_PATH, MONITOR_NAME, ret, strerror(ret));
            kill(getpid(), SIGTERM);
        }

        ctx->pid_file_created = true;

        notify_startup();

        /* Initialization is complete, terminate parent process if in daemon
         * mode. Make sure we send the signal to the right process */
        if (ctx->is_daemon) {
            if (ctx->parent_pid <= 1 || ctx->parent_pid != getppid()) {
                /* the parent process was already terminated */
                DEBUG(SSSDBG_MINOR_FAILURE, "Invalid parent pid: %d\n",
                      ctx->parent_pid);
                goto done;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "SSSD is initialized, "
                                      "terminating parent process\n");

            errno = 0;
            ret = kill(ctx->parent_pid, SIGTERM);
            if (ret != 0) {
                ret = errno;
                DEBUG(SSSDBG_FATAL_FAILURE, "Unable to terminate parent "
                      "process [%d]: %s\n", ret, strerror(ret));
            }
        }
    }

done:
    return ret;
}

static void services_startup_timeout(struct tevent_context *ev,
                                     struct tevent_timer *te,
                                     struct timeval t, void *ptr)
{
    struct mt_ctx *ctx = talloc_get_type(ptr, struct mt_ctx);
    int i;

    if (ctx->services == NULL) {
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Handling timeout\n");

    if (!ctx->services_started) {

        DEBUG(SSSDBG_CRIT_FAILURE, "Providers did not start in time, "
                  "forcing services startup!\n");

        ctx->services_started = true;

        DEBUG(SSSDBG_CONF_SETTINGS, "Now starting services!\n");
        /* then start all services */
        for (i = 0; ctx->services[i]; i++) {
            add_new_service(ctx, ctx->services[i], 0);
        }
    }
}

static int add_services_startup_timeout(struct mt_ctx *ctx)
{
    struct tevent_timer *to;
    struct timeval tv;

    /* 5 seconds should be plenty */
    tv = tevent_timeval_current_ofs(5, 0);
    to = tevent_add_timer(ctx->ev, ctx, tv, services_startup_timeout, ctx);
    if (!to) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory?!\n");
        return ENOMEM;
    }

    return EOK;
}

struct mon_srv_iface monitor_methods = {
    { &mon_srv_iface_meta, 0 },
    .getVersion = get_monitor_version,
    .RegisterService = client_registration,
};

/* monitor_dbus_init
 * Set up the monitor service as a D-BUS Server */
static int monitor_dbus_init(struct mt_ctx *ctx)
{
    char *monitor_address;
    int ret;

    ret = monitor_get_sbus_address(ctx, &monitor_address);
    if (ret != EOK) {
        return ret;
    }

    /* If a service is running as unprivileged user, we need to make sure this
     * user can access the monitor sbus server. root is still king, so we don't
     * lose any access.
     */
    ret = sbus_new_server(ctx, ctx->ev, monitor_address, ctx->uid, ctx->gid,
                          false, &ctx->sbus_srv, monitor_service_init, ctx, ctx);

    talloc_free(monitor_address);

    return ret;
}

static void monitor_restart_service(struct mt_svc *svc);

static void reload_reply(DBusPendingCall *pending, void *data)
{
    DBusMessage *reply;
    struct mt_svc *svc = talloc_get_type(data, struct mt_svc);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(SSSDBG_FATAL_FAILURE,
              "A reply callback was called but no reply was received"
                  " and no timeout occurred\n");
        /* Destroy this connection */
        sbus_disconnect(svc->conn);
        dbus_pending_call_unref(pending);
        return;
    }

    /* TODO: Handle cases where the call has timed out or returned
     * with an error.
     */

    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
}

static int service_signal_dns_reload(struct mt_svc *svc);
static int monitor_update_resolv(struct config_file_ctx *file_ctx,
                                 const char *filename)
{
    int ret;
    struct mt_svc *cur_svc;
    struct mt_ctx *mt_ctx;

    mt_ctx = file_ctx->mt_ctx;

    DEBUG(SSSDBG_TRACE_LIBS, "Resolv.conf has been updated. Reloading.\n");

    ret = res_init();
    if (ret != 0) {
        return EIO;
    }

    /* Signal all services to reload their DNS configuration */
    for (cur_svc = mt_ctx->svc_list; cur_svc; cur_svc = cur_svc->next) {
        service_signal_dns_reload(cur_svc);
    }
    return EOK;
}

static int service_signal(struct mt_svc *svc, const char *svc_signal)
{
    DBusMessage *msg;
    int ret;

    if (svc->provider && strcasecmp(svc->provider, "local") == 0) {
        /* The local provider requires no signaling */
        return EOK;
    }

    if (!svc->conn) {
        /* Avoid a race condition where we are trying to
         * order a service to reload that hasn't started
         * yet.
         */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not signal service [%s].\n", svc->name);
        return EIO;
    }

    msg = dbus_message_new_method_call(NULL,
                                       MONITOR_PATH,
                                       MON_CLI_IFACE,
                                       svc_signal);
    if (msg == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Out of memory trying to allocate memory to invoke: %s\n",
               svc_signal);
        return ENOMEM;
    }

    ret = sbus_conn_send(svc->conn, msg,
                         svc->mt_ctx->service_id_timeout,
                         reload_reply, svc, NULL);

    dbus_message_unref(msg);
    return ret;
}

static int service_signal_dns_reload(struct mt_svc *svc)
{
    return service_signal(svc, MON_CLI_IFACE_RESINIT);
}
static int service_signal_offline(struct mt_svc *svc)
{
    return service_signal(svc, MON_CLI_IFACE_GOOFFLINE);
}
static int service_signal_reset_offline(struct mt_svc *svc)
{
    return service_signal(svc, MON_CLI_IFACE_RESETOFFLINE);
}
static int service_signal_rotate(struct mt_svc *svc)
{
    return service_signal(svc, MON_CLI_IFACE_ROTATELOGS);
}
static int service_signal_clear_memcache(struct mt_svc *svc)
{
    return service_signal(svc, MON_CLI_IFACE_CLEARMEMCACHE);
}
static int service_signal_clear_enum_cache(struct mt_svc *svc)
{
    return service_signal(svc, MON_CLI_IFACE_CLEARENUMCACHE);
}
static int service_signal_sysbus_reconnect(struct mt_svc *svc)
{
    return service_signal(svc, MON_CLI_IFACE_SYSBUSRECONNECT);
}

static int check_domain_ranges(struct sss_domain_info *domains)
{
    struct sss_domain_info *dom = domains, *other = NULL;
    uint32_t id_min, id_max;

    while (dom) {
        other = get_next_domain(dom, 0);
        if (dom->id_max && dom->id_min > dom->id_max) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Domain '%s' does not have a valid ID range\n", dom->name);
            return EINVAL;
        }

        while (other) {
            id_min = MAX(dom->id_min, other->id_min);
            id_max = MIN((dom->id_max ? dom->id_max : UINT32_MAX),
                         (other->id_max ? other->id_max : UINT32_MAX));
            if (id_min <= id_max) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Domains '%s' and '%s' overlap in range %u - %u\n",
                      dom->name, other->name, id_min, id_max);
            }
            other = get_next_domain(other, 0);
        }
        dom = get_next_domain(dom, 0);
    }

    return EOK;
}

static int check_local_domain_unique(struct sss_domain_info *domains)
{
    uint8_t count = 0;

    struct sss_domain_info *dom = domains;

    while (dom) {
        if (strcasecmp(dom->provider, "local") == 0) {
            count++;
        }

        if (count > 1) {
            break;
        }

        dom = get_next_domain(dom, 0);
    }

    if (count > 1) {
        return EINVAL;
    }

    return EOK;
}

static errno_t add_implicit_services(struct confdb_ctx *cdb, TALLOC_CTX *mem_ctx,
                                     char ***_services)
{
    int ret;
    char **domain_names;
    TALLOC_CTX *tmp_ctx;
    size_t c;
    char *conf_path;
    char *id_provider;
    bool add_pac = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = confdb_get_string_as_list(cdb, tmp_ctx,
                                    CONFDB_MONITOR_CONF_ENTRY,
                                    CONFDB_MONITOR_ACTIVE_DOMAINS,
                                    &domain_names);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "No domains configured!\n");
        goto done;
    }

    for (c = 0; domain_names[c] != NULL; c++) {
        conf_path = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL,
                                    domain_names[c]);
        if (conf_path == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = confdb_get_string(cdb, tmp_ctx, conf_path,
                                CONFDB_DOMAIN_ID_PROVIDER, NULL, &id_provider);
        if (ret == EOK) {
            if (id_provider == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "id_provider is not set for "
                      "domain [%s], trying next domain.\n", domain_names[c]);
                continue;
            }

            if (strcasecmp(id_provider, "IPA") == 0) {
                add_pac = true;
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get id_provider for " \
                                      "domain [%s], trying next domain.\n",
                                      domain_names[c]);
        }
    }

    if (BUILD_WITH_PAC_RESPONDER && add_pac &&
        !string_in_list("pac", *_services, false)) {
        ret = add_string_to_list(mem_ctx, "pac", _services);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "add_string_to_list failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static char *check_service(char *service)
{
    const char * const *known_services = get_known_services();
    int i;

    for (i = 0; known_services[i] != NULL; i++) {
        if (strcasecmp(service, known_services[i]) == 0) {
            break;
        }
    }

    if (known_services[i] == NULL) {
        return service;
    }

    return NULL;
}

static char *check_services(char **services)
{
    if (services == NULL) {
        return NULL;
    }

    /* Check if services we are about to start are in the list if known */
    for (int i = 0; services[i]; i++) {
        if (check_service(services[i]) != NULL) {
            return services[i];
        }
    }

    return NULL;
}

static int get_service_user(struct mt_ctx *ctx)
{
    errno_t ret;
    char *user_str;

    ret = confdb_get_string(ctx->cdb, ctx, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_USER_RUNAS,
                            SSSD_USER, &user_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get the user to run as\n");
        return ret;
    }

    ret = sss_user_by_name_or_uid(user_str, &ctx->uid, &ctx->gid);
    talloc_free(user_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to set allowed UIDs.\n");
        return ret;
    }

    return EOK;
}

static int get_monitor_config(struct mt_ctx *ctx)
{
    int ret;
    int timeout_seconds;
    char *badsrv = NULL;
    int i;

    ret = confdb_get_int(ctx->cdb,
                         CONFDB_MONITOR_CONF_ENTRY,
                         CONFDB_MONITOR_SBUS_TIMEOUT,
                         10, &timeout_seconds);
    if (ret != EOK) {
        return ret;
    }

    ctx->service_id_timeout = timeout_seconds * 1000; /* service_id_timeout is in ms */

    ret = confdb_get_string_as_list(ctx->cdb, ctx,
                                    CONFDB_MONITOR_CONF_ENTRY,
                                    CONFDB_MONITOR_ACTIVE_SERVICES,
                                    &ctx->services);

#ifdef HAVE_SYSTEMD
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get the explicitly configured services!\n");
        return EINVAL;
    }
#else
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "No services configured!\n");
        return EINVAL;
    }
#endif

    ret = add_implicit_services(ctx->cdb, ctx, &ctx->services);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add implicit configured "
                                 "services. Some functionality might "
                                 "be missing\n");
    }

    badsrv = check_services(ctx->services);
    if (badsrv != NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Invalid service %s\n", badsrv);
        return EINVAL;
    }

    ctx->started_services = 0;
    ctx->num_services = 0;

    if (ctx->services != NULL) {
        for (i = 0; ctx->services[i] != NULL; i++) {
            ctx->num_services++;
        }
    }

    ret = get_service_user(ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to get the unprivileged user\n");
        return ret;
    }

    ret = confdb_ensure_files_domain(ctx->cdb, IMPLICIT_FILES_DOMAIN_NAME);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot add the implicit files domain [%d]: %s\n",
              ret, strerror(ret));
        /* Not fatal */
    }

    ret = confdb_expand_app_domains(ctx->cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to expand application domains\n");
        /* This must not be fatal so that SSSD keeps running and lets
         * admin correct the error.
         */
    }

    ret = confdb_get_domains(ctx->cdb, &ctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "No domains configured.\n");
        return ret;
    }

    ret = check_local_domain_unique(ctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "More than one local domain configured.\n");
        return ret;
    }

    /* Check UID/GID overlaps */
    ret = check_domain_ranges(ctx->domains);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

/* This is a temporary function that returns false if the service
 * being started was only tested when running as root.
 */
static bool svc_supported_as_nonroot(const char *svc_name)
{
    if ((strcmp(svc_name, "nss") == 0)
        || (strcmp(svc_name, "pam") == 0)
        || (strcmp(svc_name, "autofs") == 0)
        || (strcmp(svc_name, "pac") == 0)
        || (strcmp(svc_name, "sudo") == 0)
        || (strcmp(svc_name, "ssh") == 0)) {
        return true;
    }
    return false;
}

static int get_service_config(struct mt_ctx *ctx, const char *name,
                              struct mt_svc **svc_cfg)
{
    int ret;
    char *path;
    struct mt_svc *svc;
    time_t now = time(NULL);
    uid_t uid = 0;
    gid_t gid = 0;

    *svc_cfg = NULL;

    svc = talloc_zero(ctx, struct mt_svc);
    if (!svc) {
        return ENOMEM;
    }
    svc->mt_ctx = ctx;
    svc->type = MT_SVC_SERVICE;

    talloc_set_destructor((TALLOC_CTX *)svc, svc_destructor);

    svc->name = talloc_strdup(svc, name);
    if (!svc->name) {
        talloc_free(svc);
        return ENOMEM;
    }

    svc->identity = talloc_strdup(svc, name);
    if (!svc->identity) {
        talloc_free(svc);
        return ENOMEM;
    }

    path = talloc_asprintf(svc, CONFDB_SERVICE_PATH_TMPL, svc->name);
    if (!path) {
        talloc_free(svc);
        return ENOMEM;
    }

    ret = confdb_get_string(ctx->cdb, svc, path,
                            CONFDB_SERVICE_COMMAND,
                            NULL, &svc->command);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Failed to start service '%s'\n", svc->name);
        talloc_free(svc);
        return ret;
    }

    if (svc_supported_as_nonroot(svc->name)) {
        uid = ctx->uid;
        gid = ctx->gid;
    }

    if (!svc->command) {
        svc->command = talloc_asprintf(
            svc, "%s/sssd_%s", SSSD_LIBEXEC_PATH, svc->name
        );
        if (!svc->command) {
            talloc_free(svc);
            return ENOMEM;
        }

        svc->command = talloc_asprintf_append(svc->command,
                " --uid %"SPRIuid" --gid %"SPRIgid,
                uid, gid);
        if (!svc->command) {
            talloc_free(svc);
            return ENOMEM;
        }

        if (cmdline_debug_level != SSSDBG_UNRESOLVED) {
            svc->command = talloc_asprintf_append(
                svc->command, " -d %#.4x", cmdline_debug_level
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        }

        if (cmdline_debug_timestamps != SSSDBG_TIMESTAMP_UNRESOLVED) {
            svc->command = talloc_asprintf_append(
                svc->command, " --debug-timestamps=%d", cmdline_debug_timestamps
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        }

        if (cmdline_debug_microseconds != SSSDBG_MICROSECONDS_UNRESOLVED) {
            svc->command = talloc_asprintf_append(
                svc->command, " --debug-microseconds=%d",
                cmdline_debug_microseconds
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        }

        if (debug_to_file) {
            svc->command = talloc_strdup_append(
                svc->command, " --debug-to-files"
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        } else if (ctx->is_daemon == false) {
            svc->command = talloc_strdup_append(
                svc->command, " --debug-to-stderr"
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        }
    }

    svc->last_restart = now;

    *svc_cfg = svc;
    talloc_free(path);

    return EOK;
}

static int add_new_service(struct mt_ctx *ctx,
                           const char *name,
                           int restarts)
{
    int ret;
    struct mt_svc *svc;

    ret = get_service_config(ctx, name, &svc);
    if (ret != EOK) {
        return ret;
    }
    svc->restarts = restarts;

    ret = start_service(svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Failed to start service '%s'\n", svc->name);
        talloc_free(svc);
    }

    return ret;
}

static int get_provider_config(struct mt_ctx *ctx, const char *name,
                              struct mt_svc **svc_cfg)
{
    int ret;
    char *path;
    struct mt_svc *svc;
    time_t now = time(NULL);

    *svc_cfg = NULL;

    svc = talloc_zero(ctx, struct mt_svc);
    if (!svc) {
        return ENOMEM;
    }
    svc->mt_ctx = ctx;
    svc->type = MT_SVC_PROVIDER;

    talloc_set_destructor((TALLOC_CTX *)svc, svc_destructor);

    svc->name = talloc_strdup(svc, name);
    if (!svc->name) {
        talloc_free(svc);
        return ENOMEM;
    }

    svc->identity = talloc_asprintf(svc, "%%BE_%s", svc->name);
    if (!svc->identity) {
        talloc_free(svc);
        return ENOMEM;
    }

    path = talloc_asprintf(svc, CONFDB_DOMAIN_PATH_TMPL, name);
    if (!path) {
        talloc_free(svc);
        return ENOMEM;
    }

    ret = confdb_get_string(ctx->cdb, svc, path,
                            CONFDB_DOMAIN_ID_PROVIDER,
                            NULL, &svc->provider);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to find ID provider from [%s] configuration\n", name);
        talloc_free(svc);
        return ret;
    }

    ret = confdb_get_string(ctx->cdb, svc, path,
                            CONFDB_DOMAIN_COMMAND,
                            NULL, &svc->command);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to find command from [%s] configuration\n", name);
        talloc_free(svc);
        return ret;
    }

    talloc_free(path);

    /* if no provider is present do not run the domain */
    if (!svc->provider) {
        talloc_free(svc);
        return EIO;
    }

    /* if there are no custom commands, build a default one */
    if (!svc->command) {
        svc->command = talloc_asprintf(
            svc, "%s/sssd_be --domain %s", SSSD_LIBEXEC_PATH, svc->name
        );
        if (!svc->command) {
            talloc_free(svc);
            return ENOMEM;
        }

        svc->command = talloc_asprintf_append(svc->command,
                " --uid %"SPRIuid" --gid %"SPRIgid,
                ctx->uid, ctx->gid);
        if (!svc->command) {
            talloc_free(svc);
            return ENOMEM;
        }

        if (cmdline_debug_level != SSSDBG_UNRESOLVED) {
            svc->command = talloc_asprintf_append(
                svc->command, " -d %#.4x", cmdline_debug_level
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        }

        if (cmdline_debug_timestamps != SSSDBG_TIMESTAMP_UNRESOLVED) {
            svc->command = talloc_asprintf_append(
                svc->command, " --debug-timestamps=%d", cmdline_debug_timestamps
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        }

        if (cmdline_debug_microseconds != SSSDBG_MICROSECONDS_UNRESOLVED) {
            svc->command = talloc_asprintf_append(
                svc->command, " --debug-microseconds=%d",
                cmdline_debug_microseconds
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        }

        if (debug_to_file) {
            svc->command = talloc_strdup_append(
                svc->command, " --debug-to-files"
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        } else if (ctx->is_daemon == false) {
            svc->command = talloc_strdup_append(
                svc->command, " --debug-to-stderr"
            );
            if (!svc->command) {
                talloc_free(svc);
                return ENOMEM;
            }
        }
    }

    svc->last_restart = now;

    *svc_cfg = svc;
    return EOK;
}

static int add_new_provider(struct mt_ctx *ctx,
                            const char *name,
                            int restarts)
{
    int ret;
    struct mt_svc *svc;

    ret = get_provider_config(ctx, name, &svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not get provider configuration for [%s]\n",
                  name);
        return ret;
    }
    svc->restarts = restarts;

    if (strcasecmp(svc->provider, "local") == 0) {
        /* The LOCAL provider requires no back-end currently
         * We'll add it to the service list, but we don't need
         * to poll it.
         */
        svc->svc_started = true;
        DLIST_ADD(ctx->svc_list, svc);
        return ENOENT;
    }

    ret = start_service(svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Failed to start service '%s'\n", svc->name);
        talloc_free(svc);
    }

    return ret;
}

static void monitor_hup(struct tevent_context *ev,
                        struct tevent_signal *se,
                        int signum,
                        int count,
                        void *siginfo,
                        void *private_data)
{
    struct mt_ctx *ctx = talloc_get_type(private_data, struct mt_ctx);
    struct mt_svc *cur_svc;

    DEBUG(SSSDBG_CRIT_FAILURE, "Received SIGHUP.\n");

    /* Send D-Bus message to other services to rotate their logs.
     * NSS service receives also message to clear memory caches. */
    for(cur_svc = ctx->svc_list; cur_svc; cur_svc = cur_svc->next) {
        service_signal_rotate(cur_svc);
        if (!strcmp(NSS_SBUS_SERVICE_NAME, cur_svc->name)) {
            service_signal_clear_memcache(cur_svc);
            service_signal_clear_enum_cache(cur_svc);
        }

        if (!strcmp(SSS_AUTOFS_SBUS_SERVICE_NAME, cur_svc->name)) {
            service_signal_clear_enum_cache(cur_svc);
        }

    }

}

static int monitor_cleanup(void)
{
    int ret;

    errno = 0;
    ret = unlink(SSSD_PIDFILE);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Error removing pidfile! (%d [%s])\n", ret, strerror(ret));
        return ret;
    }

    return EOK;
}

static void monitor_quit(struct mt_ctx *mt_ctx, int ret)
{
    struct mt_svc *svc;
    pid_t pid;
    int status;
    errno_t error;
    int kret;
    bool killed;

    DEBUG(SSSDBG_IMPORTANT_INFO, "Returned with: %d\n", ret);

    /* Kill all of our known children manually */
    DLIST_FOR_EACH(svc, mt_ctx->svc_list) {
        if (svc->socket_activated && svc->conn != NULL) {
            /* Unset the sbus_connection destructor used to
             * unregister the service from the monitor as
             * it may lead to a double-free here. */
            talloc_set_destructor(svc->conn, NULL);
        }

        if (svc->pid == 0) {
            /* The local provider has no PID */
            continue;
        }

        killed = false;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Terminating [%s][%d]\n", svc->name, svc->pid);
        do {
            errno = 0;
            kret = kill(-svc->pid, SIGTERM);
            if (kret < 0) {
                error = errno;
                DEBUG(SSSDBG_CRIT_FAILURE, "Couldn't kill [%s][%d]: [%s]\n",
                          svc->name, svc->pid, strerror(error));
            }

            error = 0;
            do {
                errno = 0;
                pid = waitpid(svc->pid, &status, WNOHANG);
                if (pid == -1) {
                    /* An error occurred while waiting */
                    error = errno;
                    if (error == ECHILD) {
                        killed = true;
                    } else if (error != EINTR) {
                        DEBUG(SSSDBG_FATAL_FAILURE,
                              "[%d][%s] while waiting for [%s]\n",
                                  error, strerror(error), svc->name);
                        /* Forcibly kill this child */
                        kill(-svc->pid, SIGKILL);
                        break;
                    }
                } else if (pid != 0) {
                    error = 0;
                    if (WIFEXITED(status)) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Child [%s] exited gracefully\n", svc->name);
                    } else if (WIFSIGNALED(status)) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Child [%s] terminated with a signal\n", svc->name);
                    } else {
                        DEBUG(SSSDBG_FATAL_FAILURE,
                              "Child [%s] did not exit cleanly\n", svc->name);
                        /* Forcibly kill this child */
                        kill(-svc->pid, SIGKILL);
                    }
                    killed = true;
                }
            } while (error == EINTR);
            if (!killed) {
                /* Sleep 10ms and try again */
                usleep(10000);
            }
        } while (!killed);
    }

#if HAVE_GETPGRP
    /* Kill any remaining children in our process group, just in case
     * we have any leftover children we don't expect. For example, if
     * a krb5_child or ldap_child is running at the same moment.
     */
    error = 0;
    if (getpgrp() == getpid()) {
        kill(-getpgrp(), SIGTERM);
        do {
            errno = 0;
            pid = waitpid(0, &status, 0);
            if (pid == -1) {
                error = errno;
            }
        } while (error == EINTR || pid > 0);
    }
#endif

    monitor_cleanup();

    exit(ret);
}

static void monitor_quit_signal(struct tevent_context *ev,
                                struct tevent_signal *se,
                                int signum,
                                int count,
                                void *siginfo,
                                void *private_data)
{
    struct mt_ctx *mt_ctx = talloc_get_type(private_data, struct mt_ctx);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Received shutdown command\n");

    DEBUG(SSSDBG_IMPORTANT_INFO, "Monitor received %s: terminating "
                                  "children\n", strsignal(signum));

    monitor_quit(mt_ctx, 0);
}

static void signal_res_init(struct mt_ctx *monitor)
{
    struct mt_svc *cur_svc;
    int ret;
    DEBUG(SSSDBG_OP_FAILURE, "Reloading Resolv.conf.\n");

    ret = res_init();
    if (ret == 0) {
        for(cur_svc = monitor->svc_list; cur_svc; cur_svc = cur_svc->next) {
            service_signal_dns_reload(cur_svc);
        }
    }
}

static void signal_offline(struct tevent_context *ev,
                           struct tevent_signal *se,
                           int signum,
                           int count,
                           void *siginfo,
                           void *private_data)
{
    struct mt_ctx *monitor;
    struct mt_svc *cur_svc;

    monitor = talloc_get_type(private_data, struct mt_ctx);

    DEBUG(SSSDBG_TRACE_INTERNAL,
         "Signaling providers to go offline immediately.\n");

    /* Signal all providers to immediately go offline */
    for(cur_svc = monitor->svc_list; cur_svc; cur_svc = cur_svc->next) {
        /* Don't signal services, only providers */
        if (cur_svc->provider) {
            service_signal_offline(cur_svc);
        }
    }
}

static void signal_offline_reset(struct tevent_context *ev,
                                 struct tevent_signal *se,
                                 int signum,
                                 int count,
                                 void *siginfo,
                                 void *private_data)
{
    struct mt_ctx *monitor;
    struct mt_svc *cur_svc;

    monitor = talloc_get_type(private_data, struct mt_ctx);

    DEBUG(SSSDBG_TRACE_INTERNAL,
         "Signaling providers to reset offline immediately.\n");

    for(cur_svc = monitor->svc_list; cur_svc; cur_svc = cur_svc->next) {
        if (cur_svc->provider) {
            service_signal_reset_offline(cur_svc);
        }

        if (strcmp(SSS_IFP_SBUS_SERVICE_NAME, cur_svc->name) == 0) {
            service_signal_sysbus_reconnect(cur_svc);
        }
    }
    signal_res_init(monitor);
}

static int monitor_ctx_destructor(void *mem)
{
    struct mt_ctx *mon = talloc_get_type(mem, struct mt_ctx);
    struct mt_svc *svc;

    /* zero out references in svcs so that they don't try
     * to access the monitor context on process shutdown */

    for (svc = mon->svc_list; svc; svc = svc->next) {
        svc->mt_ctx = NULL;
    }
    return 0;
}

/*
 * This function should not be static otherwise gcc does some special kind of
 * optimisations which should not happen according to code: chown (unlink)
 * failed (return -1) but errno was zero.
 * As a result of this  * warning is printed ‘monitor’ may be used
 * uninitialized in this function. Instead of checking errno for 0
 * it's better to disable optimisation(in-lining) of this function.
 */
errno_t load_configuration(TALLOC_CTX *mem_ctx,
                           const char *config_file,
                           const char *config_dir,
                           struct mt_ctx **monitor)
{
    errno_t ret;
    struct mt_ctx *ctx;
    char *cdb_file = NULL;

    ctx = talloc_zero(mem_ctx, struct mt_ctx);
    if(!ctx) {
        return ENOMEM;
    }

    ctx->pid_file_created = false;
    talloc_set_destructor((TALLOC_CTX *)ctx, monitor_ctx_destructor);

    cdb_file = talloc_asprintf(ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (cdb_file == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory, aborting!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_setup(ctx, cdb_file, config_file, config_dir, &ctx->cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to setup ConfDB [%d]: %s\n",
             ret, sss_strerror(ret));
        goto done;
    }

    /* Validate the configuration in the database */
    /* Read in the monitor's configuration */
    ret = get_monitor_config(ctx);
    if (ret != EOK) {
        goto done;
    }

    /* Allow configuration database to be accessible
     * when SSSD runs as nonroot */
    ret = chown(cdb_file, ctx->uid, ctx->gid);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "chown failed for [%s]: [%d][%s].\n",
              cdb_file, ret, sss_strerror(ret));
        goto done;
    }

    *monitor = ctx;

    ret = EOK;

done:
    talloc_free(cdb_file);
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

static void poll_config_file(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval t, void *ptr);
static errno_t monitor_config_file_fallback(TALLOC_CTX *parent_ctx,
                                            struct config_file_ctx *file_ctx,
                                            const char *file);

static errno_t create_poll_timer(struct config_file_ctx *file_ctx)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    tv.tv_sec += CONFIG_FILE_POLL_INTERVAL;
    tv.tv_usec = 0;

    file_ctx->poll_check.timer = tevent_add_timer(file_ctx->mt_ctx->ev,
                                                  file_ctx->poll_check.parent_ctx,
                                                  tv,
                                                  poll_config_file,
                                                  file_ctx);
    if (!file_ctx->poll_check.timer) {
        talloc_free(file_ctx);
        return EIO;
    }

    return EOK;
}

static void poll_config_file(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval t, void *ptr)
{
    int ret, err;
    struct stat file_stat;
    struct config_file_ctx *file_ctx;
    struct config_file_callback *cb;

    file_ctx = talloc_get_type(ptr, struct config_file_ctx);

    for (cb = file_ctx->poll_check.callbacks; cb; cb = cb->next) {
        ret = stat(cb->filename, &file_stat);
        if (ret < 0) {
            err = errno;
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Could not stat file [%s]. Error [%d:%s]\n",
                  cb->filename, err, strerror(err));
            return;
        }

        if (file_stat.st_mtime != cb->modified) {
            /* Parse the configuration file and signal the children */
            /* Note: this will fire if the modification time changes into the past
             * as well as the future.
             */
            DEBUG(SSSDBG_CRIT_FAILURE, "Config file changed\n");
            cb->modified = file_stat.st_mtime;

            /* Tell the monitor to signal the children */
            cb->fn(file_ctx, cb->filename);
        }
    }

    ret = create_poll_timer(file_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Error: Config file no longer monitored for changes!\n");
    }
}

static int resolv_conf_inotify_cb(const char *filename,
                                  uint32_t flags,
                                  void *pvt)
{
    struct config_file_ctx *file_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Received inotify notification for %s\n", filename);

    file_ctx = talloc_get_type(pvt, struct config_file_ctx);
    if (file_ctx == NULL) {
        return EINVAL;
    }

    return file_ctx->fn(file_ctx, filename);
}

static int try_inotify(struct config_file_ctx *file_ctx,
                       const char *filename)
{
#ifdef HAVE_INOTIFY
    struct snotify_ctx *snctx;
    /* We will queue the file for update in one second.
     * This way, if there is a script writing to the file
     * repeatedly, we won't be attempting to update multiple
     * times.
     */
    struct timeval delay = { .tv_sec = 1, .tv_usec = 0 };

    snctx = snotify_create(file_ctx, file_ctx->mt_ctx->ev, SNOTIFY_WATCH_DIR,
                           filename, &delay,
                           IN_DELETE_SELF | IN_CLOSE_WRITE | IN_MOVE_SELF | \
                           IN_CREATE | IN_MOVED_TO | IN_IGNORED,
                           resolv_conf_inotify_cb, file_ctx);
    if (snctx == NULL) {
        return EIO;
    }

    return EOK;
#else
    return EINVAL;
#endif /* HAVE_INOTIFY */
}

static int monitor_config_file(TALLOC_CTX *mem_ctx,
                               struct mt_ctx *ctx,
                               monitor_reconf_fn fn,
                               const char *file)
{
    int ret;
    bool use_inotify;

    if (!ctx->file_ctx) {
        ctx->file_ctx = talloc_zero(mem_ctx, struct config_file_ctx);
        if (!ctx->file_ctx) return ENOMEM;

        ctx->file_ctx->mt_ctx = ctx;
        ctx->file_ctx->fn = fn;
    }

    ret = confdb_get_bool(ctx->cdb,
                          CONFDB_MONITOR_CONF_ENTRY,
                          CONFDB_MONITOR_TRY_INOTIFY,
                          true, &use_inotify);
    if (ret != EOK) {
        talloc_free(ctx->file_ctx);
        return ret;
    }

    if (use_inotify) {
        ret = try_inotify(ctx->file_ctx, file);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Falling back to polling\n");
            use_inotify = false;
        }
    }

    if (use_inotify == false) {
        ret = monitor_config_file_fallback(mem_ctx, ctx->file_ctx, file);
    }

    return ret;
}

static errno_t monitor_config_file_fallback(TALLOC_CTX *parent_ctx,
                                            struct config_file_ctx *file_ctx,
                                            const char *file)
{
    struct config_file_callback *cb = NULL;
    struct stat file_stat;
    int ret, err;

    ret = stat(file, &file_stat);
    if (ret < 0) {
        err = errno;
        if (err == ENOENT) {
             DEBUG(SSSDBG_MINOR_FAILURE,
                   "file [%s] is missing. Will not update online status "
                   "based on watching the file\n", file);
             return EOK;

        } else {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Could not stat file [%s]. Error [%d:%s]\n",
                  file, err, strerror(err));

            return err;
        }
    }

    file_ctx->poll_check.parent_ctx = parent_ctx;

    cb = talloc_zero(file_ctx, struct config_file_callback);
    if (!cb) {
        talloc_free(file_ctx);
        return ENOMEM;
    }
    cb->filename = talloc_strdup(cb, file);
    if (!cb->filename) {
        talloc_free(file_ctx);
        return ENOMEM;
    }
    cb->fn = file_ctx->fn;
    cb->modified = file_stat.st_mtime;

    DLIST_ADD(file_ctx->poll_check.callbacks, cb);

    if(!file_ctx->poll_check.timer) {
        ret = create_poll_timer(file_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot create poll timer\n");
            return ret;
        }
    }

    return EOK;
}

#define MISSING_RESOLV_CONF_POLL_TIME 10

static void missing_resolv_conf(struct tevent_context *ev,
                                struct tevent_timer *te,
                                struct timeval tv, void *data)
{
    int ret;
    struct mt_ctx *ctx = talloc_get_type(data, struct mt_ctx);

    ret = monitor_config_file(ctx, ctx, monitor_update_resolv, RESOLV_CONF_PATH);
    if (ret == EOK) {
        signal_res_init(ctx);
    } else if (ret == ENOENT) {
        tv = tevent_timeval_current_ofs(MISSING_RESOLV_CONF_POLL_TIME, 0);
        te = tevent_add_timer(ctx->ev, ctx, tv, missing_resolv_conf, ctx);
        if (te == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "tevent_add_timer failed. resolv.conf will be ignored.\n");
        }
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Monitor_config_file failed. resolv.conf will be ignored.\n");
    }
}

static int monitor_process_init(struct mt_ctx *ctx,
                                const char *config_file)
{
    TALLOC_CTX *tmp_ctx;
    struct tevent_signal *tes;
    struct timeval tv;
    struct tevent_timer *te;
    struct sss_domain_info *dom;
    char *rcachedir;
    int num_providers;
    int ret;
    int error;
    bool disable_netlink;
    struct sysdb_upgrade_ctx db_up_ctx;

    /* Set up the environment variable for the Kerberos Replay Cache */
    ret = confdb_get_string(ctx->cdb, ctx,
                            CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_KRB5_RCACHEDIR,
                            KRB5_RCACHE_DIR,
                            &rcachedir);
    if (ret != EOK) {
        return ret;
    }

    if (strcmp(rcachedir, KRB5_RCACHE_DIR_DISABLE) != 0)
    {
        errno = 0;
        ret = setenv("KRB5RCACHEDIR", rcachedir, 1);
        if (ret < 0) {
            error = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to set KRB5RCACHEDIR: %s."
                   "Will attempt to use libkrb5 defaults\n",
                   strerror(error));
        }
        talloc_zfree(rcachedir);
    }

    /* Set up an event handler for a SIGHUP */
    tes = tevent_add_signal(ctx->ev, ctx, SIGHUP, 0,
                            monitor_hup, ctx);
    if (tes == NULL) {
        return EIO;
    }

    /* Set up an event handler for a SIGINT */
    BlockSignals(false, SIGINT);
    tes = tevent_add_signal(ctx->ev, ctx, SIGINT, 0,
                            monitor_quit_signal, ctx);
    if (tes == NULL) {
        return EIO;
    }

    /* Set up an event handler for a SIGTERM */
    tes = tevent_add_signal(ctx->ev, ctx, SIGTERM, 0,
                            monitor_quit_signal, ctx);
    if (tes == NULL) {
        return EIO;
    }

    /* Handle SIGUSR1 (tell all providers to go offline) */
    BlockSignals(false, SIGUSR1);
    tes = tevent_add_signal(ctx->ev, ctx, SIGUSR1, 0,
                            signal_offline, ctx);
    if (tes == NULL) {
        return EIO;
    }

    /* Handle SIGUSR2 (tell all providers to go reset offline) */
    BlockSignals(false, SIGUSR2);
    tes = tevent_add_signal(ctx->ev, ctx, SIGUSR2, 0,
                            signal_offline_reset, ctx);
    if (tes == NULL) {
        return EIO;
    }

    /* Set up the SIGCHLD handler */
    ret = sss_sigchld_init(ctx, ctx->ev, &ctx->sigchld_ctx);
    if (ret != EOK) return ret;

    /* Watch for changes to the DNS resolv.conf */
    ret = monitor_config_file(ctx, ctx, monitor_update_resolv, RESOLV_CONF_PATH);
    if (ret == ENOENT) {
        tv = tevent_timeval_current_ofs(MISSING_RESOLV_CONF_POLL_TIME, 0);
        te = tevent_add_timer(ctx->ev, ctx, tv, missing_resolv_conf, ctx);
        if (te == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, "resolv.conf will be ignored\n");
        }
    } else if (ret != EOK) {
        return ret;
    }

    /* Avoid a startup race condition between process.
     * We need to handle DB upgrades or DB creation only
     * in one process before all other start.
     */
    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    db_up_ctx.cdb = ctx->cdb;
    ret = sysdb_init_ext(tmp_ctx, ctx->domains, &db_up_ctx,
                         true, ctx->uid, ctx->gid);
    if (ret != EOK) {
        SYSDB_VERSION_ERROR_DAEMON(ret);
        return ret;
    }
    talloc_zfree(tmp_ctx);

    /* Initialize D-BUS Server
     * The monitor will act as a D-BUS server for all
     * SSSD processes */
    ret = monitor_dbus_init(ctx);
    if (ret != EOK) {
        return ret;
    }

    ret = confdb_get_bool(ctx->cdb,
                          CONFDB_MONITOR_CONF_ENTRY,
                          CONFDB_MONITOR_DISABLE_NETLINK,
                          false, &disable_netlink);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read disable_netlink from confdb: [%d] %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    if (disable_netlink == false) {
        ret = setup_netlink(ctx, ctx->ev, network_status_change_cb,
                            ctx, &ctx->nlctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot set up listening for network notifications\n");
            return ret;
        }
    }

    /* start providers */
    num_providers = 0;
    for (dom = ctx->domains; dom; dom = get_next_domain(dom, 0)) {
        ret = add_new_provider(ctx, dom->name, 0);
        if (ret != EOK && ret != ENOENT) {
            return ret;
        }
        if (ret != ENOENT) {
            num_providers++;
        }
    }

    if (num_providers > 0) {
        /* now set the services stratup timeout *
         * (responders will be started automatically when all
         *  providers are up and running or when the tomeout
         *  expires) */
        ret = add_services_startup_timeout(ctx);
        if (ret != EOK) {
            return ret;
        }
    } else if (ctx->services != NULL) {
        int i;

        ctx->services_started = true;

        /* No providers start services immediately
         * Normally this means only LOCAL is configured */
        for (i = 0; ctx->services[i]; i++) {
            add_new_service(ctx, ctx->services[i], 0);
        }
    }

    /* When the only provider set up is the local one (num_providers == 0) and
     * there's no responder explicitly set up it means that we should notify
     * systemd that SSSD is ready right now as any other provider/responder
     * would be able to do so and the SSSD would end up hitting a systemd
     * timeout! */
    if (num_providers == 0 && ctx->services == NULL) {
        ret = notify_startup();
    }

    return EOK;
}

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr)
{
    struct mon_init_conn *mini;

    DEBUG(SSSDBG_OP_FAILURE, "Client timed out before Identification!\n");

    mini = talloc_get_type(ptr, struct mon_init_conn);

    sbus_disconnect(mini->conn);
    talloc_zfree(mini);
}

/*
 * monitor_service_init
 * Set up a timeout function and temporary connection structure.
 * If the client does not identify before the timeout kicks in,
 * the client is forcibly disconnected.
 */
static int monitor_service_init(struct sbus_connection *conn, void *data)
{
    struct mt_ctx *ctx;
    struct mon_init_conn *mini;
    struct timeval tv;

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing D-BUS Service\n");

    ctx = talloc_get_type(data, struct mt_ctx);

    mini = talloc(conn, struct mon_init_conn);
    if (!mini) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory?!\n");
        talloc_zfree(conn);
        return ENOMEM;
    }
    mini->ctx = ctx;
    mini->conn = conn;

    /* Allow access from the SSSD user */
    sbus_allow_uid(conn, &ctx->uid);

    /* 10 seconds should be plenty */
    tv = tevent_timeval_current_ofs(10, 0);

    mini->timeout = tevent_add_timer(ctx->ev, mini, tv, init_timeout, mini);
    if (!mini->timeout) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory?!\n");
        talloc_zfree(conn);
        return ENOMEM;
    }

    return sbus_conn_register_iface(conn, &monitor_methods.vtable,
                                    MON_SRV_PATH, mini);
}

/*
 * monitor_service_shutdown
 * Unregister the client when it's connection is finished.
 * Shuts down, from the monitor point of view, the service that just finished.
 */
static int monitor_service_shutdown(struct sbus_connection *conn, void *data)
{
    struct mt_ctx *ctx;
    struct mt_svc *svc;

    ctx = talloc_get_type(data, struct mt_ctx);

    for (svc = ctx->svc_list; svc != NULL; svc = svc->next) {
        if (svc->conn == conn) {
            break;
        }
    }

    if (svc != NULL) {
        /* We must decrease the number of services when shutting down
         * a {socket,dbus}-activted service. */
        ctx->num_services--;

        DEBUG(SSSDBG_TRACE_FUNC,
              "Unregistering service %s (%p)\n", svc->identity, svc);

        /* Before free'ing the service, let's unset the sbus_connection
         * destructor that triggered this call, otherwise we may end up
         * with a double-free due to a cycling call */
        talloc_set_destructor(svc->conn, NULL);

        talloc_zfree(svc);
    }

    return 0;
}

static void service_startup_handler(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval t, void *ptr);

static int start_service(struct mt_svc *svc)
{
    struct tevent_timer *te;
    struct timeval tv;

    DEBUG(SSSDBG_CONF_SETTINGS,"Queueing service %s for startup\n", svc->name);

    tv = tevent_timeval_current();

    /* Add a timed event to start up the service.
     * We have to do this in order to avoid a race
     * condition where the service being started forks
     * and attempts to connect to the SBUS before
     * the monitor is serving it.
     */
    te = tevent_add_timer(svc->mt_ctx->ev, svc, tv,
                          service_startup_handler, svc);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to queue service %s for startup\n", svc->name);
        return ENOMEM;
    }
    return EOK;
}

static void mt_svc_exit_handler(int pid, int wait_status, void *pvt);
static void service_startup_handler(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval t, void *ptr)
{
    errno_t ret;
    struct mt_svc *mt_svc;
    char **args;

    mt_svc = talloc_get_type(ptr, struct mt_svc);
    if (mt_svc == NULL) {
        return;
    }

    mt_svc->pid = fork();
    if (mt_svc->pid != 0) {
        if (mt_svc->pid == -1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Could not fork child to start service [%s]. "
                      "Continuing.\n", mt_svc->name);
            return;
        }

        /* Parent */
        mt_svc->mt_ctx->check_children = true;

        /* Handle process exit */
        ret = sss_child_register(mt_svc,
                                 mt_svc->mt_ctx->sigchld_ctx,
                                 mt_svc->pid,
                                 mt_svc_exit_handler,
                                 mt_svc,
                                 &mt_svc->child_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Could not register sigchld handler.\n");
            /* Should we exit here? For now, we'll hope this
             * child never dies, because we can't restart it.
             */
        }

        DLIST_ADD(mt_svc->mt_ctx->svc_list, mt_svc);

        return;
    }

    /* child */

    args = parse_args(mt_svc->command);
    execvp(args[0], args);

    /* If we are here, exec() has failed
     * Print errno and abort quickly */
    DEBUG(SSSDBG_FATAL_FAILURE,
          "Could not exec %s, reason: %s\n", mt_svc->command, strerror(errno));

    /* We have to call _exit() instead of exit() here
     * because a bug in D-BUS will cause the server to
     * close its socket at exit() */
    _exit(1);
}

static void mt_svc_restart(struct tevent_context *ev,
                           struct tevent_timer *te,
                           struct timeval t, void *ptr)
{
    struct mt_svc *svc;

    svc = talloc_get_type(ptr, struct mt_svc);
    if (svc == NULL) {
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Scheduling service %s for restart %d\n",
                              svc->name, svc->restarts+1);

    if (svc->type == MT_SVC_SERVICE) {
        add_new_service(svc->mt_ctx, svc->name, svc->restarts + 1);
    } else if (svc->type == MT_SVC_PROVIDER) {
        add_new_provider(svc->mt_ctx, svc->name, svc->restarts + 1);
    } else {
        /* Invalid type? */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "BUG: Invalid child process type [%d]\n", svc->type);
    }

    /* Free the old service (which will also remove it
     * from the child list)
     */
    talloc_free(svc);
}

static void mt_svc_exit_handler(int pid, int wait_status, void *pvt)
{
    struct mt_svc *svc = talloc_get_type(pvt, struct mt_svc);

    DEBUG(SSSDBG_TRACE_LIBS,
          "SIGCHLD handler of service %s called\n", svc->name);
    svc_child_info(svc, wait_status);

    /* Check the number of restart tries and relaunch the service */
    monitor_restart_service(svc);

    return;
}

static void monitor_restart_service(struct mt_svc *svc)
{
    struct mt_ctx *mt_ctx = svc->mt_ctx;
    int restart_delay;
    time_t now = time(NULL);
    struct tevent_timer *te;
    struct timeval tv;

    /* Handle the actual checks for how many times to restart this
     * service before giving up.
     */
    if ((now - svc->last_restart) > MONITOR_RESTART_CNT_INTERVAL_RESET) {
        svc->restarts = 0;
    }

    /* Restart the service */
    if (svc->restarts > MONITOR_MAX_SVC_RESTARTS) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Process [%s], definitely stopped!\n", svc->name);

        sss_log(SSS_LOG_ERR,
                "Exiting the SSSD. Could not restart critical service [%s].",
                svc->name);

        talloc_free(svc);

        /* exit the SSSD with an error, shutting down all
         * services and domains.
         * We do this because if one of the responders is down
         * and can't come back up, this is the only way to
         * guarantee admin intervention.
         */
        monitor_quit(mt_ctx, 1);
        return;
    }

    /* restarts are schedule after 0, 2, 4 seconds */
    restart_delay = svc->restarts << 1;
    if (restart_delay > MONITOR_MAX_RESTART_DELAY) {
        restart_delay = MONITOR_MAX_RESTART_DELAY;
    }

    tv = tevent_timeval_current_ofs(restart_delay, 0);
    te = tevent_add_timer(svc->mt_ctx->ev, svc, tv, mt_svc_restart, svc);
    if (te == NULL) {
        /* Nothing much we can do */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate timed event: mt_svc_restart.\n");
        talloc_free(svc);
        return;
    }
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_daemon = 0;
    int opt_interactive = 0;
    int opt_genconf = 0;
    int opt_version = 0;
    int opt_netlinkoff = 0;
    char *opt_config_file = NULL;
    char *config_file = NULL;
    int flags = 0;
    struct main_context *main_ctx;
    TALLOC_CTX *tmp_ctx;
    struct mt_ctx *monitor;
    int ret;
    uid_t uid;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        {"daemon", 'D', POPT_ARG_NONE, &opt_daemon, 0, \
         _("Become a daemon (default)"), NULL }, \
        {"interactive", 'i', POPT_ARG_NONE, &opt_interactive, 0, \
         _("Run interactive (not a daemon)"), NULL}, \
        {"disable-netlink", '\0', POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN,
            &opt_netlinkoff, 0, \
         _("Disable netlink interface"), NULL}, \
        {"config", 'c', POPT_ARG_STRING, &opt_config_file, 0, \
         _("Specify a non-default config file"), NULL}, \
        {"genconf", 'g', POPT_ARG_NONE, &opt_genconf, 0, \
         _("Refresh the configuration database, then exit"), \
         NULL}, \
        {"version", '\0', POPT_ARG_NONE, &opt_version, 0, \
         _("Print version number and exit"), NULL }, \
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    DEBUG_INIT(debug_level);

    if (opt_version) {
        puts(VERSION""PRERELEASE_VERSION);
        return EXIT_SUCCESS;
    }

    /* If the level or timestamps was passed at the command-line, we want
     * to save it and pass it to the children later.
     */
    cmdline_debug_level = debug_level;
    cmdline_debug_timestamps = debug_timestamps;
    cmdline_debug_microseconds = debug_microseconds;

    if (opt_daemon && opt_interactive) {
        fprintf(stderr, "Option -i|--interactive is not allowed together with -D|--daemon\n");
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }

    if (opt_genconf && (opt_daemon || opt_interactive)) {
        fprintf(stderr, "Option -g is incompatible with -D or -i\n");
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }

    if (!opt_daemon && !opt_interactive && !opt_genconf) {
        opt_daemon = 1;
    }

    poptFreeContext(pc);

    uid = getuid();
    if (uid != 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Running under %"SPRIuid", must be root\n", uid);
        sss_log(SSS_LOG_ALERT, "sssd must be run as root");
        return 8;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return 7;
    }

    if (opt_daemon) flags |= FLAGS_DAEMON;
    if (opt_interactive) {
        flags |= FLAGS_INTERACTIVE;
        debug_to_stderr = 1;
    }
    if (opt_genconf) {
        flags |= FLAGS_GEN_CONF;
        debug_to_stderr = 1;
    }

    if (opt_config_file) {
        config_file = talloc_strdup(tmp_ctx, opt_config_file);
    } else {
        config_file = talloc_strdup(tmp_ctx, SSSD_CONFIG_FILE);
    }

    if (opt_netlinkoff) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Option --disable-netlink has been removed and "
              "replaced as a monitor option in sssd.conf\n");
        sss_log(SSS_LOG_ALERT,
                "--disable-netlink has been deprecated, tunable option "
                "disable_netlink available as replacement(man sssd.conf)");
    }

    if (!config_file) {
        return 6;
    }

    /* the monitor should not run a watchdog on itself */
    flags |= FLAGS_NO_WATCHDOG;

    /* Open before server_setup() does to have logging
     * during configuration checking */
    if (debug_to_file) {
        ret = open_debug_file();
        if (ret) {
            return 7;
        }
    }

#ifdef USE_KEYRING
    /* Do this before all the forks, it sets the session key ring so all
     * keys are private to the daemon and cannot be read by any other process
     * tree */

    /* make a new session */
    ret = keyctl_join_session_keyring(NULL);
    if (ret == -1) {
        sss_log(SSS_LOG_ALERT,
                "Could not create private keyring session. "
                "If you store password there they may be easily accessible "
                "to the root user. (%d, %s)", errno, strerror(errno));
    }

    ret = keyctl_setperm(KEY_SPEC_SESSION_KEYRING, KEY_POS_ALL);
    if (ret == -1) {
        sss_log(SSS_LOG_ALERT,
                "Could not set permissions on private keyring. "
                "If you store password there they may be easily accessible "
                "to the root user. (%d, %s)", errno, strerror(errno));
    }
#endif

    /* Warn if nscd seems to be running */
    ret = check_file(NSCD_SOCKET_PATH,
                     -1, -1, S_IFSOCK, S_IFMT, NULL, false);
    if (ret == EOK) {
        ret = sss_nscd_parse_conf(NSCD_CONF_PATH);

        switch (ret) {
            case ENOENT:
                sss_log(SSS_LOG_NOTICE,
                        "NSCD socket was detected. NSCD caching capabilities "
                        "may conflict with SSSD for users and groups. It is "
                        "recommended not to run NSCD in parallel with SSSD, "
                        "unless NSCD is configured not to cache the passwd, "
                        "group, netgroup and services nsswitch maps.");
                break;

            case EEXIST:
                sss_log(SSS_LOG_NOTICE,
                        "NSCD socket was detected and seems to be configured "
                        "to cache some of the databases controlled by "
                        "SSSD [passwd,group,netgroup,services]. It is "
                        "recommended not to run NSCD in parallel with SSSD, "
                        "unless NSCD is configured not to cache these.");
                break;

            case EOK:
                DEBUG(SSSDBG_TRACE_FUNC, "NSCD socket was detected and it "
                            "seems to be configured not to interfere with "
                            "SSSD's caching capabilities\n");
        }
    }

    /* Check if the SSSD is already running */
    ret = check_file(SSSD_PIDFILE, 0, 0, S_IFREG|0600, 0, NULL, false);
    if (ret == EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "pidfile exists at %s\n", SSSD_PIDFILE);
        ERROR("SSSD is already running\n");
        return 2;
    }

    /* Parse config file, fail if cannot be done */
    ret = load_configuration(tmp_ctx, config_file, CONFDB_DEFAULT_CONFIG_DIR,
                             &monitor);
    if (ret != EOK) {
        switch (ret) {
        case EPERM:
        case EACCES:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  CONF_FILE_PERM_ERROR_MSG, config_file);
            sss_log(SSS_LOG_ALERT, CONF_FILE_PERM_ERROR_MSG, config_file);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                 "SSSD couldn't load the configuration database.\n");
            sss_log(SSS_LOG_ALERT,
                   "SSSD couldn't load the configuration database [%d]: %s.\n",
                    ret, strerror(ret));
            break;
        }
        return 4;
    }

    /* at this point we are done generating the config file, we may exit
     * if that's all we were asked to do */
    if (opt_genconf) return 0;

    /* set up things like debug , signals, daemonization, etc... */
    monitor->conf_path = CONFDB_MONITOR_CONF_ENTRY;
    ret = close(STDIN_FILENO);
    if (ret != EOK) return 6;

    ret = server_setup(MONITOR_NAME, flags, 0, 0,
                       monitor->conf_path, &main_ctx);
    if (ret != EOK) return 2;

    monitor->is_daemon = !opt_interactive;
    monitor->parent_pid = main_ctx->parent_pid;
    monitor->ev = main_ctx->event_ctx;
    talloc_steal(main_ctx, monitor);

    ret = monitor_process_init(monitor, config_file);

    if (ret != EOK) return 3;
    talloc_free(tmp_ctx);

    /* loop on main */
    server_loop(main_ctx);

    ret = monitor_cleanup();
    if (ret != EOK) return 5;

    return 0;
}
