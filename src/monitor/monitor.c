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

#include "config.h"
#include "util/util.h"
#include "util/child_common.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/param.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <popt.h>
#include <tevent.h>
#include <sys/prctl.h>

#include "util/sss_ini.h"
#include "confdb/confdb.h"
#include "confdb/confdb_setup.h"
#include "db/sysdb.h"
#include "sss_iface/sss_iface_async.h"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define MONITOR_VERSION 0x0001

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

/* Special value to leave the Kerberos Replay Cache set to use
 * the libkrb5 defaults
 */
#define KRB5_RCACHE_DIR_DISABLE "__LIBKRB5_DEFAULTS__"

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
    const char *busname;
    pid_t pid;

    bool svc_started;
    bool socket_activated; /* also used for dbus-activated services */

    int restarts;
    time_t last_restart;

    int debug_level;

    struct sss_child_ctx *child_ctx;
};

struct mt_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    struct sss_domain_info *domains;
    char **services;
    int num_services;
    int started_services;
    struct mt_svc *svc_list;
    bool check_children;
    bool services_started;
    struct sss_sigchild_ctx *sigchld_ctx;
    bool pid_file_created;
    bool is_daemon;
    pid_t parent_pid;

    struct sbus_server *sbus_server;
    struct sbus_connection *sbus_conn;

#ifdef BUILD_CONF_SERVICE_USER_SUPPORT
    /* User to switch to in run time */
    uid_t uid;
    gid_t gid;
#endif
};

static int start_service(struct mt_svc *mt_svc);

static void monitor_service_shutdown(struct mt_svc *svc);

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

static void monitor_quit(struct mt_ctx *mt_ctx, int ret);

static int add_svc_conn_spy(struct mt_svc *svc);

static int service_not_found(const char *svc_name,
                             struct mt_svc **_svc)
{
    DEBUG(SSSDBG_FATAL_FAILURE,
          "Unable to find peer [%s] in list of services, "
          "killing connection!\n", svc_name);

    *_svc = NULL;
    return ENOENT;
}

#ifdef HAVE_SYSTEMD
errno_t socket_activated_service_not_found(struct mt_ctx *mt_ctx,
                                           const char *svc_name,
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

    if (check_service(discard_const(svc_name)) != NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Invalid service %s\n", svc_name);
        return EINVAL;
    }

    mt_ctx->num_services++;

    ret = get_service_config(mt_ctx, svc_name, &svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to get the configuration for the service: %s\n",
              svc_name);
        return ret;
    }
    svc->restarts = 0;
    svc->socket_activated = true;

    DLIST_ADD(mt_ctx->svc_list, svc);

    *_svc = svc;
    return EOK;
}
#endif

static errno_t
get_service_in_the_list(struct mt_ctx *mt_ctx,
                        const char *svc_name,
                        bool is_provider,
                        struct mt_svc **_svc)
{
    struct mt_svc *svc;

    for (svc = mt_ctx->svc_list; svc != NULL; svc = svc->next) {
        if (strcasecmp(svc->identity, svc_name) == 0) {
            *_svc = svc;
            return EOK;
        }
    }

#ifdef HAVE_SYSTEMD
    return socket_activated_service_not_found(mt_ctx, svc_name, is_provider,
                                              _svc);
#else
    return service_not_found(svc_name, _svc);
#endif
}

static errno_t
monitor_sbus_RegisterService(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct mt_ctx *mt_ctx,
                             const char *name,
                             uint16_t version,
                             uint16_t type,
                             uint16_t *_monitor_version)
{
    struct mt_svc *svc;
    errno_t ret;

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Received ID registration: (%s,%d)\n", name, version);

    /* search this service in the list */
    ret = get_service_in_the_list(mt_ctx, name, type == MT_SVC_PROVIDER, &svc);
    if (ret != EOK) {
        return ERR_SBUS_KILL_CONNECTION;
    }

    svc->busname = talloc_strdup(svc, sbus_req->sender->name);
    if (svc->busname == NULL) {
        return ERR_SBUS_KILL_CONNECTION;
    }

    /* Fill in svc structure with connection data */
    svc->conn = sbus_server_find_connection(mt_ctx->sbus_server, svc->busname);
    if (svc->conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Bug: No connection found for '%s'\n", svc->busname);
        return ERR_SBUS_KILL_CONNECTION;
    }

    /* For {dbus,socket}-activated services we will have to unregister then
     * when the sbus_connection is freed. That's the reason we have to
     * hook up on its destructor function, do the service unregistration
     * from there and set the destructor back to NULL just before freeing
     * the service itself. */
    if (svc->socket_activated) {
        DEBUG(SSSDBG_TRACE_FUNC, "'%s' is a socket activated service\n", name);
        sbus_connection_set_destructor(svc->conn, monitor_service_shutdown, svc);
    }

    ret = mark_service_as_started(svc);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to mark service [%s]!\n", name);
        return ret;
    }

    *_monitor_version = MONITOR_VERSION;

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
    int exit_code = 0;
    int pid = svc->pid;
    const char *name = (svc->name ? svc->name : "");
    const char *identity = (svc->identity ? svc->identity : "");

    if (WIFEXITED(wait_status)) {
        exit_code = WEXITSTATUS(wait_status);
        if (exit_code == SSS_WATCHDOG_EXIT_CODE) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Child [%d] ('%s':'%s') was terminated by own WATCHDOG\n",
                  pid, name, identity);
            sss_log(SSS_LOG_CRIT,
                    "Child [%d] ('%s':'%s') was terminated by own WATCHDOG. "
                    "Consult corresponding logs to figure out the reason.",
                    pid, name, identity);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Child [%d] ('%s':'%s') exited with code [%d]\n",
                   pid, name, identity, exit_code);
        }
    } else if (WIFSIGNALED(wait_status)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Child [%d] ('%s':'%s') terminated with signal [%d]\n",
               pid, name, identity, WTERMSIG(wait_status));
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Child [%d] ('%s':'%s') did not exit cleanly\n",
              pid, name, identity);
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

    /* We need to attach a spy to the connection structure so that if some code
     * frees it we can zero it out in the service structure. Otherwise we may
     * try to access or even free, freed memory. */
    ret = add_svc_conn_spy(svc);
    if (ret) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to attach spy\n");
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
        ret = pidfile(SSSD_PIDFILE);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Error creating pidfile: %s! (%d [%s])\n",
                  SSSD_PIDFILE, ret, strerror(ret));
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

    if (ctx->services == NULL) {
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Handling timeout\n");

    if (!ctx->services_started) {
        /* This code is more a sanity guard: if any of providers
         * didn't start to this moment (MONITOR_MAX_SVC_RESTARTS),
         * `monitor_restart_service()` should already have process
         * terminated anyway.
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Providers did not start in time!\n");
        monitor_quit(ctx, 1);
    }
}

static int add_services_startup_timeout(struct mt_ctx *ctx)
{
    struct tevent_timer *to;
    struct timeval tv;

    /* 7 seconds should be enough to accommodate for
     * MONITOR_MAX_SVC_RESTARTS & MONITOR_MAX_RESTART_DELAY
     */
    tv = tevent_timeval_current_ofs(7, 0);
    to = tevent_add_timer(ctx->ev, ctx, tv, services_startup_timeout, ctx);
    if (!to) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory?!\n");
        return ENOMEM;
    }

    return EOK;
}

static void monitor_restart_service(struct mt_svc *svc);

typedef struct tevent_req *
(*service_signal_send_fn)(TALLOC_CTX *mem_ctx,
                          struct sbus_connection *conn,
                          const char *busname,
                          const char *object_path);

typedef errno_t
(*service_signal_recv_fn)(struct tevent_req *req);

static void service_signal_done(struct tevent_req *req);

static int service_signal(struct mt_svc *svc,
                          service_signal_send_fn send_fn,
                          service_signal_recv_fn recv_fn)
{
    struct sbus_connection *conn;
    struct tevent_req *req;

    conn = svc->mt_ctx->sbus_conn;

    if (!svc->conn) {
        /* Avoid a race condition where we are trying to
         * order a service to reload that hasn't started
         * yet.
         */
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Could not signal service [%s].\n", svc->name);
        return EIO;
    }

    req = send_fn(svc, conn, svc->busname, SSS_BUS_PATH);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, service_signal_done, recv_fn);

    return EOK;
}

static void service_signal_done(struct tevent_req *req)
{
    service_signal_recv_fn recv_fn;
    errno_t ret;

    recv_fn = tevent_req_callback_data_void(req);

    ret = recv_fn(req);
    talloc_zfree(req);

    if (ret == EOK) {
        return;
    }

    DEBUG(ret == ENOENT ? SSSDBG_MINOR_FAILURE : SSSDBG_OP_FAILURE,
          "Unable to signal service [%d]: %s\n", ret, sss_strerror(ret));
}

static int service_signal_offline(struct mt_svc *svc)
{
    return service_signal(svc, sbus_call_service_goOffline_send,
                          sbus_call_service_goOffline_recv);
}
static int service_signal_reset_offline(struct mt_svc *svc)
{
    return service_signal(svc, sbus_call_service_resetOffline_send,
                          sbus_call_service_resetOffline_recv);
}
static int service_signal_rotate(struct mt_svc *svc)
{
    return service_signal(svc, sbus_call_service_rotateLogs_send,
                          sbus_call_service_rotateLogs_recv);
}
static int service_signal_clear_memcache(struct mt_svc *svc)
{
    return service_signal(svc, sbus_call_service_clearMemcache_send,
                          sbus_call_service_clearMemcache_recv);
}
static int service_signal_clear_negcache(struct mt_svc *svc)
{
    return service_signal(svc, sbus_call_service_clearNegcache_send,
                          sbus_call_service_clearNegcache_recv);
}
static int service_signal_clear_enum_cache(struct mt_svc *svc)
{
    return service_signal(svc, sbus_call_service_clearEnumCache_send,
                          sbus_call_service_clearEnumCache_recv);
}
static int service_signal_sysbus_reconnect(struct mt_svc *svc)
{
    return service_signal(svc, sbus_call_service_sysbusReconnect_send,
                          sbus_call_service_sysbusReconnect_recv);
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
                DEBUG(SSSDBG_IMPORTANT_INFO,
                      "Domains '%s' and '%s' overlap in range %u - %u\n",
                      dom->name, other->name, id_min, id_max);
            }
            other = get_next_domain(other, 0);
        }
        dom = get_next_domain(dom, 0);
    }

    return EOK;
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

#ifdef BUILD_CONF_SERVICE_USER_SUPPORT
static int get_service_user(struct sss_ini *config, struct mt_ctx *ctx)
{
    errno_t ret = EOK;

    ctx->uid = 0;
    ctx->gid = 0;

/* If SSSD wasn't built '--with-sssd-user=sssd' then 'sssd.conf::user'
 * option isn't supported completely (no man page entry).
 */
#ifdef SSSD_NON_ROOT_USER
    char *user_str = NULL;

    ret = sss_ini_get_cfgobj(config, "sssd", CONFDB_MONITOR_USER_RUNAS);
    if (ret != 0) {
        ERROR("Config operation failed\n");
        return ret;
    }
    if (sss_ini_check_config_obj(config) == EOK) {
        user_str = sss_ini_get_string_config_value(config, NULL);
    }

    if (geteuid() != 0) {
        if (user_str != NULL) {
            sss_log(SSS_LOG_ALERT, "'"CONFDB_MONITOR_USER_RUNAS"' config option is "
                    "ignored when SSSD is run under non-root user initially.");
            ERROR("'"CONFDB_MONITOR_USER_RUNAS"' config option is "
                  "ignored when SSSD is run under non-root user initially.\n");
            free(user_str);
        }
        ctx->uid = geteuid();
        ctx->gid = getegid();
        return EOK;
    }

    if (user_str == NULL) {
        /* defaults to 'root' */
    } else if (strcmp(user_str, SSSD_USER) == 0) {
        sss_sssd_user_uid_and_gid(&ctx->uid, &ctx->gid);
        /* Deprecation warning is given in `bootstrap_monitor_process()` */
    } else if (strcmp(user_str, "root") != 0) {
        ERROR("Unsupported value '%s' of config option '%s'! Only 'root' or '"
              SSSD_USER"' are supported.\n",
              user_str, CONFDB_MONITOR_USER_RUNAS);
        sss_log(SSS_LOG_CRIT, "Unsupported value of config option '%s'!",
                CONFDB_MONITOR_USER_RUNAS);
        ret = ERR_INVALID_CONFIG;
    }

    free(user_str);
#endif /* SSSD_NON_ROOT_USER */

    return ret;
}
#endif /* BUILD_CONF_SERVICE_USER_SUPPORT */

static void get_debug_level(struct sss_ini *config)
{
    int ret;

    if (debug_level == SSSDBG_INVALID) {
        debug_level = SSSDBG_DEFAULT;
    }

    ret = sss_ini_get_cfgobj(config, "sssd", CONFDB_SERVICE_DEBUG_LEVEL);
    if (ret != 0) {
        return;
    }
    if (sss_ini_check_config_obj(config) != EOK) {
        ret = sss_ini_get_cfgobj(config, "sssd", CONFDB_SERVICE_DEBUG_LEVEL_ALIAS);
        if (ret != 0) {
            return;
        }
        if (sss_ini_check_config_obj(config) != EOK) {
            return;
        }
    }

    debug_level = sss_ini_get_int_config_value(config, 1, debug_level, NULL);
}

static int get_monitor_config(struct mt_ctx *ctx)
{
    int ret;
    char *badsrv = NULL;
    int i;

    ret = confdb_get_services_as_list(ctx->cdb, ctx,
                                      &ctx->services);
    if (ret != EOK) {
        return ret;
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

    /* Check UID/GID overlaps */
    ret = check_domain_ranges(ctx->domains);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static int get_service_config(struct mt_ctx *ctx, const char *name,
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get "CONFDB_SERVICE_COMMAND" for service '%s'\n",
              svc->name);
        talloc_free(svc);
        return ret;
    }

    if (!svc->command) {
        svc->command = talloc_asprintf(
            svc, "%s/sssd_%s", SSSD_LIBEXEC_PATH, svc->name
        );
        if (!svc->command) {
            talloc_free(svc);
            return ENOMEM;
        }

        if (cmdline_debug_level != SSSDBG_INVALID) {
            svc->command = talloc_asprintf_append(
                svc->command, " -d %#.5x", cmdline_debug_level
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

        svc->command = talloc_asprintf_append(
            svc->command, " --logger=%s", sss_logger_str[sss_logger]);
        if (!svc->command) {
            talloc_free(svc);
            return ENOMEM;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Formed command '%s' for service '%s'\n",
              svc->command, svc->name);
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Using custom command '%s' for service '%s'\n",
              svc->command, svc->name);
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

        if (cmdline_debug_level != SSSDBG_INVALID) {
            svc->command = talloc_asprintf_append(
                svc->command, " -d %#.5x", cmdline_debug_level
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

        svc->command = talloc_asprintf_append(
            svc->command, " --logger=%s", sss_logger_str[sss_logger]);
        if (!svc->command) {
            talloc_free(svc);
            return ENOMEM;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Formed command '%s' for provider '%s'\n",
              svc->command, svc->identity);
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Using custom command '%s' for provider '%s'\n",
              svc->command, svc->identity);
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

    DEBUG(SSSDBG_IMPORTANT_INFO, "Monitor received SIGHUP\n");

    /* Send D-Bus message to other services to rotate their logs.
     * NSS service receives also message to clear memory caches. */
    for(cur_svc = ctx->svc_list; cur_svc; cur_svc = cur_svc->next) {
        DEBUG(SSSDBG_TRACE_FUNC, "Log rotate triggered for: %s\n", cur_svc->name);
        service_signal_rotate(cur_svc);
        if (!strcmp(NSS_SBUS_SERVICE_NAME, cur_svc->name)) {
            DEBUG(SSSDBG_TRACE_FUNC, "NSS negcache cleaning\n");
            service_signal_clear_negcache(cur_svc);

            DEBUG(SSSDBG_TRACE_FUNC, "NSS memcache cleaning\n");
            service_signal_clear_memcache(cur_svc);

            DEBUG(SSSDBG_TRACE_FUNC, "NSS enum_cache cleaning\n");
            service_signal_clear_enum_cache(cur_svc);
        }

        if (!strcmp(SSS_AUTOFS_SBUS_SERVICE_NAME, cur_svc->name)) {
            DEBUG(SSSDBG_TRACE_FUNC, "AUTOFS enum_cache cleaning\n");
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

        killed = false;
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Terminating [%s][%d]\n", svc->name, svc->pid);
        do {
            errno = 0;
            kret = kill(-svc->pid, SIGTERM);
            if (kret < 0) {
                error = errno;
                DEBUG(SSSDBG_MINOR_FAILURE, "Couldn't terminate [%s][%d]: [%s]\n",
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
                        DEBUG(SSSDBG_IMPORTANT_INFO,
                              "[%d][%s] while waiting for [%s]\n",
                                  error, strerror(error), svc->name);
                        /* Forcibly kill this child */
                        kill(-svc->pid, SIGKILL);
                        break;
                    }
                } else if (pid != 0) {
                    error = 0;
                    if (WIFEXITED(status)) {
                        DEBUG(SSSDBG_IMPORTANT_INFO,
                              "Child [%s] exited gracefully\n", svc->name);
                    } else if (WIFSIGNALED(status)) {
                        DEBUG(SSSDBG_IMPORTANT_INFO,
                              "Child [%s] terminated with a signal\n", svc->name);
                    } else {
                        DEBUG(SSSDBG_IMPORTANT_INFO,
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
}

static int monitor_ctx_destructor(void *mem)
{
    struct mt_ctx *mon = talloc_get_type(mem, struct mt_ctx);
    struct mt_svc *svc;

    /* zero out references in SVCs so that they don't try
     * to access the monitor context on process shutdown */

    for (svc = mon->svc_list; svc; svc = svc->next) {
        svc->mt_ctx = NULL;
    }
    return 0;
}

static void monitor_sbus_connected(struct tevent_req *req);

static int monitor_process_init(struct mt_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    struct tevent_signal *tes;
    struct tevent_req *req;
    char *rcachedir;
    int ret;
    int error;
    struct sysdb_upgrade_ctx db_up_ctx;

    /* Set up the environment variable for the Kerberos Replay Cache */
    ret = confdb_get_string(ctx->cdb, ctx,
                            CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_KRB5_RCACHEDIR,
                            KRB5_RCACHE_DIR,
                            &rcachedir);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "confdb_get_string("CONFDB_MONITOR_KRB5_RCACHEDIR") failed\n");
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

    /* Avoid a startup race condition between process.
     * We need to handle DB upgrades or DB creation only
     * in one process before all other start.
     */
    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    db_up_ctx.cdb = ctx->cdb;
    ret = sysdb_init_ext(tmp_ctx, ctx->domains, true, &db_up_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "sysdb_init_ext() failed: '%s'\n", sss_strerror(ret));
        SYSDB_VERSION_ERROR_DAEMON(ret);
        goto done;
    }
    talloc_zfree(tmp_ctx);

    req = sbus_server_create_and_connect_send(ctx, ctx->ev, SSS_BUS_MONITOR,
                                              NULL, SSS_BUS_ADDRESS,
                                              false, 100, NULL, NULL);
    if (req == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "sbus_server_create_and_connect_send() failed\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, monitor_sbus_connected, ctx);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static void monitor_sbus_connected(struct tevent_req *req)
{
    struct mt_ctx *ctx;
    struct sss_domain_info *dom;
    int num_providers;
    errno_t ret;

    ctx = tevent_req_callback_data(req, struct mt_ctx);

    ret = sbus_server_create_and_connect_recv(ctx, req,
                                              &ctx->sbus_server,
                                              &ctx->sbus_conn);
    talloc_zfree(req);
    if (ret !=  EOK) {
        goto done;
    }

    SBUS_INTERFACE(iface_monitor,
        sssd_monitor,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_monitor, RegisterService, monitor_sbus_RegisterService, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_NO_PROPERTIES)
    );
    SBUS_INTERFACE(iface_service,
        sssd_service,
        SBUS_METHODS(SBUS_NO_METHODS),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, sssd_service, debug_level, generic_get_debug_level, NULL),
            SBUS_SYNC(SETTER, sssd_service, debug_level, generic_set_debug_level, NULL)
        )
    );

    struct sbus_path paths[] = {
        {SSS_BUS_PATH, &iface_monitor},
        {SSS_BUS_PATH, &iface_service},
        {NULL, NULL}
    };

    ret = sbus_connection_add_path_map(ctx->sbus_conn, paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to add paths [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* start providers */
    num_providers = 0;
    for (dom = ctx->domains; dom; dom = get_next_domain(dom, 0)) {
        ret = add_new_provider(ctx, dom->name, 0);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }
        if (ret != ENOENT) {
            num_providers++;
        }
    }

    if (num_providers > 0) {
        /* now set the services startup timeout *
         * (responders will be started automatically when all
         *  providers are up and running or when the timeout
         *  expires) */
        ret = add_services_startup_timeout(ctx);
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE, "No providers configured.\n");
        ret = ERR_INVALID_CONFIG;
    }

done:
    if (ret != EOK) {
        monitor_quit(ctx, 3);
    }
}

/*
 * monitor_service_shutdown
 * Unregister the client when it's connection is finished.
 * Shuts down, from the monitor point of view, the service that just finished.
 */
static void monitor_service_shutdown(struct mt_svc *svc)
{
    struct mt_ctx *ctx = svc->mt_ctx;

    /* We must decrease the number of services when shutting down
     * a {socket,dbus}-activated service. */
    if (ctx != NULL) ctx->num_services--;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Unregistering service %s (%p)\n", svc->identity, svc);

    talloc_zfree(svc);
}

static void service_startup_handler(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval t, void *ptr);

static int start_service(struct mt_svc *svc)
{
    struct tevent_timer *te;
    struct timeval tv;

    DEBUG(SSSDBG_CONF_SETTINGS,"Queueing service %s for startup\n", svc->name);

    svc->socket_activated = false;

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
    if ((mt_svc->type != MT_SVC_PROVIDER) &&
        ((mt_svc->name == NULL) || (strcmp(mt_svc->name, "pam") != 0))) {
        /* Providers are excluded because they will need to execute
         * child processes that elevate privs.
         * 'sssd_pam' is excluded because it need to use 'cap_dac_read_search'
         * to call `gss_acquire_cred_from()`/`gss_accept_sec_context()`
         * that accesses a keytab.
         */
        ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if (ret == -1) {
            DEBUG(SSSDBG_FATAL_FAILURE, "prctl(PR_SET_NO_NEW_PRIVS) failed: '%s'\n",
                  strerror(errno));
            _exit(1);
        }
    }

    args = parse_args(mt_svc->command);
    execvp(args[0], args);

    /* If we are here, exec() has failed
     * Print errno and abort quickly */
    DEBUG(SSSDBG_FATAL_FAILURE,
          "Could not exec %s, reason: %s\n", mt_svc->command, strerror(errno));

    /* Also log to syslog since SSSD failed to start. */
    sss_log(SSS_LOG_ERR, "Could not exec %s, reason: %s",
            mt_svc->command, strerror(errno));

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
        DEBUG(SSSDBG_FATAL_FAILURE,
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

/* from nscd.c */
void check_nscd(void);

#ifdef BUILD_CONF_SERVICE_USER_SUPPORT
int bootstrap_monitor_process(uid_t target_uid, gid_t target_gid);
#else
int bootstrap_monitor_process(void);
#endif

void setup_keyring(void);

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_daemon = 0;
    int opt_interactive = 0;
    int opt_version = 0;
    char *opt_config_file = NULL;
    const char *opt_logger = NULL;
    char *config_file = NULL;
    int flags = FLAGS_NO_WATCHDOG;
    struct main_context *main_ctx;
    TALLOC_CTX *tmp_ctx;
    struct mt_ctx *monitor;
    int ret;
    uid_t uid, euid;
    gid_t gid, egid;
    char *initial_caps;
    struct sss_ini *config;
    char *cdb_file = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = 2;
        goto out;
    }
    monitor = talloc_zero(tmp_ctx, struct mt_ctx);
    if (monitor == NULL) {
        ret = 2;
        goto out;
    }
    talloc_set_destructor((TALLOC_CTX *)monitor, monitor_ctx_destructor);

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
        SSSD_CONFIG_OPTS(opt_config_file)
        {"daemon", 'D', POPT_ARG_NONE, &opt_daemon, 0,
         _("Become a daemon (default)"), NULL },
        {"interactive", 'i', POPT_ARG_NONE, &opt_interactive, 0,
         _("Run interactive (not a daemon)"), NULL},
        {"version", '\0', POPT_ARG_NONE, &opt_version, 0,
         _("Print version number and exit"), NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            ERROR("\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            ret = 1;
            goto out;
        }
    }

    if (opt_version) {
        puts(VERSION""PRERELEASE_VERSION);
        ret = EXIT_SUCCESS;
        goto out;
    }

    /* If the level or timestamps was passed at the command-line, we want
     * to save it and pass it to the children later.
     */
    cmdline_debug_level = debug_level;
    cmdline_debug_timestamps = debug_timestamps;
    cmdline_debug_microseconds = debug_microseconds;

    if (opt_daemon && opt_interactive) {
        ERROR("Option -i|--interactive is not allowed together with -D|--daemon\n");
        poptPrintUsage(pc, stderr, 0);
        ret = 1;
        goto out;
    }

    if (!opt_daemon && !opt_interactive) {
        opt_daemon = 1;
    }
    if (opt_daemon) {
        flags |= FLAGS_DAEMON;
    } else if (opt_interactive) {
        flags |= FLAGS_INTERACTIVE;
        if (!opt_logger) {
            opt_logger = sss_logger_str[STDERR_LOGGER];
        }
    }

    if (opt_config_file) {
        config_file = talloc_strdup(tmp_ctx, opt_config_file);
    } else {
        config_file = talloc_strdup(tmp_ctx, SSSD_CONFIG_FILE);
    }
    if (config_file == NULL) {
        ret = 2;
        goto out;
    }

    cdb_file = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (cdb_file == NULL) {
        ret = 2;
        goto out;
    }

    poptFreeContext(pc);

    uid = getuid();
    euid = geteuid();
    gid = getgid();
    egid = getegid();
    ret = sss_log_caps_to_str(true, &initial_caps);
    if (ret != 0) {
        ERROR("Failed to get initial capabilities\n");
        ret = 3;
        goto out;
    }

#ifndef SSSD_NON_ROOT_USER
    /* Non-root service user support isn't built. */
    /* SSSD should run under root */
    if ((euid != 0) || (egid != 0)) {
        sss_log(SSS_LOG_ALERT, "Non-root service user support isn't built. "
                "Can't run under non-root");
        ERROR("Non-root service user support isn't built. "
              "Can't run under %"SPRIuid":%"SPRIgid"\n", euid, egid);
        ret = 1;
        goto out;
    }
    /* Everything is root:root owned. No caps required. */
    if (initial_caps != NULL) {
        sss_log(SSS_LOG_ALERT,
                "Those capabilities aren't needed and can be removed:\n %s",
                initial_caps);
    }
#endif /* !SSSD_NON_ROOT_USER */

    /* read/parse configuration (but don't save yet) */
    ret = confdb_read_ini(tmp_ctx, config_file, CONFDB_DEFAULT_CONFIG_DIR, false,
                          &config);
    if (ret != EOK) {
        ERROR("Can't read config: '%s'\n", sss_strerror(ret));
        sss_log(SSS_LOG_ALERT,
                "Failed to read configuration: '%s'", sss_strerror(ret));
        ret = 3;
        goto out;
    }

#ifdef BUILD_CONF_SERVICE_USER_SUPPORT
    ret = get_service_user(config, monitor);
    if (ret != EOK) {
        ret = 4; /* Error message already logged */
        goto out;
    }

    ret = bootstrap_monitor_process(monitor->uid, monitor->gid);
#else
    ret = bootstrap_monitor_process();
#endif
    if (ret != 0) {
        ERROR("Failed to boostrap SSSD 'monitor' process: %s", sss_strerror(ret));
        sss_log(SSS_LOG_ALERT, "Failed to boostrap SSSD 'monitor' process.");
        ret = 5;
        goto out;
    }

    get_debug_level(config);
    DEBUG_INIT(debug_level, opt_logger); /* use default value of 'debug_prg_name' */

    DEBUG(SSSDBG_IMPORTANT_INFO,
          "Started under uid=%"SPRIuid" (euid=%"SPRIuid") : "
          "gid=%"SPRIgid" (egid=%"SPRIgid") with SECBIT_KEEP_CAPS = %d"
          " and following capabilities:\n%s",
          uid, euid, gid, egid, prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0),
          initial_caps ? initial_caps : "   (nothing)\n");
    talloc_free(initial_caps);

    sss_ini_call_validators(config, SSSDDATADIR"/cfg_rules.ini");

    setup_keyring();

    /* Check if the SSSD is already running */
    ret = check_file(SSSD_PIDFILE, 0, 0, S_IFREG|0600, 0, NULL, false);
    if (ret == EOK) {
        ret = check_pidfile(SSSD_PIDFILE);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "SSSD is already running: pidfile exists at '"SSSD_PIDFILE"'\n");
            ret = 6;
            goto out;
        }
    }

    check_nscd();

    /* set up things like debug, signals, daemonization, etc. */
    ret = close(STDIN_FILENO);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to close stdin [%d]\n", errno);
        ret = 7;
        goto out;
    }

    ret = confdb_write_ini(tmp_ctx, config, cdb_file, false, false, &monitor->cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to write config DB: '%s'\n", sss_strerror(ret));
        ret = 8;
        goto out;
    }

    /* Use confdb initialized in server_setup. ldb_tdb module (1.4.0) check PID
     * of process which initialized db for locking purposes.
     * Failed to unlock db: ../ldb_tdb/ldb_tdb.c:147:
     *    Reusing ldb opened by pid 28889 in process 28893
     */
    talloc_zfree(monitor->cdb);

    ret = server_setup(SSSD_MONITOR_NAME, false, flags, CONFDB_FILE,
                       CONFDB_MONITOR_CONF_ENTRY, &main_ctx, false);
    if (ret != EOK) {
        ret = 9; /* Error message should be already logged */
        goto out;
    }

    monitor->cdb = main_ctx->confdb_ctx;
    ret = get_monitor_config(monitor);
    if (ret != EOK) {
        ret = 1;
        goto out;
    }
    monitor->is_daemon = !opt_interactive;
    monitor->parent_pid = main_ctx->parent_pid;
    monitor->ev = main_ctx->event_ctx;
    talloc_steal(main_ctx, monitor);

    ret = monitor_process_init(monitor);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "monitor_process_init() failed: '%s'\n", sss_strerror(ret));
        ret = 10;
        goto out;
    }

    talloc_free(tmp_ctx);

    /* loop on main */
    server_loop(main_ctx);

    ret = monitor_cleanup();
    if (ret != EOK) return 12;

    return 0;

out:
    talloc_free(tmp_ctx);
    if (ret == 2) {
        ERROR("Out of memory\n");
    }
    return ret;
}
