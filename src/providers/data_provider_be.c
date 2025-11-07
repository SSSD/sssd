/*
   SSSD

   Data Provider Process

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <dlfcn.h>
#include <popt.h>
#include <signal.h>

#include <resolv.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_utf8.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "providers/backend.h"
#include "providers/fail_over.h"
#include "providers/be_refresh.h"
#include "providers/be_ptask.h"
#include "util/file_watch.h"
#include "resolv/async_resolv.h"
#include "sss_iface/sss_iface_async.h"

#define RESOLV_CONF_PATH "/etc/resolv.conf"

#define ONLINE_CB_RETRY 3
#define ONLINE_CB_RETRY_MAX_DELAY 4

#define OFFLINE_TIMEOUT_RANDOM_OFFSET_DEFAULT 30
#define OFFLINE_TIMEOUT_DEFAULT 60
#define OFFLINE_TIMEOUT_MAX_DEFAULT 3600

/* sssd.service */
static errno_t
data_provider_go_offline(TALLOC_CTX *mem_ctx,
                         struct sbus_request *sbus_req,
                         struct be_ctx *be_ctx);

static errno_t
data_provider_reset_offline(TALLOC_CTX *mem_ctx,
                            struct sbus_request *sbus_req,
                            struct be_ctx *be_ctx);

static errno_t
data_provider_logrotate(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct be_ctx *be_ctx);

bool be_is_offline(struct be_ctx *ctx)
{
    return ctx->offline;
}

static void check_if_online(struct be_ctx *be_ctx, int delay);

static errno_t
try_to_go_online(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 struct be_ctx *be_ctx,
                 struct be_ptask *be_ptask,
                 void *be_ctx_void)
{
    struct be_ctx *ctx = (struct be_ctx*) be_ctx_void;

    check_if_online(ctx, 0);
    return EOK;
}

static int get_offline_timeout(struct be_ctx *ctx)
{
    errno_t ret;
    int offline_timeout;

    ret = confdb_get_int(ctx->cdb, ctx->conf_path,
                         CONFDB_DOMAIN_OFFLINE_TIMEOUT,
                         OFFLINE_TIMEOUT_DEFAULT,
                         &offline_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get offline_timeout from confdb. "
              "Will use %d seconds.\n", OFFLINE_TIMEOUT_DEFAULT);
        offline_timeout = OFFLINE_TIMEOUT_DEFAULT;
    }

    return offline_timeout;
}

static int get_offline_timeout_max(struct be_ctx *ctx)
{
    int offline_timeout_max;
    errno_t ret;

    ret = confdb_get_int(ctx->cdb, ctx->conf_path,
                         CONFDB_DOMAIN_OFFLINE_TIMEOUT_MAX,
                         OFFLINE_TIMEOUT_MAX_DEFAULT,
                         &offline_timeout_max);
    if (ret != EOK) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Failed to get offline_timeout_max from confdb. "
              "Will use %d seconds.\n", OFFLINE_TIMEOUT_MAX_DEFAULT);
        offline_timeout_max = OFFLINE_TIMEOUT_MAX_DEFAULT;
    }

    return offline_timeout_max;
}

static int get_offline_timeout_random_offset(struct be_ctx *ctx)
{
    int offline_timeout_random_offset;
    errno_t ret;

    ret = confdb_get_int(ctx->cdb, ctx->conf_path,
                         CONFDB_DOMAIN_OFFLINE_TIMEOUT_RANDOM_OFFSET,
                         OFFLINE_TIMEOUT_RANDOM_OFFSET_DEFAULT,
                         &offline_timeout_random_offset);
    if (ret != EOK) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Failed to get refresh_max_random_offset from confdb. "
              "Will use %d seconds.\n", OFFLINE_TIMEOUT_RANDOM_OFFSET_DEFAULT);
        offline_timeout_random_offset = OFFLINE_TIMEOUT_RANDOM_OFFSET_DEFAULT;
    }

    return offline_timeout_random_offset;
}

void be_mark_offline(struct be_ctx *ctx)
{
    int offline_timeout;
    int offline_timeout_max;
    int offline_timeout_random_offset;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Going offline!\n");

    ctx->offline = true;
    ctx->run_online_cb = true;

    if (ctx->check_if_online_ptask == NULL) {
        /* This is the first time we go offline - create a periodic task
         * to check if we can switch to online. */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Initialize check_if_online_ptask.\n");

        offline_timeout = get_offline_timeout(ctx);
        offline_timeout_max = get_offline_timeout_max(ctx);
        offline_timeout_random_offset = get_offline_timeout_random_offset(ctx);

        ret = be_ptask_create_sync(ctx,
                                   ctx,
                                   offline_timeout,
                                   offline_timeout,
                                   offline_timeout,
                                   offline_timeout_random_offset,
                                   offline_timeout,
                                   offline_timeout_max,
                                   try_to_go_online,
                                   ctx, "Check if online (periodic)",
                                   BE_PTASK_OFFLINE_EXECUTE,
                                   &ctx->check_if_online_ptask);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "be_ptask_create_sync failed [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
    } else {
        /* Periodic task was already created. Just enable it. */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Enable check_if_online_ptask.\n");
        be_ptask_enable(ctx->check_if_online_ptask);
    }

    be_run_offline_cb(ctx);
}

static void be_subdom_reset_status(struct tevent_context *ev,
                                  struct tevent_timer *te,
                                  struct timeval current_time,
                                  void *pvt)
{
    struct sss_domain_info *subdom = talloc_get_type(pvt,
                                                     struct sss_domain_info);

    DEBUG(SSSDBG_TRACE_LIBS, "Resetting subdomain %s\n", subdom->name);
    subdom->state = DOM_ACTIVE;
}

static void be_mark_subdom_offline(struct sss_domain_info *subdom,
                                   struct be_ctx *be_ctx)
{
    struct timeval tv;
    struct tevent_timer *timeout = NULL;
    int reset_status_timeout;

    reset_status_timeout = get_offline_timeout(be_ctx);
    tv = tevent_timeval_current_ofs(reset_status_timeout, 0);

    switch (subdom->state) {
    case DOM_DISABLED:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Won't touch disabled subdomain\n");
        return;
    case DOM_INACTIVE:
        DEBUG(SSSDBG_TRACE_ALL, "Subdomain already inactive\n");
        return;
    case DOM_ACTIVE:
        DEBUG(SSSDBG_TRACE_LIBS,
              "Marking subdomain %s as inactive\n", subdom->name);
        break;
    }

    timeout = tevent_add_timer(be_ctx->ev, be_ctx, tv,
                               be_subdom_reset_status, subdom);
    if (timeout == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot create timer\n");
        return;
    }

    subdom->state = DOM_INACTIVE;
}

void be_mark_dom_offline(struct sss_domain_info *dom, struct be_ctx *ctx)
{
    if (IS_SUBDOMAIN(dom) == false) {
        DEBUG(SSSDBG_TRACE_LIBS, "Marking back end offline\n");
        be_mark_offline(ctx);
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "Marking subdomain %s offline\n", dom->name);
        be_mark_subdom_offline(dom, ctx);
    }
}

static void reactivate_subdoms(struct sss_domain_info *head)
{
    struct sss_domain_info *dom;

    DEBUG(SSSDBG_TRACE_LIBS, "Resetting all subdomains\n");

    for (dom = head; dom; dom = get_next_domain(dom, true)) {
        if (sss_domain_get_state(dom) == DOM_INACTIVE) {
            sss_domain_set_state(dom, DOM_ACTIVE);
        }
    }
}

static void be_reset_offline(struct be_ctx *ctx)
{
    ctx->offline = false;
    ctx->run_offline_cb = true;

    reactivate_subdoms(ctx->domain);

    be_ptask_disable(ctx->check_if_online_ptask);
    be_run_online_cb(ctx);
}

static void be_check_online_done(struct tevent_req *req);

static errno_t be_check_online_request(struct be_ctx *be_ctx)
{
    struct tevent_req *req;

    reset_fo(be_ctx);

    req = dp_req_send(be_ctx, be_ctx->provider, NULL, "Online Check",
                      0, NULL, DPT_ID, DPM_CHECK_ONLINE, 0, NULL, NULL);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, be_check_online_done, be_ctx);

    return EOK;
}

static void check_if_online_delayed(struct tevent_context *ev,
                                    struct tevent_timer *tim,
                                    struct timeval current_time,
                                    void *private_data)
{
    errno_t ret;
    struct be_ctx *be_ctx = talloc_get_type(private_data, struct be_ctx);

    be_run_unconditional_online_cb(be_ctx);

    if (!be_is_offline(be_ctx)) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Backend is already online, nothing to do.\n");
        be_ctx->check_online_ref_count = 0;
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Trying to go back online!\n");

    ret = be_check_online_request(be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create check online req.\n");
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Check online req created.\n");
    }
}

static void be_check_online_done(struct tevent_req *req)
{
    struct be_ctx *be_ctx;
    struct dp_reply_std *reply;
    struct tevent_timer *time_event;
    struct timeval schedule;
    errno_t ret;

    be_ctx = tevent_req_callback_data(req, struct be_ctx);

    ret = dp_req_recv_ptr(be_ctx, req, struct dp_reply_std, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        reply = NULL;
        goto done;
    }

    switch (reply->dp_error) {
    case DP_ERR_OK:
        if (be_ctx->last_dp_state != DP_ERR_OK) {
            be_ctx->last_dp_state = DP_ERR_OK;
            sss_log(SSS_LOG_INFO, "Backend is online\n");
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Backend is online\n");
        break;
    case DP_ERR_OFFLINE:
        if (be_ctx->last_dp_state != DP_ERR_OFFLINE) {
            be_ctx->last_dp_state = DP_ERR_OFFLINE;
            sss_log(SSS_LOG_INFO, "Backend is offline\n");
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Backend is offline\n");
        break;
    default:
        DEBUG(SSSDBG_TRACE_FUNC, "Error during online check [%d]: %s\n",
              ret, sss_strerror(ret));
        break;
    }

    be_ctx->check_online_ref_count--;

    if (reply->dp_error != DP_ERR_OK && be_ctx->check_online_ref_count > 0) {
        be_ctx->check_online_retry_delay *= 2;
        if (be_ctx->check_online_retry_delay > ONLINE_CB_RETRY_MAX_DELAY) {
            be_ctx->check_online_retry_delay = ONLINE_CB_RETRY_MAX_DELAY;
        }

        schedule = tevent_timeval_current_ofs(be_ctx->check_online_retry_delay,
                                              0);
        time_event = tevent_add_timer(be_ctx->ev, be_ctx, schedule,
                                      check_if_online_delayed, be_ctx);

        if (time_event == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to schedule online check\n");
            goto done;
        }

        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Schedule check_if_online_delayed in %ds.\n",
              be_ctx->check_online_retry_delay);
        return;
    }

done:
    be_ctx->check_online_ref_count = 0;
    if (reply && reply->dp_error != DP_ERR_OFFLINE) {
        if (reply->dp_error != DP_ERR_OK) {
            reset_fo(be_ctx);
        }
        be_reset_offline(be_ctx);
    }
}

static void check_if_online(struct be_ctx *be_ctx, int delay)
{
    struct tevent_timer *time_event;
    struct timeval schedule;

    be_ctx->check_online_ref_count++;

    if (be_ctx->check_online_ref_count != 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "There is an online check already running.\n");
        /* Do not have more than ONLINE_CB_RETRY retries in the queue */
        if (be_ctx->check_online_ref_count > ONLINE_CB_RETRY) {
            be_ctx->check_online_ref_count--;
        }
        return;
    }

    if (!dp_method_enabled(be_ctx->provider, DPT_ID, DPM_CHECK_ONLINE)) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "ID providers does not provide a check_online method.\n");
        goto failed;
    }

    schedule = tevent_timeval_current_ofs(delay, 0);
    time_event = tevent_add_timer(be_ctx->ev, be_ctx, schedule,
                                  check_if_online_delayed, be_ctx);

    if (time_event == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Scheduling check_if_online_delayed failed.\n");
        goto failed;
    }

    be_ctx->check_online_ref_count = ONLINE_CB_RETRY;
    be_ctx->check_online_retry_delay = 1;
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Schedule check_if_online_delayed in %ds.\n", delay);
    return;

failed:
    be_ctx->check_online_ref_count--;

    if (be_ctx->check_online_ref_count == 0) {
        reset_fo(be_ctx);
        be_reset_offline(be_ctx);
    }

    return;
}

static void signal_be_offline(struct tevent_context *ev,
                              struct tevent_signal *se,
                              int signum,
                              int count,
                              void *siginfo,
                              void *private_data)
{
    struct be_ctx *ctx = talloc_get_type(private_data, struct be_ctx);
    be_mark_offline(ctx);
}

static void signal_be_reset_offline(struct tevent_context *ev,
                                    struct tevent_signal *se,
                                    int signum,
                                    int count,
                                    void *siginfo,
                                    void *private_data)
{
    struct be_ctx *ctx = talloc_get_type(private_data, struct be_ctx);
    check_if_online(ctx, 0);
}

static void signal_be_reschedule_tasks(struct tevent_context *ev,
                                       struct tevent_signal *se,
                                       int signum,
                                       int count,
                                       void *siginfo,
                                       void *private_data)
{
    struct be_ctx *ctx = talloc_get_type(private_data, struct be_ctx);
    be_ptask_postpone_all(ctx);
}

static void watch_update_resolv(const char *filename, void *arg)
{
    int ret;
    struct be_ctx *be_ctx = (struct be_ctx *) arg;

    DEBUG(SSSDBG_TRACE_FUNC, "Reloading %s.\n", filename);
    resolv_reread_configuration(be_ctx->be_res->resolv);
    ret = res_init();
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to reload %s.\n", filename);
        return;
    }
    check_if_online(be_ctx, 1);
}

static int watch_config_files(struct be_ctx *ctx)
{
    int ret;
    bool monitor_resolv_conf;
    bool use_inotify;

    /* Watch for changes to the DNS resolv.conf */
    ret = confdb_get_bool(ctx->cdb,
                          CONFDB_MONITOR_CONF_ENTRY,
                          CONFDB_MONITOR_RESOLV_CONF,
                          true, &monitor_resolv_conf);
    if (ret != EOK) {
        return ret;
    }

    ret = confdb_get_bool(ctx->cdb,
                          CONFDB_MONITOR_CONF_ENTRY,
                          CONFDB_MONITOR_TRY_INOTIFY,
                          true, &use_inotify);
    if (ret != EOK) {
        return ret;
    }

    if (monitor_resolv_conf) {
        ctx->file_ctx = fw_watch_file(ctx, ctx->ev, RESOLV_CONF_PATH,
                                      use_inotify, watch_update_resolv, ctx);
        if (ctx->file_ctx == NULL) {
            return ENOMEM;
        }

    } else {
        DEBUG(SSS_LOG_NOTICE, "%s watching is disabled\n", RESOLV_CONF_PATH);
    }

    return EOK;
}

static void network_status_change_cb(void *cb_data)
{
    struct be_ctx *ctx = (struct be_ctx *) cb_data;

    check_if_online(ctx, 1);
}


static int watch_netlink(struct be_ctx *ctx)
{
    int ret;
    bool disable_netlink;

    ret = confdb_get_bool(ctx->cdb,
                          CONFDB_MONITOR_CONF_ENTRY,
                          CONFDB_MONITOR_DISABLE_NETLINK,
                          false, &disable_netlink);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read %s from confdb: [%d] %s\n",
              CONFDB_MONITOR_DISABLE_NETLINK,
              ret, sss_strerror(ret));
        return ret;
    }


    if (disable_netlink) {
        DEBUG(SSS_LOG_NOTICE, "Netlink watching is disabled\n");
    } else {
        ret = netlink_watch(ctx, ctx->ev, network_status_change_cb,
                            ctx, &ctx->nlctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to set up listener for network status changes\n");
            return ret;
        }
    }

    return EOK;
}

static errno_t
be_register_monitor_iface(struct sbus_connection *conn, struct be_ctx *be_ctx)
{
    SBUS_INTERFACE(iface_service,
        sssd_service,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_service, goOffline, data_provider_go_offline, be_ctx),
            SBUS_SYNC(METHOD, sssd_service, resetOffline, data_provider_reset_offline, be_ctx),
            SBUS_SYNC(METHOD, sssd_service, rotateLogs, data_provider_logrotate, be_ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, sssd_service, debug_level, generic_get_debug_level, NULL),
            SBUS_SYNC(SETTER, sssd_service, debug_level, generic_set_debug_level, NULL)
        )
    );

    struct sbus_path paths[] = {
        {SSS_BUS_PATH, &iface_service},
        {NULL, NULL}
    };

    return sbus_connection_add_path_map(conn, paths);
}

errno_t be_process_init(TALLOC_CTX *mem_ctx,
                        const char *be_domain,
                        struct tevent_context *ev,
                        struct confdb_ctx *cdb)
{
    struct tevent_signal *tes;
    struct be_ctx *be_ctx;
    char *str = NULL;
    errno_t ret;

    be_ctx = talloc_zero(mem_ctx, struct be_ctx);
    if (be_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    be_ctx->ev = ev;
    be_ctx->cdb = cdb;
    be_ctx->identity = talloc_asprintf(be_ctx, "%%BE_%s", be_domain);
    be_ctx->conf_path = talloc_asprintf(be_ctx, CONFDB_DOMAIN_PATH_TMPL, be_domain);
    if (be_ctx->identity == NULL || be_ctx->conf_path == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!?\n");
        ret = ENOMEM;
        goto done;
    }
    be_ctx->last_dp_state = -1;

    ret = be_init_failover(be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize failover\n");
        goto done;
    }

    ret = sssd_domain_init(be_ctx, cdb, be_domain, DB_PATH, &be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize domain\n");
        goto done;
    }

    ret = sysdb_master_domain_update(be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to update master domain information!\n");
        goto done;
    }

    /* We need this for subdomains support, as they have to store fully
     * qualified user and group names for now. */
    ret = sss_names_init(be_ctx->domain, cdb, be_ctx->domain->name,
                         &be_ctx->domain->names);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to setup fully qualified name "
              "format for %s\n", be_ctx->domain->name);
        goto done;
    }

    /* Read the global override_space option, for output name formatting */
    ret = confdb_get_string(cdb, be_ctx, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_OVERRIDE_SPACE, NULL,
                            &str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the space substitution character [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }

    if (str != NULL) {
        if (strlen(str) > 1) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Option %s is longer than 1 character "
                  "only the first character %c will be used\n",
                  CONFDB_MONITOR_OVERRIDE_SPACE, str[0]);
        }

        be_ctx->override_space = str[0];
    }

    /* Read session_recording section */
    ret = session_recording_conf_load(be_ctx, cdb, &be_ctx->sr_conf);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed loading session recording configuration: %s\n",
              strerror(ret));
        goto done;
    }

    be_ctx->sbus_name = talloc_strdup(be_ctx, be_ctx->domain->conn_name);
    if (be_ctx->sbus_name == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory when copying D-Bus name.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = dp_init(be_ctx->ev, be_ctx, be_ctx->sbus_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to setup data provider [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = be_register_monitor_iface(be_ctx->conn, be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register monitor interface "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Handle SIGUSR1 to force offline behavior */
    BlockSignals(false, SIGUSR1);
    tes = tevent_add_signal(be_ctx->ev, be_ctx, SIGUSR1, 0,
                            signal_be_offline, be_ctx);
    if (tes == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to setup SIGUSR1 handler\n");
        ret = EIO;
        goto done;
    }

    /* Handle SIGUSR2 to force going online */
    BlockSignals(false, SIGUSR2);
    tes = tevent_add_signal(be_ctx->ev, be_ctx, SIGUSR2, 0,
                            signal_be_reset_offline, be_ctx);
    if (tes == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to setup SIGUSR2 handler\n");
        ret = EIO;
        goto done;
    }

    /* Handle SSSSIG_TIME_SHIFT_DETECTED (reschedule tasks) */
    BlockSignals(false, SSSSIG_TIME_SHIFT_DETECTED);
    tes = tevent_add_signal(be_ctx->ev, be_ctx, SSSSIG_TIME_SHIFT_DETECTED, 0,
                            signal_be_reschedule_tasks, be_ctx);
    if (tes == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to setup SSSSIG_TIME_SHIFT_DETECTED handler\n");
        ret = EIO;
        goto done;
    }

    /* Set up watchers for system config files and the net links */
    ret = watch_config_files(be_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = watch_netlink(be_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_monitor_register_service(be_ctx, be_ctx->conn,
                                       be_ctx->identity, DATA_PROVIDER_VERSION,
                                       MT_SVC_PROVIDER);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register to the monitor "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Backend provider (%s) started!\n",
          be_ctx->domain->name);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(be_ctx);
    }

    return ret;
}

#ifndef UNIT_TESTING
int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *opt_logger = NULL;
    char *be_domain = NULL;
    char *srv_name = NULL;
    struct main_context *main_ctx;
    char *confdb_path;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        SSSD_LOGGER_OPTS(&opt_logger)
        {"domain", 0, POPT_ARG_STRING, &be_domain, 0,
         _("Domain of the information provider (mandatory)"), NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
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

    if (be_domain == NULL) {
        fprintf(stderr, "\nMissing option, --domain is a mandatory option.\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
    }
    if (!is_valid_domain_name(be_domain)) {
        fprintf(stderr, "\nInvalid --domain option.\n\n");
        return 1;
    }

    poptFreeContext(pc);

    /* set up things like debug, signals, daemonization, etc. */
    debug_log_file = talloc_asprintf(NULL, "sssd_%s", be_domain);
    if (!debug_log_file) return 2;
    DEBUG_INIT(debug_level, opt_logger);

    srv_name = talloc_asprintf(NULL, "be[%s]", be_domain);
    if (!srv_name) return 2;

    confdb_path = talloc_asprintf(NULL, CONFDB_DOMAIN_PATH_TMPL, be_domain);
    if (!confdb_path) return 2;

    ret = server_setup(srv_name, false, 0, CONFDB_FILE,
                       confdb_path, &main_ctx, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set up mainloop [%d]\n", ret);
        return 2;
    }

    ret = setenv(SSS_DOM_ENV, be_domain, 1);
    if (ret != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Setting "SSS_DOM_ENV" failed, journald "
              "logging might not work as expected\n");
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = be_process_init(main_ctx,
                          be_domain,
                          main_ctx->event_ctx,
                          main_ctx->confdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize backend [%d]\n", ret);
        return 3;
    }

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
#endif

static errno_t
data_provider_go_offline(TALLOC_CTX *mem_ctx,
                         struct sbus_request *sbus_req,
                         struct be_ctx *be_ctx)
{
    be_mark_offline(be_ctx);

    return EOK;
}

static errno_t
data_provider_reset_offline(TALLOC_CTX *mem_ctx,
                            struct sbus_request *sbus_req,
                            struct be_ctx *be_ctx)
{
    check_if_online(be_ctx, 1);

    return EOK;
}

static errno_t
data_provider_logrotate(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct be_ctx *be_ctx)
{
    return server_common_rotate_logs(be_ctx->cdb, be_ctx->conf_path);
}
