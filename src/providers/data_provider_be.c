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
#include <dbus/dbus.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_utf8.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "sbus/sssd_dbus.h"
#include "providers/backend.h"
#include "providers/fail_over.h"
#include "providers/be_refresh.h"
#include "providers/be_ptask.h"
#include "util/child_common.h"
#include "resolv/async_resolv.h"
#include "monitor/monitor_interfaces.h"

static int data_provider_res_init(struct sbus_request *dbus_req, void *data);
static int data_provider_go_offline(struct sbus_request *dbus_req, void *data);
static int data_provider_reset_offline(struct sbus_request *dbus_req, void *data);
static int data_provider_logrotate(struct sbus_request *dbus_req, void *data);

struct mon_cli_iface monitor_be_methods = {
    { &mon_cli_iface_meta, 0 },
    .resInit = data_provider_res_init,
    .goOffline = data_provider_go_offline,
    .resetOffline = data_provider_reset_offline,
    .rotateLogs = data_provider_logrotate,
    .clearMemcache = NULL,
    .clearEnumCache = NULL,
    .sysbusReconnect = NULL,
};

bool be_is_offline(struct be_ctx *ctx)
{
    return ctx->offstat.offline;
}

static void check_if_online(struct be_ctx *be_ctx);

static errno_t
try_to_go_online(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 struct be_ctx *be_ctx,
                 struct be_ptask *be_ptask,
                 void *be_ctx_void)
{
    struct be_ctx *ctx = (struct be_ctx*) be_ctx_void;

    check_if_online(ctx);
    return EOK;
}

static int get_offline_timeout(struct be_ctx *ctx)
{
    errno_t ret;
    int offline_timeout;

    ret = confdb_get_int(ctx->cdb, ctx->conf_path,
                         CONFDB_DOMAIN_OFFLINE_TIMEOUT, 60,
                         &offline_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get offline_timeout from confdb. "
              "Will use 60 seconds.\n");
        offline_timeout = 60;
    }

    return offline_timeout;
}

void be_mark_offline(struct be_ctx *ctx)
{
    int offline_timeout;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Going offline!\n");

    ctx->offstat.went_offline = time(NULL);
    ctx->offstat.offline = true;
    ctx->run_online_cb = true;

    if (ctx->check_if_online_ptask == NULL) {
        /* This is the first time we go offline - create a periodic task
         * to check if we can switch to online. */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Initialize check_if_online_ptask.\n");

        offline_timeout = get_offline_timeout(ctx);

        ret = be_ptask_create_sync(ctx, ctx,
                                   offline_timeout, offline_timeout,
                                   offline_timeout, 30, offline_timeout,
                                   BE_PTASK_OFFLINE_EXECUTE,
                                   3600 /* max_backoff */,
                                   try_to_go_online,
                                   ctx, "Check if online (periodic)",
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
    case DOM_INCONSISTENT:
    case DOM_DISABLED:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Won't touch disabled or inconsistent subdomain\n");
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
    ctx->offstat.went_offline = 0;
    ctx->offstat.offline = false;
    ctx->run_offline_cb = true;

    reactivate_subdoms(ctx->domain);

    be_ptask_disable(ctx->check_if_online_ptask);
    be_run_online_cb(ctx);
}

static void be_check_online_done(struct tevent_req *req);

static errno_t be_check_online_request(struct be_ctx *be_ctx)
{
    struct tevent_req *req;

    be_ctx->offstat.went_offline = time(NULL);
    reset_fo(be_ctx);

    req = dp_req_send(be_ctx, be_ctx->provider, NULL, NULL, "Online Check",
                      DPT_ID, DPM_CHECK_ONLINE, 0, NULL, NULL);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, be_check_online_done, be_ctx);

    return EOK;
}

static void be_check_online_done(struct tevent_req *req)
{
    struct be_ctx *be_ctx;
    struct dp_reply_std *reply;
    errno_t ret;

    be_ctx = tevent_req_callback_data(req, struct be_ctx);

    ret = dp_req_recv_ptr(be_ctx, req, struct dp_reply_std, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
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
        ret = be_check_online_request(be_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create check online req.\n");
            goto done;
        }
        return;
    }

done:
    be_ctx->check_online_ref_count = 0;
    if (reply->dp_error != DP_ERR_OFFLINE) {
        if (reply->dp_error != DP_ERR_OK) {
            reset_fo(be_ctx);
        }
        be_reset_offline(be_ctx);
    }
}

static void check_if_online(struct be_ctx *be_ctx)
{
    errno_t ret;

    be_run_unconditional_online_cb(be_ctx);

    if (!be_is_offline(be_ctx)) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Backend is already online, nothing to do.\n");
        return;
    }

    /* Make sure nobody tries to go online while we are checking */
    be_ctx->offstat.went_offline = time(NULL);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Trying to go back online!\n");

    be_ctx->check_online_ref_count++;

    if (be_ctx->check_online_ref_count != 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "There is an online check already running.\n");
        return;
    }

    if (!dp_method_enabled(be_ctx->provider, DPT_ID, DPM_CHECK_ONLINE)) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "ID providers does not provide a check_online method.\n");
        goto failed;
    }

    ret = be_check_online_request(be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create check online req.\n");
        goto failed;
    }

    return;

failed:
    be_ctx->check_online_ref_count--;
    DEBUG(SSSDBG_CRIT_FAILURE, "Failed to run a check_online test.\n");

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
    check_if_online(ctx);
}

errno_t be_process_init(TALLOC_CTX *mem_ctx,
                        const char *be_domain,
                        uid_t uid,
                        gid_t gid,
                        struct tevent_context *ev,
                        struct confdb_ctx *cdb)
{
    uint32_t refresh_interval;
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
    be_ctx->uid = uid;
    be_ctx->gid = gid;
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

    ret = sss_monitor_init(be_ctx, be_ctx->ev, &monitor_be_methods,
                           be_ctx->identity, DATA_PROVIDER_VERSION,
                           MT_SVC_PROVIDER, be_ctx, NULL,
                           &be_ctx->mon_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize monitor connection\n");
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

    /* Initialize be_refresh periodic task. */
    be_ctx->refresh_ctx = be_refresh_ctx_init(be_ctx);
    if (be_ctx->refresh_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize refresh_ctx\n");
        ret = ENOMEM;
        goto done;
    }

    refresh_interval = be_ctx->domain->refresh_expired_interval;
    if (refresh_interval > 0) {
        ret = be_ptask_create(be_ctx, be_ctx, refresh_interval, 30, 5, 0,
                              refresh_interval, BE_PTASK_OFFLINE_SKIP, 0,
                              be_refresh_send, be_refresh_recv,
                              be_ctx->refresh_ctx, "Refresh Records", NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unable to initialize refresh periodic task\n");
            goto done;
        }
    }

    ret = dp_init(be_ctx->ev, be_ctx, be_ctx->uid, be_ctx->gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to setup data provider "
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
    uid_t uid;
    gid_t gid;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
        SSSD_SERVER_OPTS(uid, gid)
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

    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    /* set up things like debug, signals, daemonization, etc. */
    debug_log_file = talloc_asprintf(NULL, "sssd_%s", be_domain);
    if (!debug_log_file) return 2;

    sss_set_logger(opt_logger);

    srv_name = talloc_asprintf(NULL, "sssd[be[%s]]", be_domain);
    if (!srv_name) return 2;

    confdb_path = talloc_asprintf(NULL, CONFDB_DOMAIN_PATH_TMPL, be_domain);
    if (!confdb_path) return 2;

    ret = server_setup(srv_name, 0, 0, 0, confdb_path, &main_ctx);
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
                          be_domain, uid, gid,
                          main_ctx->event_ctx,
                          main_ctx->confdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize backend [%d]\n", ret);
        return 3;
    }

    ret = chown_debug_file(NULL, uid, gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot chown the debug files, debugging might not work!\n");
    }

    ret = become_user(uid, gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Cannot become user [%"SPRIuid"][%"SPRIgid"].\n", uid, gid);
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Backend provider (%s) started!\n", be_domain);

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
#endif

static int data_provider_res_init(struct sbus_request *dbus_req, void *data)
{
    struct be_ctx *be_ctx;
    be_ctx = talloc_get_type(data, struct be_ctx);

    resolv_reread_configuration(be_ctx->be_res->resolv);
    check_if_online(be_ctx);

    return monitor_common_res_init(dbus_req, data);
}

static int data_provider_go_offline(struct sbus_request *dbus_req, void *data)
{
    struct be_ctx *be_ctx;
    be_ctx = talloc_get_type(data, struct be_ctx);
    be_mark_offline(be_ctx);
    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}

static int data_provider_reset_offline(struct sbus_request *dbus_req, void *data)
{
    struct be_ctx *be_ctx;
    be_ctx = talloc_get_type(data, struct be_ctx);
    check_if_online(be_ctx);
    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}

static int data_provider_logrotate(struct sbus_request *dbus_req, void *data)
{
    errno_t ret;
    struct be_ctx *be_ctx = talloc_get_type(data, struct be_ctx);

    ret = server_common_rotate_logs(be_ctx->cdb, be_ctx->conf_path);
    if (ret != EOK) return ret;

    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}
