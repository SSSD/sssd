/*
   SSSD

   Secrets Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016

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
#include <sys/socket.h>
#include <sys/un.h>
#include <popt.h>

#include "responder/common/responder.h"
#include "responder/secrets/secsrv.h"
#include "resolv/async_resolv.h"

#define DEFAULT_SEC_FD_LIMIT 2048

static void adjust_global_quota(struct sec_ctx *sctx,
                                struct sss_sec_hive_config *hive_config)
{
    if (hive_config->quota.max_payload_size == 0
             || (sctx->max_payload_size != 0
                 && hive_config->quota.max_payload_size > sctx->max_payload_size)) {
        /* If the quota is unlimited or it's larger than what
         * we already have, save the total limit so we know how much to
         * accept from clients
         */
        sctx->max_payload_size = hive_config->quota.max_payload_size;
    }
}

static int sec_get_config(struct sec_ctx *sctx)
{
    int ret;
    struct sss_sec_quota_opt dfl_sec_nest_level = {
        .opt_name = CONFDB_SEC_CONTAINERS_NEST_LEVEL,
        .default_value = DEFAULT_SEC_CONTAINERS_NEST_LEVEL,
    };
    struct sss_sec_quota_opt dfl_sec_max_secrets = {
        .opt_name = CONFDB_SEC_MAX_SECRETS,
        .default_value = DEFAULT_SEC_MAX_SECRETS,
    };
    struct sss_sec_quota_opt dfl_sec_max_uid_secrets = {
        .opt_name = CONFDB_SEC_MAX_UID_SECRETS,
        .default_value = DEFAULT_SEC_MAX_UID_SECRETS,
    };
    struct sss_sec_quota_opt dfl_sec_max_payload_size = {
        .opt_name = CONFDB_SEC_MAX_PAYLOAD_SIZE,
        .default_value = DEFAULT_SEC_MAX_PAYLOAD_SIZE,
    };

    struct sss_sec_quota_opt dfl_kcm_nest_level = {
        .opt_name = CONFDB_SEC_CONTAINERS_NEST_LEVEL,
        .default_value = DEFAULT_SEC_CONTAINERS_NEST_LEVEL,
    };
    struct sss_sec_quota_opt dfl_kcm_max_secrets = {
        .opt_name = CONFDB_SEC_MAX_SECRETS,
        .default_value = DEFAULT_SEC_KCM_MAX_SECRETS,
    };
    struct sss_sec_quota_opt dfl_kcm_max_uid_secrets = {
        .opt_name = CONFDB_SEC_MAX_UID_SECRETS,
        .default_value = DEFAULT_SEC_KCM_MAX_UID_SECRETS,
    };
    struct sss_sec_quota_opt dfl_kcm_max_payload_size = {
        .opt_name = CONFDB_SEC_MAX_PAYLOAD_SIZE,
        .default_value = DEFAULT_SEC_KCM_MAX_PAYLOAD_SIZE,
    };

    ret = confdb_get_int(sctx->rctx->cdb,
                         sctx->rctx->confdb_service_path,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_SEC_FD_LIMIT,
                         &sctx->fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get file descriptors limit\n");
        goto fail;
    }

    /* Set the global max_payload to ridiculously small value so that either 0 (unlimited)
     * or any sensible value overwrite it
     */
    sctx->max_payload_size = 1;

    /* Read the global quota first -- this should be removed in a future release */
    ret = sss_sec_get_quota(sctx->rctx->cdb,
                            sctx->rctx->confdb_service_path,
                            &dfl_sec_nest_level,
                            &dfl_sec_max_secrets,
                            &dfl_sec_max_uid_secrets,
                            &dfl_sec_max_payload_size,
                            &sctx->sec_config.quota);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get legacy global quotas\n");
        goto fail;
    }

    /* Use the global quota values as defaults for the secrets/secrets section */
    dfl_sec_nest_level.default_value = \
                                sctx->sec_config.quota.containers_nest_level;
    dfl_sec_max_secrets.default_value = \
                                sctx->sec_config.quota.max_secrets;
    dfl_sec_max_uid_secrets.default_value = \
                                sctx->sec_config.quota.max_uid_secrets;
    dfl_sec_max_payload_size.default_value = \
                                sctx->sec_config.quota.max_payload_size;

    /* Read the per-hive configuration */
    ret = sss_sec_get_hive_config(sctx->rctx->cdb,
                                 "secrets",
                                 &dfl_sec_nest_level,
                                 &dfl_sec_max_secrets,
                                 &dfl_sec_max_uid_secrets,
                                 &dfl_sec_max_payload_size,
                                 &sctx->sec_config);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get configuration of the secrets hive\n");
        goto fail;
    }
    adjust_global_quota(sctx, &sctx->sec_config);

    ret = sss_sec_get_hive_config(sctx->rctx->cdb,
                                  "kcm",
                                  &dfl_kcm_nest_level,
                                  &dfl_kcm_max_secrets,
                                  &dfl_kcm_max_uid_secrets,
                                  &dfl_kcm_max_payload_size,
                                  &sctx->kcm_config);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get configuration of the kcm hive\n");
        goto fail;
    }
    adjust_global_quota(sctx, &sctx->kcm_config);

    ret = confdb_get_int(sctx->rctx->cdb, sctx->rctx->confdb_service_path,
                         CONFDB_RESPONDER_CLI_IDLE_TIMEOUT,
                         CONFDB_RESPONDER_CLI_IDLE_DEFAULT_TIMEOUT,
                         &sctx->rctx->client_idle_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the client idle timeout [%s] [%d]: %s\n",
               CONFDB_RESPONDER_CLI_IDLE_TIMEOUT, ret, strerror(ret));
        goto fail;
    }

    /* Ensure that the client timeout is at least ten seconds */
    if (sctx->rctx->client_idle_timeout < 10) {
        sctx->rctx->client_idle_timeout = 10;
    }

    ret = responder_setup_idle_timeout_config(sctx->rctx);
    if (ret != EOK) {
        goto fail;
    }

    ret = EOK;

fail:
    return ret;
}

static int sec_responder_ctx_destructor(void *ptr)
{
    struct resp_ctx *rctx = talloc_get_type(ptr, struct resp_ctx);

    /* mark that we are shutting down the responder, so it is propagated
     * into underlying contexts that are freed right before rctx */
    DEBUG(SSSDBG_TRACE_FUNC, "Responder is being shut down\n");
    rctx->shutting_down = true;

    return 0;
}

static int sec_process_init(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sec_ctx *sctx;
    int ret;

    rctx = talloc_zero(mem_ctx, struct resp_ctx);
    if (!rctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing resp_ctx\n");
        return ENOMEM;
    }
    rctx->ev = ev;
    rctx->cdb = cdb;
    rctx->sock_name = SSS_SEC_SOCKET_NAME;
    rctx->confdb_service_path = CONFDB_SEC_CONF_ENTRY;
    rctx->shutting_down = false;
    rctx->lfd = -1;
    rctx->priv_lfd = -1;

    talloc_set_destructor((TALLOC_CTX*)rctx, sec_responder_ctx_destructor);

    sctx = talloc_zero(rctx, struct sec_ctx);
    if (!sctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing sec_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    sctx->rctx = rctx;
    sctx->rctx->pvt_ctx = sctx;

    ret = sec_get_config(sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error getting secrets config\n");
        goto fail;
    }

    /* Set up file descriptor limits */
    responder_set_fd_limit(sctx->fd_limit);

    ret = activate_unix_sockets(rctx, sec_connection_setup);
    if (ret != EOK) goto fail;

    DEBUG(SSSDBG_TRACE_FUNC, "Secrets Initialization complete\n");

    return EOK;

fail:
    talloc_free(rctx);
    return ret;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *opt_logger = NULL;
    struct main_context *main_ctx;
    int ret;
    uid_t uid;
    gid_t gid;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
        SSSD_SERVER_OPTS(uid, gid)
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    umask(DFL_RSP_UMASK);

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

    poptFreeContext(pc);

    /* set up things like debug, signals, daemonization, etc. */
    debug_log_file = "sssd_secrets";
    DEBUG_INIT(debug_level, opt_logger);

    ret = server_setup("secrets", 0, uid, gid, CONFDB_SEC_CONF_ENTRY,
                       &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = sec_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
