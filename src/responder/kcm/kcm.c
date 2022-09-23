/*
   SSSD

   KCM Server - the mainloop and server setup

   Copyright (C) Red Hat, 2016

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

#include <popt.h>

#include "responder/kcm/kcmsrv_ccache.h"
#include "responder/kcm/kcmsrv_pvt.h"
#include "responder/kcm/kcm_renew.h"
#include "responder/common/responder.h"
#include "providers/krb5/krb5_common.h"
#include "util/util.h"
#include "util/sss_krb5.h"

#define DEFAULT_KCM_FD_LIMIT 2048
#define DEFAULT_KCM_CLI_IDLE_TIMEOUT 300

#ifndef SSS_KCM_SOCKET_NAME
#define SSS_KCM_SOCKET_NAME DEFAULT_KCM_SOCKET_PATH
#endif

static int kcm_responder_ctx_destructor(void *ptr)
{
    struct resp_ctx *rctx = talloc_get_type(ptr, struct resp_ctx);

    /* mark that we are shutting down the responder, so it is propagated
     * into underlying contexts that are freed right before rctx */
    DEBUG(SSSDBG_TRACE_FUNC, "Responder is being shut down\n");
    rctx->shutting_down = true;

    return 0;
}

static errno_t kcm_renewals_init(struct tevent_context *ev,
                                 struct resp_ctx *rctx,
                                 struct kcm_ctx *kctx,
                                 struct krb5_ctx *krb5_ctx,
                                 time_t renew_intv,
                                 bool *_renewal_enabled)
{
#ifndef HAVE_KCM_RENEWAL
    return EOK;
#else
    errno_t ret;

    ret = kcm_get_renewal_config(kctx, &krb5_ctx, &renew_intv);
    if (ret == ENOTSUP) {
        DEBUG(SSSDBG_TRACE_FUNC, "TGT Renewals support disabled\n");
        return EOK;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to read TGT renewal configuration [%d]: %s\n",
                                    ret, sss_strerror(ret));
        return ret;
    }

    if (renew_intv > 0) {
        *_renewal_enabled = true;

        ret = kcm_renewal_setup(rctx, krb5_ctx, ev, kctx->kcm_data->db, renew_intv);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unable to setup TGT renewals [%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    return EOK;
#endif
}

static errno_t kcm_get_ccdb_be(struct kcm_ctx *kctx)
{
    errno_t ret;
    char *str_db;

    ret = confdb_get_string(kctx->rctx->cdb,
                            kctx->rctx,
                            kctx->rctx->confdb_service_path,
                            CONFDB_KCM_DB,
                            "secdb",
                            &str_db);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the KCM database type [%d]: %s\n",
               ret, strerror(ret));
        return ret;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "KCM database type: %s\n", str_db);
    if (strcasecmp(str_db, "memory") == 0) {
        kctx->cc_be = CCDB_BE_MEMORY;
    } else if (strcasecmp(str_db, "secdb") == 0) {
        kctx->cc_be = CCDB_BE_SECDB;
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unexpected KCM database type %s\n", str_db);
    }

    return EOK;
}

static int kcm_get_config(struct kcm_ctx *kctx)
{
    int ret;
    char *sock_name;

    ret = confdb_get_int(kctx->rctx->cdb,
                         CONFDB_KCM_CONF_ENTRY,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_KCM_FD_LIMIT,
                         &kctx->fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get file descriptors limit\n");
        goto done;
    }

    ret = confdb_get_int(kctx->rctx->cdb,
                         kctx->rctx->confdb_service_path,
                         CONFDB_RESPONDER_CLI_IDLE_TIMEOUT,
                         DEFAULT_KCM_CLI_IDLE_TIMEOUT,
                         &kctx->rctx->client_idle_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the client idle timeout [%s] [%d]: %s\n",
               CONFDB_RESPONDER_CLI_IDLE_TIMEOUT, ret, strerror(ret));
        goto done;
    }

    /* Ensure that the client timeout is at least ten seconds */
    if (kctx->rctx->client_idle_timeout < 10) {
        kctx->rctx->client_idle_timeout = 10;
    }

    ret = confdb_get_string(kctx->rctx->cdb,
                            kctx->rctx,
                            kctx->rctx->confdb_service_path,
                            CONFDB_KCM_SOCKET,
                            SSS_KCM_SOCKET_NAME,
                            &sock_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get KCM socket path [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }
    kctx->rctx->sock_name = sock_name;

    ret = kcm_get_ccdb_be(kctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get KCM ccache DB [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }

    kctx->qctx = kcm_ops_queue_create(kctx, kctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot create KCM request queue [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }
    ret = EOK;
done:
    return ret;
}

static int kcm_data_destructor(void *ptr)
{
    struct kcm_resp_ctx *kcm_data = talloc_get_type(ptr, struct kcm_resp_ctx);

    if (kcm_data != NULL) {
        krb5_free_context(kcm_data->k5c);
    }
    return 0;
}

static struct kcm_resp_ctx *kcm_data_setup(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct confdb_ctx *cdb,
                                           const char *confdb_service_path,
                                           enum kcm_ccdb_be cc_be)
{
    struct kcm_resp_ctx *kcm_data;
    krb5_error_code kret;

    kcm_data = talloc_zero(mem_ctx, struct kcm_resp_ctx);
    if (kcm_data == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing kcm data\n");
        return NULL;
    }

    kcm_data->db = kcm_ccdb_init(kcm_data,
                                 ev,
                                 cdb,
                                 confdb_service_path,
                                 cc_be);
    if (kcm_data->db == NULL) {
        talloc_free(kcm_data);
        return NULL;
    }

    kret = sss_krb5_init_context(&kcm_data->k5c);
    if (kret != EOK) {
        talloc_free(kcm_data);
        return NULL;
    }
    talloc_set_destructor((TALLOC_CTX*)kcm_data, kcm_data_destructor);

    return kcm_data;
}

static int kcm_process_init(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct kcm_ctx *kctx;
    bool renewal_enabled = false;
    struct krb5_ctx *krb5_ctx = NULL;
    time_t renew_intv = 0;
    int ret;

    rctx = talloc_zero(mem_ctx, struct resp_ctx);
    if (rctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing resp_ctx\n");
        return ENOMEM;
    }
    rctx->ev = ev;
    rctx->cdb = cdb;
    rctx->confdb_service_path = CONFDB_KCM_CONF_ENTRY;
    rctx->shutting_down = false;
    rctx->lfd = -1;
    rctx->priv_lfd = -1;

    talloc_set_destructor((TALLOC_CTX*)rctx, kcm_responder_ctx_destructor);

    kctx = talloc_zero(rctx, struct kcm_ctx);
    if (kctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing kcm_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    kctx->rctx = rctx;
    kctx->rctx->pvt_ctx = kctx;

    ret = kcm_get_config(kctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error getting KCM config\n");
        goto fail;
    }

    kctx->kcm_data = kcm_data_setup(kctx,
                                    ev,
                                    kctx->rctx->cdb,
                                    kctx->rctx->confdb_service_path,
                                    kctx->cc_be);
    if (kctx->kcm_data == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing responder data\n");
        ret = EIO;
        goto fail;
    }

    ret = kcm_renewals_init(ev, rctx, kctx, krb5_ctx, renew_intv, &renewal_enabled);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize TGT Renewals [%d]: %s\n",
                                    ret, sss_strerror(ret));
        goto fail;
    }

    if (renewal_enabled) {
        /* Disable resp idle timeout to allow renewals */
        rctx->idle_timeout = 0;
    } else {
        responder_setup_idle_timeout_config(kctx->rctx);
    }

    /* Set up file descriptor limits */
    responder_set_fd_limit(kctx->fd_limit);

    ret = activate_unix_sockets(rctx, kcm_connection_setup);
    if (ret != EOK) goto fail;

    DEBUG(SSSDBG_TRACE_FUNC, "KCM Initialization complete\n");

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
    uid_t uid = 0;
    gid_t gid = 0;

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
    debug_log_file = "sssd_kcm";
    DEBUG_INIT(debug_level, opt_logger);

    ret = server_setup("kcm", true, 0, uid, gid, CONFDB_KCM_CONF_ENTRY,
                       &main_ctx, true);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = kcm_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
