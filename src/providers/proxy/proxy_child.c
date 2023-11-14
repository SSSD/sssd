/*
    SSSD

    Pam Proxy Child

    Authors:

        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "providers/proxy/proxy.h"
#include "sss_iface/sss_iface_async.h"
#include "util/sss_chain_id.h"

#include "providers/backend.h"

struct pc_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    struct sss_domain_info *domain;
    const char *identity;
    const char *conf_path;
    struct sbus_connection *sbus_conn;
    const char *pam_target;
    uint32_t id;
};

static int proxy_internal_conv(int num_msg, const struct pam_message **msgm,
                            struct pam_response **response,
                            void *appdata_ptr) {
    int i;
    struct pam_response *reply;
    struct authtok_conv *auth_data;
    const char *password;
    size_t pwlen;
    errno_t ret;

    auth_data = talloc_get_type(appdata_ptr, struct authtok_conv);

    if (num_msg <= 0) return PAM_CONV_ERR;

    reply = (struct pam_response *) calloc(num_msg,
                                           sizeof(struct pam_response));
    if (reply == NULL) return PAM_CONV_ERR;

    for (i=0; i < num_msg; i++) {
        switch( msgm[i]->msg_style ) {
            case PAM_PROMPT_ECHO_OFF:
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "Conversation message: [%s]\n", msgm[i]->msg);
                reply[i].resp_retcode = 0;

                ret = sss_authtok_get_password(auth_data->authtok,
                                               &password, &pwlen);
                if (ret) goto failed;
                reply[i].resp = calloc(pwlen + 1, sizeof(char));
                if (reply[i].resp == NULL) goto failed;
                memcpy(reply[i].resp, password, pwlen + 1);

                break;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Conversation style %d not supported.\n",
                           msgm[i]->msg_style);
                goto failed;
        }
    }

    *response = reply;
    reply = NULL;

    return PAM_SUCCESS;

failed:
    free(reply);
    return PAM_CONV_ERR;
}

static int proxy_chauthtok_conv(int num_msg, const struct pam_message **msgm,
                                struct pam_response **response,
                                void *appdata_ptr) {
    int i;
    struct pam_response *reply;
    struct authtok_conv *auth_data;
    const char *password;
    size_t pwlen;
    errno_t ret;

    auth_data = talloc_get_type(appdata_ptr, struct authtok_conv);

    if (num_msg <= 0) return PAM_CONV_ERR;

    reply = (struct pam_response *) calloc(num_msg,
                                           sizeof(struct pam_response));
    if (reply == NULL) return PAM_CONV_ERR;

    for (i=0; i < num_msg; i++) {
        switch( msgm[i]->msg_style ) {
            case PAM_PROMPT_ECHO_OFF:
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "Conversation message: [%s]\n", msgm[i]->msg);

                reply[i].resp_retcode = 0;
                if (!auth_data->sent_old) {
                    /* The first prompt will be asking for the old authtok */
                    ret = sss_authtok_get_password(auth_data->authtok,
                                                  &password, &pwlen);
                    if (ret) goto failed;
                    reply[i].resp = calloc(pwlen + 1, sizeof(char));
                    if (reply[i].resp == NULL) goto failed;
                    memcpy(reply[i].resp, password, pwlen + 1);
                    auth_data->sent_old = true;
                }
                else {
                    /* Subsequent prompts are looking for the new authtok */
                    ret = sss_authtok_get_password(auth_data->newauthtok,
                                                  &password, &pwlen);
                    if (ret) goto failed;
                    reply[i].resp = calloc(pwlen + 1, sizeof(char));
                    if (reply[i].resp == NULL) goto failed;
                    memcpy(reply[i].resp, password, pwlen + 1);
                    auth_data->sent_old = true;
                }

                break;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Conversation style %d not supported.\n",
                           msgm[i]->msg_style);
                goto failed;
        }
    }

    *response = reply;
    reply = NULL;

    return PAM_SUCCESS;

failed:
    free(reply);
    return PAM_CONV_ERR;
}

static errno_t call_pam_stack(const char *pam_target, struct pam_data *pd)
{
    int ret;
    int pam_status;
    pam_handle_t *pamh=NULL;
    struct authtok_conv *auth_data;
    struct pam_conv conv;
    char *shortname;

    if (pd->cmd == SSS_PAM_CHAUTHTOK) {
        conv.conv=proxy_chauthtok_conv;
    }
    else {
        conv.conv=proxy_internal_conv;
    }
    auth_data = talloc_zero(pd, struct authtok_conv);
    if (auth_data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }
    auth_data->authtok = sss_authtok_new(auth_data);
    if (auth_data->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_authtok_new failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    auth_data->newauthtok = sss_authtok_new(auth_data);
    if (auth_data->newauthtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_authtok_new failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    conv.appdata_ptr=auth_data;

    ret = sss_parse_internal_fqname(auth_data, pd->user, &shortname, NULL);
    if (ret != EOK) {
        goto fail;
    }

    ret = pam_start(pam_target, shortname, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Pam transaction started with service name [%s].\n",
                  pam_target);
        ret = pam_set_item(pamh, PAM_TTY, pd->tty);
        if (ret != PAM_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Setting PAM_TTY failed: %s.\n",
                      pam_strerror(pamh, ret));
        }
        ret = pam_set_item(pamh, PAM_RUSER, pd->ruser);
        if (ret != PAM_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Setting PAM_RUSER failed: %s.\n",
                      pam_strerror(pamh, ret));
        }
        ret = pam_set_item(pamh, PAM_RHOST, pd->rhost);
        if (ret != PAM_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Setting PAM_RHOST failed: %s.\n",
                      pam_strerror(pamh, ret));
        }
        switch (pd->cmd) {
            case SSS_PAM_AUTHENTICATE:
                sss_authtok_copy(pd->authtok, auth_data->authtok);
                pam_status = pam_authenticate(pamh, 0);
                break;
            case SSS_PAM_SETCRED:
                pam_status=pam_setcred(pamh, 0);
                break;
            case SSS_PAM_ACCT_MGMT:
                pam_status=pam_acct_mgmt(pamh, 0);
                break;
            case SSS_PAM_OPEN_SESSION:
                pam_status=pam_open_session(pamh, 0);
                break;
            case SSS_PAM_CLOSE_SESSION:
                pam_status=pam_close_session(pamh, 0);
                break;
            case SSS_PAM_CHAUTHTOK:
                sss_authtok_copy(pd->authtok, auth_data->authtok);
                if (pd->priv != 1) {
                    pam_status = pam_authenticate(pamh, 0);
                    auth_data->sent_old = false;
                    if (pam_status != PAM_SUCCESS) break;
                }
                sss_authtok_copy(pd->newauthtok, auth_data->newauthtok);
                pam_status = pam_chauthtok(pamh, 0);
                break;
            case SSS_PAM_CHAUTHTOK_PRELIM:
                if (pd->priv != 1) {
                    sss_authtok_copy(pd->authtok, auth_data->authtok);
                    pam_status = pam_authenticate(pamh, 0);
                } else {
                    pam_status = PAM_SUCCESS;
                }
                break;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE, "unknown PAM call %d\n", pd->cmd);
                pam_status=PAM_ABORT;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Pam result: [%d][%s]\n", pam_status,
                  pam_strerror(pamh, pam_status));

        ret = pam_end(pamh, pam_status);
        if (ret != PAM_SUCCESS) {
            pamh=NULL;
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot terminate pam transaction.\n");
        }

    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize pam transaction.\n");
        pam_status = PAM_SYSTEM_ERR;
    }

    pd->pam_status = pam_status;

    return EOK;
fail:
    talloc_free(auth_data);
    return ret;
}

static errno_t
pc_pam_handler(TALLOC_CTX *mem_ctx,
               struct sbus_request *sbus_req,
               struct pc_ctx *pc_ctx,
               struct pam_data *pd,
               struct pam_data **_response)
{
    errno_t ret;

    pd->pam_status = PAM_SYSTEM_ERR;
    pd->domain = talloc_strdup(pd, pc_ctx->domain->name);
    if (pd->domain == NULL) {
        exit(ENOMEM);
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Got request with the following data\n");
    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    ret = call_pam_stack(pc_ctx->pam_target, pd);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "call_pam_stack failed.\n");
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Sending result [%d][%s]\n",
          pd->pam_status, pd->domain);

    *_response = pd;

    /* We'll return the message and let the
     * parent process kill us.
     */
    return ret;
}

static void proxy_cli_init_done(struct tevent_req *subreq);

static errno_t
proxy_cli_init(struct pc_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    struct tevent_req *subreq;
    char *sbus_cliname;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    SBUS_INTERFACE(iface,
        sssd_ProxyChild_Auth,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_ProxyChild_Auth, PAM, pc_pam_handler, ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    struct sbus_path paths[] = {
        {SSS_BUS_PATH, &iface},
        {NULL, NULL}
    };

    sbus_cliname = sss_iface_proxy_bus(tmp_ctx, ctx->id);
    if (sbus_cliname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_sbus_connect(ctx, ctx->ev, sbus_cliname, NULL, &ctx->sbus_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to connect to SSSD D-Bus server "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sbus_connection_add_path_map(ctx->sbus_conn, paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to add paths [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Sending ID to Proxy Backend: (%"PRIu32")\n",
          ctx->id);

    subreq = sbus_call_proxy_client_Register_send(ctx, ctx->sbus_conn,
                                                  ctx->domain->conn_name,
                                                  SSS_BUS_PATH, ctx->id);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, proxy_cli_init_done, NULL);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static void proxy_cli_init_done(struct tevent_req *subreq)
{
    errno_t ret;

    ret = sbus_call_proxy_client_Register_recv(subreq);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to register with proxy provider "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got id ack from proxy child\n");
}

int proxy_child_process_init(TALLOC_CTX *mem_ctx, const char *domain,
                             struct tevent_context *ev, struct confdb_ctx *cdb,
                             const char *pam_target, uint32_t id)
{
    struct pc_ctx *ctx;
    int ret;

    ctx = talloc_zero(mem_ctx, struct pc_ctx);
    if (!ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing pc_ctx\n");
        return ENOMEM;
    }
    ctx->ev = ev;
    ctx->cdb = cdb;
    ctx->pam_target = talloc_steal(ctx, pam_target);
    ctx->id = id;
    ctx->conf_path = talloc_asprintf(ctx, CONFDB_DOMAIN_PATH_TMPL, domain);
    if (!ctx->conf_path) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!?\n");
        return ENOMEM;
    }

    ret = confdb_get_domain(cdb, domain, &ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error retrieving domain configuration\n");
        return ret;
    }

    ret = proxy_cli_init(ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error setting up server bus\n");
        return ret;
    }

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *opt_logger = NULL;
    char *domain = NULL;
    char *srv_name = NULL;
    char *conf_entry = NULL;
    struct main_context *main_ctx;
    int ret;
    long id = 0;
    long chain_id;
    char *pam_target = NULL;
    uid_t uid = 0;
    gid_t gid = 0;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
        SSSD_SERVER_OPTS(uid, gid)
        {"domain", 0, POPT_ARG_STRING, &domain, 0,
         _("Domain of the information provider (mandatory)"), NULL },
        {"id", 0, POPT_ARG_LONG, &id, 0,
         _("Child identifier (mandatory)"), NULL },
        {"chain-id", 0, POPT_ARG_LONG, &chain_id, 0,
         _("Tevent chain ID used for logging purposes"), NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    ret = chdir("/");
    if (ret != 0) {
        fprintf(stderr, "\nFailed to chdir()\n\n");
        return 1;
    }

    ret = clearenv();
    if (ret != 0) {
        fprintf(stderr, "\nFailed to clear env.\n\n");
        return 1;
    }

    umask(SSS_DFL_UMASK);

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

    if (domain == NULL) {
        fprintf(stderr, "\nMissing option, "
                        "--domain is a mandatory option.\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
    }
    if (!is_valid_domain_name(domain)) {
        fprintf(stderr, "\nInvalid --domain option.\n\n");
        return 1;
    }

    if (id == 0) {
        fprintf(stderr, "\nMissing option, "
                        "--id is a mandatory option.\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
    }

    poptFreeContext(pc);

    /* set up things like debug, signals, daemonization, etc. */
    debug_log_file = talloc_asprintf(NULL, "proxy_child_%s", domain);
    if (!debug_log_file) return 2;

    sss_chain_id_set((uint64_t)chain_id);

    DEBUG_INIT(debug_level, opt_logger);

    srv_name = talloc_asprintf(NULL, "proxy_child[%s]", domain);
    if (!srv_name) return 2;

    conf_entry = talloc_asprintf(NULL, CONFDB_DOMAIN_PATH_TMPL, domain);
    if (!conf_entry) return 2;

    ret = server_setup(srv_name, false, 0, 0, 0, CONFDB_FILE, conf_entry,
                       &main_ctx, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set up mainloop [%d]\n", ret);
        return 2;
    }

    ret = confdb_get_string(main_ctx->confdb_ctx, main_ctx, conf_entry,
                            CONFDB_PROXY_PAM_TARGET, NULL, &pam_target);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading from confdb (%d) [%s]\n",
                  ret, strerror(ret));
        return 4;
    }
    if (pam_target == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing option proxy_pam_target.\n");
        return 4;
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = proxy_child_process_init(main_ctx, domain, main_ctx->event_ctx,
                                   main_ctx->confdb_ctx, pam_target,
                                   (uint32_t)id);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize proxy child [%d].\n", ret);
        return 3;
    }

    DEBUG(SSSDBG_IMPORTANT_INFO,
          "Proxy child for domain [%s] started!\n", domain);

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
