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
#include <dbus/dbus.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "providers/proxy/proxy.h"
#include "providers/proxy/proxy_iface_generated.h"

#include "providers/backend.h"

struct pc_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    struct sss_domain_info *domain;
    const char *identity;
    const char *conf_path;
    struct sbus_connection *mon_conn;
    struct sbus_connection *conn;
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
                DEBUG(SSSDBG_CRIT_FAILURE, "unknown PAM call\n");
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

static int pc_pam_handler(struct sbus_request *dbus_req, void *user_data)
{
    DBusError dbus_error;
    DBusMessage *reply;
    struct pc_ctx *pc_ctx;
    errno_t ret;
    struct pam_data *pd = NULL;

    pc_ctx = talloc_get_type(user_data, struct pc_ctx);
    if (!pc_ctx) {
        ret = EINVAL;
        goto done;
    }

    reply = dbus_message_new_method_return(dbus_req->message);
    if (!reply) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dbus_message_new_method_return failed, "
                  "cannot send reply.\n");
        ret = ENOMEM;
        goto done;
    }

    dbus_error_init(&dbus_error);

    ret = dp_unpack_pam_request(dbus_req->message, pc_ctx, &pd, &dbus_error);
    if (!ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,"Failed, to parse message!\n");
        ret = EIO;
        goto done;
    }

    pd->pam_status = PAM_SYSTEM_ERR;
    pd->domain = talloc_strdup(pd, pc_ctx->domain->name);
    if (pd->domain == NULL) {
        talloc_free(pd);
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Got request with the following data\n");
    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    ret = call_pam_stack(pc_ctx->pam_target, pd);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "call_pam_stack failed.\n");
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Sending result [%d][%s]\n",
              pd->pam_status, pd->domain);

    ret = dp_pack_pam_response(reply, pd);
    if (!ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to generate dbus reply\n");
        talloc_free(pd);
        dbus_message_unref(reply);
        ret = EIO;
        goto done;
    }

    ret = sbus_request_finish(dbus_req, reply);
    dbus_message_unref(reply);
    talloc_free(pd);

    /* We'll return the message and let the
     * parent process kill us.
     */
    return ret;

done:
    exit(ret);
}

static void proxy_child_id_callback(DBusPendingCall *pending, void *ptr)
{
    DBusMessage *reply;
    errno_t ret;

    reply = dbus_pending_call_steal_reply(pending);
    if (reply == NULL) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(SSSDBG_FATAL_FAILURE, "Severe error. A reply callback was "
              "called but no reply was received and no timeout occurred\n");
        goto done;
    }

    ret = sbus_parse_reply(reply);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get ID ack [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got id ack from proxy child\n");

done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
}

static errno_t proxy_child_send_id(struct sbus_connection *conn, uint32_t id)
{
    DBusMessage *msg;
    errno_t ret;

    msg = sbus_create_message(NULL, NULL, PROXY_CHILD_PATH, IFACE_PROXY_CLIENT,
                              IFACE_PROXY_CLIENT_REGISTER,
                              DBUS_TYPE_UINT32, &id);
    if (msg == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory?!\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Sending ID to Proxy Backend: (%"PRIu32")\n", id);

    ret = sbus_conn_send(conn, msg, 30000, proxy_child_id_callback, NULL, NULL);

    dbus_message_unref(msg);

    return ret;
}

static int proxy_cli_init(struct pc_ctx *ctx)
{
    char *sbus_address;
    int ret;

    static struct iface_proxy_auth iface_proxy_auth = {
        { &iface_proxy_auth_meta, 0 },

        .PAM = pc_pam_handler,
    };

    sbus_address = talloc_asprintf(ctx, "unix:path=%s/%s_%s",
                                   PIPE_PATH, PROXY_CHILD_PIPE,
                                   ctx->domain->name);
    if (sbus_address == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        return ENOMEM;
    }

    ret = sbus_client_init(ctx, ctx->ev, sbus_address, NULL, &ctx->conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sbus_client_init failed.\n");
        return ret;
    }

    ret = sbus_conn_register_iface(ctx->conn, &iface_proxy_auth.vtable,
                                   PROXY_CHILD_PATH, ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to export proxy.\n");
        return ret;
    }

    ret = proxy_child_send_id(ctx->conn, ctx->id);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "dp_common_send_id failed.\n");
        return ret;
    }

    return EOK;
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
    long id;
    char *pam_target = NULL;
    uid_t uid;
    gid_t gid;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
        SSSD_SERVER_OPTS(uid, gid)
        {"domain", 0, POPT_ARG_STRING, &domain, 0,
         _("Domain of the information provider (mandatory)"), NULL },
        {"id", 0, POPT_ARG_LONG, &id, 0,
         _("Child identifier (mandatory)"), NULL },
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

    if (domain == NULL) {
        fprintf(stderr, "\nMissing option, "
                        "--domain is a mandatory option.\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
    }

    if (id == 0) {
        fprintf(stderr, "\nMissing option, "
                        "--id is a mandatory option.\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
    }

    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    /* set up things like debug, signals, daemonization, etc. */
    debug_log_file = talloc_asprintf(NULL, "proxy_child_%s", domain);
    if (!debug_log_file) return 2;

    sss_set_logger(opt_logger);

    srv_name = talloc_asprintf(NULL, "sssd[proxy_child[%s]]", domain);
    if (!srv_name) return 2;

    conf_entry = talloc_asprintf(NULL, CONFDB_DOMAIN_PATH_TMPL, domain);
    if (!conf_entry) return 2;

    ret = server_setup(srv_name, 0, 0, 0, conf_entry, &main_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set up mainloop [%d]\n", ret);
        return 2;
    }

    ret = unsetenv("_SSS_LOOPS");
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to unset _SSS_LOOPS, "
                  "pam modules might not work as expected.\n");
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

    DEBUG(SSSDBG_CRIT_FAILURE,
          "Proxy child for domain [%s] started!\n", domain);

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
