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

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "popt.h"
#include "util/util.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "providers/proxy/proxy.h"

#include "providers/dp_backend.h"

static int pc_pam_handler(DBusMessage *message, struct sbus_connection *conn);

struct sbus_method pc_methods[] = {
    { DP_METHOD_PAMHANDLER, pc_pam_handler },
    { NULL, NULL }
};

struct sbus_interface pc_interface = {
    DP_INTERFACE,
    DP_PATH,
    SBUS_DEFAULT_VTABLE,
    pc_methods,
    NULL
};

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

    auth_data = talloc_get_type(appdata_ptr, struct authtok_conv);

    if (num_msg <= 0) return PAM_CONV_ERR;

    reply = (struct pam_response *) calloc(num_msg,
                                           sizeof(struct pam_response));
    if (reply == NULL) return PAM_CONV_ERR;

    for (i=0; i < num_msg; i++) {
        switch( msgm[i]->msg_style ) {
            case PAM_PROMPT_ECHO_OFF:
                DEBUG(4, ("Conversation message: [%s]\n", msgm[i]->msg));
                reply[i].resp_retcode = 0;
                reply[i].resp = calloc(auth_data->authtok_size + 1,
                                       sizeof(char));
                if (reply[i].resp == NULL) goto failed;
                memcpy(reply[i].resp, auth_data->authtok,
                       auth_data->authtok_size);

                break;
            default:
                DEBUG(1, ("Conversation style %d not supported.\n",
                           msgm[i]->msg_style));
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

    auth_data = talloc_get_type(appdata_ptr, struct authtok_conv);

    if (num_msg <= 0) return PAM_CONV_ERR;

    reply = (struct pam_response *) calloc(num_msg,
                                           sizeof(struct pam_response));
    if (reply == NULL) return PAM_CONV_ERR;

    for (i=0; i < num_msg; i++) {
        switch( msgm[i]->msg_style ) {
            case PAM_PROMPT_ECHO_OFF:
                DEBUG(4, ("Conversation message: [%s]\n", msgm[i]->msg));

                reply[i].resp_retcode = 0;
                if (!auth_data->sent_old) {
                    /* The first prompt will be asking for the old authtok */
                    reply[i].resp = calloc(auth_data->authtok_size + 1,
                                           sizeof(char));
                    if (reply[i].resp == NULL) goto failed;
                    memcpy(reply[i].resp, auth_data->authtok,
                           auth_data->authtok_size);
                    auth_data->sent_old = true;
                }
                else {
                    /* Subsequent prompts are looking for the new authtok */
                    reply[i].resp = calloc(auth_data->newauthtok_size + 1,
                                           sizeof(char));
                    if (reply[i].resp == NULL) goto failed;
                    memcpy(reply[i].resp, auth_data->newauthtok,
                           auth_data->newauthtok_size);
                }

                break;
            default:
                DEBUG(1, ("Conversation style %d not supported.\n",
                           msgm[i]->msg_style));
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

    if (pd->cmd == SSS_PAM_CHAUTHTOK) {
        conv.conv=proxy_chauthtok_conv;
    }
    else {
        conv.conv=proxy_internal_conv;
    }
    auth_data = talloc_zero(pd, struct authtok_conv);
    conv.appdata_ptr=auth_data;

    ret = pam_start(pam_target, pd->user, &conv, &pamh);
    if (ret == PAM_SUCCESS) {
        DEBUG(7, ("Pam transaction started with service name [%s].\n",
                  pam_target));
        ret = pam_set_item(pamh, PAM_TTY, pd->tty);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_TTY failed: %s.\n",
                      pam_strerror(pamh, ret)));
        }
        ret = pam_set_item(pamh, PAM_RUSER, pd->ruser);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_RUSER failed: %s.\n",
                      pam_strerror(pamh, ret)));
        }
        ret = pam_set_item(pamh, PAM_RHOST, pd->rhost);
        if (ret != PAM_SUCCESS) {
            DEBUG(1, ("Setting PAM_RHOST failed: %s.\n",
                      pam_strerror(pamh, ret)));
        }
        switch (pd->cmd) {
            case SSS_PAM_AUTHENTICATE:
                auth_data->authtok_size = pd->authtok_size;
                auth_data->authtok = pd->authtok;
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
                auth_data->authtok_size = pd->authtok_size;
                auth_data->authtok = pd->authtok;
                if (pd->priv != 1) {
                    pam_status = pam_authenticate(pamh, 0);
                    auth_data->sent_old = false;
                    if (pam_status != PAM_SUCCESS) break;
                }
                auth_data->newauthtok_size = pd->newauthtok_size;
                auth_data->newauthtok = pd->newauthtok;
                pam_status = pam_chauthtok(pamh, 0);
                break;
            case SSS_PAM_CHAUTHTOK_PRELIM:
                if (pd->priv != 1) {
                    auth_data->authtok_size = pd->authtok_size;
                    auth_data->authtok = pd->authtok;
                    pam_status = pam_authenticate(pamh, 0);
                } else {
                    pam_status = PAM_SUCCESS;
                }
                break;
            default:
                DEBUG(1, ("unknown PAM call\n"));
                pam_status=PAM_ABORT;
        }

        DEBUG(4, ("Pam result: [%d][%s]\n", pam_status,
                  pam_strerror(pamh, pam_status)));

        ret = pam_end(pamh, pam_status);
        if (ret != PAM_SUCCESS) {
            pamh=NULL;
            DEBUG(1, ("Cannot terminate pam transaction.\n"));
        }

    } else {
        DEBUG(1, ("Failed to initialize pam transaction.\n"));
        pam_status = PAM_SYSTEM_ERR;
    }

    pd->pam_status = pam_status;

    return EOK;
}

static int pc_pam_handler(DBusMessage *message, struct sbus_connection *conn)
{
    DBusError dbus_error;
    DBusMessage *reply;
    struct pc_ctx *pc_ctx;
    errno_t ret;
    void *user_data;
    struct pam_data *pd = NULL;

    user_data = sbus_conn_get_private_data(conn);
    if (!user_data) {
        ret = EINVAL;
        goto done;
    }
    pc_ctx = talloc_get_type(user_data, struct pc_ctx);
    if (!pc_ctx) {
        ret = EINVAL;
        goto done;
    }

    reply = dbus_message_new_method_return(message);
    if (!reply) {
        DEBUG(1, ("dbus_message_new_method_return failed, "
                  "cannot send reply.\n"));
        ret = ENOMEM;
        goto done;
    }

    dbus_error_init(&dbus_error);

    ret = dp_unpack_pam_request(message, pc_ctx, &pd, &dbus_error);
    if (!ret) {
        DEBUG(1,("Failed, to parse message!\n"));
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

    DEBUG(4, ("Got request with the following data\n"));
    DEBUG_PAM_DATA(4, pd);

    ret = call_pam_stack(pc_ctx->pam_target, pd);
    if (ret != EOK) {
        DEBUG(1, ("call_pam_stack failed.\n"));
    }

    DEBUG(4, ("Sending result [%d][%s]\n",
              pd->pam_status, pd->domain));

    ret = dp_pack_pam_response(reply, pd);
    if (!ret) {
        DEBUG(1, ("Failed to generate dbus reply\n"));
        talloc_free(pd);
        dbus_message_unref(reply);
        ret = EIO;
        goto done;
    }

    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);
    talloc_free(pd);

    /* We'll return the message and let the
     * parent process kill us.
     */
    return EOK;

done:
    exit(ret);
}

int proxy_child_send_id(struct sbus_connection *conn,
                        uint16_t version,
                        uint32_t id);
static int proxy_cli_init(struct pc_ctx *ctx)
{
    char *sbus_address;
    int ret;

    sbus_address = talloc_asprintf(ctx, "unix:path=%s/%s_%s",
                                      PIPE_PATH, PROXY_CHILD_PIPE,
                                      ctx->domain->name);
    if (sbus_address == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        return ENOMEM;
    }

    ret = sbus_client_init(ctx, ctx->ev, sbus_address,
                           &pc_interface, &ctx->conn,
                           NULL, ctx);
    if (ret != EOK) {
        DEBUG(1, ("sbus_client_init failed.\n"));
        return ret;
    }

    ret = proxy_child_send_id(ctx->conn, DATA_PROVIDER_VERSION, ctx->id);
    if (ret != EOK) {
        DEBUG(0, ("dp_common_send_id failed.\n"));
        return ret;
    }

    return EOK;
}

int proxy_child_send_id(struct sbus_connection *conn,
                        uint16_t version,
                        uint32_t id)
{
    DBusMessage *msg;
    dbus_bool_t ret;
    int retval;

    /* create the message */
    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_REGISTER);
    if (msg == NULL) {
        DEBUG(0, ("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(4, ("Sending ID to Proxy Backend: (%d,%ld)\n",
              version, id));

    ret = dbus_message_append_args(msg,
                                   DBUS_TYPE_UINT16, &version,
                                   DBUS_TYPE_UINT32, &id,
                                   DBUS_TYPE_INVALID);
    if (!ret) {
        DEBUG(1, ("Failed to build message\n"));
        return EIO;
    }

    retval = sbus_conn_send(conn, msg, 30000, dp_id_callback, NULL, NULL);

    dbus_message_unref(msg);
    return retval;
}

int proxy_child_process_init(TALLOC_CTX *mem_ctx, const char *domain,
                             struct tevent_context *ev, struct confdb_ctx *cdb,
                             const char *pam_target, uint32_t id)
{
    struct pc_ctx *ctx;
    int ret;

    ctx = talloc_zero(mem_ctx, struct pc_ctx);
    if (!ctx) {
        DEBUG(0, ("fatal error initializing pc_ctx\n"));
        return ENOMEM;
    }
    ctx->ev = ev;
    ctx->cdb = cdb;
    ctx->pam_target = talloc_steal(ctx, pam_target);
    ctx->id = id;
    ctx->conf_path = talloc_asprintf(ctx, CONFDB_DOMAIN_PATH_TMPL, domain);
    if (!ctx->conf_path) {
        DEBUG(0, ("Out of memory!?\n"));
        return ENOMEM;
    }

    ret = confdb_get_domain(cdb, domain, &ctx->domain);
    if (ret != EOK) {
        DEBUG(0, ("fatal error retrieving domain configuration\n"));
        return ret;
    }

    ret = proxy_cli_init(ctx);
    if (ret != EOK) {
        DEBUG(0, ("fatal error setting up server bus\n"));
        return ret;
    }

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *domain = NULL;
    char *srv_name = NULL;
    char *conf_entry = NULL;
    struct main_context *main_ctx;
    int ret;
    long id;
    char *pam_target = NULL;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        {"domain", 0, POPT_ARG_STRING, &domain, 0,
         _("Domain of the information provider (mandatory)"), NULL },
        {"id", 0, POPT_ARG_LONG, &id, 0,
         _("Child identifier (mandatory)"), NULL },
        POPT_TABLEEND
    };

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


    /* set up things like debug , signals, daemonization, etc... */
    debug_log_file = talloc_asprintf(NULL, "proxy_child_%s", domain);
    if (!debug_log_file) return 2;

    srv_name = talloc_asprintf(NULL, "sssd[proxy_child[%s]]", domain);
    if (!srv_name) return 2;

    conf_entry = talloc_asprintf(NULL, CONFDB_DOMAIN_PATH_TMPL, domain);
    if (!conf_entry) return 2;

    ret = server_setup(srv_name, 0, conf_entry, &main_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up mainloop [%d]\n", ret));
        return 2;
    }

    ret = unsetenv("_SSS_LOOPS");
    if (ret != EOK) {
        DEBUG(1, ("Failed to unset _SSS_LOOPS, "
                  "pam modules might not work as expected.\n"));
    }

    ret = confdb_get_string(main_ctx->confdb_ctx, main_ctx, conf_entry,
                            CONFDB_PROXY_PAM_TARGET, NULL, &pam_target);
    if (ret != EOK) {
        DEBUG(0, ("Error reading from confdb (%d) [%s]\n",
                  ret, strerror(ret)));
        return 4;
    }
    if (pam_target == NULL) {
        DEBUG(1, ("Missing option proxy_pam_target.\n"));
        return 4;
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    ret = proxy_child_process_init(main_ctx, domain, main_ctx->event_ctx,
                                   main_ctx->confdb_ctx, pam_target,
                                   (uint32_t)id);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize proxy child [%d].\n", ret));
        return 3;
    }

    DEBUG(1, ("Proxy child for domain [%s] started!\n", domain));

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
