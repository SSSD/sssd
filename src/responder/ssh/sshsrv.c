/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <popt.h>

#include "util/util.h"
#include "util/child_common.h"
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include "responder/ssh/ssh_private.h"
#include "providers/data_provider.h"
#include "sss_iface/sss_iface_async.h"

int ssh_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *ssh_cmds;
    struct ssh_ctx *ssh_ctx;
    int ret;

    ssh_cmds = get_ssh_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           ssh_cmds,
                           SSS_SSH_SOCKET_NAME, -1, NULL, -1,
                           CONFDB_SSH_CONF_ENTRY,
                           SSS_BUS_SSH, SSS_SSH_SBUS_SERVICE_NAME,
                           sss_connection_setup,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_process_init() failed\n");
        return ret;
    }

    ssh_ctx = talloc_zero(rctx, struct ssh_ctx);
    if (!ssh_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing ssh_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    ssh_ctx->rctx = rctx;
    ssh_ctx->rctx->pvt_ctx = ssh_ctx;

    ret = sss_names_init_from_args(ssh_ctx,
                                   SSS_DEFAULT_RE,
                                   "%1$s@%2$s", &ssh_ctx->snctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing regex data\n");
        goto fail;
    }

    /* Get responder options */

    /* Get ssh_hash_known_hosts option */
    ret = confdb_get_bool(ssh_ctx->rctx->cdb,
                          CONFDB_SSH_CONF_ENTRY, CONFDB_SSH_HASH_KNOWN_HOSTS,
                          CONFDB_DEFAULT_SSH_HASH_KNOWN_HOSTS,
                          &ssh_ctx->hash_known_hosts);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading from confdb (%d) [%s]\n",
              ret, strerror(ret));
        goto fail;
    }

    /* Get ssh_known_hosts_timeout option */
    ret = confdb_get_int(ssh_ctx->rctx->cdb,
                         CONFDB_SSH_CONF_ENTRY, CONFDB_SSH_KNOWN_HOSTS_TIMEOUT,
                         CONFDB_DEFAULT_SSH_KNOWN_HOSTS_TIMEOUT,
                         &ssh_ctx->known_hosts_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading from confdb (%d) [%s]\n",
              ret, strerror(ret));
        goto fail;
    }

    ret = confdb_get_string(ssh_ctx->rctx->cdb, ssh_ctx,
                            CONFDB_SSH_CONF_ENTRY, CONFDB_SSH_CA_DB,
                            CONFDB_DEFAULT_SSH_CA_DB, &ssh_ctx->ca_db);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading CA DB from confdb (%d) [%s]\n",
              ret, strerror(ret));
        goto fail;
    }

    ret = confdb_get_bool(ssh_ctx->rctx->cdb, CONFDB_SSH_CONF_ENTRY,
                          CONFDB_SSH_USE_CERT_KEYS,
                          CONFDB_DEFAULT_SSH_USE_CERT_KEYS,
                          &ssh_ctx->use_cert_keys);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Error reading option "
                                    CONFDB_SSH_USE_CERT_KEYS
                                    "from confdb (%d) [%s]\n",
                                    ret, strerror(ret));
        goto fail;
    }

    ret = confdb_get_string_as_list(ssh_ctx->rctx->cdb, ssh_ctx,
                                    CONFDB_SSH_CONF_ENTRY,
                                    CONFDB_SSH_USE_CERT_RULES,
                                    &ssh_ctx->cert_rules);
    if (ret == ENOENT) {
        ssh_ctx->cert_rules = NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Error reading " CONFDB_SSH_USE_CERT_RULES
                                    " from confdb (%d) [%s].\n", ret,
                                    sss_strerror(ret));
        goto fail;
    }

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx, NULL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "schedule_get_domains_tasks failed.\n");
        goto fail;
    }

    /* The responder is initialized. Now tell it to the monitor. */
    ret = sss_monitor_service_init(rctx, rctx->ev, SSS_BUS_SSH,
                                   SSS_SSH_SBUS_SERVICE_NAME,
                                   SSS_SSH_SBUS_SERVICE_VERSION,
                                   MT_SVC_SERVICE,
                                   &rctx->last_request_time, &rctx->mon_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error setting up message bus\n");
        goto fail;
    }

    ret = sss_resp_register_service_iface(rctx);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "SSH Initialization complete\n");

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
        SSSD_RESPONDER_OPTS
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
    debug_log_file = "sssd_ssh";
    DEBUG_INIT(debug_level, opt_logger);

    /* server_setup() might switch to an unprivileged user, so the permissions
     * for p11_child.log have to be fixed first. We might call p11_child to
     * validate certificates. */
    ret = chown_debug_file("p11_child", uid, gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot chown the p11_child debug file, "
              "debugging might not work!\n");
    }

    ret = server_setup("ssh", true, 0, uid, gid,
                       CONFDB_SSH_CONF_ENTRY, &main_ctx, true);
    if (ret != EOK) {
        return 2;
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE, "Could not set up to exit "
                                  "when parent process does\n");
    }

    ret = ssh_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) {
        return 3;
    }

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
