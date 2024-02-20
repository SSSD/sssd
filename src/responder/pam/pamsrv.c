/*
   SSSD

   PAM Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2009
   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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
#include <popt.h>
#include <dbus/dbus.h>

#include "config.h"
#include "util/util.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"
#include "responder/common/negcache.h"
#include "sss_iface/sss_iface_async.h"

#define DEFAULT_PAM_FD_LIMIT 8192
#define ALL_UIDS_ALLOWED "all"
#define ALL_DOMAINS_ARE_PUBLIC "all"
#define NO_DOMAINS_ARE_PUBLIC "none"
#define DEFAULT_ALLOWED_UIDS ALL_UIDS_ALLOWED
#define DEFAULT_PAM_CERT_AUTH false
#define DEFAULT_PAM_PASSKEY_AUTH true
#define DEFAULT_PAM_CERT_DB_PATH SYSCONFDIR"/sssd/pki/sssd_auth_ca_db.pem"
#define DEFAULT_PAM_INITGROUPS_SCHEME "no_session"

static errno_t get_trusted_uids(struct pam_ctx *pctx)
{
    char *uid_str;
    errno_t ret;

    ret = confdb_get_string(pctx->rctx->cdb, pctx->rctx,
                            CONFDB_PAM_CONF_ENTRY, CONFDB_PAM_TRUSTED_USERS,
                            DEFAULT_ALLOWED_UIDS, &uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get allowed UIDs.\n");
        goto done;
    }

    if (strcmp(uid_str, ALL_UIDS_ALLOWED) == 0) {
         DEBUG(SSSDBG_TRACE_FUNC, "All UIDs are allowed.\n");
         pctx->trusted_uids_count = 0;
    } else {
        ret = csv_string_to_uid_array(pctx->rctx, uid_str,
                                      &pctx->trusted_uids_count,
                                      &pctx->trusted_uids);
    }

    talloc_free(uid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to set allowed UIDs.\n");
        goto done;
    }

done:
    return ret;
}

static errno_t get_public_domains(struct pam_ctx *pctx)
{
    char *domains_str = NULL;
    errno_t ret;

    ret = confdb_get_string(pctx->rctx->cdb, pctx->rctx,
                            CONFDB_PAM_CONF_ENTRY, CONFDB_PAM_PUBLIC_DOMAINS,
                            NO_DOMAINS_ARE_PUBLIC, &domains_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get allowed UIDs.\n");
        goto done;
    }

    if (strcmp(domains_str, ALL_DOMAINS_ARE_PUBLIC) == 0) { /* all */
        /* copy all domains */
        ret = get_dom_names(pctx,
                            pctx->rctx->domains,
                            &pctx->public_domains,
                            &pctx->public_domains_count);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "get_dom_names failed.\n");
            goto done;
        }
    } else if (strcmp(domains_str, NO_DOMAINS_ARE_PUBLIC) == 0) { /* none */
        pctx->public_domains = NULL;
        pctx->public_domains_count = 0;
    } else {
        ret = split_on_separator(pctx, domains_str, ',', true, false,
                                 &pctx->public_domains,
                                 &pctx->public_domains_count);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed [%d][%s].\n",
                  ret, strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(domains_str);
    return ret;
}

static errno_t get_app_services(struct pam_ctx *pctx)
{
    errno_t ret;

    ret = confdb_get_string_as_list(pctx->rctx->cdb, pctx,
                                    CONFDB_PAM_CONF_ENTRY,
                                    CONFDB_PAM_APP_SERVICES,
                                    &pctx->app_services);
    if (ret == ENOENT) {
        pctx->app_services = talloc_zero_array(pctx, char *, 1);
        if (pctx->app_services == NULL) {
            return ENOMEM;
        }
        /* Allocating an empty array makes it easier for the consumer
         * to iterate over it
         */
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot read "CONFDB_PAM_APP_SERVICES" [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static void pam_get_domains_callback(void *pvt)
{
    struct pam_ctx *pctx;
    int ret;

    pctx = talloc_get_type(pvt, struct pam_ctx);
    ret = p11_refresh_certmap_ctx(pctx, pctx->rctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_refresh_certmap_ctx failed.\n");
    }
}

static int pam_process_init(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *pam_cmds;
    struct pam_ctx *pctx;
    int ret;
    int id_timeout;
    int fd_limit;
    char *tmpstr = NULL;

    pam_cmds = get_pam_cmds();
    ret = sss_process_init(mem_ctx, ev, cdb,
                           pam_cmds,
                           SSS_PAM_SOCKET_NAME, SCKT_RSP_UMASK,
                           CONFDB_PAM_CONF_ENTRY,
                           SSS_BUS_PAM, SSS_PAM_SBUS_SERVICE_NAME,
                           sss_connection_setup,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_process_init() failed\n");
        return ret;
    }

    pctx = talloc_zero(rctx, struct pam_ctx);
    if (!pctx) {
        ret = ENOMEM;
        goto done;
    }

    pctx->rctx = rctx;
    pctx->rctx->pvt_ctx = pctx;

    ret = get_trusted_uids(pctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "get_trusted_uids failed: %d:[%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = get_public_domains(pctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "get_public_domains failed: %d:[%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = get_app_services(pctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "get_app_services failed: %d:[%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Set up the PAM identity timeout */
    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_ID_TIMEOUT, 5,
                         &id_timeout);
    if (ret != EOK) goto done;

    pctx->id_timeout = (size_t)id_timeout;

    ret = sss_ncache_prepopulate(pctx->rctx->ncache, cdb, pctx->rctx);
    if (ret != EOK) {
        goto done;
    }

    /* Create table for initgroup lookups */
    ret = sss_hash_create(pctx, 0, &pctx->id_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not create initgroups hash table: [%s]\n",
              strerror(ret));
        goto done;
    }

    /* Set up file descriptor limits */
    ret = confdb_get_int(pctx->rctx->cdb,
                         CONFDB_PAM_CONF_ENTRY,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_PAM_FD_LIMIT,
                         &fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to set up file descriptor limit\n");
        goto done;
    }
    responder_set_fd_limit(fd_limit);

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx, pctx->rctx->ncache,
                                    pam_get_domains_callback, pctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "schedule_get_domains_tasks failed.\n");
        goto done;
    }

    /* Check if there is a prompting configuration */
    pctx->prompting_config_sections = NULL;
    pctx->num_prompting_config_sections = 0;
    ret = confdb_get_sub_sections(pctx, pctx->rctx->cdb, CONFDB_PC_CONF_ENTRY,
                                  &pctx->prompting_config_sections,
                                  &pctx->num_prompting_config_sections);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "confdb_get_sub_sections failed, not fatal.\n");
    }

    /* Check if certificate based authentication is enabled */
    ret = confdb_get_bool(pctx->rctx->cdb,
                          CONFDB_PAM_CONF_ENTRY,
                          CONFDB_PAM_CERT_AUTH,
                          DEFAULT_PAM_CERT_AUTH,
                          &pctx->cert_auth);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to determine get cert db path.\n");
        goto done;
    }

    if (pctx->cert_auth) {
        ret = p11_child_init(pctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "p11_child_init failed.\n");
            goto done;
        }

        ret = confdb_get_string(pctx->rctx->cdb, pctx,
                                CONFDB_PAM_CONF_ENTRY,
                                CONFDB_PAM_CERT_DB_PATH,
                                DEFAULT_PAM_CERT_DB_PATH,
                                &pctx->ca_db);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to determine if certificate based authentication is " \
                  "enabled or not.\n");
            goto done;
        }

    }

    /* Check if passkey authentication is enabled */
    ret = confdb_get_bool(pctx->rctx->cdb,
                          CONFDB_PAM_CONF_ENTRY,
                          CONFDB_PAM_PASSKEY_AUTH,
                          DEFAULT_PAM_PASSKEY_AUTH,
                          &pctx->passkey_auth);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to check if passkey authentication is " \
                                    "enabled.\n");
        goto done;
    }

    if (pctx->cert_auth
        || pctx->passkey_auth
        || pctx->num_prompting_config_sections != 0) {
        ret = create_preauth_indicator();
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to create pre-authentication indicator file, "
                  "Smartcard/passkey authentication or configured prompting might "
                  "not work as expected.\n");
        }
    }

    ret = confdb_get_string(pctx->rctx->cdb, pctx, CONFDB_PAM_CONF_ENTRY,
                            CONFDB_PAM_INITGROUPS_SCHEME,
                            DEFAULT_PAM_INITGROUPS_SCHEME, &tmpstr);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to determine initgroups scheme.\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found value [%s] for option [%s].\n", tmpstr,
                                 CONFDB_PAM_INITGROUPS_SCHEME);

    if (tmpstr == NULL) {
        pctx->initgroups_scheme = PAM_INITGR_NO_SESSION;
    } else {
        pctx->initgroups_scheme = pam_initgroups_string_to_enum(tmpstr);
        if (pctx->initgroups_scheme == PAM_INITGR_INVALID) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Unknown value [%s] for option %s.\n",
                                        tmpstr, CONFDB_PAM_INITGROUPS_SCHEME);
            ret = EINVAL;
            goto done;
        }
    }

    ret = confdb_get_string(pctx->rctx->cdb, pctx, CONFDB_PAM_CONF_ENTRY,
                            CONFDB_PAM_GSSAPI_SERVICES, "-", &tmpstr);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to determine gssapi services.\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found value [%s] for option [%s].\n", tmpstr,
                                 CONFDB_PAM_GSSAPI_SERVICES);

    if (tmpstr != NULL) {
        ret = split_on_separator(pctx, tmpstr, ',', true, true,
                                 &pctx->gssapi_services, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "split_on_separator() failed [%d]: [%s].\n", ret,
                  sss_strerror(ret));
            goto done;
        }
    }

    ret = confdb_get_bool(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                          CONFDB_PAM_GSSAPI_CHECK_UPN, true,
                          &pctx->gssapi_check_upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to read %s [%d]: %s\n",
              CONFDB_PAM_GSSAPI_CHECK_UPN, ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_string(pctx->rctx->cdb, pctx, CONFDB_PAM_CONF_ENTRY,
                            CONFDB_PAM_GSSAPI_INDICATORS_MAP, "-", &tmpstr);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to determine gssapi services.\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found value [%s] for option [%s].\n", tmpstr,
                                 CONFDB_PAM_GSSAPI_INDICATORS_MAP);

    if (tmpstr != NULL) {
        ret = split_on_separator(pctx, tmpstr, ',', true, true,
                                 &pctx->gssapi_indicators_map, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "split_on_separator() failed [%d]: [%s].\n", ret,
                  sss_strerror(ret));
            goto done;
        }
    }

    /* Check if JSON authentication selection method is enabled for any PAM
     * services
     */
    ret = confdb_get_string(pctx->rctx->cdb, pctx, CONFDB_PAM_CONF_ENTRY,
                            CONFDB_PAM_JSON_SERVICES, "-", &tmpstr);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to determine json services.\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found value [%s] for option [%s].\n", tmpstr,
          CONFDB_PAM_JSON_SERVICES);

    if (tmpstr != NULL) {
        ret = split_on_separator(pctx, tmpstr, ',', true, true,
                                 &pctx->json_services, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "split_on_separator() failed [%d]: [%s].\n", ret,
                  sss_strerror(ret));
            goto done;
        }
    }

    /* The responder is initialized. Now tell it to the monitor. */
    ret = sss_monitor_register_service(rctx, rctx->sbus_conn,
                                       SSS_PAM_SBUS_SERVICE_NAME,
                                       SSS_PAM_SBUS_SERVICE_VERSION,
                                       MT_SVC_SERVICE);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register to the monitor "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_resp_register_service_iface(rctx);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(rctx);
    }
    return ret;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *opt_logger = NULL;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_LOGGER_OPTS
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
    debug_log_file = "sssd_pam";
    DEBUG_INIT(debug_level, opt_logger);

    ret = server_setup("pam", true, 0, CONFDB_FILE,
                       CONFDB_PAM_CONF_ENTRY, &main_ctx, false);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = pam_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

