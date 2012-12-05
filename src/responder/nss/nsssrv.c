/*
   SSSD

   NSS Responder

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

#include "popt.h"
#include "util/util.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_private.h"
#include "responder/nss/nsssrv_mmap_cache.h"
#include "responder/common/negcache.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"
#include "sbus/sbus_client.h"

#define DEFAULT_PWFIELD "*"
#define DEFAULT_NSS_FD_LIMIT 8192

#define SHELL_REALLOC_INCREMENT 5
#define SHELL_REALLOC_MAX       50

static int nss_clear_memcache(DBusMessage *message,
                              struct sbus_connection *conn);

struct sbus_method monitor_nss_methods[] = {
    { MON_CLI_METHOD_PING, monitor_common_pong },
    { MON_CLI_METHOD_RES_INIT, monitor_common_res_init },
    { MON_CLI_METHOD_ROTATE, responder_logrotate },
    { MON_CLI_METHOD_CLEAR_MEMCACHE, nss_clear_memcache},
    { NULL, NULL }
};

struct sbus_interface monitor_nss_interface = {
    MONITOR_INTERFACE,
    MONITOR_PATH,
    SBUS_DEFAULT_VTABLE,
    monitor_nss_methods,
    NULL
};

static int nss_clear_memcache(DBusMessage *message,
                              struct sbus_connection *conn)
{
    errno_t ret;
    int memcache_timeout;
    struct resp_ctx *rctx = talloc_get_type(sbus_conn_get_private_data(conn),
                                            struct resp_ctx);
    struct nss_ctx *nctx = (struct nss_ctx*) rctx->pvt_ctx;

    ret = unlink(SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG);
    if (ret != 0) {
        ret = errno;
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("CLEAR_MC_FLAG not found. Nothing to do.\n"));
            goto done;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to unlink file: %s.\n",
                  strerror(ret)));
            return ret;
        }
    }

    /* CLEAR_MC_FLAG removed successfully. Clearing memory caches. */

    ret = confdb_get_int(rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_MEMCACHE_TIMEOUT,
                         300, &memcache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Unable to get memory cache entry timeout.\n"));
        return ret;
    }

    /* TODO: read cache sizes from configuration */
    DEBUG(SSSDBG_TRACE_FUNC, ("Clearing memory caches.\n"));
    ret = sss_mmap_cache_reinit(nctx, SSS_MC_CACHE_ELEMENTS,
                                (time_t) memcache_timeout,
                                &nctx->pwd_mc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("passwd mmap cache invalidation failed\n"));
        return ret;
    }

    ret = sss_mmap_cache_reinit(nctx, SSS_MC_CACHE_ELEMENTS,
                                (time_t) memcache_timeout,
                                &nctx->grp_mc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("group mmap cache invalidation failed\n"));
        return ret;
    }

done:
    return monitor_common_pong(message, conn);
}

static errno_t nss_get_etc_shells(TALLOC_CTX *mem_ctx, char ***_shells)
{
    int i = 0;
    char *sh;
    char **shells = NULL;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    int size;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    shells = talloc_array(tmp_ctx, char *, SHELL_REALLOC_INCREMENT);
    if (!shells) {
        ret = ENOMEM;
        goto done;
    }
    size = SHELL_REALLOC_INCREMENT;

    setusershell();
    while ((sh = getusershell())) {
        shells[i] = talloc_strdup(shells, sh);
        if (!shells[i]) {
            endusershell();
            ret = ENOMEM;
            goto done;
        }
        DEBUG(6, ("Found shell %s in /etc/shells\n", shells[i]));
        i++;

        if (i == size) {
            size += SHELL_REALLOC_INCREMENT;
            if (size > SHELL_REALLOC_MAX) {
                DEBUG(0, ("Reached maximum number of shells [%d]. "
                          "Users may be denied access. "
                          "Please check /etc/shells for sanity\n",
                          SHELL_REALLOC_MAX));
                break;
            }
            shells = talloc_realloc(NULL, shells, char *,
                                    size);
            if (!shells) {
                ret = ENOMEM;
                goto done;
            }
        }
    }
    endusershell();

    if (i + 1 < size) {
        shells = talloc_realloc(NULL, shells, char *, i + 1);
        if (!shells) {
            ret = ENOMEM;
            goto done;
        }
    }
    shells[i] = NULL;

    *_shells = talloc_move(mem_ctx, &shells);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static int nss_get_config(struct nss_ctx *nctx,
                          struct confdb_ctx *cdb)
{
    int ret;

    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENUM_CACHE_TIMEOUT, 120,
                         &nctx->enum_cache_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENTRY_NEG_TIMEOUT, 15,
                         &nctx->neg_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_bool(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_FILTER_USERS_IN_GROUPS, true,
                         &nctx->filter_users_in_groups);
    if (ret != EOK) goto done;

    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENTRY_CACHE_NOWAIT_PERCENTAGE, 50,
                         &nctx->cache_refresh_percent);
    if (ret != EOK) goto done;
    if (nctx->cache_refresh_percent < 0 ||
        nctx->cache_refresh_percent > 99) {
        DEBUG(0,("Configuration error: entry_cache_nowait_percentage is "
                 "invalid. Disabling feature.\n"));
        nctx->cache_refresh_percent = 0;
    }

    ret = sss_ncache_prepopulate(nctx->ncache, cdb, nctx->rctx);
    if (ret != EOK) {
        goto done;
    }

    ret = confdb_get_string(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_PWFIELD, DEFAULT_PWFIELD,
                            &nctx->pwfield);
    if (ret != EOK) goto done;

    ret = confdb_get_string(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_OVERRIDE_HOMEDIR, NULL,
                            &nctx->override_homedir);
    if (ret != EOK) goto done;

    ret = confdb_get_string(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_FALLBACK_HOMEDIR, NULL,
                            &nctx->fallback_homedir);
    if (ret != EOK) goto done;

    ret = confdb_get_string(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_OVERRIDE_SHELL, NULL,
                            &nctx->override_shell);
    if (ret != EOK && ret != ENOENT) goto done;

    ret = confdb_get_string_as_list(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_ALLOWED_SHELL,
                                    &nctx->allowed_shells);
    if (ret != EOK && ret != ENOENT) goto done;

    ret = confdb_get_string_as_list(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_VETOED_SHELL,
                                    &nctx->vetoed_shells);
    if (ret != EOK && ret != ENOENT) goto done;

    ret = nss_get_etc_shells(nctx, &nctx->etc_shells);
    if (ret != EOK) goto done;

    ret = confdb_get_string(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_SHELL_FALLBACK,
                            CONFDB_DEFAULT_SHELL_FALLBACK,
                            &nctx->shell_fallback);
    if (ret != EOK) goto done;

    ret = confdb_get_string(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_NSS_DEFAULT_SHELL,
                            NULL,
                            &nctx->default_shell);
    if (ret != EOK) goto done;

    ret = 0;
done:
    return ret;
}

static int nss_update_memcache(DBusMessage *message,
                               struct sbus_connection *conn)
{
    struct resp_ctx *rctx = talloc_get_type(sbus_conn_get_private_data(conn),
                                            struct resp_ctx);
    struct nss_ctx *nctx = talloc_get_type(rctx->pvt_ctx, struct nss_ctx);

    nss_update_pw_memcache(nctx);
    nss_update_gr_memcache(nctx);

    return EOK;
}

static int nss_memcache_initgr_check(DBusMessage *message,
                                     struct sbus_connection *conn)
{
    struct resp_ctx *rctx = talloc_get_type(sbus_conn_get_private_data(conn),
                                            struct resp_ctx);
    struct nss_ctx *nctx = talloc_get_type(rctx->pvt_ctx, struct nss_ctx);
    DBusError dbus_error;
    dbus_bool_t dbret;
    DBusMessage *reply;
    char *user;
    char *domain;
    uint32_t *groups;
    int gnum;

    dbus_error_init(&dbus_error);

    dbret = dbus_message_get_args(message, &dbus_error,
                                  DBUS_TYPE_STRING, &user,
                                  DBUS_TYPE_STRING, &domain,
                                  DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
                                  &groups, &gnum,
                                  DBUS_TYPE_INVALID);

    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed, to parse message!\n"));
        if (dbus_error_is_set(&dbus_error)) {
            dbus_error_free(&dbus_error);
        }
        return EIO;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          ("Got request for [%s@%s]\n", user, domain));

    nss_update_initgr_memcache(nctx, user, domain, gnum, groups);

    reply = dbus_message_new_method_return(message);
    if (!reply) return ENOMEM;

    dbret = dbus_message_append_args(reply, DBUS_TYPE_INVALID);
    if (!dbret) {
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    return EOK;
}

static struct sbus_method nss_dp_methods[] = {
    { DP_REV_METHOD_UPDATE_CACHE, nss_update_memcache },
    { DP_REV_METHOD_INITGR_CHECK, nss_memcache_initgr_check },
    { NULL, NULL }
};

struct sbus_interface nss_dp_interface = {
    DP_INTERFACE,
    DP_PATH,
    SBUS_DEFAULT_VTABLE,
    nss_dp_methods,
    NULL
};


static void nss_dp_reconnect_init(struct sbus_connection *conn,
                                  int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(1, ("Reconnected to the Data Provider.\n"));

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "NSS");
        /* all fine */
        if (ret == EOK) {
            handle_requests_after_reconnect(be_conn->rctx);
            return;
        }
    }

    /* Failed to reconnect */
    DEBUG(0, ("Could not reconnect to %s provider.\n",
              be_conn->domain->name));

    /* FIXME: kill the frontend and let the monitor restart it ? */
    /* nss_shutdown(rctx); */
}

int nss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb)
{
    struct sss_cmd_table *nss_cmds;
    struct be_conn *iter;
    struct nss_ctx *nctx;
    int memcache_timeout;
    int ret, max_retries;
    int hret;
    int fd_limit;

    nctx = talloc_zero(mem_ctx, struct nss_ctx);
    if (!nctx) {
        DEBUG(0, ("fatal error initializing nss_ctx\n"));
        return ENOMEM;
    }

    ret = sss_ncache_init(nctx, &nctx->ncache);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing negative cache\n"));
        return ret;
    }

    nss_cmds = get_nss_cmds();

    ret = sss_process_init(nctx, ev, cdb,
                           nss_cmds,
                           SSS_NSS_SOCKET_NAME, NULL,
                           CONFDB_NSS_CONF_ENTRY,
                           NSS_SBUS_SERVICE_NAME,
                           NSS_SBUS_SERVICE_VERSION,
                           &monitor_nss_interface,
                           "NSS", &nss_dp_interface,
                           &nctx->rctx);
    if (ret != EOK) {
        return ret;
    }
    nctx->rctx->pvt_ctx = nctx;

    ret = nss_get_config(nctx, cdb);
    if (ret != EOK) {
        DEBUG(0, ("fatal error getting nss config\n"));
        return ret;
    }

    /* Enable automatic reconnection to the Data Provider */
    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES,
                         3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        return ret;
    }

    for (iter = nctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            nss_dp_reconnect_init, iter);
    }

    /* Create the lookup table for netgroup results */
    hret = sss_hash_create(nctx, 10, &nctx->netgroups);
    if (hret != HASH_SUCCESS) {
        DEBUG(0,("Unable to initialize netgroup hash table\n"));
        return EIO;
    }

    /* create mmap caches */
    /* Remove the CLEAR_MC_FLAG file if exists. */
    ret = unlink(SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG);
    if (ret != 0 && errno != ENOENT) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Failed to unlink file [%s]. This can cause memory cache to "
               "be purged when next log rotation is requested. %d: %s\n",
               SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG, ret, strerror(ret)));
    }

    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_MEMCACHE_TIMEOUT,
                         300, &memcache_timeout);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        return ret;
    }

    /* TODO: read cache sizes from configuration */
    ret = sss_mmap_cache_init(nctx, "passwd", SSS_MC_PASSWD,
                              SSS_MC_CACHE_ELEMENTS, (time_t)memcache_timeout,
                              &nctx->pwd_mc_ctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("passwd mmap cache is DISABLED\n"));
    }

    ret = sss_mmap_cache_init(nctx, "group", SSS_MC_GROUP,
                              SSS_MC_CACHE_ELEMENTS, (time_t)memcache_timeout,
                              &nctx->grp_mc_ctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("group mmap cache is DISABLED\n"));
    }

    /* Set up file descriptor limits */
    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_NSS_FD_LIMIT,
                         &fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Failed to set up file descriptor limit\n"));
        return ret;
    }
    responder_set_fd_limit(fd_limit);

    DEBUG(SSSDBG_TRACE_FUNC, ("NSS Initialization complete\n"));

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    poptFreeContext(pc);

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_nss";

    ret = server_setup("sssd[nss]", 0, CONFDB_NSS_CONF_ENTRY, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    ret = nss_process_init(main_ctx,
                           main_ctx->event_ctx,
                           main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

