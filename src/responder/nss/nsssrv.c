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
#include <popt.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "util/mmap_cache.h"
#include "responder/nss/nss_private.h"
#include "responder/nss/nss_iface.h"
#include "responder/nss/nsssrv_mmap_cache.h"
#include "responder/common/negcache.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "util/util_sss_idmap.h"
#include "sss_iface/sss_iface_async.h"

#define DEFAULT_PWFIELD "*"
#define DEFAULT_NSS_FD_LIMIT 8192

static errno_t
sss_nss_clear_memcache(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct sss_nss_ctx *nctx)
{
    int memcache_timeout;
    errno_t ret;

    if (access(SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG, F_OK) < 0) {
        ret = errno;
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "CLEAR_MC_FLAG not found. Nothing to do.\n");
            return EOK; /* Most probably log rotation SIGHUP to monitor */
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to check existence of "CLEAR_MC_FLAG": %s.\n",
                  strerror(ret));
            return ret;
        }
    }

    /*
     * CLEAR_MC_FLAG flag file found.
     * This file existance indicates that SIGHUP was called by sss_cache
     * as trigger for the memory cache cleanup.
     * sss_cache is waiting for CLEAR_MC_FLAG file deletion
     * as confirmation that memory cache cleaning has finished.
     */

    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_MEMCACHE_TIMEOUT,
                         300, &memcache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to get memory cache entry timeout [%s].\n",
              CONFDB_MEMCACHE_TIMEOUT);
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Clearing memory caches.\n");
    ret = sss_mmap_cache_reinit(nctx, nctx->mc_uid, nctx->mc_gid,
                                -1, /* keep current size */
                                (time_t) memcache_timeout,
                                &nctx->pwd_mc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "passwd mmap cache invalidation failed\n");
        goto done;
    }

    ret = sss_mmap_cache_reinit(nctx, nctx->mc_uid, nctx->mc_gid,
                                -1, /* keep current size */
                                (time_t) memcache_timeout,
                                &nctx->grp_mc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "group mmap cache invalidation failed\n");
        goto done;
    }

    ret = sss_mmap_cache_reinit(nctx, nctx->mc_uid, nctx->mc_gid,
                                -1, /* keep current size */
                                (time_t)memcache_timeout,
                                &nctx->initgr_mc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "initgroups mmap cache invalidation failed\n");
        goto done;
    }

done:
    if (unlink(SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG) != 0) {
        if (errno != ENOENT)
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to unlink file: %s.\n",
                  strerror(errno));
    }
    return ret;
}

static errno_t
sss_nss_clear_negcache(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct sss_nss_ctx *nctx)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Clearing negative cache non-permament entries\n");

    ret = sss_ncache_reset_users(nctx->rctx->ncache);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Negative cache clearing users failed\n");
        goto done;
    }

    ret = sss_ncache_reset_groups(nctx->rctx->ncache);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Negative cache clearing groups failed\n");
        goto done;
    }

done:
    return ret;
}

static errno_t
sss_nss_clear_netgroup_hash_table(TALLOC_CTX *mem_ctx,
                                  struct sbus_request *sbus_req,
                                  struct sss_nss_ctx *nss_ctx)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Invalidating netgroup hash table\n");

    sss_ptr_hash_delete_all(nss_ctx->netgrent, false);

    return EOK;
}

static int sss_nss_get_config(struct sss_nss_ctx *nctx,
                              struct confdb_ctx *cdb)
{
    int ret;
    char *tmp_str;

    ret = confdb_get_int(cdb, CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_ENUM_CACHE_TIMEOUT, 120,
                         &nctx->enum_cache_timeout);
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Configuration error: entry_cache_nowait_percentage is "
                 "invalid. Disabling feature.\n");
        nctx->cache_refresh_percent = 0;
    }

    ret = sss_ncache_prepopulate(nctx->rctx->ncache, cdb, nctx->rctx);
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
                            CONFDB_NSS_HOMEDIR_SUBSTRING,
                            CONFDB_DEFAULT_HOMEDIR_SUBSTRING,
                            &nctx->homedir_substr);
    if (ret != EOK) goto done;


    ret = confdb_get_string(cdb, nctx, CONFDB_NSS_CONF_ENTRY,
                            CONFDB_IFP_USER_ATTR_LIST, NULL, &tmp_str);
    if (ret != EOK) goto done;

    if (tmp_str == NULL) {
        ret = confdb_get_string(cdb, nctx, CONFDB_IFP_CONF_ENTRY,
                                CONFDB_IFP_USER_ATTR_LIST, NULL, &tmp_str);
        if (ret != EOK) goto done;
    }

    if (tmp_str != NULL) {
        nctx->extra_attributes = parse_attr_list_ex(nctx, tmp_str, NULL);
        if (nctx->extra_attributes == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = 0;
done:
    return ret;
}

static int setup_memcaches(struct sss_nss_ctx *nctx)
{
    /* Default memcache sizes */
    static const size_t SSS_MC_CACHE_SLOTS_PER_MB   = 1024*1024/MC_SLOT_SIZE;
    static const size_t SSS_MC_CACHE_PASSWD_SIZE    =  8;
    static const size_t SSS_MC_CACHE_GROUP_SIZE     =  6;
    static const size_t SSS_MC_CACHE_INITGROUP_SIZE = 10;
    static const size_t SSS_MC_CACHE_SID_SIZE       =  6;

    int ret;
    int memcache_timeout;
    int mc_size_passwd;
    int mc_size_group;
    int mc_size_initgroups;
    int mc_size_sid;

    /* Remove the CLEAR_MC_FLAG file if exists. */
    ret = unlink(SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG);
    if (ret != 0 && errno != ENOENT) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unlink file [%s]. This can cause memory cache to "
               "be purged when next log rotation is requested. %d: %s\n",
               SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG, ret, strerror(ret));
    }

    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_MEMCACHE_TIMEOUT,
                         300, &memcache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get 'memcache_timeout' option from confdb.\n");
        return ret;
    }

    /* Get all memcache sizes from confdb (pwd, grp, initgr, sid) */

    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_MEMCACHE_SIZE_PASSWD,
                         SSS_MC_CACHE_PASSWD_SIZE,
                         &mc_size_passwd);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get '"CONFDB_NSS_MEMCACHE_SIZE_PASSWD
              "' option from confdb.\n");
        return ret;
    }

    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_MEMCACHE_SIZE_GROUP,
                         SSS_MC_CACHE_GROUP_SIZE,
                         &mc_size_group);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get '"CONFDB_NSS_MEMCACHE_SIZE_GROUP
              "' option from confdb.\n");
        return ret;
    }

    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_MEMCACHE_SIZE_INITGROUPS,
                         SSS_MC_CACHE_INITGROUP_SIZE,
                         &mc_size_initgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get '"CONFDB_NSS_MEMCACHE_SIZE_INITGROUPS
              "' option from confdb.\n");
        return ret;
    }

    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_NSS_MEMCACHE_SIZE_SID,
                         SSS_MC_CACHE_SID_SIZE,
                         &mc_size_sid);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get '"CONFDB_NSS_MEMCACHE_SIZE_SID
              "' option from confdb.\n");
        return ret;
    }

    /* Initialize the fast in-memory caches if they were not disabled */

    ret = sss_mmap_cache_init(nctx, "passwd",
                              nctx->mc_uid, nctx->mc_gid,
                              SSS_MC_PASSWD,
                              mc_size_passwd * SSS_MC_CACHE_SLOTS_PER_MB,
                              (time_t)memcache_timeout,
                              &nctx->pwd_mc_ctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize passwd mmap cache: '%s'\n",
              sss_strerror(ret));
    }

    ret = sss_mmap_cache_init(nctx, "group",
                              nctx->mc_uid, nctx->mc_gid,
                              SSS_MC_GROUP,
                              mc_size_group * SSS_MC_CACHE_SLOTS_PER_MB,
                              (time_t)memcache_timeout,
                              &nctx->grp_mc_ctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize group mmap cache: '%s'\n",
              sss_strerror(ret));
    }

    ret = sss_mmap_cache_init(nctx, "initgroups",
                              nctx->mc_uid, nctx->mc_gid,
                              SSS_MC_INITGROUPS,
                              mc_size_initgroups * SSS_MC_CACHE_SLOTS_PER_MB,
                              (time_t)memcache_timeout,
                              &nctx->initgr_mc_ctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize initgroups mmap cache: '%s'\n",
              sss_strerror(ret));
    }

    ret = sss_mmap_cache_init(nctx, "sid",
                              nctx->mc_uid, nctx->mc_gid,
                              SSS_MC_SID,
                              mc_size_sid * SSS_MC_CACHE_SLOTS_PER_MB,
                              (time_t)memcache_timeout,
                              &nctx->sid_mc_ctx);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize sid mmap cache: '%s'\n",
              sss_strerror(ret));
    }

    return EOK;
}

static errno_t
sss_nss_register_service_iface(struct sss_nss_ctx *nss_ctx,
                           struct resp_ctx *rctx)
{
    errno_t ret;

    SBUS_INTERFACE(iface_svc,
        sssd_service,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_service, rotateLogs, responder_logrotate, rctx),
            SBUS_SYNC(METHOD, sssd_service, clearEnumCache, sss_nss_clear_netgroup_hash_table, nss_ctx),
            SBUS_SYNC(METHOD, sssd_service, clearMemcache, sss_nss_clear_memcache, nss_ctx),
            SBUS_SYNC(METHOD, sssd_service, clearNegcache, sss_nss_clear_negcache, nss_ctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(
            SBUS_SYNC(GETTER, sssd_service, debug_level, generic_get_debug_level, NULL),
            SBUS_SYNC(SETTER, sssd_service, debug_level, generic_set_debug_level, NULL)
        )
    );

    ret = sbus_connection_add_path(rctx->mon_conn, SSS_BUS_PATH, &iface_svc);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to register service interface"
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    return ret;
}

static int sssd_supplementary_group(struct sss_nss_ctx *nss_ctx)
{
    errno_t ret;
    int size;
    gid_t *supp_gids = NULL;

    /*
     * We explicitly read the IDs of the SSSD user even though the server
     * receives --uid and --gid by parameters to account for the case where
     * the SSSD is compiled --with-sssd-user=sssd but the default of the
     * user option is root (this is what RHEL does)
     */
    ret = sss_user_by_name_or_uid(SSSD_USER,
                                  &nss_ctx->mc_uid,
                                  &nss_ctx->mc_gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot get info on "SSSD_USER);
        return ret;
    }

    if (getgid() == nss_ctx->mc_gid) {
        DEBUG(SSSDBG_TRACE_FUNC, "Already running as the sssd group\n");
        return EOK;
    }

    size = getgroups(0, NULL);
    if (size == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Getgroups failed! (%d, %s)\n",
                                    ret, sss_strerror(ret));
        return ret;
    }

    if (size > 0) {
        supp_gids = talloc_zero_array(NULL, gid_t, size);
        if (supp_gids == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Allocation failed!\n");
            ret = ENOMEM;
            goto done;
        }

        size = getgroups(size, supp_gids);
        if (size == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "Getgroups failed! (%d, %s)\n",
                                        ret, sss_strerror(ret));
            goto done;
        }

        for (int i = 0; i < size; i++) {
            if (supp_gids[i] == nss_ctx->mc_gid) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Already assigned to the SSSD supplementary group\n");
                ret = EOK;
                goto done;
            }
        }
    }

    ret = setgroups(1, &nss_ctx->mc_gid);
    if (ret != EOK) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot setgroups [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(supp_gids);
    return ret;
}

int sss_nss_process_init(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct confdb_ctx *cdb)
{
    struct resp_ctx *rctx;
    struct sss_cmd_table *nss_cmds;
    struct be_conn *iter;
    struct sss_nss_ctx *nctx;
    int ret;
    enum idmap_error_code err;
    int fd_limit;

    nss_cmds = get_sss_nss_cmds();

    ret = sss_process_init(mem_ctx, ev, cdb,
                           nss_cmds,
                           SSS_NSS_SOCKET_NAME, -1, NULL, -1,
                           CONFDB_NSS_CONF_ENTRY,
                           SSS_BUS_NSS, NSS_SBUS_SERVICE_NAME,
                           sss_nss_connection_setup,
                           &rctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_process_init() failed\n");
        return ret;
    }

    nctx = talloc_zero(rctx, struct sss_nss_ctx);
    if (!nctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing nss_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    nctx->rctx = rctx;
    nctx->rctx->pvt_ctx = nctx;

    ret = sss_nss_get_config(nctx, cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error getting nss config\n");
        goto fail;
    }

    for (iter = nctx->rctx->be_conns; iter; iter = iter->next) {
        ret = sss_nss_register_backend_iface(iter->conn, nctx);
        if (ret != EOK) {
            goto fail;
        }
    }

    err = sss_idmap_init(sss_idmap_talloc, nctx, sss_idmap_talloc_free,
                         &nctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_idmap_init failed.\n");
        ret = EFAULT;
        goto fail;
    }

    nctx->pwent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    if (nctx->pwent == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize pwent context!\n");
        ret = ENOMEM;
        goto fail;
    }

    nctx->grent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    if (nctx->grent == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize grent context!\n");
        ret = ENOMEM;
        goto fail;
    }

    nctx->svcent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    if (nctx->svcent == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize svcent context!\n");
        ret = ENOMEM;
        goto fail;
    }

    nctx->netgrent = sss_ptr_hash_create(nctx, NULL, NULL);
    if (nctx->netgrent == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize netgroups table!\n");
        ret = EFAULT;
        goto fail;
    }

    nctx->hostent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    if (nctx->hostent == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize hostent context!\n");
        ret = ENOMEM;
        goto fail;
    }

    nctx->netent = talloc_zero(nctx, struct sss_nss_enum_ctx);
    if (nctx->netent == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize netent context!\n");
        ret = ENOMEM;
        goto fail;
    }

    /*
     * Adding the NSS process to the SSSD supplementary group avoids
     * dac_override AVC messages from SELinux in case sssd_nss runs
     * as root and tries to write to memcache owned by sssd:sssd
     */
    ret = sssd_supplementary_group(nctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot add process to the sssd supplementary group [%d]: %s\n",
              ret, sss_strerror(ret));
        goto fail;
    }

    ret = setup_memcaches(nctx);
    if (ret != EOK) {
        goto fail;
    }

    /* Set up file descriptor limits */
    ret = confdb_get_int(nctx->rctx->cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_SERVICE_FD_LIMIT,
                         DEFAULT_NSS_FD_LIMIT,
                         &fd_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to set up file descriptor limit\n");
        goto fail;
    }
    responder_set_fd_limit(fd_limit);

    ret = schedule_get_domains_task(rctx, rctx->ev, rctx, nctx->rctx->ncache,
                                    NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "schedule_get_domains_tasks failed.\n");
        goto fail;
    }

    /* The responder is initialized. Now tell it to the monitor. */
    ret = sss_monitor_service_init(rctx, rctx->ev, SSS_BUS_NSS,
                                   NSS_SBUS_SERVICE_NAME,
                                   NSS_SBUS_SERVICE_VERSION, MT_SVC_SERVICE,
                                   &rctx->last_request_time, &rctx->mon_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error setting up message bus\n");
        goto fail;
    }

    ret = sss_nss_register_service_iface(nctx, rctx);
    if (ret != EOK) {
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "NSS Initialization complete\n");

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
    debug_log_file = "sssd_nss";
    DEBUG_INIT(debug_level, opt_logger);

    ret = server_setup("nss", true, 0, uid, gid, CONFDB_NSS_CONF_ENTRY,
                       &main_ctx, false);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = sss_nss_process_init(main_ctx,
                               main_ctx->event_ctx,
                               main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

