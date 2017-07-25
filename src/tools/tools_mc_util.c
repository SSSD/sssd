/*
   SSSD

   tools_mc_util - interface to the memcache for userspace tools

   Copyright (C) Red Hat                                        2013

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

#include <talloc.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "tools/tools_util.h"
#include "util/mmap_cache.h"
#include "util/sss_cli_cmd.h"
#include "sss_client/sss_cli.h"
#include "tools/common/sss_process.h"

/* This is a copy of sss_mc_set_recycled present in
 * src/responder/nss/nsssrv_mmap_cache.c. If you modify this function,
 * you should modify the original function too. */
static errno_t sss_mc_set_recycled(int fd)
{
    uint32_t w = SSS_MC_HEADER_RECYCLED;
    struct sss_mc_header h;
    off_t offset;
    off_t pos;
    ssize_t written;

    offset = MC_PTR_DIFF(&h.status, &h);

    pos = lseek(fd, offset, SEEK_SET);
    if (pos == -1) {
        /* What do we do now ? */
        return errno;
    }

    errno = 0;
    written = sss_atomic_write_s(fd, (uint8_t *)&w, sizeof(h.status));
    if (written == -1) {
        return errno;
    }

    if (written != sizeof(h.status)) {
        /* Write error */
        return EIO;
    }

    return EOK;
}

errno_t sss_memcache_invalidate(const char *mc_filename)
{
    int mc_fd = -1;
    errno_t ret;
    errno_t pret;
    useconds_t t = 50000;
    int retries = 2;

    if (!mc_filename) {
        return EINVAL;
    }

    mc_fd = open(mc_filename, O_RDWR);
    if (mc_fd == -1) {
        ret = errno;
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC,"Memory cache file %s "
                  "does not exist.\n", mc_filename);
            return EOK;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to open file %s: %s\n",
                  mc_filename, strerror(ret));
            return ret;
        }
    }

    ret = sss_br_lock_file(mc_fd, 0, 1, retries, t);
    if (ret == EACCES) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "File %s already locked by someone else.\n", mc_filename);
        goto done;
    } else if (ret != EOK) {
       DEBUG(SSSDBG_CRIT_FAILURE, "Failed to lock file %s.\n", mc_filename);
       goto done;
    }
    /* Mark the mc file as recycled. */
    ret = sss_mc_set_recycled(mc_fd);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to mark memory cache file %s "
              "as recycled.\n", mc_filename);
        goto done;
    }

    ret = EOK;
done:
    if (mc_fd != -1) {
        /* Closing the file also releases the lock */
        close(mc_fd);

        /* Only unlink the file if invalidation was successful */
        if (ret == EOK) {
            pret = unlink(mc_filename);
            if (pret == -1) {
                pret = errno;
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to unlink file %s, %d [%s]. "
                      "Will be unlinked later by sssd_nss.\n",
                      mc_filename, pret, strerror(pret));
            }
        }
    }
    return ret;
}

static int clear_fastcache(bool *sssd_nss_is_off)
{
    int ret;
    ret = sss_memcache_invalidate(SSS_NSS_MCACHE_DIR"/passwd");
    if (ret != EOK) {
        if (ret == EACCES) {
            *sssd_nss_is_off = false;
            return EOK;
        } else {
            return ret;
        }
    }

    ret = sss_memcache_invalidate(SSS_NSS_MCACHE_DIR"/group");
    if (ret != EOK) {
        if (ret == EACCES) {
            *sssd_nss_is_off = false;
            return EOK;
        } else {
            return ret;
        }
    }

    ret = sss_memcache_invalidate(SSS_NSS_MCACHE_DIR"/initgroups");
    if (ret != EOK) {
        if (ret == EACCES) {
            *sssd_nss_is_off = false;
            return EOK;
        } else {
            return ret;
        }
    }

    *sssd_nss_is_off = true;
    return EOK;
}

static errno_t wait_till_nss_responder_invalidate_cache(void)
{
    struct stat stat_buf = { 0 };
    const time_t max_wait = 1000000; /* 1 second */
    const time_t step_time = 5000; /* 5 miliseconds */
    const size_t steps_count = max_wait / step_time;
    int ret;

    for (size_t i = 0; i < steps_count; ++i) {
        ret = stat(SSS_NSS_MCACHE_DIR "/" CLEAR_MC_FLAG, &stat_buf);
        if (ret == -1) {
            ret = errno;
            if (ret == ENOENT) {
                /* nss responder has already invalidated memory caches */
                return EOK;
            }

            DEBUG(SSSDBG_CRIT_FAILURE,
                  "stat failed: %s (%d)\n", sss_strerror(ret), ret);
        }

        usleep(step_time);
    }

    return EAGAIN;
}

errno_t sss_memcache_clear_all(void)
{
    errno_t ret;
    bool sssd_nss_is_off = false;
    FILE *clear_mc_flag;

    ret = clear_fastcache(&sssd_nss_is_off);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to clear caches.\n");
        return EIO;
    }
    if (!sssd_nss_is_off) {
        /* sssd_nss is running -> signal monitor to invalidate fastcache */
        clear_mc_flag = fopen(SSS_NSS_MCACHE_DIR"/"CLEAR_MC_FLAG, "w");
        if (clear_mc_flag == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to create clear_mc_flag file. "
                   "Memory cache will not be cleared.\n");
            return EIO;
        }
        ret = fclose(clear_mc_flag);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to close file descriptor: %s\n",
                   strerror(ret));
            return EIO;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Sending SIGHUP to monitor.\n");
        ret = sss_signal(SIGHUP);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to send SIGHUP to monitor.\n");
            return EIO;
        }

        ret = wait_till_nss_responder_invalidate_cache();
        if (ret != EOK) {
            ERROR("The fast memory caches was not invalidated by NSS "
                  "responder.\n");
        }
    }

    return EOK;
}

enum sss_tools_ent {
    SSS_TOOLS_USER,
    SSS_TOOLS_GROUP
};

static errno_t sss_mc_refresh_ent(const char *name, enum sss_tools_ent ent)
{
    enum sss_cli_command cmd;
    struct sss_cli_req_data rd;
    uint8_t *repbuf = NULL;
    size_t replen;
    enum nss_status nret;
    errno_t ret;

    cmd = SSS_CLI_NULL;
    switch (ent) {
        case SSS_TOOLS_USER:
            cmd = SSS_NSS_GETPWNAM;
            break;
        case SSS_TOOLS_GROUP:
            cmd = SSS_NSS_GETGRNAM;
            break;
    }

    if (cmd == SSS_CLI_NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d][%s] to refresh\n",
              cmd, sss_cmd2str(cmd));
        return EINVAL;
    }

    rd.data = name;
    rd.len = strlen(name) + 1;

    sss_nss_lock();
    nret = sss_nss_make_request(cmd, &rd, &repbuf, &replen, &ret);
    sss_nss_unlock();

    free(repbuf);
    if (nret != NSS_STATUS_SUCCESS && nret != NSS_STATUS_NOTFOUND) {
        return EIO;
    }

    return EOK;
}

errno_t sss_mc_refresh_user(const char *username)
{
    return sss_mc_refresh_ent(username, SSS_TOOLS_USER);
}

errno_t sss_mc_refresh_group(const char *groupname)
{
    return sss_mc_refresh_ent(groupname, SSS_TOOLS_GROUP);
}

static errno_t sss_mc_refresh_nested_group(struct tools_ctx *tctx,
                                           const char *shortname)
{
    errno_t ret;
    struct ldb_message *msg = NULL;
    struct ldb_message_element *el;
    const char *attrs[] = { SYSDB_MEMBEROF,
                            SYSDB_NAME,
                            NULL };
    size_t i;
    char *parent_internal_name;
    char *parent_outname;
    char *internal_name;
    TALLOC_CTX *tmpctx;

    tmpctx = talloc_new(tctx);
    if (tmpctx == NULL) {
        return ENOMEM;
    }

    internal_name = sss_create_internal_fqname(tmpctx, shortname,
                                               tctx->local->name);
    if (internal_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_mc_refresh_group(shortname);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot refresh group %s from memory cache\n", shortname);
        /* try to carry on */
    }

    ret = sysdb_search_group_by_name(tmpctx, tctx->local, internal_name, attrs,
                                     &msg);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
               "Search failed: %s (%d)\n", strerror(ret), ret);
        goto done;
    }

    el = ldb_msg_find_element(msg, SYSDB_MEMBEROF);
    if (!el || el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Group %s has no parents\n",
              internal_name);
        ret = EOK;
        goto done;
    }

    /* This group is nested. We need to invalidate all its parents, too */
    for (i=0; i < el->num_values; i++) {
        ret = sysdb_group_dn_name(tctx->sysdb, tmpctx,
                                  (const char *) el->values[i].data,
                                  &parent_internal_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Malformed DN [%s]? Skipping\n",
                  (const char *) el->values[i].data);
            talloc_free(parent_internal_name);
            continue;
        }

        parent_outname = sss_output_name(tmpctx, parent_internal_name,
                                         tctx->local->case_preserve, 0);
        if (parent_outname == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = sss_mc_refresh_group(parent_outname);
        talloc_free(parent_internal_name);
        talloc_free(parent_outname);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot refresh group %s from memory cache\n", parent_outname);
            /* try to carry on */
        }
    }

    ret = EOK;

done:
    talloc_free(tmpctx);
    return ret;
}

errno_t sss_mc_refresh_grouplist(struct tools_ctx *tctx,
                                 char **groupnames)
{
    int i;
    errno_t ret;
    bool failed = false;

    if (!groupnames) return EOK;

    for (i = 0; groupnames[i]; i++) {
        ret = sss_mc_refresh_nested_group(tctx, groupnames[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot refresh group %s from memory cache\n",
                  groupnames[i]);
            failed = true;
            continue;
        }
    }

    return failed ? EIO : EOK;
}
