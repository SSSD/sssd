/*
   SSSD

   tools_utils.c

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009

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
#include <tevent.h>
#include <popt.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "config.h"

#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "tools/sss_sync_ops.h"

static int setup_db(struct tools_ctx *ctx)
{
    char *confdb_path;
    int ret;

    confdb_path = talloc_asprintf(ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        return ENOMEM;
    }

    /* Connect to the conf db */
    ret = confdb_init(ctx, &ctx->confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not initialize connection to the confdb\n");
        return ret;
    }

    ret = sssd_domain_init(ctx, ctx->confdb, "local", DB_PATH, &ctx->local);
    if (ret != EOK) {
        SYSDB_VERSION_ERROR(ret);
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not initialize connection to the sysdb\n");
        return ret;
    }
    ctx->sysdb = ctx->local->sysdb;

    talloc_free(confdb_path);
    return EOK;
}

/*
 * Print poptUsage as well as our error message
 */
void usage(poptContext pc, const char *error)
{
    size_t lentmp;

    poptPrintUsage(pc, stderr, 0);

    if (error) {
        lentmp = strlen(error);
        if ((lentmp > 0) && (error[lentmp - 1] != '\n')) {
            fprintf(stderr, "%s\n", error);
            return;
        }

        fprintf(stderr, "%s", error);
    }
}

int parse_groups(TALLOC_CTX *mem_ctx, const char *optstr, char ***_out)
{
    char **out;
    char *orig, *n, *o;
    char delim = ',';
    unsigned int tokens = 1;
    unsigned int i;

    orig = talloc_strdup(mem_ctx, optstr);
    if (!orig) return ENOMEM;

    n = orig;
    tokens = 1;
    while ((n = strchr(n, delim))) {
        n++;
        tokens++;
    }

    out = talloc_array(mem_ctx, char *, tokens+1);
    if (!out) {
        talloc_free(orig);
        return ENOMEM;
    }

    n = o = orig;
    for (i = 0; i < tokens; i++) {
        o = n;
        n = strchr(n, delim);
        if (!n) {
            break;
        }
        *n = '\0';
        n++;
        out[i] = talloc_strdup(out, o);
    }
    out[tokens-1] = talloc_strdup(out, o);
    out[tokens] = NULL;

    talloc_free(orig);
    *_out = out;
    return EOK;
}

int parse_group_name_domain(struct tools_ctx *tctx,
                            char **groups)
{
    int i;
    int ret;
    char *name = NULL;
    char *domain = NULL;

    if (!groups) {
        return EOK;
    }

    for (i = 0; groups[i]; ++i) {
        ret = sss_parse_name(tctx, tctx->snctx, groups[i], &domain, &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid name in group list, skipping: [%s] (%d)\n",
                       groups[i], ret);
            continue;
        }

        /* If FQDN is specified, it must be within the same domain as user */
        if (domain) {
            if (strcmp(domain, tctx->octx->domain->name) != 0) {
                return EINVAL;
            }

            /* Use only groupname */
            talloc_zfree(groups[i]);
            groups[i] = talloc_strdup(tctx, name);
            if (groups[i] == NULL) {
                return ENOMEM;
            }
        }

        talloc_zfree(name);
        talloc_zfree(domain);
    }

    talloc_zfree(name);
    talloc_zfree(domain);
    return EOK;
}

int parse_name_domain(struct tools_ctx *tctx,
                      const char *fullname)
{
    int ret;
    char *domain = NULL;

    ret = sss_parse_name(tctx, tctx->snctx, fullname, &domain, &tctx->octx->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot parse full name\n");
        return ret;
    }
    DEBUG(SSSDBG_FUNC_DATA, "Parsed username: %s\n", tctx->octx->name);

    if (domain) {
        DEBUG(SSSDBG_FUNC_DATA, "Parsed domain: %s\n", domain);
        /* only the local domain, whatever named is allowed in tools */
        if (strcasecmp(domain, tctx->local->name) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid domain %s specified in FQDN\n", domain);
            return EINVAL;
        }
    } else {
        if (tctx->local->fqnames) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Name '%s' does not seem to be FQDN "
                   "('%s = TRUE' is set)\n", fullname, CONFDB_DOMAIN_FQ);
            ERROR("Name '%1$s' does not seem to be FQDN "
                  "('%2$s = TRUE' is set)\n", fullname, CONFDB_DOMAIN_FQ);
            return EINVAL;
        }
    }

    return EOK;
}

int check_group_names(struct tools_ctx *tctx,
                      char **grouplist,
                      char **badgroup)
{
    int ret;
    int i;
    struct ops_ctx *groupinfo;

    groupinfo = talloc_zero(tctx, struct ops_ctx);
    if (!groupinfo) {
        return ENOMEM;
    }
    groupinfo->domain = tctx->local;

    ret = EOK;
    for (i=0; grouplist[i]; ++i) {
        ret = sysdb_getgrnam_sync(tctx,
                                  grouplist[i],
                                  groupinfo);
        if (ret) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Cannot find group %s, ret: %d\n", grouplist[i], ret);
            break;
        }
    }

    talloc_zfree(groupinfo);
    *badgroup = grouplist[i];
    return ret;
}

int id_in_range(uint32_t id,
                struct sss_domain_info *dom)
{
    if (id &&
        ((id < dom->id_min) ||
         (dom->id_max && id > dom->id_max))) {
        return ERANGE;
    }

    return EOK;
}

int set_locale(void)
{
    char *c;

    c = setlocale(LC_ALL, "");
    if (c == NULL) {
        /* If setlocale fails, continue with the default
         * locale. */
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to set locale\n");
    }

    errno = 0;
    c = bindtextdomain(PACKAGE, LOCALEDIR);
    if (c == NULL) {
        return errno;
    }

    errno = 0;
    c = textdomain(PACKAGE);
    if (c == NULL) {
        return errno;
    }

    return EOK;
}

int init_sss_tools(struct tools_ctx **_tctx)
{
    int ret;
    struct tools_ctx *tctx;

    tctx = talloc_zero(NULL, struct tools_ctx);
    if (tctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for tools context\n");
        return ENOMEM;
    }

    /* Connect to the database */
    ret = setup_db(tctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up database\n");
        goto fini;
    }

    ret = sss_names_init(tctx, tctx->confdb, tctx->local->name, &tctx->snctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up parsing\n");
        goto fini;
    }

    tctx->octx = talloc_zero(tctx, struct ops_ctx);
    if (!tctx->octx) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for data context\n");
        ERROR("Out of memory\n");
        ret = ENOMEM;
        goto fini;
    }
    tctx->octx->domain = tctx->local;

    *_tctx = tctx;
    ret = EOK;

fini:
    if (ret != EOK) talloc_free(tctx);
    return ret;
}

/*
 * Check is path is owned by uid
 * returns  0 - owns
 *         -1 - does not own
 *         >0 - an error occurred, error code
 */
static int is_owner(uid_t uid, const char *path)
{
    struct stat statres;
    int ret;

    ret = stat(path, &statres);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot stat %s: [%d][%s]\n", path, ret, strerror(ret));
        return ret;
    }

    if (statres.st_uid == uid) {
        return EOK;
    }
    return -1;
}

static int remove_mail_spool(TALLOC_CTX *mem_ctx,
                             const char *maildir,
                             const char *username,
                             uid_t uid,
                             bool force)
{
    int ret;
    char *spool_file;

    spool_file = talloc_asprintf(mem_ctx, "%s/%s", maildir, username);
    if (spool_file == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    if (force == false) {
        /* Check the owner of the mail spool */
        ret = is_owner(uid, spool_file);
        switch (ret) {
            case 0:
                break;
            case -1:
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "%s not owned by %"SPRIuid", not removing\n",
                          spool_file, uid);
                ret = EACCES;
                /* FALLTHROUGH */
            default:
                goto fail;
        }
    }

    ret = unlink(spool_file);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot remove() the spool file %s: [%d][%s]\n",
                   spool_file, ret, strerror(ret));
        goto fail;
    }

fail:
    talloc_free(spool_file);
    return ret;
}

int remove_homedir(TALLOC_CTX *mem_ctx,
                   const char *homedir,
                   const char *maildir,
                   const char *username,
                   uid_t uid, bool force)
{
    int ret;

    ret = remove_mail_spool(mem_ctx, maildir, username, uid, force);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot remove user's mail spool\n");
        /* Should this be fatal? I don't think so. Maybe convert to ERROR? */
    }

    if (force == false && is_owner(uid, homedir) == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Not removing home dir - not owned by user\n");
        return EPERM;
    }

    /* Remove the tree */
    ret = sss_remove_tree(homedir);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot remove homedir %s: %d\n",
                  homedir, ret);
        return ret;
    }

    return EOK;
}

/* The reason for not putting this into create_homedir
 * is better granularity when it comes to reporting error
 * messages and tracebacks in pysss
 */
int create_mail_spool(TALLOC_CTX *mem_ctx,
                      const char *username,
                      const char *maildir,
                      uid_t uid, gid_t gid)
{
    char *spool_file = NULL;
    int fd = -1;
    int ret;

    spool_file = talloc_asprintf(mem_ctx, "%s/%s", maildir, username);
    if (spool_file == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    selinux_file_context(spool_file);

    fd = open(spool_file, O_CREAT | O_WRONLY | O_EXCL, 0);
    if (fd < 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot open() the spool file: [%d][%s]\n",
                  ret, strerror(ret));
        goto fail;
    }

    ret = fchmod(fd, 0600);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot fchmod() the spool file: [%d][%s]\n",
                  ret, strerror(ret));
        goto fail;
    }

    ret = fchown(fd, uid, gid);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot fchown() the spool file: [%d][%s]\n",
                  ret, strerror(ret));
        goto fail;
    }

    ret = fsync(fd);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot fsync() the spool file: [%d][%s]\n",
                  ret, strerror(ret));
    }

fail:
    if (fd >= 0) {
        ret = close(fd);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot close() the spool file: [%d][%s]\n",
                      ret, strerror(ret));
        }
    }

    reset_selinux_file_context();
    talloc_free(spool_file);
    return ret;
}

int create_homedir(const char *skeldir,
                   const char *homedir,
                   uid_t uid,
                   gid_t gid,
                   mode_t default_umask)
{
    int ret;

    selinux_file_context(homedir);

    ret = sss_copy_tree(skeldir, homedir, 0777 & ~default_umask, uid, gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot populate user's home directory: [%d][%s].\n",
                  ret, strerror(ret));
        goto done;
    }

done:
    reset_selinux_file_context();
    return ret;
}

int run_userdel_cmd(struct tools_ctx *tctx)
{
    int ret, status;
    char *userdel_cmd = NULL;
    char *conf_path = NULL;
    pid_t pid, child_pid;

    conf_path = talloc_asprintf(tctx, CONFDB_DOMAIN_PATH_TMPL,
                                      tctx->local->name);
    if (!conf_path) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_get_string(tctx->confdb, tctx,
                            conf_path, CONFDB_LOCAL_USERDEL_CMD,
                            NULL, &userdel_cmd);
    if (ret != EOK || !userdel_cmd) {
        goto done;
    }

    errno = 0;
    pid = fork();
    if (pid == 0) {
        /* child */
        execl(userdel_cmd, userdel_cmd,
              tctx->octx->name, (char *) NULL);
        exit(errno);
    } else {
        /* parent */
        if (pid == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "fork failed [%d]: %s\n", ret, strerror(ret));
            goto done;
        }

        while((child_pid = waitpid(pid, &status, 0)) > 0) {
            if (WIFEXITED(status)) {
                ret = WEXITSTATUS(status);
                if (ret != 0) {
                    DEBUG(SSSDBG_FUNC_DATA,
                          "command [%s] returned nonzero status %d.\n",
                              userdel_cmd, ret);
                    ret = EOK;  /* Ignore return code of the command */
                    goto done;
                }
            } else if (WIFSIGNALED(status)) {
                DEBUG(SSSDBG_FUNC_DATA,
                      "command [%s] was terminated by signal %d.\n",
                          userdel_cmd, WTERMSIG(status));
                ret = EIO;
                goto done;
            } else if (WIFSTOPPED(status)) {
                DEBUG(SSSDBG_FUNC_DATA,
                      "command [%s] was stopped by signal %d.\n",
                          userdel_cmd, WSTOPSIG(status));
                continue;
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unknown status from WAITPID\n");
                ret = EIO;
                goto done;
            }
        }
        if (child_pid == -1) {
            DEBUG(SSSDBG_CRIT_FAILURE, "waitpid failed\n");
            ret = errno;
            goto done;
        }
    }

    ret = EOK;
done:
    talloc_free(userdel_cmd);
    talloc_free(conf_path);
    return ret;
}
