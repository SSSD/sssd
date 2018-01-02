/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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
#include <stdio.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/common/sss_process.h"
#include "tools/sssctl/sssctl.h"
#include "tools/tools_util.h"

#define SSS_BACKUP_DIR SSS_STATEDIR "/backup"
#define SSS_BACKUP_USER_OVERRIDES SSS_BACKUP_DIR "/sssd_user_overrides.bak"
#define SSS_BACKUP_GROUP_OVERRIDES SSS_BACKUP_DIR "/sssd_group_overrides.bak"
#define SSS_CACHE "sss_cache"

struct sssctl_data_opts {
    int override;
    int restore;
    int start;
    int stop;
    int restart;
};

static errno_t sssctl_create_backup_dir(const char *path)
{
    mode_t old_umask;
    errno_t ret;

    old_umask = umask(SSS_DFL_X_UMASK);
    ret = mkdir(path, 0700);
    umask(old_umask);
    if (ret != EOK && errno != EEXIST) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to create backup directory "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static bool sssctl_backup_file_exists(const char *file)
{
    return access(file, F_OK) == 0;
}

static bool sssctl_backup_exist(const char **files)
{
    int i;

    for (i = 0; files[i] != NULL; i++) {
        if (sssctl_backup_file_exists(files[i])) {
            return true;
        }
    }

    return false;
}

static errno_t sssctl_backup(bool force)
{
    const char *files[] = {SSS_BACKUP_USER_OVERRIDES,
                           SSS_BACKUP_GROUP_OVERRIDES,
                           NULL};
    enum sssctl_prompt_result prompt;
    errno_t ret;

    ret = sssctl_create_backup_dir(SSS_BACKUP_DIR);
    if (ret != EOK) {
        fprintf(stderr, _("Unable to create backup directory [%d]: %s"),
                ret, sss_strerror(ret));
        return ret;
    }

    if (sssctl_backup_exist(files) && !force) {
        prompt = sssctl_prompt(_("SSSD backup of local data already exists, "
                                 "override?"), SSSCTL_PROMPT_NO);
        switch (prompt) {
        case SSSCTL_PROMPT_YES:
            /* continue */
            break;
        case SSSCTL_PROMPT_NO:
            return EEXIST;
        case SSSCTL_PROMPT_ERROR:
            return EIO;
        }
    }

    ret = sssctl_run_command("sss_override user-export "
                             SSS_BACKUP_USER_OVERRIDES);
    if (ret != EOK) {
        fprintf(stderr, _("Unable to export user overrides\n"));
        return ret;
    }

    ret = sssctl_run_command("sss_override group-export "
                             SSS_BACKUP_GROUP_OVERRIDES);
    if (ret != EOK) {
        fprintf(stderr, _("Unable to export group overrides\n"));
        return ret;
    }

    return ret;
}

errno_t sssctl_client_data_backup(struct sss_cmdline *cmdline,
                                  struct sss_tool_ctx *tool_ctx,
                                  void *pvt)
{
    struct sssctl_data_opts opts = {0};
    errno_t ret;

    /* Parse command line. */
    struct poptOption options[] = {
        {"override", 'o', POPT_ARG_NONE, &opts.override, 0, _("Override existing backup"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt(cmdline, options, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    ret = sssctl_backup(opts.override);
    if (ret == EEXIST) {
        return EOK;
    }

    return ret;
}

static errno_t sssctl_restore(bool force_start, bool force_restart)
{
    errno_t ret;

    if (!sssctl_start_sssd(force_start)) {
        return ERR_SSSD_NOT_RUNNING;
    }

    if (sssctl_backup_file_exists(SSS_BACKUP_USER_OVERRIDES)) {
        ret = sssctl_run_command("sss_override user-import "
                                 SSS_BACKUP_USER_OVERRIDES);
        if (ret != EOK) {
            fprintf(stderr, _("Unable to import user overrides\n"));
            return ret;
        }
    }

    if (sssctl_backup_file_exists(SSS_BACKUP_USER_OVERRIDES)) {
        ret = sssctl_run_command("sss_override group-import "
                                 SSS_BACKUP_GROUP_OVERRIDES);
        if (ret != EOK) {
            fprintf(stderr, _("Unable to import group overrides\n"));
            return ret;
        }
    }

    sssctl_restart_sssd(force_restart);

    ret = EOK;

    return ret;
}

errno_t sssctl_client_data_restore(struct sss_cmdline *cmdline,
                                   struct sss_tool_ctx *tool_ctx,
                                   void *pvt)
{
    struct sssctl_data_opts opts = {0};
    errno_t ret;

    /* Parse command line. */
    struct poptOption options[] = {
        {"start", 's', POPT_ARG_NONE, &opts.start, 0, _("Start SSSD if it is not running"), NULL },
        {"restart", 'r', POPT_ARG_NONE, &opts.restart, 0, _("Restart SSSD after data import"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt(cmdline, options, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    return sssctl_restore(opts.start, opts.restart);
}

errno_t sssctl_cache_remove(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt)
{
    struct sssctl_data_opts opts = {0};
    errno_t ret;

    /* Parse command line. */
    struct poptOption options[] = {
        {"override", 'o', POPT_ARG_NONE, &opts.override, 0, _("Override existing backup"), NULL },
        {"restore", 'r', POPT_ARG_NONE, &opts.restore, 0, _("Create clean cache files and import local data"), NULL },
        {"stop", 'p', POPT_ARG_NONE, &opts.stop, 0, _("Stop SSSD before removing the cache"), NULL },
        {"start", 's', POPT_ARG_NONE, &opts.start, 0, _("Start SSSD when the cache is removed"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt(cmdline, options, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    if (!sssctl_stop_sssd(opts.stop)) {
        fprintf(stderr, "Unable to remove the cache unless SSSD is stopped.\n");
        return ERR_SSSD_RUNNING;
    }

    printf(_("Creating backup of local data...\n"));
    ret = sssctl_backup(opts.override);
    if (ret != EOK) {
        fprintf(stderr, _("Unable to create backup of local data,"
                " can not remove the cache.\n"));
        return ret;
    }

    printf(_("Removing cache files...\n"));
    ret = sss_remove_subtree(DB_PATH);
    if (ret != EOK) {
        fprintf(stderr, _("Unable to remove cache files\n"));
        return ret;
    }

    if (opts.restore) {
        printf(_("Restoring local data...\n"));
        sssctl_restore(opts.start, opts.start);
    } else {
        sssctl_start_sssd(opts.start);
    }

    return EOK;
}

errno_t sssctl_cache_upgrade(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt)
{
    struct sysdb_upgrade_ctx db_up_ctx;
    errno_t ret;

    ret = sss_tool_popt(cmdline, NULL, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    if (sss_daemon_running()) {
        return ERR_SSSD_RUNNING;
    }

    ret = confdb_get_domains(tool_ctx->confdb, &tool_ctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "No domains configured.\n");
        return ret;
    }

    db_up_ctx.cdb = tool_ctx->confdb;
    ret = sysdb_init_ext(tool_ctx, tool_ctx->domains, &db_up_ctx,
                         true, 0, 0);
    if (ret != EOK) {
        SYSDB_VERSION_ERROR_DAEMON(ret);
        return ret;
    }

    return EOK;
}

errno_t sssctl_cache_expire(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt)
{
    errno_t ret;
    char *cmd_args = NULL;
    const char *cachecmd = SSS_CACHE;
    char *cmd = NULL;
    int i;

    if (cmdline->argc == 0) {
        ret = sssctl_run_command(cachecmd);
        goto done;
    }

    cmd_args = talloc_strdup(tool_ctx, "");
    if (cmd_args == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < cmdline->argc; i++) {
        cmd_args = talloc_strdup_append(cmd_args, cmdline->argv[i]);
        if (i != cmdline->argc - 1) {
            cmd_args = talloc_strdup_append(cmd_args, " ");
        }
    }

    cmd = talloc_asprintf(tool_ctx, "%s %s", cachecmd, cmd_args);
    if (cmd == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sssctl_run_command(cmd);

done:
    talloc_free(cmd_args);
    talloc_free(cmd);

    return ret;
}
