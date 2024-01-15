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
#include "db/sysdb_private.h"
#include "confdb/confdb.h"
#include "confdb/confdb_private.h"
#include "tools/common/sss_process.h"
#include "tools/sssctl/sssctl.h"

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
        ERROR("Unable to create backup directory [%d]: %s",
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

    ret = sssctl_run_command((const char *[]){"sss_override", "user-export",
                                              SSS_BACKUP_USER_OVERRIDES, NULL});
    if (ret != EOK) {
        ERROR("Unable to export user overrides\n");
        return ret;
    }

    ret = sssctl_run_command((const char *[]){"sss_override", "group-export",
                                              SSS_BACKUP_GROUP_OVERRIDES, NULL});
    if (ret != EOK) {
        ERROR("Unable to export group overrides\n");
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
        ret = sssctl_run_command((const char *[]){"sss_override", "user-import",
                                                  SSS_BACKUP_USER_OVERRIDES, NULL});
        if (ret != EOK) {
            ERROR("Unable to import user overrides\n");
            return ret;
        }
    }

    if (sssctl_backup_file_exists(SSS_BACKUP_USER_OVERRIDES)) {
        ret = sssctl_run_command((const char *[]){"sss_override", "group-import",
                                                  SSS_BACKUP_GROUP_OVERRIDES, NULL});
        if (ret != EOK) {
            ERROR("Unable to import group overrides\n");
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

    PRINT("Creating backup of local data...\n");
    ret = sssctl_backup(opts.override);
    if (ret != EOK) {
        ERROR("Unable to create backup of local data,"
              " can not remove the cache.\n");
        return ret;
    }

    PRINT("Removing cache files...\n");
    ret = sss_remove_subtree(DB_PATH);
    if (ret != EOK) {
        ERROR("Unable to remove cache files\n");
        return ret;
    }

    if (opts.restore) {
        PRINT("Restoring local data...\n");
        sssctl_restore(opts.start, opts.start);
    } else {
        sssctl_start_sssd(opts.start);
    }

    return EOK;
}

errno_t sssctl_cache_expire(struct sss_cmdline *cmdline,
                            struct sss_tool_ctx *tool_ctx,
                            void *pvt)
{
    errno_t ret;

    const char **args = talloc_array_size(tool_ctx,
                                          sizeof(char *),
                                          cmdline->argc + 2);
    if (!args) {
        return ENOMEM;
    }
    memcpy(&args[1], cmdline->argv, sizeof(char *) * cmdline->argc);
    args[0] = SSS_CACHE;
    args[cmdline->argc + 1] = NULL;

    ret = sssctl_run_command(args);

    talloc_free(args);
    return ret;
}

errno_t get_confdb_domains(TALLOC_CTX *ctx, struct confdb_ctx *confdb,
                           char ***_domains)
{
    int ret;
    int domain_count = 0;
    int i;
    struct sss_domain_info *domain = NULL;
    struct sss_domain_info *domain_list = NULL;
    char **domains;

    TALLOC_CTX *tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* get domains */
    ret = confdb_get_domains(confdb, &domain_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get domain list\n");
        goto done;
    }

    for (domain = domain_list;
         domain;
         domain = get_next_domain(domain, 0)) {
        domain_count++;
    }

    /* allocate output space */
    domains = talloc_array(tmp_ctx, char *, domain_count + 1);
    if (domains == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for domains\n");
        ret = ENOMEM;
        goto done;
    }

    for (domain = domain_list, i = 0;
         domain != NULL;
         domain = get_next_domain(domain, 0), i++) {
        domains[i] = talloc_asprintf(domains, "%s", domain->name);
        if (domains[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
            ret = ENOMEM;
            goto done;
        }
    }

    /* add NULL to the end */
    domains[i] = NULL;

    *_domains = talloc_steal(ctx, domains);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sssctl_cache_index_action(enum sysdb_index_actions action,
                                         const char **domains,
                                         const char *attr)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct confdb_ctx *confdb = NULL;
    char *cache;
    const char **domain;
    const char **index;
    const char **indexes = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate the context\n");
        return ENOMEM;
    }

    if (domains == NULL) {
        /* If the user selected no domain, act on all of them */
        ret = sss_tool_connect_to_confdb(tmp_ctx, &confdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not connect to configuration database.\n");
            goto done;
        }

        ret = get_confdb_domains(tmp_ctx, confdb, discard_const(&domains));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not list all the domains.\n");
            goto done;
        }
    }

    for (domain = domains; *domain != NULL; domain++) {
        if (action == SYSDB_IDX_CREATE) {
            PRINT("Creating cache index for domain %1$s\n", *domain);
        } else if (action == SYSDB_IDX_DELETE) {
            PRINT("Deleting cache index for domain %1$s\n", *domain);
        } else if (action == SYSDB_IDX_LIST) {
            PRINT("Indexes for domain %1$s:\n", *domain);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid action: %i\n", action);
            ret = EINVAL;
            goto done;
        }

        ret = sysdb_get_db_file(tmp_ctx, NULL, *domain, DB_PATH, &cache, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get the cache db name\n");
            goto done;
        }

        ret = sysdb_manage_index(tmp_ctx, action, cache, attr, &indexes);
        if (ret != EOK) {
            goto done;
        }

        if (action == SYSDB_IDX_LIST) {
            for (index = indexes; *index != NULL; index++) {
                PRINT("  Attribute: %1$s\n", *index);
            }
            talloc_zfree(indexes);
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sssctl_cache_index(struct sss_cmdline *cmdline,
                                  struct sss_tool_ctx *tool_ctx,
                                  void *pvt)
{
    const char *attr = NULL;
    const char *action_str = NULL;
    const char **domains = NULL;
    const char **p;
    enum sysdb_index_actions action;
    errno_t ret;

    /* Parse command line. */
    struct poptOption options[] = {
        { "domain", 'd', POPT_ARG_ARGV, &domains,
            0, _("Target a specific domain"), _("domain") },
        { "attribute", 'a', POPT_ARG_STRING, &attr,
            0, _("Attribute to index"), _("attribute") },
        POPT_TABLEEND
    };

    ret = sss_tool_popt_ex(cmdline, options, SSS_TOOL_OPT_OPTIONAL, NULL, NULL,
                           "ACTION", "create | delete | list",
                           SSS_TOOL_OPT_REQUIRED, &action_str, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        goto done;
    }

    if (action_str == NULL) {
        ERROR("Action not provided\n");
        ret = EINVAL;
        goto done;
    }

    if (strcmp(action_str, "list") == 0) {
        action = SYSDB_IDX_LIST;
    } else {
        if (strcmp(action_str, "create") == 0) {
            action = SYSDB_IDX_CREATE;
        } else if (strcmp(action_str, "delete") == 0) {
            action = SYSDB_IDX_DELETE;
        } else {
            ERROR("Unknown action: %1$s\nValid actions are "
                           "\"%2$s\", \"%3$s and \"%4$s\"\n",
                  action_str, "create", "delete", "list");
            ret = EINVAL;
            goto done;
        }

        if (attr == NULL) {
            ERROR("Attribute (-a) not provided\n");
            ret = EINVAL;
            goto done;
        }
    }

    ret = sssctl_cache_index_action(action, domains, attr);
    if (ret == ENOENT) {
        ERROR("Attribute %1$s not indexed.\n", attr);
        goto done;
    } if (ret == EEXIST) {
        ERROR("Attribute %1$s already indexed.\n", attr);
        goto done;
    } else if (ret != EOK) {
        ERROR("Index operation failed: %1$s\n", sss_strerror(ret));
        goto done;
    }

    if (action != SYSDB_IDX_LIST) {
        PRINT("Don't forget to also update the indexes on the remote providers.\n");
    }

    ret = EOK;

done:
    free(discard_const(action_str));
    free(discard_const(attr));
    if (domains != NULL) {
        for (p = domains; *p != NULL; p++) {
            free(discard_const(*p));
        }
        free(discard_const(domains));
    }

    return ret;
}
