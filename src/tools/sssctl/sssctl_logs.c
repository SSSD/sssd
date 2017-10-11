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

#include "config.h"

#include <stdlib.h>
#include <limits.h>
#include <talloc.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <utime.h>
#include <ldb.h>
#include <popt.h>
#include <stdio.h>
#include <signal.h>

#include "util/util.h"
#include "tools/common/sss_process.h"
#include "tools/sssctl/sssctl.h"
#include "tools/tools_util.h"
#include "confdb/confdb.h"

#define LOG_FILE(file) " " LOG_PATH "/" file
#define LOG_FILES LOG_FILE("*.log")

#define CHECK(expr, done, msg) do { \
    if (expr) { \
        ERROR(msg "\n"); \
        goto done; \
    } \
} while(0)

struct debuglevel_tool_ctx {
    struct confdb_ctx *confdb;
    char **sections;
};

struct sssctl_logs_opts {
    int delete;
    int archived;
};

errno_t set_debug_level(struct debuglevel_tool_ctx *tool_ctx,
                        int debug_to_set, const char *config_file)
{
    int ret;
    int err;
    const char *values[2];
    char **section = NULL;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* convert debug_to_set to string */
    values[0] = talloc_asprintf(tmp_ctx, "0x%.4x", debug_to_set);
    if (values[0] == NULL) {
        ret = ENOMEM;
        goto done;
    }
    values[1] = NULL;

    /* write to confdb */
    for (section = tool_ctx->sections; *section != NULL; section++) {
        ret = confdb_add_param(tool_ctx->confdb, 1, *section,
                               CONFDB_SERVICE_DEBUG_LEVEL, values);
        if (ret != EOK) {
            goto done;
        }
    }

    /*
     * Change atime and mtime of sssd.conf,
     * so the configuration can be restored on next start.
     */
    errno = 0;
    if (utime(config_file, NULL) == -1) {
        err = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to change mtime of \"%s\": %s\n",
              config_file, strerror(err));
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t connect_to_confdb(TALLOC_CTX *ctx, struct confdb_ctx **cdb_ctx)
{
    int ret;
    char *confdb_path = NULL;

    confdb_path = talloc_asprintf(ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for confdb path\n");
        return ENOMEM;
    }

    ret = confdb_init(ctx, cdb_ctx, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not initialize connection to the confdb\n");
    }

    talloc_free(confdb_path);
    return ret;
}

errno_t get_confdb_sections(TALLOC_CTX *ctx, struct confdb_ctx *confdb,
                            char ***output_sections)
{
    int ret;
    int domain_count = 0;
    int i = 0;
    struct sss_domain_info *domain = NULL;
    struct sss_domain_info *domain_list = NULL;
    char **sections;
    const char *known_services[] = {
        CONFDB_MONITOR_CONF_ENTRY,
        CONFDB_NSS_CONF_ENTRY,
        CONFDB_PAM_CONF_ENTRY,
        CONFDB_PAC_CONF_ENTRY,
        CONFDB_SSH_CONF_ENTRY,
        CONFDB_SUDO_CONF_ENTRY,
        CONFDB_AUTOFS_CONF_ENTRY,
        CONFDB_IFP_CONF_ENTRY,
    };
    static const int known_services_count = sizeof(known_services)
                                            / sizeof(*known_services);
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* get domains */
    ret = confdb_get_domains(confdb, &domain_list);
    if (ret != EOK)
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get domain list\n");

    for (domain = domain_list;
         domain;
         domain = get_next_domain(domain, 0)) {
        domain_count++;
    }

    /* allocate output space */
    sections = talloc_array(ctx, char *,
                            domain_count + known_services_count + 1);
    if (sections == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for sections\n");
        ret = ENOMEM;
        goto fail;
    }

    for (i = 0; i < known_services_count; i++) {
        sections[i] = talloc_strdup(tmp_ctx, known_services[i]);
        if (sections[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            ret = ENOMEM;
            goto fail;
        }
    }

    for (domain = domain_list;
         domain;
         domain = get_next_domain(domain, 0), i++) {
        sections[i] = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL,
                                      domain->name);
        if (sections[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
            ret = ENOMEM;
            goto fail;
        }
    }

    /* add NULL to the end */
    sections[i] = NULL;

    *output_sections = talloc_steal(ctx, sections);

    return EOK;
fail:
    talloc_free(tmp_ctx);
    return ret;
}

int parse_debug_level(const char *strlevel)
{
    long value;
    char *endptr;

    errno = 0;
    value = strtol(strlevel, &endptr, 0);
    if ((errno != 0) || (endptr == strlevel) || (*endptr != '\0')) {
        return SSSDBG_INVALID;
    }

    return debug_convert_old_level(value);
}

errno_t sssctl_logs_remove(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt)
{
    struct sssctl_logs_opts opts = {0};
    errno_t ret;

    /* Parse command line. */
    struct poptOption options[] = {
        {"delete", 'd', POPT_ARG_NONE, &opts.delete, 0, _("Delete log files instead of truncating"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt(cmdline, options, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    if (opts.delete) {
        printf(_("Deleting log files...\n"));
        ret = sss_remove_subtree(LOG_PATH);
        if (ret != EOK) {
            fprintf(stderr, _("Unable to remove log files\n"));
            return ret;
        }

        sss_signal(SIGHUP);
    } else {
        printf(_("Truncating log files...\n"));
        ret = sssctl_run_command("truncate --size 0 " LOG_FILES);
        if (ret != EOK) {
            fprintf(stderr, _("Unable to truncate log files\n"));
            return ret;
        }
    }

    return EOK;
}

errno_t sssctl_logs_fetch(struct sss_cmdline *cmdline,
                          struct sss_tool_ctx *tool_ctx,
                          void *pvt)
{
    const char *file;
    const char *cmd;
    errno_t ret;

    /* Parse command line. */
    ret = sss_tool_popt_ex(cmdline, NULL, SSS_TOOL_OPT_OPTIONAL, NULL, NULL,
                           "FILE", "Output file", &file, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    cmd = talloc_asprintf(tool_ctx, "tar -czf %s %s", file, LOG_FILES);
    if (cmd == NULL) {
        fprintf(stderr, _("Out of memory!"));
    }

    printf(_("Archiving log files into %s...\n"), file);
    ret = sssctl_run_command(cmd);
    if (ret != EOK) {
        fprintf(stderr, _("Unable to archive log files\n"));
        return ret;
    }

    return EOK;
}

errno_t sssctl_debug_level(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt)
{
    int ret;
    int debug_to_set = SSSDBG_INVALID;
    const char *debug_as_string = NULL;
    const char *config_file = NULL;
    const char *pc_config_file = NULL;
    struct debuglevel_tool_ctx *ctx = NULL;
    struct poptOption long_options[] = {
        {"config", 'c', POPT_ARG_STRING, &pc_config_file,
            0, _("Specify a non-default config file"), NULL},
        POPT_TABLEEND
    };

    ret = sss_tool_popt_ex(cmdline, long_options, SSS_TOOL_OPT_OPTIONAL, NULL,
                           NULL, "DEBUG_LEVEL_TO_SET",
                           _("Specify debug level you want to set"),
                           &debug_as_string, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    /* get config file */
    if (pc_config_file) {
        config_file = talloc_strdup(ctx, pc_config_file);
    } else {
        config_file = talloc_strdup(ctx, SSSD_CONFIG_FILE);
    }

    if (config_file == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
        ret = ENOMEM;
        goto fini;
    }

    CHECK_ROOT(ret, debug_prg_name);

    /* free pc_config_file? */
    /* free debug_as_string? */

    debug_to_set = parse_debug_level(debug_as_string);
    CHECK(debug_to_set == SSSDBG_INVALID, fini, "Invalid debug level.");

    /* allocate context */
    ctx = talloc_zero(NULL, struct debuglevel_tool_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for tools context\n");
        ret = ENOMEM;
        goto fini;
    }

    ret = connect_to_confdb(ctx, &ctx->confdb);
    CHECK(ret != EOK, fini, "Could not connect to configuration database.");

    ret = get_confdb_sections(ctx, ctx->confdb, &ctx->sections);
    CHECK(ret != EOK, fini, "Could not get all configuration sections.");

    ret = set_debug_level(ctx, debug_to_set, config_file);
    CHECK(ret != EOK, fini, "Could not set debug level.");

    ret = sss_signal(SIGHUP);
    CHECK(ret != EOK, fini,
          "Could not force sssd processes to reload configuration. "
          "Is sssd running?");

fini:
    talloc_free(ctx);
    return ret;
}
