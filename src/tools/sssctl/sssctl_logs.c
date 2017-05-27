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
#include <signal.h>

#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/common/sss_process.h"
#include "tools/sssctl/sssctl.h"
#include "tools/tools_util.h"

#define LOG_FILE(file) " " LOG_PATH "/" file
#define LOG_FILES LOG_FILE("*.log")

struct sssctl_logs_opts {
    int delete;
    int archived;
};

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
        ret = remove_subtree(LOG_PATH);
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
