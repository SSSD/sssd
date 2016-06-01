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

#include <stdlib.h>
#include <stdio.h>

#include "util/util.h"
#include "tools/sssctl/sssctl.h"
#include "tools/common/sss_tools.h"
#include "tools/common/sss_process.h"

#ifdef HAVE_SYSTEMD
    #define SSSD_SVC_CMD(cmd) "systemctl " cmd " sssd.service"
#else
    #define SSSD_SVC_CMD(cmd) "service sssd " cmd
#endif

static const char *
sssctl_prompt_str(enum sssctl_prompt_result result)
{
    switch (result) {
    case SSSCTL_PROMPT_YES:
        return _("yes");
    case SSSCTL_PROMPT_NO:
        return _("no");
    case SSSCTL_PROMPT_ERROR:
        return _("error");
    }

    return _("Invalid result.");
}

enum sssctl_prompt_result
sssctl_prompt(const char *message,
              enum sssctl_prompt_result defval)
{
    char answer[255] = {0};
    int c;
    const char *yes = sssctl_prompt_str(SSSCTL_PROMPT_YES);
    const char *no = sssctl_prompt_str(SSSCTL_PROMPT_NO);
    int attempts = 0;
    int ret;

    do {
        if (defval != SSSCTL_PROMPT_ERROR) {
            printf("%s (%s/%s) [%s] ", message, yes, no,
                                       sssctl_prompt_str(defval));

            /* Detect empty line. */
            c = getchar();
            if (c == '\n') {
                return defval;
            } else {
                ungetc(c, stdin);
            }
        } else {
            printf("%s (%s/%s)", message, yes, no);
        }

        ret = scanf("%254s", answer);

        /* Clear stdin. */
        while ((c = getchar()) != '\n' && c != EOF);

        if (ret != 1) {
            fprintf(stderr, _("Unable to read user input\n"));
            return SSSCTL_PROMPT_ERROR;
        }


        if (strcasecmp(yes, answer) == 0) {
            return SSSCTL_PROMPT_YES;
        }

        if (strcasecmp(no, answer) == 0) {
            return SSSCTL_PROMPT_NO;
        }

        fprintf(stderr, _("Invalid input, please provide either "
                "'%s' or '%s'.\n"), yes, no);

        attempts++;
    } while (attempts < 3);

    return SSSCTL_PROMPT_ERROR;
}

errno_t sssctl_run_command(const char *command)
{
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Running %s\n", command);

    ret = system(command);
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to execute %s\n", command);
        fprintf(stderr, _("Error while executing external command\n"));
        return EFAULT;
    } else if (WEXITSTATUS(ret) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Command %s failed with [%d]\n",
              command, WEXITSTATUS(ret));
        fprintf(stderr, _("Error while executing external command\n"));
        return EIO;
    }

    return EOK;
}

static errno_t sssctl_manage_service(enum sssctl_svc_action action)
{
#if defined(HAVE_SYSTEMD) || defined(HAVE_SERVICE)
    switch (action) {
    case SSSCTL_SVC_START:
        return sssctl_run_command(SSSD_SVC_CMD("start"));
    case SSSCTL_SVC_STOP:
        return sssctl_run_command(SSSD_SVC_CMD("stop"));
    case SSSCTL_SVC_RESTART:
        return sssctl_run_command(SSSD_SVC_CMD("restart"));
    }
#endif

    return ENOSYS;
}

bool sssctl_start_sssd(bool force)
{
    enum sssctl_prompt_result prompt;
    errno_t ret;

    if (sss_deamon_running()) {
        return true;
    }

    if (!force) {
        prompt = sssctl_prompt(_("SSSD needs to be running. Start SSSD now?"),
                               SSSCTL_PROMPT_YES);
        switch (prompt) {
        case SSSCTL_PROMPT_YES:
            /* continue */
            break;
        case SSSCTL_PROMPT_NO:
        case SSSCTL_PROMPT_ERROR:
            return false;
        }
    }

    ret = sssctl_manage_service(SSSCTL_SVC_START);
    switch(ret) {
    case EOK:
        return true;
    case ENOSYS:
        fprintf(stderr, "Starting SSSD automatically is not supported "
                        "on this platform, please start the service "
                        "manually\n");
        return false;
    default:
        fprintf(stderr, "Unable to start SSSD!\n");
        return false;
    }

    return true;
}

bool sssctl_stop_sssd(bool force)
{
    enum sssctl_prompt_result prompt;
    errno_t ret;

    if (!sss_deamon_running()) {
        return true;
    }

    if (!force) {
        prompt = sssctl_prompt(_("SSSD must not be running. Stop SSSD now?"),
                               SSSCTL_PROMPT_YES);
        switch (prompt) {
        case SSSCTL_PROMPT_YES:
            /* continue */
            break;
        case SSSCTL_PROMPT_NO:
        case SSSCTL_PROMPT_ERROR:
            return false;
        }
    }

    ret = sssctl_manage_service(SSSCTL_SVC_STOP);
    switch(ret) {
    case EOK:
        return true;
    case ENOSYS:
        fprintf(stderr, "Stopping SSSD automatically is not supported "
                        "on this platform, please stop the service "
                        "manually\n");
        return false;
    default:
        fprintf(stderr, "Unable to stop SSSD!\n");
        return false;
    }


    return true;
}

bool sssctl_restart_sssd(bool force)
{
    enum sssctl_prompt_result prompt;
    errno_t ret;

    if (!force) {
        prompt = sssctl_prompt(_("SSSD needs to be restarted. Restart SSSD now?"),
                               SSSCTL_PROMPT_YES);
        switch (prompt) {
        case SSSCTL_PROMPT_YES:
            /* continue */
            break;
        case SSSCTL_PROMPT_NO:
        case SSSCTL_PROMPT_ERROR:
            return false;
        }
    }

    ret = sssctl_manage_service(SSSCTL_SVC_RESTART);
    switch(ret) {
    case EOK:
        return true;
    case ENOSYS:
        fprintf(stderr, "Restarting SSSD automatically is not supported "
                        "on this platform, please restart the service "
                        "manually\n");
        return false;
    default:
        fprintf(stderr, "Unable to restart SSSD!\n");
        return false;
    }

    return true;
}

int main(int argc, const char **argv)
{
    struct sss_route_cmd commands[] = {
        SSS_TOOL_DELIMITER("SSSD Status:"),
        SSS_TOOL_COMMAND("list-domains", "List available domains", sssctl_list_domains),
        SSS_TOOL_COMMAND("domain-status", "Print information about domain", sssctl_domain_status),
        SSS_TOOL_DELIMITER("Information about cached content:"),
        SSS_TOOL_COMMAND("user", "Information about cached user", sssctl_user),
        SSS_TOOL_COMMAND("group", "Information about cached group", sssctl_group),
        SSS_TOOL_COMMAND("netgroup", "Information about cached netgroup", sssctl_netgroup),
        SSS_TOOL_DELIMITER("Local data tools:"),
        SSS_TOOL_COMMAND("backup-local-data", "Backup local data", sssctl_backup_local_data),
        SSS_TOOL_COMMAND("restore-local-data", "Restore local data from backup", sssctl_restore_local_data),
        SSS_TOOL_COMMAND("remove-cache", "Backup local data and remove cached content", sssctl_remove_cache),
        SSS_TOOL_DELIMITER("Log files tools:"),
        SSS_TOOL_COMMAND("remove-logs", "Remove existing SSSD log files", sssctl_remove_logs),
        SSS_TOOL_COMMAND("fetch-logs", "Archive SSSD log files in tarball", sssctl_fetch_logs),
        {NULL, NULL, NULL}
    };

    return sss_tool_main(argc, argv, commands, NULL);
}
