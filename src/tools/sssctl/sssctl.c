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
#include <sys/wait.h>

#include "util/util.h"
#include "tools/sssctl/sssctl.h"
#include "tools/common/sss_tools.h"
#include "tools/common/sss_process.h"

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
#ifdef HAVE_SYSTEMD
    switch (action) {
    case SSSCTL_SVC_START:
        return sssctl_systemd_start();
    case SSSCTL_SVC_STOP:
        return sssctl_systemd_stop();
    case SSSCTL_SVC_RESTART:
        return sssctl_systemd_restart();
    }
#elif defined(HAVE_SERVICE)
    switch (action) {
    case SSSCTL_SVC_START:
        return sssctl_run_command(SERVICE_PATH" sssd start");
    case SSSCTL_SVC_STOP:
        return sssctl_run_command(SERVICE_PATH" sssd stop");
    case SSSCTL_SVC_RESTART:
        return sssctl_run_command(SERVICE_PATH" sssd restart");
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
        SSS_TOOL_COMMAND("domain-list", "List available domains", 0, sssctl_domain_list),
        SSS_TOOL_COMMAND("domain-status", "Print information about domain", 0, sssctl_domain_status),
        SSS_TOOL_COMMAND("user-checks", "Print information about a user and check authentication", 0, sssctl_user_checks),
        SSS_TOOL_DELIMITER("Information about cached content:"),
        SSS_TOOL_COMMAND("user-show", "Information about cached user", 0, sssctl_user_show),
        SSS_TOOL_COMMAND("group-show", "Information about cached group", 0, sssctl_group_show),
        SSS_TOOL_COMMAND("netgroup-show", "Information about cached netgroup", 0, sssctl_netgroup_show),
        SSS_TOOL_DELIMITER("Local data tools:"),
        SSS_TOOL_COMMAND("client-data-backup", "Backup local data", 0, sssctl_client_data_backup),
        SSS_TOOL_COMMAND("client-data-restore", "Restore local data from backup", 0, sssctl_client_data_restore),
        SSS_TOOL_COMMAND("cache-remove", "Backup local data and remove cached content", 0, sssctl_cache_remove),
        SSS_TOOL_COMMAND("cache-upgrade", "Perform cache upgrade", ERR_SYSDB_VERSION_TOO_OLD, sssctl_cache_upgrade),
        SSS_TOOL_COMMAND("cache-expire", "Invalidate cached objects", 0, sssctl_cache_expire),
        SSS_TOOL_DELIMITER("Log files tools:"),
        SSS_TOOL_COMMAND("logs-remove", "Remove existing SSSD log files", 0, sssctl_logs_remove),
        SSS_TOOL_COMMAND("logs-fetch", "Archive SSSD log files in tarball", 0, sssctl_logs_fetch),
        SSS_TOOL_COMMAND("debug-level", "Change SSSD debug level", 0, sssctl_debug_level),
#ifdef HAVE_LIBINI_CONFIG_V1_3
        SSS_TOOL_DELIMITER("Configuration files tools:"),
        SSS_TOOL_COMMAND_FLAGS("config-check", "Perform static analysis of SSSD configuration", 0, sssctl_config_check, SSS_TOOL_FLAG_SKIP_CMD_INIT),
#endif
        SSS_TOOL_LAST
    };

    return sss_tool_main(argc, argv, commands, NULL);
}
