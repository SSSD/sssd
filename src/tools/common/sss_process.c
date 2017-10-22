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
#include <signal.h>

#include "util/util.h"
#include "tools/common/sss_process.h"

static pid_t parse_pid(const char *strpid)
{
    long value;
    char *endptr;

    errno = 0;
    value = strtol(strpid, &endptr, 10);
    if ((errno != 0) || (endptr == strpid)
        || ((*endptr != '\0') && (*endptr != '\n'))) {
        return 0;
    }

    return value;
}

static errno_t sss_pid(pid_t *out_pid)
{
    int ret;
    size_t fsize;
    FILE *pid_file;
    char pid_str[MAX_PID_LENGTH] = {'\0'};

    *out_pid = 0;

    errno = 0;
    pid_file = fopen(SSSD_PIDFILE, "r");
    if (pid_file == NULL) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to open pid file \"%s\": %s\n",
              SSSD_PIDFILE, strerror(ret));
        goto done;
    }

    fsize = fread(pid_str, sizeof(char), MAX_PID_LENGTH * sizeof(char),
                  pid_file);
    if (!feof(pid_file)) {
        /* eof not reached */
        ret = ferror(pid_file);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read from file \"%s\": %s\n",
                  SSSD_PIDFILE, strerror(ret));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "File \"%s\" contains invalid pid.\n",
                  SSSD_PIDFILE);
        }
        goto done;
    }
    if (fsize == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "File \"%s\" contains no pid.\n",
              SSSD_PIDFILE);
        ret = EINVAL;
        goto done;
    }

    pid_str[MAX_PID_LENGTH-1] = '\0';
    *out_pid = parse_pid(pid_str);
    if (*out_pid == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "File \"%s\" contains invalid pid.\n", SSSD_PIDFILE);
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    if (pid_file != NULL) {
        fclose(pid_file);
    }
    return ret;
}

bool sss_daemon_running(void)
{
    return sss_signal(0) == EOK;
}

errno_t sss_signal(int signum)
{
    int ret;
    pid_t pid;

    ret = sss_pid(&pid);
    if (ret != EOK) {
        return ret;
    }

    if (kill(pid, signum) != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not send signal %d to process %d: %s\n",
              signum, pid, strerror(errno));
        return ret;
    }

    return EOK;
}
