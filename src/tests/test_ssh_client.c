/*
    Copyright (C) 2018 Red Hat

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
#include <sys/wait.h>
#include "util/util.h"

#ifdef SSH_CLIENT_DIR
#define SSH_AK_CLIENT_PATH SSH_CLIENT_DIR"/sss_ssh_authorizedkeys"
#else
#error "The path to the ssh authorizedkeys helper is not defined"
#endif /* SSH_CLIENT_DIR */

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };
    struct stat sb;
    int ret;
    int status;
    int p[2];
    pid_t pid;
    const char *pc_user = NULL;
    char *av[3];
    char buf[5]; /* Ridiculously small buffer by design */
    ssize_t len;

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USER");
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 3;
        }
    }

    pc_user = poptGetArg(pc);
    if (pc_user == NULL) {
        fprintf(stderr, "No user specified\n");
        return 3;
    }

    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    ret = stat(SSH_AK_CLIENT_PATH, &sb);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not stat %s [%d]: %s\n",
              SSH_AK_CLIENT_PATH, ret, strerror(ret));
        return 3;
    }

    ret = pipe(p);
    if (ret != 0) {
        perror("pipe");
        return 3;
    }

    switch (pid = fork()) {
    case -1:
        ret = errno;
        close(p[0]);
        close(p[1]);
        DEBUG(SSSDBG_CRIT_FAILURE, "fork failed: %d\n", ret);
        return 3;
    case 0:
        /* child */
        av[0] = discard_const(SSH_AK_CLIENT_PATH);
        av[1] = discard_const(pc_user);
        av[2] = NULL;

        close(p[0]);
        ret = dup2(p[1], STDOUT_FILENO);
        if (ret == -1) {
            perror("dup2");
            return 3;
        }

        execv(av[0], av);
        return 3;
    default:
        /* parent */
        break;
    }

    close(p[1]);
    len = read(p[0], buf, sizeof(buf));
    close(p[0]);
    if (len == -1) {
        perror("waitpid");
        return 3;
    }

    pid = waitpid(pid, &status, 0);
    if (pid == -1) {
        perror("waitpid");
        return 3;
    }

    if (WIFEXITED(status)) {
        printf("sss_ssh_authorizedkeys exited with return code %d\n", WEXITSTATUS(status));
        return 0;
    } else if (WIFSIGNALED(status)) {
        printf("sss_ssh_authorizedkeys exited with signal %d\n", WTERMSIG(status));
        return 1;
    }

    printf("sss_ssh_authorizedkeys exited for another reason\n");
    return 2;
}
