/*
   SSSD

   Stress tests

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>	2009

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

#include <signal.h>
#include <stdlib.h>
#include <talloc.h>
#include <popt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#include "util/util.h"
#include "tests/common.h"

#define DEFAULT_START   10
#define DEFAULT_STOP    20

#define NAME_SIZE       255
#define CHUNK           64


/* How many tests failed */
int failure_count;

/* Be chatty */
int verbose;

/*
 * Look up one user. If the user is not found using getpwnam, the success
 * or failure depends on enoent_fail being set.
 */
int test_lookup_user(const char *name, int enoent_fail)
{
    struct passwd *pwd = NULL;
    int ret = 0;
    int error;

    errno = 0;
    pwd = getpwnam(name);
    error = errno;
    if (pwd == NULL) {
        if (error == 0 || error == ENOENT) {
            ret = (enoent_fail == 1) ? ENOENT : 0;
        }
    }

    if (ret != 0 && verbose) {
        fprintf(stderr,
                "getpwnam failed (name: %s): errno = %d, error = %s\n",
                name, ret, strerror(ret));
    }

    return ret;
}

/*
 * Look up one group. If the user is not found using getgrnam, the success
 * or failure depends on enoent_fail being set.
 */
int test_lookup_group(const char *name, int enoent_fail)
{
    struct group *grp = NULL;
    int ret = 0;

    errno = 0;
    grp = getgrnam(name);
    if (grp == NULL) {
        if (errno == 0 || errno == ENOENT) {
            ret = enoent_fail ? ENOENT : 0;
        }
    }

    if (ret != 0 && verbose) {
        fprintf(stderr,
                "getgrnam failed (name %s): errno = %d, error = %s\n",
                name, ret, strerror(ret));
    }

    return ret;
}

int run_one_testcase(const char *name, int group, int enoent_fail)
{
    if (group) {
        return test_lookup_group(name, enoent_fail);
    } else {
        return test_lookup_user(name, enoent_fail);
    }
}

/*
 * Beware, has side-effects: changes global variable failure_count
 */
void child_handler(int signum)
{
    int status, ret;

    while ((ret = wait(&status)) > 0) {
        if (ret == -1) {
            perror("wait");
            exit(EXIT_FAILURE);
        }

        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
            if (ret) {
                if (verbose) {
                    fprintf(stderr,
                            "A child exited with error code %d\n",
                             WEXITSTATUS(status));
                }
                ++failure_count;
            }
        } else ++failure_count;
    }
}

int generate_names(TALLOC_CTX *mem_ctx, const char *prefix,
                   int start, int stop, char ***_out)
{
    char **out;
    int num_names = stop-start+1;
    int idx = 0;

    out = talloc_array(mem_ctx, char *, num_names+1);
    if (out == NULL) {
        return ENOMEM;
    }

    for (idx = 0; idx < num_names; ++idx) {
        out[idx] = talloc_asprintf(mem_ctx, "%s%d", prefix, idx);
        if (out[idx] == NULL) {
            return ENOMEM;
        }
    }
    out[idx] = NULL;

    *_out = out;
    return EOK;
}

int read_names(TALLOC_CTX *mem_ctx, FILE *stream, char ***_out)
{
    char one_name[NAME_SIZE];
    int n = 0;
    int array_size = CHUNK;
    int ret;
    char **out;

    out = talloc_array(mem_ctx, char *, CHUNK+1);
    if (out == NULL) {
        return ENOMEM;
    }
    while (fgets(one_name, NAME_SIZE, stream)) {
        out[n] = talloc_strdup(mem_ctx, one_name);
        if (out[n] == NULL) {
            return ENOMEM;
        }
        if ((n++ % CHUNK) == 0) {
            array_size += CHUNK;
            out = talloc_realloc(mem_ctx, out, char *, array_size);
            if (out == NULL) {
                return ENOMEM;
            }
        }
    }

    if ((ret = ferror(stream))) {
        return ret;
    }
    out[n] = NULL;

    *_out = out;
    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int pc_start=DEFAULT_START;
    int pc_stop=DEFAULT_STOP;
    int pc_enoent_fail=0;
    int pc_groups=0;
    int pc_verbosity = 0;
    char *pc_prefix = NULL;
    TALLOC_CTX *ctx = NULL;
    char **names = NULL;

    int status, idx, ret;
    pid_t   pid;
    struct sigaction action, old_action;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "groups", 'g', POPT_ARG_NONE, &pc_groups, 0,
                    "Lookup in groups instead of users", NULL },
        { "prefix", '\0', POPT_ARG_STRING, &pc_prefix, 0,
                    "The username prefix", NULL },
        { "start",  '\0', POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
                    &pc_start, 0,
                    "Start value to append to prefix", NULL },
        { "stop",   '\0', POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT,
                    &pc_stop, 0,
                    "End value to append to prefix", NULL },
        { "enoent-fail", '\0', POPT_ARG_NONE, &pc_enoent_fail, 0,
                    "Fail on not getting the requested NSS data (default: No)",
                    NULL },
        { "verbose", 'v', POPT_ARG_NONE, 0, 'v',
                    "Be verbose", NULL },
        POPT_TABLEEND
    };

    /* parse the params */
    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
            case 'v':
                pc_verbosity = 1;
                break;

            default:
                fprintf(stderr, "\nInvalid option %s: %s\n\n",
                        poptBadOption(pc, 0), poptStrerror(opt));
                poptPrintUsage(pc, stderr, 0);
                return 1;
        }
    }
    poptFreeContext(pc);

    tests_set_cwd();

    verbose = pc_verbosity;

    if (pc_prefix) {
        ret = generate_names(ctx, pc_prefix, pc_start, pc_stop, &names);
        if (ret != EOK) {
            if (verbose) {
                errno = ret;
                perror("generate_names");
            }
            exit(EXIT_FAILURE);
        }
    } else {
        ret = read_names(ctx, stdin, &names);
        if (ret != EOK) {
            if (verbose) {
                errno = ret;
                perror("read_names");
            }
            exit(EXIT_FAILURE);
        }
    }

    /* Reap the children in a handler asynchronously so we can
     * somehow protect against too many processes */
    memset(&action, 0, sizeof(action));
    action.sa_handler = child_handler;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGCHLD);
    action.sa_flags = SA_NOCLDSTOP;

    sigaction(SIGCHLD, &action, &old_action);

    /* Fire up the child processes */
    idx = 0;
    for (idx=0; names[idx]; idx++) {
        pid = fork();
        if (pid == -1) {
            /* Try again in hope that some child has exited */
            if (errno == EAGAIN) {
                continue;
            }
            perror("fork");
            exit(EXIT_FAILURE);
        } else if ( pid == 0 ) {
            /* child */
            ret = run_one_testcase(names[idx], pc_groups, pc_enoent_fail);
            exit(ret);
        }
    }

    /* Process the rest of the children here in main */
    sigaction(SIGCHLD, &old_action, NULL);
    while ((ret = wait(&status)) > 0) {
        if (ret == -1) {
            perror("wait");
            exit(EXIT_FAILURE);
        }

        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
            if (ret) {
                if (verbose) {
                    fprintf(stderr,
                            "A child exited with error code %d\n",
                             WEXITSTATUS(status));
                }
                ++failure_count;
            }
        } else ++failure_count;
    }

    if (pc_verbosity) {
        fprintf(stderr,
                "Total tests run: %d\nPassed: %d\nFailed: %d\n",
                idx,
                idx - failure_count,
                failure_count);
    }
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
