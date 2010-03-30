/*
   SSSD

   sss_userdel

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

#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <popt.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "util/find_uid.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"

#ifndef KILL_CMD
#define KILL_CMD "killall"
#endif

#ifndef KILL_CMD_USER_FLAG
#define KILL_CMD_USER_FLAG "-u"
#endif

#ifndef KILL_CMD_SIGNAL_FLAG
#define KILL_CMD_SIGNAL_FLAG "-s"
#endif

#ifndef KILL_CMD_SIGNAL
#define KILL_CMD_SIGNAL "SIGKILL"
#endif

static int is_logged_in(TALLOC_CTX *mem_ctx, uid_t uid)
{
    int ret;
    hash_key_t key;
    hash_value_t value;
    hash_table_t *uid_table;

    ret = get_uid_table(mem_ctx, &uid_table);
    if (ret == ENOSYS) return ret;
    if (ret != EOK) {
        DEBUG(1, ("Cannot initialize hash table.\n"));
        return ret;
    }

    key.type = HASH_KEY_ULONG;
    key.ul   = (unsigned long) uid;

    ret = hash_lookup(uid_table, &key, &value);
    talloc_zfree(uid_table);
    return ret == HASH_SUCCESS ? EOK : ENOENT;
}

static int kick_user(struct tools_ctx *tctx)
{
    int ret;
    int status;
    pid_t pid, child_pid;

    tctx->octx->lock = 1;

    start_transaction(tctx);
    if (tctx->error != EOK) {
        return tctx->error;
    }

    ret = usermod(tctx, tctx->ev, tctx->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        talloc_zfree(tctx->handle);
        return ret;
    }

    end_transaction(tctx);
    if (tctx->error != EOK) {
        return tctx->error;
    }

    errno = 0;
    pid = fork();
    if (pid == 0) {
        /* child */
        execlp(KILL_CMD, KILL_CMD,
               KILL_CMD_USER_FLAG, tctx->octx->name,
               KILL_CMD_SIGNAL_FLAG, KILL_CMD_SIGNAL,
               (char *) NULL);
        exit(errno);
    } else {
        /* parent */
        if (pid == -1) {
            DEBUG(1, ("fork failed [%d]: %s\n"));
            return errno;
        }

        while((child_pid = waitpid(pid, &status, 0)) > 0) {
            if (child_pid == -1) {
                DEBUG(1, ("waitpid failed\n"));
                return errno;
            }

            if (WIFEXITED(status)) {
                break;
            }
        }
    }

    return EOK;
}

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    struct tools_ctx *tctx = NULL;
    const char *pc_username = NULL;

    int pc_debug = 0;
    int pc_remove = 0;
    int pc_force = 0;
    int pc_kick = 0;
    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                    0, _("The debug level to run with"), NULL },
        { "remove", 'r', POPT_ARG_NONE, NULL, 'r',
                    _("Remove home directory and mail spool"), NULL },
        { "no-remove", 'R', POPT_ARG_NONE, NULL, 'R',
                    _("Do not remove home directory and mail spool"), NULL },
        { "force", 'f', POPT_ARG_NONE, NULL, 'f',
                    _("Force removal of files not owned by the user"), NULL },
        { "kick", 'k', POPT_ARG_NONE, NULL, 'k',
                    _("Kill users' processes before removing him"), NULL },
        POPT_TABLEEND
    };

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* parse parameters */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'r':
                pc_remove = DO_REMOVE_HOME;
                break;

            case 'R':
                pc_remove = DO_NOT_REMOVE_HOME;
                break;

            case 'f':
                pc_force = DO_FORCE_REMOVAL;
                break;

            case 'k':
                pc_kick = 1;
                break;
        }
    }

    debug_level = pc_debug;

    if (ret != -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    pc_username = poptGetArg(pc);
    if (pc_username == NULL) {
        usage(pc, _("Specify user to delete\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    CHECK_ROOT(ret, debug_prg_name);

    ret = init_sss_tools(&tctx);
    if (ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        if (ret == ENOENT) {
            ERROR("Error initializing the tools - no local domain\n");
        } else {
            ERROR("Error initializing the tools\n");
        }
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* if the domain was not given as part of FQDN, default to local domain */
    ret = parse_name_domain(tctx, pc_username);
    if (ret != EOK) {
        ERROR("Invalid domain specified in FQDN\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /*
     * Fills in defaults for ops_ctx user did not specify.
     */
    ret = userdel_defaults(tctx, tctx->confdb, tctx->octx, pc_remove);
    if (ret != EOK) {
        ERROR("Cannot set default values\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = sysdb_getpwnam_sync(tctx,
                              tctx->ev,
                              tctx->sysdb,
                              tctx->octx->name,
                              tctx->local,
                              &tctx->octx);
    if (ret != EOK) {
        /* Error message will be printed in the switch */
        goto done;
    }

    if ((tctx->octx->uid < tctx->local->id_min) ||
        (tctx->local->id_max && tctx->octx->uid > tctx->local->id_max)) {
        ERROR("User %s is outside the defined ID range for domain\n",
              tctx->octx->name);
        ret = EXIT_FAILURE;
        goto fini;
    }

    if (pc_kick) {
        ret = kick_user(tctx);
        if (ret != EOK) {
            tctx->error = ret;

            /* cancel transaction */
            talloc_zfree(tctx->handle);
            goto done;
        }
    }

    start_transaction(tctx);
    if (tctx->error != EOK) {
        goto done;
    }

    /* userdel */
    ret = userdel(tctx, tctx->ev, tctx->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        goto done;
    }

    end_transaction(tctx);

    /* Set SELinux login context - must be done after transaction is done
     * b/c libselinux calls getpwnam */
    ret = del_seuser(tctx->octx->name);
    if (ret != EOK) {
        ERROR("Cannot reset SELinux login context\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    if (!pc_kick) {
        ret = is_logged_in(tctx, tctx->octx->uid);
        switch(ret) {
            case ENOENT:
                break;

            case EOK:
                ERROR("WARNING: The user (uid %lu) was still logged in when "
                      "deleted.\n", (unsigned long) tctx->octx->uid);
                break;

            case ENOSYS:
                ERROR("Cannot determine if the user was logged in on this "
                      "platform");
                break;

            default:
                ERROR("Error while checking if the user was logged in\n");
                break;
        }
    }

    ret = run_userdel_cmd(tctx);
    if (ret != EOK) {
        ERROR("The post-delete command failed: %s\n", strerror(ret));
        goto fini;
    }

    if (tctx->octx->remove_homedir) {
        ret = remove_homedir(tctx,
                             tctx->octx->home,
                             tctx->octx->maildir,
                             tctx->octx->name,
                             tctx->octx->uid,
                             pc_force);
        if (ret == EPERM) {
            ERROR("Not removing home dir - not owned by user\n");
        } else if (ret != EOK) {
            ERROR("Cannot remove homedir: %s\n", strerror(ret));
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    ret = tctx->error;
done:
    if (ret) {
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        switch (ret) {
            case ENOENT:
                ERROR("No such user in local domain. "
                      "Removing users only allowed in local domain.\n");
                break;

            default:
                ERROR("Internal error. Could not remove user.\n");
                break;
        }
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    talloc_free(tctx);
    poptFreeContext(pc);
    exit(ret);
}

