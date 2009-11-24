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

#include "db/sysdb.h"
#include "util/util.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    struct tools_ctx *tctx = NULL;
    const char *pc_username = NULL;

    int pc_debug = 0;
    int pc_remove = 0;
    int pc_force = 0;
    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                    0, _("The debug level to run with"), NULL },
        { "remove", 'r', POPT_ARG_NONE, NULL, 'r', _("Remove home directory and mail spool"), NULL },
        { "no-remove", 'R', POPT_ARG_NONE, NULL, 'R', _("Do not remove home directory and mail spool"), NULL },
        { "force", 'f', POPT_ARG_NONE, NULL, 'f', _("Force removal of files not owned by the user"), NULL },
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

