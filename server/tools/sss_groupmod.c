/*
   SSSD

   sss_groupmod

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
#include <errno.h>
#include <grp.h>
#include <unistd.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"

int main(int argc, const char **argv)
{
    gid_t pc_gid = 0;
    int pc_debug = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                            0, _("The debug level to run with"), NULL },
        { "append-group", 'a', POPT_ARG_STRING, NULL,
                            'a', _("Groups to add this group to"), NULL },
        { "remove-group", 'r', POPT_ARG_STRING, NULL,
                            'r', _("Groups to remove this group from"), NULL },
        { "gid",   'g', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_gid,
                            0, _("The GID of the group"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct tools_ctx *tctx = NULL;
    char *addgroups = NULL, *rmgroups = NULL;
    int ret;
    const char *pc_groupname = NULL;
    char *badgroup = NULL;

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
    poptSetOtherOptionHelp(pc, "GROUPNAME");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'a':
                addgroups = poptGetOptArg(pc);
                if (addgroups == NULL) {
                    ret = -1;
                }
                break;

            case 'r':
                rmgroups = poptGetOptArg(pc);
                if (rmgroups == NULL) {
                    ret = -1;
                }
                break;
        }
    }

    if (ret != -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* groupname is an argument without --option */
    pc_groupname = poptGetArg(pc);
    if (pc_groupname == NULL) {
        usage(pc, _("Specify group to modify\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    debug_level = pc_debug;

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

    ret = parse_name_domain(tctx, pc_groupname);
    if (ret != EOK) {
        ERROR("Invalid domain specified in FQDN\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    /* check the username to be able to give sensible error message */
    ret = sysdb_getgrnam_sync(tctx, tctx->ev, tctx->sysdb,
                              tctx->octx->name, tctx->local,
                              &tctx->octx);
    if (ret != EOK) {
        ERROR("Cannot find group in local domain, "
              "modifying groups is allowed only in local domain\n");
        ret = EXIT_FAILURE;
        goto fini;
    }


    tctx->octx->gid = pc_gid;

    if (addgroups) {
        ret = parse_groups(tctx, addgroups, &tctx->octx->addgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse groups to add the group to\n"));
            ERROR("Internal error while parsing parameters\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        ret = parse_group_name_domain(tctx, tctx->octx->addgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse FQDN groups to add the group to\n"));
            ERROR("Member groups must be in the same domain as parent group\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        /* Check group names in the LOCAL domain */
        ret = check_group_names(tctx, tctx->octx->addgroups, &badgroup);
        if (ret != EOK) {
            ERROR("Cannot find group %s in local domain, "
                  "only groups in local domain are allowed\n", badgroup);
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    if (rmgroups) {
        ret = parse_groups(tctx, rmgroups, &tctx->octx->rmgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse groups to remove the group from\n"));
            ERROR("Internal error while parsing parameters\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        ret = parse_group_name_domain(tctx, tctx->octx->rmgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse FQDN groups to remove the group from\n"));
            ERROR("Member groups must be in the same domain as parent group\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        /* Check group names in the LOCAL domain */
        ret = check_group_names(tctx, tctx->octx->rmgroups, &badgroup);
        if (ret != EOK) {
            ERROR("Cannot find group %s in local domain, "
                  "only groups in local domain are allowed\n", badgroup);
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    if (id_in_range(tctx->octx->gid, tctx->octx->domain) != EOK) {
        ERROR("The selected GID is outside the allowed range\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    start_transaction(tctx);
    if (tctx->error != EOK) {
        goto done;
    }

    /* groupmod */
    ret = groupmod(tctx, tctx->ev, tctx->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        goto done;
    }

    end_transaction(tctx);

done:
    if (tctx->error) {
        ret = tctx->error;
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        switch (ret) {
            case ENOENT:
                ERROR("Could not modify group - check if member group names are correct\n");
                break;

            case EFAULT:
                ERROR("Could not modify group - check if groupname is correct\n");
                break;

            default:
                ERROR("Transaction error. Could not modify group.\n");
                break;
        }

        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    free(addgroups);
    free(rmgroups);
    poptFreeContext(pc);
    talloc_free(tctx);
    exit(ret);
}
