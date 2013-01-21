/*
   SSSD

   sss_usermod

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
#include <pwd.h>
#include <unistd.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"

int main(int argc, const char **argv)
{
    int pc_lock = 0;
    uid_t pc_uid = 0;
    gid_t pc_gid = 0;
    char *pc_gecos = NULL;
    char *pc_home = NULL;
    char *pc_shell = NULL;
    int pc_debug = SSSDBG_DEFAULT;
    const char *pc_selinux_user = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, _("The debug level to run with"), NULL },
        { "uid",   'u', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_uid, 0, _("The UID of the user"), NULL },
        { "gid",   'g', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_gid, 0, _("The GID of the user"), NULL },
        { "gecos", 'c', POPT_ARG_STRING, &pc_gecos, 0, _("The comment string"), NULL },
        { "home",  'h', POPT_ARG_STRING, &pc_home, 0, _("Home directory"), NULL },
        { "shell", 's', POPT_ARG_STRING, &pc_shell, 0, _("Login shell"), NULL },
        { "append-group", 'a', POPT_ARG_STRING, NULL, 'a', _("Groups to add this user to"), NULL },
        { "remove-group", 'r', POPT_ARG_STRING, NULL, 'r', _("Groups to remove this user from"), NULL },
        { "lock", 'L', POPT_ARG_NONE, NULL, 'L', _("Lock the account"), NULL },
        { "unlock", 'U', POPT_ARG_NONE, NULL, 'U', _("Unlock the account"), NULL },
        { "selinux-user", 'Z', POPT_ARG_STRING, &pc_selinux_user, 0, _("The SELinux user for user's login"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    char *addgroups = NULL, *rmgroups = NULL;
    int ret;
    errno_t sret;
    const char *pc_username = NULL;
    struct tools_ctx *tctx = NULL;
    char *badgroup = NULL;
    bool in_transaction = false;

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
            case 'a':
                addgroups = poptGetOptArg(pc);
                if (addgroups == NULL) {
                    BAD_POPT_PARAMS(pc, _("Specify group to add to\n"),
                                    ret, fini);
                }
                break;

            case 'r':
                rmgroups = poptGetOptArg(pc);
                if (rmgroups == NULL) {
                    BAD_POPT_PARAMS(pc, _("Specify group to remove from\n"),
                                    ret, fini);
                }
                break;

            case 'L':
                pc_lock = DO_LOCK;
                break;

            case 'U':
                pc_lock = DO_UNLOCK;
                break;
        }
    }

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    debug_level = debug_convert_old_level(pc_debug);

    /* username is an argument without --option */
    pc_username = poptGetArg(pc);
    if (pc_username == NULL) {
        BAD_POPT_PARAMS(pc, _("Specify user to modify\n"), ret, fini);
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
    /* check the username to be able to give sensible error message */
    ret = sysdb_getpwnam_sync(tctx, tctx->sysdb, tctx->octx->name, tctx->octx);
    if (ret != EOK) {
        ERROR("Cannot find user in local domain, "
              "modifying users is allowed only in local domain\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    if (id_in_range(tctx->octx->uid, tctx->octx->domain) != EOK) {
        ERROR("The selected UID is outside the allowed range\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    if (addgroups) {
        ret = parse_groups(tctx, addgroups, &tctx->octx->addgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse groups to add the user to\n"));
            ERROR("Internal error while parsing parameters\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        ret = parse_group_name_domain(tctx, tctx->octx->addgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse FQDN groups to add the user to\n"));
            ERROR("Groups must be in the same domain as user\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        /* Check group names in the LOCAL domain */
        ret = check_group_names(tctx, tctx->octx->addgroups, &badgroup);
        if (ret != EOK) {
            ERROR("Cannot find group %1$s in local domain, "
                  "only groups in local domain are allowed\n", badgroup);
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    if (rmgroups) {
        ret = parse_groups(tctx, rmgroups, &tctx->octx->rmgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse groups to remove the user from\n"));
            ERROR("Internal error while parsing parameters\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        ret = parse_group_name_domain(tctx, tctx->octx->rmgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse FQDN groups to remove the user from\n"));
            ERROR("Groups must be in the same domain as user\n");
            ret = EXIT_FAILURE;
            goto fini;
        }

        /* Check group names in the LOCAL domain */
        ret = check_group_names(tctx, tctx->octx->rmgroups, &badgroup);
        if (ret != EOK) {
            ERROR("Cannot find group %1$s in local domain, "
                  "only groups in local domain are allowed\n", badgroup);
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    tctx->octx->gecos = pc_gecos;
    tctx->octx->home = pc_home;
    tctx->octx->shell = pc_shell;
    tctx->octx->uid = pc_uid;
    tctx->octx->gid = pc_gid;
    tctx->octx->lock = pc_lock;

    tctx->error = sysdb_transaction_start(tctx->sysdb);
    if (tctx->error != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    /* usermod */
    tctx->error = usermod(tctx, tctx->sysdb, tctx->octx);
    if (tctx->error) {
        goto done;
    }

    tctx->error = sysdb_transaction_commit(tctx->sysdb);
    if (tctx->error) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto done;
    }
    in_transaction = false;

    ret = sss_mc_refresh_user(pc_username);
    if (ret != EOK) {
        ERROR("NSS request failed (%1$d). Entry might remain in memory "
              "cache.\n", ret);
        /* Nothing we can do about it */
    }

    ret = sss_mc_refresh_grouplist(tctx, tctx->octx->addgroups);
    if (ret != EOK) {
        ERROR("NSS request failed (%1$d). Entry might remain in memory "
              "cache.\n", ret);
        /* Nothing we can do about it */
    }

    ret = sss_mc_refresh_grouplist(tctx, tctx->octx->rmgroups);
    if (ret != EOK) {
        ERROR("NSS request failed (%1$d). Entry might remain in memory "
              "cache.\n", ret);
        /* Nothing we can do about it */
    }

    /* Set SELinux login context - must be done after transaction is done
     * b/c libselinux calls getpwnam */
    ret = set_seuser(tctx->octx->name, pc_selinux_user);
    if (ret != EOK) {
        ERROR("Cannot set SELinux login context\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(tctx->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction\n"));
        }
    }

    if (tctx->error) {
        ret = tctx->error;
        switch (ret) {
            case ENOENT:
                ERROR("Could not modify user - check if group names are correct\n");
                break;

            case EFAULT:
                ERROR("Could not modify user - user already member of groups?\n");
                break;

            default:
                ERROR("Transaction error. Could not modify user.\n");
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
