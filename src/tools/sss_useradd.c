/*
   SSSD

   sss_useradd

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009
   Copyright (C) Simo Sorce <ssorce@redhat.com>           2009

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
#include <unistd.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"

static void get_gid_callback(void *ptr, int error, struct ldb_result *res)
{
    struct tools_ctx *tctx = talloc_get_type(ptr, struct tools_ctx);

    if (error) {
        tctx->error = error;
        return;
    }

    switch (res->count) {
    case 0:
        tctx->error = ENOENT;
        break;

    case 1:
        tctx->octx->gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
        if (tctx->octx->gid == 0) {
            tctx->error = ERANGE;
        }
        break;

    default:
        tctx->error = EFAULT;
        break;
    }
}

/* Returns a gid for a given groupname. If a numerical gid
 * is given, returns that as integer (rationale: shadow-utils)
 * On error, returns -EINVAL
 */
static int get_gid(struct tools_ctx *tctx, const char *groupname)
{
    char *end_ptr;
    int ret;

    errno = 0;
    tctx->octx->gid = strtoul(groupname, &end_ptr, 10);
    if (groupname == '\0' || *end_ptr != '\0' ||
        errno != 0 || tctx->octx->gid == 0) {
        /* Does not look like a gid - find the group name */

        ret = sysdb_getgrnam(tctx->octx, tctx->sysdb,
                             tctx->octx->domain, groupname,
                             get_gid_callback, tctx);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_getgrnam failed: %d\n", ret));
            goto done;
        }

        tctx->error = EOK;
        tctx->octx->gid = 0;
        while ((tctx->error == EOK) && (tctx->octx->gid == 0)) {
            tevent_loop_once(tctx->ev);
        }

        if (tctx->error) {
            DEBUG(1, ("sysdb_getgrnam failed: %d\n", ret));
            goto done;
        }
    }

done:
    return ret;
}

int main(int argc, const char **argv)
{
    uid_t pc_uid = 0;
    const char *pc_group = NULL;
    const char *pc_gecos = NULL;
    const char *pc_home = NULL;
    char *pc_shell = NULL;
    int pc_debug = 0;
    int pc_create_home = 0;
    const char *pc_username = NULL;
    const char *pc_skeldir = NULL;
    const char *pc_selinux_user = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, _("The debug level to run with"), NULL },
        { "uid",   'u', POPT_ARG_INT, &pc_uid, 0, _("The UID of the user"), NULL },
        { "gid",   'g', POPT_ARG_STRING, &pc_group, 0, _("The GID or group name of the user"), NULL },
        { "gecos", 'c', POPT_ARG_STRING, &pc_gecos, 0, _("The comment string"), NULL },
        { "home",  'h', POPT_ARG_STRING, &pc_home, 0, _("Home directory"), NULL },
        { "shell", 's', POPT_ARG_STRING, &pc_shell, 0, _("Login shell"), NULL },
        { "groups", 'G', POPT_ARG_STRING, NULL, 'G', _("Groups"), NULL },
        { "create-home", 'm', POPT_ARG_NONE, NULL, 'm', _("Create user's directory if it does not exist"), NULL },
        { "no-create-home", 'M', POPT_ARG_NONE, NULL, 'M', _("Never create user's directory, overrides config"), NULL },
        { "skel", 'k', POPT_ARG_STRING, &pc_skeldir, 0, _("Specify an alternative skeleton directory"), NULL },
        { "selinux-user", 'Z', POPT_ARG_STRING, &pc_selinux_user, 0, _("The SELinux user for user's login"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct tools_ctx *tctx = NULL;
    char *groups = NULL;
    char *badgroup = NULL;
    int ret;

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
            case 'G':
                groups = poptGetOptArg(pc);
                if (!groups) goto fini;

            case 'm':
                pc_create_home = DO_CREATE_HOME;
                break;

            case 'M':
                pc_create_home = DO_NOT_CREATE_HOME;
                break;
        }
    }

    debug_level = pc_debug;

    if (ret != -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* username is an argument without --option */
    pc_username = poptGetArg(pc);
    if (pc_username == NULL) {
        usage(pc, (_("Specify user to add\n")));
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

    if (groups) {
        ret = parse_groups(tctx, groups, &tctx->octx->addgroups);
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
            ERROR("Cannot find group %s in local domain\n", badgroup);
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    /* Same as shadow-utils useradd, -g can specify gid or group name */
    if (pc_group != NULL) {
        ret = get_gid(tctx, pc_group);
        if (ret != EOK) {
            ERROR("Cannot get group information for the user\n");
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    tctx->octx->uid = pc_uid;

    /*
     * Fills in defaults for ops_ctx user did not specify.
     */
    ret = useradd_defaults(tctx, tctx->confdb, tctx->octx,
                           pc_gecos, pc_home, pc_shell,
                           pc_create_home, pc_skeldir);
    if (ret != EOK) {
        ERROR("Cannot set default values\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */
    if (id_in_range(tctx->octx->uid, tctx->octx->domain) != EOK) {
        ERROR("The selected UID is outside the allowed range\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    start_transaction(tctx);
    if (tctx->error != EOK) {
        goto done;
    }

    /* useradd */
    ret = useradd(tctx, tctx->ev, tctx->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        goto done;
    }

    end_transaction(tctx);

    /* Set SELinux login context - must be done after transaction is done
     * b/c libselinux calls getpwnam */
    ret = set_seuser(tctx->octx->name, pc_selinux_user);
    if (ret != EOK) {
        ERROR("Cannot set SELinux login context\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* Create user's home directory and/or mail spool */
    if (tctx->octx->create_homedir) {
        /* We need to know the UID and GID of the user, if
         * sysdb did assign it automatically, do a lookup */
        if (tctx->octx->uid == 0 || tctx->octx->gid == 0) {
            ret = sysdb_getpwnam_sync(tctx,
                                      tctx->ev,
                                      tctx->sysdb,
                                      tctx->octx->name,
                                      tctx->local,
                                      &tctx->octx);
            if (ret != EOK) {
                ERROR("Cannot get info about the user\n");
                ret = EXIT_FAILURE;
                goto fini;
            }
        }

        ret = create_homedir(tctx,
                             tctx->octx->skeldir,
                             tctx->octx->home,
                             tctx->octx->name,
                             tctx->octx->uid,
                             tctx->octx->gid,
                             tctx->octx->umask);
        if (ret == EEXIST) {
            ERROR("User's home directory already exists, not copying "
                  "data from skeldir\n");
        } else if (ret != EOK) {
            ERROR("Cannot create user's home directory: %s\n", strerror(ret));
            ret = EXIT_FAILURE;
            goto fini;
        }

        ret = create_mail_spool(tctx,
                                tctx->octx->name,
                                tctx->octx->maildir,
                                tctx->octx->uid,
                                tctx->octx->gid);
        if (ret != EOK) {
            ERROR("Cannot create user's mail spool: %s\n", strerror(ret));
            DEBUG(1, ("Cannot create user's mail spool: [%d][%s].\n",
                        ret, strerror(ret)));
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

done:
    if (tctx->error) {
        switch (tctx->error) {
            case ERANGE:
                ERROR("Could not allocate ID for the user - domain full?\n");
                break;

            case EEXIST:
                ERROR("A user or group with the same name or ID already exists\n");
                break;

            default:
                DEBUG(1, ("sysdb operation failed (%d)[%s]\n",
                          tctx->error, strerror(tctx->error)));
                ERROR("Transaction error. Could not add user.\n");
                break;
        }
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    poptFreeContext(pc);
    talloc_free(tctx);
    free(groups);
    exit(ret);
}
