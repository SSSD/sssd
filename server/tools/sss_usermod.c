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

static void mod_user_transaction(struct tevent_req *req)
{
    int ret;
    struct tools_ctx *tctx = tevent_req_callback_data(req,
                                                struct tools_ctx);
    struct tevent_req *subreq;

    ret = sysdb_transaction_recv(req, tctx, &tctx->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(req);

    /* usermod */
    ret = usermod(tctx, tctx->ev,
                  tctx->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        goto fail;
    }

    subreq = sysdb_transaction_commit_send(tctx, tctx->ev, tctx->handle);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, tools_transaction_done, tctx);
    return;

fail:
    /* free transaction and signal error */
    talloc_zfree(tctx->handle);
    tctx->transaction_done = true;
    tctx->error = ret;
}

int main(int argc, const char **argv)
{
    int pc_lock = 0;
    uid_t pc_uid = 0;
    gid_t pc_gid = 0;
    char *pc_gecos = NULL;
    char *pc_home = NULL;
    char *pc_shell = NULL;
    int pc_debug = 0;
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
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    char *addgroups = NULL, *rmgroups = NULL;
    int ret;
    const char *pc_username = NULL;
    struct tools_ctx *tctx = NULL;
    struct tevent_req *req;

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
                    ret = -1;
                }
                break;

            case 'r':
                rmgroups = poptGetOptArg(pc);
                if (rmgroups == NULL) {
                    ret = -1;
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
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    debug_level = pc_debug;

    /* username is an argument without --option */
    pc_username = poptGetArg(pc);
    if (pc_username == NULL) {
        usage(pc, _("Specify user to modify\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    CHECK_ROOT(ret, debug_prg_name);

    ret = init_sss_tools(&tctx);
    if (ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* if the domain was not given as part of FQDN, default to local domain */
    ret = parse_name_domain(tctx, pc_username);
    if (ret != EOK) {
        ERROR("Cannot get domain information\n");
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
            goto fini;
        }
    }

    if (rmgroups) {
        ret = parse_groups(tctx, rmgroups, &tctx->octx->rmgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse groups to remove the user from\n"));
            ERROR("Internal error while parsing parameters\n");
            goto fini;
        }
    }

    tctx->octx->gecos = pc_gecos;
    tctx->octx->home = pc_home;
    tctx->octx->shell = pc_shell;
    tctx->octx->uid = pc_uid;
    tctx->octx->gid = pc_gid;
    tctx->octx->lock = pc_lock;

    req = sysdb_transaction_send(tctx->octx, tctx->ev, tctx->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not modify user.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, mod_user_transaction, tctx);

    while (!tctx->transaction_done) {
        tevent_loop_once(tctx->ev);
    }

    if (tctx->error) {
        ret = tctx->error;
        switch (ret) {
            case ENOENT:
                ERROR("Could not modify user - check if group names are correct\n");
                break;

            case EFAULT:
                ERROR("Could not modify user - check if username is correct\n");
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
