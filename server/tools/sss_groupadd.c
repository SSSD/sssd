/*
   SSSD

   sss_groupadd

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
#include <unistd.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

static void add_group_transaction(struct tevent_req *req)
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

    /* groupadd */
    ret = groupadd(tctx, tctx->ev,
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
    gid_t pc_gid = 0;
    int pc_debug = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug",'\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
            0, _("The debug level to run with"), NULL },
        { "gid",   'g', POPT_ARG_INT, &pc_gid,
            0, _("The GID of the group"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct tools_ctx *tctx = NULL;
    int ret = EXIT_SUCCESS;
    const char *pc_groupname = NULL;
    struct tevent_req *req;

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* parse params */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "GROUPNAME");
    if ((ret = poptGetNextOpt(pc)) < -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    debug_level = pc_debug;

    /* groupname is an argument, not option */
    pc_groupname = poptGetArg(pc);
    if (pc_groupname == NULL) {
        usage(pc, _("Specify group to add\n"));
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
    ret = parse_name_domain(tctx, pc_groupname);
    if (ret != EOK) {
        ERROR("Invalid domain specified in FQDN\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    tctx->octx->gid = pc_gid;

    /* arguments processed, go on to actual work */
    if (id_in_range(tctx->octx->gid, tctx->octx->domain) != EOK) {
        ERROR("The selected GID is outside the allowed range\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* add_group */
    req = sysdb_transaction_send(tctx->octx, tctx->ev, tctx->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not add group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, add_group_transaction, tctx);

    while (!tctx->transaction_done) {
        tevent_loop_once(tctx->ev);
    }

    if (tctx->error) {
        ret = tctx->error;
        switch (ret) {
            case EEXIST:
                ERROR("A group with the same name or GID already exists\n");
                break;

            default:
                DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
                ERROR("Transaction error. Could not add group.\n");
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

