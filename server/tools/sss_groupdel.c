/*
   SSSD

   sss_groupdel

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
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "tools/tools_util.h"

#ifndef GROUPDEL
#define GROUPDEL SHADOW_UTILS_PATH"/groupdel "
#endif

#ifndef GROUPDEL_GROUPNAME
#define GROUPDEL_GROUPNAME "%s "
#endif


struct group_del_ctx {
    struct sysdb_req *sysreq;
    sysdb_callback_t next_fn;

    gid_t gid;
    const char *groupname;
    struct ldb_dn *group_dn;

    struct sss_domain_info *domain;
    struct tools_ctx *ctx;

    int error;
    bool done;
};

/* sysdb callback */
static void groupdel_done(void *pvt, int error, struct ldb_result *ignore)
{
    struct group_del_ctx *data = talloc_get_type(pvt, struct group_del_ctx);

    data->done = true;

    sysdb_transaction_done(data->sysreq, error);

    if (error)
        data->error = error;
}

/* sysdb_req_fn_t */
static void group_del(struct sysdb_req *req, void *pvt)
{
    struct group_del_ctx *group_ctx;
    int ret;

    group_ctx = talloc_get_type(pvt, struct group_del_ctx);
    group_ctx->sysreq = req;

    ret = sysdb_delete_entry(req,
                             group_ctx->group_dn,
                             groupdel_done,
                             group_ctx);

    if(ret != EOK)
        groupdel_done(group_ctx, ret, NULL);
}

static int groupdel_legacy(struct group_del_ctx *ctx)
{
    int ret = EOK;
    char *command = NULL;

    APPEND_STRING(command, GROUPDEL);
    APPEND_PARAM(command, GROUPDEL_GROUPNAME, ctx->groupname);

    ret = system(command);
    if (ret) {
        if (ret == -1) {
            DEBUG(1, ("system(3) failed\n"));
        } else {
            DEBUG(1, ("Could not exec '%s', return code: %d\n", command, WEXITSTATUS(ret)));
        }
        talloc_free(command);
        return EFAULT;
    }

    talloc_free(command);
    return ret;
}

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    int pc_debug = 0;
    struct group_del_ctx *group_ctx = NULL;
    struct tools_ctx *ctx = NULL;
    struct sss_domain_info *dom;
    struct group *grp_info;

    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, _("The debug level to run with"), NULL },
        POPT_TABLEEND
    };

    debug_prg_name = argv[0];

    ret = init_sss_tools(&ctx);
    if(ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx = talloc_zero(NULL, struct group_del_ctx);
    if (group_ctx == NULL) {
        DEBUG(1, ("Could not allocate memory for group_ctx context\n"));
        ERROR("Out of memory\n");
        return ENOMEM;
    }
    group_ctx->ctx = ctx;

    /* parse group_ctx */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    if((ret = poptGetNextOpt(pc)) < -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    debug_level = pc_debug;

    group_ctx->groupname = poptGetArg(pc);
    if(group_ctx->groupname == NULL) {
        usage(pc, _("Specify group to delete\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */
    grp_info = getgrnam(group_ctx->groupname);
    if (grp_info) {
        group_ctx->gid = grp_info->gr_gid;
    }

    ret = find_domain_for_id(ctx, group_ctx->gid, &dom);
    switch (ret) {
        case ID_IN_LOCAL:
            group_ctx->domain = dom;
            break;

        case ID_IN_LEGACY_LOCAL:
            group_ctx->domain = dom;
        case ID_OUTSIDE:
            ret = groupdel_legacy(group_ctx);
            if(ret != EOK) {
                ERROR("Cannot delete group from domain using the legacy tools\n");
                ret = EXIT_FAILURE;
                goto fini;
            }
            break; /* Also delete possible cached entries in sysdb */

        case ID_IN_OTHER:
            DEBUG(1, ("Cannot remove group from domain %s\n", dom->name));
            ERROR("Unsupported domain type\n");
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(1, ("Unknown return code %d from find_domain_for_id\n", ret));
            ERROR("Error looking up domain\n");
            ret = EXIT_FAILURE;
            goto fini;
    }

    group_ctx->group_dn = sysdb_group_dn(ctx->sysdb, ctx,
                                         group_ctx->domain->name,
                                         group_ctx->groupname);
    if(group_ctx->group_dn == NULL) {
        DEBUG(1, ("Could not construct a group DN\n"));
        ERROR("Internal database error. Could not remove group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* groupdel */
    ret = sysdb_transaction(ctx, ctx->sysdb, group_del, group_ctx);
    if(ret != EOK) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not remove group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    while (!group_ctx->done) {
        tevent_loop_once(ctx->ev);
    }

    if (group_ctx->error) {
        ret = group_ctx->error;
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not remove group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    talloc_free(ctx);
    talloc_free(group_ctx);
    poptFreeContext(pc);
    exit(ret);
}

