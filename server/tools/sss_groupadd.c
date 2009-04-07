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
#include <sys/types.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

struct group_add_ctx {
    struct sysdb_req *sysreq;

    struct sss_domain_info *domain;
    struct tools_ctx *ctx;

    const char *groupname;
    gid_t gid;

    int error;
    bool done;
};

/* sysdb callback */
static void add_group_done(void *pvt, int error, struct ldb_result *ignore)
{
    struct group_add_ctx *data = talloc_get_type(pvt, struct group_add_ctx);

    data->done = true;

    sysdb_transaction_done(data->sysreq, error);

    if (error)
        data->error = error;
}

/* sysdb_req_fn_t */
static void add_group(struct sysdb_req *req, void *pvt)
{
    struct group_add_ctx *group_ctx;
    int ret;

    group_ctx = talloc_get_type(pvt, struct group_add_ctx);
    group_ctx->sysreq = req;

    ret = sysdb_add_group(req, group_ctx->domain,
                          group_ctx->groupname,
                          group_ctx->gid,
                          add_group_done,
                          group_ctx);

    if(ret != EOK)
        add_group_done(group_ctx, ret, NULL);
}

int main(int argc, const char **argv)
{
    gid_t pc_gid;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "gid",   'g', POPT_ARG_INT, &pc_gid, 0, "The GID of the group", NULL },
        POPT_TABLEEND
    };
    struct sss_domain_info *dom;
    poptContext pc = NULL;
    struct tools_ctx *ctx = NULL;
    struct group_add_ctx *group_ctx = NULL;
    int ret = EXIT_SUCCESS;

    debug_prg_name = argv[0];


    /* arguments processed, go on to actual work */
    ret = setup_db(&ctx);
    if(ret != EOK) {
        DEBUG(0, ("Could not set up database\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx = talloc_zero(NULL, struct group_add_ctx);
    if (group_ctx == NULL) {
        DEBUG(0, ("Could not allocate memory for group_ctx context\n"));
        return ENOMEM;
    }
    group_ctx->ctx = ctx;

    /* parse params */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "GROUPNAME");
    if((ret = poptGetNextOpt(pc)) < -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* groupname is an argument, not option */
    group_ctx->groupname = poptGetArg(pc);
    if(group_ctx->groupname == NULL) {
        usage(pc, "Specify group to add\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx->gid = pc_gid;

    /* arguments processed, go on to actual work */

    for (dom = ctx->domains; dom; dom = dom->next) {
        if (strcasecmp(dom->name, "LOCAL") == 0) break;
    }
    if (dom == NULL) {
        DEBUG(0, ("Could not get domain info\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }
    group_ctx->domain = dom;

    /* add_group */
    ret = sysdb_transaction(ctx, ctx->sysdb, add_group, group_ctx);
    if(ret != EOK) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n",
                  ret, strerror(ret)));
        ret = EXIT_FAILURE;
        goto fini;
    }

    while (!group_ctx->done) {
        tevent_loop_once(ctx->ev);
    }

    if (group_ctx->error) {
        ret = group_ctx->error;
        DEBUG(0, ("Operation failed (%d)[%s]\n", ret, strerror(ret)));
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;
fini:
    talloc_free(group_ctx);
    talloc_free(ctx);
    poptFreeContext(pc);
    exit(ret);
}

