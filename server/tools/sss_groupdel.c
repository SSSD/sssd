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
#include <sys/types.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "tools/tools_util.h"

struct group_del_ctx {
    struct sysdb_req *sysreq;
    sysdb_callback_t next_fn;

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

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    struct group_del_ctx *group_ctx = NULL;
    struct tools_ctx *ctx = NULL;


    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        POPT_TABLEEND
    };

    debug_prg_name = argv[0];

    ret = setup_db(&ctx);
    if(ret != EOK) {
        DEBUG(0, ("Could not set up database\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx = talloc_zero(NULL, struct group_del_ctx);
    if (group_ctx == NULL) {
        DEBUG(0, ("Could not allocate memory for group_ctx context\n"));
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

    group_ctx->groupname = poptGetArg(pc);
    if(group_ctx->groupname == NULL) {
        usage(pc, "Specify group to delete\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */

    group_ctx->domain = btreemap_get_value(ctx->domains, "LOCAL");
    if (group_ctx->domain == NULL) {
        DEBUG(0, ("Could not set default values\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx->group_dn = sysdb_group_dn(ctx->sysdb, ctx,
                                         group_ctx->domain->name,
                                         group_ctx->groupname);
    if(group_ctx->group_dn == NULL) {
        DEBUG(0, ("Could not construct a group DN\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* groupdel */
    ret = sysdb_transaction(ctx, ctx->sysdb, group_del, group_ctx);
    if(ret != EOK) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
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
    talloc_free(ctx);
    talloc_free(group_ctx);
    poptFreeContext(pc);
    exit(ret);
}

