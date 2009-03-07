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

struct user_del_ctx {
    struct sysdb_req *sysreq;
    sysdb_callback_t next_fn;

    const char *username;
    struct ldb_dn *user_dn;

    struct sss_domain_info *domain;
    struct tools_ctx *ctx;

    int error;
    bool done;
};

/* sysdb callback */
static void userdel_done(void *pvt, int error, struct ldb_result *ignore)
{
    struct user_del_ctx *data = talloc_get_type(pvt, struct user_del_ctx);

    data->done = true;

    sysdb_transaction_done(data->sysreq, error);

    if (error)
        data->error = error;
}

/* sysdb_req_fn_t */
static void user_del(struct sysdb_req *req, void *pvt)
{
    struct user_del_ctx *user_ctx;
    int ret;

    user_ctx = talloc_get_type(pvt, struct user_del_ctx);
    user_ctx->sysreq = req;

    ret = sysdb_delete_entry(req,
                             user_ctx->user_dn,
                             userdel_done,
                             user_ctx);

    if(ret != EOK)
        userdel_done(user_ctx, ret, NULL);
}

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    struct user_del_ctx *user_ctx = NULL;
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

    user_ctx = talloc_zero(NULL, struct user_del_ctx);
    if (user_ctx == NULL) {
        DEBUG(0, ("Could not allocate memory for user_ctx context\n"));
        return ENOMEM;
    }
    user_ctx->ctx = ctx;

    /* parse user_ctx */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    if((ret = poptGetNextOpt(pc)) < -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    user_ctx->username = poptGetArg(pc);
    if(user_ctx->username == NULL) {
        usage(pc, "Specify user to delete\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */

    user_ctx->domain = btreemap_get_value(ctx->domains, "LOCAL");
    if (user_ctx->domain == NULL) {
        DEBUG(0, ("Could not set default values\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    user_ctx->user_dn = sysdb_user_dn(ctx->sysdb, ctx,
                                      user_ctx->domain->name,
                                      user_ctx->username);
    if(user_ctx->user_dn == NULL) {
        DEBUG(0, ("Could not construct an user DN\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }


    /* userdel */
    ret = sysdb_transaction(ctx, ctx->sysdb, user_del, user_ctx);
    if(ret != EOK) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ret = EXIT_FAILURE;
        goto fini;
    }

    while (!user_ctx->done) {
        tevent_loop_once(ctx->ev);
    }

    if (user_ctx->error) {
        ret = user_ctx->error;
        DEBUG(0, ("Operation failed (%d)[%s]\n", ret, strerror(ret)));
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    talloc_free(ctx);
    talloc_free(user_ctx);
    poptFreeContext(pc);
    exit(ret);
}

