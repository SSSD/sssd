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
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "tools/tools_util.h"

#ifndef USERDEL
#define USERDEL SHADOW_UTILS_PATH"/userdel "
#endif

#ifndef USERDEL_USERNAME
#define USERDEL_USERNAME    "%s "
#endif

struct user_del_ctx {
    struct sysdb_req *sysreq;
    sysdb_callback_t next_fn;

    uid_t uid;
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

static int userdel_legacy(struct user_del_ctx *ctx)
{
    int ret = EOK;
    char *command = NULL;

    APPEND_STRING(command, USERDEL);
    APPEND_PARAM(command, USERDEL_USERNAME, ctx->username);

    ret = system(command);
    if (ret) {
        if (ret == -1) {
            DEBUG(0, ("system(3) failed\n"));
        } else {
            DEBUG(0,("Could not exec '%s', return code: %d\n", command, WEXITSTATUS(ret)));
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
    struct user_del_ctx *user_ctx = NULL;
    struct tools_ctx *ctx = NULL;
    struct sss_domain_info *dom;
    struct passwd *pwd_info;

    int pc_debug = 0;
    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, "The debug level to run with", NULL },
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

    debug_level = pc_debug;

    user_ctx->username = poptGetArg(pc);
    if(user_ctx->username == NULL) {
        usage(pc, "Specify user to delete\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */
    pwd_info = getpwnam(user_ctx->username);
    if (pwd_info) {
        user_ctx->uid = pwd_info->pw_uid;
    }

    ret = find_domain_for_id(ctx, user_ctx->uid, &dom);
    switch (ret) {
        case ID_IN_LOCAL:
            user_ctx->domain = dom;
            break;

        case ID_IN_LEGACY_LOCAL:
            user_ctx->domain = dom;
        case ID_OUTSIDE:
            ret = userdel_legacy(user_ctx);
            break; /* Also delete possible cached entries in sysdb */

        case ID_IN_OTHER:
            DEBUG(0, ("Cannot delete user from domain %s\n", dom->name));
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(0, ("Unknown return code from find_domain_for_id"));
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

