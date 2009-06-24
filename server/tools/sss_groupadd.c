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
#include <sys/wait.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

#ifndef GROUPADD
#define GROUPADD SHADOW_UTILS_PATH"/groupadd "
#endif

#ifndef GROUPADD_GID
#define GROUPADD_GID "-g %u "
#endif

#ifndef GROUPADD_GROUPNAME
#define GROUPADD_GROUPNAME "%s "
#endif

struct group_add_ctx {
    struct sysdb_handle *handle;

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

    sysdb_transaction_done(data->handle, error);

    if (error)
        data->error = error;
}

/* sysdb_fn_t */
static void add_group(struct sysdb_handle *handle, void *pvt)
{
    struct group_add_ctx *group_ctx;
    int ret;

    group_ctx = talloc_get_type(pvt, struct group_add_ctx);
    group_ctx->handle = handle;

    ret = sysdb_add_group(handle, group_ctx->domain,
                          group_ctx->groupname,
                          group_ctx->gid,
                          add_group_done,
                          group_ctx);

    if(ret != EOK)
        add_group_done(group_ctx, ret, NULL);
}

static int groupadd_legacy(struct group_add_ctx *ctx)
{
    int ret = EOK;
    char *command = NULL;

    command = talloc_asprintf(ctx, "%s ", GROUPADD);
    if (command == NULL) {
        DEBUG(1, ("Cannot allocate memory for command string\n"));
        return ENOMEM;
    }

    APPEND_PARAM(command, GROUPADD_GID, ctx->gid);
    APPEND_STRING(command, ctx->groupname);

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
    gid_t pc_gid = 0;
    int pc_debug = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug",'\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, _("The debug level to run with"), NULL },
        { "gid",   'g', POPT_ARG_INT, &pc_gid, 0, _("The GID of the group"), NULL },
        POPT_TABLEEND
    };
    struct sss_domain_info *dom;
    poptContext pc = NULL;
    struct tools_ctx *ctx = NULL;
    struct group_add_ctx *group_ctx = NULL;
    int ret = EXIT_SUCCESS;

    debug_prg_name = argv[0];

    ret = init_sss_tools(&ctx);
    if(ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx = talloc_zero(NULL, struct group_add_ctx);
    if (group_ctx == NULL) {
        DEBUG(1, ("Could not allocate memory for group_ctx context\n"));
        ERROR("Out of memory.\n");
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

    debug_level = pc_debug;

    /* groupname is an argument, not option */
    group_ctx->groupname = poptGetArg(pc);
    if(group_ctx->groupname == NULL) {
        usage(pc, _("Specify group to add\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx->gid = pc_gid;

    /* arguments processed, go on to actual work */
    ret = find_domain_for_id(ctx, group_ctx->gid, &dom);
    switch (ret) {
        case ID_IN_LOCAL:
            group_ctx->domain = dom;
            break;

        case ID_IN_LEGACY_LOCAL:
            group_ctx->domain = dom;
        case ID_OUTSIDE:
            ret = groupadd_legacy(group_ctx);
            if(ret != EOK) {
                ERROR("Cannot add group to domain using the legacy tools\n");
            }
            goto fini;

        case ID_IN_OTHER:
            DEBUG(1, ("Cannot add group to domain %s\n", dom->name));
            ERROR("Unsupported domain type");
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(1, ("Unknown return code %d from find_domain_for_id\n", ret));
            ERROR("Error looking up domain\n");
            ret = EXIT_FAILURE;
            goto fini;
    }

    /* add_group */
    ret = sysdb_transaction(ctx, ctx->sysdb, add_group, group_ctx);
    if(ret != EOK) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not add group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    while (!group_ctx->done) {
        tevent_loop_once(ctx->ev);
    }

    if (group_ctx->error) {
        ret = group_ctx->error;
        switch (ret) {
            case EEXIST:
                ERROR("The group %s already exists\n", group_ctx->groupname);
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
    talloc_free(group_ctx);
    talloc_free(ctx);
    poptFreeContext(pc);
    exit(ret);
}

