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

static void add_group_req_done(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);

    data->error = sysdb_transaction_commit_recv(req);
    data->done = true;
}

static void add_group_terminate(struct ops_ctx *data, int error)
{
    struct tevent_req *req;

    if (error != EOK) {
        goto fail;
    }

    req = sysdb_transaction_commit_send(data, data->ev, data->handle);
    if (!req) {
        error = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, add_group_req_done, data);

    return;

fail:
    /* free transaction */
    talloc_zfree(data->handle);

    data->error = error;
    data->done = true;
}

static void add_group_done(struct tevent_req *subreq);

static void add_group(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return add_group_terminate(data, ret);
    }

    subreq = sysdb_add_group_send(data, data->ev, data->handle,
                                  data->domain, data->name,
                                  data->gid, NULL);
    if (!subreq) {
        add_group_terminate(data, ENOMEM);
    }
    tevent_req_set_callback(subreq, add_group_done, data);
}

static void add_group_done(struct tevent_req *subreq)
{
    struct ops_ctx *data = tevent_req_callback_data(subreq, struct ops_ctx);
    int ret;

    ret = sysdb_add_group_recv(subreq);
    talloc_zfree(subreq);

    return add_group_terminate(data, ret);
}

static int groupadd_legacy(struct ops_ctx *ctx)
{
    int ret = EOK;
    char *command = NULL;

    command = talloc_asprintf(ctx, "%s ", GROUPADD);
    if (command == NULL) {
        DEBUG(1, ("Cannot allocate memory for command string\n"));
        return ENOMEM;
    }

    APPEND_PARAM(command, GROUPADD_GID, ctx->gid);
    APPEND_STRING(command, ctx->name);

    ret = system(command);
    if (ret) {
        if (ret == -1) {
            DEBUG(1, ("system(3) failed\n"));
        } else {
            DEBUG(1, ("Could not exec '%s', return code: %d\n",
                      command, WEXITSTATUS(ret)));
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
        { "debug",'\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
            0, _("The debug level to run with"), NULL },
        { "gid",   'g', POPT_ARG_INT, &pc_gid,
            0, _("The GID of the group"), NULL },
        POPT_TABLEEND
    };
    struct sss_domain_info *dom;
    poptContext pc = NULL;
    struct tools_ctx *ctx = NULL;
    struct tevent_req *req;
    struct ops_ctx *data = NULL;
    int ret = EXIT_SUCCESS;
    const char *pc_groupname = NULL;

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    CHECK_ROOT(ret, debug_prg_name);

    ret = init_sss_tools(&ctx);
    if(ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    data = talloc_zero(NULL, struct ops_ctx);
    if (data == NULL) {
        DEBUG(1, ("Could not allocate memory for data context\n"));
        ERROR("Out of memory.\n");
        return ENOMEM;
    }
    data->ctx = ctx;
    data->ev = ctx->ev;

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
    pc_groupname = poptGetArg(pc);
    if (pc_groupname == NULL) {
        usage(pc, _("Specify group to add\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = parse_name_domain(data, pc_groupname);
    if (ret != EOK) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    data->gid = pc_gid;

    ret = get_domain_by_id(data->ctx, data->gid, &dom);
    if (ret != EOK) {
        ERROR("Cannot get domain info\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    if (data->domain && data->gid && data->domain != dom) {
        ERROR("Selected domain %s conflicts with selected GID %llu\n",
                data->domain->name, (unsigned long long int) data->gid);
        ret = EXIT_FAILURE;
        goto fini;
    }
    if (data->domain == NULL && dom) {
        data->domain = dom;
    }

    ret = get_domain_type(data->ctx, data->domain);
    switch (ret) {
        case ID_IN_LOCAL:
            break;

        case ID_IN_LEGACY_LOCAL:
            ret = groupadd_legacy(data);
            if(ret != EOK) {
                ERROR("Cannot add group to domain using the legacy tools\n");
            }
            goto fini;

        case ID_OUTSIDE:
            ERROR("The selected GID is outside all domain ranges\n");
            ret = EXIT_FAILURE;
            goto fini;

        case ID_IN_OTHER:
            DEBUG(1, ("Cannot add group to domain %s\n", dom->name));
            ERROR("Unsupported domain type");
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(1, ("Unknown return code %d from get_domain_type\n", ret));
            ERROR("Error looking up domain\n");
            ret = EXIT_FAILURE;
            goto fini;
    }

    /* add_group */
    req = sysdb_transaction_send(ctx, ctx->ev, data->ctx->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not add group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, add_group, data);

    while (!data->done) {
        tevent_loop_once(ctx->ev);
    }

    if (data->error) {
        ret = data->error;
        switch (ret) {
            case EEXIST:
                ERROR("A group with the same name or UID already exists\n");
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
    talloc_free(data);
    talloc_free(ctx);
    poptFreeContext(pc);
    exit(ret);
}

