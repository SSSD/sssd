/*
   SSSD

   sss_groupmod

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
#include <grp.h>
#include <unistd.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

static void mod_group_req_done(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);

    data->error = sysdb_transaction_commit_recv(req);
    data->done = true;
}

static void mod_group_done(struct ops_ctx *data, int error)
{
    struct tevent_req *req;

    if (error != EOK) {
        goto fail;
    }

    req = sysdb_transaction_commit_send(data, data->ctx->ev, data->handle);
    if (!req) {
        error = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, mod_group_req_done, data);

    return;

fail:
    /* free transaction */
    talloc_zfree(data->handle);

    data->error = error;
    data->done = true;
}

static void mod_group_attr_done(struct tevent_req *req);
static void mod_group_cont(struct ops_ctx *data);
static void remove_from_groups(struct ops_ctx *data);
static void remove_from_groups_done(struct tevent_req *req);
static void add_to_groups(struct ops_ctx *data);
static void add_to_groups_done(struct tevent_req *req);

static void mod_group(struct tevent_req *req)
{
    struct ops_ctx *data;
    struct tevent_req *subreq;
    struct sysdb_attrs *attrs;
    int ret;

    data = tevent_req_callback_data(req, struct ops_ctx);

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return mod_group_done(data, ret);
    }
    talloc_zfree(req);

    if (data->gid != 0) {
        attrs = sysdb_new_attrs(data);
        if (!attrs) {
            mod_group_done(data, ENOMEM);
        }
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, data->gid);
        if (ret) {
            mod_group_done(data, ret);
        }

        subreq = sysdb_set_group_attr_send(data, data->ctx->ev, data->handle,
                                           data->domain, data->name,
                                           attrs, SYSDB_MOD_REP);
        if (!subreq) {
            return mod_group_done(data, ENOMEM);
        }
        tevent_req_set_callback(subreq, mod_group_attr_done, data);
        return;
    }

    return mod_group_cont(data);
}

static void mod_group_attr_done(struct tevent_req *subreq)
{
    struct ops_ctx *data = tevent_req_callback_data(subreq, struct ops_ctx);
    int ret;

    ret = sysdb_set_group_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        return mod_group_done(data, ret);
    }

    mod_group_cont(data);
}

static void mod_group_cont(struct ops_ctx *data)
{
    if (data->rmgroups != NULL) {
        return remove_from_groups(data);
    }

    if (data->addgroups != NULL) {
        return add_to_groups(data);
    }

    return mod_group_done(data, EOK);
}

static void remove_from_groups(struct ops_ctx *data)
{
    struct ldb_dn *parent_dn;
    struct ldb_dn *member_dn;
    struct tevent_req *req;

    parent_dn = sysdb_group_dn(data->ctx->sysdb, data,
                               data->domain->name, data->name);
    if (!parent_dn) {
        return mod_group_done(data, ENOMEM);
    }

    member_dn = sysdb_group_dn(data->ctx->sysdb, data,
                               data->domain->name,
                               data->rmgroups[data->cur]);
    if (!member_dn) {
        return mod_group_done(data, ENOMEM);
    }

    req = sysdb_mod_group_member_send(data,
                                      data->ctx->ev,
                                      data->handle,
                                      member_dn,
                                      parent_dn,
                                      LDB_FLAG_MOD_DELETE);
    if (!req) {
        return mod_group_done(data, ENOMEM);
    }
    tevent_req_set_callback(req, remove_from_groups_done, data);
}

static void remove_from_groups_done(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);
    int ret;

    ret = sysdb_mod_group_member_recv(req);
    if (ret) {
        return mod_group_done(data, ret);
    }
    talloc_zfree(req);

    /* go on to next group */
    data->cur++;

    /* check if we added all of them */
    if (data->rmgroups[data->cur] == NULL) {
        data->cur = 0;
        if (data->addgroups != NULL) {
            return remove_from_groups(data);
        }
        return mod_group_done(data, EOK);
    }

    return remove_from_groups(data);
}

static void add_to_groups(struct ops_ctx *data)
{
    struct ldb_dn *parent_dn;
    struct ldb_dn *member_dn;
    struct tevent_req *req;

    parent_dn = sysdb_group_dn(data->ctx->sysdb, data,
                               data->domain->name, data->name);
    if (!parent_dn) {
        return mod_group_done(data, ENOMEM);
    }

    member_dn = sysdb_group_dn(data->ctx->sysdb, data,
                               data->domain->name,
                               data->addgroups[data->cur]);
    if (!member_dn) {
        return mod_group_done(data, ENOMEM);
    }

    req = sysdb_mod_group_member_send(data,
                                      data->ctx->ev,
                                      data->handle,
                                      member_dn,
                                      parent_dn,
                                      LDB_FLAG_MOD_ADD);
    if (!req) {
        return mod_group_done(data, ENOMEM);
    }
    tevent_req_set_callback(req, add_to_groups_done, data);
}

static void add_to_groups_done(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);
    int ret;

    ret = sysdb_mod_group_member_recv(req);
    if (ret) {
        return mod_group_done(data, ret);
    }
    talloc_zfree(req);

    /* go on to next group */
    data->cur++;

    /* check if we added all of them */
    if (data->addgroups[data->cur] == NULL) {
        return mod_group_done(data, EOK);
    }

    return add_to_groups(data);
}

int main(int argc, const char **argv)
{
    gid_t pc_gid = 0;
    int pc_debug = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                            0, _("The debug level to run with"), NULL },
        { "append-group", 'a', POPT_ARG_STRING, NULL,
                            'a', _("Groups to add this group to"), NULL },
        { "remove-group", 'r', POPT_ARG_STRING, NULL,
                            'r', _("Groups to remove this group from"), NULL },
        { "gid",   'g', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_gid,
                            0, _("The GID of the group"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct ops_ctx *data = NULL;
    struct tevent_req *req;
    char *addgroups = NULL, *rmgroups = NULL;
    int ret;
    struct group *grp_info;
    gid_t old_gid = 0;
    const char *pc_groupname = NULL;

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
    poptSetOtherOptionHelp(pc, "GROUPNAME");
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
        }
    }

    if (ret != -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* groupname is an argument without --option */
    pc_groupname = poptGetArg(pc);
    if (pc_groupname == NULL) {
        usage(pc, _("Specify group to modify\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    debug_level = pc_debug;

    CHECK_ROOT(ret, debug_prg_name);

    ret = init_sss_tools(&data);
    if (ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = get_domain(data, pc_groupname);
    if (ret != EOK) {
        ERROR("Cannot get domain information\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    data->gid = pc_gid;

    if (addgroups) {
        ret = parse_groups(data,
                addgroups,
                &data->addgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse groups to add the group to\n"));
            ERROR("Internal error while parsing parameters\n");
            goto fini;
        }
    }

    if (rmgroups) {
        ret = parse_groups(data,
                rmgroups,
                &data->rmgroups);
        if (ret != EOK) {
            DEBUG(1, ("Cannot parse groups to remove the group from\n"));
            ERROR("Internal error while parsing parameters\n");
            goto fini;
        }
    }

    /* arguments processed, go on to actual work */
    grp_info = getgrnam(data->name);
    if (grp_info) {
       old_gid = grp_info->gr_gid;
    }

    if (id_in_range(data->gid, data->domain) != EOK) {
        ERROR("The selected GID is outside the allowed range\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    req = sysdb_transaction_send(data, data->ctx->ev, data->ctx->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not modify group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, mod_group, data);

    while (!data->done) {
        tevent_loop_once(data->ctx->ev);
    }

    if (data->error) {
        ret = data->error;
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        switch (ret) {
            case ENOENT:
                ERROR("Could not modify group - check if member group names are correct\n");
                break;

            case EFAULT:
                ERROR("Could not modify group - check if groupname is correct\n");
                break;

            default:
                ERROR("Transaction error. Could not modify group.\n");
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
    talloc_free(data);
    exit(ret);
}
