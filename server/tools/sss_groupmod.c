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
#include <sys/types.h>
#include <sys/wait.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

#ifndef GROUPMOD
#define GROUPMOD SHADOW_UTILS_PATH"/groupmod "
#endif

#ifndef GROUPMOD_GID
#define GROUPMOD_GID "-g %u "
#endif

#ifndef GROUPMOD_GROUPNAME
#define GROUPMOD_GROUPNAME "%s "
#endif

struct group_mod_ctx {
    struct sysdb_req *sysreq;
    struct sss_domain_info *domain;

    struct tools_ctx *ctx;

    gid_t gid;
    const char *groupname;

    char **addgroups;
    char **rmgroups;
    int cur;

    int error;
    bool done;
};

/* sysdb callback */
static void mod_group_done(void *pvt, int error, struct ldb_result *ignore)
{
    struct group_mod_ctx *data = talloc_get_type(pvt, struct group_mod_ctx);

    data->done = true;

    sysdb_transaction_done(data->sysreq, error);

    if (error)
        data->error = error;
}

static void add_to_groups(void *, int, struct ldb_result *);

/* sysdb_req_fn_t */
static void mod_group(struct sysdb_req *req, void *pvt)
{
    struct group_mod_ctx *group_ctx;
    int ret;

    group_ctx = talloc_get_type(pvt, struct group_mod_ctx);
    group_ctx->sysreq = req;

    if(group_ctx->gid == 0) {
        add_to_groups(group_ctx, EOK, NULL);
    } else {
        ret = sysdb_set_group_gid(req,
                                  group_ctx->domain,
                                  group_ctx->groupname,
                                  group_ctx->gid,
                                  mod_group_done,
                                  group_ctx);
        if (ret != EOK) {
            mod_group_done(group_ctx, ret, NULL);
        }
    }
}

static void remove_from_groups(void *pvt, int error, struct ldb_result *ignore)
{
    struct group_mod_ctx *group_ctx = talloc_get_type(pvt, struct group_mod_ctx);
    struct ldb_dn *group_dn;
    struct ldb_dn *parent_group_dn;
    int ret;

    if (error) {
        mod_group_done(pvt, error, NULL);
        return;
    }

    /* check if we removed all of them */
    if (group_ctx->rmgroups == NULL ||
        group_ctx->rmgroups[group_ctx->cur] == NULL) {
        mod_group_done(group_ctx, EOK, NULL);
        return;
    }

    group_dn = sysdb_group_dn(group_ctx->ctx->sysdb, group_ctx,
                            group_ctx->domain->name, group_ctx->groupname);
    if (!group_dn) {
        mod_group_done(pvt, ENOMEM, NULL);
        return;
    }

    parent_group_dn = sysdb_group_dn(group_ctx->ctx->sysdb, group_ctx,
                              group_ctx->domain->name,
                              group_ctx->rmgroups[group_ctx->cur]);
    if (!parent_group_dn) {
        mod_group_done(pvt, ENOMEM, NULL);
        return;
    }

    ret = sysdb_remove_group_member(group_ctx->sysreq,
                                    group_dn, parent_group_dn,
                                    remove_from_groups, group_ctx);
    if (ret != EOK)
        mod_group_done(group_ctx, ret, NULL);

    /* go on to next group */
    group_ctx->cur++;
}

static void add_to_groups(void *pvt, int error, struct ldb_result *ignore)
{
    struct group_mod_ctx *group_ctx = talloc_get_type(pvt, struct group_mod_ctx);
    struct ldb_dn *group_dn;
    struct ldb_dn *parent_group_dn;
    int ret;

    if (error) {
        mod_group_done(pvt, error, NULL);
        return;
    }

    /* check if we added all of them */
    if (group_ctx->addgroups == NULL ||
        group_ctx->addgroups[group_ctx->cur] == NULL) {
        group_ctx->cur = 0;
        remove_from_groups(group_ctx, EOK, NULL);
        return;
    }

    group_dn = sysdb_group_dn(group_ctx->ctx->sysdb, group_ctx,
                            group_ctx->domain->name, group_ctx->groupname);
    if (!group_dn) {
        mod_group_done(pvt, ENOMEM, NULL);
        return;
    }

    parent_group_dn = sysdb_group_dn(group_ctx->ctx->sysdb, group_ctx,
                              group_ctx->domain->name,
                              group_ctx->addgroups[group_ctx->cur]);
    if (!parent_group_dn) {
        mod_group_done(pvt, ENOMEM, NULL);
        return;
    }

    ret = sysdb_add_group_member(group_ctx->sysreq,
                                 group_dn, parent_group_dn,
                                 add_to_groups, group_ctx);
    if (ret != EOK)
        mod_group_done(group_ctx, ret, NULL);

    /* go on to next group */
    group_ctx->cur++;
}

static int groupmod_legacy(struct tools_ctx *tools_ctx, struct group_mod_ctx *ctx, int old_domain)
{
    int ret = EOK;
    char *command = NULL;
    struct sss_domain_info *dom = NULL;

    APPEND_STRING(command, GROUPMOD);

    if (ctx->addgroups || ctx->rmgroups) {
        ERROR("Group nesting is not supported in this domain\n");
        talloc_free(command);
        return EINVAL;
    }

    if (ctx->gid) {
        ret = find_domain_for_id(tools_ctx, ctx->gid, &dom);
        if (ret == old_domain) {
            APPEND_PARAM(command, GROUPMOD_GID, ctx->gid);
        } else {
            ERROR("Changing gid only allowed inside the same domain\n");
            talloc_free(command);
            return EINVAL;
        }
    }

    APPEND_PARAM(command, GROUPMOD_GROUPNAME, ctx->groupname);

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
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, _("The debug level to run with"), NULL },
        { "append-group", 'a', POPT_ARG_STRING, NULL, 'a', _("Groups to add this group to"), NULL },
        { "remove-group", 'r', POPT_ARG_STRING, NULL, 'r', _("Groups to remove this group from"), NULL },
        { "gid",   'g', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_gid, 0, _("The GID of the group"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct sss_domain_info *dom;
    struct group_mod_ctx *group_ctx = NULL;
    struct tools_ctx *ctx = NULL;
    char *groups;
    int ret;
    struct group *grp_info;
    gid_t old_gid = 0;

    debug_prg_name = argv[0];

    ret = init_sss_tools(&ctx);
    if (ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx = talloc_zero(ctx, struct group_mod_ctx);
    if (group_ctx == NULL) {
        DEBUG(1, ("Could not allocate memory for group_ctx context\n"));
        ERROR("Out of memory\n");
        return ENOMEM;
    }
    group_ctx->ctx = ctx;

    /* parse group_ctx */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        if (ret == 'a' || ret == 'r') {
            groups = poptGetOptArg(pc);
            if (!groups) {
                ret = -1;
                break;
            }

            ret = parse_groups(ctx,
                    groups,
                    (ret == 'a') ? (&group_ctx->addgroups) : (&group_ctx->rmgroups));

            free(groups);
            if (ret != EOK) {
                break;
            }
        }
    }

    debug_level = pc_debug;

    if(ret != -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* groupname is an argument without --option */
    group_ctx->groupname = poptGetArg(pc);
    if (group_ctx->groupname == NULL) {
        usage(pc, _("Specify group to modify\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx->gid = pc_gid;

    /* arguments processed, go on to actual work */
    grp_info = getgrnam(group_ctx->groupname);
    if (grp_info) {
       old_gid = grp_info->gr_gid;
    }

    ret = find_domain_for_id(ctx, old_gid, &dom);
    switch (ret) {
        case ID_IN_LOCAL:
            group_ctx->domain = dom;
            break;

        case ID_IN_LEGACY_LOCAL:
            group_ctx->domain = dom;
        case ID_OUTSIDE:
            ret = groupmod_legacy(ctx, group_ctx, ret);
            if(ret != EOK) {
                ERROR("Cannot delete group from domain using the legacy tools\n");
            }
            goto fini;

        case ID_IN_OTHER:
            DEBUG(1, ("Cannot modify group from domain %s\n", dom->name));
            ERROR("Unsupported domain type\n");
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(1, ("Unknown return code %d from find_domain_for_id\n", ret));
            ERROR("Error looking up domain\n");
            ret = EXIT_FAILURE;
            goto fini;
    }

    ret = sysdb_transaction(ctx, ctx->sysdb, mod_group, group_ctx);
    if (ret != EOK) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not modify group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    while (!group_ctx->done) {
        tevent_loop_once(ctx->ev);
    }

    if (group_ctx->error) {
        ret = group_ctx->error;
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not modify group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    poptFreeContext(pc);
    talloc_free(ctx);
    exit(ret);
}
