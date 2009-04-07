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
#include <sys/types.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

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

int main(int argc, const char **argv)
{
    gid_t pc_gid = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "append-group", 'a', POPT_ARG_STRING, NULL, 'a', "Groups to add this group to", NULL },
        { "remove-group", 'r', POPT_ARG_STRING, NULL, 'r', "Groups to remove this group from", NULL },
        { "gid",   'g', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_gid, 0, "The GID of the group", NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct sss_domain_info *dom;
    struct group_mod_ctx *group_ctx = NULL;
    struct tools_ctx *ctx = NULL;
    char *groups;
    int ret;

    debug_prg_name = argv[0];

    ret = setup_db(&ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up database\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    group_ctx = talloc_zero(ctx, struct group_mod_ctx);
    if (group_ctx == NULL) {
        DEBUG(0, ("Could not allocate memory for group_ctx context\n"));
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

    if(ret != -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* groupname is an argument without --option */
    group_ctx->groupname = poptGetArg(pc);
    if (group_ctx->groupname == NULL) {
        usage(pc, "Specify group to modify\n");
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

    ret = sysdb_transaction(ctx, ctx->sysdb, mod_group, group_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not start transaction (%d)[%s]\n",
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
    poptFreeContext(pc);
    talloc_free(ctx);
    exit(ret);
}
