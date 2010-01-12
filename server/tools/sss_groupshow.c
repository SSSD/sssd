/*
   SSSD

   sss_groupshow

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2010

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
#include "tools/sss_sync_ops.h"

struct group_show_state {
    const char **user_members;
    const char **group_members;
    const char **memberofs;
    gid_t gid;

    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    bool done;
    int  ret;
};

const char *rdn_as_string(TALLOC_CTX *mem_ctx,
                          struct ldb_dn *dn)
{
    const struct ldb_val *val;

    val = ldb_dn_get_rdn_val(dn);
    if (val == NULL) {
        return NULL;
    }

    return ldb_dn_escape_value(mem_ctx, *val);;
}

int parse_members(TALLOC_CTX *mem_ctx,
                  struct ldb_context *ldb,
                  struct sss_domain_info *domain,
                  struct ldb_message_element *el,
                  const char ***user_members,
                  const char ***group_members)
{
    struct ldb_dn *user_basedn = NULL, *group_basedn = NULL;
    struct ldb_dn *parent_dn = NULL;
    struct ldb_dn *dn = NULL;
    const char **um = NULL, **gm = NULL;
    unsigned int um_index = 0, gm_index = 0;
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;
    int i;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto fail;
    }

    user_basedn = ldb_dn_new_fmt(tmp_ctx, ldb,
                                 SYSDB_TMPL_USER_BASE,
                                 domain->name);
    group_basedn = ldb_dn_new_fmt(tmp_ctx, ldb,
                                  SYSDB_TMPL_GROUP_BASE,
                                  domain->name);
    if (!user_basedn || !group_basedn) {
        ret = ENOMEM;
        goto fail;
    }

    um = talloc_array(mem_ctx, const char *, el->num_values+1);
    gm = talloc_array(mem_ctx, const char *, el->num_values+1);
    if (!um || !gm) {
        ret = ENOMEM;
        goto fail;
    }

    for (i = 0; i< el->num_values; ++i) {
        dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &(el->values[i]));

        /* user member or group member? */
        parent_dn = ldb_dn_get_parent(tmp_ctx, dn);
        if (ldb_dn_compare_base(parent_dn, user_basedn) == 0) {
            um[um_index] = rdn_as_string(mem_ctx, dn);
            if (um[um_index] == NULL) {
                ret = ENOMEM;
                goto fail;
            }
            DEBUG(6, ("User member %s\n", um[um_index]));
            um_index++;
        } else if (ldb_dn_compare_base(parent_dn, group_basedn) == 0) {
            gm[gm_index] = rdn_as_string(mem_ctx, dn);
            if (gm[gm_index] == NULL) {
                ret = ENOMEM;
                goto fail;
            }
            DEBUG(6, ("Group member %s\n", gm[gm_index]));
            gm_index++;
        } else {
            DEBUG(2, ("Group member not a user nor group: %s\n",
                        ldb_dn_get_linearized(dn)));
            ret = EIO;
            goto fail;
        }

        talloc_free(dn);
        talloc_free(parent_dn);
    }
    um[um_index] = NULL;
    gm[gm_index] = NULL;

    um = talloc_realloc(mem_ctx, um, const char *, um_index+1);
    gm = talloc_realloc(mem_ctx, gm, const char *, gm_index+1);
    if (!um || !gm) {
        ret = ENOMEM;
        goto fail;
    }

    *user_members = um;
    *group_members = gm;
    talloc_free(tmp_ctx);
    return EOK;

fail:
    talloc_free(um);
    talloc_free(gm);
    talloc_free(tmp_ctx);
    return ret;
}

static void group_show_done(struct tevent_req *req)
{
    struct group_show_state *state = tevent_req_callback_data(req,
                                                     struct group_show_state);
    int ret;
    int i;
    struct ldb_message *msg = NULL;
    struct ldb_context *ldb = sysdb_ctx_get_ldb(state->sysdb);
    struct ldb_message_element *el;
    struct ldb_dn *dn = NULL;

    ret = sysdb_search_group_recv(req, state, &msg);
    talloc_zfree(req);
    if (ret) {
        DEBUG(2, ("Search failed: %s (%d)\n", strerror(ret), ret));
        ret = EIO;
        goto done;
    }

    DEBUG(6, ("Found entry %s\n", ldb_dn_get_linearized(msg->dn)));

    /* list members */
    el = ldb_msg_find_element(msg, SYSDB_MEMBER);
    if (el) {
        ret = parse_members(state, ldb, state->domain, el,
                            &state->user_members,
                            &state->group_members);
        if (ret != EOK) {
            goto done;
        }
    }

    /* list memberofs */
    el = ldb_msg_find_element(msg, SYSDB_MEMBEROF);
    if (el) {
        state->memberofs = talloc_array(state, const char *, el->num_values+1);
        if (state->memberofs == NULL) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i< el->num_values; ++i) {
            dn = ldb_dn_from_ldb_val(state, ldb, &(el->values[i]));
            state->memberofs[i] = rdn_as_string(state, dn);
            if (state->memberofs[i] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            DEBUG(6, ("memberof value: %s\n", state->memberofs[i]));

            talloc_free(dn);
        }
        state->memberofs[el->num_values] = NULL;
    }

    state->gid = ldb_msg_find_attr_as_uint64(msg,
                                             SYSDB_GIDNUM, 0);
    if (state->gid == 0) {
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    state->ret = ret;
    state->done = true;
}

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    int pc_debug = 0;
    const char *pc_groupname = NULL;
    struct tools_ctx *tctx = NULL;
    struct tevent_req *req = NULL;
    const char *attrs[] = { SYSDB_MEMBEROF, SYSDB_GIDNUM,
                            SYSDB_MEMBER, NULL };
    struct group_show_state *search_state = NULL;
    int i;

    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                    0, _("The debug level to run with"), NULL },
        POPT_TABLEEND
    };

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* parse ops_ctx */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "GROUPNAME");
    if ((ret = poptGetNextOpt(pc)) < -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    debug_level = pc_debug;

    pc_groupname = poptGetArg(pc);
    if (pc_groupname == NULL) {
        usage(pc, _("Specify group to show\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    CHECK_ROOT(ret, debug_prg_name);

    ret = init_sss_tools(&tctx);
    if (ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        if (ret == ENOENT) {
            ERROR("Error initializing the tools - no local domain\n");
        } else {
            ERROR("Error initializing the tools\n");
        }
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* if the domain was not given as part of FQDN, default to local domain */
    ret = parse_name_domain(tctx, pc_groupname);
    if (ret != EOK) {
        ERROR("Invalid domain specified in FQDN\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* Do the search */
    search_state = talloc_zero(tctx, struct group_show_state);
    if (search_state == NULL) {
        ret = EXIT_FAILURE;
        goto fini;
    }
    search_state->sysdb = tctx->sysdb;
    search_state->domain = tctx->local;

    req = sysdb_search_group_by_name_send(tctx, tctx->ev, tctx->sysdb,
                                          tctx->handle, tctx->local,
                                          tctx->octx->name, attrs);
    if (!req || !search_state) {
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, group_show_done, search_state);

    /* Busy wait */
    while (!search_state->done) {
        tevent_loop_once(tctx->ev);
    }

    /* Process result */
    ret = search_state->ret;
    if (ret) {
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        switch (ret) {
            case ENOENT:
                ERROR("No such group in local domain. "
                      "Printing groups only allowed in local domain.\n");
                break;

            default:
                ERROR("Internal error. Could not print group.\n");
                break;
        }
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* print the results */
    printf(_("Group: %s\nGID number: %d"), tctx->octx->name,
                                           search_state->gid);
    if (search_state->user_members) {
        printf(_("\nMember users: "));
        for (i=0; search_state->user_members[i]; ++i) {
            printf("%s ", search_state->user_members[i]);
        }
    }
    if (search_state->group_members) {
        printf(_("\nMember groups: "));
        for (i=0; search_state->group_members[i]; ++i) {
            printf("%s ", search_state->group_members[i]);
        }
    }
    if (search_state->memberofs) {
        printf(_("\nIs a member of: "));
        for (i=0; search_state->memberofs[i]; ++i) {
            printf("%s ", search_state->memberofs[i]);
        }
    }
    printf("\n");

fini:
    talloc_free(tctx);
    poptFreeContext(pc);
    exit(ret);
}
