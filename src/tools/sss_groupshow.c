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

#define PADDING_SPACES   4
#define GROUP_SHOW_ATTRS { SYSDB_MEMBEROF, SYSDB_GIDNUM, \
                           SYSDB_MEMBER, SYSDB_NAME, \
                           NULL }
#define GROUP_SHOW_MPG_ATTRS { SYSDB_MEMBEROF, SYSDB_UIDNUM, \
                                SYSDB_NAME, NULL }

struct group_info {
    const char *name;
    gid_t gid;
    bool  mpg;

    const char **user_members;
    const char **memberofs;

    struct group_info **group_members;
};

/*==================Helper routines to process results================= */
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

static int parse_memberofs(struct ldb_context *ldb,
                           struct ldb_message_element *el,
                           struct group_info *gi)
{
    int i;
    struct ldb_dn *dn = NULL;

    gi->memberofs = talloc_array(gi, const char *, el->num_values+1);
    if (gi->memberofs == NULL) {
        return ENOMEM;
    }

    for (i = 0; i< el->num_values; ++i) {
        dn = ldb_dn_from_ldb_val(gi, ldb, &(el->values[i]));
        gi->memberofs[i] = talloc_strdup(gi, rdn_as_string(gi, dn));
        talloc_zfree(dn);
        if (gi->memberofs[i] == NULL) {
            return ENOMEM;
        }
        DEBUG(6, ("memberof value: %s\n", gi->memberofs[i]));
    }
    gi->memberofs[el->num_values] = NULL;

    return EOK;
}

static int parse_members(TALLOC_CTX *mem_ctx,
                         struct ldb_context *ldb,
                         struct sss_domain_info *domain,
                         struct ldb_message_element *el,
                         const  char *parent_name,
                         const  char ***user_members,
                         const  char ***group_members,
                         int    *num_group_members)
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
            if (parent_name && strcmp(gm[gm_index], parent_name) == 0) {
                DEBUG(6, ("Skipping circular nesting for group %s\n",
                          gm[gm_index]));
                continue;
            }
            DEBUG(6, ("Group member %s\n", gm[gm_index]));
            gm_index++;
        } else {
            DEBUG(2, ("Group member not a user nor group: %s\n",
                        ldb_dn_get_linearized(dn)));
            ret = EIO;
            goto fail;
        }

        talloc_zfree(dn);
        talloc_zfree(parent_dn);
    }
    um[um_index] = NULL;
    gm[gm_index] = NULL;

    if (um_index > 0) {
        um = talloc_realloc(mem_ctx, um, const char *, um_index+1);
        if (!um) {
            ret = ENOMEM;
            goto fail;
        }
    } else {
        talloc_zfree(um);
    }

    if (gm_index > 0) {
        gm = talloc_realloc(mem_ctx, gm, const char *, gm_index+1);
        if (!gm) {
            ret = ENOMEM;
            goto fail;
        }
    } else {
        talloc_zfree(gm);
    }

    *user_members = um;
    *group_members = gm;
    *num_group_members = gm_index;
    talloc_zfree(tmp_ctx);
    return EOK;

fail:
    talloc_zfree(um);
    talloc_zfree(gm);
    talloc_zfree(tmp_ctx);
    return ret;
}

static int process_group(TALLOC_CTX *mem_ctx,
                         struct ldb_context *ldb,
                         struct ldb_message *msg,
                         struct sss_domain_info *domain,
                         const  char *parent_name,
                         struct group_info **info,
                         const char ***group_members,
                         int    *num_group_members)
{
    struct ldb_message_element *el;
    int ret;
    struct group_info *gi = NULL;

    DEBUG(6, ("Found entry %s\n", ldb_dn_get_linearized(msg->dn)));

    gi = talloc_zero(mem_ctx, struct group_info);
    if (!gi) {
        ret = ENOMEM;
        goto done;
    }

    /* mandatory data - name and gid */
    gi->name = talloc_strdup(gi,
                             ldb_msg_find_attr_as_string(msg,
                                                         SYSDB_NAME,
                                                         NULL));
    gi->gid = ldb_msg_find_attr_as_uint64(msg,
                                          SYSDB_GIDNUM, 0);
    if (gi->gid == 0 || gi->name == NULL) {
        DEBUG(3, ("No name or no GID?\n"));
        ret = EIO;
        goto done;
    }

    /* list members */
    el = ldb_msg_find_element(msg, SYSDB_MEMBER);
    if (el) {
        ret = parse_members(gi, ldb, domain, el,
                            parent_name,
                            &gi->user_members,
                            group_members, num_group_members);
        if (ret != EOK) {
            goto done;
        }
    }

    /* list memberofs */
    el = ldb_msg_find_element(msg, SYSDB_MEMBEROF);
    if (el) {
        ret = parse_memberofs(ldb, el, gi);
        if (ret != EOK) {
            goto done;
        }
    }

    *info = gi;
    return EOK;
done:
    talloc_zfree(gi);
    return ret;
}

/*========Find info about a group and recursively about subgroups====== */
struct group_show_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;

    struct group_info *root;
    bool recursive;
};

static void group_show_root_done(struct tevent_req *subreq);
static void group_show_recurse_done(struct tevent_req *subreq);
static void group_show_trim_done(struct tevent_req *subreq);

struct tevent_req *group_show_recurse_send(TALLOC_CTX *,
                                           struct group_show_state *,
                                           struct group_info *,
                                           const char **,
                                           const int  );
static int group_show_recurse_recv(TALLOC_CTX *, struct tevent_req *,
                                   struct group_info ***);

static struct tevent_req *group_show_trim_memberof_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct sysdb_ctx *sysdb,
                                                struct sysdb_handle *handle,
                                                struct sss_domain_info *domain,
                                                const char *name,
                                                const char **memberofs);
static int group_show_trim_memberof_recv(TALLOC_CTX *mem_ctx,
                                         struct tevent_req *req,
                                         const char ***direct);

struct tevent_req *group_show_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct sysdb_ctx *sysdb,
                                   struct sysdb_handle *handle,
                                   struct sss_domain_info *domain,
                                   bool   recursive,
                                   const char *name)
{
    struct group_show_state *search_state = NULL;
    struct tevent_req *subreq = NULL;
    struct tevent_req *req = NULL;
    static const char *attrs[] = GROUP_SHOW_ATTRS;

    req = tevent_req_create(mem_ctx, &search_state, struct group_show_state);
    if (req == NULL) {
        return NULL;
    }
    search_state->ev = ev;
    search_state->sysdb = sysdb;
    search_state->handle = handle;
    search_state->domain = domain;
    search_state->recursive = recursive;

    /* First, search for the root group */
    subreq = sysdb_search_group_by_name_send(search_state,
                                             search_state->ev,
                                             search_state->sysdb,
                                             search_state->handle,
                                             search_state->domain,
                                             name, attrs);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, group_show_root_done, req);

    return req;
}

static void group_show_root_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct group_show_state *state = tevent_req_data(req,
                                                     struct group_show_state);
    int ret;
    int i;
    struct ldb_message *msg = NULL;
    const char **group_members = NULL;
    int nmembers = 0;

    ret = sysdb_search_group_recv(subreq, state, &msg);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Search failed: %s (%d)\n", strerror(ret), ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = process_group(state,
                        sysdb_ctx_get_ldb(state->sysdb),
                        msg, state->domain, NULL, &state->root,
                        &group_members, &nmembers);
    if (ret != EOK) {
        DEBUG(2, ("Group processing failed: %s (%d)\n",
                   strerror(ret), ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->recursive == false) {
        if (group_members) {
            state->root->group_members = talloc_array(state->root,
                                                    struct group_info *,
                                                    nmembers+1);
            for (i=0; group_members[i]; i++) {
                state->root->group_members[i] = talloc_zero(state->root,
                                                            struct group_info);
                if (!state->root->group_members) {
                    tevent_req_error(req, ENOMEM);
                    return;
                }
                state->root->group_members[i]->name = talloc_strdup(state->root,
                                                                group_members[i]);
                if (!state->root->group_members[i]->name) {
                    tevent_req_error(req, ENOMEM);
                    return;
                }
            }
            state->root->group_members[nmembers] = NULL;
        }

        if (state->root->memberofs == NULL) {
            tevent_req_done(req);
            return;
        }

        /* if not recursive, only show the direct parent */
        subreq = group_show_trim_memberof_send(state, state->ev,
                                               state->sysdb, state->handle,
                                               state->domain, state->root->name,
                                               state->root->memberofs);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, group_show_trim_done, req);
        return;
    }

    if (group_members == NULL) {
        tevent_req_done(req);
        return;
    }

    subreq = group_show_recurse_send(state->root, state,
                                     state->root,
                                     group_members,
                                     nmembers);
    if (!subreq) {
        tevent_req_error(req, ret);
        return;
    }
    tevent_req_set_callback(subreq, group_show_recurse_done, req);
}

static void group_show_trim_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct group_show_state *state = tevent_req_data(req,
                                                     struct group_show_state);
    int ret;

    ret = group_show_trim_memberof_recv(state->root, subreq,
                                        &state->root->memberofs);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static void group_show_recurse_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct group_show_state *state = tevent_req_data(req,
                                                     struct group_show_state);
    int ret;

    ret = group_show_recurse_recv(state->root,
                                  subreq,
                                  &state->root->group_members);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Recursive search failed: %s (%d)\n", strerror(ret), ret));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

static int group_show_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct group_info **res)
{
    struct group_show_state *state = tevent_req_data(req,
                                                     struct group_show_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *res = talloc_move(mem_ctx, &state->root);

    return EOK;
}

/*=========Nonrecursive search should only show direct parent========== */
struct group_show_trim_state {
    const char *name;
    struct ldb_dn *dn;

    const char **all;
    int  current;

    const char **direct;
    int ndirect;

    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;
};

static int group_show_trim_memberof_next(struct tevent_req *req);
static void group_show_trim_memberof_done(struct tevent_req *subreq);

static struct tevent_req *group_show_trim_memberof_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct sysdb_ctx *sysdb,
                                                struct sysdb_handle *handle,
                                                struct sss_domain_info *domain,
                                                const char *name,
                                                const char **memberofs)
{
    struct tevent_req *req = NULL;
    struct group_show_trim_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct group_show_trim_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->domain = domain;
    state->name = name;
    state->all = memberofs;

    state->dn = sysdb_group_dn(state->sysdb, state,
                               state->domain->name,
                               state->name);
    if (!state->dn) {
        talloc_zfree(req);
        return NULL;
    }

    ret = group_show_trim_memberof_next(req);
    if (ret) {
        talloc_zfree(req);
        return NULL;
    }

    return req;
}

static int group_show_trim_memberof_next(struct tevent_req *req)
{
    const char *filter;
    struct tevent_req *subreq = NULL;
    struct group_show_trim_state *state = tevent_req_data(req,
                                                 struct group_show_trim_state);

    filter = talloc_asprintf(req, "(&(%s=%s)(%s=%s))",
                             SYSDB_NAME, state->all[state->current],
                             SYSDB_MEMBER, ldb_dn_get_linearized(state->dn));
    if (!filter) {
        return ENOMEM;
    }

    subreq = sysdb_search_groups_send(state, state->ev, state->sysdb,
                                      state->handle, state->domain,
                                      filter, NULL);
    if (!subreq) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, group_show_trim_memberof_done, req);

    return EOK;
}

static void group_show_trim_memberof_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                 struct tevent_req);
    struct group_show_trim_state *state = tevent_req_data(req,
                                                 struct group_show_trim_state);
    int ret;
    struct ldb_message **msgs;
    size_t count = 0;
    const char *name;

    ret = sysdb_search_groups_recv(subreq, state, &count, &msgs);
    talloc_zfree(subreq);
    /* ENOENT is OK, the group is just not a direct parent */
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }

    if (count > 0) {
        name = ldb_msg_find_attr_as_string(msgs[0],
                                           SYSDB_NAME, NULL);
        if (!name) {
            DEBUG(2, ("Entry %s has no Name Attribute ?!?\n",
                  ldb_dn_get_linearized(msgs[0]->dn)));
            tevent_req_error(req, EFAULT);
            return;
        }

        state->direct = talloc_realloc(state, state->direct,
                                       const char *, state->ndirect+2);
        if (!state->direct) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        state->direct[state->ndirect] = talloc_strdup(state->direct, name);
        if (!state->direct[state->ndirect]) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        state->direct[state->ndirect+1] = NULL;
        state->ndirect++;
    }

    state->current++;
    if (state->all[state->current] != NULL) {
        ret = group_show_trim_memberof_next(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    tevent_req_done(req);
}

static int group_show_trim_memberof_recv(TALLOC_CTX *mem_ctx,
                                         struct tevent_req *req,
                                         const char ***direct)
{
    struct group_show_trim_state *state = tevent_req_data(req,
                                                 struct group_show_trim_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *direct = talloc_move(mem_ctx, &state->direct);

    return EOK;
}

/*==================Recursive search for nested groups================= */
struct group_show_recurse {
    const char **names;
    int  current;

    struct group_info *parent;
    struct group_show_state *state;

    struct group_info **groups;
};

static int  group_show_recurse_search(struct tevent_req *,
                                      struct group_show_recurse *);
static void group_show_recurse_next(struct tevent_req *);
static void group_show_recurse_level_done(struct tevent_req *);
static void group_show_recurse_cont(struct tevent_req *);

struct tevent_req *group_show_recurse_send(TALLOC_CTX *mem_ctx,
                                           struct group_show_state *state,
                                           struct group_info *parent,
                                           const char **group_members,
                                           const int  nmembers)
{
    struct tevent_req *req = NULL;
    struct group_show_recurse *recurse_state = NULL;

    req = tevent_req_create(mem_ctx, &recurse_state, struct group_show_recurse);
    if (req == NULL) {
        return NULL;
    }
    recurse_state->current = 0;
    recurse_state->parent  = parent;
    recurse_state->names   = group_members;
    recurse_state->state   = state;
    recurse_state->groups  = talloc_array(state->root,
                                          struct group_info *,
                                          nmembers+1); /* trailing NULL */

    if (!recurse_state->names ||
        !recurse_state->names[recurse_state->current]) {
        talloc_zfree(req);
        return NULL;
    }

    if (group_show_recurse_search(req, recurse_state) != EOK) {
        talloc_zfree(req);
        return NULL;
    }

    return req;
}

static int group_show_recurse_search(struct tevent_req *req,
                                     struct group_show_recurse *recurse_state)
{
    static const char *attrs[] = GROUP_SHOW_ATTRS;
    struct tevent_req *subreq = NULL;

    /* Skip circular groups */
    if (strcmp(recurse_state->names[recurse_state->current],
               recurse_state->parent->name) == 0) {
        group_show_recurse_cont(req);
        return EOK;
    }

    subreq = sysdb_search_group_by_name_send(recurse_state->state,
                                             recurse_state->state->ev,
                                             recurse_state->state->sysdb,
                                             recurse_state->state->handle,
                                             recurse_state->state->domain,
                                             recurse_state->names[recurse_state->current],
                                             attrs);
    if (!subreq) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, group_show_recurse_next, req);

    return EOK;
}

static void group_show_recurse_next(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct group_show_recurse *recurse_state = tevent_req_data(req,
                                                      struct group_show_recurse);
    const char **group_members = NULL;
    const char **gm = NULL;
    int nmembers = 0;
    struct ldb_message *msg = NULL;
    int ret;
    struct tevent_req *recurse_req = NULL;

    ret = sysdb_search_group_recv(subreq, recurse_state, &msg);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Search failed: %s (%d)\n", strerror(ret), ret));
        tevent_req_error(req, EIO);
        return;
    }

    ret = process_group(recurse_state->state->root,
                        sysdb_ctx_get_ldb(recurse_state->state->sysdb),
                        msg,
                        recurse_state->state->domain,
                        recurse_state->parent->name,
                        &recurse_state->groups[recurse_state->current],
                        &group_members,
                        &nmembers);
    if (ret != EOK) {
        DEBUG(2, ("Group processing failed: %s (%d)\n",
                   strerror(ret), ret));
        tevent_req_error(req, ret);
        return;
    }

    /* descend to another level */
    if (nmembers > 0) {
        recurse_req = group_show_recurse_send(recurse_state,
                                        recurse_state->state,
                                        recurse_state->groups[recurse_state->current],
                                        group_members, nmembers);
        if (!recurse_req) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        /* to free group_members in the callback */
        gm = talloc_move(recurse_req, &group_members);
        if (gm == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(recurse_req, group_show_recurse_level_done, req);
        return;
    }

    /* Move to next group in the same level */
    group_show_recurse_cont(req);
}

static void group_show_recurse_level_done(struct tevent_req *recurse_req)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(recurse_req,
                                                      struct tevent_req);
    struct group_show_recurse *recurse_state = tevent_req_data(recurse_req,
                                                      struct group_show_recurse);

    ret = group_show_recurse_recv(recurse_state->state->root, recurse_req,
                                  &recurse_state->parent->group_members);
    talloc_zfree(recurse_req);
    if (ret) {
        DEBUG(2, ("Recursive search failed: %s (%d)\n", strerror(ret), ret));
        tevent_req_error(req, EIO);
        return;
    }

    /* Move to next group on the upper level */
    group_show_recurse_cont(req);
}

static void group_show_recurse_cont(struct tevent_req *req)
{
    struct group_show_recurse *recurse_state = tevent_req_data(req,
                                                      struct group_show_recurse);
    int ret;

    recurse_state->current++;
    if (recurse_state->names[recurse_state->current] == NULL) {
        recurse_state->groups[recurse_state->current] = NULL; /* Sentinel */
        tevent_req_done(req);
        return;
    }

    /* examine next group on the same level */
    ret = group_show_recurse_search(req, recurse_state);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
}

static int group_show_recurse_recv(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *req,
                                   struct group_info ***out)
{
    struct group_show_recurse *recurse_state = tevent_req_data(req,
                                                         struct group_show_recurse);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *out = talloc_move(mem_ctx, &recurse_state->groups);

    return EOK;
}

/*==================Get info about MPG================================= */
struct group_show_mpg_state {
    struct ldb_context *ldb;
    struct group_info *info;
};

static void group_show_mpg_done(struct tevent_req *);

struct tevent_req *group_show_mpg_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sysdb_ctx *sysdb,
                                       struct sysdb_handle *handle,
                                       struct sss_domain_info *domain,
                                       const char *name)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct group_show_mpg_state *state;
    static const char *mpg_attrs[] = GROUP_SHOW_MPG_ATTRS;

    req = tevent_req_create(mem_ctx, &state, struct group_show_mpg_state);
    if (req == NULL) {
        return NULL;
    }
    state->ldb = sysdb_ctx_get_ldb(sysdb);

    subreq = sysdb_search_user_by_name_send(mem_ctx, ev, sysdb, handle,
                                            domain, name, mpg_attrs);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, group_show_mpg_done, req);

    return req;
}

static void group_show_mpg_done(struct tevent_req *subreq)
{
    int ret;
    struct ldb_message *msg = NULL;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct group_show_mpg_state *state = tevent_req_data(req,
                                                      struct group_show_mpg_state);

    ret = sysdb_search_user_recv(subreq, req, &msg);
    talloc_zfree(subreq);
    if (ret) {
        DEBUG(2, ("Search failed: %s (%d)\n", strerror(ret), ret));
        tevent_req_error(req, ret);
        return;
    }

    state->info = talloc_zero(state, struct group_info);
    if (!state->info) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    state->info->name = talloc_strdup(state->info,
                                      ldb_msg_find_attr_as_string(msg,
                                                                  SYSDB_NAME,
                                                                  NULL));
    state->info->gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
    if (state->info->gid == 0 || state->info->name == NULL) {
        DEBUG(3, ("No name or no GID?\n"));
        tevent_req_error(req, EIO);
        return;
    }
    state->info->mpg = true;

    tevent_req_done(req);
}

static int group_show_mpg_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               struct group_info **res)
{
    struct group_show_mpg_state *state = tevent_req_data(req,
                                                      struct group_show_mpg_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *res = talloc_move(mem_ctx, &state->info);

    return EOK;
}

/*==================The main program=================================== */
struct sss_groupshow_state {
    struct group_info *root;

    int ret;
    bool done;
};

static void sss_group_show_done(struct tevent_req *req)
{
    int ret;
    struct sss_groupshow_state *sss_state = tevent_req_callback_data(req,
                                                   struct sss_groupshow_state);

    ret = group_show_recv(sss_state, req, &sss_state->root);
    talloc_zfree(req);

    sss_state->ret = ret;
    sss_state->done = true;
}

static void sss_group_show_mpg_done(struct tevent_req *req)
{
    int ret;
    struct sss_groupshow_state *sss_state = tevent_req_callback_data(req,
                                                   struct sss_groupshow_state);

    ret = group_show_mpg_recv(sss_state, req, &sss_state->root);
    talloc_zfree(req);

    sss_state->ret = ret;
    sss_state->done = true;
}

static void print_group_info(struct group_info *g, int level)
{
    int i;
    char padding[512];
    char fmt[8];

    snprintf(fmt, 8, "%%%ds", level*PADDING_SPACES);
    snprintf(padding, 512, fmt, "");

    printf(_("%s%sGroup: %s\n"), padding,
                                 g->mpg ? _("Magic Private ") : "",
                                 g->name);
    printf(_("%sGID number: %d\n"), padding, g->gid);

    printf(_("%sMember users: "), padding);
    if (g->user_members) {
        for (i=0; g->user_members[i]; ++i) {
            printf("%s%s", i>0 ? "," : "",
                           g->user_members[i]);
        }
    }
    printf(_("\n%sIs a member of: "), padding);
    if (g->memberofs) {
        for (i=0; g->memberofs[i]; ++i) {
            printf("%s%s", i>0 ? "," : "",
                           g->memberofs[i]);
        }
    }
    printf(_("\n%sMember groups: "), padding);
}

static void print_recursive(struct group_info **group_members, int level)
{
    int i;

    if (group_members == NULL) {
        return;
    }

    level++;
    for (i=0; group_members[i]; ++i) {
        printf("\n");
        print_group_info(group_members[i], level);
        printf("\n");
        print_recursive(group_members[i]->group_members, level);
    }
}

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    int pc_debug = 0;
    bool pc_recursive = false;
    const char *pc_groupname = NULL;
    struct tools_ctx *tctx = NULL;
    struct tevent_req *req = NULL;
    struct sss_groupshow_state *state = NULL;
    int i;

    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                    0, _("The debug level to run with"), NULL },
        { "recursive", 'R', POPT_ARG_NONE, NULL, 'r',
            _("Print indirect group members recursively"), NULL },
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
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'r':
                pc_recursive = true;
                break;
        }
    }

    debug_level = pc_debug;

    if (ret != -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

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

    /* The search itself */
    state = talloc_zero(tctx, struct sss_groupshow_state);
    if (!state) {
        goto fini;
    }

    req = group_show_send(tctx, tctx->ev, tctx->sysdb, tctx->handle,
                          tctx->local, pc_recursive, tctx->octx->name);
    if (!req) {
        ERROR("Cannot initiate search\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, sss_group_show_done, state);
    while (!state->done) {
        tevent_loop_once(tctx->ev);
    }
    ret = state->ret;

    /* Also show MPGs */
    if (ret == ENOENT) {
        state->done = false;
        state->ret  = EOK;

        req = group_show_mpg_send(tctx, tctx->ev, tctx->sysdb, tctx->handle,
                                  tctx->local, tctx->octx->name);
        if (!req) {
            ERROR("Cannot initiate search\n");
            ret = EXIT_FAILURE;
            goto fini;
        }
        tevent_req_set_callback(req, sss_group_show_mpg_done, state);
        while (!state->done) {
            tevent_loop_once(tctx->ev);
        }
        ret = state->ret;
    }

    /* Process result */
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
    print_group_info(state->root, 0);
    if (pc_recursive) {
        printf("\n");
        print_recursive(state->root->group_members, 0);
    } else {
        if (state->root->group_members) {
            for (i=0; state->root->group_members[i]; ++i) {
                printf("%s%s", i>0 ? "," : "",
                               state->root->group_members[i]->name);
            }
        }
        printf("\n");
    }

fini:
    talloc_free(tctx);
    poptFreeContext(pc);
    exit(ret);
}
