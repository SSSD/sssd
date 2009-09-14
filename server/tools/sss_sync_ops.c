/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <tevent.h>
#include <talloc.h>

#include "util/util.h"
#include "db/sysdb.h"

#include "tools/sss_sync_ops.h"

/* Default settings for user attributes */
#define CONFDB_DFL_SECTION "config/user_defaults"

#define DFL_SHELL_ATTR     "defaultShell"
#define DFL_BASEDIR_ATTR   "baseDirectory"

#define DFL_SHELL_VAL      "/bin/bash"
#define DFL_BASEDIR_VAL    "/home"

#define VAR_CHECK(var, val, attr, msg) do { \
        if (var != (val)) { \
            DEBUG(1, (msg" attribute: %s", attr)); \
            return val; \
        } \
} while(0)

#define SYNC_LOOP(ops, retval) do { \
    while (!ops->done) { \
        tevent_loop_once(ev); \
    } \
    retval = ops->error; \
} while(0)

struct sync_op_res {
    int error;
    bool done;
};

/*
 * Generic recv function
 */
static int sync_ops_recv(struct tevent_req *req)
{
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        return err;
    }

    return EOK;
}

/*
 * Generic add member to group
 */
struct add_to_groups_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;

    int cur;
    struct ops_ctx *data;
    struct ldb_dn *member_dn;
};

static void add_to_groups_done(struct tevent_req *subreq);

static struct tevent_req *add_to_groups_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_ctx *sysdb,
                                             struct sysdb_handle *handle,
                                             struct ops_ctx *data,
                                             struct ldb_dn *member_dn)
{
    struct add_to_groups_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ldb_dn *parent_dn;

    req = tevent_req_create(mem_ctx, &state, struct add_to_groups_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->data = data;
    state->member_dn = member_dn;
    state->cur = 0;

    parent_dn = sysdb_group_dn(state->sysdb, state,
                               state->data->domain->name,
                               state->data->addgroups[state->cur]);
    if (!parent_dn) {
        return NULL;
    }

    subreq = sysdb_mod_group_member_send(state,
                                         state->ev,
                                         state->handle,
                                         member_dn,
                                         parent_dn,
                                         LDB_FLAG_MOD_ADD);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, add_to_groups_done, req);
    return req;
}

static void add_to_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct add_to_groups_state *state = tevent_req_data(req,
                                                struct add_to_groups_state);
    int ret;
    struct ldb_dn *parent_dn;
    struct tevent_req *next_group_req;

    ret = sysdb_mod_group_member_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* go on to next group */
    state->cur++;

    /* check if we added all of them */
    if (state->data->addgroups[state->cur] == NULL) {
        tevent_req_done(req);
        return;
    }

    /* if not, schedule a new addition */
    parent_dn = sysdb_group_dn(state->sysdb, state,
                               state->data->domain->name,
                               state->data->addgroups[state->cur]);
    if (!parent_dn) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    next_group_req = sysdb_mod_group_member_send(state,
                                                 state->ev,
                                                 state->handle,
                                                 state->member_dn,
                                                 parent_dn,
                                                 LDB_FLAG_MOD_ADD);
    if (!next_group_req) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(next_group_req, add_to_groups_done, req);
}

static int add_to_groups_recv(struct tevent_req *req)
{
    return sync_ops_recv(req);
}

/*
 * Generic remove member from group
 */
struct remove_from_groups_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;

    int cur;
    struct ops_ctx *data;
    struct ldb_dn *member_dn;
};

static void remove_from_groups_done(struct tevent_req *subreq);

static struct tevent_req *remove_from_groups_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_ctx *sysdb,
                                                  struct sysdb_handle *handle,
                                                  struct ops_ctx *data,
                                                  struct ldb_dn *member_dn)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ldb_dn *parent_dn;
    struct remove_from_groups_state *state;

    req = tevent_req_create(mem_ctx, &state, struct remove_from_groups_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->data = data;
    state->member_dn = member_dn;
    state->cur = 0;

    parent_dn = sysdb_group_dn(state->sysdb, state,
                               state->data->domain->name,
                               state->data->rmgroups[state->cur]);
    if (!parent_dn) {
        return NULL;
    }

    subreq = sysdb_mod_group_member_send(state,
                                         state->ev,
                                         state->handle,
                                         state->member_dn,
                                         parent_dn,
                                         LDB_FLAG_MOD_DELETE);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, remove_from_groups_done, req);
    return req;
}

static void remove_from_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct remove_from_groups_state *state = tevent_req_data(req,
                                                struct remove_from_groups_state);
    int ret;
    struct ldb_dn *parent_dn;
    struct tevent_req *next_group_req;

    ret = sysdb_mod_group_member_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    /* go on to next group */
    state->cur++;

    /* check if we removed all of them */
    if (state->data->rmgroups[state->cur] == NULL) {
        tevent_req_done(req);
        return;
    }

    /* if not, schedule a new removal */
    parent_dn = sysdb_group_dn(state->sysdb, state,
                               state->data->domain->name,
                               state->data->rmgroups[state->cur]);
    if (!parent_dn) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    next_group_req = sysdb_mod_group_member_send(state,
                                                 state->ev,
                                                 state->handle,
                                                 state->member_dn,
                                                 parent_dn,
                                                 LDB_FLAG_MOD_DELETE);
    if (!next_group_req) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(next_group_req, remove_from_groups_done, req);
}

static int remove_from_groups_recv(struct tevent_req *req)
{
    return sync_ops_recv(req);
}

/*
 * Add a user
 */
struct user_add_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;

    struct ops_ctx *data;
};

static void user_add_to_group_done(struct tevent_req *groupreq);
static void user_add_done(struct tevent_req *subreq);

static struct tevent_req *user_add_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sysdb_ctx *sysdb,
                                        struct sysdb_handle *handle,
                                        struct ops_ctx *data)
{
    struct user_add_state *state = NULL;
    struct tevent_req *req;
    struct tevent_req *subreq;

    req = tevent_req_create(mem_ctx, &state, struct user_add_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->data = data;

    subreq = sysdb_add_user_send(state, state->ev, state->handle,
                                 state->data->domain, state->data->name,
                                 state->data->uid, state->data->gid,
                                 state->data->gecos, state->data->home,
                                 state->data->shell, NULL);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, user_add_done, req);
    return req;
}

static void user_add_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct user_add_state *state = tevent_req_data(req,
                                                   struct user_add_state);
    int ret;
    struct ldb_dn *member_dn;
    struct tevent_req *groupreq;

    ret = sysdb_add_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->data->addgroups) {
        member_dn = sysdb_user_dn(state->sysdb, state,
                                  state->data->domain->name,
                                  state->data->name);
        if (!member_dn) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        groupreq = add_to_groups_send(state, state->ev, state->sysdb,
                                      state->handle, state->data, member_dn);
        tevent_req_set_callback(groupreq, user_add_to_group_done, req);
        return;
    }

    return tevent_req_done(req);
}

static void user_add_to_group_done(struct tevent_req *groupreq)
{
    struct tevent_req *req = tevent_req_callback_data(groupreq,
                                                      struct tevent_req);
    int ret;

    ret = add_to_groups_recv(groupreq);
    talloc_zfree(groupreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static int user_add_recv(struct tevent_req *req)
{
    return sync_ops_recv(req);
}

/*
 * Remove a user
 */
struct user_del_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;

    struct ops_ctx *data;
};

static void user_del_done(struct tevent_req *subreq);

static struct tevent_req *user_del_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sysdb_ctx *sysdb,
                                        struct sysdb_handle *handle,
                                        struct ops_ctx *data)
{
    struct user_del_state *state = NULL;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ldb_dn *user_dn;

    req = tevent_req_create(mem_ctx, &state, struct user_del_state);
    if (req == NULL) {
        talloc_zfree(req);
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->data = data;

    user_dn = sysdb_user_dn(state->sysdb, state,
                            state->data->domain->name, state->data->name);
    if (!user_dn) {
        DEBUG(1, ("Could not construct a user DN\n"));
        return NULL;
    }

    subreq = sysdb_delete_entry_send(state,
                                     state->ev, state->handle,
                                     user_dn, false);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, user_del_done, req);
    return req;
}

static void user_del_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    return tevent_req_done(req);
}

static int user_del_recv(struct tevent_req *req)
{
    return sync_ops_recv(req);
}

/*
 * Modify a user
 */
struct user_mod_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;

    struct sysdb_attrs *attrs;
    struct ldb_dn *member_dn;

    struct ops_ctx *data;
};

static int usermod_build_attrs(TALLOC_CTX *mem_ctx,
                               const char *gecos,
                               const char *home,
                               const char *shell,
                               uid_t uid,
                               gid_t gid,
                               int lock,
                               struct sysdb_attrs **_attrs)
{
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return ENOMEM;
    }

    if (shell) {
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_SHELL,
                                     shell);
        VAR_CHECK(ret, EOK, SYSDB_SHELL,
                  "Could not add attribute to changeset\n");
    }

    if (home) {
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_HOMEDIR,
                                     home);
        VAR_CHECK(ret, EOK, SYSDB_HOMEDIR,
                  "Could not add attribute to changeset\n");
    }

    if (gecos) {
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_GECOS,
                                     gecos);
        VAR_CHECK(ret, EOK, SYSDB_GECOS,
                  "Could not add attribute to changeset\n");
    }

    if (uid) {
        ret = sysdb_attrs_add_long(attrs,
                                   SYSDB_UIDNUM,
                                   uid);
        VAR_CHECK(ret, EOK, SYSDB_UIDNUM,
                  "Could not add attribute to changeset\n");
    }

    if (gid) {
        ret = sysdb_attrs_add_long(attrs,
                                   SYSDB_GIDNUM,
                                   gid);
        VAR_CHECK(ret, EOK, SYSDB_GIDNUM,
                  "Could not add attribute to changeset\n");
    }

    if (lock == DO_LOCK) {
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_DISABLED,
                                     "true");
        VAR_CHECK(ret, EOK, SYSDB_DISABLED,
                  "Could not add attribute to changeset\n");
    }

    if (lock == DO_UNLOCK) {
        /* PAM code checks for 'false' value in SYSDB_DISABLED attribute */
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_DISABLED,
                                     "false");
        VAR_CHECK(ret, EOK, SYSDB_DISABLED,
                  "Could not add attribute to changeset\n");
    }

    *_attrs = attrs;
    return EOK;
}

static void user_mod_attr_done(struct tevent_req *attrreq);
static void user_mod_attr_wakeup(struct tevent_req *subreq);
static void user_mod_rm_group_done(struct tevent_req *groupreq);
static void user_mod_add_group_done(struct tevent_req *groupreq);

static struct tevent_req *user_mod_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sysdb_ctx *sysdb,
                                        struct sysdb_handle *handle,
                                        struct ops_ctx *data)
{
    struct user_mod_state *state = NULL;
    struct tevent_req *req;
    struct tevent_req *subreq;
    int ret;
    struct timeval tv = { 0, 0 };

    req = tevent_req_create(mem_ctx, &state, struct user_mod_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->data = data;

    if (data->addgroups || data->rmgroups) {
        state->member_dn = sysdb_user_dn(state->sysdb, state,
                                         state->data->domain->name,
                                         state->data->name);
        if (!state->member_dn) {
            talloc_zfree(req);
            return NULL;
        }
    }

    ret = usermod_build_attrs(state,
                              state->data->gecos,
                              state->data->home,
                              state->data->shell,
                              state->data->uid,
                              state->data->gid,
                              state->data->lock,
                              &state->attrs);
    if (ret != EOK) {
        talloc_zfree(req);
        return NULL;
    }

    subreq = tevent_wakeup_send(req, ev, tv);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, user_mod_attr_wakeup, req);
    return req;
}

static void user_mod_attr_wakeup(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct user_mod_state *state = tevent_req_data(req,
                                                   struct user_mod_state);
    struct tevent_req *attrreq, *groupreq;

    if (state->attrs->num != 0) {
        attrreq = sysdb_set_user_attr_send(state, state->ev, state->handle,
                                           state->data->domain, state->data->name,
                                           state->attrs, SYSDB_MOD_REP);
        if (!attrreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(attrreq, user_mod_attr_done, req);
        return;
    }

    if (state->data->rmgroups != NULL) {
        groupreq = remove_from_groups_send(state, state->ev, state->sysdb,
                                           state->handle, state->data, state->member_dn);
        if (!groupreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(groupreq, user_mod_rm_group_done, req);
        return;
    }

    if (state->data->addgroups != NULL) {
        groupreq = add_to_groups_send(state, state->ev, state->sysdb,
                                      state->handle, state->data, state->member_dn);
        if (!groupreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(groupreq, user_mod_add_group_done, req);
        return;
    }

    /* No changes to be made, mark request as done */
    tevent_req_done(req);
}

static void user_mod_attr_done(struct tevent_req *attrreq)
{
    struct tevent_req *req = tevent_req_callback_data(attrreq,
                                                      struct tevent_req);
    struct user_mod_state *state = tevent_req_data(req,
                                                   struct user_mod_state);
    int ret;
    struct tevent_req *groupreq;

    ret = sysdb_set_user_attr_recv(attrreq);
    talloc_zfree(attrreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->data->rmgroups != NULL) {
        groupreq = remove_from_groups_send(state, state->ev, state->sysdb,
                                           state->handle, state->data, state->member_dn);
        if (!groupreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(groupreq, user_mod_rm_group_done, req);
        return;
    }

    if (state->data->addgroups != NULL) {
        groupreq = add_to_groups_send(state, state->ev, state->sysdb,
                                      state->handle, state->data, state->member_dn);
        if (!groupreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(groupreq, user_mod_add_group_done, req);
        return;
    }

    return tevent_req_done(req);
}

static void user_mod_rm_group_done(struct tevent_req *groupreq)
{
    struct tevent_req *req = tevent_req_callback_data(groupreq,
                                                      struct tevent_req);
    struct user_mod_state *state = tevent_req_data(req,
                                                   struct user_mod_state);
    int ret;
    struct tevent_req *addreq;

    ret = remove_from_groups_recv(groupreq);
    talloc_zfree(groupreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->data->addgroups != NULL) {
        addreq = add_to_groups_send(state, state->ev, state->sysdb,
                                    state->handle, state->data, state->member_dn);
        if (!addreq) {
            tevent_req_error(req, ENOMEM);
        }
        tevent_req_set_callback(addreq, user_mod_add_group_done, req);
        return;
    }

    tevent_req_done(req);
    return;
}

static void user_mod_add_group_done(struct tevent_req *groupreq)
{
    struct tevent_req *req = tevent_req_callback_data(groupreq,
                                                      struct tevent_req);
    int ret;

    ret = add_to_groups_recv(groupreq);
    talloc_zfree(groupreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static int user_mod_recv(struct tevent_req *req)
{
    return sync_ops_recv(req);
}

/*
 * Add a group
 */
struct group_add_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    struct sysdb_attrs *attrs;

    struct ops_ctx *data;
};

static void group_add_done(struct tevent_req *subreq);

static struct tevent_req *group_add_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_ctx *sysdb,
                                         struct sysdb_handle *handle,
                                         struct ops_ctx *data)
{
    struct group_add_state *state = NULL;
    struct tevent_req *req;
    struct tevent_req *subreq;

    req = tevent_req_create(mem_ctx, &state, struct group_add_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->data = data;

    subreq = sysdb_add_group_send(state, state->ev, state->handle,
                                  state->data->domain, state->data->name,
                                  state->data->gid, NULL);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, group_add_done, req);
    return req;
}

static void group_add_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_add_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    return tevent_req_done(req);
}

static int group_add_recv(struct tevent_req *req)
{
    return sync_ops_recv(req);
}

/*
 * Delete a group
 */
struct group_del_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;
    struct sysdb_attrs *attrs;

    struct ops_ctx *data;
};

static void group_del_done(struct tevent_req *subreq);

static struct tevent_req *group_del_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_ctx *sysdb,
                                         struct sysdb_handle *handle,
                                         struct ops_ctx *data)
{
    struct group_del_state *state = NULL;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ldb_dn *group_dn;

    req = tevent_req_create(mem_ctx, &state, struct group_del_state);
    if (req == NULL) {
        talloc_zfree(req);
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->data = data;

    group_dn = sysdb_group_dn(state->sysdb, state,
                              state->data->domain->name, state->data->name);
    if (group_dn == NULL) {
        DEBUG(1, ("Could not construct a group DN\n"));
        return NULL;
    }

    subreq = sysdb_delete_entry_send(state,
                                     state->ev, state->handle,
                                     group_dn, false);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, group_del_done, req);
    return req;
}

static void group_del_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    return tevent_req_done(req);
}

static int group_del_recv(struct tevent_req *req)
{
    return sync_ops_recv(req);
}

/*
 * Modify a group
 */
struct group_mod_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sysdb_handle *handle;

    struct sysdb_attrs *attrs;
    struct ldb_dn *member_dn;

    struct ops_ctx *data;
};

static void group_mod_attr_done(struct tevent_req *);
static void group_mod_attr_wakeup(struct tevent_req *);
static void group_mod_add_group_done(struct tevent_req *groupreq);
static void group_mod_rm_group_done(struct tevent_req *groupreq);

static struct tevent_req *group_mod_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_ctx *sysdb,
                                         struct sysdb_handle *handle,
                                         struct ops_ctx *data)
{
    struct group_mod_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct timeval tv = { 0, 0 };

    req = tevent_req_create(mem_ctx, &state, struct group_mod_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sysdb = sysdb;
    state->handle = handle;
    state->data = data;

    if (data->addgroups || data->rmgroups) {
        state->member_dn = sysdb_group_dn(state->sysdb, state,
                                          state->data->domain->name,
                                          state->data->name);
        if (!state->member_dn) {
            return NULL;
        }
    }

    subreq = tevent_wakeup_send(req, ev, tv);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }

    tevent_req_set_callback(subreq, group_mod_attr_wakeup, req);
    return req;
}

static void group_mod_attr_wakeup(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct group_mod_state *state = tevent_req_data(req,
                                                    struct group_mod_state);
    struct sysdb_attrs *attrs;
    struct tevent_req *attrreq;
    struct tevent_req *groupreq;
    int ret;

    if (state->data->gid != 0) {
        attrs = sysdb_new_attrs(NULL);
        if (!attrs) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, state->data->gid);
        if (ret) {
            tevent_req_error(req, ret);
            return;
        }

        attrreq = sysdb_set_group_attr_send(state, state->ev, state->handle,
                                            state->data->domain, state->data->name,
                                            attrs, SYSDB_MOD_REP);
        if (!attrreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        tevent_req_set_callback(attrreq, group_mod_attr_done, req);
        return;
    }

    if (state->data->rmgroups != NULL) {
        groupreq = remove_from_groups_send(state, state->ev, state->sysdb,
                                           state->handle, state->data, state->member_dn);
        if (!groupreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(groupreq, group_mod_rm_group_done, req);
        return;
    }

    if (state->data->addgroups != NULL) {
        groupreq = add_to_groups_send(state, state->ev, state->sysdb,
                                      state->handle, state->data, state->member_dn);
        if (!groupreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(groupreq, group_mod_add_group_done, req);
        return;
    }

    /* No changes to be made, mark request as done */
    tevent_req_done(req);
}

static void group_mod_attr_done(struct tevent_req *attrreq)
{
    struct tevent_req *req = tevent_req_callback_data(attrreq,
                                                      struct tevent_req);
    struct group_mod_state *state = tevent_req_data(req,
                                                    struct group_mod_state);
    int ret;
    struct tevent_req *groupreq;

    ret = sysdb_set_group_attr_recv(attrreq);
    talloc_zfree(attrreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->data->rmgroups != NULL) {
        groupreq = remove_from_groups_send(state, state->ev, state->sysdb,
                                           state->handle, state->data, state->member_dn);
        if (!groupreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(groupreq, group_mod_rm_group_done, req);
        return;
    }

    if (state->data->addgroups != NULL) {
        groupreq = add_to_groups_send(state, state->ev, state->sysdb,
                                      state->handle, state->data, state->member_dn);
        if (!groupreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(groupreq, group_mod_add_group_done, req);
        return;
    }

    return tevent_req_done(req);
}

static void group_mod_rm_group_done(struct tevent_req *groupreq)
{
    struct tevent_req *req = tevent_req_callback_data(groupreq,
                                                      struct tevent_req);
    struct group_mod_state *state = tevent_req_data(req,
                                                    struct group_mod_state);
    int ret;
    struct tevent_req *addreq;

    ret = remove_from_groups_recv(groupreq);
    talloc_zfree(groupreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->data->addgroups != NULL) {
        addreq = add_to_groups_send(state, state->ev, state->sysdb,
                                    state->handle, state->data, state->member_dn);
        if (!addreq) {
            tevent_req_error(req, ENOMEM);
        }
        tevent_req_set_callback(addreq, group_mod_add_group_done, req);
        return;
    }

    tevent_req_done(req);
    return;
}

static void group_mod_add_group_done(struct tevent_req *groupreq)
{
    struct tevent_req *req = tevent_req_callback_data(groupreq,
                                                      struct tevent_req);
    int ret;

    ret = add_to_groups_recv(groupreq);
    talloc_zfree(groupreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static int group_mod_recv(struct tevent_req *req)
{
    return sync_ops_recv(req);
}

/*
 * Default values for add operations
 */
int useradd_defaults(TALLOC_CTX *mem_ctx,
                     struct confdb_ctx *confdb,
                     struct ops_ctx *data,
                     const char *gecos,
                     const char *homedir,
                     const char *shell)
{
    int ret;
    char *basedir = NULL;
    char *dfl_shell = NULL;

    data->gecos = talloc_strdup(mem_ctx, gecos ? gecos : data->name);
    if (!data->gecos) {
        return ENOMEM;
    }

    if (homedir) {
        data->home = talloc_strdup(data, homedir);
    } else {
        ret = confdb_get_string(confdb, mem_ctx,
                                CONFDB_DFL_SECTION, DFL_BASEDIR_ATTR,
                                DFL_BASEDIR_VAL, &basedir);
        if (ret != EOK) {
            goto done;
        }
        data->home = talloc_asprintf(mem_ctx, "%s/%s", basedir, data->name);
        if (!data->home) {
            ret = ENOMEM;
            goto done;
        }
    }
    if (!data->home) {
        ret = ENOMEM;
        goto done;
    }

    if (!shell) {
        ret = confdb_get_string(confdb, mem_ctx,
                                CONFDB_DFL_SECTION, DFL_SHELL_ATTR,
                                DFL_SHELL_VAL, &dfl_shell);
        if (ret != EOK) {
            goto done;
        }
        shell = dfl_shell;
    }
    data->shell = talloc_strdup(mem_ctx, shell);
    if (!data->shell) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(dfl_shell);
    talloc_free(basedir);
    return ret;
}

/*
 * Public interface for adding users
 */
static void useradd_done(struct tevent_req *);

int useradd(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data)
{
    int ret;
    struct tevent_req *req;
    struct sync_op_res *res = NULL;

    res = talloc_zero(mem_ctx, struct sync_op_res);
    if (!res) {
        return ENOMEM;
    }

    req = user_add_send(res, ev, sysdb, handle, data);
    if (!req) {
        return ENOMEM;
    }
    tevent_req_set_callback(req, useradd_done, res);

    SYNC_LOOP(res, ret);

    talloc_free(res);
    return ret;
}

static void useradd_done(struct tevent_req *req)
{
    int ret;
    struct sync_op_res *res = tevent_req_callback_data(req,
                                                       struct sync_op_res);

    ret = user_add_recv(req);
    talloc_free(req);
    if (ret) {
        DEBUG(2, ("Adding user failed: %s (%d)\n", strerror(ret), ret));
    }

    res->done = true;
    res->error = ret;
}

/*
 * Public interface for deleting users
 */
static void userdel_done(struct tevent_req *req);

int userdel(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data)
{
    int ret;
    struct tevent_req *req;
    struct sync_op_res *res = NULL;

    res = talloc_zero(mem_ctx, struct sync_op_res);
    if (!res) {
        return ENOMEM;
    }

    req = user_del_send(res, ev, sysdb, handle, data);
    if (!req) {
        return ENOMEM;
    }
    tevent_req_set_callback(req, userdel_done, res);

    SYNC_LOOP(res, ret);

    talloc_free(res);
    return ret;
}

static void userdel_done(struct tevent_req *req)
{
    int ret;
    struct sync_op_res *res = tevent_req_callback_data(req,
                                                       struct sync_op_res);

    ret = user_del_recv(req);
    talloc_free(req);
    if (ret) {
        DEBUG(2, ("Removing user failed: %s (%d)\n", strerror(ret), ret));
    }

    res->done = true;
    res->error = ret;
}

/*
 * Public interface for modifying users
 */
static void usermod_done(struct tevent_req *req);

int usermod(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data)
{
    int ret;
    struct tevent_req *req;
    struct sync_op_res *res = NULL;

    res = talloc_zero(mem_ctx, struct sync_op_res);
    if (!res) {
        return ENOMEM;
    }

    req = user_mod_send(res, ev, sysdb, handle, data);
    if (!req) {
        return ENOMEM;
    }
    tevent_req_set_callback(req, usermod_done, res);

    SYNC_LOOP(res, ret);

    talloc_free(res);
    return ret;
}

static void usermod_done(struct tevent_req *req)
{
    int ret;
    struct sync_op_res *res = tevent_req_callback_data(req,
                                                       struct sync_op_res);

    ret = user_mod_recv(req);
    talloc_free(req);
    if (ret) {
        DEBUG(2, ("Modifying user failed: %s (%d)\n", strerror(ret), ret));
    }

    res->done = true;
    res->error = ret;
}

/*
 * Public interface for adding groups
 */
static void groupadd_done(struct tevent_req *);

int groupadd(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data)
{
    int ret;
    struct tevent_req *req;
    struct sync_op_res *res = NULL;

    res = talloc_zero(mem_ctx, struct sync_op_res);
    if (!res) {
        return ENOMEM;
    }

    req = group_add_send(res, ev, sysdb, handle, data);
    if (!req) {
        return ENOMEM;
    }
    tevent_req_set_callback(req, groupadd_done, res);

    SYNC_LOOP(res, ret);

    talloc_free(res);
    return ret;
}

static void groupadd_done(struct tevent_req *req)
{
    int ret;
    struct sync_op_res *res = tevent_req_callback_data(req,
                                                       struct sync_op_res);

    ret = group_add_recv(req);
    talloc_free(req);
    if (ret) {
        DEBUG(2, ("Adding group failed: %s (%d)\n", strerror(ret), ret));
    }

    res->done = true;
    res->error = ret;
}

/*
 * Public interface for deleting groups
 */
static void groupdel_done(struct tevent_req *req);

int groupdel(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data)
{
    int ret;
    struct tevent_req *req;
    struct sync_op_res *res = NULL;

    res = talloc_zero(mem_ctx, struct sync_op_res);
    if (!res) {
        return ENOMEM;
    }

    req = group_del_send(res, ev, sysdb, handle, data);
    if (!req) {
        return ENOMEM;
    }
    tevent_req_set_callback(req, groupdel_done, res);

    SYNC_LOOP(res, ret);

    talloc_free(res);
    return ret;
}

static void groupdel_done(struct tevent_req *req)
{
    int ret;
    struct sync_op_res *res = tevent_req_callback_data(req,
                                                       struct sync_op_res);

    ret = group_del_recv(req);
    talloc_free(req);
    if (ret) {
        DEBUG(2, ("Removing group failed: %s (%d)\n", strerror(ret), ret));
    }

    res->done = true;
    res->error = ret;
}

/*
 * Public interface for modifying groups
 */
static void groupmod_done(struct tevent_req *req);

int groupmod(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data)
{
    int ret;
    struct tevent_req *req;
    struct sync_op_res *res = NULL;

    res = talloc_zero(mem_ctx, struct sync_op_res);
    if (!res) {
        return ENOMEM;
    }

    req = group_mod_send(res, ev, sysdb, handle, data);
    if (!req) {
        return ENOMEM;
    }
    tevent_req_set_callback(req, groupmod_done, res);

    SYNC_LOOP(res, ret);

    talloc_free(res);
    return ret;
}

static void groupmod_done(struct tevent_req *req)
{
    int ret;
    struct sync_op_res *res = tevent_req_callback_data(req,
                                                       struct sync_op_res);

    ret = group_mod_recv(req);
    talloc_free(req);
    if (ret) {
        DEBUG(2, ("Modifying group failed: %s (%d)\n", strerror(ret), ret));
    }

    res->done = true;
    res->error = ret;
}

