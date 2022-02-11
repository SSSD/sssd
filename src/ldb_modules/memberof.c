/*
   SSSD memberof module

   Copyright (C) Simo Sorce <idra@samba.org> 2008-2011

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

#include <string.h>
#include <dhash.h>

#include "ldb_module.h"
#include "util/util.h"

#define DB_MEMBER "member"
#define DB_GHOST "ghost"
#define DB_MEMBEROF "memberof"
#define DB_MEMBERUID "memberuid"
#define DB_NAME "name"
#define DB_USER_CLASS "user"
#define DB_GROUP_CLASS "group"
#define DB_CACHE_EXPIRE "dataExpireTimestamp"
#define DB_OC "objectCategory"

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif

struct mbof_val_array {
    struct ldb_val *vals;
    int num;
};

struct mbof_dn_array {
    struct ldb_dn **dns;
    int num;
};

struct mbof_dn {
    struct mbof_dn *next;
    struct ldb_dn *dn;
};

struct mbof_ctx {
    struct ldb_module *module;
    struct ldb_request *req;

    struct ldb_control **ret_ctrls;
    struct ldb_extended *ret_resp;
};

struct mbof_add_operation {
    struct mbof_add_ctx *add_ctx;
    struct mbof_add_operation *next;

    struct mbof_dn_array *parents;
    struct ldb_dn *entry_dn;

    struct ldb_message *entry;
};

struct mbof_memberuid_op {
    struct ldb_dn *dn;
    struct ldb_message_element *el;
};

struct mbof_add_ctx {
    struct mbof_ctx *ctx;

    struct mbof_add_operation *add_list;
    struct mbof_add_operation *current_op;

    struct ldb_message *msg;
    struct ldb_dn *msg_dn;
    bool terminate;

    struct mbof_dn *missing;

    struct mbof_memberuid_op *muops;
    int num_muops;
    int cur_muop;
};

struct mbof_del_ancestors_ctx {
    struct mbof_dn_array *new_list;
    int num_direct;
    int cur;

    struct ldb_message *entry;
};

struct mbof_del_operation {
    struct mbof_del_ctx *del_ctx;
    struct mbof_del_operation *parent;
    struct mbof_del_operation **children;
    int num_children;
    int next_child;

    struct ldb_dn *entry_dn;

    struct ldb_message *entry;
    struct ldb_message **parents;
    int num_parents;
    int cur_parent;

    struct mbof_del_ancestors_ctx *anc_ctx;
};

struct mbof_mod_ctx;

struct mbof_del_ctx {
    struct mbof_ctx *ctx;

    struct mbof_del_operation *first;
    struct mbof_dn *history;

    struct ldb_message **mus;
    int num_mus;

    struct mbof_memberuid_op *muops;
    int num_muops;
    int cur_muop;

    struct mbof_memberuid_op *ghops;
    int num_ghops;
    int cur_ghop;

    struct mbof_mod_ctx *follow_mod;
    bool is_mod;
};

struct mbof_mod_del_op {
    struct mbof_mod_ctx *mod_ctx;

    struct ldb_message *mod_msg;
    struct ldb_message_element *el;

    hash_table_t *inherited_gh;
};

struct mbof_mod_ctx {
    struct mbof_ctx *ctx;

    const struct ldb_message_element *membel;
    const struct ldb_message_element *ghel;
    struct ldb_message *entry;

    struct mbof_dn_array *mb_add;
    struct mbof_dn_array *mb_remove;

    struct mbof_val_array *gh_add;
    struct mbof_val_array *gh_remove;
    struct mbof_mod_del_op *igh;

    struct ldb_message *msg;
    bool terminate;
};

static struct mbof_ctx *mbof_init(struct ldb_module *module,
                                  struct ldb_request *req)
{
    struct mbof_ctx *ctx;

    ctx = talloc_zero(req, struct mbof_ctx);
    if (!ctx) {
        return NULL;
    }

    ctx->module = module;
    ctx->req = req;

    return ctx;
}

static void *hash_alloc(const size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void hash_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

static int entry_has_objectclass(struct ldb_message *entry,
                                 const char *objectclass)
{
    struct ldb_message_element *el;
    struct ldb_val *val;
    int i;

    el = ldb_msg_find_element(entry, DB_OC);
    if (!el) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    for (i = 0; i < el->num_values; i++) {
        val = &(el->values[i]);
        if (strncasecmp(objectclass, (char *)val->data, val->length) == 0) {
            return LDB_SUCCESS;
        }
    }

    return LDB_ERR_NO_SUCH_ATTRIBUTE;
}

static int entry_is_user_object(struct ldb_message *entry)
{
    return entry_has_objectclass(entry, DB_USER_CLASS);
}

static int entry_is_group_object(struct ldb_message *entry)
{
    return entry_has_objectclass(entry, DB_GROUP_CLASS);
}

static int mbof_append_muop(TALLOC_CTX *memctx,
                            struct mbof_memberuid_op **_muops,
                            int *_num_muops,
                            int flags,
                            struct ldb_dn *parent,
                            const char *name,
                            const char *element_name)
{
    struct mbof_memberuid_op *muops = *_muops;
    int num_muops = *_num_muops;
    struct mbof_memberuid_op *op;
    struct ldb_val *val;
    int i;

    op = NULL;
    if (muops) {
        for (i = 0; i < num_muops; i++) {
            if (ldb_dn_compare(parent, muops[i].dn) == 0) {
                op = &muops[i];
                break;
            }
        }
    }
    if (!op) {
        muops = talloc_realloc(memctx, muops,
                               struct mbof_memberuid_op,
                               num_muops + 1);
        if (!muops) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        op = &muops[num_muops];
        num_muops++;
        *_muops = muops;
        *_num_muops = num_muops;

        op->dn = parent;
        op->el = NULL;
    }

    if (!op->el) {
        op->el = talloc_zero(muops, struct ldb_message_element);
        if (!op->el) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        op->el->name = talloc_strdup(op->el, element_name);
        if (!op->el->name) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        op->el->flags = flags;
    }

    for (i = 0; i < op->el->num_values; i++) {
        if (strcmp((char *)op->el->values[i].data, name) == 0) {
            /* we already have this value, get out*/
            return LDB_SUCCESS;
        }
    }

    val = talloc_realloc(op->el, op->el->values,
                         struct ldb_val, op->el->num_values + 1);
    if (!val) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    val[op->el->num_values].data = (uint8_t *)talloc_strdup(val, name);
    if (!val[op->el->num_values].data) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    val[op->el->num_values].length = strlen(name);

    op->el->values = val;
    op->el->num_values++;

    return LDB_SUCCESS;
}


/* add operation */

/* An add operation is quite simple.
 * First of all a new object cannot yet have parents, so the only memberof
 * attribute that can be added to any member contains just one object DN.
 *
 * The real add operation is done first, to assure nothing else fails.
 * Then we list all members of the object just created, and for each member
 * we create an "add operation" and we pass it a parent list of one member
 * (the object we just added again).
 *
 * For each add operation we lookup the object we want to operate on.
 * We take the list of memberof attributes and sort out which parents are
 * still missing from the parent list we have provided.
 * We modify the object memberof attributes to reflect the new memberships.
 * Then we list all members of this object, and for each once again we create
 * an "add operation" as we did in the initial object.
 *
 * Processing stops when the target object does not have members or when it
 * already has all the parents (can happen if nested groups create loops).
 *
 * Group cache unrolling:
 * Every time we add a memberof attribute to an actual user object,
 * we proceed to store the user name.
 *
 * At the end we will add a memberuid attribute to our new object that
 * includes all direct and indirect user members names.
 *
 * Group objects can also contain a "ghost" attribute. A ghost attribute
 * represents a user that is a member of the group but has not yet been
 * looked up so there is no real user entry with member/memberof links.
 *
 * If an object being added contains a "ghost" attribute, the ghost attribute
 * is in turn copied to all parents of that object so that retrieving a
 * group returns both its direct and indirect members. The ghost attribute is
 * similar to the memberuid attribute in many respects. One difference is that
 * the memberuid attribute is completely generated and managed by the memberof
 * plugin - in contrast, the ghost attribute is added to the entry that "owns"
 * it and only propagated to parent groups.
 */

static int mbof_append_addop(struct mbof_add_ctx *add_ctx,
                             struct mbof_dn_array *parents,
                             struct ldb_dn *entry_dn)
{
    struct mbof_add_operation *lastop = NULL;
    struct mbof_add_operation *addop;

    /* test if this is a duplicate */
    /* FIXME: this is not efficient */
    if (add_ctx->add_list) {
        do {
            if (lastop) {
                lastop = lastop->next;
            } else {
                lastop = add_ctx->add_list;
            }

            /* FIXME: check if this is right, might have to compare parents */
            if (ldb_dn_compare(lastop->entry_dn, entry_dn) == 0) {
                /* duplicate found */
                return LDB_SUCCESS;
            }
        } while (lastop->next);
    }

    addop = talloc_zero(add_ctx, struct mbof_add_operation);
    if (!addop) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    addop->add_ctx = add_ctx;
    addop->parents = parents;
    addop->entry_dn = entry_dn;

    if (add_ctx->add_list) {
        lastop->next = addop;
    } else {
        add_ctx->add_list = addop;
    }

    return LDB_SUCCESS;
}

static int mbof_add_fill_ghop_ex(struct mbof_add_ctx *add_ctx,
                                 struct ldb_message *entry,
                                 struct mbof_dn_array *parents,
                                 struct ldb_val *ghvals,
                                 unsigned int num_gh_vals)
{
    int ret;
    int i, j;

    if (!parents || parents->num == 0) {
        /* no parents attributes ... */
        return LDB_SUCCESS;
    }

    ret = entry_is_group_object(entry);
    switch (ret) {
    case LDB_SUCCESS:
        /* it's a group object, continue */
        break;

    case LDB_ERR_NO_SUCH_ATTRIBUTE:
        /* it is not a group object, just return */
        return LDB_SUCCESS;

    default:
        /* an error occurred, return */
        return ret;
    }

    ldb_debug(ldb_module_get_ctx(add_ctx->ctx->module),
              LDB_DEBUG_TRACE,
              "will add %d ghost users to %d parents\n",
              num_gh_vals, parents->num);

    for (i = 0; i < parents->num; i++) {
        for (j = 0; j < num_gh_vals; j++) {
            ret = mbof_append_muop(add_ctx, &add_ctx->muops,
                                   &add_ctx->num_muops,
                                   LDB_FLAG_MOD_ADD,
                                   parents->dns[i],
                                   (const char *) ghvals[j].data,
                                   DB_GHOST);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }
    }

    return LDB_SUCCESS;
}

static int memberof_recompute_task(struct ldb_module *module,
                                   struct ldb_request *req);

static int mbof_add_callback(struct ldb_request *req,
                             struct ldb_reply *ares);
static int mbof_next_add(struct mbof_add_operation *addop);
static int mbof_next_add_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static int mbof_add_operation(struct mbof_add_operation *addop);
static int mbof_add_fill_ghop(struct mbof_add_ctx *add_ctx,
                              struct ldb_message *entry,
                              struct mbof_dn_array *parents);
static int mbof_add_missing(struct mbof_add_ctx *add_ctx, struct ldb_dn *dn);
static int mbof_add_cleanup(struct mbof_add_ctx *add_ctx);
static int mbof_add_cleanup_callback(struct ldb_request *req,
                                     struct ldb_reply *ares);
static int mbof_add_muop(struct mbof_add_ctx *add_ctx);
static int mbof_add_muop_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);

static int memberof_add(struct ldb_module *module, struct ldb_request *req)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct mbof_add_ctx *add_ctx;
    struct mbof_ctx *ctx;
    struct ldb_request *add_req;
    struct ldb_message_element *el;
    struct mbof_dn_array *parents;
    struct ldb_dn *valdn;
    int i, ret;

    if (ldb_dn_is_special(req->op.add.message->dn)) {

        if (strcmp("@MEMBEROF-REBUILD",
                   ldb_dn_get_linearized(req->op.add.message->dn)) == 0) {
            return memberof_recompute_task(module, req);
        }

        /* do not manipulate other control entries */
        return ldb_next_request(module, req);
    }

    /* check if memberof is specified */
    el = ldb_msg_find_element(req->op.add.message, DB_MEMBEROF);
    if (el) {
        ldb_debug(ldb, LDB_DEBUG_ERROR,
                  "Error: the memberof attribute is readonly.");
        return LDB_ERR_UNWILLING_TO_PERFORM;
    }

    /* check if memberuid is specified */
    el = ldb_msg_find_element(req->op.add.message, DB_MEMBERUID);
    if (el) {
        ldb_debug(ldb, LDB_DEBUG_ERROR,
                  "Error: the memberuid attribute is readonly.");
        return LDB_ERR_UNWILLING_TO_PERFORM;
    }

    ctx = mbof_init(module, req);
    if (!ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    add_ctx = talloc_zero(ctx, struct mbof_add_ctx);
    if (!add_ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    add_ctx->ctx = ctx;

    add_ctx->msg = ldb_msg_copy(add_ctx, req->op.add.message);
    if (!add_ctx->msg) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    add_ctx->msg_dn = add_ctx->msg->dn;

    /* continue with normal ops if there are no members */
    el = ldb_msg_find_element(add_ctx->msg, DB_MEMBER);
    if (!el) {
        add_ctx->terminate = true;
        goto done;
    }

    parents = talloc_zero(add_ctx, struct mbof_dn_array);
    if (!parents) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    parents->dns = talloc_array(parents, struct ldb_dn *, 1);
    if (!parents->dns) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    parents->dns[0] = add_ctx->msg_dn;
    parents->num = 1;

    /* process new members */
    /* check we are not adding ourselves as member as well */
    for (i = 0; i < el->num_values; i++) {
        valdn = ldb_dn_from_ldb_val(add_ctx, ldb, &el->values[i]);
        if (!valdn || !ldb_dn_validate(valdn)) {
            ldb_debug(ldb, LDB_DEBUG_ERROR, "Invalid dn value: [%s]",
                                            (const char *)el->values[i].data);
            return LDB_ERR_INVALID_DN_SYNTAX;
        }
        if (ldb_dn_compare(valdn, req->op.add.message->dn) == 0) {
            ldb_debug(ldb, LDB_DEBUG_ERROR,
                      "Adding self as member is not permitted! Skipping");
            continue;
        }
        ret = mbof_append_addop(add_ctx, parents, valdn);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

done:
    /* add original object */
    ret = ldb_build_add_req(&add_req, ldb, add_ctx,
                            add_ctx->msg, req->controls,
                            add_ctx, mbof_add_callback,
                            req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(module, add_req);
}

static int mbof_add_callback(struct ldb_request *req,
                             struct ldb_reply *ares)
{
    struct mbof_add_ctx *add_ctx;
    struct mbof_ctx *ctx;
    int ret;

    add_ctx = talloc_get_type(req->context, struct mbof_add_ctx);
    ctx = add_ctx->ctx;

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        /* shouldn't happen */
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        if (add_ctx->terminate) {
            return ldb_module_done(ctx->req,
                                   ctx->ret_ctrls,
                                   ctx->ret_resp,
                                   LDB_SUCCESS);
        }

        if (add_ctx->current_op == NULL) {
            /* first operation */
            ctx->ret_ctrls = talloc_steal(ctx, ares->controls);
            ctx->ret_resp = talloc_steal(ctx, ares->response);
            ret = mbof_next_add(add_ctx->add_list);
        }
        else if (add_ctx->current_op->next) {
            /* next operation */
            ret = mbof_next_add(add_ctx->current_op->next);
        }
        else {
            /* no more operations */
            if (add_ctx->missing) {
                ret = mbof_add_cleanup(add_ctx);
            }
            else if (add_ctx->muops) {
                ret = mbof_add_muop(add_ctx);
            }
            else {
                return ldb_module_done(ctx->req,
                                       ctx->ret_ctrls,
                                       ctx->ret_resp,
                                       LDB_SUCCESS);
            }
        }

        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_next_add(struct mbof_add_operation *addop)
{
    static const char *attrs[] = { DB_OC, DB_NAME,
                                   DB_MEMBER, DB_GHOST,
                                   DB_MEMBEROF, NULL };
    struct ldb_context *ldb;
    struct ldb_request *req;
    struct mbof_add_ctx *add_ctx;
    struct mbof_ctx *ctx;
    int ret;

    add_ctx = addop->add_ctx;
    ctx = add_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    /* mark the operation as being handled */
    add_ctx->current_op = addop;

    ret = ldb_build_search_req(&req, ldb, ctx,
                               addop->entry_dn, LDB_SCOPE_BASE,
                               NULL, attrs, NULL,
                               addop, mbof_next_add_callback,
                               ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_request(ldb, req);
}

static int mbof_next_add_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct mbof_add_operation *addop;
    struct mbof_add_ctx *add_ctx;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int ret;

    addop = talloc_get_type(req->context, struct mbof_add_operation);
    add_ctx = addop->add_ctx;
    ctx = add_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        if (addop->entry != NULL) {
            ldb_debug(ldb, LDB_DEBUG_TRACE,
                           "Found multiple entries for (%s)",
                           ldb_dn_get_linearized(addop->entry_dn));
            /* more than one entry per DN!? DB corrupted? */
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        addop->entry = talloc_steal(addop, ares->message);
        if (addop->entry == NULL) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        break;
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        talloc_zfree(ares);
        if (addop->entry == NULL) {
            ldb_debug(ldb, LDB_DEBUG_TRACE, "Entry not found (%s)",
                           ldb_dn_get_linearized(addop->entry_dn));

            /* this target does not exists, save as missing */
            ret = mbof_add_missing(add_ctx, addop->entry_dn);
            if (ret != LDB_SUCCESS) {
                return ldb_module_done(ctx->req, NULL, NULL, ret);
            }
            /* now try the next operation */
            if (add_ctx->current_op->next) {
                ret = mbof_next_add(add_ctx->current_op->next);
            }
            else {
                /* no more operations */
                if (add_ctx->missing) {
                    ret = mbof_add_cleanup(add_ctx);
                }
                else if (add_ctx->muops) {
                    ret = mbof_add_muop(add_ctx);
                }
                else {
                    return ldb_module_done(ctx->req,
                                           ctx->ret_ctrls,
                                           ctx->ret_resp,
                                           LDB_SUCCESS);
                }
            }
            if (ret != LDB_SUCCESS) {
                return ldb_module_done(ctx->req, NULL, NULL, ret);
            }
        }
        else {
            ret = mbof_add_operation(addop);
            if (ret != LDB_SUCCESS) {
                return ldb_module_done(ctx->req, NULL, NULL, ret);
            }
        }
        return LDB_SUCCESS;
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

/* if it is a group, add all members for cascade effect
 * add memberof attribute to this entry
 */
static int mbof_add_operation(struct mbof_add_operation *addop)
{

    TALLOC_CTX *tmp_ctx;
    struct mbof_ctx *ctx;
    struct mbof_add_ctx *add_ctx;
    struct ldb_context *ldb;
    struct ldb_message_element *el;
    struct ldb_request *mod_req;
    struct ldb_message *msg;
    struct ldb_dn *elval_dn;
    struct ldb_dn *valdn;
    struct mbof_dn_array *parents;
    int i, j, ret;
    const char *val;
    const char *name;

    add_ctx = addop->add_ctx;
    ctx = add_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    parents = talloc_zero(add_ctx, struct mbof_dn_array);
    if (!parents) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    /* can't be more than the immediate parent */
    parents->dns = talloc_array(parents, struct ldb_dn *,
                                addop->parents->num);
    if (!parents->dns) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    /* create new parent set for this entry */
    for (i = 0; i < addop->parents->num; i++) {
        /* never add yourself as memberof */
        if (ldb_dn_compare(addop->parents->dns[i], addop->entry_dn) == 0) {
            continue;
        }
        parents->dns[parents->num] = addop->parents->dns[i];
        parents->num++;
    }

    /* remove entries that are already there */
    el = ldb_msg_find_element(addop->entry, DB_MEMBEROF);
    if (el) {

        tmp_ctx = talloc_new(addop);
        if (!tmp_ctx) return LDB_ERR_OPERATIONS_ERROR;

        for (i = 0; i < el->num_values; i++) {
            elval_dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &el->values[i]);
            if (!elval_dn) {
                ldb_debug(ldb, LDB_DEBUG_TRACE, "Invalid DN in memberof [%s]",
                                            (const char *)el->values[i].data);
                talloc_free(tmp_ctx);
                return LDB_ERR_OPERATIONS_ERROR;
            }
            for (j = 0; j < parents->num; j++) {
                if (ldb_dn_compare(parents->dns[j], elval_dn) == 0) {
                    /* duplicate found */
                    break;
                }
            }
            if (j < parents->num) {
                /* remove duplicate */
                for (;j+1 < parents->num; j++) {
                    parents->dns[j] = parents->dns[j+1];
                }
                parents->num--;
            }
        }

        if (parents->num == 0) {
            /* already contains all parents as memberof, skip to next */
            talloc_free(tmp_ctx);
            talloc_free(addop->entry);
            addop->entry = NULL;

            if (addop->next) {
                return mbof_next_add(addop->next);
            }
            else if (add_ctx->muops) {
                return mbof_add_muop(add_ctx);
            }
            else {
                /* that was the last entry, get out */
                return ldb_module_done(ctx->req,
                                       ctx->ret_ctrls,
                                       ctx->ret_resp,
                                       LDB_SUCCESS);
            }
        }
        talloc_free(tmp_ctx);
    }

    /* if it is a group add all members */
    el = ldb_msg_find_element(addop->entry, DB_MEMBER);
    if (el) {
        for (i = 0; i < el->num_values; i++) {
            valdn = ldb_dn_from_ldb_val(add_ctx, ldb, &el->values[i]);
            if (!valdn) {
                ldb_debug(ldb, LDB_DEBUG_TRACE, "Invalid DN in member [%s]",
                                            (const char *)el->values[i].data);
                return LDB_ERR_OPERATIONS_ERROR;
            }
            if (!ldb_dn_validate(valdn)) {
                ldb_debug(ldb, LDB_DEBUG_TRACE,
                               "Invalid DN syntax for member [%s]",
                                            (const char *)el->values[i].data);
                return LDB_ERR_INVALID_DN_SYNTAX;
            }
            ret = mbof_append_addop(add_ctx, parents, valdn);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }
    }

    /* check if we need to store memberuid ops for this entry */
    ret = entry_is_user_object(addop->entry);
    switch (ret) {
    case LDB_SUCCESS:
        /* it's a user object  */
        name = ldb_msg_find_attr_as_string(addop->entry, DB_NAME, NULL);
        if (!name) {
            return LDB_ERR_OPERATIONS_ERROR;
        }

        for (i = 0; i < parents->num; i++) {
            ret = mbof_append_muop(add_ctx, &add_ctx->muops,
                                   &add_ctx->num_muops,
                                   LDB_FLAG_MOD_ADD,
                                   parents->dns[i], name,
                                   DB_MEMBERUID);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        break;

    case LDB_ERR_NO_SUCH_ATTRIBUTE:
        /* it is not a user object, continue */
        break;

    default:
        /* an error occurred, return */
        return ret;
    }

    ret = mbof_add_fill_ghop(add_ctx, addop->entry, parents);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    /* we are done with the entry now */
    talloc_free(addop->entry);
    addop->entry = NULL;

    /* add memberof to entry */
    msg = ldb_msg_new(addop);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = addop->entry_dn;

    ret = ldb_msg_add_empty(msg, DB_MEMBEROF, LDB_FLAG_MOD_ADD, &el);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    el->values = talloc_array(msg, struct ldb_val, parents->num);
    if (!el->values) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    for (i = 0, j = 0; i < parents->num; i++) {
        if (ldb_dn_compare(parents->dns[i], msg->dn) == 0) continue;
        val = ldb_dn_get_linearized(parents->dns[i]);
        el->values[j].length = strlen(val);
        el->values[j].data = (uint8_t *)talloc_strdup(el->values, val);
        if (!el->values[j].data) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        j++;
    }
    el->num_values = j;

    ret = ldb_build_mod_req(&mod_req, ldb, add_ctx,
                            msg, NULL,
                            add_ctx, mbof_add_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    talloc_steal(mod_req, msg);

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_add_fill_ghop(struct mbof_add_ctx *add_ctx,
                              struct ldb_message *entry,
                              struct mbof_dn_array *parents)
{
    struct ldb_message_element *ghel;

    ghel = ldb_msg_find_element(entry, DB_GHOST);
    if (ghel == NULL || ghel->num_values == 0) {
        /* No ghel attribute, just return success */
        return LDB_SUCCESS;
    }

    return mbof_add_fill_ghop_ex(add_ctx, entry, parents,
                                 ghel->values, ghel->num_values);
}

static int mbof_add_missing(struct mbof_add_ctx *add_ctx, struct ldb_dn *dn)
{
    struct mbof_dn *mdn;

    mdn = talloc(add_ctx, struct mbof_dn);
    if (!mdn) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    mdn->dn = talloc_steal(mdn, dn);

    /* add to the list */
    mdn->next = add_ctx->missing;
    add_ctx->missing = mdn;

    return LDB_SUCCESS;
}

/* remove unexisting members and add memberuid attribute */
static int mbof_add_cleanup(struct mbof_add_ctx *add_ctx)
{
    struct ldb_context *ldb;
    struct ldb_message *msg;
    struct ldb_request *mod_req;
    struct ldb_message_element *el;
    struct mbof_ctx *ctx;
    struct mbof_dn *iter;
    const char *val;
    int ret, i, num;

    ctx = add_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    num = 0;
    for (iter = add_ctx->missing; iter; iter = iter->next) {
        num++;
    }
    if (num == 0) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    msg = ldb_msg_new(add_ctx);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = add_ctx->msg_dn;

    ret = ldb_msg_add_empty(msg, DB_MEMBER, LDB_FLAG_MOD_DELETE, &el);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    el->values = talloc_array(msg, struct ldb_val, num);
    if (!el->values) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    el->num_values = num;
    for (i = 0, iter = add_ctx->missing; iter; iter = iter->next, i++) {
        val = ldb_dn_get_linearized(iter->dn);
        el->values[i].length = strlen(val);
        el->values[i].data = (uint8_t *)talloc_strdup(el->values, val);
        if (!el->values[i].data) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
    }

    ret = ldb_build_mod_req(&mod_req, ldb, add_ctx,
                            msg, NULL,
                            add_ctx, mbof_add_cleanup_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_add_cleanup_callback(struct ldb_request *req,
                                     struct ldb_reply *ares)
{
    struct mbof_add_ctx *add_ctx;
    struct mbof_ctx *ctx;
    int ret;

    add_ctx = talloc_get_type(req->context, struct mbof_add_ctx);
    ctx = add_ctx->ctx;

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        /* shouldn't happen */
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        if (add_ctx->muops) {
            ret = mbof_add_muop(add_ctx);
        }
        else {
            return ldb_module_done(ctx->req,
                                   ctx->ret_ctrls,
                                   ctx->ret_resp,
                                   LDB_SUCCESS);
        }

        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

/* add memberuid attributes to parent groups */
static int mbof_add_muop(struct mbof_add_ctx *add_ctx)
{
    struct ldb_context *ldb;
    struct ldb_message *msg;
    struct ldb_request *mod_req;
    struct mbof_ctx *ctx;
    int ret;

    ctx = add_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    msg = ldb_msg_new(add_ctx);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = add_ctx->muops[add_ctx->cur_muop].dn;
    msg->elements = add_ctx->muops[add_ctx->cur_muop].el;
    msg->num_elements = 1;

    ret = ldb_build_mod_req(&mod_req, ldb, add_ctx,
                            msg, NULL,
                            add_ctx, mbof_add_muop_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    ret = ldb_request_add_control(mod_req, LDB_CONTROL_PERMISSIVE_MODIFY_OID,
                                  false, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(mod_req);
        return ret;
    }

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_add_muop_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct mbof_add_ctx *add_ctx;
    struct mbof_ctx *ctx;
    int ret;

    add_ctx = talloc_get_type(req->context, struct mbof_add_ctx);
    ctx = add_ctx->ctx;

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        /* shouldn't happen */
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        add_ctx->cur_muop++;
        if (add_ctx->cur_muop < add_ctx->num_muops) {
            ret = mbof_add_muop(add_ctx);
        }
        else {
            return ldb_module_done(ctx->req,
                                   ctx->ret_ctrls,
                                   ctx->ret_resp,
                                   LDB_SUCCESS);
        }

        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}




/* delete operations */

/* The implementation of delete operations is a bit more complex than an add
 * operation. This is because we need to recompute memberships of potentially
 * quite far descendants and we also have to account for loops and how to
 * break them without ending in an endless loop ourselves.
 * The difficulty is in the fact that while the member -> memberof link is
 * direct, memberof -> member is not as membership is transitive.
 *
 * Ok, first of all, contrary to the add operation, a delete operation
 * involves an existing object that may have existing parents. So, first, we
 * search  the object itself to get the original membership lists (member and
 * memberof) for this object, and we also search for any object that has it as
 * one of its members.
 * Once we have the results, we store object and parents and proceed with the
 * original operation to make sure it is valid.
 *
 * Once the original op returns we proceed fixing parents (parents being each
 * object that has the delete operation target object as member), if any.
 *
 * For each parent we retrieved we proceed to delete the member attribute that
 * points to the object we just deleted. Once done for all parents (or if no
 * parents exists), we proceed with the children and descendants.
 *
 * To handle the children we create a first ancestor operation that reflects
 * the delete we just made. We set as parents of this object the parents just
 * retrieved with the first search. Then we create a remove list.
 *
 * The remove list contains all objects in the original memberof list and the
 * object dn itself of the original delete operation target object (the first
 * ancestor).
 *
 * An operation is identified by an object that contains a tree of
 * descendants:
 * The remove list for the children, the immediate parent, and the dn and
 * entry of the object this operation is about.
 *
 * We now proceed with adding a new operation for each original member of the
 * first ancestor.
 *
 * In each operation we must first lookup the target object and each immediate
 * parent (all the objects in the tree that have target as a "member").
 *
 * Then we proceed to calculate the new memberof list that we are going to set
 * on the target object.
 * The new memberof list starts with including all the objects that have the
 * target as their direct member.
 * Finally for each entry in this provisional new memberof list we add all its
 * memberof elements to the new memberof list (taking care of excluding
 * duplicates). This way we are certain all direct and indirect membership are
 * accounted for.
 *
 * At this point we have the final new memberof list for this operation and we
 * can proceed to modify the entry.
 *
 * Once the entry has been modified we proceed again to check if there are any
 * children of this entry (the entry has "member"s).
 * We create a new remove list that is the difference between the original
 * entry memberof list and the new memberof list we just stored back in the
 * object.
 * Then for each member we create a new operation.
 *
 * We continue to process operations until no new operations need to be
 * performed.
 *
 * Ordering is important here, se the mbof_del_get_next() function to
 * understand how we proceed to select which new operation to process.
 *
 * As a final operation remove any memberuid corresponding to a removal of
 * a memberof field from a user entry. Also if the original entry had a ghost
 * attribute, we need to remove that attribute from all its parents as well.
 *
 * There is one catch though - at the memberof level, we can't know if the
 * attribute being removed from a parent group is just inherited from the group
 * being removed or also a direct member of the parent group. To make sure
 * that the attribute is displayed next time the group is requested, we also
 * set expire the parent group at the same time.
 */

static int mbof_del_search_callback(struct ldb_request *req,
                                    struct ldb_reply *ares);
static int mbof_orig_del(struct mbof_del_ctx *ctx);
static int mbof_orig_del_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static int mbof_del_cleanup_parents(struct mbof_del_ctx *del_ctx);
static int mbof_del_clean_par_callback(struct ldb_request *req,
                                       struct ldb_reply *ares);
static int mbof_del_cleanup_children(struct mbof_del_ctx *del_ctx);
static int mbof_append_delop(struct mbof_del_operation *parent,
                             struct ldb_dn *entry_dn);
static int mbof_del_execute_op(struct mbof_del_operation *delop);
static int mbof_del_exop_search_callback(struct ldb_request *req,
                                         struct ldb_reply *ares);
static int mbof_del_execute_cont(struct mbof_del_operation *delop);
static int mbof_del_ancestors(struct mbof_del_operation *delop);
static int mbof_del_anc_callback(struct ldb_request *req,
                                 struct ldb_reply *ares);
static int mbof_del_mod_entry(struct mbof_del_operation *delop);
static int mbof_del_mod_callback(struct ldb_request *req,
                                 struct ldb_reply *ares);
static int mbof_del_progeny(struct mbof_del_operation *delop);
static int mbof_del_get_next(struct mbof_del_operation *delop,
                             struct mbof_del_operation **nextop);
static int mbof_del_fill_muop(struct mbof_del_ctx *del_ctx,
                              struct ldb_message *entry);
static int mbof_del_fill_ghop(struct mbof_del_ctx *del_ctx,
                              struct ldb_message *entry);
static int mbof_del_muop(struct mbof_del_ctx *ctx);
static int mbof_del_muop_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static int mbof_del_ghop(struct mbof_del_ctx *del_ctx);
static int mbof_del_ghop_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static void free_delop_contents(struct mbof_del_operation *delop);


static int memberof_del(struct ldb_module *module, struct ldb_request *req)
{
    static const char *attrs[] = { DB_OC, DB_NAME,
                                   DB_MEMBER, DB_MEMBEROF,
                                   DB_GHOST, NULL };
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct mbof_del_operation *first;
    struct ldb_request *search;
    char *expression;
    const char *dn;
    char *clean_dn;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    int ret;
    errno_t sret;

    if (ldb_dn_is_special(req->op.del.dn)) {
        /* do not manipulate our control entries */
        return ldb_next_request(module, req);
    }

    ctx = mbof_init(module, req);
    if (!ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    del_ctx = talloc_zero(ctx, struct mbof_del_ctx);
    if (!del_ctx) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    del_ctx->ctx = ctx;

    /* create first entry */
    /* the first entry is the parent of all entries and the one where we remove
     * member from, it does not get the same treatment as others */
    first = talloc_zero(del_ctx, struct mbof_del_operation);
    if (!first) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    del_ctx->first = first;

    first->del_ctx = del_ctx;
    first->entry_dn = req->op.del.dn;

    dn = ldb_dn_get_linearized(req->op.del.dn);
    if (!dn) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    sret = sss_filter_sanitize_dn(del_ctx, dn, &clean_dn);
    if (sret != 0) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    expression = talloc_asprintf(del_ctx,
                                 "(|(distinguishedName=%s)(%s=%s))",
                                 clean_dn, DB_MEMBER, clean_dn);
    if (!expression) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    talloc_zfree(clean_dn);

    ret = ldb_build_search_req(&search, ldb, del_ctx,
                               NULL, LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               first, mbof_del_search_callback,
                               req);
    if (ret != LDB_SUCCESS) {
        talloc_free(ctx);
        return ret;
    }

    return ldb_request(ldb, search);
}

static int mbof_del_search_callback(struct ldb_request *req,
                                    struct ldb_reply *ares)
{
    struct mbof_del_operation *first;
    struct ldb_context *ldb;
    struct ldb_message *msg;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    int ret;

    first = talloc_get_type(req->context, struct mbof_del_operation);
    del_ctx = first->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        msg = ares->message;

        if (ldb_dn_compare(msg->dn, ctx->req->op.del.dn) == 0) {

            if (first->entry != NULL) {
                /* more than one entry per DN!? DB corrupted? */
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }

            first->entry = talloc_steal(first, msg);
            if (first->entry == NULL) {
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }
        } else {
            first->parents = talloc_realloc(first, first->parents,
                                             struct ldb_message *,
                                             first->num_parents + 1);
            if (!first->parents) {
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }
            msg = talloc_steal(first->parents, ares->message);
            if (!msg) {
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }
            first->parents[first->num_parents] = msg;
            first->num_parents++;
        }
        break;
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        if (first->entry == NULL) {
            /* this target does not exists, too bad! */
            ldb_debug(ldb, LDB_DEBUG_TRACE,
                           "Target entry (%s) not found",
                           ldb_dn_get_linearized(first->entry_dn));
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_NO_SUCH_OBJECT);
        }

        /* now perform the requested delete, before proceeding further */
        ret =  mbof_orig_del(del_ctx);
        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_orig_del(struct mbof_del_ctx *del_ctx)
{
    struct ldb_request *del_req;
    struct mbof_ctx *ctx;
    int ret;

    ctx = del_ctx->ctx;

    ret = ldb_build_del_req(&del_req, ldb_module_get_ctx(ctx->module),
                            ctx->req, ctx->req->op.del.dn, NULL,
                            del_ctx, mbof_orig_del_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(ctx->module, del_req);
}

static int mbof_orig_del_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct ldb_context *ldb;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    int ret;

    del_ctx = talloc_get_type(req->context, struct mbof_del_ctx);
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    if (ares->type != LDB_REPLY_DONE) {
        talloc_zfree(ares);
        ldb_set_errstring(ldb, "Invalid reply type!");
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }

    /* save real call stuff */
    ctx->ret_ctrls = talloc_steal(ctx, ares->controls);
    ctx->ret_resp = talloc_steal(ctx, ares->response);

    /* prep following clean ops */
    if (del_ctx->first->num_parents) {

        /* if there are parents there may be memberuids to remove */
        ret = mbof_del_fill_muop(del_ctx, del_ctx->first->entry);
        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }

        /* ..or ghost attributes to remove */
        ret = mbof_del_fill_ghop(del_ctx, del_ctx->first->entry);
        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }

        /* if there are any parents, fire a removal sequence */
        ret = mbof_del_cleanup_parents(del_ctx);
    }
    else if (ldb_msg_find_element(del_ctx->first->entry, DB_MEMBER)) {
        /* if there are any children, fire a removal sequence */
        ret = mbof_del_cleanup_children(del_ctx);
    }
    /* see if there are memberuid operations to perform */
    else if (del_ctx->muops) {
        return mbof_del_muop(del_ctx);
    }
    /* see if we need to remove some ghost users */
    else if (del_ctx->ghops) {
        return mbof_del_ghop(del_ctx);
    }
    else {
        /* no parents nor children, end ops */
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               LDB_SUCCESS);
    }
    if (ret != LDB_SUCCESS) {
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL, ret);
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_del_cleanup_parents(struct mbof_del_ctx *del_ctx)
{
    struct mbof_del_operation *first;
    struct mbof_ctx *ctx;
    struct ldb_context *ldb;
    struct ldb_request *mod_req;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    const char *val;
    int ret;

    first = del_ctx->first;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    msg = ldb_msg_new(first->parents);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = first->parents[first->cur_parent]->dn;
    first->cur_parent++;

    ret = ldb_msg_add_empty(msg, DB_MEMBER, LDB_FLAG_MOD_DELETE, &el);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    el->values = talloc_array(msg, struct ldb_val, 1);
    if (!el->values) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    val = ldb_dn_get_linearized(first->entry_dn);
    el->values[0].length = strlen(val);
    el->values[0].data = (uint8_t *)talloc_strdup(el->values, val);
    if (!el->values[0].data) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    el->num_values = 1;

    ret = ldb_build_mod_req(&mod_req, ldb, first->parents,
                            msg, NULL,
                            del_ctx, mbof_del_clean_par_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_del_clean_par_callback(struct ldb_request *req,
                                       struct ldb_reply *ares)
{
    struct mbof_del_operation *first;
    struct ldb_context *ldb;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    int ret;

    del_ctx = talloc_get_type(req->context, struct mbof_del_ctx);
    first = del_ctx->first;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }

    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    if (ares->type != LDB_REPLY_DONE) {
        talloc_zfree(ares);
        ldb_set_errstring(ldb, "Invalid reply type!");
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }

    if (first->num_parents > first->cur_parent) {
        /* still parents to cleanup, go on */
        ret = mbof_del_cleanup_parents(del_ctx);
    }
    else {
        /* continue */
        if (ldb_msg_find_element(first->entry, DB_MEMBER)) {
            /* if there are any children, fire a removal sequence */
            ret = mbof_del_cleanup_children(del_ctx);
        }
        /* see if there are memberuid operations to perform */
        else if (del_ctx->muops) {
            return mbof_del_muop(del_ctx);
        }
        /* see if we need to remove some ghost users */
        else if (del_ctx->ghops) {
            return mbof_del_ghop(del_ctx);
        }
        else {
            /* no children, end ops */
            return ldb_module_done(ctx->req,
                                   ctx->ret_ctrls,
                                   ctx->ret_resp,
                                   LDB_SUCCESS);
        }
    }

    if (ret != LDB_SUCCESS) {
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL, ret);
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_del_cleanup_children(struct mbof_del_ctx *del_ctx)
{
    struct mbof_del_operation *first;
    struct mbof_ctx *ctx;
    struct ldb_context *ldb;
    const struct ldb_message_element *el;
    struct ldb_dn *valdn;
    int i, ret;

    first = del_ctx->first;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    el = ldb_msg_find_element(first->entry, DB_MEMBER);
    if (el == NULL) {
        return EINVAL;
    }

    /* prepare del sets */
    for (i = 0; i < el->num_values; i++) {
        valdn = ldb_dn_from_ldb_val(first, ldb, &el->values[i]);
        if (!valdn || !ldb_dn_validate(valdn)) {
            ldb_debug(ldb, LDB_DEBUG_TRACE,
                           "Invalid dn syntax for member [%s]",
                                        (const char *)el->values[i].data);
            return LDB_ERR_INVALID_DN_SYNTAX;
        }
        ret = mbof_append_delop(first, valdn);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    /* now that sets are built, start processing */
    return mbof_del_execute_op(first->children[0]);
}

static int mbof_append_delop(struct mbof_del_operation *parent,
                             struct ldb_dn *entry_dn)
{
    struct mbof_del_operation *delop;

    delop = talloc_zero(parent, struct mbof_del_operation);
    if (!delop) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    delop->del_ctx = parent->del_ctx;
    delop->parent = parent;
    delop->entry_dn = entry_dn;

    parent->children = talloc_realloc(parent, parent->children,
                                      struct mbof_del_operation *,
                                      parent->num_children +1);
    if (!parent->children) {
        talloc_free(delop);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    parent->children[parent->num_children] = delop;
    parent->num_children++;

    return LDB_SUCCESS;
}

static int mbof_del_execute_op(struct mbof_del_operation *delop)
{
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    struct ldb_context *ldb;
    struct ldb_request *search;
    char *expression;
    const char *dn;
    char *clean_dn;
    static const char *attrs[] = { DB_OC, DB_NAME,
                                   DB_MEMBER, DB_MEMBEROF, NULL };
    int ret;

    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    /* load entry */
    dn = ldb_dn_get_linearized(delop->entry_dn);
    if (!dn) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = sss_filter_sanitize_dn(del_ctx, dn, &clean_dn);
    if (ret != 0) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    expression = talloc_asprintf(del_ctx,
                                 "(|(distinguishedName=%s)(%s=%s))",
                                 clean_dn, DB_MEMBER, clean_dn);
    if (!expression) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    talloc_zfree(clean_dn);

    ret = ldb_build_search_req(&search, ldb, delop,
                               NULL, LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               delop, mbof_del_exop_search_callback,
                               ctx->req);
    if (ret != LDB_SUCCESS) {
        talloc_free(ctx);
        return ret;
    }

    return ldb_request(ldb, search);
}

static int mbof_del_exop_search_callback(struct ldb_request *req,
                                         struct ldb_reply *ares)
{
    struct mbof_del_operation *delop;
    struct mbof_del_ctx *del_ctx;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    struct ldb_message *msg;
    int ret;

    delop = talloc_get_type(req->context, struct mbof_del_operation);
    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        msg = ares->message;

        if (ldb_dn_compare(msg->dn, delop->entry_dn) == 0) {

            if (delop->entry != NULL) {
                ldb_debug(ldb, LDB_DEBUG_TRACE,
                               "Found multiple entries for (%s)",
                               ldb_dn_get_linearized(delop->entry_dn));
                /* more than one entry per DN!? DB corrupted? */
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }

            delop->entry = talloc_steal(delop, msg);
            if (delop->entry == NULL) {
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }
        } else {
            delop->parents = talloc_realloc(delop, delop->parents,
                                            struct ldb_message *,
                                            delop->num_parents + 1);
            if (!delop->parents) {
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }
            msg = talloc_steal(delop->parents, msg);
            if (!msg) {
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }
            delop->parents[delop->num_parents] = msg;
            delop->num_parents++;
        }
        break;
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        if (delop->entry == NULL) {
            /* no target, no party! */
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        /* ok process the entry */
        ret = mbof_del_execute_cont(delop);

        if (ret != LDB_SUCCESS) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_del_execute_cont(struct mbof_del_operation *delop)
{
    struct mbof_del_ancestors_ctx *anc_ctx;
    struct mbof_dn_array *new_list;
    int i;

    anc_ctx = talloc_zero(delop, struct mbof_del_ancestors_ctx);
    if (!anc_ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    delop->anc_ctx = anc_ctx;

    new_list = talloc_zero(anc_ctx, struct mbof_dn_array);
    if (!new_list) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    /* at the very least we have a number of memberof elements
     * equal to the number of objects that have this entry as
     * direct member */
    new_list->num = delop->num_parents;

    /* attach the list to the operation */
    delop->anc_ctx->new_list = new_list;
    delop->anc_ctx->num_direct = new_list->num;

    /* do we have any direct parent at all? */
    if (new_list->num == 0) {
        /* no entries at all, entry ended up being orphaned */
        /* skip to directly set the new memberof list for this entry */

        return mbof_del_mod_entry(delop);
    }

    /* fill in the list if we have parents */
    new_list->dns = talloc_zero_array(new_list,
                                      struct ldb_dn *,
                                      new_list->num);
    if (!new_list->dns) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    for (i = 0; i < delop->num_parents; i++) {
        new_list->dns[i] = delop->parents[i]->dn;
    }

    /* before proceeding we also need to fetch the ancestors (anew as some may
     * have changed by preceding operations) */
    return mbof_del_ancestors(delop);
}

static int mbof_del_ancestors(struct mbof_del_operation *delop)
{
    struct mbof_del_ancestors_ctx *anc_ctx;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    struct ldb_context *ldb;
    struct mbof_dn_array *new_list;
    static const char *attrs[] = { DB_MEMBEROF, NULL };
    struct ldb_request *search;
    int ret;

    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);
    anc_ctx = delop->anc_ctx;
    new_list = anc_ctx->new_list;

    ret = ldb_build_search_req(&search, ldb, anc_ctx,
                               new_list->dns[anc_ctx->cur],
                               LDB_SCOPE_BASE, NULL, attrs, NULL,
                               delop, mbof_del_anc_callback,
                               ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_request(ldb, search);
}

static int mbof_del_anc_callback(struct ldb_request *req,
                                 struct ldb_reply *ares)
{
    struct mbof_del_ancestors_ctx *anc_ctx;
    struct mbof_del_operation *delop;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    struct ldb_context *ldb;
    struct ldb_message *msg;
    const struct ldb_message_element *el;
    struct mbof_dn_array *new_list;
    struct ldb_dn *valdn;
    int i, j, ret;

    delop = talloc_get_type(req->context, struct mbof_del_operation);
    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);
    anc_ctx = delop->anc_ctx;
    new_list = anc_ctx->new_list;

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        msg = ares->message;

        if (anc_ctx->entry != NULL) {
            ldb_debug(ldb, LDB_DEBUG_TRACE,
                           "Found multiple entries for (%s)",
                           ldb_dn_get_linearized(anc_ctx->entry->dn));
            /* more than one entry per DN!? DB corrupted? */
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        anc_ctx->entry = talloc_steal(anc_ctx, msg);
        if (anc_ctx->entry == NULL) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }
        break;
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        if (anc_ctx->entry == NULL) {
            /* no target, no party! */
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        /* check entry */
        el = ldb_msg_find_element(anc_ctx->entry, DB_MEMBEROF);
        if (el) {
            for (i = 0; i < el->num_values; i++) {
                valdn = ldb_dn_from_ldb_val(new_list, ldb, &el->values[i]);
                if (!valdn) {
                    ldb_debug(ldb, LDB_DEBUG_TRACE,
                                   "Invalid dn for memberof: (%s)",
                                   (const char *)el->values[i].data);
                    return ldb_module_done(ctx->req, NULL, NULL,
                                           LDB_ERR_OPERATIONS_ERROR);
                }
                for (j = 0; j < new_list->num; j++) {
                    if (ldb_dn_compare(valdn, new_list->dns[j]) == 0)
                        break;
                }
                if (j < new_list->num) {
                    talloc_free(valdn);
                    continue;
                }

                new_list->dns = talloc_realloc(new_list,
                                               new_list->dns,
                                               struct ldb_dn *,
                                               new_list->num + 1);
                if (!new_list->dns) {
                    return ldb_module_done(ctx->req, NULL, NULL,
                                           LDB_ERR_OPERATIONS_ERROR);
                }
                new_list->dns[new_list->num] = valdn;
                new_list->num++;
            }
        }

        /* done with this one */
        talloc_free(anc_ctx->entry);
        anc_ctx->entry = NULL;
        anc_ctx->cur++;

        /* check if we need to process any more */
        if (anc_ctx->cur < anc_ctx->num_direct) {
            /* ok process the next one */
            ret = mbof_del_ancestors(delop);
        } else {
            /* ok, end of the story, proceed to modify the entry */
            ret = mbof_del_mod_entry(delop);
        }

        if (ret != LDB_SUCCESS) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_del_mod_entry(struct mbof_del_operation *delop)
{
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    struct ldb_context *ldb;
    struct mbof_dn_array *new_list;
    struct ldb_request *mod_req;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    struct ldb_dn **diff = NULL;
    const char *name;
    const char *val;
    int i, j, k;
    bool is_user;
    int ret;

    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);
    new_list = delop->anc_ctx->new_list;

    /* if this is a user we need to find out which entries have been
     * removed so that we can later schedule removal of memberuid
     * attributes from these entries */
    ret = entry_is_user_object(delop->entry);
    switch (ret) {
    case LDB_SUCCESS:
        /* it's a user object  */
        is_user = true;
        break;
    case LDB_ERR_NO_SUCH_ATTRIBUTE:
        /* it is not a user object, continue */
        is_user = false;
        break;
    default:
        /* an error occurred, return */
        return ret;
    }

    if (is_user) {
        /* prepare memberuid delete list */
        /* copy all original memberof entries, and then later remove
         * the ones that will survive in the entry */
        el = ldb_msg_find_element(delop->entry, DB_MEMBEROF);
        if (!el || !el->num_values) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        diff = talloc_array(del_ctx, struct ldb_dn *,
                            el->num_values + 1);
        if (!diff) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        for (i = 0, j = 0; i < el->num_values; i++) {
            diff[j] = ldb_dn_from_ldb_val(diff, ldb, &el->values[i]);
            if (!diff[j]) {
                return LDB_ERR_OPERATIONS_ERROR;
            }
            /* skip the deleted entry if this is a delete op */
            if (!del_ctx->is_mod) {
                if (ldb_dn_compare(del_ctx->first->entry_dn, diff[j]) == 0) {
                    continue;
                }
            }
            j++;
        }
        /* zero terminate array */
        diff[j] = NULL;
    }

    /* change memberof on entry */
    msg = ldb_msg_new(delop);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = delop->entry_dn;

    if (new_list->num) {
        ret = ldb_msg_add_empty(msg, DB_MEMBEROF, LDB_FLAG_MOD_REPLACE, &el);
        if (ret != LDB_SUCCESS) {
            return ret;
        }

        el->values = talloc_array(el, struct ldb_val, new_list->num);
        if (!el->values) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        for (i = 0, j = 0; i < new_list->num; i++) {
            if (ldb_dn_compare(new_list->dns[i], msg->dn) == 0)
                continue;
            val = ldb_dn_get_linearized(new_list->dns[i]);
            if (!val) {
                return LDB_ERR_OPERATIONS_ERROR;
            }
            el->values[j].length = strlen(val);
            el->values[j].data = (uint8_t *)talloc_strdup(el->values, val);
            if (!el->values[j].data) {
                return LDB_ERR_OPERATIONS_ERROR;
            }
            j++;

            if (is_user) {
                /* compare the entry's original memberof list with the new
                 * one and for each missing entry add a memberuid removal
                 * operation */
                for (k = 0; diff[k]; k++) {
                    if (ldb_dn_compare(new_list->dns[i], diff[k]) == 0) {
                        break;
                    }
                }
                if (diff[k]) {
                    talloc_zfree(diff[k]);
                    for (; diff[k + 1]; k++) {
                        diff[k] = diff[k + 1];
                    }
                    diff[k] = NULL;
                }
            }
        }
        el->num_values = j;

    }
    else {
        ret = ldb_msg_add_empty(msg, DB_MEMBEROF, LDB_FLAG_MOD_DELETE, &el);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    if (is_user && diff[0]) {
        /* file memberuid removal operations */
        name = ldb_msg_find_attr_as_string(delop->entry, DB_NAME, NULL);
        if (!name) {
            return LDB_ERR_OPERATIONS_ERROR;
        }

        for (i = 0; diff[i]; i++) {
            ret = mbof_append_muop(del_ctx, &del_ctx->muops,
                                   &del_ctx->num_muops,
                                   LDB_FLAG_MOD_DELETE,
                                   diff[i], name,
                                   DB_MEMBERUID);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            talloc_steal(del_ctx->muops, diff[i]);
        }
    }

    ret = ldb_build_mod_req(&mod_req, ldb, delop,
                            msg, NULL,
                            delop, mbof_del_mod_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }
    talloc_steal(mod_req, msg);

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_del_mod_callback(struct ldb_request *req,
                                 struct ldb_reply *ares)
{
    struct mbof_del_operation *delop;
    struct mbof_del_ctx *del_ctx;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int ret;

    delop = talloc_get_type(req->context, struct mbof_del_operation);
    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        ldb_debug(ldb, LDB_DEBUG_TRACE, "Got an entry on a non search op?!");
        /* shouldn't happen */
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        talloc_zfree(ares);
        break;

    case LDB_REPLY_DONE:

        ret = mbof_del_progeny(delop);

        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    return LDB_SUCCESS;
}

static int mbof_mod_add(struct mbof_mod_ctx *mod_ctx,
                        struct mbof_dn_array *ael,
                        struct mbof_val_array *addgh);

static int mbof_del_progeny(struct mbof_del_operation *delop)
{
    struct mbof_ctx *ctx;
    struct mbof_del_ctx *del_ctx;
    struct mbof_del_operation *nextop;
    const struct ldb_message_element *el;
    struct ldb_context *ldb;
    struct ldb_dn *valdn;
    int i, ret;

    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    /* now verify if this entry is a group and members need to be processed as
     * well */

    el = ldb_msg_find_element(delop->entry, DB_MEMBER);
    if (el) {
        for (i = 0; i < el->num_values; i++) {
            valdn = ldb_dn_from_ldb_val(delop, ldb, &el->values[i]);
            if (!valdn || !ldb_dn_validate(valdn)) {
                ldb_debug(ldb, LDB_DEBUG_TRACE,
                               "Invalid DN for member: (%s)",
                               (const char *)el->values[i].data);
                return LDB_ERR_INVALID_DN_SYNTAX;
            }
            ret = mbof_append_delop(delop, valdn);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }
    }

    /* finally find the next entry to handle */
    ret = mbof_del_get_next(delop, &nextop);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    free_delop_contents(delop);

    if (nextop) {
        return mbof_del_execute_op(nextop);
    }

    /* see if there are memberuid operations to perform */
    if (del_ctx->muops) {
        return mbof_del_muop(del_ctx);
    }
    /* see if we need to remove some ghost users */
    else if (del_ctx->ghops) {
        return mbof_del_ghop(del_ctx);
    }
    /* see if there are follow functions to run */
    if (del_ctx->follow_mod) {
        return mbof_mod_add(del_ctx->follow_mod,
                            del_ctx->follow_mod->mb_add,
                            del_ctx->follow_mod->gh_add);
    }

    /* ok, no more ops, this means our job is done */
    return ldb_module_done(ctx->req,
                           ctx->ret_ctrls,
                           ctx->ret_resp,
                           LDB_SUCCESS);
}

static int mbof_del_get_next(struct mbof_del_operation *delop,
                             struct mbof_del_operation **nextop)
{
    struct mbof_del_operation *top, *cop;
    struct mbof_del_ctx *del_ctx;
    struct mbof_dn *save, *tmp;

    del_ctx = delop->del_ctx;

    /* first of all, save the current delop in the history */
    save = talloc_zero(del_ctx, struct mbof_dn);
    if (!save) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    save->dn = delop->entry_dn;

    if (del_ctx->history) {
        tmp = del_ctx->history;
        while (tmp->next) tmp = tmp->next;
        tmp->next = save;
    } else {
        del_ctx->history = save;
    }

    /* Find next one */
    for (top = delop; top; top = top->parent) {
        if (top->num_children == 0 || top->next_child >= top->num_children) {
            /* no children, go for next one */
            continue;
        }

        while (top->next_child < top->num_children) {
            cop = top->children[top->next_child];
            top->next_child++;

            /* verify this operation has not already been performed */
            for (tmp = del_ctx->history; tmp; tmp = tmp->next) {
                if (ldb_dn_compare(tmp->dn, cop->entry_dn) == 0) {
                    break;
                }
            }
            if (tmp == NULL) {
                /* and return the current one */
                *nextop = cop;
                return LDB_SUCCESS;
            }
        }
    }

    /* we have no more ops */
    *nextop = NULL;
    return LDB_SUCCESS;
}

static int mbof_del_fill_muop(struct mbof_del_ctx *del_ctx,
                              struct ldb_message *entry)
{
    struct ldb_message_element *el;
    char *name;
    int ret;
    int i;

    el = ldb_msg_find_element(entry, DB_MEMBEROF);
    if (!el || el->num_values == 0) {
        /* no memberof attributes ... */
        return LDB_SUCCESS;
    }

    ret = entry_is_user_object(entry);
    switch (ret) {
    case LDB_SUCCESS:
        /* it's a user object, continue */
        break;

    case LDB_ERR_NO_SUCH_ATTRIBUTE:
        /* it is not a user object, just return */
        return LDB_SUCCESS;

    default:
        /* an error occurred, return */
        return ret;
    }

    name = talloc_strdup(del_ctx,
                         ldb_msg_find_attr_as_string(entry, DB_NAME, NULL));
    if (!name) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    for (i = 0; i < el->num_values; i++) {
        struct ldb_dn *valdn;

        valdn = ldb_dn_from_ldb_val(del_ctx,
                                    ldb_module_get_ctx(del_ctx->ctx->module),
                                    &el->values[i]);
        if (!valdn || !ldb_dn_validate(valdn)) {
            ldb_debug(ldb_module_get_ctx(del_ctx->ctx->module),
                      LDB_DEBUG_ERROR,
                      "Invalid dn value: [%s]",
                      (const char *)el->values[i].data);
        }

        ret = mbof_append_muop(del_ctx, &del_ctx->muops,
                               &del_ctx->num_muops,
                               LDB_FLAG_MOD_DELETE,
                               valdn, name,
                               DB_MEMBERUID);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        talloc_steal(del_ctx->muops, valdn);
    }

    return LDB_SUCCESS;
}

static int mbof_del_fill_ghop_ex(struct mbof_del_ctx *del_ctx,
                                 struct ldb_message *entry,
                                 struct ldb_val *ghvals,
                                 unsigned int num_gh_vals)
{
    struct ldb_message_element *mbof;
    struct ldb_dn *valdn;
    int ret;
    int i, j;

    mbof = ldb_msg_find_element(entry, DB_MEMBEROF);
    if (!mbof || mbof->num_values == 0) {
        /* no memberof attributes ... */
        return LDB_SUCCESS;
    }

    ret = entry_is_group_object(entry);
    switch (ret) {
    case LDB_SUCCESS:
        /* it's a group object, continue */
        break;

    case LDB_ERR_NO_SUCH_ATTRIBUTE:
        /* it is not a group object, just return */
        return LDB_SUCCESS;

    default:
        /* an error occurred, return */
        return ret;
    }

    ldb_debug(ldb_module_get_ctx(del_ctx->ctx->module),
              LDB_DEBUG_TRACE,
              "will delete %d ghost users from %d parents\n",
              num_gh_vals, mbof->num_values);

    for (i = 0; i < mbof->num_values; i++) {
        valdn = ldb_dn_from_ldb_val(del_ctx,
                                    ldb_module_get_ctx(del_ctx->ctx->module),
                                    &mbof->values[i]);
        if (!valdn || !ldb_dn_validate(valdn)) {
            ldb_debug(ldb_module_get_ctx(del_ctx->ctx->module),
                      LDB_DEBUG_ERROR,
                      "Invalid dn value: [%s]",
                      (const char *)mbof->values[i].data);
        }

        ldb_debug(ldb_module_get_ctx(del_ctx->ctx->module),
                  LDB_DEBUG_TRACE,
                  "processing ghosts in parent [%s]\n",
                  (const char *) mbof->values[i].data);

        for (j = 0; j < num_gh_vals; j++) {
            ret = mbof_append_muop(del_ctx, &del_ctx->ghops,
                                   &del_ctx->num_ghops,
                                   LDB_FLAG_MOD_DELETE,
                                   valdn,
                                   (const char *) ghvals[j].data,
                                   DB_GHOST);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
            talloc_steal(del_ctx->ghops, valdn);
        }
    }

    return LDB_SUCCESS;
}

static int mbof_del_fill_ghop(struct mbof_del_ctx *del_ctx,
                              struct ldb_message *entry)
{
    struct ldb_message_element *ghel;

    ghel = ldb_msg_find_element(entry, DB_GHOST);
    if (ghel == NULL || ghel->num_values == 0) {
        /* No ghel attribute, just return success */
        return LDB_SUCCESS;
    }

    return mbof_del_fill_ghop_ex(del_ctx, entry,
                                 ghel->values, ghel->num_values);
}

/* del memberuid attributes from parent groups */
static int mbof_del_muop(struct mbof_del_ctx *del_ctx)
{
    struct ldb_context *ldb;
    struct ldb_message *msg;
    struct ldb_request *mod_req;
    struct mbof_ctx *ctx;
    int ret;

    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    msg = ldb_msg_new(del_ctx);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = del_ctx->muops[del_ctx->cur_muop].dn;
    msg->elements = del_ctx->muops[del_ctx->cur_muop].el;
    msg->num_elements = 1;

    ret = ldb_build_mod_req(&mod_req, ldb, del_ctx,
                            msg, NULL,
                            del_ctx, mbof_del_muop_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_del_muop_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    int ret;

    del_ctx = talloc_get_type(req->context, struct mbof_del_ctx);
    ctx = del_ctx->ctx;

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    /* if the attribute was not present it means the db is not
     * perfectly consistent but failing here is not useful
     * anyway and missing entries cause no harm if we are trying
     * to remove them anyway */
    if (ares->error != LDB_SUCCESS &&
        ares->error != LDB_ERR_NO_SUCH_ATTRIBUTE) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        /* shouldn't happen */
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        del_ctx->cur_muop++;
        if (del_ctx->cur_muop < del_ctx->num_muops) {
            ret = mbof_del_muop(del_ctx);
        }
        /* see if we need to remove some ghost users */
        else if (del_ctx->ghops) {
            return mbof_del_ghop(del_ctx);
        }
        /* see if there are follow functions to run */
        else if (del_ctx->follow_mod) {
            return mbof_mod_add(del_ctx->follow_mod,
                                del_ctx->follow_mod->mb_add,
                                del_ctx->follow_mod->gh_add);
        }
        else {
            return ldb_module_done(ctx->req,
                                   ctx->ret_ctrls,
                                   ctx->ret_resp,
                                   LDB_SUCCESS);
        }

        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

/* del ghost attributes from parent groups */
static int mbof_del_ghop(struct mbof_del_ctx *del_ctx)
{
    struct ldb_context *ldb;
    struct ldb_message *msg;
    struct ldb_request *mod_req;
    struct mbof_ctx *ctx;
    int ret;

    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    msg = ldb_msg_new(del_ctx);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = del_ctx->ghops[del_ctx->cur_ghop].dn;

    ret = ldb_msg_add(msg, del_ctx->ghops[del_ctx->cur_ghop].el,
                      LDB_FLAG_MOD_DELETE);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    /* Also expire any parent groups to force reloading direct members in
     * case the ghost users we remove now were actually *also* direct members
     * of the parent groups
     */
    ret = ldb_msg_add_empty(msg, DB_CACHE_EXPIRE, LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    ret = ldb_msg_add_string(msg, DB_CACHE_EXPIRE, "1");
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    ret = ldb_build_mod_req(&mod_req, ldb, del_ctx,
                            msg, NULL,
                            del_ctx, mbof_del_ghop_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_del_ghop_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    int ret;

    del_ctx = talloc_get_type(req->context, struct mbof_del_ctx);
    ctx = del_ctx->ctx;

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }

    /* We must treat no such attribute as non-fatal b/c the entry
     * might have been directly nested in the parent as well and
     * updated with another replace operation.
     */
    if (ares->error != LDB_SUCCESS &&
        ares->error != LDB_ERR_NO_SUCH_ATTRIBUTE) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        /* shouldn't happen */
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        del_ctx->cur_ghop++;
        if (del_ctx->cur_ghop < del_ctx->num_ghops) {
            ret = mbof_del_ghop(del_ctx);
        }
        /* see if there are follow functions to run */
        else if (del_ctx->follow_mod) {
            return mbof_mod_add(del_ctx->follow_mod,
                                del_ctx->follow_mod->mb_add,
                                del_ctx->follow_mod->gh_add);
        }
        else {
            return ldb_module_done(ctx->req,
                                   ctx->ret_ctrls,
                                   ctx->ret_resp,
                                   LDB_SUCCESS);
        }

        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

/* delop may carry on a lot of memory, so we need a function to clean up
 * the payload without breaking the delop chain */
static void free_delop_contents(struct mbof_del_operation *delop)
{
    talloc_zfree(delop->entry);
    talloc_zfree(delop->parents);
    talloc_zfree(delop->anc_ctx);
    delop->num_parents = 0;
    delop->cur_parent = 0;
}

/* mod operation */

/* A modify operation just implements either an add operation, or a delete
 * operation or both (replace) in turn.
 * One difference between a modify and a pure add or a pure delete is that
 * the object is not created a new or not completely removed, but the setup just
 * treats it in the same way children objects are treated in a pure add or delete
 * operation. A list of appropriate parents and objects to modify is built, then
 * we jump directly in the add or delete code.
 * If both add and delete are necessary, delete operations are performed first
 * and then a followup add operation is concatenated
 *
 * Another difference is the ghost users. Because of its semi-managed nature,
 * the ghost attribute requires some special care. During a modify operation, the
 * ghost attribute can be set to a new list. That list coming, from an
 * application, would typically only include the direct ghost
 * members. However, we want to keep both direct and indirect ghost members
 * in the cache to be able to return them all in a single call. To solve
 * that problem, we also iterate over members of the group being modified,
 * collect all ghost entries and add them back in case the original modify
 * operation wiped them out.
 */

static int mbof_mod_callback(struct ldb_request *req,
                             struct ldb_reply *ares);
static int mbof_collect_child_ghosts(struct mbof_mod_ctx *mod_ctx);
static int mbof_get_ghost_from_parent(struct mbof_mod_del_op *igh);
static int mbof_get_ghost_from_parent_cb(struct ldb_request *req,
                                         struct ldb_reply *ares);
static int mbof_orig_mod(struct mbof_mod_ctx *mod_ctx);
static int mbof_orig_mod_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static int mbof_inherited_mod(struct mbof_mod_ctx *mod_ctx);
static int mbof_inherited_mod_callback(struct ldb_request *req,
                                       struct ldb_reply *ares);
static int mbof_mod_process(struct mbof_mod_ctx *mod_ctx, bool *done);
static int mbof_mod_process_membel(TALLOC_CTX *mem_ctx, struct ldb_context *ldb,
                                   struct ldb_message *entry,
                                   const struct ldb_message_element *membel,
                                   struct mbof_dn_array **_added,
                                   struct mbof_dn_array **_removed);
static int mbof_mod_process_ghel(TALLOC_CTX *mem_ctx,
                                 struct ldb_message *entry,
                                 const struct ldb_message_element *ghel,
                                 const struct ldb_message_element *inherited,
                                 struct mbof_val_array **_added,
                                 struct mbof_val_array **_removed);
static int mbof_mod_delete(struct mbof_mod_ctx *mod_ctx,
                           struct mbof_dn_array *del,
                           struct mbof_val_array *delgh);
static int mbof_fill_dn_array(TALLOC_CTX *memctx,
                              struct ldb_context *ldb,
                              const struct ldb_message_element *el,
                              struct mbof_dn_array **dn_array);
static int mbof_fill_vals_array(TALLOC_CTX *memctx,
                                unsigned int num_values,
                                struct ldb_val *values,
                                struct mbof_val_array **val_array);
static int mbof_fill_vals_array_el(TALLOC_CTX *memctx,
                                   const struct ldb_message_element *el,
                                   struct mbof_val_array **val_array);

static int memberof_mod(struct ldb_module *module, struct ldb_request *req)
{
    struct ldb_message_element *el;
    struct mbof_mod_ctx *mod_ctx;
    struct mbof_ctx *ctx;
    static const char *attrs[] = { DB_OC, DB_GHOST,
                                   DB_MEMBER, DB_MEMBEROF, NULL};
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct ldb_request *search;
    int ret;

    if (getenv("SSSD_UPGRADE_DB")) {
        /* do not do anything during upgrade */
        return ldb_next_request(module, req);
    }

    if (ldb_dn_is_special(req->op.mod.message->dn)) {
        /* do not manipulate our control entries */
        return ldb_next_request(module, req);
    }

    /* check if memberof is specified */
    el = ldb_msg_find_element(req->op.mod.message, DB_MEMBEROF);
    if (el) {
        ldb_debug(ldb, LDB_DEBUG_ERROR,
                  "Error: the memberof attribute is readonly.");
        return LDB_ERR_UNWILLING_TO_PERFORM;
    }

    /* check if memberuid is specified */
    el = ldb_msg_find_element(req->op.mod.message, DB_MEMBERUID);
    if (el) {
        ldb_debug(ldb, LDB_DEBUG_ERROR,
                  "Error: the memberuid attribute is readonly.");
        return LDB_ERR_UNWILLING_TO_PERFORM;
    }

    ctx = mbof_init(module, req);
    if (!ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    mod_ctx = talloc_zero(ctx, struct mbof_mod_ctx);
    if (!mod_ctx) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    mod_ctx->ctx = ctx;

    mod_ctx->msg = ldb_msg_copy(mod_ctx, req->op.mod.message);
    if (!mod_ctx->msg) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    mod_ctx->membel = ldb_msg_find_element(mod_ctx->msg, DB_MEMBER);
    mod_ctx->ghel = ldb_msg_find_element(mod_ctx->msg, DB_GHOST);

    /* continue with normal ops if there are no members and no ghosts */
    if (mod_ctx->membel == NULL && mod_ctx->ghel == NULL) {
        mod_ctx->terminate = true;
        return mbof_orig_mod(mod_ctx);
    }

    /* can't do anything,
     * must check first what's on the entry */
    ret = ldb_build_search_req(&search, ldb, mod_ctx,
                               mod_ctx->msg->dn, LDB_SCOPE_BASE,
                               NULL, attrs, NULL,
                               mod_ctx, mbof_mod_callback,
                               req);
    if (ret != LDB_SUCCESS) {
        talloc_free(ctx);
        return ret;
    }

    return ldb_request(ldb, search);
}


static int mbof_mod_callback(struct ldb_request *req,
                             struct ldb_reply *ares)
{
    struct mbof_mod_ctx *mod_ctx;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int ret;

    mod_ctx = talloc_get_type(req->context, struct mbof_mod_ctx);
    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        if (mod_ctx->entry != NULL) {
            ldb_debug(ldb, LDB_DEBUG_TRACE,
                           "Found multiple entries for (%s)",
                           ldb_dn_get_linearized(mod_ctx->msg->dn));
            /* more than one entry per DN!? DB corrupted? */
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        mod_ctx->entry = talloc_steal(mod_ctx, ares->message);
        if (mod_ctx->entry == NULL) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }
        break;
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        if (mod_ctx->entry == NULL) {
            ldb_debug(ldb, LDB_DEBUG_TRACE, "Entry not found (%s)",
                           ldb_dn_get_linearized(mod_ctx->msg->dn));
            /* this target does not exists, too bad! */
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_NO_SUCH_OBJECT);
        }

        ret = mbof_collect_child_ghosts(mod_ctx);
        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_collect_child_ghosts(struct mbof_mod_ctx *mod_ctx)
{
    int ret;
    const struct ldb_message_element *member;

    member = ldb_msg_find_element(mod_ctx->entry, DB_MEMBER);

    if (member == NULL || member->num_values == 0 ||
        mod_ctx->ghel == NULL || mod_ctx->ghel->flags != LDB_FLAG_MOD_REPLACE) {
        ret = mbof_orig_mod(mod_ctx);
        if (ret != LDB_SUCCESS) {
            return ret;
        }

        return LDB_SUCCESS;
    }

    mod_ctx->igh = talloc_zero(mod_ctx, struct mbof_mod_del_op);
    if (mod_ctx->igh == NULL) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    mod_ctx->igh->mod_ctx = mod_ctx;

    ret = hash_create_ex(1024, &mod_ctx->igh->inherited_gh, 0, 0, 0, 0,
                         hash_alloc, hash_free, mod_ctx, NULL, NULL);
    if (ret != HASH_SUCCESS) {
        return LDB_ERR_OPERATIONS_ERROR;
    }


    return mbof_get_ghost_from_parent(mod_ctx->igh);
}

static int mbof_get_ghost_from_parent(struct mbof_mod_del_op *igh)
{
    struct ldb_request *search;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int ret;
    static const char *attrs[] = { DB_GHOST, NULL };
    char *expression;
    char *clean_dn;
    const char *dn;

    ctx = igh->mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    dn = ldb_dn_get_linearized(igh->mod_ctx->entry->dn);
    if (!dn) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = sss_filter_sanitize_dn(igh, dn, &clean_dn);
    if (ret != 0) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    expression = talloc_asprintf(igh,
                                 "(&(%s=%s)(%s=%s))",
                                 DB_OC, DB_GROUP_CLASS,
                                 DB_MEMBEROF, clean_dn);
    if (!expression) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    talloc_zfree(clean_dn);

    ret = ldb_build_search_req(&search, ldb, igh,
                               NULL,
                               LDB_SCOPE_SUBTREE,
                               expression, attrs, NULL,
                               igh, mbof_get_ghost_from_parent_cb,
                               ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_request(ldb, search);
}

static int mbof_get_ghost_from_parent_cb(struct ldb_request *req,
                                         struct ldb_reply *ares)
{
    struct mbof_mod_del_op *igh;
    struct mbof_ctx *ctx;
    struct ldb_message_element *el;
    struct ldb_val *dupval;
    int ret;
    hash_value_t value;
    hash_key_t key;
    int i;

    igh = talloc_get_type(req->context, struct mbof_mod_del_op);
    ctx = igh->mod_ctx->ctx;

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        el = ldb_msg_find_element(ares->message, DB_GHOST);
        if (!el) {
            break;
        }

        for (i=0; i < el->num_values; i++) {
            key.type = HASH_KEY_STRING;
            key.str = (char *) el->values[i].data;

            if (hash_has_key(igh->inherited_gh, &key)) {
                /* We already have this user. Don't re-add him */
                continue;
            }

            dupval = talloc_zero(igh->inherited_gh, struct ldb_val);
            if (dupval == NULL) {
                return LDB_ERR_OPERATIONS_ERROR;
            }

            *dupval = ldb_val_dup(igh->inherited_gh, &el->values[i]);
            if (dupval->data == NULL) {
                return LDB_ERR_OPERATIONS_ERROR;
            }

            value.type = HASH_VALUE_PTR;
            value.ptr = dupval;

            ret = hash_enter(igh->inherited_gh, &key, &value);
            if (ret != HASH_SUCCESS) {
                return LDB_ERR_OPERATIONS_ERROR;
            }
        }
        break;

    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        /* All the children are gathered, let's do the real
         * modify operation
         */
        ret = mbof_orig_mod(igh->mod_ctx);
        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
        break;
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_orig_mod(struct mbof_mod_ctx *mod_ctx)
{
    struct ldb_request *mod_req;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int ret;

    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    ret = ldb_build_mod_req(&mod_req, ldb, ctx->req,
                            mod_ctx->msg, ctx->req->controls,
                            mod_ctx, mbof_orig_mod_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_orig_mod_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct ldb_context *ldb;
    struct mbof_mod_ctx *mod_ctx;
    struct mbof_ctx *ctx;
    int ret;

    mod_ctx = talloc_get_type(req->context, struct mbof_mod_ctx);
    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    if (ares->type != LDB_REPLY_DONE) {
        talloc_zfree(ares);
        ldb_debug(ldb, LDB_DEBUG_TRACE, "Invalid reply type!");
        ldb_set_errstring(ldb, "Invalid reply type!");
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }

    /* save real call stuff */
    ctx->ret_ctrls = talloc_steal(ctx, ares->controls);
    ctx->ret_resp = talloc_steal(ctx, ares->response);

    if (!mod_ctx->terminate) {
        /* next step */
        if (mod_ctx->igh && mod_ctx->igh->inherited_gh &&
            hash_count(mod_ctx->igh->inherited_gh) > 0) {
            ret = mbof_inherited_mod(mod_ctx);
        } else {
            ret = mbof_mod_process(mod_ctx, &mod_ctx->terminate);
        }

        if (ret != LDB_SUCCESS) {
            talloc_zfree(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    if (mod_ctx->terminate) {
        talloc_zfree(ares);
        return ldb_module_done(ctx->req,
                               ctx->ret_ctrls,
                               ctx->ret_resp,
                               LDB_SUCCESS);
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_inherited_mod(struct mbof_mod_ctx *mod_ctx)
{
    struct ldb_request *mod_req;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int ret;
    struct ldb_message_element *el;
    struct ldb_message *msg;
    struct ldb_val *val;
    struct ldb_val *dupval;
    hash_value_t *values;
    unsigned long num_values;
    int i, j;

    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    /* add back the inherited children to entry */
    msg = ldb_msg_new(mod_ctx);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = mod_ctx->entry->dn;

    /* We only inherit during replaces, so it's safe to only look
     * at the replaced set
     */
    ret = ldb_msg_add_empty(msg, DB_GHOST, LDB_FLAG_MOD_ADD, &el);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    ret = hash_values(mod_ctx->igh->inherited_gh, &num_values, &values);
    if (ret != HASH_SUCCESS) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    el->values = talloc_array(msg, struct ldb_val, num_values);
    if (!el->values) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    for (i = 0, j = 0; i < num_values; i++) {
        val = talloc_get_type(values[i].ptr, struct ldb_val);

        dupval = ldb_msg_find_val(mod_ctx->ghel, val);
        if (dupval) {
            continue;
        }

        el->values[j].length = strlen((const char *) val->data);
        el->values[j].data = (uint8_t *) talloc_strdup(el->values,
                                                    (const char *) val->data);
        if (!el->values[j].data) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        j++;
    }
    el->num_values = j;

    if (el->num_values == 0) {
        /* nothing to do */
        /* We cannot modify element which has 0 values */
        msg->num_elements = 0;
    }

    mod_ctx->igh->mod_msg = msg;
    mod_ctx->igh->el = el;

    ret = ldb_build_mod_req(&mod_req, ldb, ctx->req,
                            msg, ctx->req->controls,
                            mod_ctx, mbof_inherited_mod_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_next_request(ctx->module, mod_req);
}

static int mbof_inherited_mod_callback(struct ldb_request *req,
                                       struct ldb_reply *ares)
{
    struct ldb_context *ldb;
    struct mbof_mod_ctx *mod_ctx;
    struct mbof_ctx *ctx;
    int ret;

    mod_ctx = talloc_get_type(req->context, struct mbof_mod_ctx);
    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    if (ares->type != LDB_REPLY_DONE) {
        talloc_zfree(ares);
        ldb_debug(ldb, LDB_DEBUG_TRACE, "Invalid reply type!");
        ldb_set_errstring(ldb, "Invalid reply type!");
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }

    ret = mbof_mod_process(mod_ctx, &mod_ctx->terminate);
    if (ret != LDB_SUCCESS) {
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL, ret);
    }

    if (mod_ctx->terminate) {
        talloc_zfree(ares);
        return ldb_module_done(ctx->req,
                               ctx->ret_ctrls,
                               ctx->ret_resp,
                               LDB_SUCCESS);
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_mod_process(struct mbof_mod_ctx *mod_ctx, bool *done)
{
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int ret;

    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    ret = mbof_mod_process_membel(mod_ctx, ldb, mod_ctx->entry, mod_ctx->membel,
                                  &mod_ctx->mb_add, &mod_ctx->mb_remove);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    ret = mbof_mod_process_ghel(mod_ctx, mod_ctx->entry, mod_ctx->ghel,
                                mod_ctx->igh ? mod_ctx->igh->el : NULL,
                                &mod_ctx->gh_add, &mod_ctx->gh_remove);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    /* Process the operations */
    /* if we have something to remove, do it first */
    if ((mod_ctx->mb_remove && mod_ctx->mb_remove->num) ||
        (mod_ctx->gh_remove && mod_ctx->gh_remove->num)) {
        return mbof_mod_delete(mod_ctx, mod_ctx->mb_remove, mod_ctx->gh_remove);
    }

    /* if there is nothing to remove and we have stuff to add,
     * do it right away */
    if ((mod_ctx->mb_add && mod_ctx->mb_add->num) ||
        (mod_ctx->gh_add && mod_ctx->gh_add->num)) {
        return mbof_mod_add(mod_ctx, mod_ctx->mb_add, mod_ctx->gh_add);
    }

    /* the replacement function resulted in a null op,
     * nothing to do, return happily */
    *done = true;
    return LDB_SUCCESS;
}

static int mbof_mod_process_membel(TALLOC_CTX *mem_ctx,
                                   struct ldb_context *ldb,
                                   struct ldb_message *entry,
                                   const struct ldb_message_element *membel,
                                   struct mbof_dn_array **_added,
                                   struct mbof_dn_array **_removed)
{
    const struct ldb_message_element *el;
    struct mbof_dn_array *removed = NULL;
    struct mbof_dn_array *added = NULL;
    int i, j, ret;

    if (!membel) {
        /* Nothing to do.. */
        return LDB_SUCCESS;
    }

    switch (membel->flags) {
    case LDB_FLAG_MOD_ADD:

        ret = mbof_fill_dn_array(mem_ctx, ldb, membel, &added);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        break;

    case LDB_FLAG_MOD_DELETE:

        if (membel->num_values == 0) {
            el = ldb_msg_find_element(entry, DB_MEMBER);
        } else {
            el = membel;
        }

        if (!el) {
            /* nothing to do really */
            break;
        }

        ret = mbof_fill_dn_array(mem_ctx, ldb, el, &removed);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        break;

    case LDB_FLAG_MOD_REPLACE:

        removed = NULL;
        el = ldb_msg_find_element(entry, DB_MEMBER);
        if (el) {
            ret = mbof_fill_dn_array(mem_ctx, ldb, el, &removed);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        added = NULL;
        el = membel;
        if (el) {
            ret = mbof_fill_dn_array(mem_ctx, ldb, el, &added);
            if (ret != LDB_SUCCESS) {
                talloc_free(removed);
                return ret;
            }
        }

        /* remove from arrays values that ended up unchanged */
        if (removed && removed->num && added && added->num) {
            for (i = 0; i < added->num; i++) {
                for (j = 0; j < removed->num; j++) {
                    if (ldb_dn_compare(added->dns[i], removed->dns[j]) == 0) {
                        break;
                    }
                }
                if (j < removed->num) {
                    /* preexisting one, not removed, nor added */
                    for (; j+1 < removed->num; j++) {
                        removed->dns[j] = removed->dns[j+1];
                    }
                    removed->num--;
                    for (j = i; j+1 < added->num; j++) {
                        added->dns[j] = added->dns[j+1];
                    }
                    added->num--;
                    i--;
                }
            }
        }
        break;

    default:
        return LDB_ERR_OPERATIONS_ERROR;
    }

    *_added = added;
    *_removed = removed;
    return LDB_SUCCESS;
}

static int mbof_mod_process_ghel(TALLOC_CTX *mem_ctx,
                                 struct ldb_message *entry,
                                 const struct ldb_message_element *ghel,
                                 const struct ldb_message_element *inherited,
                                 struct mbof_val_array **_added,
                                 struct mbof_val_array **_removed)
{
    const struct ldb_message_element *el;
    struct mbof_val_array *removed = NULL;
    struct mbof_val_array *added = NULL;
    int i, j, ret;

    if (!ghel) {
        /* Nothing to do.. */
        return LDB_SUCCESS;
    }

    el = ldb_msg_find_element(entry, DB_MEMBEROF);
    if (!el || el->num_values == 0) {
        /* no memberof attributes ... */
        return LDB_SUCCESS;
    }

    switch (ghel->flags) {
    case LDB_FLAG_MOD_ADD:
        ret = mbof_fill_vals_array_el(mem_ctx, ghel, &added);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        break;

    case LDB_FLAG_MOD_DELETE:
        if (ghel->num_values == 0) {
            el = ldb_msg_find_element(entry, DB_GHOST);
        } else {
            el = ghel;
        }

        if (!el) {
            /* nothing to do really */
            break;
        }

        ret = mbof_fill_vals_array_el(mem_ctx, ghel, &removed);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
        break;

    case LDB_FLAG_MOD_REPLACE:
        el = ldb_msg_find_element(entry, DB_GHOST);
        if (el) {
            ret = mbof_fill_vals_array_el(mem_ctx, el, &removed);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        el = ghel;
        if (el) {
            ret = mbof_fill_vals_array_el(mem_ctx, el, &added);
            if (ret != LDB_SUCCESS) {
                talloc_free(removed);
                return ret;
            }
        }

        if (inherited) {
            ret = mbof_fill_vals_array_el(mem_ctx, inherited, &added);
            if (ret != LDB_SUCCESS) {
                talloc_free(added);
                talloc_free(removed);
                return ret;
            }
        }

        /* remove from arrays values that ended up unchanged */
        if (removed && removed->num && added && added->num) {
            for (i = 0; i < added->num; i++) {
                for (j = 0; j < removed->num; j++) {
                    if (strcmp((const char *) added->vals[i].data,
                               (const char *) removed->vals[j].data) == 0) {
                        break;
                    }
                }
                if (j < removed->num) {
                    /* preexisting one, not removed, nor added */
                    for (; j+1 < removed->num; j++) {
                        removed->vals[j] = removed->vals[j+1];
                    }
                    removed->num--;
                    for (j = i; j+1 < added->num; j++) {
                        added->vals[j] = added->vals[j+1];
                    }
                    added->num--;
                    i--;
                }
            }
        }
        break;

    default:
        return LDB_ERR_OPERATIONS_ERROR;
    }

    *_added = added;
    *_removed = removed;
    return LDB_SUCCESS;
}

static int mbof_mod_add(struct mbof_mod_ctx *mod_ctx,
                        struct mbof_dn_array *ael,
                        struct mbof_val_array *addgh)
{
    const struct ldb_message_element *el;
    struct mbof_dn_array *parents;
    struct mbof_add_ctx *add_ctx;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int i, ret;

    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    el = ldb_msg_find_element(mod_ctx->entry, DB_MEMBEROF);

    /* all the parents + itself */
    ret = mbof_fill_dn_array(mod_ctx, ldb, el, &parents);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    add_ctx = talloc_zero(mod_ctx, struct mbof_add_ctx);
    if (!add_ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    add_ctx->ctx = ctx;
    add_ctx->msg_dn = mod_ctx->msg->dn;

    if (addgh != NULL) {
        /* Build the memberuid add op */
        ret =  mbof_add_fill_ghop_ex(add_ctx, mod_ctx->entry,
                                     parents, addgh->vals, addgh->num);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    if (ael != NULL && ael->num > 0) {
        /* Add itself to the list of the parents to also get the memberuid */
        parents->dns = talloc_realloc(parents, parents->dns,
                                    struct ldb_dn *, parents->num + 1);
        if (!parents->dns) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        parents->dns[parents->num] = mod_ctx->entry->dn;
        parents->num++;

        /* Build the member-add array */
        for (i = 0; i < ael->num; i++) {
            ret = mbof_append_addop(add_ctx, parents, ael->dns[i]);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        return mbof_next_add(add_ctx->add_list);
    }

    return mbof_add_muop(add_ctx);
}

static int mbof_mod_delete(struct mbof_mod_ctx *mod_ctx,
                           struct mbof_dn_array *del,
                           struct mbof_val_array *delgh)
{
    struct mbof_del_operation *first;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    int i, ret;

    ctx = mod_ctx->ctx;

    del_ctx = talloc_zero(mod_ctx, struct mbof_del_ctx);
    if (!del_ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    del_ctx->ctx = ctx;
    del_ctx->is_mod = true;

    /* create first entry */
    /* the first entry is the parent of all entries and the one where we
     * remove member from, it does not get the same treatment as others */
    first = talloc_zero(del_ctx, struct mbof_del_operation);
    if (!first) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    del_ctx->first = first;

    /* add followup function if we also have stuff to add */
    if ((mod_ctx->mb_add && mod_ctx->mb_add->num > 0) ||
        (mod_ctx->gh_add && mod_ctx->gh_add->num > 0)) {
        del_ctx->follow_mod = mod_ctx;
    }

    first->del_ctx = del_ctx;
    first->entry = mod_ctx->entry;
    first->entry_dn = mod_ctx->entry->dn;

    if (delgh != NULL) {
        ret = mbof_del_fill_ghop_ex(del_ctx, del_ctx->first->entry,
                                    delgh->vals, delgh->num);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    /* prepare del sets */
    if (del != NULL && del->num > 0) {
        for (i = 0; i < del->num; i++) {
            ret = mbof_append_delop(first, del->dns[i]);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        /* now that sets are built, start processing */
        return mbof_del_execute_op(first->children[0]);
    }

    /* No member processing, just delete ghosts */
    return mbof_del_ghop(del_ctx);
}

static int mbof_fill_dn_array(TALLOC_CTX *memctx,
                              struct ldb_context *ldb,
                              const struct ldb_message_element *el,
                              struct mbof_dn_array **dn_array)
{
    struct mbof_dn_array *ar;
    struct ldb_dn *valdn;
    int i;

    ar = talloc_zero(memctx, struct mbof_dn_array);
    if (!ar) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    *dn_array = ar;

    if (!el || el->num_values == 0) {
        return LDB_SUCCESS;
    }

    ar->dns = talloc_array(ar, struct ldb_dn *, el->num_values);
    if (!ar->dns) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    ar->num = el->num_values;

    for (i = 0; i < ar->num; i++) {
        valdn = ldb_dn_from_ldb_val(ar, ldb, &el->values[i]);
        if (!valdn || !ldb_dn_validate(valdn)) {
            ldb_debug(ldb, LDB_DEBUG_TRACE, "Invalid dn value: [%s]",
                                            (const char *)el->values[i].data);
            return LDB_ERR_INVALID_DN_SYNTAX;
        }
        ar->dns[i] = valdn;
    }

    return LDB_SUCCESS;
}

static int mbof_fill_vals_array(TALLOC_CTX *memctx,
                                unsigned int num_values,
                                struct ldb_val *values,
                                struct mbof_val_array **val_array)
{
    struct mbof_val_array *var = *val_array;
    int i, vi;

    if (var == NULL) {
        var = talloc_zero(memctx, struct mbof_val_array);
        if (!var) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        *val_array = var;
    }

    if (values == NULL || num_values == 0) {
        return LDB_SUCCESS;
    }

    /* We do not care about duplicate values now.
     * They will be filtered later */
    vi = var->num;
    var->num += num_values;
    var->vals = talloc_realloc(memctx, var->vals, struct ldb_val, var->num);
    if (!var->vals) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    /* FIXME - use ldb_val_dup() */
    for (i = 0; i < num_values; i++) {
        var->vals[vi].length = strlen((const char *) values[i].data);
        var->vals[vi].data = (uint8_t *) talloc_strdup(var,
                                          (const char *) values[i].data);
        if (var->vals[vi].data == NULL) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        vi++;
    }

    return LDB_SUCCESS;
}

static int mbof_fill_vals_array_el(TALLOC_CTX *memctx,
                                   const struct ldb_message_element *el,
                                   struct mbof_val_array **val_array)
{
    if (el == NULL) {
        return LDB_SUCCESS;
    }

    return mbof_fill_vals_array(memctx, el->num_values, el->values,
                                val_array);
}

/*************************
 * Cleanup task routines *
 *************************/

struct mbof_member {
    struct mbof_member *prev;
    struct mbof_member *next;

    struct ldb_dn *dn;
    const char *name;
    bool orig_has_memberof;
    bool orig_has_memberuid;
    struct ldb_message_element *orig_members;

    struct mbof_member **members;

    hash_table_t *memberofs;

    struct ldb_message_element *memuids;

    enum { MBOF_GROUP_TO_DO = 0,
           MBOF_GROUP_DONE,
           MBOF_USER,
           MBOF_ITER_ERROR } status;
};

struct mbof_rcmp_context {
    struct ldb_module *module;
    struct ldb_request *req;

    struct mbof_member *user_list;
    hash_table_t *user_table;

    struct mbof_member *group_list;
    hash_table_t *group_table;
};

static int mbof_steal_msg_el(TALLOC_CTX *memctx,
                             const char *name,
                             struct ldb_message *msg,
                             struct ldb_message_element **_dest)
{
    struct ldb_message_element *src;
    struct ldb_message_element *dest;

    src = ldb_msg_find_element(msg, name);
    if (!src) {
        return LDB_ERR_NO_SUCH_ATTRIBUTE;
    }

    dest = talloc_zero(memctx, struct ldb_message_element);
    if (!dest) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    *dest = *src;
    talloc_steal(dest, dest->name);
    talloc_steal(dest, dest->values);

    *_dest = dest;
    return LDB_SUCCESS;
}

static int mbof_rcmp_usr_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static int mbof_rcmp_search_groups(struct mbof_rcmp_context *ctx);
static int mbof_rcmp_grp_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static int mbof_member_update(struct mbof_rcmp_context *ctx,
                              struct mbof_member *parent,
                              struct mbof_member *mem);
static bool mbof_member_iter(hash_entry_t *item, void *user_data);
static int mbof_add_memuid(struct mbof_member *grp, const char *user);
static int mbof_rcmp_update(struct mbof_rcmp_context *ctx);
static int mbof_rcmp_mod_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);

static int memberof_recompute_task(struct ldb_module *module,
                                   struct ldb_request *req)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    static const char *attrs[] = { DB_NAME, DB_MEMBEROF, NULL };
    static const char *filter = "("DB_OC"="DB_USER_CLASS")";
    struct mbof_rcmp_context *ctx;
    struct ldb_request *src_req;
    int ret;

    ctx = talloc_zero(req, struct mbof_rcmp_context);
    if (!ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    ctx->module = module;
    ctx->req = req;

    ret = hash_create_ex(1024, &ctx->user_table, 0, 0, 0, 0,
                         hash_alloc, hash_free, ctx, NULL, NULL);
    if (ret != HASH_SUCCESS) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    ret = ldb_build_search_req(&src_req, ldb, ctx,
                               NULL, LDB_SCOPE_SUBTREE,
                               filter, attrs, NULL,
                               ctx, mbof_rcmp_usr_callback, ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_request(ldb, src_req);
}

static int mbof_rcmp_usr_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct mbof_rcmp_context *ctx;
    struct mbof_member *usr;
    hash_value_t value;
    hash_key_t key;
    const char *name;
    int ret;

    ctx = talloc_get_type(req->context, struct mbof_rcmp_context);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:

        usr = talloc_zero(ctx, struct mbof_member);
        if (!usr) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        usr->status = MBOF_USER;
        usr->dn = talloc_steal(usr, ares->message->dn);
        name = ldb_msg_find_attr_as_string(ares->message, DB_NAME, NULL);
        if (name) {
            usr->name = talloc_steal(usr, name);
        }

        if (ldb_msg_find_element(ares->message, DB_MEMBEROF)) {
            usr->orig_has_memberof = true;
        }

        DLIST_ADD(ctx->user_list, usr);

        key.type = HASH_KEY_STRING;
        key.str = discard_const(ldb_dn_get_linearized(usr->dn));
        value.type = HASH_VALUE_PTR;
        value.ptr = usr;

        ret = hash_enter(ctx->user_table, &key, &value);
        if (ret != HASH_SUCCESS) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        break;

    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        talloc_zfree(ares);

        /* and now search groups */
        return mbof_rcmp_search_groups(ctx);
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_rcmp_search_groups(struct mbof_rcmp_context *ctx)
{
    struct ldb_context *ldb = ldb_module_get_ctx(ctx->module);
    static const char *attrs[] = { DB_MEMBEROF, DB_MEMBERUID,
                                   DB_NAME, DB_MEMBER, NULL };
    static const char *filter = "("DB_OC"="DB_GROUP_CLASS")";
    struct ldb_request *req;
    int ret;

    ret = hash_create_ex(1024, &ctx->group_table, 0, 0, 0, 0,
                         hash_alloc, hash_free, ctx, NULL, NULL);
    if (ret != HASH_SUCCESS) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }

    ret = ldb_build_search_req(&req, ldb, ctx,
                               NULL, LDB_SCOPE_SUBTREE,
                               filter, attrs, NULL,
                               ctx, mbof_rcmp_grp_callback, ctx->req);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    return ldb_request(ldb, req);
}

static int mbof_rcmp_grp_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct ldb_context *ldb;
    struct mbof_rcmp_context *ctx;
    struct ldb_message_element *el;
    struct mbof_member *iter;
    struct mbof_member *grp;
    hash_value_t value;
    hash_key_t key;
    const char *name;
    int i, j;
    int ret;

    ctx = talloc_get_type(req->context, struct mbof_rcmp_context);
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:

        grp = talloc_zero(ctx, struct mbof_member);
        if (!grp) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        grp->status = MBOF_GROUP_TO_DO;
        grp->dn = talloc_steal(grp, ares->message->dn);
        grp->name = ldb_msg_find_attr_as_string(ares->message, DB_NAME, NULL);
        name = ldb_msg_find_attr_as_string(ares->message, DB_NAME, NULL);
        if (name) {
            grp->name = talloc_steal(grp, name);
        }

        if (ldb_msg_find_element(ares->message, DB_MEMBEROF)) {
            grp->orig_has_memberof = true;
        }

        if (ldb_msg_find_element(ares->message, DB_MEMBERUID)) {
            grp->orig_has_memberuid = true;
        }

        ret = mbof_steal_msg_el(grp, DB_MEMBER,
                                ares->message, &grp->orig_members);
        if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        DLIST_ADD(ctx->group_list, grp);

        key.type = HASH_KEY_STRING;
        key.str = discard_const(ldb_dn_get_linearized(grp->dn));
        value.type = HASH_VALUE_PTR;
        value.ptr = grp;

        ret = hash_enter(ctx->group_table, &key, &value);
        if (ret != HASH_SUCCESS) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }

        break;

    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
        talloc_zfree(ares);

        if (!ctx->group_list) {
            /* no groups? */
            return ldb_module_done(ctx->req, NULL, NULL, LDB_SUCCESS);
        }

        /* for each group compute the members list */
        for (iter = ctx->group_list; iter; iter = iter->next) {

            el = iter->orig_members;
            if (!el || el->num_values == 0) {
                /* no members */
                continue;
            }

            /* we have at most num_values group members */
            iter->members = talloc_array(iter, struct mbof_member *,
                                         el->num_values +1);
            if (!iter->members) {
                return ldb_module_done(ctx->req, NULL, NULL,
                                       LDB_ERR_OPERATIONS_ERROR);
            }

            for (i = 0, j = 0; i < el->num_values; i++) {
                key.type = HASH_KEY_STRING;
                key.str = (char *)el->values[i].data;

                ret = hash_lookup(ctx->user_table, &key, &value);
                switch (ret) {
                case HASH_SUCCESS:
                    iter->members[j] = (struct mbof_member *)value.ptr;
                    j++;
                    break;

                case HASH_ERROR_KEY_NOT_FOUND:
                    /* not a user, see if it is a group */

                    ret = hash_lookup(ctx->group_table, &key, &value);
                    if (ret != HASH_SUCCESS) {
                        if (ret != HASH_ERROR_KEY_NOT_FOUND) {
                            return ldb_module_done(ctx->req, NULL, NULL,
                                                   LDB_ERR_OPERATIONS_ERROR);
                        }
                    }
                    if (ret == HASH_ERROR_KEY_NOT_FOUND) {
                        /* not a known user, nor a known group!?
                           give a warning and continue */
                        ldb_debug(ldb, LDB_DEBUG_ERROR,
                                  "member attribute [%s] has no corresponding"
                                  " entry!", key.str);
                        break;
                    }

                    iter->members[j] = (struct mbof_member *)value.ptr;
                    j++;
                    break;

                default:
                    return ldb_module_done(ctx->req, NULL, NULL,
                                           LDB_ERR_OPERATIONS_ERROR);
                }
            }
            /* terminate */
            iter->members[j] = NULL;

            talloc_zfree(iter->orig_members);
        }

        /* now generate correct memberof tables */
        while (ctx->group_list->status == MBOF_GROUP_TO_DO) {

            grp = ctx->group_list;

            /* move to end of list and mark as done.
             * NOTE: this is not efficient, but will do for now */
            DLIST_DEMOTE(ctx->group_list, grp, struct mbof_member *);
            grp->status = MBOF_GROUP_DONE;

            /* verify if members need updating */
            if (!grp->members) {
                continue;
            }
            for (i = 0; grp->members[i]; i++) {
                ret = mbof_member_update(ctx, grp, grp->members[i]);
                if (ret != LDB_SUCCESS) {
                    return ldb_module_done(ctx->req, NULL, NULL,
                                           LDB_ERR_OPERATIONS_ERROR);
                }
            }
        }

        /* ok all done, now go on and modify the tree */
        return mbof_rcmp_update(ctx);
    }

    talloc_zfree(ares);
    return LDB_SUCCESS;
}

static int mbof_member_update(struct mbof_rcmp_context *ctx,
                              struct mbof_member *parent,
                              struct mbof_member *mem)
{
    hash_value_t value;
    hash_key_t key;
    int ret;

    /* ignore loops */
    if (parent == mem) return LDB_SUCCESS;

    key.type = HASH_KEY_STRING;
    key.str = discard_const(ldb_dn_get_linearized(parent->dn));

    if (!mem->memberofs) {
        ret = hash_create_ex(0, &mem->memberofs, 0, 0, 0, 0,
                             hash_alloc, hash_free, mem, NULL, NULL);
        if (ret != HASH_SUCCESS) {
            return LDB_ERR_OPERATIONS_ERROR;
        }

        ret = HASH_ERROR_KEY_NOT_FOUND;

    } else {

        ret = hash_lookup(mem->memberofs, &key, &value);
        if (ret != HASH_SUCCESS) {
            if (ret != HASH_ERROR_KEY_NOT_FOUND) {
                /* fatal error */
                return LDB_ERR_OPERATIONS_ERROR;
            }
        }
    }

    if (ret == HASH_ERROR_KEY_NOT_FOUND) {

        /* it's missing, update member */
        value.type = HASH_VALUE_PTR;
        value.ptr = parent;

        ret = hash_enter(mem->memberofs, &key, &value);
        if (ret != HASH_SUCCESS) {
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (mem->status == MBOF_USER) {
            /* add corresponding memuid to the group */
            ret = mbof_add_memuid(parent, mem->name);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        /* if we updated a group, mark it as TO DO again */
        if (mem->status == MBOF_GROUP_DONE) {
            mem->status = MBOF_GROUP_TO_DO;
        }
    }

    /* now see if the parent has memberofs to pass down */
    if (parent->memberofs) {
        ret = hash_iterate(parent->memberofs, mbof_member_iter, mem);
        if (ret != HASH_SUCCESS) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
        if (mem->status == MBOF_ITER_ERROR) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
    }

    /* finally, if it was made TO DO move it to the head */
    if (mem->status == MBOF_GROUP_TO_DO) {
        DLIST_PROMOTE(ctx->group_list, mem);
    }

    return LDB_SUCCESS;
}

static bool mbof_member_iter(hash_entry_t *item, void *user_data)
{
    struct mbof_member *parent;
    struct mbof_member *mem;
    hash_value_t value;
    int ret;

    mem = talloc_get_type(user_data, struct mbof_member);

    /* exclude self */
    if (strcmp(item->key.str, ldb_dn_get_linearized(mem->dn)) == 0) {
        return true;
    }

    /* check if we already have it */
    ret = hash_lookup(mem->memberofs, &item->key, &value);
    if (ret != HASH_SUCCESS) {
        if (ret != HASH_ERROR_KEY_NOT_FOUND) {
            /* fatal error */
            mem->status = MBOF_ITER_ERROR;
            return false;
        }

        /* was not already here, add it and mark group as TO DO */
        ret = hash_enter(mem->memberofs, &item->key, &item->value);
        if (ret != HASH_SUCCESS) {
            return LDB_ERR_OPERATIONS_ERROR;
        }

        if (mem->status == MBOF_GROUP_DONE) {
            mem->status = MBOF_GROUP_TO_DO;
        }

        if (mem->status == MBOF_USER) {
            /* add corresponding memuid to the group */
            parent = (struct mbof_member *)item->value.ptr;
            ret = mbof_add_memuid(parent, mem->name);
            if (ret != LDB_SUCCESS) {
                mem->status = MBOF_ITER_ERROR;
                return false;
            }
        }
    }

    return true;
}

static int mbof_add_memuid(struct mbof_member *grp, const char *user)
{
    struct ldb_val *vals;
    int n;

    if (!grp->memuids) {
        grp->memuids = talloc_zero(grp, struct ldb_message_element);
        if (!grp->memuids) {
            return LDB_ERR_OPERATIONS_ERROR;
        }

        grp->memuids->name = talloc_strdup(grp->memuids, DB_MEMBERUID);
        if (!grp->memuids->name) {
            return LDB_ERR_OPERATIONS_ERROR;
        }
    }

    n = grp->memuids->num_values;
    vals = talloc_realloc(grp->memuids,
                          grp->memuids->values,
                          struct ldb_val, n + 1);
    if (!vals) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    vals[n].data = (uint8_t *)talloc_strdup(vals, user);
    vals[n].length = strlen(user);

    grp->memuids->values = vals;
    grp->memuids->num_values = n + 1;

    return LDB_SUCCESS;
}

static int mbof_rcmp_update(struct mbof_rcmp_context *ctx)
{
    struct ldb_context *ldb = ldb_module_get_ctx(ctx->module);
    struct ldb_message_element *el;
    struct ldb_message *msg = NULL;
    struct ldb_request *req;
    struct mbof_member *x = NULL;
    hash_key_t *keys;
    unsigned long count;
    int flags;
    int ret, i;

    /* we process all users first and then all groups */
    if (ctx->user_list) {
        /* take the next entry and remove it from the list */
        x = ctx->user_list;
        DLIST_REMOVE(ctx->user_list, x);
    }
    else if (ctx->group_list) {
        /* take the next entry and remove it from the list */
        x = ctx->group_list;
        DLIST_REMOVE(ctx->group_list, x);
    }
    else {
        /* processing terminated, return */
        ret = LDB_SUCCESS;
        goto done;
    }

    msg = ldb_msg_new(ctx);
    if (!msg) {
        ret = LDB_ERR_OPERATIONS_ERROR;
        goto done;
    }

    msg->dn = x->dn;

    /* process memberof */
    if (x->memberofs) {
        ret = hash_keys(x->memberofs, &count, &keys);
        if (ret != HASH_SUCCESS) {
            ret = LDB_ERR_OPERATIONS_ERROR;
            goto done;
        }

        if (x->orig_has_memberof) {
            flags = LDB_FLAG_MOD_REPLACE;
        } else {
            flags = LDB_FLAG_MOD_ADD;
        }

        ret = ldb_msg_add_empty(msg, DB_MEMBEROF, flags, &el);
        if (ret != LDB_SUCCESS) {
            goto done;
        }

        el->values = talloc_array(el, struct ldb_val, count);
        if (!el->values) {
            ret = LDB_ERR_OPERATIONS_ERROR;
            goto done;
        }
        el->num_values = count;

        for (i = 0; i < count; i++) {
            el->values[i].data = (uint8_t *)keys[i].str;
            el->values[i].length = strlen(keys[i].str);
        }
    } else if (x->orig_has_memberof) {
        ret = ldb_msg_add_empty(msg, DB_MEMBEROF, LDB_FLAG_MOD_DELETE, NULL);
        if (ret != LDB_SUCCESS) {
            goto done;
        }
    }

    /* process memberuid */
    if (x->memuids) {
        if (x->orig_has_memberuid) {
            flags = LDB_FLAG_MOD_REPLACE;
        } else {
            flags = LDB_FLAG_MOD_ADD;
        }

        ret = ldb_msg_add(msg, x->memuids, flags);
        if (ret != LDB_SUCCESS) {
            goto done;
        }
    }
    else if (x->orig_has_memberuid) {
        ret = ldb_msg_add_empty(msg, DB_MEMBERUID, LDB_FLAG_MOD_DELETE, NULL);
        if (ret != LDB_SUCCESS) {
            goto done;
        }
    }

    ret = ldb_build_mod_req(&req, ldb, ctx, msg, NULL,
                            ctx, mbof_rcmp_mod_callback,
                            ctx->req);
    if (ret != LDB_SUCCESS) {
        goto done;
    }
    talloc_steal(req, msg);

    /* fire next call */
    return ldb_next_request(ctx->module, req);

done:
    /* all users and groups have been processed */
    return ldb_module_done(ctx->req, NULL, NULL, ret);
}

static int mbof_rcmp_mod_callback(struct ldb_request *req,
                                  struct ldb_reply *ares)
{
    struct ldb_context *ldb;
    struct mbof_rcmp_context *ctx;

    ctx = talloc_get_type(req->context, struct mbof_rcmp_context);
    ldb = ldb_module_get_ctx(ctx->module);

    if (!ares) {
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    }
    if (ares->error != LDB_SUCCESS) {
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               ares->error);
    }

    switch (ares->type) {
    case LDB_REPLY_ENTRY:
        ldb_debug(ldb, LDB_DEBUG_TRACE, "Got an entry on a non search op?!");
        /* shouldn't happen */
        talloc_zfree(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        talloc_zfree(ares);
        break;

    case LDB_REPLY_DONE:
        talloc_zfree(ares);

        /* update the next one */
        return mbof_rcmp_update(ctx);
    }

    return LDB_SUCCESS;
}



/* module init code */

static int memberof_init(struct ldb_module *module)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    int ret;

    /* set syntaxes for member and memberof so that comparisons in filters and
     * such are done right */
    ret = ldb_schema_attribute_add(ldb, DB_MEMBER, 0, LDB_SYNTAX_DN);
    if (ret != 0) return LDB_ERR_OPERATIONS_ERROR;

    ret = ldb_schema_attribute_add(ldb, DB_MEMBEROF, 0, LDB_SYNTAX_DN);
    if (ret != 0) return LDB_ERR_OPERATIONS_ERROR;

    return ldb_next_init(module);
}

const struct ldb_module_ops ldb_memberof_module_ops = {
    .name = "memberof",
    .init_context = memberof_init,
    .add = memberof_add,
    .modify = memberof_mod,
    .del = memberof_del,
};

int ldb_init_module(const char *version)
{
#if defined(SSS_LDB_VERSION_CHECK) && defined(LDB_MODULE_CHECK_VERSION)
    LDB_MODULE_CHECK_VERSION(version);
#endif /* SSS_LDB_VERSION_CHECK && LDB_MODULE_CHECK_VERSION */
    return ldb_register_module(&ldb_memberof_module_ops);
}
