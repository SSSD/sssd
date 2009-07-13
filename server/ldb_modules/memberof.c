/*
   SSSD memberof module

   Copyright (C) Simo Sorce <idra@samba.org> 2008

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
#include "ldb_module.h"

#ifndef MAX
#define MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif

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

struct mbof_add_ctx {
    struct mbof_ctx *ctx;

    struct mbof_add_operation *add_list;
    struct mbof_add_operation *current_op;
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
    int cur_child;

    struct ldb_dn *entry_dn;

    struct ldb_message *entry;
    struct ldb_message **parents;
    int num_parents;
    int cur_parent;

    struct mbof_del_ancestors_ctx *anc_ctx;
};

struct mbof_del_ctx {
    struct mbof_ctx *ctx;

    struct mbof_del_operation *first;
    struct mbof_dn *history;

    void *followup_ctx;
    int (*followup_fn)(void *);
};

struct mbof_mod_ctx {
    struct mbof_ctx *ctx;

    const struct ldb_message_element *membel;
    struct ldb_message *entry;

    struct mbof_dn_array *to_add;
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




/* add operation */

/* An add operation is quite simple.
 * First of all a new object cannot yet have parents, so the only memberof
 * attribute that can be added to any member contains just one object DN.
 *
 * Once the add operation has been performed to assure nothing else fails, then
 * on return we list all members and for each member we create an "add
 * operation" for each member of the object we just added and we pass it a
 * parent list of one member (the object we just added).
 *
 * For each add operation we lookup the object we want to operate on (children
 * or descendant of a previously added/changed object).
 * We take the list of memberof attributes and sort out which parents are still
 * missing from the parent list we have been provided.
 * We modify the object memberof attributes to reflect the new memberships.
 * Then we list all members of this object, and for each once again we create an
 * "add operation" as we did in the initial object.
 * Processing stops when the target object does not have members or when it
 * already has all the parents (can happen if nested groups create loops).
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

static int mbof_add_callback(struct ldb_request *req,
                             struct ldb_reply *ares);
static int mbof_next_add(struct mbof_add_operation *addop);
static int mbof_next_add_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static int mbof_add_operation(struct mbof_add_operation *addop);

static int memberof_add(struct ldb_module *module, struct ldb_request *req)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct mbof_add_ctx *add_ctx;
    struct mbof_ctx *ctx;
    struct ldb_request *add_req;
    const struct ldb_message_element *el;
    struct mbof_dn_array *parents;
    struct ldb_dn *valdn;
    int i, ret;

	if (ldb_dn_is_special(req->op.add.message->dn)) {
		/* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

    /* fail operation if memberof is ever specified */
    el = ldb_msg_find_element(req->op.add.message, "memberof");
    if (el) {
        /* FIXME: should we simply filter it instead ? */
        ldb_debug(ldb, LDB_DEBUG_TRACE, "the memberof attrinbute is readonly");
        return LDB_ERR_CONSTRAINT_VIOLATION;
    }

    /* continue with normal ops if there are no members */
    el = ldb_msg_find_element(req->op.add.message, "member");
    if (!el) {
        return ldb_next_request(module, req);
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

    parents = talloc_zero(add_ctx, struct mbof_dn_array);
    if (!parents) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    parents->dns = talloc_array(parents, struct ldb_dn *, 1);
    if (!parents->dns) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    parents->dns[0] = req->op.add.message->dn;
    parents->num = 1;

    /* process new members */
    /* check we are not adding ourselves as member as well */
    for (i = 0; i < el->num_values; i++) {
        valdn = ldb_dn_from_ldb_val(add_ctx, ldb, &el->values[i]);
        if (!valdn || !ldb_dn_validate(valdn)) {
            ldb_debug(ldb, LDB_DEBUG_TRACE, "Invalid dn value: [%s]",
                                            (const char *)el->values[i].data);
            return LDB_ERR_INVALID_DN_SYNTAX;
        }
        if (ldb_dn_compare(valdn, req->op.add.message->dn) == 0) {
            ldb_debug(ldb, LDB_DEBUG_TRACE, "Adding self as member is not permitted!");
		    ldb_set_errstring(ldb, "Adding self as member is not permitted!");
            return LDB_ERR_CONSTRAINT_VIOLATION;
        }
        ret = mbof_append_addop(add_ctx, parents, valdn);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    /* add original object */
    ret = ldb_build_add_req(&add_req, ldb, add_ctx,
                            req->op.add.message, req->controls,
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
        talloc_free(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        break;

    case LDB_REPLY_DONE:
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
            talloc_free(ares);
            return ldb_module_done(ctx->req,
                                   ctx->ret_ctrls,
                                   ctx->ret_resp,
                                   LDB_SUCCESS);
        }

        if (ret != LDB_SUCCESS) {
            talloc_free(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_free(ares);
    return LDB_SUCCESS;
}

static int mbof_next_add(struct mbof_add_operation *addop)
{
    static const char *attrs[] = {"member", "memberof", NULL};
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
            /* more than one entry per dn ?? db corrupted ? */
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
        if (addop->entry == NULL) {
            ldb_debug(ldb, LDB_DEBUG_TRACE, "Entry not found (%s)",
                           ldb_dn_get_linearized(addop->entry_dn));
            /* this target does not exists, too bad! */
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_CONSTRAINT_VIOLATION);
        }

        ret = mbof_add_operation(addop);
        if (ret != LDB_SUCCESS) {
            talloc_free(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_free(ares);
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
    el = ldb_msg_find_element(addop->entry, "memberof");
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
            } else {
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
    el = ldb_msg_find_element(addop->entry, "member");
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

    /* we are done with the entry now */
    talloc_free(addop->entry);
    addop->entry = NULL;

    /* add memberof to entry */
    msg = ldb_msg_new(addop);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = addop->entry_dn;

    ret = ldb_msg_add_empty(msg, "memberof", LDB_FLAG_MOD_ADD, &el);
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




/* delete operations */

/* The implementation of delete operations is a bit more complex than an add
 * operation. This is because we need to recompute, memberships of potentially
 * quite far descendants and we also have to account for loops and how to break
 * them without ending in an endless loop ourselves.
 * The difficulty is in the fact that while the member -> memberof link is quite
 * direct, memberof -> member is not as membership ius transitive.
 *
 * Ok, first of all, contrary to the add operation, a delete operation involves
 * an existing object that may have existing parents. So forst thing we search
 * the object itself to get the original membership lists (member and memberof)
 * for this object, and we also search for any object that has it as one of its
 * members.
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
 * To handle the children we create a first ancestor operation that reflects the
 * delete we just made. We set as parents of this object the parents just
 * retrieved with the first search. Then we create a remove list.
 *
 * The remove list contains all objects in the original memberof list and the
 * object dn itself of the original delete operation target object (the first
 * ancestor).
 *
 * An operation is identified by an object that contains a tre of descendants,
 * The remove list for the children, the immediate parent, and the dn and entry
 * of the object this operation is about.
 *
 * We now proceed with adding a new operatoin for each original member of the
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
 * At this point we have the final new memberof list for this operation  and we
 * can proceed to modify the entry.
 *
 * Once the entry has been modified we proceed again to check if there are any
 * children of this entry (the entry has "member"s).
 * We create a new remove list that is the difference between the original entry
 * memberof list and the new memberof list we just stored back in the object.
 * Then for each member we create a new operation.
 *
 * We continue to process operations until no new operations need to be
 * performed.
 *
 * Ordering is important here, se the mbof_del_get_next() function to understand
 * how we proceed to select which new operation to process.
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


static int memberof_del(struct ldb_module *module, struct ldb_request *req)
{
    static const char *attrs[] = {"member", "memberof", NULL};
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct mbof_del_operation *first;
    struct ldb_request *search;
    char *expression;
    const char *dn;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    int ret;

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
    expression = talloc_asprintf(del_ctx,
                                 "(|(distinguishedName=%s)(member=%s))",
                                 dn, dn);
    if (!expression) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }

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
                /* more than one entry per dn ?? db corrupted ? */
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
            talloc_free(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_free(ares);
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
		talloc_free(ares);
		ldb_set_errstring(ldb, "Invalid reply type!");
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
	}

    /* save real call stuff */
    ctx->ret_ctrls = talloc_steal(ctx, ares->controls);
    ctx->ret_resp = talloc_steal(ctx, ares->response);

    /* prep following clean ops */
    if (del_ctx->first->num_parents) {
        /* if there are any parents, fire a removal sequence */
        ret = mbof_del_cleanup_parents(del_ctx);
    }
    else if (ldb_msg_find_element(del_ctx->first->entry, "member")) {
        /* if there are any children, fire a removal sequence */
        ret = mbof_del_cleanup_children(del_ctx);
    }
    else {
        /* no parents nor children, end ops */
        return ldb_module_done(ctx->req,
                               ares->controls,
                               ares->response,
                               LDB_SUCCESS);
    }
    if (ret != LDB_SUCCESS) {
        talloc_free(ares);
        return ldb_module_done(ctx->req, NULL, NULL, ret);
    }

    talloc_free(ares);
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

    ret = ldb_msg_add_empty(msg, "member", LDB_FLAG_MOD_DELETE, &el);
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
		talloc_free(ares);
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
        if (ldb_msg_find_element(first->entry, "member")) {
            /* if there are any children, fire a removal sequence */
            ret = mbof_del_cleanup_children(del_ctx);
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
        talloc_free(ares);
        return ldb_module_done(ctx->req, NULL, NULL, ret);
    }

    talloc_free(ares);
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

    el = ldb_msg_find_element(first->entry, "member");

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
    static const char *attrs[] = {"member", "memberof", NULL};
    int ret;

    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    /* load entry */
    dn = ldb_dn_get_linearized(delop->entry_dn);
    if (!dn) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    expression = talloc_asprintf(del_ctx,
                                 "(|(distinguishedName=%s)(member=%s))",
                                 dn, dn);
    if (!expression) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

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
                /* more than one entry per dn ?? db corrupted ? */
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

    talloc_free(ares);
    return LDB_SUCCESS;
}

static int mbof_del_execute_cont(struct mbof_del_operation *delop)
{
    struct mbof_del_ancestors_ctx *anc_ctx;
    struct mbof_del_operation *parent;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    struct ldb_context *ldb;
    struct mbof_dn_array *new_list;
    int i;

    del_ctx = delop->del_ctx;
    parent = delop->parent;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

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

    /* do we have any direct parent at all ? */
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
     * have changed by preceeding operations) */
    return mbof_del_ancestors(delop);
}

static int mbof_del_ancestors(struct mbof_del_operation *delop)
{
    struct mbof_del_ancestors_ctx *anc_ctx;
    struct mbof_del_ctx *del_ctx;
    struct mbof_ctx *ctx;
    struct ldb_context *ldb;
    struct mbof_dn_array *new_list;
    static const char *attrs[] = {"memberof", NULL};
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
            /* more than one entry per dn ?? db corrupted ? */
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
        el = ldb_msg_find_element(anc_ctx->entry, "memberof");
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
        if (anc_ctx->cur == anc_ctx->num_direct) {
            /* ok, end of the story, proceed to modify the entry */
            ret = mbof_del_mod_entry(delop);
        } else {
            /* ok process the next one */
            ret = mbof_del_ancestors(delop);
        }

        if (ret != LDB_SUCCESS) {
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_OPERATIONS_ERROR);
        }
    }

    talloc_free(ares);
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
    const char *val;
    int i, j, ret;

    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);
    new_list = delop->anc_ctx->new_list;

    /* change memberof on entry */
    msg = ldb_msg_new(delop);
    if (!msg) return LDB_ERR_OPERATIONS_ERROR;

    msg->dn = delop->entry_dn;

    if (new_list->num) {
        ret = ldb_msg_add_empty(msg, "memberof", LDB_FLAG_MOD_REPLACE, &el);
        if (ret != LDB_SUCCESS) {
            return ret;
        }

        el->values = talloc_array(msg, struct ldb_val, new_list->num);
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
        }
        el->num_values = j;
    }
    else {
        ret = ldb_msg_add_empty(msg, "memberof", LDB_FLAG_MOD_DELETE, &el);
        if (ret != LDB_SUCCESS) {
            return ret;
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
        ldb_debug(ldb, LDB_DEBUG_TRACE, "Got an entry on a non search op ?!");
        /* shouldn't happen */
        talloc_free(ares);
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
    case LDB_REPLY_REFERRAL:
        /* ignore */
        talloc_free(ares);
        break;

    case LDB_REPLY_DONE:

        ret = mbof_del_progeny(delop);

        if (ret != LDB_SUCCESS) {
            talloc_free(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    return LDB_SUCCESS;
}

static int mbof_del_progeny(struct mbof_del_operation *delop)
{
    struct mbof_ctx *ctx;
    struct mbof_del_ctx *del_ctx;
    struct mbof_del_operation *nextop;
    const struct ldb_message_element *el;
    struct mbof_dn_array *new_list;
    struct ldb_context *ldb;
    struct ldb_dn *valdn;
    int i, ret;

    new_list = delop->anc_ctx->new_list;
    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    /* now verify if this entry is a group and members need to be processed as
     * well */

    el = ldb_msg_find_element(delop->entry, "member");
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

    if (nextop) {
        return mbof_del_execute_op(nextop);
    }

    /* see if there are follow functions to run */
    if (del_ctx->followup_fn) {
        return del_ctx->followup_fn(del_ctx->followup_ctx);
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
    struct mbof_ctx *ctx;
    struct mbof_dn *save, *tmp;

    del_ctx = delop->del_ctx;
    ctx = del_ctx->ctx;

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
        if (top->num_children &&
            top->cur_child < top->num_children) {

            cop = top->children[top->cur_child];
            top->cur_child++;

            /* verify this operation has not already been performed */
            for (tmp = del_ctx->history; tmp; tmp = tmp->next) {
                if (ldb_dn_compare(tmp->dn, cop->entry_dn) == 0) break;
            }
            if (tmp) {
                /* it's a dup */
                continue;
            }

            *nextop = cop;
            return LDB_SUCCESS;
        }
    }

    /* we have no more ops */
    *nextop = NULL;
    return LDB_SUCCESS;
}



/* mod operation */

/* A modify operation just implements either an add operation, or a delete
 * operation or both (replace) in turn.
 * The only difference between a modify and a pure add or a pure delete is that
 * the object is not created a new or not completely removed, but the setup just
 * treats it in the same way children objects are treated in a pure add or delete
 * operation. A list of appropriate parents and objects to modify is built, then
 * we jump directly in the add or delete code.
 * If both add and delete are necessary, delete operations are performed first
 * and then a followup add operation is concatenated */

static int mbof_mod_callback(struct ldb_request *req,
                             struct ldb_reply *ares);
static int mbof_orig_mod(struct mbof_mod_ctx *mod_ctx);
static int mbof_orig_mod_callback(struct ldb_request *req,
                                  struct ldb_reply *ares);
static int mbof_mod_process(struct mbof_mod_ctx *mod_ctx, bool *done);
static int mbof_mod_add(struct mbof_mod_ctx *mod_ctx,
                        struct mbof_dn_array *ael);
static int mbof_mod_followup(void *ctx);
static int mbof_mod_delete(struct mbof_mod_ctx *mod_ctx,
                           struct mbof_dn_array *del);
static int mbof_fill_dn_array(TALLOC_CTX *memctx,
                              struct ldb_context *ldb,
                              const struct ldb_message_element *el,
                              struct mbof_dn_array **dn_array);

static int memberof_mod(struct ldb_module *module, struct ldb_request *req)
{
    const struct ldb_message_element *el;
    struct mbof_mod_ctx *mod_ctx;
    struct mbof_ctx *ctx;
    static const char *attrs[] = {"member", "memberof", NULL};
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    struct ldb_request *search;
    int ret;

    if (ldb_dn_is_special(req->op.mod.message->dn)) {
        /* do not manipulate our control entries */
        return ldb_next_request(module, req);
    }

    /* fail operation if memberof is ever specified */
    el = ldb_msg_find_element(req->op.mod.message, "memberof");
    if (el) {
        ldb_debug(ldb, LDB_DEBUG_TRACE, "the memberof attrinbute is readonly");
        /* FIXME: should we simply filter it instead ? */
        return LDB_ERR_CONSTRAINT_VIOLATION;
    }

    /* continue with normal ops if there are no members */
    el = ldb_msg_find_element(req->op.mod.message, "member");
    if (!el) {
        return ldb_next_request(module, req);
    }

    /* TODO: fail if this is not a group ? */

    ctx = mbof_init(module, req);
    if (!ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }

    /* can't do anything,
     * must check first what's on the entry */
    mod_ctx = talloc_zero(ctx, struct mbof_mod_ctx);
    if (!mod_ctx) {
        talloc_free(ctx);
        return LDB_ERR_OPERATIONS_ERROR;
    }
    mod_ctx->ctx = ctx;
    mod_ctx->membel = el;

    ret = ldb_build_search_req(&search, ldb, mod_ctx,
                               req->op.mod.message->dn, LDB_SCOPE_BASE,
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
                           ldb_dn_get_linearized(mod_ctx->entry->dn));
            /* more than one entry per dn ?? db corrupted ? */
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
                           ldb_dn_get_linearized(req->op.mod.message->dn));
            /* this target does not exists, too bad! */
            return ldb_module_done(ctx->req, NULL, NULL,
                                   LDB_ERR_NO_SUCH_OBJECT);
        }

        ret = mbof_orig_mod(mod_ctx);
        if (ret != LDB_SUCCESS) {
            talloc_free(ares);
            return ldb_module_done(ctx->req, NULL, NULL, ret);
        }
    }

    talloc_free(ares);
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
                            ctx->req->op.mod.message, ctx->req->controls,
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
    bool done = false;
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
		talloc_free(ares);
        ldb_debug(ldb, LDB_DEBUG_TRACE, "Invalid reply type!");
		ldb_set_errstring(ldb, "Invalid reply type!");
        return ldb_module_done(ctx->req, NULL, NULL,
                               LDB_ERR_OPERATIONS_ERROR);
	}

    /* save real call stuff */
    ctx->ret_ctrls = talloc_steal(ctx, ares->controls);
    ctx->ret_resp = talloc_steal(ctx, ares->response);

    /* next step */
    ret = mbof_mod_process(mod_ctx, &done);
    if (ret != LDB_SUCCESS) {
        talloc_free(ares);
        return ldb_module_done(ctx->req, NULL, NULL, ret);
    }
    if (done) {
        talloc_free(ares);
        return ldb_module_done(ctx->req,
                               ctx->ret_ctrls,
                               ctx->ret_resp,
                               LDB_SUCCESS);
    }

    talloc_free(ares);
    return LDB_SUCCESS;
}

static int mbof_mod_process(struct mbof_mod_ctx *mod_ctx, bool *done)
{
    const struct ldb_message_element *el;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    struct mbof_dn_array *removed;
    struct mbof_dn_array *added;
    int i, j, ret;

    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    switch (mod_ctx->membel->flags) {
    case LDB_FLAG_MOD_ADD:

        ret = mbof_fill_dn_array(mod_ctx, ldb, mod_ctx->membel, &added);
        if (ret != LDB_SUCCESS) {
            return ret;
        }

        return mbof_mod_add(mod_ctx, added);

    case LDB_FLAG_MOD_DELETE:

        if (mod_ctx->membel->num_values == 0) {
            el = ldb_msg_find_element(mod_ctx->entry, "member");
        } else {
            el = mod_ctx->membel;
        }

        if (!el) {
            /* nothing to do really */
            *done = true;
            return LDB_SUCCESS;
        }

        ret = mbof_fill_dn_array(mod_ctx, ldb, el, &removed);
        if (ret != LDB_SUCCESS) {
            return ret;
        }

        return mbof_mod_delete(mod_ctx, removed);

    case LDB_FLAG_MOD_REPLACE:

        removed = NULL;
        el = ldb_msg_find_element(mod_ctx->entry, "member");
        if (el) {
            ret = mbof_fill_dn_array(mod_ctx, ldb, el, &removed);
            if (ret != LDB_SUCCESS) {
                return ret;
            }
        }

        added = NULL;
        el = mod_ctx->membel;
        if (el) {
            ret = mbof_fill_dn_array(mod_ctx, ldb, el, &added);
            if (ret != LDB_SUCCESS) {
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
                }
            }
        }

        /* if we need to add something put it away so that it
         * can be done after all delete operations are over */
        if (added && added->num) {
            mod_ctx->to_add = added;
        }

        /* if we have something to remove do it first */
        if (removed && removed->num) {
            return mbof_mod_delete(mod_ctx, removed);
        }

        /* if there is nothing to remove and we have stuff to add
         * do it right away */
        if (mod_ctx->to_add) {
            return mbof_mod_add(mod_ctx, added);
        }

        /* the replacement function resulted in a null op,
         * nothing to do, return happily */
        *done = true;
        return LDB_SUCCESS;
    }

    return LDB_ERR_OPERATIONS_ERROR;
}

static int mbof_mod_followup(void *ctx)
{
    struct mbof_mod_ctx *mod_ctx;

    mod_ctx = talloc_get_type(ctx, struct mbof_mod_ctx);

    return mbof_mod_add(mod_ctx, mod_ctx->to_add);
}

static int mbof_mod_add(struct mbof_mod_ctx *mod_ctx,
                        struct mbof_dn_array *ael)
{
    const struct ldb_message_element *el;
    struct mbof_dn_array *parents;
    struct mbof_add_ctx *add_ctx;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int i, ret;

    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    el = ldb_msg_find_element(mod_ctx->entry, "memberof");

    /* all the parents + itself */
    ret = mbof_fill_dn_array(mod_ctx, ldb, el, &parents);
    if (ret != LDB_SUCCESS) {
        return ret;
    }

    parents->dns = talloc_realloc(parents, parents->dns,
                                  struct ldb_dn *, parents->num + 1);
    if (!parents->dns) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    parents->dns[parents->num] = mod_ctx->entry->dn;
    parents->num++;

    add_ctx = talloc_zero(mod_ctx, struct mbof_add_ctx);
    if (!add_ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    add_ctx->ctx = ctx;

    for (i = 0; i < ael->num; i++) {
        ret = mbof_append_addop(add_ctx, parents, ael->dns[i]);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    return mbof_next_add(add_ctx->add_list);
}

static int mbof_mod_delete(struct mbof_mod_ctx *mod_ctx,
                           struct mbof_dn_array *del)
{
    struct mbof_del_operation *first;
    struct mbof_del_ctx *del_ctx;
    struct ldb_context *ldb;
    struct mbof_ctx *ctx;
    int i, ret;

    ctx = mod_ctx->ctx;
    ldb = ldb_module_get_ctx(ctx->module);

    del_ctx = talloc_zero(mod_ctx, struct mbof_del_ctx);
    if (!del_ctx) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    del_ctx->ctx = ctx;

    /* create first entry */
    /* the first entry is the parent of all entries and the one where we
     * remove member from, it does not get the same treatment as others */
    first = talloc_zero(del_ctx, struct mbof_del_operation);
    if (!first) {
        return LDB_ERR_OPERATIONS_ERROR;
    }
    del_ctx->first = first;

    first->del_ctx = del_ctx;
    first->entry = mod_ctx->entry;
    first->entry_dn = mod_ctx->entry->dn;

    /* prepare del sets */
    for (i = 0; i < del->num; i++) {
        ret = mbof_append_delop(first, del->dns[i]);
        if (ret != LDB_SUCCESS) {
            return ret;
        }
    }

    /* add followup function if we also have stuff to add */
    if (mod_ctx->to_add) {
        del_ctx->followup_ctx = mod_ctx;
        del_ctx->followup_fn = mbof_mod_followup;
    }

    /* now that sets are built, start processing */
    return mbof_del_execute_op(first->children[0]);
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




/* module init code */

static int memberof_init(struct ldb_module *module)
{
    struct ldb_context *ldb = ldb_module_get_ctx(module);
    int ret;

    /* set syntaxes for member and memberof so that comparisons in filters and
     * such are done right */
    ret = ldb_schema_attribute_add(ldb, "member", 0, LDB_SYNTAX_DN);
    ret = ldb_schema_attribute_add(ldb, "memberof", 0, LDB_SYNTAX_DN);

    return ldb_next_init(module);
}

const struct ldb_module_ops ldb_memberof_module_ops = {
    .name = "memberof",
    .init_context = memberof_init,
    .add = memberof_add,
    .modify = memberof_mod,
    .del = memberof_del,
};
