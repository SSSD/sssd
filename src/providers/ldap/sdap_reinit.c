/*
    Authors:
        Pavel B??ezina <pbrezina@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <talloc.h>
#include <tevent.h>
#include <string.h>
#include <ldb.h>

#include "util/util.h"
#include "providers/ldap/ldap_common.h"
#include "db/sysdb.h"
#include "db/sysdb_services.h"
#include "db/sysdb_private.h"

struct sdap_reinit_cleanup_state {
    struct sysdb_ctx *sysdb;
};

static errno_t sdap_reinit_clear_usn(struct sysdb_ctx *sysdb);
static void sdap_reinit_cleanup_done(struct tevent_req *subreq);
static errno_t sdap_reinit_delete_records(struct sysdb_ctx *sysdb);

struct tevent_req* sdap_reinit_cleanup_send(TALLOC_CTX *mem_ctx,
                                            struct be_ctx *be_ctx,
                                            struct sdap_id_ctx *id_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_reinit_cleanup_state *state;
    int ret;

    /*
     * 1. remove entryUSN attribute from all entries
     * 2. run enumeration
     * 3. remove records that doesn't have entryUSN attribute updated
     *
     * We don't need to do this for sudo rules, they will be refreshed
     * automatically during next smart/full refresh, or when an expired rule
     * is deleted.
     */

    req = tevent_req_create(mem_ctx, &state, struct sdap_reinit_cleanup_state);
    if (req == NULL) {
        return NULL;
    }

    if (!be_ctx->domain->enumerate) {
        /* enumeration is disabled, this whole process is meaningless */
        ret = EOK;
        goto immediately;
    }

    ret = sdap_reinit_clear_usn(be_ctx->domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to clear USN attributes [%d]: %s\n",
                                    ret, strerror(ret)));
        goto immediately;
    }

    req = ldap_id_enumerate_send(be_ctx->ev, id_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to issue enumeration request\n"));
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_reinit_cleanup_done, req);

    return req;

immediately:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, be_ctx->ev);

    return req;
}

static errno_t sdap_reinit_clear_usn(struct sysdb_ctx *sysdb)
{
    TALLOC_CTX *tmp_ctx = NULL;
    bool in_transaction = false;
    struct ldb_result *result = NULL;
    struct ldb_message **messages = NULL;
    struct ldb_message *msg = NULL;
    int messages_num = 0;
    struct ldb_dn *base_dn = NULL;
    const char *base[] = { SYSDB_TMPL_USER_BASE,
                           SYSDB_TMPL_GROUP_BASE,
                           SYSDB_TMPL_SVC_BASE,
                           NULL };
    const char *attrs[] = { "dn", NULL };
    int i, j;
    int sret;
    int lret;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    for (i = 0; base[i] != NULL; i++) {
        lret = ldb_search(sysdb->ldb, tmp_ctx, &result, base_dn,
                          LDB_SCOPE_SUBTREE, attrs, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        if (result->count == 0) {
            talloc_zfree(result);
            continue;
        }

        messages = talloc_realloc(tmp_ctx, messages, struct ldb_message*,
                                  messages_num + result->count);

        for (j = 0; j < result->count; j++) {
            msg = ldb_msg_new(messages);
            if (msg == NULL) {
                ret = ENOMEM;
                goto done;
            }
            msg->dn = talloc_move(tmp_ctx, &result->msgs[j]->dn);

            lret = ldb_msg_add_empty(msg, SYSDB_USN, LDB_FLAG_MOD_DELETE, NULL);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }

            messages[messages_num + j] = msg;
        }

        messages_num += result->count;
        talloc_zfree(result);
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < messages_num; i++) {
        lret = ldb_modify(sysdb->ldb, messages[i]);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Could not commit transaction\n"));
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

static void sdap_reinit_cleanup_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_reinit_cleanup_state *state = NULL;
    enum tevent_req_state tstate;
    uint64_t err;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_reinit_cleanup_state);

    if (tevent_req_is_error(subreq, &tstate, &err)) {
        ret = err;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Domain enumeration failed [%d]: %s\n",
                                    err, strerror(err)));
        goto fail;
    }

    /* Ok, we've completed an enumeration. Save this to the
     * sysdb so we can postpone starting up the enumeration
     * process on the next SSSD service restart (to avoid
     * slowing down system boot-up
     */
    ret = sysdb_set_enumerated(state->sysdb, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Could not mark domain as having "
                                     "enumerated.\n"));
        /* This error is non-fatal, so continue */
    }

    ret = sdap_reinit_delete_records(state->sysdb);
    if (ret != EOK) {
        goto fail;
    }

    tevent_req_done(req);
    return;

fail:
    tevent_req_error(req, ret);
}

static errno_t sdap_reinit_delete_records(struct sysdb_ctx *sysdb)
{
    TALLOC_CTX *tmp_ctx = NULL;
    bool in_transaction = false;
    struct ldb_result *result = NULL;
    struct ldb_dn *base_dn = NULL;
    const char *base[] = { SYSDB_TMPL_USER_BASE,
                           SYSDB_TMPL_GROUP_BASE,
                           SYSDB_TMPL_SVC_BASE,
                           NULL };
    const char *attrs[] = { "dn", NULL };
    int i, j;
    int sret;
    int lret;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    for (i = 0; base[i] != NULL; i++) {
        lret = ldb_search(sysdb->ldb, tmp_ctx, &result, base_dn,
                          LDB_SCOPE_SUBTREE, attrs, "(!("SYSDB_USN"=*))");
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        for (j = 0; j < result->count; j++) {
            ret = ldb_delete(sysdb->ldb, result->msgs[i]->dn);
            if (ret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(ret);
                goto done;
            }
        }

        talloc_zfree(result);
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Could not commit transaction\n"));
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

errno_t sdap_reinit_cleanup_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
