/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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
#include "providers/ldap/sdap_async_enum.h"
#include "db/sysdb.h"
#include "db/sysdb_services.h"

struct sdap_reinit_cleanup_state {
    struct sss_domain_info *domain;
    struct sysdb_ctx *sysdb;
};

static errno_t sdap_reinit_clear_usn(struct sysdb_ctx *sysdb,
                                     struct sss_domain_info *domain);
static void sdap_reinit_cleanup_done(struct tevent_req *subreq);
static errno_t sdap_reinit_delete_records(struct sss_domain_info *domain);

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

    state->sysdb = be_ctx->domain->sysdb;
    state->domain = be_ctx->domain;

    if (!be_ctx->domain->enumerate) {
        /* enumeration is disabled, this whole process is meaningless */
        ret = EOK;
        goto immediately;
    }

    ret = sdap_reinit_clear_usn(state->sysdb, state->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to clear USN attributes [%d]: %s\n",
                                    ret, strerror(ret));
        goto immediately;
    }

    subreq = sdap_dom_enum_send(id_ctx, be_ctx->ev, id_ctx,
                                id_ctx->opts->sdom, id_ctx->conn);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to issue enumeration request\n");
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

static void sdap_delete_msgs_usn(struct sysdb_ctx *sysdb,
                                 struct ldb_message **msgs,
                                 size_t msgs_num)
{
    struct ldb_message_element el = { 0, SYSDB_USN, 0, NULL };
    struct sysdb_attrs usn_el = { 1, &el };
    errno_t ret;
    int i;

    for (i = 0; i < msgs_num; i++) {
        ret = sysdb_set_entry_attr(sysdb, msgs[i]->dn, &usn_el, SYSDB_MOD_DEL);
        if (ret) {
            DEBUG(SSSDBG_TRACE_FUNC, "Failed to clean USN on entry: [%s]\n",
                                      ldb_dn_get_linearized(msgs[i]->dn));
        }
    }
}

static errno_t sdap_reinit_clear_usn(struct sysdb_ctx *sysdb,
                                     struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx = NULL;
    bool in_transaction = false;
    struct ldb_message **msgs = NULL;
    size_t msgs_num = 0;
    const char *attrs[] = { "dn", NULL };
    int sret;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    /* reset users' usn */
    ret = sysdb_search_users(tmp_ctx, domain,
                             "", attrs, &msgs_num, &msgs);
    if (ret != EOK) {
        goto done;
    }
    sdap_delete_msgs_usn(sysdb, msgs, msgs_num);
    talloc_zfree(msgs);
    msgs_num = 0;

    /* reset groups' usn */
    ret = sysdb_search_groups(tmp_ctx, domain, "", attrs, &msgs_num, &msgs);
    if (ret != EOK) {
        goto done;
    }
    sdap_delete_msgs_usn(sysdb, msgs, msgs_num);
    talloc_zfree(msgs);
    msgs_num = 0;

    /* reset services' usn */
    ret = sysdb_search_services(tmp_ctx, domain, "", attrs, &msgs_num, &msgs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot search services [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    sdap_delete_msgs_usn(sysdb, msgs, msgs_num);
    talloc_zfree(msgs);
    msgs_num = 0;

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not commit transaction\n");
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

static void sdap_reinit_cleanup_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_reinit_cleanup_state *state = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_reinit_cleanup_state);

    ret = sdap_dom_enum_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Domain enumeration failed [%d]: %s\n",
                                    ret, strerror(ret));
        goto fail;
    }

    /* Ok, we've completed an enumeration. Save this to the
     * sysdb so we can postpone starting up the enumeration
     * process on the next SSSD service restart (to avoid
     * slowing down system boot-up
     */
    ret = sysdb_set_enumerated(state->domain, SYSDB_HAS_ENUMERATED_ID, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not mark domain as having "
                                     "enumerated.\n");
        /* This error is non-fatal, so continue */
    }

    ret = sdap_reinit_delete_records(state->domain);
    if (ret != EOK) {
        goto fail;
    }

    tevent_req_done(req);
    return;

fail:
    tevent_req_error(req, ret);
}

static void sdap_delete_msgs_dn(struct sysdb_ctx *sysdb,
                                struct ldb_message **msgs,
                                size_t msgs_num)
{
    errno_t ret;
    int i;

    for (i = 0; i < msgs_num; i++) {
        ret = sysdb_delete_entry(sysdb, msgs[i]->dn, true);
        if (ret) {
            DEBUG(SSSDBG_TRACE_FUNC, "Failed to delete entry: [%s]\n",
                                      ldb_dn_get_linearized(msgs[i]->dn));
        }
    }
}

static errno_t sdap_reinit_delete_records(struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx = NULL;
    bool in_transaction = false;
    struct ldb_message **msgs = NULL;
    size_t msgs_num = 0;
    const char *attrs[] = { "dn", NULL };
    int sret;
    errno_t ret;
    struct sysdb_ctx *sysdb = domain->sysdb;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        goto done;
    }
    in_transaction = true;

    /* purge untouched users */
    ret = sysdb_search_users(tmp_ctx, domain, "(!("SYSDB_USN"=*))",
                             attrs, &msgs_num, &msgs);
    if (ret != EOK) {
        goto done;
    }
    sdap_delete_msgs_dn(sysdb, msgs, msgs_num);
    talloc_zfree(msgs);
    msgs_num = 0;

    /* purge untouched groups */
    ret = sysdb_search_groups(tmp_ctx, domain, "(!("SYSDB_USN"=*))",
                              attrs, &msgs_num, &msgs);
    if (ret != EOK) {
        goto done;
    }
    sdap_delete_msgs_dn(sysdb, msgs, msgs_num);
    talloc_zfree(msgs);
    msgs_num = 0;

    /* purge untouched services */
    ret = sysdb_search_services(tmp_ctx, domain, "(!("SYSDB_USN"=*))",
                                attrs, &msgs_num, &msgs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot search services [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    sdap_delete_msgs_dn(sysdb, msgs, msgs_num);
    talloc_zfree(msgs);
    msgs_num = 0;

    ret = sysdb_transaction_commit(sysdb);
    if (ret == EOK) {
        in_transaction = false;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not commit transaction\n");
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
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
