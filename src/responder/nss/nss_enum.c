/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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
#include "util/sss_ptr_hash.h"
#include "responder/nss/nss_private.h"

typedef errno_t (*sss_nss_setent_set_timeout_fn)(struct tevent_context *ev,
                                                 struct sss_nss_ctx *nss_ctx,
                                                 struct sss_nss_enum_ctx *enum_ctx);

struct sss_nss_setent_internal_state {
    struct tevent_context *ev;
    struct sss_nss_ctx *nss_ctx;
    struct sss_nss_enum_ctx *enum_ctx;
    sss_nss_setent_set_timeout_fn timeout_handler;
    enum cache_req_type type;
};

static void sss_nss_setent_internal_done(struct tevent_req *subreq);

/* Cache request data is stealed on internal state. */
static struct tevent_req *
sss_nss_setent_internal_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct cli_ctx *cli_ctx,
                         struct cache_req_data *data,
                         enum cache_req_type type,
                         struct sss_nss_enum_ctx *enum_ctx,
                         sss_nss_setent_set_timeout_fn timeout_handler)
{
    struct sss_nss_setent_internal_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sss_nss_setent_internal_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    talloc_steal(state, data);

    state->ev = ev;
    state->nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct sss_nss_ctx);
    state->enum_ctx = enum_ctx;
    state->type = type;
    state->timeout_handler = timeout_handler;

    if (state->enum_ctx->is_ready) {
        /* Object is already constructed, just return here. */
        talloc_free(data);
        ret = EOK;
        goto done;
    }

    if (state->enum_ctx->ongoing != NULL) {
        /* Object is being constructed. Register ourselves for
         * notification when it is finished. */
        ret = setent_add_ref(state, &state->enum_ctx->notify_list, req);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to register setent reference [%d]: %s!\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        ret = EAGAIN;
        goto done;
    }

    /* Create new object. */
    state->enum_ctx->is_ready = false;
    subreq = cache_req_send(req, ev, cli_ctx->rctx, cli_ctx->rctx->ncache,
                            state->nss_ctx->cache_refresh_percent,
                            CACHE_REQ_POSIX_DOM, NULL, data);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send cache request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_nss_setent_internal_done, req);
    state->enum_ctx->ongoing = subreq;

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sss_nss_setent_internal_done(struct tevent_req *subreq)
{
    struct cache_req_result **result;
    struct sss_nss_setent_internal_state *state;
    struct setent_req_list **notify_list;
    struct tevent_req *req;
    errno_t ret;
    errno_t tret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_nss_setent_internal_state);

    /* This is the ongoing request and it is finished. Remove it. */
    state->enum_ctx->ongoing = NULL;

    ret = cache_req_recv(state, subreq, &result);
    talloc_zfree(subreq);

    switch (ret) {
    case EOK:
        talloc_zfree(state->enum_ctx->result);
        state->enum_ctx->result = talloc_steal(state->enum_ctx, result);

        if (state->type == CACHE_REQ_NETGROUP_BY_NAME) {
            /* We need to expand the netgroup into triples and members. */
            ret = sysdb_netgr_to_entries(state->enum_ctx,
                                         result[0]->ldb_result,
                                         &state->enum_ctx->netgroup,
                                         &state->enum_ctx->netgroup_count);
            if (ret != EOK) {
                goto done;
            }
        }
        break;
    case ENOENT:
        /* Reset the result but build it again next time setent is called. */
        talloc_zfree(state->enum_ctx->result);
        talloc_zfree(state->enum_ctx->netgroup);
        goto done;
    default:
        /* In case of an error, we do not touch the enumeration context. */
        goto done;
    }

    /* Expire the result object after its timeout is reached. */
    tret = state->timeout_handler(state->ev, state->nss_ctx, state->enum_ctx);
    if (tret != EOK) {
        ret = ENOMEM;
        goto done;
    }

    /* The object is ready now. */
    state->enum_ctx->is_ready = true;

    ret = EOK;

done:
    /* We want to finish the requests in correct order, this was the
     * first request, notify_list contain the subsequent request.
     *
     * Because callback invoked from tevent_req_done will free state,
     * we must remember notify_list explicitly to avoid segfault.
     */
    notify_list = &state->enum_ctx->notify_list;

    if (ret == EOK) {
        tevent_req_done(req);
        setent_notify_done(notify_list);
    } else {
        tevent_req_error(req, ret);
        setent_notify(notify_list, ret);
    }
}

static errno_t
sss_nss_setent_internal_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void
sss_nss_setent_timeout(struct tevent_context *ev,
                       struct tevent_timer *te,
                       struct timeval current_time,
                       void *pvt)
{
    struct sss_nss_enum_ctx *enum_ctx = pvt;

    DEBUG(SSSDBG_TRACE_FUNC, "Enumeration result object has expired.\n");

    /* Reset enumeration context. */
    talloc_zfree(enum_ctx->result);
    enum_ctx->is_ready = false;
}

static errno_t
sss_nss_setent_set_timeout(struct tevent_context *ev,
                           struct sss_nss_ctx *nss_ctx,
                           struct sss_nss_enum_ctx *enum_ctx)
{
    struct tevent_timer *te;
    struct timeval tv;

    tv = tevent_timeval_current_ofs(nss_ctx->enum_cache_timeout, 0);
    te = tevent_add_timer(ev, nss_ctx, tv, sss_nss_setent_timeout, enum_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not set up life timer for enumeration object.\n");
        return ENOMEM;
    }

    return EOK;
}

struct tevent_req *
sss_nss_setent_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct cli_ctx *cli_ctx,
                    enum cache_req_type type,
                    struct sss_nss_enum_ctx *enum_ctx)
{
    struct cache_req_data *data;

    data = cache_req_data_enum(mem_ctx, type);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set cache request data!\n");
        return NULL;
    }

    return sss_nss_setent_internal_send(mem_ctx, ev, cli_ctx, data, type, enum_ctx,
                                        sss_nss_setent_set_timeout);
}

errno_t sss_nss_setent_recv(struct tevent_req *req)
{
    return sss_nss_setent_internal_recv(req);
}

static void
sss_nss_setnetgrent_timeout(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval current_time,
                            void *pvt)
{
    struct sss_nss_enum_ctx *enum_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Enumeration result object has expired.\n");

    /* Free enumeration context. This will also remove it from the table. */
    enum_ctx = talloc_get_type(pvt, struct sss_nss_enum_ctx);
    talloc_free(enum_ctx);
}

static errno_t
sss_nss_setnetgrent_set_timeout(struct tevent_context *ev,
                            struct sss_nss_ctx *nss_ctx,
                            struct sss_nss_enum_ctx *enum_ctx)
{
    struct tevent_timer *te;
    struct timeval tv;
    uint32_t timeout;

    if (nss_ctx->cache_refresh_percent) {
        timeout = enum_ctx->result[0]->domain->netgroup_timeout *
            (nss_ctx->cache_refresh_percent / 100.0);
    } else {
        timeout = enum_ctx->result[0]->domain->netgroup_timeout;
    }

    /* In order to not trash the cache between setnetgrent()/getnetgrent()
     * calls with too low timeout values, we only allow 10 seconds as
     * the minimal timeout
     */
    if (timeout < 10) timeout = 10;

    tv = tevent_timeval_current_ofs(timeout, 0);
    te = tevent_add_timer(ev, enum_ctx, tv, sss_nss_setnetgrent_timeout, enum_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not set up life timer for enumeration object.\n");
        return ENOMEM;
    }

    return EOK;
}

static struct sss_nss_enum_ctx *
sss_nss_setnetgrent_set_enum_ctx(hash_table_t *table,
                                 const char *netgroup)
{
    struct sss_nss_enum_ctx *enum_ctx;
    errno_t ret;

    enum_ctx = sss_ptr_hash_lookup(table, netgroup, struct sss_nss_enum_ctx);
    if (enum_ctx != NULL) {
        return enum_ctx;
    }

    enum_ctx = talloc_zero(table, struct sss_nss_enum_ctx);
    if (enum_ctx == NULL) {
        return NULL;
    }

    ret = sss_ptr_hash_add(table, netgroup, enum_ctx, struct sss_nss_enum_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to add enumeration context into table [%d]: %s\n",
              ret, sss_strerror(ret));
        talloc_free(enum_ctx);
        return NULL;
    }

    return enum_ctx;
}

struct tevent_req *
sss_nss_setnetgrent_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct cli_ctx *cli_ctx,
                         enum cache_req_type type,
                         hash_table_t *table,
                         const char *netgroup)
{
    struct sss_nss_enum_ctx *enum_ctx;
    struct cache_req_data *data;

    enum_ctx = sss_nss_setnetgrent_set_enum_ctx(table, netgroup);
    if (enum_ctx == NULL) {
        return NULL;
    }

    data = cache_req_data_name(mem_ctx, type, netgroup);
    if (data == NULL) {
        return NULL;
    }

    return sss_nss_setent_internal_send(mem_ctx, ev, cli_ctx, data, type, enum_ctx,
                                        sss_nss_setnetgrent_set_timeout);
}
