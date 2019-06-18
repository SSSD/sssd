/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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
#include <time.h>
#include <ldb.h>

#include "providers/backend.h"
#include "providers/be_ptask.h"
#include "providers/be_refresh.h"
#include "util/util_errors.h"
#include "db/sysdb.h"

static errno_t be_refresh_get_values_ex(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domain,
                                        time_t period,
                                        struct ldb_dn *base_dn,
                                        const char *attr,
                                        char ***_values)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *attrs[] = {attr, NULL};
    const char *filter = NULL;
    char **values = NULL;
    struct sysdb_attrs **records = NULL;
    struct ldb_result *res;
    time_t now = time(NULL);
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(%s<=%lld))",
                             SYSDB_CACHE_EXPIRE, (long long) now + period);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_with_ts_attr(tmp_ctx, domain, base_dn,
                                    LDB_SCOPE_SUBTREE,
                                    SYSDB_SEARCH_WITH_TS_ONLY_TS_FILTER,
                                    filter, attrs,
                                    &res);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_msg2attrs(tmp_ctx, res->count, res->msgs, &records);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not convert ldb message to sysdb_attrs\n");
        goto done;
    }

    ret = sysdb_attrs_to_list(tmp_ctx, records, res->count, attr, &values);
    if (ret != EOK) {
        goto done;
    }

    *_values = talloc_steal(mem_ctx, values);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t be_refresh_get_values(TALLOC_CTX *mem_ctx,
                                     enum be_refresh_type type,
                                     const char *attr_name,
                                     struct sss_domain_info *domain,
                                     time_t period,
                                     char ***_values)
{
    struct ldb_dn *base_dn = NULL;
    errno_t ret;

    switch (type) {
    case BE_REFRESH_TYPE_USERS:
        base_dn = sysdb_user_base_dn(mem_ctx, domain);
        break;
    case BE_REFRESH_TYPE_GROUPS:
        base_dn = sysdb_group_base_dn(mem_ctx, domain);
        break;
    case BE_REFRESH_TYPE_NETGROUPS:
        base_dn = sysdb_netgroup_base_dn(mem_ctx, domain);
        break;
    case BE_REFRESH_TYPE_SENTINEL:
        return ERR_INTERNAL;
        break;
    }

    if (base_dn == NULL) {
        return ENOMEM;
    }

    ret = be_refresh_get_values_ex(mem_ctx, domain, period,
                                   base_dn, attr_name, _values);

    talloc_free(base_dn);
    return ret;
}

struct be_refresh_cb {
    const char *name;
    bool enabled;
    be_refresh_send_t send_fn;
    be_refresh_recv_t recv_fn;
    void *pvt;
};

struct be_refresh_ctx {
    const char *attr_name;
    struct be_refresh_cb callbacks[BE_REFRESH_TYPE_SENTINEL];
};

errno_t be_refresh_ctx_init(struct be_ctx *be_ctx,
                            const char *attr_name)
{
    struct be_refresh_ctx *ctx = NULL;
    uint32_t refresh_interval;
    errno_t ret;

    ctx = talloc_zero(be_ctx, struct be_refresh_ctx);
    if (ctx == NULL) {
        return ENOMEM;
    }

    ctx->attr_name = attr_name;
    ctx->callbacks[BE_REFRESH_TYPE_USERS].name = "users";
    ctx->callbacks[BE_REFRESH_TYPE_GROUPS].name = "groups";
    ctx->callbacks[BE_REFRESH_TYPE_NETGROUPS].name = "netgroups";

    refresh_interval = be_ctx->domain->refresh_expired_interval;
    if (refresh_interval > 0) {
        ret = be_ptask_create(be_ctx, be_ctx, refresh_interval, 30, 5, 0,
                              refresh_interval, BE_PTASK_OFFLINE_SKIP,
                              BE_PTASK_SCHEDULE_FROM_LAST,
                              0,
                              be_refresh_send, be_refresh_recv,
                              ctx, "Refresh Records", NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unable to initialize refresh periodic task [%d]: %s\n",
                  ret, sss_strerror(ret));
            talloc_free(ctx);
            return ret;
        }
    }

    be_ctx->refresh_ctx = ctx;
    return EOK;
}

errno_t be_refresh_add_cb(struct be_refresh_ctx *ctx,
                          enum be_refresh_type type,
                          be_refresh_send_t send_fn,
                          be_refresh_recv_t recv_fn,
                          void *pvt)
{
    if (ctx == NULL || send_fn == NULL || recv_fn == NULL
            || type >= BE_REFRESH_TYPE_SENTINEL) {
        return EINVAL;
    }

    if (ctx->callbacks[type].enabled) {
        return EEXIST;
    }

    ctx->callbacks[type].enabled = true;
    ctx->callbacks[type].send_fn = send_fn;
    ctx->callbacks[type].recv_fn = recv_fn;
    ctx->callbacks[type].pvt = pvt;

    return EOK;
}

struct be_refresh_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct be_refresh_ctx *ctx;
    struct be_refresh_cb *cb;

    struct sss_domain_info *domain;
    enum be_refresh_type index;
    time_t period;

    char **refresh_values;
    size_t refresh_val_size;
    size_t refresh_index;

    size_t batch_size;
    char **refresh_batch;
};

static errno_t be_refresh_batch_step(struct tevent_req *req,
                                     uint32_t msec_delay);
static void be_refresh_batch_step_wakeup(struct tevent_context *ev,
                                         struct tevent_timer *tt,
                                         struct timeval tv,
                                         void *pvt);
static errno_t be_refresh_step(struct tevent_req *req);
static void be_refresh_done(struct tevent_req *subreq);

struct tevent_req *be_refresh_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *be_ctx,
                                   struct be_ptask *be_ptask,
                                   void *pvt)
{
    struct be_refresh_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct be_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->domain = be_ctx->domain;
    state->period = be_ptask_get_period(be_ptask);
    state->ctx = talloc_get_type(pvt, struct be_refresh_ctx);
    if (state->ctx == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    state->batch_size = 200;
    state->refresh_batch = talloc_zero_array(state, char *, state->batch_size+1);
    if (state->refresh_batch == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = be_refresh_step(req);
    if (ret == EOK) {
        goto immediately;
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_refresh_step() failed [%d]: %s\n",
                                    ret, sss_strerror(ret));
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t be_refresh_step(struct tevent_req *req)
{
    struct be_refresh_state *state = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct be_refresh_state);

    while (state->domain != NULL) {
        /* find first enabled callback */
        state->cb = &state->ctx->callbacks[state->index];
        while (state->index != BE_REFRESH_TYPE_SENTINEL && !state->cb->enabled) {
            state->index++;
            state->cb = &state->ctx->callbacks[state->index];
        }

        /* if not found than continue with next domain */
        if (state->index == BE_REFRESH_TYPE_SENTINEL) {
            state->domain = get_next_domain(state->domain,
                                            SSS_GND_DESCEND);
            state->index = 0;
            continue;
        }

        if (state->cb->send_fn == NULL || state->cb->recv_fn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid parameters!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        talloc_zfree(state->refresh_values);
        ret = be_refresh_get_values(state, state->index, state->ctx->attr_name,
                                    state->domain, state->period,
                                    &state->refresh_values);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to obtain DN list [%d]: %s\n",
                                        ret, sss_strerror(ret));
            goto done;
        }

        for (state->refresh_val_size = 0;
             state->refresh_values[state->refresh_val_size] != NULL;
             state->refresh_val_size++);

        DEBUG(SSSDBG_TRACE_FUNC, "Refreshing %zu %s in domain %s\n",
              state->refresh_val_size, state->cb->name, state->domain->name);

        ret = be_refresh_batch_step(req, 0);
        if (ret == EOK) {
            state->index++;
            continue;
        } else if (ret != EAGAIN) {
            goto done;
        }
        /* EAGAIN only, refreshing something.. */

        state->index++;
        goto done;
    }

    ret = EOK;

done:
    return ret;
}

static errno_t be_refresh_batch_step(struct tevent_req *req,
                                     uint32_t msec_delay)
{
    struct be_refresh_state *state = tevent_req_data(req, struct be_refresh_state);
    struct timeval tv;
    struct tevent_timer *timeout = NULL;

    size_t remaining;
    size_t batch_size;

    memset(state->refresh_batch, 0, sizeof(char *) * state->batch_size);

    if (state->refresh_index >= state->refresh_val_size) {
        DEBUG(SSSDBG_FUNC_DATA, "The batch is done\n");
        state->refresh_index = 0;
        return EOK;
    }

    remaining = state->refresh_val_size - state->refresh_index;
    batch_size = MIN(remaining, state->batch_size);
    DEBUG(SSSDBG_FUNC_DATA,
          "This batch will refresh %zu entries (so far %zu/%zu)\n",
          batch_size, state->refresh_index, state->refresh_val_size);

    for (size_t i = 0; i < batch_size; i++) {
        state->refresh_batch[i] = state->refresh_values[state->refresh_index];
        state->refresh_index++;
    }

    tv = tevent_timeval_current_ofs(0, msec_delay * 1000);
    timeout = tevent_add_timer(state->be_ctx->ev, req, tv,
                               be_refresh_batch_step_wakeup, req);
    if (timeout == NULL) {
        return ENOMEM;
    }

    return EAGAIN;
}

static void be_refresh_batch_step_wakeup(struct tevent_context *ev,
                                         struct tevent_timer *tt,
                                         struct timeval tv,
                                         void *pvt)
{
    struct tevent_req *req;
    struct tevent_req *subreq = NULL;
    struct be_refresh_state *state = NULL;

    req = talloc_get_type(pvt, struct tevent_req);
    state = tevent_req_data(req, struct be_refresh_state);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Issuing refresh\n");
    subreq = state->cb->send_fn(state, state->ev, state->be_ctx,
                                state->domain,
                                state->refresh_batch,
                                state->cb->pvt);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, be_refresh_done, req);
}

static void be_refresh_done(struct tevent_req *subreq)
{
    struct be_refresh_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct be_refresh_state);

    ret = state->cb->recv_fn(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = be_refresh_batch_step(req, 500);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Another batch in this step in progress\n");
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "be_refresh_batch_step failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "All batches in this step refreshed\n");

    /* Proceed to the next step */
    ret = be_refresh_step(req);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Another step in progress\n");
        return;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t be_refresh_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct dp_id_data *be_refresh_acct_req(TALLOC_CTX *mem_ctx,
                                       uint32_t entry_type,
                                       uint32_t filter_type,
                                       struct sss_domain_info *domain)
{
    struct dp_id_data *account_req;

    account_req = talloc_zero(mem_ctx, struct dp_id_data);
    if (account_req == NULL) {
        return NULL;
    }

    account_req->entry_type = entry_type;
    account_req->filter_type = filter_type;
    account_req->extra_value = NULL;
    account_req->domain = domain->name;
    return account_req;
}
