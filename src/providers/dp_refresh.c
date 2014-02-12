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

#include "providers/dp_backend.h"
#include "providers/dp_ptask.h"
#include "providers/dp_refresh.h"
#include "util/util_errors.h"
#include "db/sysdb.h"

static errno_t be_refresh_get_values(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     time_t period,
                                     const char *objectclass,
                                     struct ldb_dn *base_dn,
                                     const char *attr,
                                     char ***_values)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *attrs[] = {attr, NULL};
    const char *filter = NULL;
    char **values = NULL;
    struct ldb_message **msgs = NULL;
    struct sysdb_attrs **records = NULL;
    size_t count;
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

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, base_dn,
                             LDB_SCOPE_SUBTREE, filter, attrs,
                             &count, &msgs);
    if (ret == ENOENT) {
        count = 0;
    } else if (ret != EOK) {
        goto done;
    }

    ret = sysdb_msg2attrs(tmp_ctx, count, msgs, &records);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not convert ldb message to sysdb_attrs\n");
        goto done;
    }

    ret = sysdb_attrs_to_list(tmp_ctx, records, count, attr, &values);
    if (ret != EOK) {
        goto done;
    }

    *_values = talloc_steal(mem_ctx, values);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t be_refresh_get_netgroups(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domain,
                                        time_t period,
                                        char ***_values)
{
    struct ldb_dn *base_dn = NULL;
    errno_t ret;

    base_dn = sysdb_netgroup_base_dn(mem_ctx, domain);
    if (base_dn == NULL) {
        return ENOMEM;
    }

    ret = be_refresh_get_values(mem_ctx, domain, period, SYSDB_NETGROUP_CLASS,
                                base_dn, SYSDB_NAME, _values);

    talloc_free(base_dn);
    return ret;
}

typedef errno_t
(*be_refresh_get_values_t)(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           time_t period,
                           char ***_values);


struct be_refresh_cb {
    bool enabled;
    be_refresh_get_values_t get_values;
    be_refresh_send_t send_fn;
    be_refresh_recv_t recv_fn;
    void *pvt;
};

struct be_refresh_ctx {
    struct be_refresh_cb callbacks[BE_REFRESH_TYPE_SENTINEL];
};

struct be_refresh_ctx *be_refresh_ctx_init(TALLOC_CTX *mem_ctx)
{
    struct be_refresh_ctx *ctx = NULL;

    ctx = talloc_zero(mem_ctx, struct be_refresh_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->callbacks[BE_REFRESH_TYPE_NETGROUPS].get_values \
        = be_refresh_get_netgroups;

    return ctx;
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
    enum be_refresh_type index;
    time_t period;
};

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
    state->period = be_ptask_get_period(be_ptask);
    state->ctx = talloc_get_type(pvt, struct be_refresh_ctx);
    if (state->ctx == NULL) {
        ret = EINVAL;
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
    struct tevent_req *subreq = NULL;
    char **values = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct be_refresh_state);

    state->cb = &state->ctx->callbacks[state->index];
    while (state->index != BE_REFRESH_TYPE_SENTINEL && !state->cb->enabled) {
        state->index++;
        state->cb = &state->ctx->callbacks[state->index];
    }

    if (state->index == BE_REFRESH_TYPE_SENTINEL) {
        ret = EOK;
        goto done;
    }

    if (state->cb->get_values == NULL || state->cb->send_fn == NULL
        || state->cb->recv_fn == NULL) {
        ret = EINVAL;
        goto done;
    }

    ret = state->cb->get_values(state, state->be_ctx->domain, state->period,
                                &values);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to obtain DN list [%d]: %s\n",
                                    ret, sss_strerror(ret));
        goto done;
    }

    subreq = state->cb->send_fn(state, state->ev, state->be_ctx,
                             values, state->cb->pvt);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* make the list disappear with subreq */
    talloc_steal(subreq, values);

    tevent_req_set_callback(subreq, be_refresh_done, req);

    state->index++;
    ret = EAGAIN;

done:
    return ret;
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

    ret = be_refresh_step(req);
    if (ret == EAGAIN) {
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
