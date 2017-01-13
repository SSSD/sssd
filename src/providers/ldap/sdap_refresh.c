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

#include <talloc.h>
#include <tevent.h>

#include "providers/ldap/sdap.h"
#include "providers/ldap/ldap_common.h"

struct sdap_refresh_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct dp_id_data *account_req;
    struct sdap_id_ctx *id_ctx;
    struct sdap_domain *sdom;
    const char *type;
    char **names;
    size_t index;
};

static errno_t sdap_refresh_step(struct tevent_req *req);
static void sdap_refresh_done(struct tevent_req *subreq);

static struct tevent_req *sdap_refresh_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct be_ctx *be_ctx,
                                            struct sss_domain_info *domain,
                                            int entry_type,
                                            char **names,
                                            void *pvt)
{
    struct sdap_refresh_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (names == NULL) {
        ret = EOK;
        goto immediately;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->id_ctx = talloc_get_type(pvt, struct sdap_id_ctx);
    state->names = names;
    state->index = 0;

    state->sdom = sdap_domain_get(state->id_ctx->opts, domain);
    if (state->sdom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto immediately;
    }

    switch (entry_type) {
    case BE_REQ_USER:
        state->type = "user";
        break;
    case BE_REQ_GROUP:
        state->type = "group";
        break;
    case BE_REQ_NETGROUP:
        state->type = "netgroup";
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid entry type [%d]!\n", entry_type);
    }

    state->account_req = talloc_zero(state, struct dp_id_data);
    if (state->account_req == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->account_req->entry_type = entry_type;
    state->account_req->filter_type = BE_FILTER_NAME;
    state->account_req->extra_value = NULL;
    state->account_req->domain = domain->name;
    /* filter will be filled later */

    ret = sdap_refresh_step(req);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Nothing to refresh\n");
        goto immediately;
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_refresh_step() failed "
                                   "[%d]: %s\n", ret, sss_strerror(ret));
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

static errno_t sdap_refresh_step(struct tevent_req *req)
{
    struct sdap_refresh_state *state = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct sdap_refresh_state);

    if (state->names == NULL) {
        ret = EOK;
        goto done;
    }

    state->account_req->filter_value = state->names[state->index];
    if (state->account_req->filter_value == NULL) {
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing refresh of %s %s\n",
          state->type, state->account_req->filter_value);

    subreq = sdap_handle_acct_req_send(state, state->be_ctx,
                                       state->account_req, state->id_ctx,
                                       state->sdom, state->id_ctx->conn, true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_refresh_done, req);

    state->index++;
    ret = EAGAIN;

done:
    return ret;
}

static void sdap_refresh_done(struct tevent_req *subreq)
{
    struct sdap_refresh_state *state = NULL;
    struct tevent_req *req = NULL;
    const char *err_msg = NULL;
    errno_t dp_error;
    int sdap_ret;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_refresh_state);

    ret = sdap_handle_acct_req_recv(subreq, &dp_error, &err_msg, &sdap_ret);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to refresh %s [dp_error: %d, "
              "sdap_ret: %d, errno: %d]: %s\n", state->type,
              dp_error, sdap_ret, ret, err_msg);
        goto done;
    }

    ret = sdap_refresh_step(req);
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

static errno_t sdap_refresh_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static struct tevent_req *
sdap_refresh_users_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct be_ctx *be_ctx,
                        struct sss_domain_info *domain,
                        char **names,
                        void *pvt)
{
    return sdap_refresh_send(mem_ctx, ev, be_ctx, domain,
                             BE_REQ_USER, names, pvt);
}

static errno_t sdap_refresh_users_recv(struct tevent_req *req)
{
    return sdap_refresh_recv(req);
}

static struct tevent_req *
sdap_refresh_groups_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct be_ctx *be_ctx,
                         struct sss_domain_info *domain,
                         char **names,
                         void *pvt)
{
    return sdap_refresh_send(mem_ctx, ev, be_ctx, domain,
                             BE_REQ_GROUP, names, pvt);
}

static errno_t sdap_refresh_groups_recv(struct tevent_req *req)
{
    return sdap_refresh_recv(req);
}

static struct tevent_req *
sdap_refresh_netgroups_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct be_ctx *be_ctx,
                            struct sss_domain_info *domain,
                            char **names,
                            void *pvt)
{
    return sdap_refresh_send(mem_ctx, ev, be_ctx, domain,
                             BE_REQ_NETGROUP, names, pvt);
}

static errno_t sdap_refresh_netgroups_recv(struct tevent_req *req)
{
    return sdap_refresh_recv(req);
}

errno_t sdap_refresh_init(struct be_refresh_ctx *refresh_ctx,
                          struct sdap_id_ctx *id_ctx)
{
    errno_t ret;

    ret = be_refresh_add_cb(refresh_ctx, BE_REFRESH_TYPE_USERS,
                            sdap_refresh_users_send,
                            sdap_refresh_users_recv,
                            id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh of users "
              "will not work [%d]: %s\n", ret, strerror(ret));
    }

    ret = be_refresh_add_cb(refresh_ctx, BE_REFRESH_TYPE_GROUPS,
                            sdap_refresh_groups_send,
                            sdap_refresh_groups_recv,
                            id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh of groups "
              "will not work [%d]: %s\n", ret, strerror(ret));
    }

    ret = be_refresh_add_cb(refresh_ctx, BE_REFRESH_TYPE_NETGROUPS,
                            sdap_refresh_netgroups_send,
                            sdap_refresh_netgroups_recv,
                            id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh of netgroups "
              "will not work [%d]: %s\n", ret, strerror(ret));
    }

    return ret;
}
