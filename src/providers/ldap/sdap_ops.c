/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include "util/util.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/ldap_common.h"

struct sdap_search_bases_ex_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    const char *filter;
    const char **attrs;
    struct sdap_attr_map *map;
    int map_num_attrs;
    int timeout;
    bool allow_paging;
    bool return_first_reply;
    const char *base_dn;

    size_t base_iter;
    struct sdap_search_base *cur_base;
    struct sdap_search_base **bases;

    size_t reply_count;
    struct sysdb_attrs **reply;
};

static errno_t sdap_search_bases_ex_next_base(struct tevent_req *req);
static void sdap_search_bases_ex_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_search_bases_ex_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct sdap_options *opts,
                          struct sdap_handle *sh,
                          struct sdap_search_base **bases,
                          struct sdap_attr_map *map,
                          bool allow_paging,
                          bool return_first_reply,
                          int timeout,
                          const char *filter,
                          const char **attrs,
                          const char *base_dn)
{
    struct tevent_req *req;
    struct sdap_search_bases_ex_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_search_bases_ex_state);
    if (req == NULL) {
        return NULL;
    }

    if (bases == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No search base specified!\n");
        ret = ERR_INTERNAL;
        goto immediately;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->bases = bases;
    state->map = map;
    state->filter = filter;
    state->attrs = attrs;
    state->allow_paging = allow_paging;
    state->return_first_reply = return_first_reply;
    state->base_dn = base_dn;

    state->timeout = timeout == 0
                     ? dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT)
                     : timeout;

    if (state->map != NULL) {
        for (state->map_num_attrs = 0;
                state->map[state->map_num_attrs].opt_name != NULL;
                state->map_num_attrs++) {
            /* no op */;
        }
    } else {
        state->map_num_attrs = 0;
    }

    if (state->attrs == NULL && state->map != NULL) {
        ret = build_attrs_from_map(state, state->map, state->map_num_attrs,
                                   NULL, &state->attrs, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to build attrs from map "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto immediately;
        }
    }

    state->base_iter = 0;
    ret = sdap_search_bases_ex_next_base(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t sdap_search_bases_ex_next_base(struct tevent_req *req)
{
    struct sdap_search_bases_ex_state *state;
    struct tevent_req *subreq;
    const char *base_dn;
    char *filter;

    state = tevent_req_data(req, struct sdap_search_bases_ex_state);
    state->cur_base = state->bases[state->base_iter];
    if (state->cur_base == NULL) {
        return EOK;
    }

    /* Combine lookup and search base filters. */
    filter = sdap_combine_filters(state, state->filter,
                                  state->cur_base->filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    base_dn = state->base_dn != NULL ? state->base_dn : state->cur_base->basedn;

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing LDAP lookup with base [%s]\n", base_dn);

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   base_dn, state->cur_base->scope, filter,
                                   state->attrs, state->map,
                                   state->map_num_attrs, state->timeout,
                                   state->allow_paging);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_search_bases_ex_done, req);

    state->base_iter++;
    return EAGAIN;
}

static void sdap_search_bases_ex_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_search_bases_ex_state *state;
    struct sysdb_attrs **attrs;
    size_t count;
    size_t i;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_search_bases_ex_state);

    DEBUG(SSSDBG_TRACE_FUNC, "Receiving data from base [%s]\n",
                             state->cur_base->basedn);

    ret = sdap_get_generic_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Add rules to result. */
    if (count > 0) {
        if (state->return_first_reply == false) {
            /* Merge with previous reply. */
            state->reply = talloc_realloc(state, state->reply,
                                          struct sysdb_attrs *,
                                          state->reply_count + count);
            if (state->reply == NULL) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            for (i = 0; i < count; i++) {
                state->reply[state->reply_count + i] = talloc_steal(state->reply,
                                                                    attrs[i]);
            }

            state->reply_count += count;
        } else {
            /* Return the first successful search result. */
            state->reply_count = count;
            state->reply = attrs;
            tevent_req_done(req);
            return;
        }
    }

    /* Try next search base. */
    ret = sdap_search_bases_ex_next_base(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static int sdap_search_bases_ex_recv(struct tevent_req *req,
                                     TALLOC_CTX *mem_ctx,
                                     size_t *reply_count,
                                     struct sysdb_attrs ***reply)
{
    struct sdap_search_bases_ex_state *state =
                tevent_req_data(req, struct sdap_search_bases_ex_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->reply_count;
    *reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}

struct tevent_req *
sdap_search_bases_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sdap_options *opts,
                       struct sdap_handle *sh,
                       struct sdap_search_base **bases,
                       struct sdap_attr_map *map,
                       bool allow_paging,
                       int timeout,
                       const char *filter,
                       const char **attrs,
                       const char *base_dn)
{
    return sdap_search_bases_ex_send(mem_ctx, ev, opts, sh, bases, map,
                                     allow_paging, false, timeout,
                                     filter, attrs, base_dn);
}

int sdap_search_bases_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *_reply_count,
                           struct sysdb_attrs ***_reply)
{
    return sdap_search_bases_ex_recv(req, mem_ctx, _reply_count, _reply);
}

struct tevent_req *
sdap_search_bases_return_first_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sdap_options *opts,
                                    struct sdap_handle *sh,
                                    struct sdap_search_base **bases,
                                    struct sdap_attr_map *map,
                                    bool allow_paging,
                                    int timeout,
                                    const char *filter,
                                    const char **attrs,
                                    const char *base_dn)
{
    return sdap_search_bases_ex_send(mem_ctx, ev, opts, sh, bases, map,
                                     allow_paging, true, timeout,
                                     filter, attrs, base_dn);
}

int sdap_search_bases_return_first_recv(struct tevent_req *req,
                                        TALLOC_CTX *mem_ctx,
                                        size_t *_reply_count,
                                        struct sysdb_attrs ***_reply)
{
    return sdap_search_bases_ex_recv(req, mem_ctx, _reply_count, _reply);
}

struct sdap_deref_bases_ex_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    const char *filter;
    const char **attrs;
    const char *deref_attr;
    struct sdap_attr_map_info *maps;
    size_t num_maps;
    unsigned int flags;
    bool return_first_reply;
    int timeout;

    size_t base_iter;
    struct sdap_search_base *cur_base;
    struct sdap_search_base **bases;

    size_t reply_count;
    struct sdap_deref_attrs **reply;
};

static errno_t sdap_deref_bases_ex_next_base(struct tevent_req *req);
static void sdap_deref_bases_ex_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_deref_bases_ex_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sdap_options *opts,
                         struct sdap_handle *sh,
                         struct sdap_search_base **bases,
                         struct sdap_attr_map_info *maps,
                         const char *filter,
                         const char **attrs,
                         const char *deref_attr,
                         unsigned int flags,
                         bool return_first_reply,
                         int timeout)
{
    struct tevent_req *req;
    struct sdap_deref_bases_ex_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_deref_bases_ex_state);
    if (req == NULL) {
        return NULL;
    }

    if (bases == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No search base specified!\n");
        ret = ERR_INTERNAL;
        goto immediately;
    }

    if (maps == NULL || attrs == NULL || deref_attr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No attributes or map specified!\n");
        ret = ERR_INTERNAL;
        goto immediately;
    }

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->bases = bases;
    state->maps = maps;
    state->filter = filter;
    state->attrs = attrs;
    state->deref_attr = deref_attr;
    state->return_first_reply = return_first_reply;
    state->flags = flags;

    state->timeout = timeout == 0
                     ? dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT)
                     : timeout;

    for (state->num_maps = 0; maps[state->num_maps].map != NULL;
            state->num_maps++) {
            /* no op */;
    }

    state->base_iter = 0;
    ret = sdap_deref_bases_ex_next_base(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t sdap_deref_bases_ex_next_base(struct tevent_req *req)
{
    struct sdap_deref_bases_ex_state *state;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sdap_deref_bases_ex_state);
    state->cur_base = state->bases[state->base_iter];
    if (state->cur_base == NULL) {
        return EOK;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing LDAP deref lookup with base [%s]\n",
                             state->cur_base->basedn);

    subreq = sdap_deref_search_with_filter_send(state, state->ev, state->opts,
                 state->sh, state->cur_base->basedn, state->filter,
                 state->deref_attr, state->attrs, state->num_maps, state->maps,
                 state->timeout, state->flags);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_deref_bases_ex_done, req);

    state->base_iter++;
    return EAGAIN;
}

static void sdap_deref_bases_ex_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_deref_bases_ex_state *state;
    struct sdap_deref_attrs **attrs;
    size_t count;
    size_t i;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_deref_bases_ex_state);

    DEBUG(SSSDBG_TRACE_FUNC, "Receiving data from base [%s]\n",
                             state->cur_base->basedn);

    ret = sdap_deref_search_with_filter_recv(subreq, state, &count, &attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    /* Add rules to result. */
    if (count > 0) {
        if (state->return_first_reply == false) {
            /* Merge with previous reply. */
            state->reply = talloc_realloc(state, state->reply,
                                          struct sdap_deref_attrs *,
                                          state->reply_count + count);
            if (state->reply == NULL) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            for (i = 0; i < count; i++) {
                state->reply[state->reply_count + i] = talloc_steal(state->reply,
                                                                    attrs[i]);
            }

            state->reply_count += count;
        } else {
            /* Return the first successful search result. */
            state->reply_count = count;
            state->reply = attrs;
            tevent_req_done(req);
            return;
        }
    }

    /* Try next search base. */
    ret = sdap_deref_bases_ex_next_base(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static int sdap_deref_bases_ex_recv(struct tevent_req *req,
                                    TALLOC_CTX *mem_ctx,
                                    size_t *reply_count,
                                    struct sdap_deref_attrs ***reply)
{
    struct sdap_deref_bases_ex_state *state =
                tevent_req_data(req, struct sdap_deref_bases_ex_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->reply_count;
    *reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}

struct tevent_req *
sdap_deref_bases_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct sdap_options *opts,
                      struct sdap_handle *sh,
                      struct sdap_search_base **bases,
                      struct sdap_attr_map_info *maps,
                      const char *filter,
                      const char **attrs,
                      const char *deref_attr,
                      unsigned int flags,
                      int timeout)
{
    return sdap_deref_bases_ex_send(mem_ctx, ev, opts, sh, bases, maps,
                                    filter, attrs, deref_attr, flags,
                                    false, timeout);
}

int sdap_deref_bases_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          size_t *_reply_count,
                          struct sdap_deref_attrs ***_reply)
{
    return sdap_deref_bases_ex_recv(req, mem_ctx, _reply_count, _reply);
}

struct tevent_req *
sdap_deref_bases_return_first_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct sdap_options *opts,
                                   struct sdap_handle *sh,
                                   struct sdap_search_base **bases,
                                   struct sdap_attr_map_info *maps,
                                   const char *filter,
                                   const char **attrs,
                                   const char *deref_attr,
                                   unsigned int flags,
                                   int timeout)
{
    return sdap_deref_bases_ex_send(mem_ctx, ev, opts, sh, bases, maps,
                                    filter, attrs, deref_attr, flags,
                                    true, timeout);
}

int sdap_deref_bases_return_first_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *_reply_count,
                                       struct sdap_deref_attrs ***_reply)
{
    return sdap_deref_bases_ex_recv(req, mem_ctx, _reply_count, _reply);
}
