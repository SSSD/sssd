/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: the responder commands

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

#include "db/sysdb.h"

#include "responder/ifp/ifp_private.h"

struct ifp_attr_req {
    const char *name;
    const char **attrs;
    int nattrs;

    struct ifp_req *ireq;
};

static struct tevent_req *
ifp_user_get_attr_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                       struct sss_nc_ctx *ncache, int neg_timeout,
                       enum sss_dp_acct_type search_type,
                       const char *inp, const char **attrs);
static errno_t ifp_user_get_attr_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct ldb_result **_res);

static void ifp_user_get_attr_process(struct tevent_req *req);

static errno_t
ifp_user_get_attr_handle_reply(struct ifp_req *ireq,
                               const char **attrs, struct ldb_result *res);
static errno_t
ifp_user_get_attr_unpack_msg(struct ifp_attr_req *attr_req);

int ifp_user_get_attr(struct sbus_request *dbus_req, void *data)
{
    errno_t ret;
    struct ifp_req *ireq;
    struct ifp_ctx *ifp_ctx;
    struct ifp_attr_req *attr_req;
    struct tevent_req *req;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
    }

    ret = ifp_req_create(dbus_req, ifp_ctx, &ireq);
    if (ret != EOK) {
        return ifp_req_create_handle_failure(dbus_req, ret);
    }

    attr_req = talloc_zero(ireq, struct ifp_attr_req);
    if (attr_req == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    attr_req->ireq = ireq;

    ret = ifp_user_get_attr_unpack_msg(attr_req);
    if (ret != EOK) {
        return ret;     /* handled internally */
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Looking up attributes of user [%s] on behalf of %"PRIi64"\n",
          attr_req->name, ireq->dbus_req->client);

    req = ifp_user_get_attr_send(ireq, ifp_ctx->rctx,
                                 ifp_ctx->ncache, ifp_ctx->neg_timeout,
                                 SSS_DP_USER,
                                 attr_req->name, attr_req->attrs);
    if (req == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    tevent_req_set_callback(req, ifp_user_get_attr_process, attr_req);
    return EOK;
}

static errno_t
ifp_user_get_attr_unpack_msg(struct ifp_attr_req *attr_req)
{
    bool parsed;
    char **attrs;
    int nattrs;
    int i, ai;
    const char **whitelist = attr_req->ireq->ifp_ctx->user_whitelist;

    parsed = sbus_request_parse_or_finish(attr_req->ireq->dbus_req,
                                          DBUS_TYPE_STRING, &attr_req->name,
                                          DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
                                          &attrs, &nattrs,
                                          DBUS_TYPE_INVALID);
    if (parsed == false) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not parse arguments\n");
        return EOK; /* handled */
    }

    /* Copy the attributes to maintain memory hierarchy with talloc */
    attr_req->attrs = talloc_zero_array(attr_req, const char *, nattrs+1);
    if (attr_req->attrs == NULL) {
        return ENOMEM;
    }

    ai = 0;
    for (i = 0; i < nattrs; i++) {
        if (ifp_attr_allowed(whitelist, attrs[i]) == false) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Attribute %s not present in the whitelist, skipping\n",
                  attrs[i]);
            continue;
        }

        attr_req->attrs[ai] = talloc_strdup(attr_req->attrs, attrs[i]);
        if (attr_req->attrs[ai] == NULL) {
            return ENOMEM;
        }
        ai++;
    }

    return EOK;
}

static void ifp_user_get_attr_process(struct tevent_req *req)
{
    struct ifp_attr_req *attr_req;
    errno_t ret;
    struct ldb_result *res = NULL;

    attr_req = tevent_req_callback_data(req, struct ifp_attr_req);

    ret = ifp_user_get_attr_recv(attr_req, req, &res);
    talloc_zfree(req);
    if (ret == ENOENT) {
        sbus_request_fail_and_finish(attr_req->ireq->dbus_req,
                               sbus_error_new(attr_req->ireq->dbus_req,
                                              DBUS_ERROR_FAILED,
                                              "No such user\n"));
        return;
    } else if (ret != EOK) {
        sbus_request_fail_and_finish(attr_req->ireq->dbus_req,
                               sbus_error_new(attr_req->ireq->dbus_req,
                                              DBUS_ERROR_FAILED,
                                              "Failed to read user attribute\n"));
        return;
    }

    ret = ifp_user_get_attr_handle_reply(attr_req->ireq,
                                         attr_req->attrs, res);
    if (ret != EOK) {
        sbus_request_fail_and_finish(attr_req->ireq->dbus_req,
                               sbus_error_new(attr_req->ireq->dbus_req,
                                              DBUS_ERROR_FAILED,
                                              "Failed to build a reply\n"));
        return;
    }
}

static errno_t
ifp_user_get_attr_handle_reply(struct ifp_req *ireq,
                               const char **attrs, struct ldb_result *res)
{
    errno_t ret;
    dbus_bool_t dbret;
    DBusMessage *reply;
    DBusMessageIter iter;
    DBusMessageIter iter_dict;
    struct ldb_message_element *el;
    int ai;

    /* Construct a reply */
    reply = dbus_message_new_method_return(ireq->dbus_req->message);
    if (!reply) {
        return sbus_request_finish(ireq->dbus_req, NULL);
    }

    dbus_message_iter_init_append(reply, &iter);

    dbret = dbus_message_iter_open_container(
                                      &iter, DBUS_TYPE_ARRAY,
                                      DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                      DBUS_TYPE_STRING_AS_STRING
                                      DBUS_TYPE_VARIANT_AS_STRING
                                      DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                      &iter_dict);
    if (!dbret) {
        return sbus_request_finish(ireq->dbus_req, NULL);
    }

    if (res->count > 0) {
        for (ai = 0; attrs[ai]; ai++) {
            el = ldb_msg_find_element(res->msgs[0], attrs[ai]);
            if (el == NULL || el->num_values == 0) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Attribute %s not present or has no values\n",
                      attrs[ai]);
                continue;
            }

            ret = ifp_add_ldb_el_to_dict(&iter_dict, el);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Cannot add attribute %s to message\n",
                      attrs[ai]);
                continue;
            }
        }
    }

    dbret = dbus_message_iter_close_container(&iter, &iter_dict);
    if (!dbret) {
        return sbus_request_finish(ireq->dbus_req, NULL);
    }

    return sbus_request_finish(ireq->dbus_req, reply);
}

static void ifp_user_get_groups_process(struct tevent_req *req);
static errno_t ifp_user_get_groups_reply(struct ifp_req *ireq,
                                         struct ldb_result *res);

int ifp_user_get_groups(struct sbus_request *dbus_req,
                         void *data, const char *arg_user)
{
    struct ifp_req *ireq;
    struct ifp_ctx *ifp_ctx;
    struct ifp_attr_req *group_req;
    struct tevent_req *req;
    errno_t ret;

    ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
    }

    ret = ifp_req_create(dbus_req, ifp_ctx, &ireq);
    if (ret != EOK) {
        return ifp_req_create_handle_failure(dbus_req, ret);
    }

    group_req = talloc_zero(ireq, struct ifp_attr_req);
    if (group_req == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    group_req->ireq = ireq;
    group_req->name = arg_user;

    group_req->attrs = talloc_zero_array(group_req, const char *, 2);
    if (group_req->attrs == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }

    group_req->attrs[0] = talloc_strdup(group_req->attrs, SYSDB_MEMBEROF);
    if (group_req->attrs[0] == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Looking up groups of user [%s] on behalf of %"PRIi64"\n",
          group_req->name, group_req->ireq->dbus_req->client);

    req = ifp_user_get_attr_send(ireq, ifp_ctx->rctx,
                                 ifp_ctx->ncache, ifp_ctx->neg_timeout,
                                 SSS_DP_INITGROUPS,
                                 group_req->name, group_req->attrs);
    if (req == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    tevent_req_set_callback(req, ifp_user_get_groups_process, group_req);
    return EOK;
}

static void ifp_user_get_groups_process(struct tevent_req *req)
{
    struct ifp_attr_req *group_req;
    errno_t ret;
    struct ldb_result *res;

    group_req = tevent_req_callback_data(req, struct ifp_attr_req);

    ret = ifp_user_get_attr_recv(group_req, req, &res);
    talloc_zfree(req);
    if (ret == ENOENT) {
        sbus_request_fail_and_finish(group_req->ireq->dbus_req,
                               sbus_error_new(group_req->ireq->dbus_req,
                                              DBUS_ERROR_FAILED,
                                              "No such user\n"));
        return;
    } else if (ret != EOK) {
        sbus_request_fail_and_finish(group_req->ireq->dbus_req,
                               sbus_error_new(group_req->ireq->dbus_req,
                                              DBUS_ERROR_FAILED,
                                              "Failed to read attribute\n"));
        return;
    }

    ret = ifp_user_get_groups_reply(group_req->ireq, res);
    if (ret != EOK) {
        sbus_request_fail_and_finish(group_req->ireq->dbus_req,
                               sbus_error_new(group_req->ireq->dbus_req,
                                              DBUS_ERROR_FAILED,
                                              "Failed to build a reply\n"));
        return;
    }
}

static errno_t
ifp_user_get_groups_reply(struct ifp_req *ireq, struct ldb_result *res)
{
    int i, num;
    const char *name;
    const char **groupnames;

    /* one less, the first one is the user entry */
    num = res->count - 1;
    groupnames = talloc_zero_array(ireq, const char *, num);
    if (groupnames == NULL) {
        return sbus_request_finish(ireq->dbus_req, NULL);
    }

    for (i = 0; i < num; i++) {
        name = ldb_msg_find_attr_as_string(res->msgs[i + 1], SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Skipping a group with no name\n");
            continue;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Adding group %s\n", name);
        groupnames[i] = name;
    }

    return infopipe_iface_GetUserGroups_finish(ireq->dbus_req,
                                               groupnames, num);
}

struct ifp_user_get_attr_state {
    const char *inp;
    const char **attrs;
    struct ldb_result *res;

    enum sss_dp_acct_type search_type;

    char *name;
    char *domname;

    struct sss_domain_info *dom;
    bool check_next;
    bool check_provider;

    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
    int neg_timeout;
};

static void ifp_user_get_attr_dom(struct tevent_req *subreq);
static errno_t ifp_user_get_attr_search(struct tevent_req *req);
int ifp_cache_check(struct ifp_user_get_attr_state *state,
                    enum sss_dp_acct_type search_type,
                    sss_dp_callback_t callback,
                    unsigned int cache_refresh_percent,
                    void *pvt);
void ifp_user_get_attr_done(struct tevent_req *req);

static struct tevent_req *
ifp_user_get_attr_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                       struct sss_nc_ctx *ncache, int neg_timeout,
                       enum sss_dp_acct_type search_type,
                       const char *inp, const char **attrs)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ifp_user_get_attr_state *state;

    req = tevent_req_create(mem_ctx, &state, struct ifp_user_get_attr_state);
    if (req == NULL) {
         return NULL;
    }
    state->inp = inp;
    state->attrs = attrs;
    state->rctx = rctx;
    state->ncache = ncache;
    state->neg_timeout = neg_timeout;
    state->search_type = search_type;

    subreq = sss_parse_inp_send(req, rctx, inp);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ifp_user_get_attr_dom, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    return req;
}

static void
ifp_user_get_attr_dom(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ifp_user_get_attr_state *state = tevent_req_data(req,
                                            struct ifp_user_get_attr_state);

    ret = sss_parse_inp_recv(subreq, state, &state->name, &state->domname);
    talloc_free(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->domname) {
        /* this is a search in one domain */
        state->dom = responder_get_domain(state->rctx, state->domname);
        if (state->dom == NULL) {
            tevent_req_error(req, EINVAL);
            return;
        }
        state->check_next = false;
    } else {
        /* this is a multidomain search */
        state->dom = state->rctx->domains;
        state->check_next = true;
    }

    state->check_provider = NEED_CHECK_PROVIDER(state->dom->provider);

    /* All set up, do the search! */
    ret = ifp_user_get_attr_search(req);
    if (ret == EOK) {
        /* The data was cached. Just quit */
        tevent_req_done(req);
        return;
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }

    /* Execution will resume in ifp_dp_callback */
}

static void ifp_dp_callback(uint16_t err_maj, uint32_t err_min,
                            const char *err_msg, void *ptr);

static errno_t ifp_user_get_attr_search(struct tevent_req *req)
{
    struct ifp_user_get_attr_state *state = tevent_req_data(req,
                                            struct ifp_user_get_attr_state);
    struct sss_domain_info *dom = state->dom;
    char *name = NULL;
    errno_t ret;

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
        * qualified names instead */
        while (dom && state->check_next && dom->fqnames) {
            dom = get_next_domain(dom, false);
        }

        if (!dom) break;

        if (dom != state->dom) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            state->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the cache_req if we changed domain */
        state->dom = dom;

        talloc_free(name);
        name = sss_get_cased_name(state, state->name, dom->case_sensitive);
        if (!name) return ENOMEM;

        /* verify this user has not yet been negatively cached,
         * or has been permanently filtered */
        ret = sss_ncache_check_user(state->ncache,
                                    state->neg_timeout,
                                    dom, name);
        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "User [%s] does not exist in [%s]! (negative cache)\n",
                   name, dom->name);
            /* if a multidomain search, try with next */
            if (state->check_next) {
                dom = get_next_domain(dom, false);
                continue;
            }

            /* There are no further domains or this was a
             * fully-qualified user request.
             */
            return ENOENT;
        }

        DEBUG(SSSDBG_FUNC_DATA,
              "Requesting info for [%s@%s]\n", name, dom->name);

        switch (state->search_type) {
            case SSS_DP_USER:
                ret = sysdb_get_user_attr(state, dom, name,
                                          state->attrs, &state->res);
                break;
            case SSS_DP_INITGROUPS:
                ret = sysdb_initgroups(state, dom, name,
                                       &state->res);
                break;
            default:
                DEBUG(SSSDBG_OP_FAILURE, "Unsupported operation\n");
                return EIO;
        }

        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to make request to our cache!\n");
            return EIO;
        }

        if (state->search_type == SSS_DP_USER) {
            if (state->res->count > 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                        "getpwnam call returned more than one result !?!\n");
                return ENOENT;
            }
        }

        if (state->res->count == 0 && state->check_provider == false) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_user(state->ncache, false, dom, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set negcache for %s@%s\n",
                      name, dom->name);
                /* Not fatal */
            }

            /* if a multidomain search, try with next */
            if (state->check_next) {
                dom = get_next_domain(dom, false);
                if (dom) continue;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "No results for getpwnam call\n");
            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (state->check_provider) {
            ret = ifp_cache_check(state, state->search_type,
                                  ifp_dp_callback, 0, req);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        /* One result found */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Returning info for user [%s@%s]\n", name, dom->name);
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          "No matching domain found for [%s], fail!\n", state->inp);
    return ENOENT;
}

int ifp_cache_check(struct ifp_user_get_attr_state *state,
                    enum sss_dp_acct_type search_type,
                    sss_dp_callback_t callback,
                    unsigned int cache_refresh_percent,
                    void *pvt)
{
    uint64_t cache_expire = 0;
    int ret;
    struct tevent_req *req;
    struct dp_callback_ctx *cb_ctx = NULL;

    if (search_type == SSS_DP_USER && state->res->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "cache search call returned more than one result! "
              "DB Corrupted?\n");
        return ENOENT;
    }

    if (state->res->count > 0) {
        if (search_type == SSS_DP_USER) {
            cache_expire = ldb_msg_find_attr_as_uint64(state->res->msgs[0],
                                                       SYSDB_CACHE_EXPIRE, 0);
        } else {
            cache_expire = ldb_msg_find_attr_as_uint64(state->res->msgs[0],
                                                       SYSDB_INITGR_EXPIRE, 0);
        }

        /* if we have any reply let's check cache validity */
        ret = sss_cmd_check_cache(state->res->msgs[0], cache_refresh_percent,
                                cache_expire);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, "Cached entry is valid, returning..\n");
            return EOK;
        } else if (ret != EAGAIN && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Error checking cache: %d\n", ret);
            return ret;
        }
    } else {
        /* No replies */
        ret = ENOENT;
    }

    /* EAGAIN (off band) or ENOENT (cache miss) -> check cache */
    if (ret == EAGAIN) {
        /* No callback required
         * This was an out-of-band update. We'll return EOK
         * so the calling function can return the cached entry
         * immediately.
         */
        DEBUG(SSSDBG_TRACE_FUNC, "Performing midpoint cache update\n");

        req = sss_dp_get_account_send(state, state->rctx, state->dom, true,
                                      search_type, state->inp, 0,
                                      NULL);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending out-of-band data provider "
                  "request\n");
            /* This is non-fatal, so we'll continue here */
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Updating cache out-of-band\n");
        }

        /* We don't need to listen for a reply, so we will free the
         * request here.
         */
        talloc_zfree(req);
    } else {
        /* This is a cache miss. Or the cache is expired.
         * We need to get the updated user information before returning it.
         */

        /* dont loop forever; mark the provider as checked */
        state->check_provider = false;

        req = sss_dp_get_account_send(state, state->rctx, state->dom, true,
                                      search_type, state->inp, 0, NULL);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
            return ENOMEM;
        }

        cb_ctx = talloc_zero(state, struct dp_callback_ctx);
        if (cb_ctx == NULL) {
            talloc_zfree(req);
            return ENOMEM;
        }
        cb_ctx->callback = callback;
        cb_ctx->ptr = pvt;
        cb_ctx->cctx = NULL;   /* There is no client in ifp */
        cb_ctx->mem_ctx = state;

        tevent_req_set_callback(req, ifp_user_get_attr_done, cb_ctx);
        return EAGAIN;
    }

    return EOK;
}

void ifp_user_get_attr_done(struct tevent_req *req)
{
    struct dp_callback_ctx *cb_ctx =
        tevent_req_callback_data(req, struct dp_callback_ctx);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_account_recv(cb_ctx->mem_ctx, req,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not get account info: %d\n", ret);
        /* report error with callback */
    }

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}

static void ifp_dp_callback(uint16_t err_maj, uint32_t err_min,
                            const char *err_msg, void *ptr)
{
    errno_t ret;
    struct tevent_req *req = talloc_get_type(ptr, struct tevent_req);

    if (err_maj) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Unable to get information from Data Provider\n"
              "Error: %u, %u, %s\n"
              "Will try to return what we have in cache\n",
              (unsigned int)err_maj, (unsigned int)err_min, err_msg);
    }

    /* Backend was updated successfully. Check again */
    ret = ifp_user_get_attr_search(req);
    if (ret == EAGAIN) {
        /* Another search in progress */
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
ifp_user_get_attr_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ldb_result **_res)
{
    struct ifp_user_get_attr_state *state = tevent_req_data(req,
                                            struct ifp_user_get_attr_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->res == NULL) {
        /* Did the request end with success but with no data? */
        return ENOENT;
    }

    if (_res) {
        *_res = talloc_steal(mem_ctx, state->res);
    }
    return EOK;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version ssh_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return ssh_cli_protocol_version;
}

/* This is a throwaway method to ease the review of the patch.
 * It will be removed later */
int ifp_ping(struct sbus_request *dbus_req, void *data)
{
    struct ifp_ctx *ifp_ctx = talloc_get_type(data, struct ifp_ctx);
    static const char *pong = "PONG";
    const char *request;
    DBusError dberr;
    errno_t ret;
    struct ifp_req *ifp_req;

    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
    }

    ret = ifp_req_create(dbus_req, ifp_ctx, &ifp_req);
    if (ret != EOK) {
        return ifp_req_create_handle_failure(dbus_req, ret);
    }

    if (!sbus_request_parse_or_finish(dbus_req,
                                      DBUS_TYPE_STRING, &request,
                                      DBUS_TYPE_INVALID)) {
        return EOK; /* handled */
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Got request for [%s]\n", request);

    if (strcasecmp(request, "ping") != 0) {
        dbus_error_init(&dberr);
        dbus_set_error_const(&dberr,
                             DBUS_ERROR_INVALID_ARGS,
                             "Ping() only accepts ping as a param\n");
        return sbus_request_fail_and_finish(dbus_req, &dberr);
    }

    return sbus_request_return_and_finish(dbus_req,
                                          DBUS_TYPE_STRING, &pong,
                                          DBUS_TYPE_INVALID);
}
