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
#include "responder/common/cache_req/cache_req.h"

struct ifp_attr_req {
    const char *name;
    const char **attrs;
    int nattrs;

    struct ifp_req *ireq;
};

static struct tevent_req *
ifp_user_get_attr_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                       struct sss_nc_ctx *ncache,
                       enum sss_dp_acct_type search_type,
                       const char *inp, const char **attrs);
static errno_t ifp_user_get_attr_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct ldb_result **_res,
                                      struct sss_domain_info **_domain);

static void ifp_user_get_attr_process(struct tevent_req *req);

static errno_t
ifp_user_get_attr_handle_reply(struct sss_domain_info *domain,
                               struct ifp_req *ireq,
                               const char **attrs,
                               struct ldb_result *res);
static errno_t
ifp_user_get_attr_unpack_msg(struct ifp_attr_req *attr_req);

int ifp_user_get_attr(struct sbus_request *dbus_req, void *data)
{
    errno_t ret;
    struct ifp_req *ireq;
    struct ifp_ctx *ifp_ctx;
    struct ifp_attr_req *attr_req;
    struct tevent_req *req;

    DEBUG(SSSDBG_IMPORTANT_INFO, "GetUserAttr is deprecated, please consider "
          "switching to org.freedesktop.sssd.infopipe.Users.User interface\n");

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
        return ret;     /* internal error */
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Looking up attributes of user [%s] on behalf of %"PRIi64"\n",
          attr_req->name, ireq->dbus_req->client);

    req = ifp_user_get_attr_send(ireq, ifp_ctx->rctx,
                                 ifp_ctx->rctx->ncache, SSS_DP_USER,
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
        return ERR_SBUS_REQUEST_HANDLED;
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
    struct sss_domain_info *dom = NULL;

    attr_req = tevent_req_callback_data(req, struct ifp_attr_req);

    ret = ifp_user_get_attr_recv(attr_req, req, &res, &dom);
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

    ret = ifp_user_get_attr_handle_reply(dom, attr_req->ireq,
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
ifp_user_get_attr_handle_reply(struct sss_domain_info *domain,
                               struct ifp_req *ireq,
                               const char **attrs,
                               struct ldb_result *res)
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
        ret = ifp_ldb_el_output_name(ireq->ifp_ctx->rctx, res->msgs[0],
                                     SYSDB_NAME, domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert SYSDB_NAME to output format [%d]: %s\n",
                  ret, sss_strerror(ret));
            return sbus_request_finish(ireq->dbus_req, NULL);
        }

        ret = ifp_ldb_el_output_name(ireq->ifp_ctx->rctx, res->msgs[0],
                                     SYSDB_NAME_ALIAS, domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert SYSDB_NAME_ALIAS to output format [%d]: %s\n",
                  ret, sss_strerror(ret));
            return sbus_request_finish(ireq->dbus_req, NULL);
        }

        for (ai = 0; attrs[ai]; ai++) {
            if (strcmp(attrs[ai], "domainname") == 0) {
                ret = ifp_add_value_to_dict(&iter_dict, "domainname",
                                            domain->name);
                if (ret != EOK) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "Cannot add attribute domainname to message\n");
                    continue;
                }
            }

            el = sss_view_ldb_msg_find_element(domain, res->msgs[0], attrs[ai]);
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

struct ifp_user_get_groups_state {
    struct resp_ctx *rctx;

    struct ifp_attr_req *group_attr_req;

    struct ldb_result *res;
    struct ldb_result *res_names;
    struct sss_domain_info *dom;
};

static void ifp_user_get_groups_process(struct tevent_req *req);
static void ifp_user_get_groups_names_resolved(struct tevent_req *req);
static errno_t ifp_user_get_groups_reply(struct sss_domain_info *domain,
                                         struct ifp_req *ireq,
                                         struct ldb_result *res);

int ifp_user_get_groups(struct sbus_request *dbus_req,
                         void *data, const char *arg_user)
{
    struct ifp_req *ireq;
    struct ifp_ctx *ifp_ctx;
    struct ifp_user_get_groups_state *state;
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

    state = talloc_zero(ireq, struct ifp_user_get_groups_state);
    if (state == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    state->rctx = ifp_ctx->rctx;

    state->group_attr_req = talloc_zero(state, struct ifp_attr_req);
    if (state->group_attr_req == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    state->group_attr_req->ireq = ireq;
    state->group_attr_req->name = arg_user;

    state->group_attr_req->attrs = talloc_zero_array(state->group_attr_req,
                                                     const char *, 2);
    if (state->group_attr_req->attrs == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }

    state->group_attr_req->attrs[0] = talloc_strdup(state->group_attr_req->attrs,
                                                    SYSDB_MEMBEROF);
    if (state->group_attr_req->attrs[0] == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Looking up groups of user [%s] on behalf of %"PRIi64"\n",
          state->group_attr_req->name,
          state->group_attr_req->ireq->dbus_req->client);

    req = ifp_user_get_attr_send(ireq, ifp_ctx->rctx,
                                 ifp_ctx->rctx->ncache, SSS_DP_INITGROUPS,
                                 state->group_attr_req->name,
                                 state->group_attr_req->attrs);
    if (req == NULL) {
        return sbus_request_finish(dbus_req, NULL);
    }
    tevent_req_set_callback(req,
                            ifp_user_get_groups_process,
                            state);
    return EOK;
}

static void ifp_user_get_groups_process(struct tevent_req *req)
{
    struct ifp_user_get_groups_state *state;
    struct ifp_attr_req *group_attr_req;
    errno_t ret;

    state = tevent_req_callback_data(req, struct ifp_user_get_groups_state);
    group_attr_req = state->group_attr_req;

    ret = ifp_user_get_attr_recv(group_attr_req, req, &state->res, &state->dom);
    talloc_zfree(req);
    if (ret == ENOENT) {
        sbus_request_fail_and_finish(group_attr_req->ireq->dbus_req,
                               sbus_error_new(group_attr_req->ireq->dbus_req,
                                              DBUS_ERROR_FAILED,
                                              "No such user\n"));
        return;
    } else if (ret != EOK) {
        sbus_request_fail_and_finish(group_attr_req->ireq->dbus_req,
                               sbus_error_new(group_attr_req->ireq->dbus_req,
                                              DBUS_ERROR_FAILED,
                                              "Failed to read attribute\n"));
        return;
    }

    req = resp_resolve_group_names_send(state,
                                        state->rctx->ev,
                                        state->rctx,
                                        state->dom,
                                        state->res);
    if (req == NULL) {
        sbus_request_finish(group_attr_req->ireq->dbus_req, NULL);
        return;
    }
    tevent_req_set_callback(req,
                            ifp_user_get_groups_names_resolved,
                            state);
}

static void ifp_user_get_groups_names_resolved(struct tevent_req *req)
{
    struct ifp_user_get_groups_state *state;
    struct ifp_attr_req *group_attr_req;
    errno_t ret;

    state = tevent_req_callback_data(req, struct ifp_user_get_groups_state);
    group_attr_req = state->group_attr_req;

    ret = resp_resolve_group_names_recv(state, req, &state->res_names);
    talloc_zfree(req);
    if (ret != EOK) {
        sbus_request_fail_and_finish(group_attr_req->ireq->dbus_req,
                            sbus_error_new(group_attr_req->ireq->dbus_req,
                                           DBUS_ERROR_FAILED,
                                           "Failed to resolve groupnames\n"));
        return;
    }

    if (state->res_names == NULL) {
        state->res_names = state->res;
    }

    ret = ifp_user_get_groups_reply(state->dom,
                                    group_attr_req->ireq,
                                    state->res_names);
    if (ret != EOK) {
        sbus_request_fail_and_finish(group_attr_req->ireq->dbus_req,
                                     sbus_error_new(
                                            group_attr_req->ireq->dbus_req,
                                            DBUS_ERROR_FAILED,
                                            "Failed to build a reply\n"));
        return;
    }
}

static errno_t
ifp_user_get_groups_reply(struct sss_domain_info *domain,
                          struct ifp_req *ireq,
                          struct ldb_result *res)
{
    int i, gri, num;
    const char *name;
    const char **groupnames;
    struct sized_string *group_name;
    errno_t ret;

    /* one less, the first one is the user entry */
    num = res->count - 1;
    groupnames = talloc_zero_array(ireq, const char *, num);
    if (groupnames == NULL) {
        return sbus_request_finish(ireq->dbus_req, NULL);
    }

    gri = 0;
    for (i = 0; i < num; i++) {
        name = sss_view_ldb_msg_find_attr_as_string(domain,
                                                    res->msgs[i + 1],
                                                    SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Skipping a group with no name\n");
            continue;
        }

        ret = sized_domain_name(ireq, ireq->ifp_ctx->rctx, name, &group_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unable to get sized name for %s [%d]: %s\n",
                  name, ret, sss_strerror(ret));
            continue;
        }

        groupnames[gri] = talloc_strndup(groupnames,
                                         group_name->str, group_name->len);
        if (groupnames[gri] == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "talloc_strndup failed\n");
            continue;
        }
        gri++;

        DEBUG(SSSDBG_TRACE_FUNC, "Adding group %s\n", groupnames[i]);
    }

    return iface_ifp_GetUserGroups_finish(ireq->dbus_req, groupnames, num);
}

struct ifp_user_get_attr_state {
    const char *inp;
    const char **attrs;
    struct ldb_result *res;

    enum sss_dp_acct_type search_type;

    char *inp_name;
    char *domname;

    struct sss_domain_info *dom;

    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
};

static void ifp_user_get_attr_lookup(struct tevent_req *subreq);
static void ifp_user_get_attr_done(struct tevent_req *subreq);

static struct tevent_req *
ifp_user_get_attr_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                       struct sss_nc_ctx *ncache,
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
    state->search_type = search_type;

    subreq = sss_parse_inp_send(req, rctx, rctx->default_domain, inp);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ifp_user_get_attr_lookup, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    return req;
}

static void
ifp_user_get_attr_lookup(struct tevent_req *subreq)
{
    struct ifp_user_get_attr_state *state = NULL;
    struct tevent_req *req = NULL;
    struct cache_req_data *data;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_user_get_attr_state);

    ret = sss_parse_inp_recv(subreq, state,
                             &state->inp_name, &state->domname);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    switch (state->search_type) {
    case SSS_DP_USER:
        data = cache_req_data_name(state, CACHE_REQ_USER_BY_NAME,
                                   state->inp_name);
        break;
    case SSS_DP_INITGROUPS:
        data = cache_req_data_name(state, CACHE_REQ_INITGROUPS,
                                   state->inp_name);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported search type [%d]!\n",
              state->search_type);
        tevent_req_error(req, ERR_INTERNAL);
        return;
    }

    if (data == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* IFP serves both POSIX and application domains. Requests that need
     * to differentiate between the two must be qualified
     */
    subreq = cache_req_send(state, state->rctx->ev, state->rctx,
                            state->ncache, 0,
                            CACHE_REQ_ANY_DOM,
                            state->domname, data);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ifp_user_get_attr_done, req);
}

static void ifp_user_get_attr_done(struct tevent_req *subreq)
{
    struct ifp_user_get_attr_state *state = NULL;
    struct tevent_req *req = NULL;
    struct cache_req_result *result;
    errno_t ret;
    char *fqdn;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_user_get_attr_state);

    ret = cache_req_single_domain_recv(state, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->res = talloc_steal(state, result->ldb_result);
    state->dom = result->domain;
    talloc_zfree(result);

    fqdn = sss_create_internal_fqname(state, state->inp_name,
                                      state->dom->name);
    if (fqdn == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    if (state->search_type == SSS_DP_USER) {
        /* throw away the result and perform attr search */
        talloc_zfree(state->res);

        ret = sysdb_get_user_attr_with_views(state, state->dom, fqdn,
                                             state->attrs, &state->res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_get_user_attr_with_views() "
                  "failed [%d]: %s\n", ret, sss_strerror(ret));
            tevent_req_error(req, ret);
            return;
        } else if (state->res->count == 0) {
            tevent_req_error(req, ENOENT);
            return;
        } else if (state->res->count != 1) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_get_user_attr_with_views() "
                  "returned more than one result!\n");
            tevent_req_error(req, ENOENT);
            return;
        }
    }

    tevent_req_done(req);
}

static errno_t
ifp_user_get_attr_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ldb_result **_res,
                       struct sss_domain_info **_domain)
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

    if (_domain) {
        *_domain = state->dom;
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
