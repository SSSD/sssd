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
#include "responder/ifp/ifp_iface/ifp_iface_async.h"

struct ifp_user_get_attr_state {
    const char **attrs;
    struct ldb_result *res;

    enum sss_dp_acct_type search_type;

    struct sss_domain_info *dom;

    struct resp_ctx *rctx;
    struct sss_nc_ctx *ncache;
};

static void ifp_user_get_attr_done(struct tevent_req *subreq);

static struct tevent_req *
ifp_user_get_attr_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                       struct sss_nc_ctx *ncache,
                       enum sss_dp_acct_type search_type,
                       const char *input, const char **attrs)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ifp_user_get_attr_state *state;
    struct cache_req_data *data;

    req = tevent_req_create(mem_ctx, &state, struct ifp_user_get_attr_state);
    if (req == NULL) {
         return NULL;
    }
    state->attrs = attrs;
    state->rctx = rctx;
    state->ncache = ncache;
    state->search_type = search_type;

    switch (state->search_type) {
    case SSS_DP_USER:
        data = cache_req_data_name(state, CACHE_REQ_USER_BY_NAME, input);
        break;
    case SSS_DP_INITGROUPS:
        data = cache_req_data_name(state, CACHE_REQ_INITGROUPS, input);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported search type [%d]!\n",
              state->search_type);
        ret = ERR_INTERNAL;
        goto done;
    }

    if (data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* IFP serves both POSIX and application domains. Requests that need
     * to differentiate between the two must be qualified
     */
    subreq = cache_req_send(state, state->rctx->ev, state->rctx, state->ncache,
                            0, CACHE_REQ_ANY_DOM, NULL, data);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_user_get_attr_done, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, rctx->ev);
    }
    return req;
}

static void ifp_user_get_attr_done(struct tevent_req *subreq)
{
    struct ifp_user_get_attr_state *state = NULL;
    struct tevent_req *req = NULL;
    struct cache_req_result *result;
    errno_t ret;
    const char *fqdn;

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

    fqdn = ldb_msg_find_attr_as_string(state->res->msgs[0], SYSDB_NAME, NULL);
    if (fqdn == NULL) {
        tevent_req_error(req, ERR_INTERNAL);
        return;
    }

    if (state->search_type == SSS_DP_USER) {
        /* throw away the result but keep the fqdn and perform attr search */
        fqdn = talloc_steal(state, fqdn);
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

static errno_t
ifp_get_user_attr_write_reply(DBusMessageIter *iter,
                              const char **attrs,
                              struct resp_ctx *rctx,
                              struct sss_domain_info *domain,
                              struct ldb_result *res)
{
    struct ldb_message_element *el;
    DBusMessageIter iter_dict;
    dbus_bool_t dbret;
    errno_t ret;
    int ai;

    dbret = dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
                                      DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                      DBUS_TYPE_STRING_AS_STRING
                                      DBUS_TYPE_VARIANT_AS_STRING
                                      DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                      &iter_dict);
    if (!dbret) {
        return EIO;
    }

    if (res->count > 0) {
        ret = ifp_ldb_el_output_name(rctx, res->msgs[0], SYSDB_NAME, domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert SYSDB_NAME to output format [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        ret = ifp_ldb_el_output_name(rctx, res->msgs[0], SYSDB_NAME_ALIAS, domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert SYSDB_NAME_ALIAS to output format [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        for (ai = 0; attrs != NULL && attrs[ai] != NULL; ai++) {
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

    dbret = dbus_message_iter_close_container(iter, &iter_dict);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        dbus_message_iter_abandon_container(iter, &iter_dict);
    }

    return ret;
}

struct ifp_get_user_attr_state {
    const char *name;
    const char **attrs;
    struct resp_ctx *rctx;

    DBusMessageIter *write_iter;
};

static void ifp_get_user_attr_done(struct tevent_req *subreq);

struct tevent_req *
ifp_get_user_attr_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sbus_request *sbus_req,
                       struct ifp_ctx *ctx,
                       const char *name,
                       const char **attrs,
                       DBusMessageIter *write_iter)
{
    struct ifp_get_user_attr_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    DEBUG(SSSDBG_IMPORTANT_INFO, "GetUserAttr is deprecated, please consider "
          "switching to org.freedesktop.sssd.infopipe.Users.User interface\n");

    req = tevent_req_create(mem_ctx, &state, struct ifp_get_user_attr_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->name = name;
    state->attrs = attrs;
    state->rctx = ctx->rctx;
    state->write_iter = write_iter;

    DEBUG(SSSDBG_FUNC_DATA,
          "Looking up attributes of user [%s] on behalf of %"PRIi64"\n",
          state->name, sbus_req->sender->uid);

    subreq = ifp_user_get_attr_send(state, ctx->rctx, ctx->rctx->ncache,
                                    SSS_DP_USER, state->name, state->attrs);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_get_user_attr_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_get_user_attr_done(struct tevent_req *subreq)
{
    struct ifp_get_user_attr_state *state;
    struct sss_domain_info *dom;
    struct ldb_result *res;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_get_user_attr_state);

    ret = ifp_user_get_attr_recv(state, subreq, &res, &dom);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get user attributes [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = ifp_get_user_attr_write_reply(state->write_iter, state->attrs,
                                        state->rctx, dom, res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to construct reply [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
ifp_get_user_attr_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static errno_t
ifp_user_get_groups_build_group_list(struct resp_ctx *rctx,
                                     const char *name,
                                     const char **groupnames,
                                     int *gri)
{
    struct sized_string *group_name;
    errno_t ret;

    ret = sized_domain_name(NULL, rctx, name, &group_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Unable to get sized name for %s [%d]: %s\n",
              name, ret, sss_strerror(ret));
        goto done;
    }

    groupnames[*gri] = talloc_strndup(groupnames,
                                      group_name->str,
                                      group_name->len);
    talloc_free(group_name);
    if (groupnames[*gri] == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "talloc_strndup failed\n");
        ret = ENOMEM;
        goto done;
    }
    (*gri)++;

    DEBUG(SSSDBG_TRACE_FUNC, "Adding group %s\n", groupnames[*gri]);

done:
    return ret;
}

static errno_t
ifp_user_get_groups_build_reply(TALLOC_CTX *mem_ctx,
                                struct resp_ctx *rctx,
                                struct sss_domain_info *domain,
                                struct ldb_result *res,
                                const char ***_groupnames)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int i, gri, num;
    const char *name;
    const char **groupnames;
    gid_t orig_gid;
    struct ldb_message *msg = NULL;
    const char *attrs[] = {SYSDB_NAME, NULL};
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    num = res->count;
    groupnames = talloc_zero_array(mem_ctx, const char *, num + 1);
    if (groupnames == NULL) {
        return ENOMEM;
    }

    gri = 0;
    orig_gid = sss_view_ldb_msg_find_attr_as_uint64(domain,
                                                res->msgs[0],
                                                SYSDB_PRIMARY_GROUP_GIDNUM, 0);
    ret = sysdb_search_group_by_gid(tmp_ctx, domain, orig_gid, attrs, &msg);

    /* If origPrimaryGroupGidNumber exists add it to group list */
    if(ret == EOK) {
        name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);

        if (name != NULL) {
            ifp_user_get_groups_build_group_list(rctx, name, groupnames, &gri);
        }
    }

    /* Start counting from 1 to exclude the user entry */
    for (i = 1; i < num; i++) {
        name = sss_view_ldb_msg_find_attr_as_string(domain,
                                                    res->msgs[i],
                                                    SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Skipping a group with no name\n");
            continue;
        }

        ifp_user_get_groups_build_group_list(rctx, name, groupnames, &gri);
    }

    *_groupnames = groupnames;

    talloc_free(tmp_ctx);
    return EOK;
}

struct ifp_user_get_groups_state {
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct ldb_result *res;
    struct sss_domain_info *domain;
    const char **groupnames;
};

static void ifp_user_get_groups_attr_done(struct tevent_req *subreq);
static void ifp_user_get_groups_done(struct tevent_req *subreq);

struct tevent_req *
ifp_user_get_groups_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct ifp_ctx *ctx,
                         const char *name)
{
    const char *attrs[] = {SYSDB_MEMBEROF, NULL};
    struct ifp_user_get_groups_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ifp_user_get_groups_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->ev = ev;
    state->rctx = ctx->rctx;

    DEBUG(SSSDBG_FUNC_DATA,
          "Looking up groups of user [%s] on behalf of %"PRIi64"\n",
          name, sbus_req->sender->uid);

    subreq = ifp_user_get_attr_send(state, ctx->rctx, ctx->rctx->ncache,
                                    SSS_DP_INITGROUPS, name, attrs);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ifp_user_get_groups_attr_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ifp_user_get_groups_attr_done(struct tevent_req *subreq)
{
    struct ifp_user_get_groups_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_user_get_groups_state);

    ret = ifp_user_get_attr_recv(state, subreq, &state->res, &state->domain);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to get group members [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = resp_resolve_group_names_send(state, state->ev, state->rctx,
                                           state->domain, state->res);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ifp_user_get_groups_done, req);
}

static void ifp_user_get_groups_done(struct tevent_req *subreq)
{
    struct ifp_user_get_groups_state *state;
    struct ldb_result *res;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ifp_user_get_groups_state);

    ret = resp_resolve_group_names_recv(state, subreq, &res);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to resolve group names [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    res = res == NULL ? state->res : res;

    ret = ifp_user_get_groups_build_reply(state, state->rctx, state->domain,
                                          res, &state->groupnames);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to construct reply [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
ifp_user_get_groups_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         const char ***_groupnames)
{
    struct ifp_user_get_groups_state *state;
    state = tevent_req_data(req, struct ifp_user_get_groups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_groupnames = talloc_steal(mem_ctx, state->groupnames);

    return EOK;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version ssh_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return ssh_cli_protocol_version;
}

errno_t
ifp_ping(TALLOC_CTX *mem_ctx,
         struct sbus_request *sbus_req,
         struct ifp_ctx *ctx,
         const char *ping,
         const char **_pong)
{
    DEBUG(SSSDBG_CONF_SETTINGS, "Got request for [%s]\n", ping);

    if (strcasecmp(ping, "ping") != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Ping() only accepts \"ping\" as a param\n");
        return EINVAL;
    }

    *_pong = "PONG";

    return EOK;
}
