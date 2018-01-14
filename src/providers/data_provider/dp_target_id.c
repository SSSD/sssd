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

#include <talloc.h>
#include <tevent.h>

#include "sbus/sssd_dbus.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "responder/nss/nss_iface.h"
#include "util/util.h"

#define FILTER_TYPE(str, type) {str "=", sizeof(str "=") - 1, type}

static bool check_and_parse_filter(struct dp_id_data *data,
                                   const char *filter,
                                   const char *extra)
{
    /* We will use sizeof() to determine the length of a string so we don't
     * call strlen over and over again with each request. Not a bottleneck,
     * but unnecessary and simple to avoid. */
    static struct {
        const char *name;
        size_t lenght;
        uint32_t type;
    } types[] = {FILTER_TYPE("name", BE_FILTER_NAME),
                 FILTER_TYPE("idnumber", BE_FILTER_IDNUM),
                 FILTER_TYPE(DP_SEC_ID, BE_FILTER_SECID),
                 FILTER_TYPE(DP_CERT, BE_FILTER_CERT),
                 FILTER_TYPE(DP_WILDCARD, BE_FILTER_WILDCARD),
                 {0, 0, 0}};
    int i;

    if (SBUS_IS_STRING_EMPTY(filter)) {
        return false;
    }

    for (i = 0; types[i].name != NULL; i++) {
        if (strncmp(filter, types[i].name, types[i].lenght) == 0) {
            data->filter_type = types[i].type;
            data->filter_value = SBUS_SET_STRING(&filter[types[i].lenght]);
            data->extra_value = SBUS_SET_STRING(extra);
            return true;
        }
    }

    if (strcmp(filter, ENUM_INDICATOR) == 0) {
        data->filter_type = BE_FILTER_ENUM;
        data->filter_value = NULL;
        data->extra_value = NULL;
        return true;
    }

    return false;
}

struct dp_initgr_ctx {
    const char *domain;
    struct sss_domain_info *domain_info;
    const char *filter_value;
    const char *username;
    uint32_t gnum;
    uint32_t *groups;
};

static struct dp_initgr_ctx *create_initgr_ctx(
                                        TALLOC_CTX *mem_ctx,
                                        const char *domain,
                                        struct sss_domain_info *domain_info,
                                        const char *filter_value,
                                        struct ldb_result *res)
{
    struct dp_initgr_ctx *ctx;
    const char *username;
    unsigned int i;
    errno_t ret;

    ctx = talloc_zero(mem_ctx, struct dp_initgr_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    /* Copy domain name */
    ctx->domain = talloc_strdup(ctx, domain);
    if (ctx->domain == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Copy filter value */
    ctx->filter_value = talloc_strdup(ctx, filter_value);
    if (ctx->filter_value == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Reference domain info */
    ctx->domain_info = domain_info;

    /* If we had the data in sysdb */
    if (res != NULL) {
        /* Copy original username */
        username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
        if (username == NULL) {
            ret = EINVAL;
            goto done;
        }
        ctx->username = talloc_strdup(ctx, username);
        if (ctx->username == NULL) {
            ret = ENOMEM;
            goto done;
        }

        /* Copy group IDs */
        ctx->groups = talloc_array(mem_ctx, uint32_t, res->count);
        if (ctx->groups == NULL) {
            ret = ENOMEM;
            goto done;
        }

        /* The first GID is the primary so it might be duplicated
         * later in the list. */
        for (ctx->gnum = 0, i = 0; i < res->count; i++) {
            ctx->groups[ctx->gnum] = ldb_msg_find_attr_as_uint(res->msgs[i],
                                                               SYSDB_GIDNUM, 0);
            /* If 0 it may be a non-POSIX group, so we skip it. */
            if (ctx->groups[ctx->gnum] != 0) {
                ctx->gnum++;
            }
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
        return NULL;
    }

    return ctx;
}

static void dp_req_initgr_pp_nss_notify(const char *req_name,
                                        struct data_provider *provider,
                                        struct dp_initgr_ctx *ctx)
{
    struct dp_client *dp_cli;
    DBusMessage *msg;
    dbus_bool_t dbret;
    int num;

    /* If user didn't exist in the cache previously */
    if (ctx->username == NULL) {
        /* There is no point in contacting NSS responder */
        return;
    }

    dp_cli = provider->clients[DPC_NSS];
    if (dp_cli == NULL) {
        return;
    }

    msg = dbus_message_new_method_call(NULL,
                                       NSS_MEMORYCACHE_PATH,
                                       IFACE_NSS_MEMORYCACHE,
                                       IFACE_NSS_MEMORYCACHE_UPDATEINITGROUPS);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return;
    }

    num = ctx->gnum;
    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_STRING, &ctx->username,
                                     DBUS_TYPE_STRING, &ctx->domain,
                                     DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
                                     &ctx->groups, num,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        dbus_message_unref(msg);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to update memory cache\n");

    sbus_conn_send_reply(dp_client_conn(dp_cli), msg);
    dbus_message_unref(msg);

    return;
}

static void dp_req_initgr_pp_sr_overlay(struct data_provider *provider,
                                        struct dp_initgr_ctx *ctx)
{
    bool enabled = false;
    struct be_ctx *be = provider->be_ctx;
    struct ldb_result *res;
    struct ldb_message *msg;
    const char *name;
    char *output_name;
    char **conf_user;
    char **conf_group;
    size_t i;
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    struct ldb_message_element el = { 0, SYSDB_SESSION_RECORDING, 0, NULL };
    struct sysdb_attrs del_attrs = { 1, &el };
    struct sysdb_attrs *add_attrs;

    /* If selective session recording is not enabled */
    if (be->sr_conf.scope != SESSION_RECORDING_SCOPE_SOME) {
        goto done;
    }

    /* Allocate temporary talloc context */
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed creating temporary talloc context\n");
        ret = ENOMEM;
        goto done;
    }

    /* Get updated initgroups data with overrides */
    ret = sysdb_initgroups_with_views(tmp_ctx, ctx->domain_info,
                                      ctx->filter_value, &res);
    if (ret == ENOENT || (ret == EOK && res->count == 0)) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get initgroups: %s\n",
              sss_strerror(ret));
        goto done;
    }

    /* Delete sessionRecording attribute so we know when we failed */
    ret = sysdb_set_entry_attr(ctx->domain_info->sysdb, res->msgs[0]->dn,
                               &del_attrs, SYSDB_MOD_DEL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed removing %s attribute: %s\n",
              SYSDB_SESSION_RECORDING, sss_strerror(ret));
        goto done;
    }

    /* Format output username */
    name = sss_get_name_from_msg(ctx->domain_info, res->msgs[0]);
    ret = sss_output_fqname(tmp_ctx, ctx->domain_info, name,
                            be->override_space, &output_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed formatting output username from \"%s\": %s\n",
              name, sss_strerror(ret));
        goto done;
    }

    /* For each user name in session recording config */
    conf_user = be->sr_conf.users;
    if (conf_user != NULL) {
        for (; *conf_user != NULL && !enabled; conf_user++) {
            /* If it matches the requested user name */
            if (strcmp(*conf_user, output_name) == 0) {
                enabled = true;
            }
        }
    }

    /* If we have groups in config and are not yet enabled */
    if (be->sr_conf.groups != NULL &&
        be->sr_conf.groups[0] != NULL &&
        !enabled) {
        /* For each group in response */
        for (i = 0; i < res->count && !enabled; i++) {
            /* Get the group msg */
            if (i == 0) {
                gid_t gid;
                struct ldb_result *group_res;

                /* Get the primary group */
                gid = sss_view_ldb_msg_find_attr_as_uint64(ctx->domain_info,
                                                           res->msgs[i],
                                                           SYSDB_GIDNUM, 0);
                if (gid == 0) {
                    continue;
                }
                ret = sysdb_getgrgid_with_views(tmp_ctx, ctx->domain_info,
                                                gid, &group_res);
                if (ret == ENOENT) {
                    continue;
                } else if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed retrieving group #%llu: %s\n",
                          (unsigned long long)gid, sss_strerror(ret));
                    goto done;
                } else if (group_res->count == 0) {
                    continue;
                }
                msg = group_res->msgs[0];
            } else {
                msg = res->msgs[i];
            }
            /* Get the group's output name */
            name = sss_get_name_from_msg(ctx->domain_info, msg);
            if (name == NULL) {
                continue;
            }
            ret = sss_output_fqname(tmp_ctx, ctx->domain_info,
                                    name, be->override_space,
                                    &output_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed formatting output group name from \"%s\": %s\n",
                      name, sss_strerror(ret));
                goto done;
            }
            /* For each group in configuration */
            for (conf_group = be->sr_conf.groups;
                 *conf_group != NULL && !enabled;
                 conf_group++) {
                if (strcmp(*conf_group, output_name) == 0) {
                    enabled = true;
                }
            }
        }
    }

    /* Set sessionRecording attribute to enabled value */
    add_attrs = sysdb_new_attrs(tmp_ctx);
    if (add_attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed creating attributes\n");
        ret = ENOMEM;
        goto done;
    }
    ret = sysdb_attrs_add_bool(add_attrs, SYSDB_SESSION_RECORDING, enabled);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed setting %s attribute: %s\n",
              SYSDB_SESSION_RECORDING, sss_strerror(ret));
        goto done;
    }
    ret = sysdb_set_entry_attr(ctx->domain_info->sysdb, res->msgs[0]->dn,
                               add_attrs, SYSDB_MOD_ADD);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed storing %s attribute: %s\n",
              SYSDB_SESSION_RECORDING, sss_strerror(ret));
        goto done;
    }

done:
    talloc_free(tmp_ctx);
}

static void dp_req_initgr_pp(const char *req_name,
                             struct data_provider *provider,
                             struct dp_initgr_ctx *ctx,
                             struct dp_reply_std *reply)
{
    (void)reply;
    dp_req_initgr_pp_nss_notify(req_name, provider, ctx);
    dp_req_initgr_pp_sr_overlay(provider, ctx);
}

static errno_t dp_initgroups(struct sbus_request *sbus_req,
                             struct dp_client *dp_cli,
                             const char *key,
                             uint32_t dp_flags,
                             struct dp_id_data *data)
{
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;
    struct dp_initgr_ctx *ctx;
    struct ldb_result *res = NULL;
    errno_t ret;

    be_ctx = dp_client_be(dp_cli);

    if (data->domain == NULL) {
        domain = be_ctx->domain;
    } else {
        domain = find_domain_by_name(be_ctx->domain, data->domain, true);
        if (domain == NULL) {
            return ERR_DOMAIN_NOT_FOUND;
        }
    }

    ret = sysdb_initgroups(sbus_req, domain, data->filter_value, &res);
    if (ret == ENOENT || (ret == EOK && res->count == 0)) {
        talloc_zfree(res);
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get initgroups [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ctx = create_initgr_ctx(sbus_req, data->domain, domain,
                            data->filter_value, res);
    if (ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    dp_req_with_reply_pp(dp_cli, data->domain, "Initgroups", key,
                      sbus_req, DPT_ID, DPM_ACCOUNT_HANDLER, dp_flags, data,
                      dp_req_initgr_pp, ctx, struct dp_initgr_ctx,
                      dp_req_reply_std, struct dp_reply_std);

    ret = EOK;

done:
    talloc_free(res);
    return ret;
}

errno_t dp_get_account_info_handler(struct sbus_request *sbus_req,
                                    void *dp_cli,
                                    uint32_t dp_flags,
                                    uint32_t entry_type,
                                    const char *filter,
                                    const char *domain,
                                    const char *extra)
{
    struct dp_id_data *data;
    const char *key;
    errno_t ret;

    data = talloc_zero(sbus_req, struct dp_id_data);
    if (data == NULL) {
        return ENOMEM;
    }

    data->entry_type = entry_type;
    data->domain = domain;

    if (!check_and_parse_filter(data, filter, extra)) {
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Got request for [%#"PRIx32"][%s][%s]\n",
          data->entry_type, be_req2str(data->entry_type),
          filter);

    key = talloc_asprintf(data, "%u:%s:%s:%s", data->entry_type,
                          extra, domain, filter);
    if (key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if ((data->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_INITGROUPS) {
        ret = dp_initgroups(sbus_req, dp_cli, key, dp_flags, data);
        if (ret != EAGAIN) {
            goto done;
        }
    }

    dp_req_with_reply(dp_cli, domain, "Account", key,
                      sbus_req, DPT_ID, DPM_ACCOUNT_HANDLER, dp_flags, data,
                      dp_req_reply_std, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(data);
    }

    return ret;
}

static bool
check_and_parse_acct_domain_filter(struct dp_get_acct_domain_data *data,
                                   const char *filter)
{
    /* We will use sizeof() to determine the length of a string so we don't
     * call strlen over and over again with each request. Not a bottleneck,
     * but unnecessary and simple to avoid. */
    static struct {
        const char *name;
        size_t lenght;
        uint32_t type;
    } types[] = {FILTER_TYPE("idnumber", BE_FILTER_IDNUM),
                 {0, 0, 0}};
    int i;

    if (SBUS_IS_STRING_EMPTY(filter)) {
        return false;
    }

    for (i = 0; types[i].name != NULL; i++) {
        if (strncmp(filter, types[i].name, types[i].lenght) == 0) {
            data->filter_type = types[i].type;
            data->filter_value = SBUS_SET_STRING(&filter[types[i].lenght]);
            return true;
        }
    }

    if (strcmp(filter, ENUM_INDICATOR) == 0) {
        data->filter_type = BE_FILTER_ENUM;
        data->filter_value = NULL;
        return true;
    }

    return false;
}

errno_t dp_get_account_domain_handler(struct sbus_request *sbus_req,
                                      void *dp_cli,
                                      uint32_t entry_type,
                                      const char *filter)
{
    struct dp_get_acct_domain_data *data;
    const char *key = NULL;
    errno_t ret;

    data = talloc_zero(sbus_req, struct dp_get_acct_domain_data);
    if (data == NULL) {
        return ENOMEM;
    }
    data->entry_type = entry_type;

    if (!check_and_parse_acct_domain_filter(data, filter)) {
        ret = EINVAL;
        goto done;
    }

    dp_req_with_reply(dp_cli, NULL, "AccountDomain", key, sbus_req,
                      DPT_ID, DPM_ACCT_DOMAIN_HANDLER, 0, data,
                      dp_req_reply_std, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(data);
    }

    return ret;
}

struct default_account_domain_state {
    struct dp_reply_std reply;
};

struct tevent_req *
default_account_domain_send(TALLOC_CTX *mem_ctx,
                            void *unused_ctx,
                            struct dp_get_acct_domain_data *data,
                            struct dp_req_params *params)
{
    struct default_account_domain_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct default_account_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    dp_reply_std_set(&state->reply,
                     DP_ERR_DECIDE, ERR_GET_ACCT_DOM_NOT_SUPPORTED,
                     NULL);
    tevent_req_done(req);
    tevent_req_post(req, params->ev);
    return req;
}

errno_t default_account_domain_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct dp_reply_std *data)
{
    struct default_account_domain_state *state = NULL;

    state = tevent_req_data(req, struct default_account_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
