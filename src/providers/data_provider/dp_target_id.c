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
    const char *username;
    const char *domain;
    uint32_t gnum;
    uint32_t *groups;
};

static struct dp_initgr_ctx *create_initgr_ctx(TALLOC_CTX *mem_ctx,
                                               const char *domain,
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

    ctx->domain = talloc_strdup(ctx, domain);
    if (ctx->domain == NULL) {
        ret = ENOMEM;
        goto done;
    }

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
        /* If 0 it may be a non-posix group, so we skip it. */
        if (ctx->groups[ctx->gnum] != 0) {
            ctx->gnum++;
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

static void dp_req_initgr_pp(const char *req_name,
                             struct data_provider *provider,
                             struct dp_initgr_ctx *ctx,
                             struct dp_reply_std *reply)
{
    struct dp_client *dp_cli;
    DBusMessage *msg;
    dbus_bool_t dbret;
    int num;

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

static errno_t dp_initgroups(struct sbus_request *sbus_req,
                             struct dp_client *dp_cli,
                             const char *key,
                             uint32_t dp_flags,
                             struct dp_id_data *data)
{
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;
    struct dp_initgr_ctx *ctx;
    struct ldb_result *res;
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
        /* There is no point in concacting NSS responder. Proceed as usual. */
        return EAGAIN;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get initgroups [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ctx = create_initgr_ctx(sbus_req, data->domain, res);
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
        ret =  dp_initgroups(sbus_req, dp_cli, key, dp_flags, data);
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
