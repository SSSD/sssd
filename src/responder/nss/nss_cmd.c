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
#include "db/sysdb.h"
#include "responder/nss/nss_private.h"
#include "responder/nss/nss_protocol.h"

static struct nss_cmd_ctx *
nss_cmd_ctx_create(TALLOC_CTX *mem_ctx,
                   struct cli_ctx *cli_ctx,
                   enum cache_req_type type,
                   nss_protocol_fill_packet_fn fill_fn)
{
    struct nss_cmd_ctx *cmd_ctx;

    cmd_ctx = talloc_zero(mem_ctx, struct nss_cmd_ctx);
    if (cmd_ctx == NULL) {
        return NULL;
    }

    cmd_ctx->cli_ctx = cli_ctx;
    cmd_ctx->nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    cmd_ctx->state_ctx = talloc_get_type(cli_ctx->state_ctx,
                                         struct nss_state_ctx);
    cmd_ctx->type = type;
    cmd_ctx->fill_fn = fill_fn;

    return cmd_ctx;
}

static errno_t eval_flags(struct nss_cmd_ctx *cmd_ctx,
                          struct cache_req_data *data)
{
    if ((cmd_ctx->flags & SSS_NSS_EX_FLAG_NO_CACHE) != 0
            && (cmd_ctx->flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Flags SSS_NSS_EX_FLAG_NO_CACHE and "
                                   "SSS_NSS_EX_FLAG_INVALIDATE_CACHE are "
                                   "mutually exclusive.\n");
        return EINVAL;
    }

    if ((cmd_ctx->flags & SSS_NSS_EX_FLAG_NO_CACHE) != 0) {
        cache_req_data_set_bypass_cache(data, true);
    } else if ((cmd_ctx->flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) != 0) {
        cache_req_data_set_bypass_dp(data, true);
    }

    return EOK;
}

static void nss_getby_done(struct tevent_req *subreq);
static void nss_getlistby_done(struct tevent_req *subreq);

static errno_t nss_getby_name(struct cli_ctx *cli_ctx,
                              bool ex_version,
                              enum cache_req_type type,
                              const char **attrs,
                              enum sss_mc_type memcache,
                              nss_protocol_fill_packet_fn fill_fn)
{
    struct cache_req_data *data;
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    const char *rawname;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cmd_ctx->flags = 0;
    if (ex_version) {
        ret = nss_protocol_parse_name_ex(cli_ctx, &rawname, &cmd_ctx->flags);
    } else {
        ret = nss_protocol_parse_name(cli_ctx, &rawname);
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Input name: %s\n", rawname);

    data = cache_req_data_name_attrs(cmd_ctx, type, rawname, attrs);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set cache request data!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = eval_flags(cmd_ctx, data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "eval_flags failed.\n");
        goto done;
    }

    subreq = nss_get_object_send(cmd_ctx, cli_ctx->ev, cli_ctx,
                                 data, memcache, rawname, 0);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, nss_getby_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return EOK;
}

static errno_t nss_getby_id(struct cli_ctx *cli_ctx,
                            bool ex_version,
                            enum cache_req_type type,
                            const char **attrs,
                            enum sss_mc_type memcache,
                            nss_protocol_fill_packet_fn fill_fn)
{
    struct cache_req_data *data;
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    uint32_t id;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (ex_version) {
        ret = nss_protocol_parse_id_ex(cli_ctx, &id, &cmd_ctx->flags);
    } else {
        ret = nss_protocol_parse_id(cli_ctx, &id);
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Input ID: %u\n", id);

    data = cache_req_data_id_attrs(cmd_ctx, type, id, attrs);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set cache request data!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = eval_flags(cmd_ctx, data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "eval_flags failed.\n");
        goto done;
    }

    subreq = nss_get_object_send(cmd_ctx, cli_ctx->ev, cli_ctx,
                                 data, memcache, NULL, id);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, nss_getby_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return EOK;
}

static errno_t nss_getby_svc(struct cli_ctx *cli_ctx,
                             enum cache_req_type type,
                             const char *protocol,
                             const char *name,
                             uint16_t port,
                             nss_protocol_fill_packet_fn fill_fn)
{
    struct cache_req_data *data;
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cmd_ctx->svc_protocol = protocol;

    data = cache_req_data_svc(cmd_ctx, type, name, protocol, port);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set cache request data!\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Input name: %s, protocol: %s, port: %u\n",
          (name == NULL ? "<none>" : name),
          (protocol == NULL ? "<none>" : protocol),
          port);

    subreq = nss_get_object_send(cmd_ctx, cli_ctx->ev, cli_ctx,
                                 data, SSS_MC_NONE, NULL, 0);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, nss_getby_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return EOK;
}

static errno_t nss_getlistby_cert(struct cli_ctx *cli_ctx,
                                  enum cache_req_type type)
{
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    const char *cert;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, NULL);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cmd_ctx->sid_id_type = SSS_ID_TYPE_UID;

    ret = nss_protocol_parse_cert(cli_ctx, &cert);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Input cert: %s\n", get_last_x_chars(cert, 10));

    subreq = cache_req_user_by_cert_send(cmd_ctx, cli_ctx->ev, cli_ctx->rctx,
                                         cli_ctx->rctx->ncache, 0,
                                         CACHE_REQ_ANY_DOM, NULL,
                                         cert);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "cache_req_user_by_cert_send failed.\n");
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, nss_getlistby_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return EOK;
}

static void nss_getlistby_done(struct tevent_req *subreq)
{
    struct cache_req_result **results;
    struct nss_cmd_ctx *cmd_ctx;
    errno_t ret;
    struct cli_protocol *pctx;

    cmd_ctx = tevent_req_callback_data(subreq, struct nss_cmd_ctx);

    ret = cache_req_recv(cmd_ctx, subreq, &results);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "cache_req_user_by_cert request failed.\n");
        goto done;
    }

    pctx = talloc_get_type(cmd_ctx->cli_ctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        goto done;
    }

    ret = nss_protocol_fill_name_list_all_domains(cmd_ctx->nss_ctx, cmd_ctx,
                                                  pctx->creq->out, results);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_set_error(pctx->creq->out, EOK);

done:
    nss_protocol_done(cmd_ctx->cli_ctx, ret);
    talloc_free(cmd_ctx);
}

static errno_t nss_getby_cert(struct cli_ctx *cli_ctx,
                              enum cache_req_type type,
                              nss_protocol_fill_packet_fn fill_fn)
{
    struct cache_req_data *data;
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    const char *cert;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cmd_ctx->sid_id_type = SSS_ID_TYPE_UID;

    ret = nss_protocol_parse_cert(cli_ctx, &cert);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    data = cache_req_data_cert(cmd_ctx, type, cert);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set cache request data!\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Input cert: %s\n", get_last_x_chars(cert, 10));

    subreq = nss_get_object_send(cmd_ctx, cli_ctx->ev, cli_ctx,
                                 data, SSS_MC_NONE, NULL, 0);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, nss_getby_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return EOK;
}

static errno_t nss_getby_sid(struct cli_ctx *cli_ctx,
                             enum cache_req_type type,
                             nss_protocol_fill_packet_fn fill_fn)
{
    struct cache_req_data *data;
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    const char *sid;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* It will be detected when constructing output packet. */
    cmd_ctx->sid_id_type = SSS_ID_TYPE_NOT_SPECIFIED;

    ret = nss_protocol_parse_sid(cli_ctx, &sid);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Input SID: %s\n", sid);

    data = cache_req_data_sid(cmd_ctx, type, sid, NULL);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set cache request data!\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = nss_get_object_send(cmd_ctx, cli_ctx->ev, cli_ctx,
                                 data, SSS_MC_NONE, NULL, 0);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, nss_getby_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return EOK;
}

static errno_t invalidate_cache(struct nss_cmd_ctx *cmd_ctx,
                                struct cache_req_result *result)
{
    int ret;
    enum sss_mc_type memcache_type;
    const char *name;
    char *output_name = NULL;
    bool is_user;
    struct sysdb_attrs *attrs = NULL;

    switch (cmd_ctx->type) {
    case CACHE_REQ_INITGROUPS:
    case CACHE_REQ_INITGROUPS_BY_UPN:
        memcache_type = SSS_MC_INITGROUPS;
        is_user = true;
        break;
    case CACHE_REQ_USER_BY_NAME:
    case CACHE_REQ_USER_BY_ID:
        memcache_type = SSS_MC_PASSWD;
        is_user = true;
        break;
    case CACHE_REQ_GROUP_BY_NAME:
    case CACHE_REQ_GROUP_BY_ID:
        memcache_type = SSS_MC_GROUP;
        is_user = false;
        break;
    default:
        /* nothing to do */
        return EOK;
    }

    /* Find output name to invalidate memory cache entry*/
    name = sss_get_name_from_msg(result->domain, result->msgs[0]);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Found object has no name.\n");
        return EINVAL;
    }
    ret = sss_output_fqname(cmd_ctx, result->domain, name,
                            cmd_ctx->nss_ctx->rctx->override_space,
                            &output_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_output_fqname failed.\n");
        return ret;
    }

    memcache_delete_entry(cmd_ctx->nss_ctx, cmd_ctx->nss_ctx->rctx, NULL,
                          output_name, 0, memcache_type);
    if (memcache_type == SSS_MC_INITGROUPS) {
        /* Invalidate the passwd data as well */
        memcache_delete_entry(cmd_ctx->nss_ctx, cmd_ctx->nss_ctx->rctx,
                              result->domain, output_name, 0, SSS_MC_PASSWD);
    }
    talloc_free(output_name);

    /* Use sysdb name to invalidate disk cache entry */
    name = ldb_msg_find_attr_as_string(result->msgs[0], SYSDB_NAME, NULL);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Found object has no name.\n");
        return EINVAL;
    }

    if (memcache_type == SSS_MC_INITGROUPS) {
        attrs = sysdb_new_attrs(cmd_ctx);
        if (attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            return ENOMEM;
        }

        ret = sysdb_attrs_add_time_t(attrs, SYSDB_INITGR_EXPIRE, 1);
        if (ret != EOK) {
            talloc_free(attrs);
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_time_t failed.\n");
            return ret;
        }

        ret = sysdb_set_user_attr(result->domain, name, attrs, SYSDB_MOD_REP);
        talloc_free(attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_user_attr failed.\n");
            return ret;
        }
    }

    ret = sysdb_invalidate_cache_entry(result->domain, name, is_user);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_invalidate_cache_entry failed.\n");
        return ret;
    }

    return EOK;
}

static void nss_getby_done(struct tevent_req *subreq)
{
    struct cache_req_result *result;
    struct nss_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct nss_cmd_ctx);

    ret = nss_get_object_recv(cmd_ctx, subreq, &result, &cmd_ctx->rawname);
    talloc_zfree(subreq);
    if (ret != EOK) {
        nss_protocol_done(cmd_ctx->cli_ctx, ret);
        goto done;
    }

    if ((cmd_ctx->flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) != 0) {
        ret = invalidate_cache(cmd_ctx, result);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to invalidate cache for [%s].\n",
                                     cmd_ctx->rawname);
            nss_protocol_done(cmd_ctx->cli_ctx, ret);
            goto done;
        }
    }

    nss_protocol_reply(cmd_ctx->cli_ctx, cmd_ctx->nss_ctx, cmd_ctx,
                       result, cmd_ctx->fill_fn);

done:
    talloc_free(cmd_ctx);
}

static void nss_setent_done(struct tevent_req *subreq);

static errno_t nss_setent(struct cli_ctx *cli_ctx,
                          enum cache_req_type type,
                          struct nss_enum_ctx *enum_ctx)
{
    struct tevent_req *subreq;

    subreq = nss_setent_send(cli_ctx, cli_ctx->ev, cli_ctx, type, enum_ctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, nss_setent_done, cli_ctx);

    return EOK;
}

static void nss_setent_done(struct tevent_req *subreq)
{
    struct cli_ctx *cli_ctx;
    errno_t ret;

    cli_ctx = tevent_req_callback_data(subreq, struct cli_ctx);

    ret = nss_setent_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        nss_protocol_done(cli_ctx, ret);
        return;
    }

    /* Both EOK and ENOENT means that setent was successful. */
    nss_protocol_done(cli_ctx, EOK);
}

static void nss_getent_done(struct tevent_req *subreq);

static errno_t nss_getent(struct cli_ctx *cli_ctx,
                          enum cache_req_type type,
                          struct nss_enum_index *idx,
                          nss_protocol_fill_packet_fn fill_fn,
                          struct nss_enum_ctx *enum_ctx)
{
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = nss_protocol_parse_limit(cli_ctx, &cmd_ctx->enum_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    cmd_ctx->enumeration = true;
    cmd_ctx->enum_ctx = enum_ctx;
    cmd_ctx->enum_index = idx;

    subreq = nss_setent_send(cli_ctx, cli_ctx->ev, cli_ctx, type, enum_ctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create setent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, nss_getent_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return ret;
}

static struct cache_req_result *
nss_getent_get_result(struct nss_enum_ctx *enum_ctx,
                      struct nss_enum_index *idx)
{
    struct cache_req_result *result;

    if (enum_ctx->result == NULL) {
        /* Nothing was found. */
        return NULL;
    }

    result = enum_ctx->result[idx->domain];

    if (result != NULL && idx->result >= result->count) {
        /* Switch to next domain. */
        idx->result = 0;
        idx->domain++;

        result = enum_ctx->result[idx->domain];
    }

    return result;
}

static void nss_getent_done(struct tevent_req *subreq)
{
    struct cache_req_result *limited;
    struct cache_req_result *result;
    struct nss_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct nss_cmd_ctx);

    ret = nss_setent_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    result = nss_getent_get_result(cmd_ctx->enum_ctx, cmd_ctx->enum_index);
    if (result == NULL) {
        /* No more records to return. */
        ret = ENOENT;
        goto done;
    }

    /* Create copy of the result with limited number of records. */
    limited = cache_req_copy_limited_result(cmd_ctx, result,
                                            cmd_ctx->enum_index->result,
                                            cmd_ctx->enum_limit);
    if (limited == NULL) {
        ret = ERR_INTERNAL;
        goto done;
    }

    cmd_ctx->enum_index->result += result->count;

    /* Reply with limited result. */
    nss_protocol_reply(cmd_ctx->cli_ctx, cmd_ctx->nss_ctx, cmd_ctx,
                       result, cmd_ctx->fill_fn);

    ret = EOK;

done:
    if (ret != EOK) {
        nss_protocol_done(cmd_ctx->cli_ctx, ret);
    }

    talloc_free(cmd_ctx);
}

static void nss_setnetgrent_done(struct tevent_req *subreq);

static errno_t nss_setnetgrent(struct cli_ctx *cli_ctx,
                               enum cache_req_type type,
                               nss_protocol_fill_packet_fn fill_fn)
{
    struct nss_ctx *nss_ctx;
    struct nss_state_ctx *state_ctx;
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    const char *netgroup;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    nss_ctx = cmd_ctx->nss_ctx;
    state_ctx = cmd_ctx->state_ctx;

    ret = nss_protocol_parse_name(cli_ctx, &netgroup);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    talloc_zfree(state_ctx->netgroup);
    state_ctx->netgroup = talloc_strdup(state_ctx, netgroup);
    if (state_ctx->netgroup == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = nss_setnetgrent_send(cli_ctx, cli_ctx->ev, cli_ctx, type,
                                  nss_ctx->netgrent, state_ctx->netgroup);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, nss_setnetgrent_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return EOK;
}

static void nss_setnetgrent_done(struct tevent_req *subreq)
{
    struct nss_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct nss_cmd_ctx);

    ret = nss_setnetgrent_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        nss_protocol_done(cmd_ctx->cli_ctx, ret);
        goto done;
    }

    nss_protocol_reply(cmd_ctx->cli_ctx, cmd_ctx->nss_ctx, cmd_ctx,
                       NULL, cmd_ctx->fill_fn);

done:
    talloc_free(cmd_ctx);
}

static void nss_getnetgrent_done(struct tevent_req *subreq);

static errno_t nss_getnetgrent(struct cli_ctx *cli_ctx,
                               enum cache_req_type type,
                               nss_protocol_fill_packet_fn fill_fn)
{
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    errno_t ret;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (cmd_ctx->state_ctx->netgroup == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "State does not contain netgroup name!\n");
        ret = EINVAL;
        goto done;
    }

    ret = nss_protocol_parse_limit(cli_ctx, &cmd_ctx->enum_limit);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    cmd_ctx->enumeration = true;
    cmd_ctx->enum_ctx = NULL; /* We will determine it later. */
    cmd_ctx->enum_index = &cmd_ctx->state_ctx->netgrent;

    subreq = nss_setnetgrent_send(cli_ctx, cli_ctx->ev, cli_ctx, type,
                                  cmd_ctx->nss_ctx->netgrent,
                                  cmd_ctx->state_ctx->netgroup);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, nss_getnetgrent_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return nss_protocol_done(cli_ctx, ret);
    }

    return EOK;
}

static void nss_getnetgrent_done(struct tevent_req *subreq)
{
    struct nss_enum_ctx *enum_ctx;
    struct nss_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct nss_cmd_ctx);

    ret = nss_setent_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    enum_ctx = sss_ptr_hash_lookup(cmd_ctx->nss_ctx->netgrent,
                                   cmd_ctx->state_ctx->netgroup,
                                   struct nss_enum_ctx);
    if (enum_ctx == NULL) {
        ret = ENOENT;
        goto done;
    }

    cmd_ctx->enum_ctx = enum_ctx;

    /* Reply with result. */
    nss_protocol_reply(cmd_ctx->cli_ctx, cmd_ctx->nss_ctx, cmd_ctx,
                       NULL, cmd_ctx->fill_fn);

    ret = EOK;

done:
    if (ret != EOK) {
        nss_protocol_done(cmd_ctx->cli_ctx, ret);
    }

    talloc_free(cmd_ctx);
}

static errno_t nss_endent(struct cli_ctx *cli_ctx,
                          struct nss_enum_index *idx)
{
    DEBUG(SSSDBG_CONF_SETTINGS, "Resetting enumeration state\n");

    idx->domain = 0;
    idx->result = 0;

    nss_protocol_done(cli_ctx, EOK);

    return EOK;
}

static errno_t nss_cmd_getpwnam(struct cli_ctx *cli_ctx)
{
    return nss_getby_name(cli_ctx, false, CACHE_REQ_USER_BY_NAME, NULL,
                          SSS_MC_PASSWD, nss_protocol_fill_pwent);
}

static errno_t nss_cmd_getpwuid(struct cli_ctx *cli_ctx)
{
    return nss_getby_id(cli_ctx, false, CACHE_REQ_USER_BY_ID, NULL,
                        SSS_MC_PASSWD, nss_protocol_fill_pwent);
}

static errno_t nss_cmd_getpwnam_ex(struct cli_ctx *cli_ctx)
{
    return nss_getby_name(cli_ctx, true, CACHE_REQ_USER_BY_NAME, NULL,
                          SSS_MC_PASSWD, nss_protocol_fill_pwent);
}

static errno_t nss_cmd_getpwuid_ex(struct cli_ctx *cli_ctx)
{
    return nss_getby_id(cli_ctx, true, CACHE_REQ_USER_BY_ID, NULL,
                        SSS_MC_PASSWD, nss_protocol_fill_pwent);
}

static errno_t nss_cmd_setpwent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);

    return nss_setent(cli_ctx, CACHE_REQ_ENUM_USERS, &nss_ctx->pwent);
}

static errno_t nss_cmd_getpwent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;
    struct nss_state_ctx *state_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_getent(cli_ctx, CACHE_REQ_ENUM_USERS,
                      &state_ctx->pwent, nss_protocol_fill_pwent,
                      &nss_ctx->pwent);
}

static errno_t nss_cmd_endpwent(struct cli_ctx *cli_ctx)
{
    struct nss_state_ctx *state_ctx;

    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_endent(cli_ctx, &state_ctx->pwent);
}

static errno_t nss_cmd_getgrnam(struct cli_ctx *cli_ctx)
{
    return nss_getby_name(cli_ctx, false, CACHE_REQ_GROUP_BY_NAME, NULL,
                          SSS_MC_GROUP, nss_protocol_fill_grent);
}

static errno_t nss_cmd_getgrgid(struct cli_ctx *cli_ctx)
{
    return nss_getby_id(cli_ctx, false, CACHE_REQ_GROUP_BY_ID, NULL,
                        SSS_MC_GROUP, nss_protocol_fill_grent);
}

static errno_t nss_cmd_getgrnam_ex(struct cli_ctx *cli_ctx)
{
    return nss_getby_name(cli_ctx, true, CACHE_REQ_GROUP_BY_NAME, NULL,
                          SSS_MC_GROUP, nss_protocol_fill_grent);
}

static errno_t nss_cmd_getgrgid_ex(struct cli_ctx *cli_ctx)
{
    return nss_getby_id(cli_ctx, true, CACHE_REQ_GROUP_BY_ID, NULL,
                        SSS_MC_GROUP, nss_protocol_fill_grent);
}


static errno_t nss_cmd_setgrent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);

    return nss_setent(cli_ctx, CACHE_REQ_ENUM_GROUPS, &nss_ctx->grent);
}

static errno_t nss_cmd_getgrent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;
    struct nss_state_ctx *state_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_getent(cli_ctx, CACHE_REQ_ENUM_GROUPS,
                      &state_ctx->grent, nss_protocol_fill_grent,
                      &nss_ctx->grent);
}

static errno_t nss_cmd_endgrent(struct cli_ctx *cli_ctx)
{
    struct nss_state_ctx *state_ctx;

    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_endent(cli_ctx, &state_ctx->grent);
}

static errno_t nss_cmd_initgroups(struct cli_ctx *cli_ctx)
{
    return nss_getby_name(cli_ctx, false, CACHE_REQ_INITGROUPS, NULL,
                          SSS_MC_INITGROUPS, nss_protocol_fill_initgr);
}

static errno_t nss_cmd_initgroups_ex(struct cli_ctx *cli_ctx)
{
    return nss_getby_name(cli_ctx, true, CACHE_REQ_INITGROUPS, NULL,
                          SSS_MC_INITGROUPS, nss_protocol_fill_initgr);
}

static errno_t nss_cmd_setnetgrent(struct cli_ctx *cli_ctx)
{
    return nss_setnetgrent(cli_ctx, CACHE_REQ_NETGROUP_BY_NAME,
                           nss_protocol_fill_setnetgrent);
}

static errno_t nss_cmd_getnetgrent(struct cli_ctx *cli_ctx)
{
    return nss_getnetgrent(cli_ctx, CACHE_REQ_NETGROUP_BY_NAME,
                           nss_protocol_fill_netgrent);
}

static errno_t nss_cmd_endnetgrent(struct cli_ctx *cli_ctx)
{
    struct nss_state_ctx *state_ctx;

    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);
    talloc_zfree(state_ctx->netgroup);

    return nss_endent(cli_ctx, &state_ctx->netgrent);
}

static errno_t nss_cmd_getservbyname(struct cli_ctx *cli_ctx)
{
    const char *name;
    const char *protocol;
    errno_t ret;

    ret = nss_protocol_parse_svc_name(cli_ctx, &name, &protocol);
    if (ret != EOK) {
        return ret;
    }

    return nss_getby_svc(cli_ctx, CACHE_REQ_SVC_BY_NAME, protocol, name, 0,
                         nss_protocol_fill_svcent);
}

static errno_t nss_cmd_getservbyport(struct cli_ctx *cli_ctx)
{
    const char *protocol;
    uint16_t port;
    errno_t ret;

    ret = nss_protocol_parse_svc_port(cli_ctx, &port, &protocol);
    if (ret != EOK) {
        return ret;
    }

    return nss_getby_svc(cli_ctx, CACHE_REQ_SVC_BY_PORT, protocol, NULL, port,
                         nss_protocol_fill_svcent);
}

static errno_t nss_cmd_setservent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);

    return nss_setent(cli_ctx, CACHE_REQ_ENUM_SVC, &nss_ctx->svcent);
}

static errno_t nss_cmd_getservent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;
    struct nss_state_ctx *state_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_getent(cli_ctx, CACHE_REQ_ENUM_SVC,
                      &state_ctx->svcent, nss_protocol_fill_svcent,
                      &nss_ctx->svcent);
}

static errno_t nss_cmd_endservent(struct cli_ctx *cli_ctx)
{
    struct nss_state_ctx *state_ctx;

    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_endent(cli_ctx, &state_ctx->grent);
}

static errno_t nss_cmd_getsidbyname(struct cli_ctx *cli_ctx)
{
    const char *attrs[] = { SYSDB_SID_STR, NULL };

    return nss_getby_name(cli_ctx, false, CACHE_REQ_OBJECT_BY_NAME, attrs,
                          SSS_MC_NONE, nss_protocol_fill_sid);
}

static errno_t nss_cmd_getsidbyid(struct cli_ctx *cli_ctx)
{
    const char *attrs[] = { SYSDB_SID_STR, NULL };

    return nss_getby_id(cli_ctx, false, CACHE_REQ_OBJECT_BY_ID, attrs,
                        SSS_MC_NONE, nss_protocol_fill_sid);
}

static errno_t nss_cmd_getnamebysid(struct cli_ctx *cli_ctx)
{
    return nss_getby_sid(cli_ctx, CACHE_REQ_OBJECT_BY_SID,
                         nss_protocol_fill_name);
}

static errno_t nss_cmd_getidbysid(struct cli_ctx *cli_ctx)
{
    return nss_getby_sid(cli_ctx, CACHE_REQ_OBJECT_BY_SID,
                         nss_protocol_fill_id);
}

static errno_t nss_cmd_getorigbyname(struct cli_ctx *cli_ctx)
{
    errno_t ret;
    struct nss_ctx *nss_ctx;
    const char **attrs;
    static const char *defattrs[] = { SYSDB_NAME, SYSDB_OBJECTCATEGORY,
                                      SYSDB_SID_STR,
                                      ORIGINALAD_PREFIX SYSDB_NAME,
                                      ORIGINALAD_PREFIX SYSDB_UIDNUM,
                                      ORIGINALAD_PREFIX SYSDB_GIDNUM,
                                      ORIGINALAD_PREFIX SYSDB_GECOS,
                                      ORIGINALAD_PREFIX SYSDB_HOMEDIR,
                                      ORIGINALAD_PREFIX SYSDB_SHELL,
                                      SYSDB_UPN,
                                      SYSDB_DEFAULT_OVERRIDE_NAME,
                                      SYSDB_AD_ACCOUNT_EXPIRES,
                                      SYSDB_AD_USER_ACCOUNT_CONTROL,
                                      SYSDB_SSH_PUBKEY,
                                      SYSDB_USER_CERT,
                                      SYSDB_USER_EMAIL,
                                      SYSDB_ORIG_DN,
                                      SYSDB_ORIG_MEMBEROF,
                                      SYSDB_DEFAULT_ATTRS, NULL };

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);

    if (nss_ctx->extra_attributes != NULL) {
        ret = add_strings_lists(cli_ctx, defattrs, nss_ctx->extra_attributes,
                                false, discard_const(&attrs));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unable to concatenate attributes [%d]: %s\n",
                  ret, sss_strerror(ret));
            return ENOMEM;
        }
    } else {
        attrs = defattrs;
    }

    return nss_getby_name(cli_ctx, false, CACHE_REQ_OBJECT_BY_NAME, attrs,
                          SSS_MC_NONE, nss_protocol_fill_orig);
}

static errno_t nss_cmd_getnamebycert(struct cli_ctx *cli_ctx)
{
    return nss_getby_cert(cli_ctx, CACHE_REQ_USER_BY_CERT,
                          nss_protocol_fill_single_name);
}

static errno_t nss_cmd_getlistbycert(struct cli_ctx *cli_ctx)
{
    return nss_getlistby_cert(cli_ctx, CACHE_REQ_USER_BY_CERT);
}

struct sss_cmd_table *get_nss_cmds(void)
{
    static struct sss_cmd_table nss_cmds[] = {
        { SSS_GET_VERSION, sss_cmd_get_version },
        { SSS_NSS_GETPWNAM, nss_cmd_getpwnam },
        { SSS_NSS_GETPWUID, nss_cmd_getpwuid },
        { SSS_NSS_SETPWENT, nss_cmd_setpwent },
        { SSS_NSS_GETPWENT, nss_cmd_getpwent },
        { SSS_NSS_ENDPWENT, nss_cmd_endpwent },
        { SSS_NSS_GETGRNAM, nss_cmd_getgrnam },
        { SSS_NSS_GETGRGID, nss_cmd_getgrgid },
        { SSS_NSS_SETGRENT, nss_cmd_setgrent },
        { SSS_NSS_GETGRENT, nss_cmd_getgrent },
        { SSS_NSS_ENDGRENT, nss_cmd_endgrent },
        { SSS_NSS_INITGR, nss_cmd_initgroups },
        { SSS_NSS_SETNETGRENT, nss_cmd_setnetgrent },
        { SSS_NSS_GETNETGRENT, nss_cmd_getnetgrent },
        { SSS_NSS_ENDNETGRENT, nss_cmd_endnetgrent },
        { SSS_NSS_GETSERVBYNAME, nss_cmd_getservbyname },
        { SSS_NSS_GETSERVBYPORT, nss_cmd_getservbyport },
        { SSS_NSS_SETSERVENT, nss_cmd_setservent },
        { SSS_NSS_GETSERVENT, nss_cmd_getservent },
        { SSS_NSS_ENDSERVENT, nss_cmd_endservent },
        { SSS_NSS_GETSIDBYNAME, nss_cmd_getsidbyname },
        { SSS_NSS_GETSIDBYID, nss_cmd_getsidbyid },
        { SSS_NSS_GETNAMEBYSID, nss_cmd_getnamebysid },
        { SSS_NSS_GETIDBYSID, nss_cmd_getidbysid },
        { SSS_NSS_GETORIGBYNAME, nss_cmd_getorigbyname },
        { SSS_NSS_GETNAMEBYCERT, nss_cmd_getnamebycert },
        { SSS_NSS_GETLISTBYCERT, nss_cmd_getlistbycert },
        { SSS_NSS_GETPWNAM_EX, nss_cmd_getpwnam_ex },
        { SSS_NSS_GETPWUID_EX, nss_cmd_getpwuid_ex },
        { SSS_NSS_GETGRNAM_EX, nss_cmd_getgrnam_ex },
        { SSS_NSS_GETGRGID_EX, nss_cmd_getgrgid_ex },
        { SSS_NSS_INITGR_EX, nss_cmd_initgroups_ex },
        { SSS_CLI_NULL, NULL }
    };

    return nss_cmds;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version nss_cli_protocol_version[] = {
        { 1, "2008-09-05", "initial version, \\0 terminated strings" },
        { 0, NULL, NULL }
    };

    return nss_cli_protocol_version;
}

int nss_connection_setup(struct cli_ctx *cli_ctx)
{
    int ret;

    ret = sss_connection_setup(cli_ctx);
    if (ret != EOK) return ret;

    cli_ctx->state_ctx = talloc_zero(cli_ctx, struct nss_state_ctx);
    if (cli_ctx->state_ctx == NULL) {
        return ENOMEM;
    }

    return EOK;
}
