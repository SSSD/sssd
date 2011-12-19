/*
    SSSD

    IPA Subdomains Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_common.h"

#define SUBDOMAINS_FILTER "objectclass=ipaNTTrustedDomain"
#define IPA_CN "cn"
#define IPA_FLATNAME "ipaNTFlatName"
#define IPA_SID "ipaNTTrustedDomainSID"

static void ipa_subdomains_reply(struct be_req *be_req, int dp_err, int result)
{
    be_req->fn(be_req, dp_err, result, NULL);
}

static errno_t ipa_subdomains_parse_results(
                                        struct be_get_subdomains_req *sd_data,
                                        size_t count,
                                        struct sysdb_attrs **reply)
{
    struct subdomain_info **new_domain_list = NULL;
    const char *value;
    size_t c;
    int ret;

    new_domain_list = talloc_array(sd_data, struct subdomain_info *, count + 1);
    if (new_domain_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_array failed.\n"));
        return ENOMEM;
    }

    for (c = 0; c < count; c++) {
        new_domain_list[c] = talloc_zero(new_domain_list,
                                         struct subdomain_info);
        if (new_domain_list[c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }
        new_domain_list[c]->name = talloc_strdup(new_domain_list[c], value);
        if (new_domain_list[c]->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_FLATNAME, &value);
        if (ret == EOK) {
            new_domain_list[c]->flat_name = talloc_strdup(new_domain_list[c],
                                                          value);
            if (new_domain_list[c]->flat_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_SID, &value);
        if (ret == EOK) {
            new_domain_list[c]->id = talloc_strdup(new_domain_list[c], value);
            if (new_domain_list[c]->id == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }
    }
    new_domain_list[c] = NULL;

    ret = EOK;

done:
    if (ret == EOK) {
        talloc_free(sd_data->domain_list);
        sd_data->domain_list = new_domain_list;
    } else {
        talloc_free(new_domain_list);
    }

    return ret;
}

struct ipa_subdomains_req_ctx {
    struct be_req *be_req;
    struct ipa_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;
    struct be_get_subdomains_req *sd_data;

    char *current_filter;

    struct sdap_search_base **search_bases;
    int search_base_iter;

    size_t reply_count;
    struct sysdb_attrs **reply;
};

static void ipa_subdomains_get_conn_done(struct tevent_req *req);
static errno_t ipa_subdomains_handler_next(struct ipa_subdomains_req_ctx *ctx);
static void ipa_subdomains_handler_done(struct tevent_req *req);

void ipa_subdomains_handler(struct be_req *be_req)
{
    struct tevent_req *req;
    struct ipa_subdomains_req_ctx *ctx = NULL;
    int ret;

    ctx = talloc(be_req, struct ipa_subdomains_req_ctx);
    if (ctx == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ctx->be_req = be_req;
    ctx->sd_ctx = talloc_get_type(
                        be_req->be_ctx->bet_info[BET_SUBDOMAINS].pvt_bet_data,
                        struct ipa_subdomains_ctx);
    ctx->sd_data = talloc_get_type(be_req->req_data,
                                     struct be_get_subdomains_req);

    ctx->search_base_iter = 0;
    ctx->search_bases = ctx->sd_ctx->search_bases;
    ctx->current_filter = NULL;
    ctx->reply_count = 0;
    ctx->reply = NULL;

    ctx->sdap_op = sdap_id_op_create(ctx,
                                     ctx->sd_ctx->sdap_id_ctx->conn_cache);
    if (ctx->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    req = sdap_id_op_connect_send(ctx->sdap_op, ctx, &ret);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret)));
        goto fail;
    }

    tevent_req_set_callback(req, ipa_subdomains_get_conn_done, ctx);

    return;

fail:
    talloc_free(ctx);
    ipa_subdomains_reply(be_req, DP_ERR_FATAL, ret);
}

static void ipa_subdomains_get_conn_done(struct tevent_req *req)
{
    int ret;
    int dp_error = DP_ERR_FATAL;
    struct be_req *be_req;
    struct ipa_subdomains_req_ctx *ctx = tevent_req_callback_data(req,
                                                       struct ipa_subdomains_req_ctx);
    ret = sdap_id_op_connect_recv(req, &dp_error);
    talloc_zfree(req);
    if (ret) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("No IPA server is available, cannot get the "
                   "subdomain list while offline\n"));

/* FIXME: return saved results ?? */
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to connect to IPA server: [%d](%s)\n",
                   ret, strerror(ret)));
        }

        goto fail;
    }

    ret = ipa_subdomains_handler_next(ctx);
    if (ret != EOK && ret != EAGAIN) {
        goto fail;
    }

    return;

fail:
    be_req = ctx->be_req;
    talloc_free(ctx);
    ipa_subdomains_reply(be_req, dp_error, ret);
}

static errno_t ipa_subdomains_handler_next(struct ipa_subdomains_req_ctx *ctx)
{
    struct tevent_req *req;
    struct sdap_search_base *base;
    const char *attrs[] = {"cn",
                           "ipaNTFlatName",
                           "ipaNTTrustedDomainSID",
                           NULL};

    base = ctx->search_bases[ctx->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    talloc_free(ctx->current_filter);
    ctx->current_filter = sdap_get_id_specific_filter(ctx, SUBDOMAINS_FILTER,
                                                      base->filter);
    if (ctx->current_filter == NULL) {
        return ENOMEM;
    }

    req = sdap_get_generic_send(ctx, ctx->be_req->be_ctx->ev,
                        ctx->sd_ctx->sdap_id_ctx->opts,
                        sdap_id_op_handle(ctx->sdap_op),
                        base->basedn, base->scope,
                        ctx->current_filter, attrs, NULL, 0,
                        dp_opt_get_int(ctx->sd_ctx->sdap_id_ctx->opts->basic,
                                       SDAP_SEARCH_TIMEOUT), false);

    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        return ENOMEM;
    }

    tevent_req_set_callback(req, ipa_subdomains_handler_done, ctx);

    return EAGAIN;
}

static void ipa_subdomains_handler_done(struct tevent_req *req)
{
    int ret;
    struct be_req *be_req;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ipa_subdomains_req_ctx *ctx = tevent_req_callback_data(req,
                                                       struct ipa_subdomains_req_ctx);

    be_req = ctx->be_req;

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send request failed.\n"));
        goto done;
    }

    if (reply_count) {
        ctx->reply = talloc_realloc(ctx, ctx->reply, struct sysdb_attrs *,
                                    ctx->reply_count + reply_count);
        if (ctx->reply == NULL) {
            ret = ENOMEM;
            goto done;
        }
        memcpy(ctx->reply+ctx->reply_count, reply,
               reply_count * sizeof(struct sysdb_attrs *));
        ctx->reply_count += reply_count;
    }

    ctx->search_base_iter++;
    ret = ipa_subdomains_handler_next(ctx);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

    ret = ipa_subdomains_parse_results(ctx->sd_data, ctx->reply_count, ctx->reply);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("ipa_subdomains_parse_results request failed.\n"));
        goto done;
    }

    ret = sysdb_update_subdomains(ctx->sd_ctx->sdap_id_ctx->be->sysdb,
                                  ctx->sd_data->domain_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_update_subdomains failed.\n"));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(ctx);
    ipa_subdomains_reply(be_req, (ret == EOK ? DP_ERR_OK : DP_ERR_FATAL), ret);
}
