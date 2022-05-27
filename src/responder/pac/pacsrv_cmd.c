/*
   SSSD

   PAC Responder

   Copyright (C) Sumit Bose <sbose@redhat.com> 2012, 2016
                 Jan Zeleny <jzeleny@redhat.com> 2012

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

#include "util/util.h"
#include "responder/pac/pacsrv.h"
#include "responder/common/cache_req/cache_req.h"
#include "confdb/confdb.h"

#include "providers/ad/ad_pac.h"

static errno_t pac_cmd_done(struct cli_ctx *cctx, int cmd_ret)
{
    struct cli_protocol *pctx;
    int ret;

    if (cmd_ret == EAGAIN) {
        /* async processing, just return here */
        return EOK;
    }

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_new failed [%d][%s].\n",
                                  ret, strerror(ret));
        return ret;
    }

    sss_packet_set_error(pctx->creq->out, cmd_ret);
    if (cmd_ret != 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Sending error [%d][%s].\n", cmd_ret,
                                                         sss_strerror(cmd_ret));
    }

    sss_cmd_done(cctx, NULL);

    return EOK;
}

struct pac_req_ctx {
    struct cli_ctx *cctx;
    struct pac_ctx *pac_ctx;
    const char *domain_name;
    struct sss_domain_info *dom;

    uint8_t *blob;
    size_t blen;

    struct PAC_LOGON_INFO *logon_info;
    struct PAC_UPN_DNS_INFO *upn_dns_info;

    char *user_sid_str;
    char *user_dom_sid_str;
};

static errno_t pac_resolve_user_sid_next(struct pac_req_ctx *pr_ctx);
static void pac_resolve_user_sid_done(struct tevent_req *req);
static void pac_get_domains_done(struct tevent_req *req);

static errno_t pac_add_pac_user(struct cli_ctx *cctx)
{
    int ret;
    uint8_t *body;
    size_t blen;
    struct pac_req_ctx *pr_ctx;
    struct tevent_req *req;
    enum idmap_error_code err;
    struct cli_protocol *pctx;

    pctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    pr_ctx = talloc_zero(cctx, struct pac_req_ctx);
    if (pr_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    pr_ctx->cctx = cctx;
    pr_ctx->blob = body;
    pr_ctx->blen = blen;

    pr_ctx->pac_ctx = talloc_get_type(cctx->rctx->pvt_ctx,  struct pac_ctx);
    if (pr_ctx->pac_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot find pac responder context.\n");
        return EINVAL;
    }

    ret = ad_get_data_from_pac(pr_ctx, pr_ctx->pac_ctx->pac_check_opts,
                               body, blen,
                               &pr_ctx->logon_info, &pr_ctx->upn_dns_info);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_get_data_from_pac failed.\n");
        goto done;
    }

    pr_ctx->domain_name = pr_ctx->logon_info->info3.base.logon_domain.string;
    if (pr_ctx->domain_name == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "No domain name in PAC\n");
        ret = EINVAL;
        goto done;
    }

    err = sss_idmap_smb_sid_to_sid(pr_ctx->pac_ctx->idmap_ctx,
                                   pr_ctx->logon_info->info3.base.domain_sid,
                                   &pr_ctx->user_dom_sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_smb_sid_to_sid failed.\n");
        ret = EFAULT;
        goto done;
    }

    talloc_steal(pr_ctx, pr_ctx->user_dom_sid_str);

    pr_ctx->user_sid_str = talloc_asprintf(pr_ctx, "%s-%"PRIu32,
                                           pr_ctx->user_dom_sid_str,
                                           pr_ctx->logon_info->info3.base.rid);
    if (pr_ctx->user_sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = responder_get_domain_by_id(cctx->rctx, pr_ctx->user_dom_sid_str,
                                     &pr_ctx->dom);
    if (ret == EAGAIN || ret == ENOENT) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true,
                                      pr_ctx->domain_name);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(req, pac_get_domains_done, pr_ctx);
            ret = EAGAIN;
        }
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "responder_get_domain_by_id failed.\n");
        goto done;
    }

    ret = pac_resolve_user_sid_next(pr_ctx);

done:
    if (ret != EAGAIN) {
        talloc_free(pr_ctx);
    }
    return pac_cmd_done(cctx, ret);
}

static void pac_get_domains_done(struct tevent_req *req)
{
    struct pac_req_ctx *pr_ctx = tevent_req_callback_data(req,
                                                          struct pac_req_ctx);
    struct cli_ctx *cctx = pr_ctx->cctx;
    int ret;

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        goto done;
    }

    ret = responder_get_domain_by_id(cctx->rctx, pr_ctx->user_dom_sid_str,
                                     &pr_ctx->dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Corresponding domain [%s] has not been "
                                  "found\n", pr_ctx->user_dom_sid_str);
        ret = ENOENT;
        goto done;
    }

    ret = pac_resolve_user_sid_next(pr_ctx);

done:
    if (ret != EAGAIN) {
        talloc_free(pr_ctx);
    }
    pac_cmd_done(cctx, ret);
}

static errno_t pac_resolve_user_sid_next(struct pac_req_ctx *pr_ctx)
{
    int ret;
    struct tevent_req *req;
    const char *pw_attrs[] = SYSDB_PW_ATTRS;


    req = cache_req_object_by_sid_send(pr_ctx, pr_ctx->cctx->ev,
                                       pr_ctx->cctx->rctx,
                                       pr_ctx->pac_ctx->rctx->ncache,
                                       0, pr_ctx->dom->name,
                                       pr_ctx->user_sid_str,
                                       pw_attrs);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "cache_req_object_by_sid_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, pac_resolve_user_sid_done, pr_ctx);

    ret = EAGAIN;


    return ret;
}

static void pac_resolve_user_sid_done(struct tevent_req *req)
{
    struct pac_req_ctx *pr_ctx = tevent_req_callback_data(req,
                                                          struct pac_req_ctx);
    struct cli_ctx *cctx = pr_ctx->cctx;
    errno_t ret;
    struct cache_req_result *result;
    struct sysdb_attrs *user_attrs;

    ret = cache_req_object_by_sid_recv(pr_ctx, req, &result);
    talloc_zfree(req);

    if (ret != EOK) {
        talloc_free(pr_ctx);
        pac_cmd_done(cctx, ret);
        return;
    }

    ret = check_upn_and_sid_from_user_and_pac(result->msgs[0],
                                              pr_ctx->pac_ctx->idmap_ctx,
                                              pr_ctx->upn_dns_info,
                                              pr_ctx->pac_ctx->pac_check_opts);
    if (ret != EOK) {
        talloc_free(pr_ctx);
        pac_cmd_done(cctx, ret);
        return;
    }

    user_attrs = sysdb_new_attrs(pr_ctx);
    if (user_attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_mem(user_attrs, SYSDB_PAC_BLOB, pr_ctx->blob,
                              pr_ctx->blen);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_mem failed");
        goto done;
    }

    ret = sysdb_attrs_add_time_t(user_attrs, SYSDB_PAC_BLOB_EXPIRE,
                                 (time(NULL) + pr_ctx->pac_ctx->pac_lifetime));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_time_t failed");
        goto done;
    }

    ret = sysdb_set_entry_attr(result->domain->sysdb,
                               result->msgs[0]->dn, user_attrs,
                               SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_entry_attr failed.\n");
        goto done;
    }

done:
    talloc_free(pr_ctx);
    pac_cmd_done(cctx, ret);
    return;
}


struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version pac_cli_protocol_version[] = {
        {1, "2011-04-12", "initial version"},
        {0, NULL, NULL}
    };

    return pac_cli_protocol_version;
}

static struct sss_cmd_table pac_cmds[] = {
    {SSS_GET_VERSION, sss_cmd_get_version},
    {SSS_PAC_ADD_PAC_USER, pac_add_pac_user},
    {SSS_CLI_NULL, NULL}
};

struct sss_cmd_table *get_pac_cmds(void) {
    return pac_cmds;
}
