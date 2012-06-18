/*
   SSSD

   PAC Responder

   Copyright (C) Sumit Bose <sbose@redhat.com> 2012
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
#include "confdb/confdb.h"

static errno_t pac_cmd_done(struct cli_ctx *cctx, int cmd_ret)
{
    int ret;

    if (cmd_ret == EAGAIN) {
        /* async processing, just return here */
        return EOK;
    }

    ret = sss_packet_new(cctx->creq, 0, sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sss_packet_new failed [%d][%s].\n",
                                  ret, strerror(ret)));
        return ret;
    }

    sss_packet_set_error(cctx->creq->out, cmd_ret);

    sss_cmd_done(cctx, NULL);

    return EOK;
}

struct pac_req_ctx {
    struct cli_ctx *cctx;
    struct pac_ctx *pac_ctx;
    const char *domain_name;
    const char *user_name;
    struct sss_domain_info *dom;

    struct PAC_LOGON_INFO *logon_info;
    struct dom_sid2 *domain_sid;

    size_t gid_count;
    gid_t *gids;
};

static errno_t pac_add_user_next(struct pac_req_ctx *pr_ctx);
static void pac_get_domains_done(struct tevent_req *req);
static errno_t save_pac_user(struct pac_req_ctx *pr_ctx);
static void pac_get_group_done(struct tevent_req *subreq);
static errno_t pac_save_memberships_next(struct tevent_req *req);
static errno_t pac_store_membership(struct pac_req_ctx *pr_ctx,
                                     struct sysdb_ctx *group_sysdb,
                                     struct ldb_dn *user_dn,
                                     int gid_iter);
struct tevent_req *pac_save_memberships_send(struct pac_req_ctx *pr_ctx);
static void pac_save_memberships_done(struct tevent_req *req);


static errno_t pac_add_pac_user(struct cli_ctx *cctx)
{
    int ret;
    uint8_t *body;
    size_t blen;
    struct pac_req_ctx *pr_ctx;
    struct tevent_req *req;

    sss_packet_get_body(cctx->creq->in, &body, &blen);

    pr_ctx = talloc_zero(cctx, struct pac_req_ctx);
    if (pr_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    pr_ctx->cctx = cctx;

    pr_ctx->pac_ctx = talloc_get_type(cctx->rctx->pvt_ctx,  struct pac_ctx);
    if (pr_ctx->pac_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Cannot find pac responder context.\n"));
        return EINVAL;
    }

    ret = get_data_from_pac(pr_ctx, body, blen,
                            &pr_ctx->logon_info);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("get_data_from_pac failed.\n"));
        goto done;
    }

    pr_ctx->domain_name = pr_ctx->logon_info->info3.base.logon_domain.string;
    if (pr_ctx->domain_name == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("No domain name in PAC"));
        ret = EINVAL;
        goto done;
    }

    pr_ctx->user_name = pr_ctx->logon_info->info3.base.account_name.string;
    if (pr_ctx->user_name == NULL) {
        ret = EINVAL;
        DEBUG(SSSDBG_FATAL_FAILURE, ("Missing account name in PAC.\n"));
        goto done;
    }


    pr_ctx->dom = responder_get_domain(pr_ctx, cctx->rctx, pr_ctx->domain_name);
    if (pr_ctx->dom == NULL) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true,
                                      pr_ctx->domain_name);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(req, pac_get_domains_done, pr_ctx);
            ret = EAGAIN;
        }
        goto done;
    }

    ret = pac_add_user_next(pr_ctx);

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

    pr_ctx->dom = responder_get_domain(pr_ctx, cctx->rctx, pr_ctx->domain_name);
    if (pr_ctx->dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Corresponding domain [%s] has not been "
                                  "found\n", pr_ctx->domain_name));
        ret = ENOENT;
        goto done;
    }

    ret = pac_add_user_next(pr_ctx);

done:
    if (ret != EAGAIN) {
        talloc_free(pr_ctx);
    }
    pac_cmd_done(cctx, ret);
}

static errno_t pac_add_user_next(struct pac_req_ctx *pr_ctx)
{
    int ret;
    struct tevent_req *req;
    struct dom_sid *my_dom_sid;
    struct local_mapping_ranges *my_range_map;

    ret = save_pac_user(pr_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("save_pac_user failed.\n"));
        goto done;
    }

    ret = get_my_domain_data(pr_ctx->pac_ctx, pr_ctx->dom,
                             &my_dom_sid, &my_range_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("get_my_domain_sid failed.\n"));
        goto done;
    }

    ret = get_gids_from_pac(pr_ctx, my_range_map, my_dom_sid,
                            pr_ctx->logon_info, &pr_ctx->gid_count,
                            &pr_ctx->gids);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("get_gids_from_pac failed.\n"));
        goto done;
    }

    req = pac_save_memberships_send(pr_ctx);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, pac_save_memberships_done, pr_ctx);

    ret = EAGAIN;

done:
    return ret;
}

static errno_t save_pac_user(struct pac_req_ctx *pr_ctx)
{
    struct sysdb_ctx *sysdb;
    int ret;
    const char *attrs[] = {SYSDB_NAME, SYSDB_UIDNUM, SYSDB_GIDNUM, NULL};
    struct ldb_message *msg;
    struct passwd *pwd = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    sysdb = pr_ctx->dom->sysdb;
    if (sysdb == NULL) {
        ret = EINVAL;
        DEBUG(SSSDBG_FATAL_FAILURE, ("Fatal: Sysdb CTX not found for this domain!\n"));
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
        goto done;
    }

    ret = sysdb_search_user_by_name(tmp_ctx, sysdb, pr_ctx->user_name, attrs,
                                    &msg);
    if (ret == EOK) {
        /* TODO: check id uid and gid are equal. */
    } else if (ret == ENOENT) {
        ret = get_pwd_from_pac(tmp_ctx, pr_ctx->pac_ctx, pr_ctx->dom,
                               pr_ctx->logon_info, &pwd);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("get_pwd_from_pac failed.\n"));
            goto done;
        }

        ret = sysdb_store_user(sysdb, pwd->pw_name, NULL,
                               pwd->pw_uid, pwd->pw_gid, pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell, NULL, NULL,
                               pr_ctx->dom->user_timeout, 0);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_store_user failed [%d][%s].\n",
                                      ret, strerror(ret)));
            goto done;
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_search_user_by_name failed.\n"));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct pac_save_memberships_state {
    int gid_iter;
    struct ldb_dn *user_dn;

    struct pac_req_ctx *pr_ctx;
    struct sss_domain_info *group_dom;
};

struct tevent_req *pac_save_memberships_send(struct pac_req_ctx *pr_ctx)
{
    struct pac_save_memberships_state *state;
    struct sss_domain_info *dom = pr_ctx->dom;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(pr_ctx, &state, struct pac_save_memberships_state);
    if (req == NULL) {
        return NULL;
    }

    state->gid_iter = 0;
    state->user_dn = sysdb_user_dn(dom->sysdb, state, dom->name,
                                   pr_ctx->user_name);
    if (state->user_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }
    state->pr_ctx = pr_ctx;

    /* Remote users are members of local groups */
    if (pr_ctx->dom->parent != NULL) {
        state->group_dom = pr_ctx->dom->parent;
    } else {
        state->group_dom = pr_ctx->dom;
    }

    ret = pac_save_memberships_next(req);
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, pr_ctx->cctx->ev);
    }

done:
    if (ret != EOK && ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, pr_ctx->cctx->ev);
    }

    return req;
}

static errno_t pac_save_memberships_next(struct tevent_req *req)
{
    errno_t ret;
    uint32_t gid;
    struct tevent_req *subreq;
    struct pac_save_memberships_state *state;
    struct pac_req_ctx *pr_ctx;

    state = tevent_req_data(req, struct pac_save_memberships_state);
    pr_ctx = state->pr_ctx;

    while (state->gid_iter < pr_ctx->gid_count) {
        gid = pr_ctx->gids[state->gid_iter];

        ret = pac_store_membership(state->pr_ctx, state->group_dom->sysdb,
                                    state->user_dn, state->gid_iter);
        if (ret == EOK) {
            state->gid_iter++;
            continue;
        } else if (ret == ENOENT) {
            subreq = sss_dp_get_account_send(state, pr_ctx->cctx->rctx,
                                             state->group_dom, true,
                                             SSS_DP_GROUP, NULL,
                                             gid, NULL);
            if (subreq == NULL) {
                ret = ENOMEM;
                goto done;
            }
            tevent_req_set_callback(subreq, pac_get_group_done, req);

            return EAGAIN;
        } else  {
            goto done;
        }
    }

    ret = EOK;
done:
    return ret;
}

static void pac_get_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct pac_save_memberships_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct pac_save_memberships_state);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_account_recv(req, subreq,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_zfree(subreq);
    talloc_zfree(err_msg);
    if (ret != EOK) {
        goto error;
    }

    ret = pac_store_membership(state->pr_ctx, state->group_dom->sysdb,
                                state->user_dn, state->gid_iter);
    if (ret != EOK) {
        goto error;
    }
    state->gid_iter++;

    ret = pac_save_memberships_next(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        goto error;
    }

    return;

error:
    tevent_req_error(req, ret);
}

static errno_t
pac_store_membership(struct pac_req_ctx *pr_ctx,
                      struct sysdb_ctx *group_sysdb,
                      struct ldb_dn *user_dn,
                      int gid_iter)
{
    TALLOC_CTX *tmp_ctx;
    const char *group_name;
    struct sysdb_attrs *group_attrs;
    struct ldb_message *group;
    uint32_t gid;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    gid = pr_ctx->gids[gid_iter];

    ret = sysdb_search_group_by_gid(tmp_ctx, group_sysdb,
                                    gid, NULL, &group);
    if (ret != EOK) {
        goto done;
    }

    group_name = ldb_msg_find_attr_as_string(group, SYSDB_NAME, NULL);
    if (group_name == NULL) {
        ret = EIO;
        goto done;
    }

    group_attrs = talloc_zero(tmp_ctx, struct sysdb_attrs);
    if (group_attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }
    group_attrs->num = 1;
    group_attrs->a = ldb_msg_find_element(group, SYSDB_MEMBER);
    if (group_attrs->a == NULL) {
        group_attrs->a = talloc_zero(group_attrs, struct ldb_message_element);
        if (group_attrs->a == NULL) {
            ret = ENOMEM;
            goto done;
        }
        group_attrs->a[0].name = talloc_strdup(group_attrs->a, SYSDB_MEMBER);
        if (group_attrs->a[0].name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_attrs_add_string(group_attrs, SYSDB_MEMBER,
                                 ldb_dn_get_linearized(user_dn));
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_store_group(group_sysdb, group_name, gid,
                            group_attrs, pr_ctx->dom->group_timeout, 0);
    if (ret != EOK) {
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t pac_save_memberships_recv(struct tevent_req *subreq)
{
    TEVENT_REQ_RETURN_ON_ERROR(subreq);

    return EOK;
}

static void pac_save_memberships_done(struct tevent_req *req)
{
    struct pac_req_ctx *pr_ctx = tevent_req_callback_data(req, struct pac_req_ctx);
    struct cli_ctx *cctx = pr_ctx->cctx;
    errno_t ret;

    ret = pac_save_memberships_recv(req);
    talloc_zfree(req);

    talloc_free(pr_ctx);
    pac_cmd_done(cctx, ret);
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

int pac_cmd_execute(struct cli_ctx *cctx)
{
    enum sss_cli_command cmd;
    int i;

    cmd = sss_packet_get_cmd(cctx->creq->in);

    for (i = 0; pac_cmds[i].cmd != SSS_CLI_NULL; i++) {
        if (cmd == pac_cmds[i].cmd) {
            return pac_cmds[i].fn(cctx);
        }
    }

    return EINVAL;
}
