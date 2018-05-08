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

#include "config.h"

#include <talloc.h>
#include <string.h>
#include <pwd.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/ssh/ssh_private.h"

struct ssh_cmd_ctx {
    struct cli_ctx *cli_ctx;
    const char *name;
    const char *alias;
    const char *domain;
};

static errno_t
ssh_check_non_sssd_user(const char *username)
{
    struct passwd *pwd;

    pwd = getpwnam(username);
    if (pwd != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "%s is a non-SSSD user\n", username);
        return ERR_NON_SSSD_USER;
    }

    return ENOENT;
}


static struct sss_domain_info *
ssh_get_result_domain(struct resp_ctx *rctx,
                      struct cache_req_result *result,
                      const char *name)
{
    if (result != NULL) {
        return result->domain;
    }

    return find_domain_by_name(rctx->domains, name, true);
}

static void ssh_cmd_get_user_pubkeys_done(struct tevent_req *subreq);

static errno_t ssh_cmd_get_user_pubkeys(struct cli_ctx *cli_ctx)
{
    struct ssh_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    errno_t ret;

    static const char *attrs[] = { SYSDB_NAME, SYSDB_SSH_PUBKEY,
                                   SYSDB_USER_CERT, NULL };

    cmd_ctx = talloc_zero(cli_ctx, struct ssh_cmd_ctx);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cmd_ctx->cli_ctx = cli_ctx;

    ret = ssh_protocol_parse_user(cli_ctx, cli_ctx->rctx->default_domain,
                                  &cmd_ctx->name, &cmd_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Requesting SSH user public keys for [%s] from [%s]\n",
          cmd_ctx->name, cmd_ctx->domain ? cmd_ctx->domain : "<ALL>");

    if (strcmp(cmd_ctx->name, "root") == 0) {
        ret = ERR_NON_SSSD_USER;
        goto done;
    }

    subreq = cache_req_user_by_name_attrs_send(cmd_ctx, cli_ctx->ev,
                                               cli_ctx->rctx,
                                               cli_ctx->rctx->ncache, 0,
                                               cmd_ctx->domain,
                                               cmd_ctx->name, attrs);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ssh_cmd_get_user_pubkeys_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return ssh_protocol_done(cli_ctx, ret);
    }

    return ret;
}

static void ssh_cmd_get_user_pubkeys_done(struct tevent_req *subreq)
{
    struct cache_req_result *result;
    struct ssh_cmd_ctx *cmd_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct ssh_cmd_ctx);

    ret = cache_req_user_by_name_attrs_recv(cmd_ctx, subreq, &result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* Check if it is a non SSSD user. */
            ret = ssh_check_non_sssd_user(cmd_ctx->name);
        }

        ssh_protocol_done(cmd_ctx->cli_ctx, ret);
        goto done;
    }

    ssh_protocol_reply(cmd_ctx->cli_ctx, result);

done:
    talloc_free(cmd_ctx);
}

static void ssh_cmd_get_host_pubkeys_done(struct tevent_req *subreq);

static errno_t ssh_cmd_get_host_pubkeys(struct cli_ctx *cli_ctx)
{
    struct ssh_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    errno_t ret;

    static const char *attrs[] = { SYSDB_NAME, SYSDB_SSH_PUBKEY, NULL };

    cmd_ctx = talloc_zero(cli_ctx, struct ssh_cmd_ctx);
    if (cmd_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cmd_ctx->cli_ctx = cli_ctx;

    ret = ssh_protocol_parse_host(cli_ctx, &cmd_ctx->name, &cmd_ctx->alias,
                                  &cmd_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request message!\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Requesting SSH host public keys for [%s] from [%s]\n",
          cmd_ctx->name, cmd_ctx->domain ? cmd_ctx->domain : "<ALL>");

    subreq = cache_req_host_by_name_send(cmd_ctx, cli_ctx->ev,
                                         cli_ctx->rctx,
                                         cli_ctx->rctx->ncache, 0,
                                         cmd_ctx->domain,
                                         cmd_ctx->name,
                                         cmd_ctx->alias, attrs);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ssh_cmd_get_host_pubkeys_done, cmd_ctx);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmd_ctx);
        return ssh_protocol_done(cli_ctx, ret);
    }

    return ret;
}

static void ssh_cmd_get_host_pubkeys_done(struct tevent_req *subreq)
{
    struct cache_req_result *result = NULL;
    struct sss_domain_info *domain;
    struct ssh_cmd_ctx *cmd_ctx;
    struct ssh_ctx *ssh_ctx;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct ssh_cmd_ctx);
    ssh_ctx = talloc_get_type(cmd_ctx->cli_ctx->rctx->pvt_ctx, struct ssh_ctx);

    ret = cache_req_host_by_name_recv(cmd_ctx, subreq, &result);
    talloc_zfree(subreq);

    if (ret == EOK || ret == ENOENT) {
        domain = ssh_get_result_domain(ssh_ctx->rctx, result, cmd_ctx->domain);

        ssh_update_known_hosts_file(ssh_ctx->rctx->domains, domain,
                                    cmd_ctx->name, ssh_ctx->hash_known_hosts,
                                    ssh_ctx->known_hosts_timeout);
    }

    if (ret != EOK) {
        ssh_protocol_done(cmd_ctx->cli_ctx, ret);
        goto done;
    }

    ssh_protocol_reply(cmd_ctx->cli_ctx, result);

done:
    talloc_free(cmd_ctx);
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version ssh_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return ssh_cli_protocol_version;
}

struct sss_cmd_table *get_ssh_cmds(void) {
    static struct sss_cmd_table ssh_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_SSH_GET_USER_PUBKEYS, ssh_cmd_get_user_pubkeys},
        {SSS_SSH_GET_HOST_PUBKEYS, ssh_cmd_get_host_pubkeys},
        {SSS_CLI_NULL, NULL}
    };

    return ssh_cmds;
}
