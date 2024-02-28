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
#include "responder/pam/pam_helpers.h"
#include "lib/certmap/sss_certmap.h"

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


#ifdef BUILD_SSH_KNOWN_HOSTS_PROXY
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
#endif

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

struct priv_sss_debug {
    int level;
};

static void ssh_ext_debug(void *private, const char *file, long line,
                      const char *function, const char *format, ...)
{
    va_list ap;
    struct priv_sss_debug *data = private;
    int level = SSSDBG_OP_FAILURE;

    if (data != NULL) {
        level = data->level;
    }

    va_start(ap, format);
    sss_vdebug_fn(file, line, function, level, APPEND_LINE_FEED,
                  format, ap);
    va_end(ap);
}

static errno_t ssh_cmd_refresh_certmap_ctx(struct ssh_ctx *ssh_ctx,
                                           struct sss_domain_info *domains)
{

    struct sss_certmap_ctx *sss_certmap_ctx = NULL;
    struct sss_domain_info *dom;
    struct certmap_info **certmap_list;
    size_t c;
    int ret;
    bool rule_added;
    bool all_rules = false;
    bool no_rules = false;
    bool rules_present = false;

    ssh_ctx->cert_rules_error = false;

    if (ssh_ctx->cert_rules == NULL || ssh_ctx->cert_rules[0] == NULL) {
        all_rules = true;
    } else if (ssh_ctx->cert_rules[0] != NULL
                    && ssh_ctx->cert_rules[1] == NULL) {
        if (strcmp(ssh_ctx->cert_rules[0], "all_rules") == 0) {
            all_rules = true;
        } else if (strcmp(ssh_ctx->cert_rules[0], "no_rules") == 0) {
            no_rules = true;
        }
    }

    if (!ssh_ctx->use_cert_keys
            || ssh_ctx->certmap_last_read
                    >= ssh_ctx->rctx->get_domains_last_call.tv_sec
            || no_rules) {
        DEBUG(SSSDBG_TRACE_ALL, "No certmap update needed.\n");
        return EOK;
    }

    ret = sss_certmap_init(ssh_ctx, ssh_ext_debug, NULL, &sss_certmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_certmap_init failed.\n");
        goto done;
    }

    rule_added = false;
    DLIST_FOR_EACH(dom, domains) {
        certmap_list = dom->certmaps;
        if (certmap_list == NULL || *certmap_list == NULL) {
            continue;
        }

        for (c = 0; certmap_list[c] != NULL; c++) {
            rules_present = true;

            if (!all_rules && !string_in_list(certmap_list[c]->name,
                                              ssh_ctx->cert_rules, true)) {
                DEBUG(SSSDBG_TRACE_ALL, "Skipping matching rule [%s], it is "
                      "not listed in the ssh_use_certificate_matching_rules "
                      "option.\n", certmap_list[c]->name);
                continue;
            }

            DEBUG(SSSDBG_TRACE_ALL,
                  "Trying to add rule [%s][%d][%s][%s].\n",
                  certmap_list[c]->name, certmap_list[c]->priority,
                  certmap_list[c]->match_rule, certmap_list[c]->map_rule);

            ret = sss_certmap_add_rule(sss_certmap_ctx,
                                       certmap_list[c]->priority,
                                       certmap_list[c]->match_rule,
                                       certmap_list[c]->map_rule,
                                       certmap_list[c]->domains);
            if (ret != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sss_certmap_add_rule failed for rule [%s] "
                      "with error [%d][%s], skipping. "
                      "Please check for typos and if rule syntax is supported.\n",
                      certmap_list[c]->name, ret, sss_strerror(ret));
                continue;
            }
            rule_added = true;
        }
    }

    if (!rule_added) {
        if (!rules_present) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "No rules available, trying to add default matching rule.\n");
            ret = sss_certmap_add_rule(sss_certmap_ctx, SSS_CERTMAP_MIN_PRIO,
                                       CERT_AUTH_DEFAULT_MATCHING_RULE,
                                       NULL, NULL);
            if (ret != 0) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to add default matching rule [%d][%s].\n",
                      ret, sss_strerror(ret));
                goto done;
            }
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "No matching rule added, please check "
                  "ssh_use_certificate_matching_rules option values for "
                  "typos.\n");

            ret = EINVAL;
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret == EOK) {
        sss_certmap_free_ctx(ssh_ctx->sss_certmap_ctx);
        ssh_ctx->sss_certmap_ctx = sss_certmap_ctx;
        ssh_ctx->certmap_last_read = ssh_ctx->rctx->get_domains_last_call.tv_sec;
    } else {
        sss_certmap_free_ctx(sss_certmap_ctx);
        ssh_ctx->cert_rules_error = true;
    }

    return ret;
}

static void ssh_cmd_get_user_pubkeys_done(struct tevent_req *subreq)
{
    struct cache_req_result *result;
    struct ssh_cmd_ctx *cmd_ctx;
    errno_t ret;
    struct ssh_ctx *ssh_ctx;

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

    ssh_ctx = talloc_get_type(cmd_ctx->cli_ctx->rctx->pvt_ctx, struct ssh_ctx);
    ret = ssh_cmd_refresh_certmap_ctx(ssh_ctx, cmd_ctx->cli_ctx->rctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ssh_cmd_refresh_certmap_ctx failed, "
              "certificate matching might not work as expected.\n");
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

    subreq = cache_req_ssh_host_id_by_name_send(cmd_ctx, cli_ctx->ev,
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
    struct ssh_cmd_ctx *cmd_ctx;
    errno_t ret;
#ifdef BUILD_SSH_KNOWN_HOSTS_PROXY
    struct sss_domain_info *domain;
    struct ssh_ctx *ssh_ctx;
#endif

    cmd_ctx = tevent_req_callback_data(subreq, struct ssh_cmd_ctx);

    ret = cache_req_ssh_host_id_by_name_recv(cmd_ctx, subreq, &result);
    talloc_zfree(subreq);

#ifdef BUILD_SSH_KNOWN_HOSTS_PROXY
    if (ret == EOK || ret == ENOENT) {
        ssh_ctx = talloc_get_type(cmd_ctx->cli_ctx->rctx->pvt_ctx, struct ssh_ctx);
        domain = ssh_get_result_domain(ssh_ctx->rctx, result, cmd_ctx->domain);

        ssh_update_known_hosts_file(ssh_ctx->rctx->domains, domain,
                                    cmd_ctx->name, ssh_ctx->hash_known_hosts,
                                    ssh_ctx->known_hosts_timeout);
    }
#endif

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
