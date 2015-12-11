/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include "providers/ipa/ipa_opts.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ipa/ipa_sudo.h"
#include "db/sysdb_sudo.h"

static void ipa_sudo_handler(struct be_req *breq);

struct bet_ops ipa_sudo_ops = {
    .handler = ipa_sudo_handler,
    .finalize = NULL,
};

enum sudo_schema {
    SUDO_SCHEMA_IPA,
    SUDO_SCHEMA_LDAP
};

static errno_t
ipa_sudo_choose_schema(struct dp_option *ipa_opts,
                       struct dp_option *sdap_opts,
                       enum sudo_schema *_schema)
{
    TALLOC_CTX *tmp_ctx;
    char *ipa_search_base;
    char *search_base;
    char *basedn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = domain_to_basedn(tmp_ctx, dp_opt_get_string(ipa_opts,
                           IPA_KRB5_REALM), &basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to obtain basedn\n");
        goto done;
    }

    ipa_search_base = talloc_asprintf(tmp_ctx, "cn=sudo,%s", basedn);
    if (ipa_search_base == NULL) {
        ret = ENOMEM;
        goto done;
    }

    search_base = dp_opt_get_string(sdap_opts, SDAP_SUDO_SEARCH_BASE);
    if (search_base == NULL) {
        ret = dp_opt_set_string(sdap_opts, SDAP_SUDO_SEARCH_BASE,
                                ipa_search_base);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
              sdap_opts[SDAP_SUDO_SEARCH_BASE].opt_name, ipa_search_base);

        search_base = ipa_search_base;
    }

    /* Use IPA schema only if search base is cn=sudo,$dc. */
    if (strcmp(ipa_search_base, search_base) == 0) {
        *_schema = SUDO_SCHEMA_IPA;
    } else {
        *_schema = SUDO_SCHEMA_LDAP;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int
ipa_sudo_init_ipa_schema(struct be_ctx *be_ctx,
                         struct ipa_id_ctx *id_ctx,
                         struct bet_ops **ops,
                         void **pvt_data)
{
    struct ipa_sudo_ctx *sudo_ctx;
    errno_t ret;

    sudo_ctx = talloc_zero(be_ctx, struct ipa_sudo_ctx);
    if (sudo_ctx == NULL) {
        return ENOMEM;
    }

    sudo_ctx->id_ctx = id_ctx->sdap_id_ctx;
    sudo_ctx->ipa_opts = id_ctx->ipa_options;
    sudo_ctx->sdap_opts = id_ctx->sdap_id_ctx->opts;

    ret = sdap_get_map(sudo_ctx, be_ctx->cdb, be_ctx->conf_path,
                       ipa_sudorule_map, IPA_OPTS_SUDORULE,
                       &sudo_ctx->sudorule_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse attribute map "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sdap_get_map(sudo_ctx, be_ctx->cdb, be_ctx->conf_path,
                       ipa_sudocmdgroup_map, IPA_OPTS_SUDOCMDGROUP,
                       &sudo_ctx->sudocmdgroup_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse attribute map "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sdap_get_map(sudo_ctx, be_ctx->cdb, be_ctx->conf_path,
                       ipa_sudocmd_map, IPA_OPTS_SUDOCMD,
                       &sudo_ctx->sudocmd_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse attribute map "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sdap_parse_search_base(sudo_ctx, sudo_ctx->sdap_opts->basic,
                                 SDAP_SUDO_SEARCH_BASE,
                                 &sudo_ctx->sudo_sb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not parse sudo search base\n");
        return ret;
    }

    ret = ipa_sudo_ptask_setup(be_ctx, sudo_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup periodic tasks "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *ops = &ipa_sudo_ops;
    *pvt_data = sudo_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sudo_ctx);
    }

    return ret;
}

int ipa_sudo_init(struct be_ctx *be_ctx,
                  struct ipa_id_ctx *id_ctx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    enum sudo_schema schema;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA sudo back end\n");

    ret = ipa_sudo_choose_schema(id_ctx->ipa_options->basic,
                                 id_ctx->ipa_options->id->basic,
                                 &schema);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to choose sudo schema [%d]: %s\n",
                                   ret, sss_strerror(ret));
        return ret;
    }

    switch (schema) {
    case SUDO_SCHEMA_IPA:
        DEBUG(SSSDBG_TRACE_FUNC, "Using IPA schema for sudo\n");
        ret = ipa_sudo_init_ipa_schema(be_ctx, id_ctx, ops, pvt_data);
        break;
    case SUDO_SCHEMA_LDAP:
        DEBUG(SSSDBG_TRACE_FUNC, "Using LDAP schema for sudo\n");
        ret = sdap_sudo_init(be_ctx, id_ctx->sdap_id_ctx, ops, pvt_data);
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize sudo provider"
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static void
ipa_sudo_reply(struct tevent_req *req)
{
    struct be_sudo_req *sudo_req;
    struct be_req *be_req;
    int dp_error;
    int ret;

    be_req = tevent_req_callback_data(req, struct be_req);
    sudo_req = talloc_get_type(be_req_get_data(be_req), struct be_sudo_req);

    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        ret = ipa_sudo_full_refresh_recv(req, &dp_error);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n",
                                    sudo_req->type);
        dp_error = DP_ERR_FATAL;
        ret = ERR_INTERNAL;
        break;
    }

    talloc_zfree(req);
    sdap_handler_done(be_req, dp_error, ret, sss_strerror(ret));
}

static void
ipa_sudo_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct ipa_sudo_ctx *sudo_ctx;
    struct be_sudo_req *sudo_req;
    struct tevent_req *req;
    int ret;

    if (be_is_offline(be_ctx)) {
        sdap_handler_done(be_req, DP_ERR_OFFLINE, EAGAIN, "Offline");
        return;
    }

    sudo_ctx = talloc_get_type(be_ctx->bet_info[BET_SUDO].pvt_bet_data,
                               struct ipa_sudo_ctx);

    sudo_req = talloc_get_type(be_req_get_data(be_req), struct be_sudo_req);

    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        req = ipa_sudo_full_refresh_send(be_req, be_ctx->ev, sudo_ctx);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n",
                                    sudo_req->type);
        ret = EINVAL;
        goto fail;
    }

    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request: %d\n",
                                    sudo_req->type);
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(req, ipa_sudo_reply, be_req);

    return;

fail:
    sdap_handler_done(be_req, DP_ERR_FATAL, ret, NULL);
}
