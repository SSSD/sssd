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
#include "providers/ldap/ldap_opts.h"
#include "providers/ipa/ipa_sudo.h"
#include "db/sysdb_sudo.h"

struct ipa_sudo_handler_state {
    uint32_t type;
    struct dp_reply_std reply;
    struct ipa_sudo_ctx *sudo_ctx;
};

static void ipa_sudo_handler_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_sudo_handler_send(TALLOC_CTX *mem_ctx,
                      struct ipa_sudo_ctx *sudo_ctx,
                      struct dp_sudo_data *data,
                      struct dp_req_params *params)
{
    struct ipa_sudo_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ipa_sudo_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->type = data->type;
    state->sudo_ctx = sudo_ctx;

    switch (data->type) {
    case BE_REQ_SUDO_FULL:
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing a full refresh of sudo rules\n");
        subreq = ipa_sudo_full_refresh_send(state, params->ev, sudo_ctx);
        break;
    case BE_REQ_SUDO_RULES:
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing a refresh of specific sudo rules\n");
        subreq = ipa_sudo_rules_refresh_send(state, params->ev, sudo_ctx,
                                             data->rules);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n", data->type);
        ret = EINVAL;
        goto immediately;
    }

    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request: %d\n", data->type);
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_sudo_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void ipa_sudo_handler_done(struct tevent_req *subreq)
{
    struct ipa_sudo_handler_state *state;
    struct tevent_req *req;
    int dp_error;
    bool deleted;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_handler_state);

    switch (state->type) {
    case BE_REQ_SUDO_FULL:
        ret = ipa_sudo_full_refresh_recv(subreq, &dp_error);
        talloc_zfree(subreq);

        /* Postpone the periodic task since the refresh was just finished
         * per user request. */
        if (ret == EOK && dp_error == DP_ERR_OK) {
            be_ptask_postpone(state->sudo_ctx->full_refresh);
        }
        break;
    case BE_REQ_SUDO_RULES:
        ret = ipa_sudo_rules_refresh_recv(subreq, &dp_error, &deleted);
        talloc_zfree(subreq);
        if (ret == EOK && deleted == true) {
            ret = ENOENT;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n", state->type);
        dp_error = DP_ERR_FATAL;
        ret = ERR_INTERNAL;
        break;
    }

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, dp_error, ret, NULL);
    tevent_req_done(req);
}

static errno_t
ipa_sudo_handler_recv(TALLOC_CTX *mem_ctx,
                      struct tevent_req *req,
                      struct dp_reply_std *data)
{
    struct ipa_sudo_handler_state *state = NULL;

    state = tevent_req_data(req, struct ipa_sudo_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}

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
ipa_sudo_init_ipa_schema(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         struct ipa_id_ctx *id_ctx,
                         struct dp_method *dp_methods)
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse attribute map (rule) "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sdap_get_map(sudo_ctx, be_ctx->cdb, be_ctx->conf_path,
                       ipa_sudocmdgroup_map, IPA_OPTS_SUDOCMDGROUP,
                       &sudo_ctx->sudocmdgroup_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse attribute map (cmdgroup) "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sdap_get_map(sudo_ctx, be_ctx->cdb, be_ctx->conf_path,
                       ipa_sudocmd_map, IPA_OPTS_SUDOCMD,
                       &sudo_ctx->sudocmd_map);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse attribute map (cmd) "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_int(be_ctx->cdb, CONFDB_SUDO_CONF_ENTRY,
                         CONFDB_SUDO_THRESHOLD, CONFDB_DEFAULT_SUDO_THRESHOLD,
                         &sudo_ctx->sudocmd_threshold);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not get sudo threshold\n");
        goto done;
    }

    ret = sdap_parse_search_base(sudo_ctx,
                                 sysdb_ctx_get_ldb(be_ctx->domain->sysdb),
                                 sudo_ctx->sdap_opts->basic,
                                 SDAP_SUDO_SEARCH_BASE,
                                 &sudo_ctx->sudo_sb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not parse sudo search base\n");
        goto done;
    }

    ret = ipa_sudo_ptask_setup(be_ctx, sudo_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup periodic tasks "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    dp_set_method(dp_methods, DPM_SUDO_HANDLER,
                  ipa_sudo_handler_send, ipa_sudo_handler_recv, sudo_ctx,
                  struct ipa_sudo_ctx, struct dp_sudo_data, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sudo_ctx);
    }

    return ret;
}

int ipa_sudo_init(TALLOC_CTX *mem_ctx,
                  struct be_ctx *be_ctx,
                  struct ipa_id_ctx *id_ctx,
                  struct dp_method *dp_methods)
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
        ret = ipa_sudo_init_ipa_schema(mem_ctx, be_ctx, id_ctx, dp_methods);
        break;
    case SUDO_SCHEMA_LDAP:
        DEBUG(SSSDBG_TRACE_FUNC, "Using LDAP schema for sudo\n");
        ret = sdap_sudo_init(mem_ctx,
                             be_ctx,
                             id_ctx->sdap_id_ctx,
                             native_sudorule_map,
                             dp_methods);
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize sudo provider"
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}
