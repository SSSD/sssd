/*
    SSSD

    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2017 Red Hat

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
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_deskprofile_private.h"
#include "providers/ipa/ipa_deskprofile_config.h"
#include "providers/ldap/sdap_async.h"

struct ipa_deskprofile_config_state {
    struct sysdb_attrs *config;
};

static void
ipa_deskprofile_get_config_done(struct tevent_req *subreq);

struct tevent_req *
ipa_deskprofile_get_config_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct sdap_handle *sh,
                                struct sdap_options *opts,
                                struct dp_option *ipa_opts)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq;
    struct ipa_deskprofile_rule_state *state;
    char *rule_filter;
    const char *attrs[] = { IPA_DESKPROFILE_PRIORITY, NULL };
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_deskprofile_config_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed.\n");
        return NULL;
    }

    rule_filter = talloc_asprintf(state, "(objectclass=%s)",
                                  IPA_DESKPROFILE_CONFIG);
    if (rule_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_get_generic_send(state, ev, opts, sh,
                                   dp_opt_get_string(ipa_opts,
                                                     IPA_DESKPROFILE_SEARCH_BASE),
                                   LDAP_SCOPE_BASE, rule_filter,
                                   attrs, NULL, 0,
                                   dp_opt_get_int(opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_get_generic_send failed.\n");
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_deskprofile_get_config_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
ipa_deskprofile_get_config_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_deskprofile_config_state *state;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    errno_t ret;


    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_deskprofile_config_state);

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not retrieve Desktop Profile config\n");
        goto done;
    }

    if (reply_count == 0) {
        /*
         * When connecting to an old server that doesn't support Desktop
         * Profile, the reply_count will be zero.
         * In order to not throw a unnecessary error and fail let's just
         * return ENOENT and print a debug message about it.
         */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Server doesn't support Desktop Profile.\n");
        ret = ENOENT;
        goto done;
    } else if (reply_count != 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unexpected number of results, expected 1, got %zu.\n",
              reply_count);
        ret = EINVAL;
        goto done;
    }

    state->config = reply[0];

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
ipa_deskprofile_get_config_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx,
                                struct sysdb_attrs **config)
{
    struct ipa_deskprofile_config_state *state;

    state = tevent_req_data(req, struct ipa_deskprofile_config_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *config = talloc_steal(mem_ctx, state->config);

    return EOK;
}
