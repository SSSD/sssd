/*
    SSSD

    IPA Backend Module -- configuration retrieval

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "providers/ipa/ipa_config.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ldap/sdap_async.h"

struct ipa_get_config_state {
    char *base;
    const char **attrs;

    struct sysdb_attrs *config;
};

static void ipa_get_config_done(struct tevent_req *subreq);

struct tevent_req *
ipa_get_config_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct sdap_handle *sh,
                    struct sdap_options *opts,
                    const char *domain,
                    const char **attrs,
                    const char *filter,
                    const char *base)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_get_config_state *state;
    errno_t ret;
    char *ldap_basedn;

    req = tevent_req_create(mem_ctx, &state, struct ipa_get_config_state);
    if (req == NULL) {
        return NULL;
    }

    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Requested attributes must be provided.\n");
        ret = EINVAL;
        goto done;
    }
    state->attrs = attrs;

    if (filter == NULL) {
        filter = IPA_CONFIG_FILTER;
    }

    ret = domain_to_basedn(state, domain, &ldap_basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "domain_to_basedn failed.\n");
        goto done;
    }

    if (base == NULL) {
        base = IPA_CONFIG_SEARCH_BASE_TEMPLATE;
    }
    state->base = talloc_asprintf(state, base, ldap_basedn);
    if (state->base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_get_generic_send(state, ev, opts,
                                   sh, state->base,
                                   LDAP_SCOPE_SUBTREE, filter,
                                   state->attrs, NULL, 0,
                                   dp_opt_get_int(opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_get_config_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ipa_get_config_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_config_state *state = tevent_req_data(req,
                                            struct ipa_get_config_state);
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    errno_t ret;

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret) {
        goto done;
    }

    if (reply_count > 1) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unexpected number of results: %zu.\n",
              reply_count);
        ret = EINVAL;
        goto done;
    } else if (reply_count == 0) {
        ret = ENOENT;
        goto done;
    }

    state->config = reply[0];

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

errno_t ipa_get_config_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct sysdb_attrs **config)
{
    struct ipa_get_config_state *state = tevent_req_data(req,
                                              struct ipa_get_config_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *config = talloc_steal(mem_ctx, state->config);

    return EOK;
}
