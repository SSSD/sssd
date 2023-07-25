/*
    SSSD

    IPA Subdomains Passkey Module

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2022 Red Hat

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
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_ops.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_opts.h"
#include "providers/ipa/ipa_config.h"
#include "providers/ipa/ipa_subdomains_passkey.h"
#include "db/sysdb_passkey_user_verification.h"

#include <ctype.h>
#define IPA_PASSKEY_VERIFICATION "ipaRequireUserVerification"
#define IPA_PASSKEY_CONFIG_FILTER "cn=passkeyconfig"

void ipa_subdomains_passkey_done(struct tevent_req *subreq);

struct tevent_req *
ipa_subdomains_passkey_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ipa_subdomains_ctx *sd_ctx,
                           struct sdap_handle *sh)
{
    struct ipa_subdomains_passkey_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;
    const char *attrs[] = { IPA_PASSKEY_VERIFICATION, NULL };

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_subdomains_passkey_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->domain = sd_ctx->be_ctx->domain;
    state->sdap_opts = sd_ctx->sdap_id_ctx->opts;

    subreq = ipa_get_config_send(state, ev, sh, sd_ctx->sdap_id_ctx->opts,
                                 state->domain->name, attrs, IPA_PASSKEY_CONFIG_FILTER, NULL);

    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_subdomains_passkey_done, req);

    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

void ipa_subdomains_passkey_done(struct tevent_req *subreq)
{
    struct ipa_subdomains_passkey_state *state;
    struct tevent_req *req;
    struct sysdb_attrs *config;
    const char *user_verification = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_subdomains_passkey_state);

    ret = ipa_get_config_recv(subreq, state, &config);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to get data from LDAP [%d]: %s\n",
                        ret, sss_strerror(ret));
        goto done;
    }

    if (config != NULL) {
        ret = sysdb_attrs_get_string(config, IPA_PASSKEY_VERIFICATION,
                                     &user_verification);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_ALL, "Retrieved [%s] from [%s] attribute.\n",
                                    user_verification, IPA_PASSKEY_VERIFICATION);
        }
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to get passkey user verification "
                  "value [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        } else if (ret == ENOENT) {
            user_verification = NULL;
        }
    }

    ret = sysdb_domain_update_passkey_user_verification(
                        state->domain->sysdb, state->domain->name,
                        user_verification);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_domain_passkey_user_verification() [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t ipa_subdomains_passkey_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
