/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include "util/util.h"
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ldap/sdap_async.h"

struct ipa_hbac_rule_state {
    struct sdap_options *opts;

    size_t rule_count;
    struct sysdb_attrs **rules;
};

static void
ipa_hbac_rule_info_done(struct tevent_req *subreq);

struct tevent_req *
ipa_hbac_rule_info_send(TALLOC_CTX *mem_ctx,
                        bool get_deny_rules,
                        struct tevent_context *ev,
                        struct sysdb_ctx *sysdb,
                        struct sss_domain_info *dom,
                        struct sdap_handle *sh,
                        struct sdap_options *opts,
                        const char *search_base,
                        struct sysdb_attrs *ipa_host)
{
    errno_t ret;
    size_t i;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq;
    struct ipa_hbac_rule_state *state;
    TALLOC_CTX *tmp_ctx;
    const char *host_dn;
    char *host_dn_clean;
    char *host_group_clean;
    char *rule_filter;
    const char **memberof_list;
    const char *rule_attrs[] = { OBJECTCLASS,
                                 IPA_CN,
                                 IPA_UNIQUE_ID,
                                 IPA_ENABLED_FLAG,
                                 IPA_ACCESS_RULE_TYPE,
                                 IPA_MEMBER_USER,
                                 IPA_USER_CATEGORY,
                                 IPA_MEMBER_SERVICE,
                                 IPA_SERVICE_CATEGORY,
                                 IPA_SOURCE_HOST,
                                 IPA_SOURCE_HOST_CATEGORY,
                                 IPA_EXTERNAL_HOST,
                                 IPA_MEMBER_HOST,
                                 IPA_HOST_CATEGORY,
                                 NULL };

    if (ipa_host == NULL) {
        DEBUG(1, ("Missing host\n"));
        return NULL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) return NULL;

    ret = sysdb_attrs_get_string(ipa_host, SYSDB_ORIG_DN, &host_dn);
    if (ret != EOK) {
        DEBUG(1, ("Could not identify IPA hostname\n"));
        goto error;
    }

    ret = sss_filter_sanitize(tmp_ctx, host_dn, &host_dn_clean);
    if (ret != EOK) goto error;

    req = tevent_req_create(mem_ctx, &state, struct ipa_hbac_rule_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->opts = opts;

    if (get_deny_rules) {
        rule_filter = talloc_asprintf(tmp_ctx,
                                      "(&(objectclass=%s)"
                                      "(%s=%s)(|(%s=%s)(%s=%s)",
                                      IPA_HBAC_RULE,
                                      IPA_ENABLED_FLAG, IPA_TRUE_VALUE,
                                      IPA_HOST_CATEGORY, "all",
                                      IPA_MEMBER_HOST, host_dn_clean);
    } else {
        rule_filter = talloc_asprintf(tmp_ctx,
                                      "(&(objectclass=%s)"
                                      "(%s=%s)(%s=%s)"
                                      "(|(%s=%s)(%s=%s)",
                                      IPA_HBAC_RULE,
                                      IPA_ENABLED_FLAG, IPA_TRUE_VALUE,
                                      IPA_ACCESS_RULE_TYPE, IPA_HBAC_ALLOW,
                                      IPA_HOST_CATEGORY, "all",
                                      IPA_MEMBER_HOST, host_dn_clean);
    }
    if (rule_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    /* Add all parent groups of ipa_hostname to the filter */
    ret = sysdb_attrs_get_string_array(ipa_host, SYSDB_ORIG_MEMBEROF,
                                       tmp_ctx, &memberof_list);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(1, ("Could not identify "))
    } if (ret == ENOENT) {
        /* This host is not a member of any hostgroups */
        memberof_list = talloc_array(tmp_ctx, const char *, 1);
        if (memberof_list == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
        memberof_list[0] = NULL;
    }

    for (i = 0; memberof_list[i]; i++) {
        ret = sss_filter_sanitize(tmp_ctx,
                                  memberof_list[i],
                                  &host_group_clean);
        if (ret != EOK) goto immediate;

        rule_filter = talloc_asprintf_append(rule_filter, "(%s=%s)",
                                             IPA_MEMBER_HOST,
                                             host_group_clean);
        if (rule_filter == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
    }

    rule_filter = talloc_asprintf_append(rule_filter, "))");
    if (rule_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    talloc_steal(state, rule_filter);

    subreq = sdap_get_generic_send(state, ev, opts, sh, search_base,
                                   LDAP_SCOPE_SUB, rule_filter, rule_attrs,
                                   NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   true);
    if (subreq == NULL) {
        DEBUG(1, ("sdap_get_generic_send failed.\n"));
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ipa_hbac_rule_info_done, req);

    talloc_free(tmp_ctx);
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    talloc_free(tmp_ctx);
    return req;

error:
    talloc_free(tmp_ctx);
    return NULL;
}

static void
ipa_hbac_rule_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_hbac_rule_state *state =
            tevent_req_data(req, struct ipa_hbac_rule_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &state->rule_count,
                                &state->rules);
    if (ret != EOK) {
        DEBUG(3, ("Could not retrieve HBAC rules\n"));
        tevent_req_error(req, ret);
        return;
    } else if (state->rule_count == 0) {
        DEBUG(3, ("No rules apply to this host\n"));
        tevent_req_error(req, ENOENT);
        return;
    }

    tevent_req_done(req);
}

errno_t
ipa_hbac_rule_info_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        size_t *rule_count,
                        struct sysdb_attrs ***rules)
{
    struct ipa_hbac_rule_state *state =
            tevent_req_data(req, struct ipa_hbac_rule_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *rule_count = state->rule_count;
    *rules = talloc_steal(mem_ctx, state->rules);

    return EOK;
}
