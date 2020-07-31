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
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ipa/ipa_rules_common.h"
#include "providers/ipa/ipa_deskprofile_private.h"
#include "providers/ipa/ipa_deskprofile_rules.h"
#include "providers/ipa/ipa_deskprofile_rules_util.h"

struct ipa_deskprofile_rule_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    struct sdap_options *opts;

    int search_base_iter;
    struct sdap_search_base **search_bases;

    const char **attrs;
    char *rules_filter;
    char *cur_filter;

    size_t rule_count;
    struct sysdb_attrs **rules;
};

static errno_t
ipa_deskprofile_rule_info_next(struct tevent_req *req,
                               struct ipa_deskprofile_rule_state *state);
static void
ipa_deskprofile_rule_info_done(struct tevent_req *subreq);

struct tevent_req *
ipa_deskprofile_rule_info_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct sdap_handle *sh,
                               struct sdap_options *opts,
                               struct sdap_search_base **search_bases,
                               struct sysdb_attrs *ipa_host,
                               struct sss_domain_info *domain,
                               const char *username)
{
    struct tevent_req *req = NULL;
    struct ipa_deskprofile_rule_state *state;
    char *user;
    char *group;
    char *host_dn_clean;
    char *group_clean;
    char *host_group_clean;
    char *rule_filter;
    const char *host_dn;
    const char **memberof_list;
    char **groups_list;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ipa_deskprofile_rule_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    if (ipa_host == NULL) {
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing host\n");
        goto immediate;
    }

    ret = sysdb_attrs_get_string(ipa_host, SYSDB_ORIG_DN, &host_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not identify IPA hostname\n");
        goto immediate;
    }

    ret = sss_filter_sanitize_dn(state, host_dn, &host_dn_clean);
    if (ret != EOK) {
        goto immediate;
    }

    state->ev = ev;
    state->sh = sh;
    state->opts = opts;
    state->search_bases = search_bases;
    state->search_base_iter = 0;
    state->attrs = deskprofile_get_attrs_to_get_cached_rules(state);
    if (state->attrs == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "deskprofile_get_attrs_get_cached_rules() failed\n");
        goto immediate;
    }

    rule_filter = talloc_asprintf(state,
                                  "(&(objectclass=%s)"
                                  "(%s=%s)"
                                  "(|(%s=%s)(%s=%s)(%s=%s)",
                                  IPA_DESKPROFILE_RULE,
                                  IPA_ENABLED_FLAG, IPA_TRUE_VALUE,
                                  IPA_HOST_CATEGORY, "all",
                                  IPA_USER_CATEGORY, "all",
                                  IPA_MEMBER_HOST, host_dn_clean);
    if (rule_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    /* Add all parent groups of ipa_hostname to the filter */
    ret = sysdb_attrs_get_string_array(ipa_host, SYSDB_ORIG_MEMBEROF,
                                       state, &memberof_list);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not identify.\n");
    } else if (ret == ENOENT) {
        /* This host is not a member of any hostgroups */
        memberof_list = talloc_array(state, const char *, 1);
        if (memberof_list == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
        memberof_list[0] = NULL;
    }

    for (size_t i = 0; memberof_list[i] != NULL; i++) {
        ret = sss_filter_sanitize(state,
                                  memberof_list[i],
                                  &host_group_clean);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_filter_sanitize() failed [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto immediate;
        }

        rule_filter = talloc_asprintf_append(rule_filter, "(%s=%s)",
                                             IPA_MEMBER_HOST,
                                             host_group_clean);
        if (rule_filter == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
    }

    /* Add the username to the filter */
    ret = sss_parse_internal_fqname(state, username, &user, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_parse_internal_fqname() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    rule_filter = talloc_asprintf_append(rule_filter, "(%s=%s)",
                                         IPA_MEMBER_USER, user);
    if (rule_filter == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    /* Add all parent groups of `username` to the filter */
    ret = get_sysdb_grouplist(state, domain->sysdb, domain, username,
                              &groups_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "get_sysdb_grouplist() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    for (size_t i = 0; groups_list[i] != NULL; i++) {
        ret = sss_filter_sanitize(state, groups_list[i], &group_clean);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_filter_sanitize() failed [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto immediate;
        }

        ret = sss_parse_internal_fqname(state, group_clean, &group, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_parse_internal_fqname() failed [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto immediate;
        }

        rule_filter = talloc_asprintf_append(rule_filter, "(%s=%s)",
                                             IPA_MEMBER_USER, group);
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
    state->rules_filter = talloc_steal(state, rule_filter);

    ret = ipa_deskprofile_rule_info_next(req, state);
    if (ret != EAGAIN) {
        if (ret == EOK) {
            /* ipa_deskprofile_rule_info_next should always have a search base
             * when called for the first time.
             *
             * For the subsequent iterations, not finding any more search bases
             * is fine though (thus the function returns EOK).
             *
             * As, here, it's the first case happening, let's return EINVAL.
             */
            DEBUG(SSSDBG_CRIT_FAILURE, "No search base found\n");
            ret = EINVAL;
        }
        goto immediate;
    }

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t
ipa_deskprofile_rule_info_next(struct tevent_req *req,
                               struct ipa_deskprofile_rule_state *state)
{
    struct tevent_req *subreq;
    struct sdap_search_base *base;

    base = state->search_bases[state->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    talloc_zfree(state->cur_filter);
    state->cur_filter = sdap_combine_filters(state, state->rules_filter,
                                             base->filter);
    if (state->cur_filter == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Sending request for next search base: [%s][%d][%s]\n",
          base->basedn, base->scope, state->cur_filter);

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
                                   base->basedn, base->scope,
                                   state->cur_filter, state->attrs,
                                   NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_ENUM_SEARCH_TIMEOUT),
                                   true);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_get_generic_send failed.\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ipa_deskprofile_rule_info_done, req);

    return EAGAIN;
}

static void
ipa_deskprofile_rule_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req;
    struct ipa_deskprofile_rule_state *state;
    size_t rule_count;
    size_t total_count;
    struct sysdb_attrs **rules;
    struct sysdb_attrs **target;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_deskprofile_rule_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &rule_count,
                                &rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not retrieve Desktop Profile rules\n");
        goto fail;
    }

    if (rule_count > 0) {
        total_count = rule_count + state->rule_count;
        state->rules = talloc_realloc(state, state->rules,
                                      struct sysdb_attrs *,
                                      total_count);
        if (state->rules == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        i = 0;
        while (state->rule_count < total_count) {
            target = &state->rules[state->rule_count];
            *target = talloc_steal(state->rules, rules[i]);

            state->rule_count++;
            i++;
        }
    }

    state->search_base_iter++;
    ret = ipa_deskprofile_rule_info_next(req, state);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto fail;
    } else if (ret == EOK && state->rule_count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No rules apply to this host\n");
        tevent_req_error(req, ENOENT);
        return;
    }

    /* We went through all search bases and we have some results */
    tevent_req_done(req);

    return;

fail:
    tevent_req_error(req, ret);
}

errno_t
ipa_deskprofile_rule_info_recv(struct tevent_req *req,
                               TALLOC_CTX *mem_ctx,
                               size_t *_rule_count,
                               struct sysdb_attrs ***_rules)
{
    struct ipa_deskprofile_rule_state *state;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    state = tevent_req_data(req, struct ipa_deskprofile_rule_state);

    *_rule_count = state->rule_count;
    *_rules = talloc_steal(mem_ctx, state->rules);

    return EOK;
}
