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

#include <talloc.h>
#include <tevent.h>
#include <dhash.h>

#include "providers/ldap/sdap_ops.h"
#include "providers/ldap/sdap_sudo_shared.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_sudo.h"
#include "providers/ipa/ipa_dn.h"
#include "db/sysdb.h"
#include "db/sysdb_sudo.h"

struct ipa_hostinfo {
    size_t num_hosts;
    size_t num_hostgroups;
    struct sysdb_attrs **hosts;
    struct sysdb_attrs **hostgroups;
};

static char *
ipa_sudo_filter_append_origdn(char *filter,
                              struct sysdb_attrs *attrs,
                              const char *attr_name)
{
    const char *origdn;
    char *sanitizeddn;
    errno_t ret;

    ret = sysdb_attrs_get_string(attrs, SYSDB_ORIG_DN, &origdn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get original DN "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return NULL;
    }

    ret = sss_filter_sanitize(NULL, origdn, &sanitizeddn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to sanitize DN "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return NULL;
    }

    filter = talloc_asprintf_append(filter, "(%s=%s)", attr_name, sanitizeddn);
    talloc_free(sanitizeddn);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf_append() failed\n");
    }

    return filter;
}

/**
 * (|(hostCategory=ALL)(memberHost=$DN(fqdn))(memberHost=$DN(hostgroup))...)
 */
static char *
ipa_sudo_host_filter(TALLOC_CTX *mem_ctx,
                     struct ipa_hostinfo *host,
                     struct sdap_attr_map *map)
{
    TALLOC_CTX *tmp_ctx;
    char *filter;
    size_t i;

    /* If realloc fails we will free all data through tmp_ctx. */
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(!(%s=*))(%s=defaults))",
                             map[IPA_AT_SUDORULE_HOST].name,
                             map[IPA_AT_SUDORULE_NAME].name);
    if (filter == NULL) {
        goto fail;
    }

    /* Append hostCategory=ALL */
    filter = talloc_asprintf_append(filter, "(%s=ALL)",
                                    map[IPA_AT_SUDORULE_HOSTCATEGORY].name);
    if (filter == NULL) {
        goto fail;
    }

    /* Append client machine */
    for (i = 0; i < host->num_hosts; i++) {
        filter = ipa_sudo_filter_append_origdn(filter, host->hosts[i],
                                               map[IPA_AT_SUDORULE_HOST].name);
        if (filter == NULL) {
            goto fail;
        }
    }

    /* Append hostgroups */
    for (i = 0; i < host->num_hostgroups; i++) {
        filter = ipa_sudo_filter_append_origdn(filter, host->hostgroups[i],
                                               map[IPA_AT_SUDORULE_HOST].name);
        if (filter == NULL) {
            goto fail;
        }
    }

    /* OR filters */
    filter = talloc_asprintf(tmp_ctx, "(|%s)", filter);
    if (filter == NULL) {
        goto fail;
    }

    talloc_steal(mem_ctx, filter);
    talloc_free(tmp_ctx);
    return filter;

fail:
    talloc_free(tmp_ctx);
    return NULL;
}

static errno_t
ipa_sudo_highest_usn(TALLOC_CTX *mem_ctx,
                     struct sysdb_attrs **attrs,
                     size_t num_attrs,
                     char **current_usn)
{
    errno_t ret;
    char *usn;

    ret = sysdb_get_highest_usn(mem_ctx, attrs, num_attrs, &usn);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to get highest USN [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    if (sysdb_compare_usn(usn, *current_usn) > 0) {
        talloc_free(*current_usn);
        *current_usn = usn;
        return EOK;
    }

    talloc_free(usn);
    return EOK;
}

static errno_t
ipa_sudo_assoc_rules_filter(TALLOC_CTX *mem_ctx,
                            struct sysdb_attrs **cmdgroups,
                            size_t num_cmdgroups,
                            char **_filter)
{
    TALLOC_CTX *tmp_ctx;
    const char *origdn;
    char *sanitized;
    char *filter;
    errno_t ret;
    size_t i;

    if (num_cmdgroups == 0) {
        return ENOENT;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    filter = talloc_strdup(tmp_ctx, "");
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_cmdgroups; i++) {
        ret = sysdb_attrs_get_string(cmdgroups[i], SYSDB_ORIG_DN, &origdn);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get original dn [%d]: %s\n",
                  ret, sss_strerror(ret));
            ret = ERR_INTERNAL;
            goto done;
        }

        ret = sss_filter_sanitize(tmp_ctx, origdn, &sanitized);
        if (ret != EOK) {
            goto done;
        }

        filter = talloc_asprintf_append(filter, "(%s=%s)",
                                        SYSDB_IPA_SUDORULE_ORIGCMD, sanitized);
        if (filter == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    filter = talloc_asprintf(tmp_ctx, "(&(objectClass=%s)(|%s)))",
                             SYSDB_SUDO_CACHE_OC, filter);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_filter = talloc_steal(mem_ctx, filter);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ipa_sudo_assoc_rules(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
                     struct sysdb_attrs **cmdgroups,
                     size_t num_cmdgroups,
                     struct sysdb_attrs ***_rules,
                     size_t *_num_rules)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = {SYSDB_NAME, NULL};
    struct sysdb_attrs **rules;
    struct ldb_message **msgs;
    size_t num_rules;
    char *filter;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ipa_sudo_assoc_rules_filter(tmp_ctx, cmdgroups,
                                      num_cmdgroups, &filter);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              SUDORULE_SUBDIR, attrs,
                              &num_rules, &msgs);
    if (ret == ENOENT) {
        *_rules = NULL;
        *_num_rules = 0;
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up sudo rules [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_msg2attrs(tmp_ctx, num_rules, msgs, &rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not convert ldb message to "
              "sysdb_attrs [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_rules = talloc_steal(mem_ctx, rules);
    *_num_rules = num_rules;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ipa_sudo_filter_rules_bycmdgroups(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  struct sysdb_attrs **cmdgroups,
                                  size_t num_cmdgroups,
                                  struct sdap_attr_map *map_rule,
                                  char **_filter)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs **rules;
    size_t num_rules;
    const char *name;
    char *sanitized;
    char *filter;
    errno_t ret;
    size_t i;

    if (num_cmdgroups == 0) {
        *_filter = NULL;
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ipa_sudo_assoc_rules(tmp_ctx, domain, cmdgroups, num_cmdgroups,
                               &rules, &num_rules);
    if (ret != EOK) {
        goto done;
    }

    if (num_rules == 0) {
        *_filter = NULL;
        ret = EOK;
        goto done;
    }

    filter = talloc_strdup(tmp_ctx, "");
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_rules; i++) {
        ret = sysdb_attrs_get_string(rules[i], SYSDB_NAME, &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get name [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        ret = sss_filter_sanitize(tmp_ctx, name, &sanitized);
        if (ret != EOK) {
            goto done;
        }

        filter = talloc_asprintf_append(filter, "(%s=%s)",
                    map_rule[IPA_AT_SUDORULE_NAME].name, sanitized);
        if (filter == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    filter = talloc_asprintf(tmp_ctx, "(|%s)", filter);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_filter = talloc_steal(mem_ctx, filter);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct ipa_sudo_fetch_state {
    struct tevent_context *ev;
    struct sss_domain_info *domain;
    struct ipa_sudo_ctx *sudo_ctx;
    struct sdap_options *sdap_opts;
    struct ipa_hostinfo *host;
    struct sdap_handle *sh;
    const char *search_filter;
    const char *cmdgroups_filter;

    struct sdap_attr_map *map_cmdgroup;
    struct sdap_attr_map *map_rule;
    struct sdap_attr_map *map_cmd;
    struct sdap_search_base **sudo_sb;

    struct ipa_sudo_conv *conv;
    struct sysdb_attrs **rules;
    size_t num_rules;
    int cmd_threshold;
    char *usn;
};

static errno_t ipa_sudo_fetch_addtl_cmdgroups(struct tevent_req *req);
static void ipa_sudo_fetch_addtl_cmdgroups_done(struct tevent_req *subreq);
static errno_t ipa_sudo_fetch_rules(struct tevent_req *req);
static void ipa_sudo_fetch_rules_done(struct tevent_req *subreq);
static errno_t ipa_sudo_fetch_cmdgroups(struct tevent_req *req);
static void ipa_sudo_fetch_cmdgroups_done(struct tevent_req *subreq);
static errno_t ipa_sudo_fetch_cmds(struct tevent_req *req);
static void ipa_sudo_fetch_cmds_done(struct tevent_req *subreq);
static void ipa_sudo_fetch_done(struct tevent_req *req);

static struct tevent_req *
ipa_sudo_fetch_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct sss_domain_info *domain,
                    struct ipa_sudo_ctx *sudo_ctx,
                    struct ipa_hostinfo *host,
                    struct sdap_attr_map *map_user,
                    struct sdap_attr_map *map_group,
                    struct sdap_attr_map *map_host,
                    struct sdap_attr_map *map_hostgroup,
                    struct sdap_handle *sh,
                    const char *cmdgroups_filter,
                    const char *search_filter)
{
    struct ipa_sudo_fetch_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_sudo_fetch_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->domain = domain;
    state->sudo_ctx = sudo_ctx;
    state->sdap_opts = sudo_ctx->sdap_opts;
    state->host = host;
    state->sh = sh;
    state->search_filter = search_filter == NULL ? "" : search_filter;
    state->cmdgroups_filter = cmdgroups_filter;

    state->map_cmdgroup = sudo_ctx->sudocmdgroup_map;
    state->map_rule = sudo_ctx->sudorule_map;
    state->map_cmd = sudo_ctx->sudocmd_map;
    state->sudo_sb = sudo_ctx->sudo_sb;
    state->cmd_threshold = sudo_ctx->sudocmd_threshold;

    state->conv = ipa_sudo_conv_init(state, domain, state->map_rule,
                                     state->map_cmdgroup, state->map_cmd,
                                     map_user, map_group, map_host,
                                     map_hostgroup);
    if (state->conv == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (state->cmdgroups_filter != NULL) {
        /* We need to fetch additional cmdgroups that may not be revealed
         * during normal search. Such as when using entryUSN filter in smart
         * refresh, some command groups may have change but none rule was
         * modified but we need to fetch associated rules anyway. */
        ret = ipa_sudo_fetch_addtl_cmdgroups(req);
    } else {
        ret = ipa_sudo_fetch_rules(req);
    }
    if (ret != EAGAIN) {
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, state->ev);

    return req;
}

static errno_t
ipa_sudo_fetch_addtl_cmdgroups(struct tevent_req *req)
{
    struct ipa_sudo_fetch_state *state;
    struct tevent_req *subreq;
    struct sdap_attr_map *map;
    char *filter;

    DEBUG(SSSDBG_TRACE_FUNC, "About to fetch additional command groups\n");

    state = tevent_req_data(req, struct ipa_sudo_fetch_state);
    map = state->map_cmdgroup;

    filter = talloc_asprintf(state, "(&(objectClass=%s)%s)",
                             map[IPA_OC_SUDOCMDGROUP].name,
                             state->cmdgroups_filter);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build filter\n");
        return ENOMEM;
    }

    subreq = sdap_search_bases_send(state, state->ev, state->sdap_opts,
                                    state->sh, state->sudo_sb, map, true, 0,
                                    filter, NULL, NULL);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_sudo_fetch_addtl_cmdgroups_done, req);
    return EAGAIN;
}

static void
ipa_sudo_fetch_addtl_cmdgroups_done(struct tevent_req *subreq)
{
    struct ipa_sudo_fetch_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs **attrs;
    size_t num_attrs;
    char *filter;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_fetch_state);

    ret = sdap_search_bases_recv(subreq, state, &num_attrs, &attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Received %zu additional command groups\n",
          num_attrs);

    ret = ipa_sudo_filter_rules_bycmdgroups(state, state->domain, attrs,
                                            num_attrs, state->map_rule,
                                            &filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to construct rules filter "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    state->search_filter = sdap_or_filters(state, state->search_filter, filter);
    if (state->search_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ipa_sudo_fetch_rules(req);

done:
    if (ret == EOK) {
        ipa_sudo_fetch_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t
ipa_sudo_fetch_rules(struct tevent_req *req)
{
    struct ipa_sudo_fetch_state *state;
    struct tevent_req *subreq;
    struct sdap_attr_map *map;
    char *host_filter;
    char *filter;

    DEBUG(SSSDBG_TRACE_FUNC, "About to fetch sudo rules\n");

    state = tevent_req_data(req, struct ipa_sudo_fetch_state);
    map = state->map_rule;

    host_filter = ipa_sudo_host_filter(state, state->host, map);
    if (host_filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build host filter\n");
        return ENOMEM;
    }

    filter = talloc_asprintf(state, "(&(objectClass=%s)(%s=TRUE)%s%s)",
                             map[IPA_OC_SUDORULE].name,
                             map[IPA_AT_SUDORULE_ENABLED].name,
                             host_filter, state->search_filter);
    talloc_zfree(host_filter);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build filter\n");
        return ENOMEM;
    }

    subreq = sdap_search_bases_send(state, state->ev, state->sdap_opts,
                                    state->sh, state->sudo_sb, map, true, 0,
                                    filter, NULL, NULL);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_sudo_fetch_rules_done, req);
    return EAGAIN;
}

static void
ipa_sudo_fetch_rules_done(struct tevent_req *subreq)
{
    struct ipa_sudo_fetch_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs **attrs;
    size_t num_attrs;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_fetch_state);

    ret = sdap_search_bases_recv(subreq, state, &num_attrs, &attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Received %zu sudo rules\n", num_attrs);

    ret = ipa_sudo_conv_rules(state->conv, attrs, num_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed when converting rules "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = ipa_sudo_highest_usn(state, attrs, num_attrs, &state->usn);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_sudo_fetch_cmdgroups(req);

done:
    if (ret == EOK) {
        ipa_sudo_fetch_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t
ipa_sudo_fetch_cmdgroups(struct tevent_req *req)
{
    struct ipa_sudo_fetch_state *state;
    struct tevent_req *subreq;
    char *filter;

    DEBUG(SSSDBG_TRACE_FUNC, "About to fetch sudo command groups\n");

    state = tevent_req_data(req, struct ipa_sudo_fetch_state);

    if (ipa_sudo_conv_has_cmdgroups(state->conv)) {
        DEBUG(SSSDBG_TRACE_FUNC, "No command groups needs to be downloaded\n");
        return ipa_sudo_fetch_cmds(req);
    }

    filter = ipa_sudo_conv_cmdgroup_filter(state, state->conv,
                                           state->cmd_threshold);

    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build filter\n");
        return ENOMEM;
    }

    subreq = sdap_search_bases_send(state, state->ev, state->sdap_opts,
                                    state->sh, state->sudo_sb,
                                    state->map_cmdgroup, true, 0,
                                    filter, NULL, NULL);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_sudo_fetch_cmdgroups_done, req);
    return EAGAIN;
}

static void
ipa_sudo_fetch_cmdgroups_done(struct tevent_req *subreq)
{
    struct ipa_sudo_fetch_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs **attrs;
    size_t num_attrs;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_fetch_state);

    ret = sdap_search_bases_recv(subreq, state, &num_attrs, &attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Received %zu sudo command groups\n",
          num_attrs);

    ret = ipa_sudo_conv_cmdgroups(state->conv, attrs, num_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed when converting command groups "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = ipa_sudo_highest_usn(state, attrs, num_attrs, &state->usn);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_sudo_fetch_cmds(req);

done:
    if (ret == EOK) {
        ipa_sudo_fetch_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t
ipa_sudo_fetch_cmds(struct tevent_req *req)
{
    struct ipa_sudo_fetch_state *state;
    struct tevent_req *subreq;
    char *filter;

    DEBUG(SSSDBG_TRACE_FUNC, "About to fetch sudo commands\n");

    state = tevent_req_data(req, struct ipa_sudo_fetch_state);

    if (ipa_sudo_conv_has_cmds(state->conv)) {
        DEBUG(SSSDBG_TRACE_FUNC, "No commands needs to be downloaded\n");
        return EOK;
    }

    filter = ipa_sudo_conv_cmd_filter(state, state->conv, state->cmd_threshold);

    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build filter\n");
        return ENOMEM;
    }

    subreq = sdap_search_bases_send(state, state->ev, state->sdap_opts,
                                    state->sh, state->sudo_sb,
                                    state->map_cmd, true, 0,
                                    filter, NULL, NULL);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_sudo_fetch_cmds_done, req);
    return EAGAIN;
}

static void
ipa_sudo_fetch_cmds_done(struct tevent_req *subreq)
{
    struct ipa_sudo_fetch_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs **attrs;
    size_t num_attrs;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_fetch_state);

    ret = sdap_search_bases_recv(subreq, state, &num_attrs, &attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Received %zu sudo commands\n", num_attrs);

    ret = ipa_sudo_conv_cmds(state->conv, attrs, num_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed when converting commands "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret == EOK) {
        ipa_sudo_fetch_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void
ipa_sudo_fetch_done(struct tevent_req *req)
{
    struct ipa_sudo_fetch_state *state = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct ipa_sudo_fetch_state);

    DEBUG(SSSDBG_TRACE_FUNC, "About to convert rules\n");

    ret = ipa_sudo_conv_result(state, state->conv,
                               &state->rules, &state->num_rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to convert rules [%d]: %s\n",
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

static errno_t
ipa_sudo_fetch_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    struct sysdb_attrs ***_rules,
                    size_t *_num_rules,
                    char **_usn)
{
    struct ipa_sudo_fetch_state *state = NULL;
    state = tevent_req_data(req, struct ipa_sudo_fetch_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_rules = talloc_steal(mem_ctx, state->rules);
    *_num_rules = state->num_rules;
    *_usn = talloc_steal(mem_ctx, state->usn);

    return EOK;
}


struct ipa_sudo_refresh_state {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct ipa_sudo_ctx *sudo_ctx;
    struct ipa_options *ipa_opts;
    struct sdap_options *sdap_opts;
    const char *cmdgroups_filter;
    const char *search_filter;
    const char *delete_filter;
    bool update_usn;

    struct sdap_id_op *sdap_op;
    struct sdap_handle *sh;
    int dp_error;

    struct sysdb_attrs **rules;
    size_t num_rules;
};

static errno_t ipa_sudo_refresh_retry(struct tevent_req *req);
static void ipa_sudo_refresh_connect_done(struct tevent_req *subreq);
static void ipa_sudo_refresh_host_done(struct tevent_req *subreq);
static void ipa_sudo_refresh_done(struct tevent_req *subreq);

struct tevent_req *
ipa_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct ipa_sudo_ctx *sudo_ctx,
                      const char *cmdgroups_filter,
                      const char *search_filter,
                      const char *delete_filter,
                      bool update_usn)
{
    struct ipa_sudo_refresh_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ipa_sudo_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sudo_ctx->id_ctx->be->domain->sysdb;
    state->domain = sudo_ctx->id_ctx->be->domain;
    state->sudo_ctx = sudo_ctx;
    state->ipa_opts = sudo_ctx->ipa_opts;
    state->sdap_opts = sudo_ctx->sdap_opts;
    state->dp_error = DP_ERR_FATAL;
    state->update_usn = update_usn;

    state->sdap_op = sdap_id_op_create(state,
                                       sudo_ctx->id_ctx->conn->conn_cache);
    if (!state->sdap_op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    state->cmdgroups_filter = talloc_strdup(state, cmdgroups_filter);
    if (cmdgroups_filter != NULL && state->cmdgroups_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->search_filter = talloc_strdup(state, search_filter);
    if (search_filter != NULL && state->search_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    state->delete_filter = talloc_strdup(state, delete_filter);
    if (delete_filter != NULL && state->delete_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = ipa_sudo_refresh_retry(req);
    if (ret == EAGAIN) {
        /* asynchronous processing */
        return req;
    }

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, state->ev);

    return req;
}

static errno_t
ipa_sudo_refresh_retry(struct tevent_req *req)
{
    struct ipa_sudo_refresh_state *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct ipa_sudo_refresh_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send() failed: "
                                   "%d(%s)\n", ret, strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, ipa_sudo_refresh_connect_done, req);

    return EAGAIN;
}

static void
ipa_sudo_refresh_connect_done(struct tevent_req *subreq)
{
    struct ipa_sudo_refresh_state *state;
    const char *hostname;
    struct tevent_req *req;
    int dp_error;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_refresh_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "SUDO LDAP connection failed "
                                   "[%d]: %s\n", ret, strerror(ret));
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    state->sh = sdap_id_op_handle(state->sdap_op);

    DEBUG(SSSDBG_TRACE_FUNC, "SUDO LDAP connection successful\n");
    DEBUG(SSSDBG_TRACE_FUNC, "About to fetch host information\n");

    /* Obtain host information. */
    hostname = dp_opt_get_string(state->ipa_opts->basic, IPA_HOSTNAME);

    subreq = ipa_host_info_send(state, state->ev,
                                state->sh, state->sdap_opts, hostname,
                                state->ipa_opts->id->host_map,
                                state->ipa_opts->hostgroup_map,
                                state->ipa_opts->id->sdom->host_search_bases);
    if (subreq == NULL) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ipa_sudo_refresh_host_done, req);
}

static void
ipa_sudo_refresh_host_done(struct tevent_req *subreq)
{
    struct ipa_sudo_refresh_state *state;
    struct ipa_hostinfo *host;
    struct tevent_req *req;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_refresh_state);

    host = talloc_zero(state, struct ipa_hostinfo);
    if (host == NULL) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = ipa_host_info_recv(subreq, host, &host->num_hosts, &host->hosts,
                             &host->num_hostgroups, &host->hostgroups);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve host information "
                                 "[%d]: %s\n", ret, sss_strerror(ret));
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
        return;
    }

    subreq = ipa_sudo_fetch_send(state, state->ev, state->domain,
                                 state->sudo_ctx, host,
                                 state->sdap_opts->user_map,
                                 state->sdap_opts->group_map,
                                 state->ipa_opts->id->host_map,
                                 state->ipa_opts->hostgroup_map, state->sh,
                                 state->cmdgroups_filter, state->search_filter);
    if (subreq == NULL) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ipa_sudo_refresh_done, req);
}

static void
ipa_sudo_refresh_done(struct tevent_req *subreq)
{
    struct ipa_sudo_refresh_state *state;
    struct tevent_req *req;
    char *usn = NULL;
    bool in_transaction = false;
    errno_t sret;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_refresh_state);

    ret = ipa_sudo_fetch_recv(state, subreq, &state->rules,
                              &state->num_rules, &usn);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &state->dp_error);
    if (state->dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ipa_sudo_refresh_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    ret = sysdb_sudo_purge(state->domain, state->delete_filter,
                           state->rules, state->num_rules);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_sudo_store(state->domain, state->rules, state->num_rules);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    if (usn != NULL && state->update_usn) {
        sdap_sudo_set_usn(state->sudo_ctx->id_ctx->srv_opts, usn);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Sudo rules are successfully stored in cache\n");

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(state->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
ipa_sudo_refresh_recv(struct tevent_req *req,
                      int *dp_error,
                      size_t *_num_rules)
{
    struct ipa_sudo_refresh_state *state = NULL;
    state = tevent_req_data(req, struct ipa_sudo_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    if (_num_rules != NULL) {
        *_num_rules = state->num_rules;
    }

    return EOK;
}
