/*
    SSSD

    IPA Backend Module -- Session Management

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
#include <security/pam_modules.h>

#include "util/child_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_config.h"
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_session.h"
#include "providers/ipa/ipa_rules_common.h"
#include "providers/ipa/ipa_deskprofile_private.h"
#include "providers/ipa/ipa_deskprofile_config.h"
#include "providers/ipa/ipa_deskprofile_rules.h"
#include "providers/ipa/ipa_deskprofile_rules_util.h"
#include "sss_iface/sss_iface_async.h"


/* Those here are used for sending a message to the deskprofile client
 * informing that our side is done. */
#define SSS_FLEETCOMMANDERCLIENT_BUS "org.freedesktop.FleetCommanderClient"
#define SSS_FLEETCOMMANDERCLIENT_PATH "/org/freedesktop/FleetCommanderClient"
#define SSS_FLEETCOMMANDERCLIENT_IFACE "org.freedesktop.FleetCommanderClient"

#define MINUTE_IN_SECONDS 60

struct ipa_fetch_deskprofile_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct sdap_id_ctx *sdap_ctx;
    struct ipa_session_ctx *session_ctx;
    struct sdap_id_op *sdap_op;
    struct dp_option *ipa_options;
    struct sdap_search_base **search_bases;
    const char *username;

    /* Hosts */
    struct ipa_common_entries *hosts;
    struct sysdb_attrs *ipa_host;

    /* Rules */
    struct ipa_common_entries *rules;
    struct sysdb_attrs *config;
    uint16_t priority;
};

static errno_t ipa_fetch_deskprofile_retry(struct tevent_req *req);
static void ipa_fetch_deskprofile_connect_done(struct tevent_req *subreq);
static errno_t ipa_fetch_deskprofile_hostinfo(struct tevent_req *req);
static void ipa_fetch_deskprofile_hostinfo_done(struct tevent_req *subreq);
static void ipa_fetch_deskprofile_config_done(struct tevent_req *subreq);
static void ipa_fetch_deskprofile_rules_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_fetch_deskprofile_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct be_ctx *be_ctx,
                           struct ipa_session_ctx *session_ctx,
                           const char *username)
{
    struct ipa_fetch_deskprofile_state *state;
    struct tevent_req *req;
    time_t now;
    time_t refresh_interval;
    time_t request_interval;
    time_t next_request;
    bool offline;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_fetch_deskprofile_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->session_ctx = session_ctx;
    state->sdap_ctx = session_ctx->sdap_ctx;
    state->ipa_options = session_ctx->ipa_options;
    state->search_bases = session_ctx->deskprofile_search_bases;
    state->username = username;
    state->hosts = talloc_zero(state, struct ipa_common_entries);
    if (state->hosts == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    state->rules = talloc_zero(state, struct ipa_common_entries);
    if (state->rules == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    if (state->search_bases == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No Desktop Profile search base found.\n");
        ret = EINVAL;
        goto immediately;
    }

    state->sdap_op = sdap_id_op_create(state,
                                       state->sdap_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create() failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    now = time(NULL);

    request_interval = dp_opt_get_int(state->ipa_options,
                                      IPA_DESKPROFILE_REQUEST_INTERVAL);
    /* This value is in minutes ... */
    request_interval *= MINUTE_IN_SECONDS;

    if (state->session_ctx->no_rules_found &&
        now < session_ctx->last_request + request_interval) {
        next_request = (session_ctx->last_request + request_interval - now);
        /* This value is in seconds ... */
        next_request /= 60;
        DEBUG(SSSDBG_TRACE_FUNC,
              "No rules were found in the last request.\n"
              "Next request will happen in any login after %"SPRItime" minutes\n",
              next_request);
        ret = ENOENT;
        goto immediately;
    }

    state->session_ctx->no_rules_found = false;

    offline = be_is_offline(be_ctx);
    DEBUG(SSSDBG_TRACE_ALL, "Connection status is [%s].\n",
          offline ? "offline" : "online");

    refresh_interval = dp_opt_get_int(state->ipa_options,
                                      IPA_DESKPROFILE_REFRESH);

    if (offline || now < session_ctx->last_update + refresh_interval) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Performing cached Desktop Profile evaluation\n");
        ret = EOK;
        goto immediately;
    }

    ret = ipa_fetch_deskprofile_retry(req);
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
    tevent_req_post(req, ev);

    return req;
}

static errno_t
ipa_fetch_deskprofile_retry(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct ipa_fetch_deskprofile_state *state;
    int ret;

    state = tevent_req_data(req, struct ipa_fetch_deskprofile_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sdap_id_op_connect_send() failed: %d (%s)\n",
              ret, strerror(ret));

        return ret;
    }

    tevent_req_set_callback(subreq, ipa_fetch_deskprofile_connect_done, req);

    return EAGAIN;
}

static void
ipa_fetch_deskprofile_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_fetch_deskprofile_hostinfo(req);
    if (ret == EAGAIN) {
        return;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static errno_t
ipa_fetch_deskprofile_hostinfo(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct ipa_fetch_deskprofile_state *state;
    const char *hostname;

    state = tevent_req_data(req, struct ipa_fetch_deskprofile_state);
    hostname = dp_opt_get_string(state->ipa_options, IPA_HOSTNAME);

    subreq = ipa_host_info_send(state,
                                state->ev,
                                sdap_id_op_handle(state->sdap_op),
                                state->sdap_ctx->opts,
                                hostname,
                                state->session_ctx->host_map,
                                state->session_ctx->hostgroup_map,
                                state->session_ctx->host_search_bases);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_fetch_deskprofile_hostinfo_done, req);

    return EAGAIN;
}

static void
ipa_fetch_deskprofile_hostinfo_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_fetch_deskprofile_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_fetch_deskprofile_state);

    ret = ipa_host_info_recv(subreq, state,
                             &state->hosts->entry_count,
                             &state->hosts->entries,
                             &state->hosts->group_count,
                             &state->hosts->groups);
    state->hosts->entry_subdir = DESKPROFILE_HOSTS_SUBDIR;
    state->hosts->group_subdir = DESKPROFILE_HOSTGROUPS_SUBDIR;
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_get_host_attrs(state->ipa_options,
                             state->hosts->entry_count,
                             state->hosts->entries,
                             &state->ipa_host);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not locate IPA host.\n");
        goto done;
    }

    subreq = ipa_deskprofile_get_config_send(state,
                                             state->ev,
                                             sdap_id_op_handle(state->sdap_op),
                                             state->sdap_ctx->opts,
                                             state->ipa_options);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_fetch_deskprofile_config_done, req);
    return;

done:
    tevent_req_error(req, ret);
}

static void
ipa_fetch_deskprofile_config_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_fetch_deskprofile_state *state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_fetch_deskprofile_state);

    ret = ipa_deskprofile_get_config_recv(subreq, state, &state->config);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_store_custom(state->be_ctx->domain, IPA_DESKPROFILE_PRIORITY,
                             DESKPROFILE_CONFIG_SUBDIR, state->config);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to save Desktop Profile policy\n");
        goto done;
    }

    subreq = ipa_deskprofile_rule_info_send(state,
                                            state->ev,
                                            sdap_id_op_handle(state->sdap_op),
                                            state->sdap_ctx->opts,
                                            state->search_bases,
                                            state->ipa_host,
                                            state->be_ctx->domain,
                                            state->username);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_fetch_deskprofile_rules_done, req);
    return;

done:
    tevent_req_error(req, ret);
}

static void
ipa_fetch_deskprofile_rules_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_fetch_deskprofile_state *state;
    int dp_error;
    errno_t ret;
    bool found;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_fetch_deskprofile_state);

    ret = ipa_deskprofile_rule_info_recv(subreq,
                                         state,
                                         &state->rules->entry_count,
                                         &state->rules->entries);
    state->rules->entry_subdir = DESKPROFILE_RULES_SUBDIR;
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        /* Set ret to EOK so we can safely call sdap_id_op_done. */
        ret = EOK;
        found = false;
    } else if (ret == EOK) {
        found = true;
    } else {
        goto done;
    }

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ipa_fetch_deskprofile_retry(req);
        if (ret != EAGAIN) {
            tevent_req_error(req, ret);
        }
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

   /* For now, let's completely purge the previous stored
    * rules before saving the new ones */
    ret = ipa_common_purge_rules(state->be_ctx->domain,
                                 DESKPROFILE_RULES_SUBDIR);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to remove Desktop Profile rules\n");
        goto done;
    }

    if (!found) {
        ret = ENOENT;
        goto done;
    }

    ret = ipa_common_save_rules(state->be_ctx->domain,
                                state->hosts, NULL, state->rules,
                                &state->session_ctx->last_update);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to save Desktop Profile rules\n");
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
ipa_fetch_deskprofile_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_pam_session_handler_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct ipa_session_ctx *session_ctx;
    struct pam_data *pd;

    /* Those attributes are used for:
     * - saving the deskprofile rules to the disk;
     * - deleting the deskprofile rules from the disk;
     * - contacting the deskprofile client that everything is ready;
     */
    char *shortname;
    char *domain;
    char *user_dir;
    uid_t uid;
};

static errno_t
ipa_pam_session_handler_get_deskprofile_user_info(
                                                TALLOC_CTX *mem_ctx,
                                                struct sss_domain_info *domain,
                                                const char *username,
                                                char **_shortname,
                                                char **_domain,
                                                char **_user_dir,
                                                uid_t *uid);
static void ipa_pam_session_handler_done(struct tevent_req *subreq);
static errno_t
ipa_pam_session_handler_save_deskprofile_rules(
                                    struct be_ctx *be_ctx,
                                    struct sss_domain_info *domain,
                                    const char *username, /* fully-qualified */
                                    const char *user_dir,
                                    const char *hostname,
                                    uid_t uid);
static errno_t
ipa_pam_session_handler_notify_deskprofile_client(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  uid_t uid,
                                                  const char *user_dir,
                                                  uint16_t prio);


struct tevent_req *
ipa_pam_session_handler_send(TALLOC_CTX *mem_ctx,
                             struct ipa_session_ctx *session_ctx,
                             struct pam_data *pd,
                             struct dp_req_params *params)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_pam_session_handler_state *state;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Retrieving Desktop Profile rules\n");
    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_pam_session_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->ev = params->ev;
    state->be_ctx = params->be_ctx;
    state->session_ctx = session_ctx;

    /* Get all the user info that will be needed in order the delete the
     * user's deskprofile directory from the disk, create the user's directory,
     * save the fetched rules to the disk and notify the deskprofile client
     * that this operation is done. */
    ret = ipa_pam_session_handler_get_deskprofile_user_info(
                                                        state,
                                                        params->domain,
                                                        pd->user,
                                                        &state->shortname,
                                                        &state->domain,
                                                        &state->user_dir,
                                                        &state->uid);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ipa_deskprofile_get_user_info() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        state->pd->pam_status = PAM_SESSION_ERR;
        goto done;
    }

    /* As no proper merging mechanism has been implemented yet ...
     * let's just remove the user directory stored in the disk as it's
     * going to be created again in case there's any rule fetched. */
    ret = ipa_deskprofile_rules_remove_user_dir(state->user_dir);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ipa_deskprofile_rules_remove_user_dir() failed.\n");
        state->pd->pam_status = PAM_SESSION_ERR;
        goto done;
    }

    subreq = ipa_fetch_deskprofile_send(state, state->ev, state->be_ctx,
                                        state->session_ctx, pd->user);
    if (subreq == NULL) {
        state->pd->pam_status = PAM_SESSION_ERR;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_pam_session_handler_done, req);
    return req;

done:
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void
ipa_pam_session_handler_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_pam_session_handler_state *state;
    const char *hostname;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_pam_session_handler_state);

    ret = ipa_fetch_deskprofile_recv(subreq);
    talloc_free(subreq);

    if (ret == ENOENT) {
        DEBUG(SSSDBG_FUNC_DATA, "No Desktop Profile rules found\n");
        if (!state->session_ctx->no_rules_found) {
            state->session_ctx->no_rules_found = true;
            state->session_ctx->last_request = time(NULL);
        }
        state->pd->pam_status = PAM_SUCCESS;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to fetch Desktop Profile rules [%d]: %s\n",
              ret, sss_strerror(ret));
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    state->session_ctx->last_request = time(NULL);

    hostname = dp_opt_get_string(state->session_ctx->ipa_options, IPA_HOSTNAME);
    ret = ipa_pam_session_handler_save_deskprofile_rules(state->be_ctx,
                                                         state->be_ctx->domain,
                                                         state->pd->user,
                                                         state->user_dir,
                                                         hostname,
                                                         state->uid);

    if (ret == EOK || ret == ENOENT) {
        state->pd->pam_status = PAM_SUCCESS;
    } else {
        state->pd->pam_status = PAM_SESSION_ERR;
    }

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
ipa_pam_session_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data)
{
    struct ipa_pam_session_handler_state *state = NULL;

    state = tevent_req_data(req, struct ipa_pam_session_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}

static errno_t
ipa_pam_session_handler_get_deskprofile_user_info(TALLOC_CTX *mem_ctx,
                                                  struct sss_domain_info *domain,
                                                  const char *username,
                                                  char **_shortname,
                                                  char **_domain,
                                                  char **_user_dir,
                                                  uid_t *_uid)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res = NULL;
    char *shortname;
    char *domain_name;
    char *user_dir;
    uid_t uid;
    gid_t gid;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, username,
                                    &shortname, &domain_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Failed to parse \"%s\" [%d]: %s\n",
              username, ret, sss_strerror(ret));
        goto done;
    }

    user_dir = talloc_asprintf(tmp_ctx, IPA_DESKPROFILE_RULES_USER_DIR"/%s/%s",
                               domain_name, shortname);
    if (user_dir == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_getpwnam(tmp_ctx, domain, username, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_getpwnam() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (res->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_getpwnam() returned unexpected amount of users. "
              "Expected [%d], got [%d]\n", 1, res->count);
        ret = EINVAL;
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_UIDNUM, 0);
    gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM, 0);
    if (uid == 0 || gid == 0) {
        /* As IPA doesn't handle root users or groups, we know for sure that's
         * something wrong in case we get uid = 0 or gid = 0.
         */
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

    *_shortname = talloc_steal(mem_ctx, shortname);
    *_domain = talloc_steal(mem_ctx, domain_name);
    *_user_dir = talloc_steal(mem_ctx, user_dir);
    *_uid = uid;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ipa_pam_session_handler_save_deskprofile_rules(
                                    struct be_ctx *be_ctx,
                                    struct sss_domain_info *domain,
                                    const char *username, /* fully-qualified */
                                    const char *user_dir,
                                    const char *hostname,
                                    uid_t uid)
{
    TALLOC_CTX *tmp_ctx;
    const char **attrs_get_cached_rules;
    size_t rule_count;
    struct sysdb_attrs **rules;
    uint16_t priority;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Get Desktop Profile priority from sysdb */
    ret = deskprofile_get_cached_priority(be_ctx->domain, &priority);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_FUNC_DATA, "No Desktop Profile priority found in sysdb\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "deskprofile_get_cached_priority() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }


    /* Get Desktop Profile rules from sysdb */
    attrs_get_cached_rules = deskprofile_get_attrs_to_get_cached_rules(tmp_ctx);
    if (attrs_get_cached_rules == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "deskprofile_get_attrs_get_cached_rules() failed\n");
        ret = ENOMEM;
        goto done;
    }
    ret = ipa_common_get_cached_rules(tmp_ctx, be_ctx->domain,
                                      IPA_DESKPROFILE_RULE,
                                      DESKPROFILE_RULES_SUBDIR,
                                      attrs_get_cached_rules,
                                      &rule_count,
                                      &rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not retrieve Desktop Profile rules from the cache\n");
        goto done;
    }

    /* nothing to do for FC */
    if (!rule_count) {
        DEBUG(SSSDBG_FUNC_DATA, "No Desktop Profile rules found in sysdb\n");
        ret = ENOENT;
        goto done;
    }

    /* Create the user directory where the rules are going to be stored */
    ret = ipa_deskprofile_rules_create_user_dir(username);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot create the user directory [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Save the rules to the disk */
    for (size_t i = 0; i < rule_count; i++) {
        ret = ipa_deskprofile_rules_save_rule_to_disk(tmp_ctx,
                                                      priority,
                                                      rules[i],
                                                      domain,
                                                      hostname,
                                                      username);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to save a Desktop Profile Rule to disk [%d]: %s\n",
                  ret, sss_strerror(ret));
            continue;
        }
    }

    /* Notify FleetCommander that our side is done */
    ret = ipa_pam_session_handler_notify_deskprofile_client(be_ctx,
                                                            be_ctx->ev,
                                                            uid,
                                                            user_dir,
                                                            priority);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ipa_pam_session_handler_notify_deskprofile_client() "
              "failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void
ipa_pam_session_handler_notify_deskprofile_client_done(struct tevent_req *subreq);

static errno_t
ipa_pam_session_handler_notify_deskprofile_client(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  uid_t uid,
                                                  const char *user_dir,
                                                  uint16_t prio)
{
    struct sbus_connection *conn;
    struct tevent_req *subreq;

    conn = sbus_connect_system(mem_ctx, ev, NULL, NULL);
    if (conn == NULL) {
        return ENOMEM;
    }

    subreq = sbus_call_fleet_ProcessSSSDFiles_send(mem_ctx, conn,
                 SSS_FLEETCOMMANDERCLIENT_BUS, SSS_FLEETCOMMANDERCLIENT_PATH,
                 uid, user_dir, prio);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        talloc_free(conn);
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_pam_session_handler_notify_deskprofile_client_done,
                            conn);

    return EOK;
}

static void ipa_pam_session_handler_notify_deskprofile_client_done(struct tevent_req *subreq)
{
    struct sbus_connection *conn;
    errno_t ret;

    conn = tevent_req_callback_data(subreq, struct sbus_connection);

    ret = sbus_call_fleet_ProcessSSSDFiles_recv(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Error sending sbus message [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    talloc_free(conn);
}
