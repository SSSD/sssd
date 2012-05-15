/*
    SSSD

    IPA Backend Module -- session loading

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

#include <security/pam_modules.h>

#include "db/sysdb_selinux.h"
#include "util/sss_selinux.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_config.h"
#include "providers/ipa/ipa_session.h"
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_hbac_rules.h"
#include "providers/ipa/ipa_selinux_common.h"
#include "providers/ipa/ipa_selinux_maps.h"

/* FIXME: this is temporary until host map is implemented in ipa_common.c */
#include "providers/ipa/ipa_hbac_private.h"

struct ipa_get_selinux_state {
    struct be_req *be_req;
    struct pam_data *pd;
    struct ipa_session_ctx *session_ctx;
    struct sdap_id_op *op;

    /* Just tmp stuff so we can free it after query */
    const char **attrs;

    const char *hostname;
    struct sysdb_attrs *host;
    struct sysdb_attrs *user;

    struct sysdb_attrs *defaults;

    struct sysdb_attrs **possible_match;
    struct sysdb_attrs **confirmed_match;
};

static struct
tevent_req *ipa_get_selinux_send(struct be_req *breq,
                                 struct pam_data *pd,
                                 struct ipa_session_ctx *session_ctx);
static void ipa_session_handler_done(struct tevent_req *subreq);
static errno_t ipa_get_selinux_recv(struct tevent_req *req,
                                    TALLOC_CTX *mem_ctx,
                                    size_t *count,
                                    struct sysdb_attrs ***maps,
                                    char **default_user,
                                    char **map_order);

static void ipa_get_selinux_connect_done(struct tevent_req *subreq);
static void ipa_get_selinux_hosts_done(struct tevent_req *subreq);
static void ipa_get_selinux_maps_done(struct tevent_req *subreq);
static void ipa_get_selinux_hbac_done(struct tevent_req *subreq);
static void ipa_get_selinux_config_done(struct tevent_req *subreq);

void ipa_session_handler(struct be_req *be_req)
{
    struct ipa_session_ctx *session_ctx;
    struct tevent_req *req;
    struct pam_data *pd;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    session_ctx = talloc_get_type(
                             be_req->be_ctx->bet_info[BET_SESSION].pvt_bet_data,
                             struct ipa_session_ctx);


    req = ipa_get_selinux_send(be_req, pd, session_ctx);
    if (req == NULL) {
        goto fail;
    }

    tevent_req_set_callback(req, ipa_session_handler_done, be_req);

    return;

fail:
    be_req->fn(be_req, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
}

static void ipa_session_handler_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    struct sysdb_ctx *sysdb = breq->be_ctx->sysdb;
    errno_t ret, sret;
    size_t map_count;
    struct sysdb_attrs **maps;
    bool in_transaction = false;
    char *default_user;
    struct pam_data *pd = talloc_get_type(breq->req_data, struct pam_data);
    char *map_order;

    ret = ipa_get_selinux_recv(req, breq, &map_count, &maps,
                               &default_user, &map_order);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) goto fail;
    in_transaction = true;

    if (default_user != NULL && map_order != NULL) {
        ret = sysdb_store_selinux_config(sysdb, default_user, map_order);
        if (ret != EOK) {
            goto fail;
        }
    }

    if (map_count > 0 && maps != NULL) {
        ret = ipa_save_user_maps(sysdb, map_count, maps);
        if (ret != EOK) {
            goto fail;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not commit transaction\n"));
        goto fail;
    }

    /* Just in case more code will follow after this place in the future */
    in_transaction = false;


    pd->pam_status = PAM_SUCCESS;
    breq->fn(breq, DP_ERR_OK, EOK, "Success");
    return;

fail:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not cancel transaction\n"));
        }
    }
    if (ret == EAGAIN) {
        breq->fn(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    } else {
        breq->fn(breq, DP_ERR_FATAL, ret, NULL);
    }
}

static struct tevent_req *ipa_get_selinux_send(struct be_req *breq,
                                               struct pam_data *pd,
                                               struct ipa_session_ctx *session_ctx)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct be_ctx *bctx = breq->be_ctx;
    struct ipa_get_selinux_state *state;
    bool offline;
    int ret = EOK;

    DEBUG(SSSDBG_TRACE_FUNC, ("Retrieving SELinux user mapping\n"));
    req = tevent_req_create(breq, &state, struct ipa_get_selinux_state);
    if (req == NULL) {
        return NULL;
    }

    state->be_req = breq;
    state->pd = pd;
    state->session_ctx = session_ctx;

    offline = be_is_offline(bctx);
    DEBUG(SSSDBG_TRACE_INTERNAL, ("Connection status is [%s].\n",
                                  offline ? "offline" : "online"));

    if (!offline) {
        state->op = sdap_id_op_create(state, session_ctx->id_ctx->sdap_id_ctx->conn_cache);
        if (!state->op) {
            DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed\n"));
            ret = ENOMEM;
            goto immediate;
        }

        subreq = sdap_id_op_connect_send(state->op, state, &ret);
        if (!subreq) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("sdap_id_op_connect_send failed: "
                                        "%d(%s).\n", ret, strerror(ret)));
            talloc_zfree(state->op);
            goto immediate;
        }

        tevent_req_set_callback(subreq, ipa_get_selinux_connect_done, req);
    } else {
        ret = EAGAIN;
        goto immediate;
    }

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, bctx->ev);
    return req;
}

static void ipa_get_selinux_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    struct ipa_id_ctx *id_ctx = state->session_ctx->id_ctx;
    struct be_ctx *bctx = state->be_req->be_ctx;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(state->op);
        ret = EAGAIN;
    }

    if (ret != EOK) {
        goto fail;
    }

    state->hostname = dp_opt_get_string(state->session_ctx->id_ctx->ipa_options->basic,
                                        IPA_HOSTNAME);

    /* FIXME: detect if HBAC is configured
     * - if yes, we can skip host retrieval and get it directly from sysdb
     */
    state->attrs = talloc_array(state, const char *, 3);
    if (state->attrs == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    state->attrs[0] = "objectClass";
    state->attrs[1] = IPA_MEMBEROF;
    state->attrs[2] = NULL;

    subreq = ipa_host_info_send(state, bctx->ev, bctx->sysdb,
                                sdap_id_op_handle(state->op),
                                id_ctx->sdap_id_ctx->opts,
                                state->hostname,
                                state->attrs, NULL, 0,
                                false, state->session_ctx->host_search_bases);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_get_selinux_hosts_done, req);

    return;

fail:
    tevent_req_error(req, ret);
}

static void ipa_get_selinux_hosts_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    struct be_ctx *bctx = state->be_req->be_ctx;
    struct sdap_id_ctx *id_ctx = state->session_ctx->id_ctx->sdap_id_ctx;
    size_t host_count, hostgroup_count;
    struct sysdb_attrs **hostgroups;
    struct sysdb_attrs **host;

    ret = ipa_host_info_recv(subreq, state, &host_count, &host,
                             &hostgroup_count, &hostgroups);
    talloc_free(subreq);
    if (ret != EOK) {
        goto done;
    }
    state->host = host[0];

    ret = sysdb_attrs_add_string(state->host, SYSDB_NAME, state->hostname);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_selinux_extract_user(state, bctx->sysdb,
                                   state->pd->user, &state->user);
    if (ret != EOK) {
        goto done;
    }

    subreq = ipa_selinux_get_maps_send(state, bctx->ev, bctx->sysdb,
                                       sdap_id_op_handle(state->op),
                                       id_ctx->opts,
                                       state->session_ctx->selinux_search_bases);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_get_selinux_maps_done, req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void ipa_get_selinux_maps_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_get_selinux_state *state;

    struct be_ctx *bctx;
    struct ipa_id_ctx *id_ctx;

    struct sysdb_attrs **results;
    size_t count;
    const char *domain;
    const char *tmp_str;
    size_t conf_cnt = 0;
    size_t pos_cnt = 0;
    errno_t ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_get_selinux_state);
    bctx = state->be_req->be_ctx;
    id_ctx = state->session_ctx->id_ctx;

    ret = ipa_selinux_get_maps_recv(subreq, state, &count, &results);
    talloc_free(subreq);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* This is returned if no SELinux mapping
             * rules were found. In that case no error
             * occurred, but we don't want any more processing.*/
            ret = EOK;
        }
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Found %d SELinux user maps in total, "
                              "filtering ...\n", count));
    state->confirmed_match = talloc_zero_array(state, struct sysdb_attrs *,
                                               count + 1);
    state->possible_match = talloc_zero_array(state, struct sysdb_attrs *,
                                              count + 1);
    if (state->confirmed_match == NULL || state->possible_match == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        if (sss_selinux_match(results[i], state->user, state->host)) {
            state->confirmed_match[conf_cnt] = talloc_steal(state->confirmed_match,
                                                            results[i]);
            conf_cnt++;
            continue;
        }

        ret = sysdb_attrs_get_string(results[i], SYSDB_SELINUX_SEEALSO, &tmp_str);
        if (ret == ENOENT) {
            continue;
        }

        state->possible_match[pos_cnt] = talloc_steal(state->possible_match,
                                                      results[i]);
        pos_cnt++;
    }
    DEBUG(SSSDBG_TRACE_FUNC, ("Filtering done. Results: %d confirmed and %d "
                              "possible maps remained.\n", conf_cnt, pos_cnt));

    /* Don't shrink the confirmed list, it could be later filled by HBAC rules */
    state->possible_match = talloc_realloc(state, state->possible_match,
                                           struct sysdb_attrs *, pos_cnt + 1);
    if (state->possible_match == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* This will free all rules that are neither confirmed nor possible */
    talloc_free(results);

    if (pos_cnt) {
        /* FIXME: detect if HBAC is configured
         * - if yes, we can skip HBAC retrieval and get it directly from sysdb
         */
        subreq = ipa_hbac_rule_info_send(state, false, bctx->ev,
                                         sdap_id_op_handle(state->op),
                                         id_ctx->sdap_id_ctx->opts,
                                         state->session_ctx->hbac_search_bases,
                                         state->host);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, ipa_get_selinux_hbac_done, req);
        return;
    }

    domain = dp_opt_get_string(state->session_ctx->id_ctx->ipa_options->basic,
                               IPA_KRB5_REALM);
    subreq = ipa_get_config_send(state, bctx->ev,
                                 sdap_id_op_handle(state->op),
                                 id_ctx->sdap_id_ctx->opts,
                                 domain, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_get_selinux_config_done, req);

    return;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static void ipa_get_selinux_hbac_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    struct be_ctx *bctx = state->be_req->be_ctx;
    struct ipa_id_ctx *id_ctx = state->session_ctx->id_ctx;
    struct sysdb_attrs **rules;
    struct sysdb_attrs *usermap;
    const char *hbac_dn;
    const char *seealso_dn;
    const char *domain;
    size_t rule_count;
    size_t conf_cnt;
    size_t pos_cnt;
    errno_t ret;
    int i, j;

    ret = ipa_hbac_rule_info_recv(subreq, state, &rule_count,
                                  &rules);
    talloc_free(subreq);
    if (ret != EOK) {
        goto done;
    }
    for (conf_cnt = 0 ; state->confirmed_match[conf_cnt]; conf_cnt++) ;
    for (pos_cnt = 0 ; state->possible_match[pos_cnt]; pos_cnt++) ;

    for (i = 0; i < rule_count; i++) {
        if (!sss_selinux_match(rules[i], state->user, state->host)) {
            continue;
        }

        ret = sysdb_attrs_get_string(rules[i], SYSDB_ORIG_DN, &hbac_dn);
        if (ret != EOK) {
            goto done;
        }

        /* HBAC rule matched, find if it is in the "possible" list */
        for (j = 0; state->possible_match[j]; j++) {
            usermap = state->possible_match[j];
            if (usermap == NULL) {
                continue;
            }

            ret = sysdb_attrs_get_string(usermap, SYSDB_SELINUX_SEEALSO, &seealso_dn);
            if (ret != EOK) {
                goto done;
            }

            if (strcasecmp(hbac_dn, seealso_dn) == 0) {
                state->confirmed_match[conf_cnt++] = talloc_steal(
                                                        state->confirmed_match,
                                                        usermap);
                /* Just to boost the following lookup */
                state->possible_match[j] = NULL;

                ret = ipa_selinux_map_merge(usermap, rules[i], SYSDB_ORIG_MEMBER_USER);
                if (ret != EOK) {
                    goto done;
                }

                ret = ipa_selinux_map_merge(usermap, rules[i], SYSDB_ORIG_MEMBER_HOST);
                if (ret != EOK) {
                    goto done;
                }
            }
        }
    }

    /* Now we can dispose all possible rules, since they aren't possible any more */
    talloc_zfree(state->possible_match);

    domain = dp_opt_get_string(state->session_ctx->id_ctx->ipa_options->basic,
                               IPA_KRB5_REALM);
    subreq = ipa_get_config_send(state, bctx->ev,
                                 sdap_id_op_handle(state->op),
                                 id_ctx->sdap_id_ctx->opts,
                                 domain, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_get_selinux_config_done, req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void ipa_get_selinux_config_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    errno_t ret;

    ret = ipa_get_config_recv(subreq, state, &state->defaults);
    talloc_free(subreq);
    if (ret != EOK) {
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

static errno_t
ipa_get_selinux_recv(struct tevent_req *req,
                     TALLOC_CTX *mem_ctx,
                     size_t *count,
                     struct sysdb_attrs ***maps,
                     char **default_user,
                     char **map_order)
{
    struct ipa_get_selinux_state *state =
            tevent_req_data(req, struct ipa_get_selinux_state);
    const char *tmp_str;
    errno_t ret;
    int i;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->defaults != NULL) {
        ret = sysdb_attrs_get_string(state->defaults, IPA_CONFIG_SELINUX_DEFAULT_MAP,
                                     &tmp_str);
        if (ret != EOK) {
            return ret;
        }

        *default_user = talloc_strdup(mem_ctx, tmp_str);
        if (*default_user == NULL) {
            return ENOMEM;
        }

        ret = sysdb_attrs_get_string(state->defaults, IPA_CONFIG_SELINUX_MAP_ORDER,
                                     &tmp_str);
        if (ret != EOK) {
            return ret;
        }

        *map_order = talloc_strdup(mem_ctx, tmp_str);
        if (*map_order == NULL) {
            talloc_zfree(*default_user);
            return ENOMEM;
        }
    } else {
        *map_order = NULL;
        *default_user = NULL;
    }

    if (state->confirmed_match != NULL) {
        for (i = 0; state->confirmed_match[i]; i++) ;

        *count = i;
        *maps = talloc_steal(mem_ctx, state->confirmed_match);
    } else {
        *count = 0;
        *maps = NULL;
    }

    return EOK;
}
