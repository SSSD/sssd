/*
    SSSD

    IPA Backend Module -- selinux loading

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
#include "providers/ipa/ipa_selinux.h"
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_hbac_rules.h"
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_selinux_common.h"
#include "providers/ipa/ipa_selinux_maps.h"

struct ipa_get_selinux_state {
    struct be_req *be_req;
    struct pam_data *pd;
    struct ipa_selinux_ctx *selinux_ctx;
    struct sdap_id_op *op;

    const char *hostname;
    struct sysdb_attrs *host;
    struct sysdb_attrs *user;

    struct sysdb_attrs *defaults;
    struct sysdb_attrs **selinuxmaps;
    size_t nmaps;

    struct sysdb_attrs **possible_match;
    size_t possible_matches;
};

static struct
tevent_req *ipa_get_selinux_send(struct be_req *breq,
                                 struct pam_data *pd,
                                 struct ipa_selinux_ctx *selinux_ctx);
static void ipa_selinux_handler_done(struct tevent_req *subreq);
static errno_t ipa_get_selinux_recv(struct tevent_req *req,
                                    TALLOC_CTX *mem_ctx,
                                    size_t *count,
                                    struct sysdb_attrs ***maps,
                                    char **default_user,
                                    char **map_order);

static void ipa_get_selinux_connect_done(struct tevent_req *subreq);
static void ipa_get_selinux_hosts_done(struct tevent_req *subreq);
static void ipa_get_config_step(struct tevent_req *req);
static void ipa_get_selinux_config_done(struct tevent_req *subreq);
static void ipa_get_selinux_maps_done(struct tevent_req *subreq);
static void ipa_get_selinux_hbac_done(struct tevent_req *subreq);
static int
ipa_get_selinux_hbac_process(struct ipa_get_selinux_state *state,
                             struct sysdb_attrs **rules,
                             size_t rule_count);

void ipa_selinux_handler(struct be_req *be_req)
{
    struct ipa_selinux_ctx *selinux_ctx;
    struct tevent_req *req;
    struct pam_data *pd;

    pd = talloc_get_type(be_req->req_data, struct pam_data);

    selinux_ctx = talloc_get_type(
                             be_req->be_ctx->bet_info[BET_SELINUX].pvt_bet_data,
                             struct ipa_selinux_ctx);


    req = ipa_get_selinux_send(be_req, pd, selinux_ctx);
    if (req == NULL) {
        goto fail;
    }

    tevent_req_set_callback(req, ipa_selinux_handler_done, be_req);

    return;

fail:
    be_req->fn(be_req, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
}

static void ipa_selinux_handler_done(struct tevent_req *req)
{
    struct be_req *breq = tevent_req_callback_data(req, struct be_req);
    struct sysdb_ctx *sysdb = breq->be_ctx->sysdb;
    errno_t ret, sret;
    size_t map_count = 0;
    struct sysdb_attrs **maps = NULL;
    bool in_transaction = false;
    char *default_user = NULL;
    struct pam_data *pd = talloc_get_type(breq->req_data, struct pam_data);
    char *map_order = NULL;

    ret = ipa_get_selinux_recv(req, breq, &map_count, &maps,
                               &default_user, &map_order);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    ret = sysdb_delete_usermaps(breq->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot delete existing maps from sysdb\n"));
        goto fail;
    }

    ret = sysdb_store_selinux_config(sysdb, default_user, map_order);
    if (ret != EOK) {
        goto fail;
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
                                               struct ipa_selinux_ctx *selinux_ctx)
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
    state->selinux_ctx = selinux_ctx;

    offline = be_is_offline(bctx);
    DEBUG(SSSDBG_TRACE_INTERNAL, ("Connection status is [%s].\n",
                                  offline ? "offline" : "online"));

    if (!offline) {
        state->op = sdap_id_op_create(state, selinux_ctx->id_ctx->sdap_id_ctx->conn_cache);
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
    struct ipa_id_ctx *id_ctx = state->selinux_ctx->id_ctx;
    struct be_ctx *bctx = state->be_req->be_ctx;

    const char *access_name;
    const char *selinux_name;
    struct ldb_dn *host_dn;
    const char *attrs[] = { SYSDB_ORIG_DN,
                            SYSDB_ORIG_MEMBEROF,
                            NULL };
    size_t count;
    struct ldb_message **msgs;
    struct sysdb_attrs **hosts;
    struct sss_domain_info *domain;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(state->op);
        ret = EAGAIN;
    }

    if (ret != EOK) {
        goto fail;
    }

    state->hostname = dp_opt_get_string(state->selinux_ctx->id_ctx->ipa_options->basic,
                                        IPA_HOSTNAME);

    access_name = state->be_req->be_ctx->bet_info[BET_ACCESS].mod_name;
    selinux_name = state->be_req->be_ctx->bet_info[BET_SELINUX].mod_name;
    if (strcasecmp(access_name, selinux_name) == 0) {
        domain = sysdb_ctx_get_domain(bctx->sysdb);
        host_dn = sysdb_custom_dn(bctx->sysdb, state, domain->name,
                                  state->hostname, HBAC_HOSTS_SUBDIR);
        if (host_dn == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        /* Look up the host to get its originalMemberOf entries */
        ret = sysdb_search_entry(state, bctx->sysdb, host_dn,
                                 LDB_SCOPE_BASE, NULL,
                                 attrs, &count, &msgs);
        if (ret == ENOENT || count == 0) {
            /* We need to query the server */
            goto server;
        } else if (ret != EOK) {
            goto fail;
        } else if (count > 1) {
            DEBUG(SSSDBG_OP_FAILURE, ("More than one result for a BASE search!\n"));
            ret = EIO;
            goto fail;
        }

        ret = sysdb_msg2attrs(state, count, msgs, &hosts);
        if (ret != EOK) {
            goto fail;
        }

        state->host = hosts[0];
        return ipa_get_config_step(req);
    }

server:
    subreq = ipa_host_info_send(state, bctx->ev, bctx->sysdb,
                                sdap_id_op_handle(state->op),
                                id_ctx->sdap_id_ctx->opts,
                                state->hostname,
                                id_ctx->ipa_options->host_map,
                                NULL,
                                state->selinux_ctx->host_search_bases);
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

    return ipa_get_config_step(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void ipa_get_config_step(struct tevent_req *req)
{
    errno_t ret;
    const char *domain;
    struct tevent_req *subreq;
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    struct be_ctx *bctx = state->be_req->be_ctx;
    struct ipa_id_ctx *id_ctx = state->selinux_ctx->id_ctx;

    ret = sss_selinux_extract_user(state, bctx->sysdb,
                                   state->pd->user, &state->user);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    domain = dp_opt_get_string(state->selinux_ctx->id_ctx->ipa_options->basic,
                               IPA_KRB5_REALM);
    subreq = ipa_get_config_send(state, bctx->ev,
                                 sdap_id_op_handle(state->op),
                                 id_ctx->sdap_id_ctx->opts,
                                 domain, NULL);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
    }
    tevent_req_set_callback(subreq, ipa_get_selinux_config_done, req);
}

static void ipa_get_selinux_config_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    struct be_ctx *bctx = state->be_req->be_ctx;
    struct sdap_id_ctx *id_ctx = state->selinux_ctx->id_ctx->sdap_id_ctx;
    errno_t ret;

    ret = ipa_get_config_recv(subreq, state, &state->defaults);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not get IPA config\n"));
        goto done;
    }

    subreq = ipa_selinux_get_maps_send(state, bctx->ev, bctx->sysdb,
                                     sdap_id_op_handle(state->op),
                                     id_ctx->opts,
                                     state->selinux_ctx->id_ctx->ipa_options,
                                     state->selinux_ctx->selinux_search_bases);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ipa_get_selinux_maps_done, req);
    return;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

static void ipa_get_selinux_maps_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_get_selinux_state *state;

    struct be_ctx *bctx;
    struct ipa_id_ctx *id_ctx;

    char *selinux_name;
    char *access_name;
    struct sysdb_attrs **rules;
    size_t rule_count;

    const char *tmp_str;
    uint32_t priority = 0;
    errno_t ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_get_selinux_state);
    bctx = state->be_req->be_ctx;
    id_ctx = state->selinux_ctx->id_ctx;

    ret = ipa_selinux_get_maps_recv(subreq, state,
                                    &state->nmaps, &state->selinuxmaps);
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

    DEBUG(SSSDBG_TRACE_FUNC,
         ("Found %d SELinux user maps\n", state->nmaps));
    state->possible_match = talloc_zero_array(state, struct sysdb_attrs *,
                                              state->nmaps + 1);
    if (state->possible_match == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < state->nmaps; i++) {
        if (sss_selinux_match(state->selinuxmaps[i], state->user,
                              state->host, &priority)) {
            priority &= ~(SELINUX_PRIORITY_USER_NAME |
                          SELINUX_PRIORITY_USER_GROUP |
                          SELINUX_PRIORITY_USER_CAT);
            ret = sysdb_attrs_add_uint32(state->selinuxmaps[i],
                                         SYSDB_SELINUX_HOST_PRIORITY,
                                         priority);
            if (ret != EOK) {
                goto done;
            }
            continue;
        }

        ret = sysdb_attrs_get_string(state->selinuxmaps[i],
                                     SYSDB_SELINUX_SEEALSO, &tmp_str);
        if (ret == ENOENT) {
            continue;
        }

        state->possible_match[state->possible_matches] = state->selinuxmaps[i];
        state->possible_matches++;
    }

    if (state->possible_matches) {
        access_name = state->be_req->be_ctx->bet_info[BET_ACCESS].mod_name;
        selinux_name = state->be_req->be_ctx->bet_info[BET_SELINUX].mod_name;
        if (strcasecmp(access_name, selinux_name) == 0) {
            ret = hbac_get_cached_rules(state, state->be_req->be_ctx->sysdb,
                                        &rule_count, &rules);
            if (ret != EOK) {
                goto done;
            }

            ret = ipa_get_selinux_hbac_process(state, rules, rule_count);
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, ("%d SELinux maps referenced an HBAC rule. "
              "Need to refresh HBAC rules\n", state->possible_matches));
        subreq = ipa_hbac_rule_info_send(state, false, bctx->ev,
                                         sdap_id_op_handle(state->op),
                                         id_ctx->sdap_id_ctx->opts,
                                         state->selinux_ctx->hbac_search_bases,
                                         state->host);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, ipa_get_selinux_hbac_done, req);
        return;
    }

    ret = EOK;
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
    struct sysdb_attrs **rules;
    size_t rule_count;
    errno_t ret;

    ret = ipa_hbac_rule_info_recv(subreq, state, &rule_count,
                                  &rules);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          ("Received %d HBAC rules\n", rule_count));
    talloc_free(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = ipa_get_selinux_hbac_process(state, rules, rule_count);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

static int
ipa_get_selinux_hbac_process(struct ipa_get_selinux_state *state,
                             struct sysdb_attrs **rules,
                             size_t rule_count)
{
    int i, j;
    errno_t ret;
    uint32_t priority = 0;
    const char *hbac_dn;
    const char *seealso_dn;
    struct sysdb_attrs *usermap;
    struct ldb_message_element *el;

    for (i = 0; i < rule_count; i++) {
        ret = sysdb_attrs_get_string(rules[i], SYSDB_ORIG_DN, &hbac_dn);
        if (ret != EOK) {
            goto done;
        }

        /* We need to do this translation for further processing. We have to
         * do it manually because no map was used to retrieve HBAC rules.
         */
        ret = sysdb_attrs_get_el(rules[i], IPA_MEMBER_HOST, &el);
        if (ret != EOK) goto done;
        el->name = SYSDB_ORIG_MEMBER_HOST;

        ret = sysdb_attrs_get_el(rules[i], IPA_MEMBER_USER, &el);
        if (ret != EOK) goto done;
        el->name = SYSDB_ORIG_MEMBER_USER;

        DEBUG(SSSDBG_TRACE_ALL,
              ("Matching HBAC rule %s with SELinux mappings\n", hbac_dn));

        if (!sss_selinux_match(rules[i], state->user, state->host, &priority)) {
            DEBUG(SSSDBG_TRACE_ALL, ("Rule did not match\n"));
            continue;
        }


        /* HBAC rule matched, find if it is in the "possible" list */
        for (j = 0; j < state->possible_matches; j++) {
            usermap = state->possible_match[j];
            if (usermap == NULL) {
                continue;
            }

            ret = sysdb_attrs_get_string(usermap, SYSDB_SELINUX_SEEALSO, &seealso_dn);
            if (ret != EOK) {
                goto done;
            }

            if (strcasecmp(hbac_dn, seealso_dn) == 0) {
                DEBUG(SSSDBG_TRACE_FUNC, ("HBAC rule [%s] matched, copying its"
                                          "attributes to SELinux user map [%s]\n",
                                          hbac_dn, seealso_dn));
                priority &= ~(SELINUX_PRIORITY_USER_NAME |
                              SELINUX_PRIORITY_USER_GROUP |
                              SELINUX_PRIORITY_USER_CAT);
                ret = sysdb_attrs_add_uint32(usermap,
                                             SYSDB_SELINUX_HOST_PRIORITY,
                                             priority);
                if (ret != EOK) {
                    goto done;
                }

                ret = sysdb_attrs_copy_values(rules[i], usermap, SYSDB_ORIG_MEMBER_USER);
                if (ret != EOK) {
                    goto done;
                }

                ret = sysdb_attrs_copy_values(rules[i], usermap, SYSDB_USER_CATEGORY);
                if (ret != EOK) {
                    goto done;
                }

                /* Just to boost the following lookup */
                state->possible_match[j] = NULL;
            }
        }
    }

    /* Now we can dispose all possible rules, since they aren't possible any more */
    talloc_zfree(state->possible_match);

    ret = EOK;
done:
    return ret;
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

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->defaults != NULL) {
        ret = sysdb_attrs_get_string(state->defaults, IPA_CONFIG_SELINUX_DEFAULT_MAP,
                                     &tmp_str);
        if (ret != EOK && ret != ENOENT) {
            return ret;
        }

        if (ret == EOK) {
            *default_user = talloc_strdup(mem_ctx, tmp_str);
            if (*default_user == NULL) {
                return ENOMEM;
            }
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

    if (state->selinuxmaps != NULL) {
        *count = state->nmaps;
        *maps = talloc_steal(mem_ctx, state->selinuxmaps);
    } else {
        *count = 0;
        *maps = NULL;
    }

    return EOK;
}
