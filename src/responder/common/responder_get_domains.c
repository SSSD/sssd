/*
    Authors:
        Jan Zeleny <jzeleny@redhat.com>

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
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "db/sysdb.h"

/* ========== Get subdomains for a domain ================= */
static DBusMessage *sss_dp_get_domains_msg(void *pvt);

struct sss_dp_domains_info {
    struct sss_domain_info *dom;
    const char *hint;
};

static struct tevent_req *
get_subdomains_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                    struct sss_domain_info *dom,
                    const char *hint)
{
    errno_t ret;
    struct tevent_req *req;
    struct sss_dp_req_state *state;
    struct sss_dp_domains_info *info;
    char *key;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_req_state);
    if (req == NULL) {
        return NULL;
    }

    info = talloc_zero(state, struct sss_dp_domains_info);
    if (!info) {
        ret = ENOMEM;
        goto fail;
    }
    info->hint = hint;
    info->dom = dom;

    key = talloc_asprintf(state, "domains@%s", dom->name);
    if (key == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sss_dp_issue_request(state, rctx, key, dom,
                               sss_dp_get_domains_msg, info, req);
    talloc_free(key);
    if (ret != EOK) {
        ret = EIO;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, rctx->ev);
    return req;
}

static DBusMessage *
sss_dp_get_domains_msg(void *pvt)
{
    struct sss_dp_domains_info *info;
    DBusMessage *msg = NULL;
    dbus_bool_t dbret;

    info = talloc_get_type(pvt, struct sss_dp_domains_info);

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       IFACE_DP,
                                       IFACE_DP_GETDOMAINS);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Sending get domains request for [%s][%s]\n",
           info->dom->name, info->hint);

    /* Send the hint argument to provider as well. This will
     * be useful for some cases of transitional trust where
     * the server might not know all trusted domains
     */
    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_STRING, &info->hint,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_OP_FAILURE ,"Failed to build message\n");
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

static errno_t
get_next_domain_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     dbus_uint16_t *dp_err,
                     dbus_uint32_t *dp_ret,
                     char **err_msg)
{
    return sss_dp_req_recv(mem_ctx, req, dp_err, dp_ret, err_msg);
}

/* ====== Iterate over all domains, searching for their subdomains  ======= */
static errno_t process_subdomains(struct sss_domain_info *dom,
                                  struct confdb_ctx *confdb);
static void set_time_of_last_request(struct resp_ctx *rctx);
static errno_t check_last_request(struct resp_ctx *rctx, const char *hint);

struct sss_dp_get_domains_state {
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    const char *hint;
};

static void
sss_dp_get_domains_process(struct tevent_req *subreq);

struct tevent_req *sss_dp_get_domains_send(TALLOC_CTX *mem_ctx,
                                           struct resp_ctx *rctx,
                                           bool force,
                                           const char *hint)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sss_dp_get_domains_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_get_domains_state);
    if (req == NULL) {
         return NULL;
    }

    if (rctx->domains == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No domains configured.\n");
        ret = EINVAL;
        goto immediately;
    }

    if (!force) {
        ret = check_last_request(rctx, hint);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Last call was too recent, nothing to do!\n");
            goto immediately;
        } else if (ret != EAGAIN) {
            DEBUG(SSSDBG_TRACE_FUNC, "check_domain_request failed with [%d][%s]\n",
                                      ret, strerror(ret));
            goto immediately;
        }
    }

    state->rctx = rctx;
    if (hint != NULL) {
        state->hint = hint;
    } else {
        state->hint = talloc_strdup(state, "");
        if (state->hint == NULL) {
            ret = ENOMEM;
            goto immediately;
        }
    }

    state->dom = rctx->domains;
    while(state->dom != NULL && !NEED_CHECK_PROVIDER(state->dom->provider)) {
        state->dom = get_next_domain(state->dom, 0);
    }

    if (state->dom == NULL) {
        /* All domains were local */
        ret = sss_resp_populate_cr_domains(state->rctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_resp_populate_cr_domains() failed [%d]: [%s]\n",
                  ret, sss_strerror(ret));
            goto immediately;
        }
        ret = EOK;
        goto immediately;
    }

    subreq = get_subdomains_send(req, rctx, state->dom, state->hint);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, sss_dp_get_domains_process, req);

    return req;

immediately:
    if (ret == EOK) {
        set_time_of_last_request(rctx);
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, rctx->ev);

    return req;
}

static void sss_resp_update_certmaps(struct resp_ctx *rctx)
{
    int ret;
    struct certmap_info **certmaps;
    bool user_name_hint;
    struct sss_domain_info *dom;

    for (dom = rctx->domains; dom != NULL; dom = dom->next) {
        ret = sysdb_get_certmap(dom, dom->sysdb, &certmaps, &user_name_hint);
        if (ret == EOK) {
            dom->user_name_hint = user_name_hint;
            talloc_free(dom->certmaps);
            dom->certmaps = certmaps;
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_get_certmap failed for domain [%s].\n", dom->name);
        }
    }
}

static void
sss_dp_get_domains_process(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sss_dp_get_domains_state *state = tevent_req_data(req,
                                                struct sss_dp_get_domains_state);
    dbus_uint16_t dp_err;
    dbus_uint32_t dp_ret;
    char *err_msg;

    ret = get_next_domain_recv(req, subreq, &dp_err, &dp_ret, &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto fail;
    }

    ret = process_subdomains(state->dom, state->rctx->cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "process_subdomains failed, "
                                  "trying next domain.\n");
        goto fail;
    }

    /* Advance to the next domain */
    state->dom = get_next_domain(state->dom, 0);

    /* Skip local domains */
    while(state->dom != NULL && !NEED_CHECK_PROVIDER(state->dom->provider)) {
        state->dom = get_next_domain(state->dom, 0);
    }

    if (state->dom == NULL) {
        /* All domains were local */
        set_time_of_last_request(state->rctx);
        ret = sss_resp_populate_cr_domains(state->rctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_resp_populate_cr_domains() failed [%d]: [%s]\n",
                  ret, sss_strerror(ret));
            goto fail;
        }

        sss_resp_update_certmaps(state->rctx);

        tevent_req_done(req);
        return;
    }

    subreq = get_subdomains_send(req, state->rctx, state->dom, state->hint);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sss_dp_get_domains_process, req);
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static errno_t
process_subdomains(struct sss_domain_info *domain, struct confdb_ctx *confdb)
{
    int ret;

    if (domain->realm == NULL ||
        domain->flat_name == NULL ||
        domain->domain_id == NULL) {
        ret = sysdb_master_domain_update(domain);
        if (ret != EOK) {
                DEBUG(SSSDBG_FUNC_DATA, "sysdb_master_domain_get_info " \
                                         "failed.\n");
                goto done;
        }
    }

    /* Retrieve all subdomains of this domain from sysdb
     * and create their struct sss_domain_info representations
     */
    ret = sysdb_update_subdomains(domain, confdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FUNC_DATA, "sysdb_update_subdomains failed.\n");
        goto done;
    }

    errno = 0;
    ret = gettimeofday(&domain->subdomains_last_checked, NULL);
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to update sub-domains "
                                  "of domain [%s].\n", domain->name);
    }

    return ret;
}

errno_t sss_dp_get_domains_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void set_time_of_last_request(struct resp_ctx *rctx)
{
    int ret;

    errno = 0;
    ret = gettimeofday(&rctx->get_domains_last_call, NULL);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "gettimeofday failed [%d][%s].\n",
                                  ret, strerror(ret));
    }
}

static errno_t check_last_request(struct resp_ctx *rctx, const char *hint)
{
    struct sss_domain_info *dom;
    time_t now = time(NULL);
    time_t diff;

    diff = now - rctx->get_domains_last_call.tv_sec;
    if (diff >= rctx->domains_timeout) {
        /* Timeout, expired, fetch domains again */
        return EAGAIN;
    }

    if (hint != NULL) {
        for (dom = rctx->domains; dom;
                dom = get_next_domain(dom, SSS_GND_DESCEND)) {
            if (!IS_SUBDOMAIN(dom)) {
                diff = now - dom->subdomains_last_checked.tv_sec;
                /* not a subdomain */
                continue;
            }
            if (strcasecmp(dom->name, hint) == 0) {
                if (diff >= rctx->domains_timeout) {
                    /* Timeout, expired, fetch domains again */
                    return EAGAIN;
                }
            }
        }
    }

    return EOK;
}

struct get_domains_state {
    struct resp_ctx *rctx;
    struct sss_nc_ctx *optional_ncache;
};

static void get_domains_at_startup_done(struct tevent_req *req)
{
    int ret;
    struct get_domains_state *state;

    state = tevent_req_callback_data(req, struct get_domains_state);

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_dp_get_domains request failed.\n");
    }

    if (state->optional_ncache != NULL) {
        ret = sss_ncache_reset_repopulate_permanent(state->rctx,
                                                    state->optional_ncache);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "sss_dp_get_domains request failed.\n");
        }
    }

    if (!NEED_CHECK_PROVIDER(state->rctx->domains->provider)) {
        ret = sysdb_master_domain_update(state->rctx->domains);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_master_domain_update failed, "
                                     "ignored.\n");
        }
    }

    talloc_free(state);
    return;
}

static void get_domains_at_startup(struct tevent_context *ev,
                                   struct tevent_immediate *imm,
                                   void *pvt)
{
    struct tevent_req *req;
    struct get_domains_state *state;

    state = talloc_get_type(pvt, struct get_domains_state);

    req = sss_dp_get_domains_send(state, state->rctx, true, NULL);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_dp_get_domains_send failed.\n");
        talloc_free(state);
        return;
    }

    tevent_req_set_callback(req, get_domains_at_startup_done, state);
    return;
}

errno_t schedule_get_domains_task(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct resp_ctx *rctx,
                                  struct sss_nc_ctx *optional_ncache)
{
    struct tevent_immediate *imm;
    struct get_domains_state *state;

    state = talloc(mem_ctx, struct get_domains_state);
    if (state == NULL) {
        return ENOMEM;
    }
    state->rctx = rctx;
    state->optional_ncache = optional_ncache;

    imm = tevent_create_immediate(mem_ctx);
    if (imm == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_create_immediate failed.\n");
        talloc_free(state);
        return ENOMEM;
    }

    tevent_schedule_immediate(imm, ev, get_domains_at_startup, state);

    return EOK;
}

struct sss_parse_inp_state {
    struct resp_ctx *rctx;
    const char *default_domain;
    const char *rawinp;

    char *name;
    char *domname;
    errno_t error;
};

static void sss_parse_inp_done(struct tevent_req *subreq);

struct tevent_req *
sss_parse_inp_send(TALLOC_CTX *mem_ctx,
                   struct resp_ctx *rctx,
                   const char *default_domain,
                   const char *rawinp)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sss_parse_inp_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sss_parse_inp_state);
    if (req == NULL) {
         return NULL;
    }

    if (rawinp == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Empty input!\n");
        ret = EINVAL;
        goto done;
    }

    state->rctx = rctx;

    state->rawinp = talloc_strdup(state, rawinp);
    if (state->rawinp == NULL) {
        ret = ENOMEM;
        goto done;
    }


    state->default_domain = talloc_strdup(state, default_domain);
    if (default_domain != NULL && state->default_domain == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* If the subdomains haven't been checked yet, we need to always
     * attach to the post-startup subdomain request and only then parse
     * the input. Otherwise, we might not be able to parse input with a
     * flat domain name specifier */
    if (rctx->get_domains_last_call.tv_sec > 0) {
        ret = sss_parse_name_for_domains(state, rctx->domains,
                                         default_domain, rawinp,
                                         &state->domname, &state->name);
        if (ret == EOK) {
            /* Was able to use cached domains */
            goto done;
        } else if (ret != EAGAIN) {
            DEBUG(SSSDBG_OP_FAILURE, "Invalid name received [%s]\n", rawinp);
            ret = ERR_INPUT_PARSE;
            goto done;
        }
    }

    /* EAGAIN - check the DP for subdomains */

    DEBUG(SSSDBG_FUNC_DATA, "Requesting info for [%s] from [%s]\n",
          state->name, state->domname ? state->domname : "<ALL>");

    /* We explicitly use force=false here. This request should decide itself
     * if it's time to re-use the cached subdomain list or refresh. If the
     * caller needs to specify the 'force' parameter, they should use the
     * sss_dp_get_domains_send() request itself
     */
    subreq = sss_dp_get_domains_send(state, rctx, false, state->domname);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, sss_parse_inp_done, req);
    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, rctx->ev);
    return req;
}

static void sss_parse_inp_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sss_parse_inp_state *state = tevent_req_data(req,
                                                struct sss_parse_inp_state);

    ret = sss_dp_get_domains_recv(subreq);
    talloc_free(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->error = ERR_OK;

    ret = sss_parse_name_for_domains(state, state->rctx->domains,
                                     state->default_domain,
                                     state->rawinp,
                                     &state->domname, &state->name);
    if (ret == EAGAIN && state->domname != NULL && state->name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unknown domain in [%s]\n", state->rawinp);
        state->error = ERR_DOMAIN_NOT_FOUND;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Invalid name received [%s]\n", state->rawinp);
        state->error = ERR_INPUT_PARSE;
    }

    if (state->error != ERR_OK) {
        tevent_req_error(req, state->error);
        return;
    }

    /* Was able to parse the name now */
    tevent_req_done(req);
}

errno_t sss_parse_inp_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           char **_name, char **_domname)
{
    struct sss_parse_inp_state *state = tevent_req_data(req,
                                                struct sss_parse_inp_state);

    if (state->error != ERR_DOMAIN_NOT_FOUND) {
        TEVENT_REQ_RETURN_ON_ERROR(req);
    }

    if (_name) {
        *_name = talloc_steal(mem_ctx, state->name);
    }

    if (_domname) {
        *_domname = talloc_steal(mem_ctx, state->domname);
    }

    return state->error;
}
