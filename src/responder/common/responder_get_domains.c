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

struct sss_dp_domains_info {
    struct resp_ctx *rctx;
    struct sss_domain_info *dom;
    const char *hint;
    bool force;

    struct sss_dp_req_state *state;
};

static DBusMessage *sss_dp_get_domains_msg(void *pvt);
static errno_t get_domains_next(struct tevent_req *req);
static void sss_dp_get_domains_callback(struct tevent_req *subreq);

static errno_t get_domains_done(struct tevent_req *req);
static errno_t check_last_request(struct resp_ctx *rctx, const char *hint);

struct tevent_req *sss_dp_get_domains_send(TALLOC_CTX *mem_ctx,
                                           struct resp_ctx *rctx,
                                           bool force,
                                           const char *hint)
{
    errno_t ret;
    struct tevent_req *req;
    struct sss_dp_domains_info *info;

    req = tevent_req_create(mem_ctx, &info, struct sss_dp_domains_info);
    if (req == NULL) {
         return NULL;
    }

    if (rctx->domains == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No domains configured.\n"));
        ret = EINVAL;
        goto immediately;
    }

    if (!force) {
        ret = check_last_request(rctx, hint);

        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("Last call was too recent, nothing to do!\n"));
            goto immediately;
        } else if (ret != EAGAIN) {
            DEBUG(SSSDBG_TRACE_FUNC, ("check_domain_request failed with [%d][%s]\n",
                                      ret, strerror(ret)));
            goto immediately;
        }
    }

    info->rctx = rctx;
    info->dom = rctx->domains;
    info->force = force;
    if (hint != NULL) {
        info->hint = hint;
    } else {
        info->hint = talloc_strdup(info, "");
        if (info->hint == NULL) {
            ret = ENOMEM;
            goto immediately;
        }
    }

    ret = get_domains_next(req);
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
    tevent_req_post(req, rctx->ev);

    return req;
}

static errno_t get_domains_next(struct tevent_req *req)
{
    struct sss_dp_domains_info *info;
    struct tevent_req *subreq;
    struct sss_dp_req_state *state;
    errno_t ret;
    char *key;

    info = tevent_req_data(req, struct sss_dp_domains_info);

    /* Skip all local domains. */
    while(info->dom != NULL && !NEED_CHECK_PROVIDER(info->dom->provider)) {
        info->dom = info->dom->next;
    }

    if (info->dom == NULL) {
        return EOK;
    }

    subreq = tevent_req_create(info, &state, struct sss_dp_req_state);
    if (subreq == NULL) {
         return ENOMEM;
    }

    key = talloc_asprintf(info, "domains@%s", info->dom->name);
    if (key == NULL) {
        talloc_free(subreq);
        return ENOMEM;
    }

    ret = sss_dp_issue_request(info, info->rctx, key, info->dom,
                               sss_dp_get_domains_msg, info, subreq);
    talloc_free(key);
    if (ret != EOK) {
        talloc_free(subreq);
        return ret;
    }

    tevent_req_set_callback(subreq, sss_dp_get_domains_callback, req);

    return EAGAIN;
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
                                       DP_INTERFACE,
                                       DP_METHOD_GETDOMAINS);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory?!\n"));
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Sending get domains request for [%s][%sforced][%s]\n",
           info->dom->name, info->force ? "" : "not ", info->hint));

    /* Send the hint argument to provider as well. This will
     * be useful for some cases of transitional trust where
     * the server might not know all trusted domains
     */
    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_BOOLEAN, &info->force,
                                     DBUS_TYPE_STRING, &info->hint,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_OP_FAILURE ,("Failed to build message\n"));
        dbus_message_unref(msg);
        return NULL;
    }

    return msg;
}

static void sss_dp_get_domains_callback(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sss_dp_domains_info *info = tevent_req_data(req, struct sss_dp_domains_info);
    errno_t ret;
    dbus_uint16_t dp_err;
    dbus_uint32_t dp_ret;
    char *err_msg;

    /* TODO: handle errors better */
    ret = sss_dp_req_recv(info, subreq, &dp_err, &dp_ret, &err_msg);
    talloc_free(subreq);
    if (ret != EOK) {
        goto fail;
    }

    ret = get_domains_done(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("get_domains_done failed, "
                                  "trying next domain.\n"));
        goto fail;
    }

    info->dom = info->dom->next;
    ret = get_domains_next(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        goto fail;
    }

    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static errno_t get_domains_done(struct tevent_req *req)
{
    int ret;
    size_t c;
    struct sss_dp_domains_info *state;
    struct sss_domain_info *domain;
    struct sss_domain_info **new_sd_list = NULL;
    size_t subdomain_count;
    struct sysdb_subdom **subdomains;

    state = tevent_req_data(req, struct sss_dp_domains_info);
    domain = state->dom;

    /* Retrieve all subdomains of this domain from sysdb
     * and create their struct sss_domain_info representations
     */
    ret = sysdb_get_subdomains(domain, domain->sysdb,
                               &subdomain_count, &subdomains);
    if (ret != EOK) {
        DEBUG(SSSDBG_FUNC_DATA, ("sysdb_get_subdomains failed.\n"));
        goto done;
    }

    if (subdomain_count == 0) {
        talloc_zfree(domain->subdomains);
        domain->subdomain_count = 0;
        goto done;
    }

    new_sd_list = talloc_zero_array(domain, struct sss_domain_info *,
                                    subdomain_count);
    if (new_sd_list == NULL) {
        ret = ENOMEM;
        goto done;
    }
    for (c = 0; c < subdomain_count; c++) {
        DEBUG(SSSDBG_FUNC_DATA, ("Adding subdomain [%s] to the domain [%s]!\n",
                                 subdomains[c]->name, domain->name));
        new_sd_list[c] =  new_subdomain(new_sd_list, domain,
                                        subdomains[c]->name,
                                        subdomains[c]->flat_name,
                                        subdomains[c]->id);
        if (new_sd_list[c] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* Link all subdomains into single-linked list
     * (the list is used when processing all domains)
     */
    while (c > 1) {
        new_sd_list[c-1]->next  = new_sd_list[c];
        --c;
    }

    errno = 0;
    ret = gettimeofday(&domain->subdomains_last_checked, NULL);
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    domain->subdomain_count = subdomain_count;
    talloc_zfree(domain->subdomains);
    domain->subdomains = new_sd_list;
    new_sd_list = NULL;

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to update sub-domains "
                                  "of domain [%s].\n", domain->name));
        talloc_free(new_sd_list);
    }

    return ret;
}

errno_t sss_dp_get_domains_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static errno_t check_last_request(struct resp_ctx *rctx, const char *hint)
{
    struct sss_domain_info *dom;
    time_t now = time(NULL);
    time_t diff;
    int i;

    diff = now-rctx->get_domains_last_call.tv_sec;
    if (diff >= rctx->domains_timeout) {
        /* Timeout, expired, fetch domains again */
        return EAGAIN;
    }

    if (hint != NULL) {
        dom = rctx->domains;
        while (dom) {
            for (i = 0; i< dom->subdomain_count; i++) {
                if (strcasecmp(dom->subdomains[i]->name, hint) == 0) {
                    diff = now-dom->subdomains_last_checked.tv_sec;
                    if (diff >= rctx->domains_timeout) {
                        /* Timeout, expired, fetch domains again */
                        return EAGAIN;
                    }
                    /* Skip the rest of this domain, but check other domains
                     * perhaps this subdomain will be also a part of another
                     * domain where it will need refreshing
                     */
                    break;
                }
            }
            dom = dom->next;
        }
    }

    return EOK;
}
