/*
    Authors:
        Simo Sorce <ssorce@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2009 Red Hat

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


#include <sys/time.h>
#include <time.h>
#include "util/util.h"
#include "util/sss_chain_id.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"

#ifdef BUILD_FILES_PROVIDER
static errno_t
sss_dp_account_files_params(struct sss_domain_info *dom,
                            enum sss_dp_acct_type type_in,
                            const char *opt_name_in,
                            enum sss_dp_acct_type *_type_out,
                            const char **_opt_name_out)
{
    if (type_in != SSS_DP_CERT) {
        if (sss_domain_get_state(dom) != DOM_INCONSISTENT) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "The entries in the files domain are up-to-date\n");
            return EOK;
        }

        if (sss_domain_fallback_to_nss(dom)) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Domain files is not consistent, falling back to nss.\n");
            return ENOENT;
        }

        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Domain files is not consistent, issuing update\n");
    }

    switch(type_in) {
    case SSS_DP_USER:
    case SSS_DP_GROUP:
        *_type_out = type_in;
        *_opt_name_out = NULL;
        return EAGAIN;
    case SSS_DP_INITGROUPS:
        /* There is no initgroups enumeration so let's use a dummy
         * name to let the DP chain the requests
         */
        *_type_out = type_in;
        *_opt_name_out = DP_REQ_OPT_FILES_INITGR;
        return EAGAIN;
    case SSS_DP_CERT:
        /* Let the backend handle certificate mapping for local users */
        *_type_out = type_in;
        *_opt_name_out = opt_name_in;
        return EAGAIN;
    /* These are not handled by the files provider, just fall back */
    case SSS_DP_SUBID_RANGES:
    case SSS_DP_NETGR:
    case SSS_DP_SERVICES:
    case SSS_DP_SECID:
    case SSS_DP_USER_AND_GROUP:
    case SSS_DP_WILDCARD_USER:
    case SSS_DP_WILDCARD_GROUP:
        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "Unhandled type %d\n", type_in);
    return EINVAL;
}
#endif

static errno_t
sss_dp_get_account_filter(TALLOC_CTX *mem_ctx,
                          enum sss_dp_acct_type type,
                          bool fast_reply,
                          const char *opt_name,
                          uint32_t opt_id,
                          uint32_t *_dp_flags,
                          uint32_t *_entry_type,
                          char **_filter)
{
    uint32_t entry_type = 0;
    uint32_t dp_flags;
    char *filter;

    switch (type) {
        case SSS_DP_USER:
        case SSS_DP_WILDCARD_USER:
            entry_type = BE_REQ_USER;
            break;
        case SSS_DP_GROUP:
        case SSS_DP_WILDCARD_GROUP:
            entry_type = BE_REQ_GROUP;
            break;
        case SSS_DP_INITGROUPS:
            entry_type = BE_REQ_INITGROUPS;
            break;
        case SSS_DP_SUBID_RANGES:
            entry_type = BE_REQ_SUBID_RANGES;
            break;
        case SSS_DP_NETGR:
            entry_type = BE_REQ_NETGROUP;
            break;
        case SSS_DP_SERVICES:
            entry_type = BE_REQ_SERVICES;
            break;
        case SSS_DP_SECID:
            entry_type = BE_REQ_BY_SECID;
            break;
        case SSS_DP_USER_AND_GROUP:
            entry_type = BE_REQ_USER_AND_GROUP;
            break;
        case SSS_DP_CERT:
            entry_type = BE_REQ_BY_CERT;
            break;
    }

    dp_flags = fast_reply ? DP_FAST_REPLY : 0;

    if (opt_name != NULL) {
        switch(type) {
            case SSS_DP_SECID:
                filter = talloc_asprintf(mem_ctx, "%s=%s", DP_SEC_ID,
                                         opt_name);
                break;
            case SSS_DP_CERT:
                filter = talloc_asprintf(mem_ctx, "%s=%s", DP_CERT,
                                         opt_name);
                break;
            case SSS_DP_WILDCARD_USER:
            case SSS_DP_WILDCARD_GROUP:
                filter = talloc_asprintf(mem_ctx, "%s=%s", DP_WILDCARD,
                                         opt_name);
                break;
            default:
                filter = talloc_asprintf(mem_ctx, "name=%s", opt_name);
                break;
        }
    } else if (opt_id != 0) {
        filter = talloc_asprintf(mem_ctx, "idnumber=%u", opt_id);
    } else {
        filter = talloc_strdup(mem_ctx, ENUM_INDICATOR);
    }

    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return ENOMEM;
    }

    *_dp_flags = dp_flags;
    *_entry_type = entry_type;
    *_filter = filter;

    return EOK;
}

struct sss_dp_get_account_state {
    uint16_t dp_error;
    uint32_t error;
    const char *error_message;
};

static void sss_dp_get_account_done(struct tevent_req *subreq);

struct tevent_req *
sss_dp_get_account_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        enum sss_dp_acct_type type,
                        const char *opt_name,
                        uint32_t opt_id,
                        const char *extra)
{
    struct sss_dp_get_account_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    uint32_t entry_type;
    uint32_t dp_flags;
    char *filter;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_get_account_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    /* either, or, not both */
    if (opt_name != NULL && opt_id != 0) {
        ret = EINVAL;
        goto done;
    }

    if (dom == NULL) {
        ret = EINVAL;
        goto done;
    }

#ifdef BUILD_FILES_PROVIDER
    if (is_files_provider(dom)) {
        /* This is a special case. If the files provider is just being updated,
         * we issue an enumeration request. We always use the same request type
         * (user enumeration) to make sure concurrent requests are just chained
         * in the Data Provider */
        ret = sss_dp_account_files_params(dom, type, opt_name,
                                          &type, &opt_name);
        if (ret == EOK) {
            state->dp_error = DP_ERR_OK;
            state->error = EOK;
            state->error_message = talloc_strdup(state, "Success");
            if (state->error_message == NULL) {
                ret = ENOMEM;
                goto done;
            }
            goto done;
        } else if (ret != EAGAIN) {
            DEBUG((ret == ENOENT) ? SSSDBG_MINOR_FAILURE : SSSDBG_OP_FAILURE,
                  "Failed to set files provider update [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
        /* EAGAIN, fall through to issuing the request */
    }
#endif

    if (rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        ret = EIO;
        goto done;
    }

    /* Build filter. */
    ret = sss_dp_get_account_filter(state, type, fast_reply, opt_name, opt_id,
                                    &dp_flags, &entry_type, &filter);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Creating request for [%s][%#x][%s][%s:%s]\n",
          dom->name, entry_type, be_req2str(entry_type),
          filter, extra == NULL ? "-" : extra);

    subreq = sbus_call_dp_dp_getAccountInfo_send(state, rctx->sbus_conn,
                 dom->conn_name, SSS_BUS_PATH, dp_flags,
                 entry_type, filter, dom->name, extra,
                 sss_chain_id_get());
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_dp_get_account_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, rctx->ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, rctx->ev);
    }

    return req;
}

static void sss_dp_get_account_done(struct tevent_req *subreq)
{
    struct sss_dp_get_account_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_dp_get_account_state);

    ret = sbus_call_dp_dp_getAccountInfo_recv(state, subreq, &state->dp_error,
                                              &state->error,
                                              &state->error_message);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
sss_dp_get_account_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        uint16_t *_dp_error,
                        uint32_t *_error,
                        const char **_error_message)
{
    struct sss_dp_get_account_state *state;
    state = tevent_req_data(req, struct sss_dp_get_account_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_dp_error = state->dp_error;
    *_error = state->error;
    *_error_message = talloc_steal(mem_ctx, state->error_message);

    return EOK;
}

struct sss_dp_resolver_get_state {
    uint16_t dp_error;
    uint32_t error;
    const char *error_message;
};

static void sss_dp_resolver_get_done(struct tevent_req *subreq);

struct tevent_req *
sss_dp_resolver_get_send(TALLOC_CTX *mem_ctx,
                         struct resp_ctx *rctx,
                         struct sss_domain_info *dom,
                         bool fast_reply,
                         uint32_t entry_type,
                         uint32_t filter_type,
                         const char *filter_value)
{
    struct sss_dp_resolver_get_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    uint32_t dp_flags;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sss_dp_resolver_get_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    /* Validate filter_type */
    switch (filter_type) {
    case BE_FILTER_NAME:
    case BE_FILTER_ADDR:
    case BE_FILTER_ENUM:
        break;
    default:
        ret = EINVAL;
        goto done;
    }

    if (dom == NULL) {
        ret = EINVAL;
        goto done;
    }

    if (rctx->sbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "BUG: The D-Bus connection is not available!\n");
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Creating request for [%s][%#x][%s][%#x:%s]\n",
          dom->name, entry_type, be_req2str(entry_type),
          filter_type, filter_value ? filter_value : "-");

    dp_flags = fast_reply ? DP_FAST_REPLY : 0;
    subreq = sbus_call_dp_dp_resolverHandler_send(state, rctx->sbus_conn,
                                                  dom->conn_name,
                                                  SSS_BUS_PATH,
                                                  dp_flags, entry_type,
                                                  filter_type, filter_value,
                                                  sss_chain_id_get());
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_dp_resolver_get_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, rctx->ev);
    }

    return req;
}

static void sss_dp_resolver_get_done(struct tevent_req *subreq)
{
    struct sss_dp_resolver_get_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_dp_resolver_get_state);

    ret = sbus_call_dp_dp_resolverHandler_recv(state, subreq,
                                               &state->dp_error,
                                               &state->error,
                                               &state->error_message);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
sss_dp_resolver_get_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         uint16_t *_dp_error,
                         uint32_t *_error,
                         const char **_error_message)
{
    struct sss_dp_resolver_get_state *state;
    state = tevent_req_data(req, struct sss_dp_resolver_get_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_dp_error = state->dp_error;
    *_error = state->error;
    *_error_message = talloc_steal(mem_ctx, state->error_message);

    return EOK;
}
