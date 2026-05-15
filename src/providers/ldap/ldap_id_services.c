/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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


#include <errno.h>

#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb.h"
#include "db/sysdb_services.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"

struct sdap_services_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *id_ctx;
    struct sdap_domain *sdom;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct sdap_id_conn_ctx *conn;

    const char *name;
    const char *protocol;

    char *filter;
    const char **attrs;

    int filter_type;

    int dp_error;
    int sdap_ret;
    bool noexist_delete;
};

static errno_t
services_get_retry(struct tevent_req *req);
static void
services_get_connect_done(struct tevent_req *subreq);
static void
services_get_done(struct tevent_req *subreq);

struct tevent_req *
services_get_send(TALLOC_CTX *mem_ctx,
                  struct tevent_context *ev,
                  struct sdap_id_ctx *id_ctx,
                  struct sdap_domain *sdom,
                  struct sdap_id_conn_ctx *conn,
                  const char *name,
                  const char *protocol,
                  int filter_type,
                  bool noexist_delete)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_services_get_state *state;
    const char *attr_name;
    char *clean_name;
    char *clean_protocol = NULL;

    req = tevent_req_create(mem_ctx, &state, struct sdap_services_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->id_ctx = id_ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->dp_error = DP_ERR_FATAL;
    state->domain = sdom->dom;
    state->sysdb = sdom->dom->sysdb;
    state->name = name;
    state->protocol = protocol;
    state->filter_type = filter_type;
    state->noexist_delete = noexist_delete;

    state->op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto error;
    }

    switch(filter_type) {
    case BE_FILTER_NAME:
        attr_name = id_ctx->opts->service_map[SDAP_AT_SERVICE_NAME].name;
        break;
    case BE_FILTER_IDNUM:
        attr_name = id_ctx->opts->service_map[SDAP_AT_SERVICE_PORT].name;
        break;
    default:
        ret = EINVAL;
        goto error;
    }

    ret = sss_filter_sanitize(state, name, &clean_name);
    if (ret != EOK)  goto error;

    if (protocol != NULL) {
        ret = sss_filter_sanitize(state, protocol, &clean_protocol);
        if (ret != EOK)  goto error;
    }

    if (clean_protocol) {
        state->filter = talloc_asprintf(
                state, "(&(%s=%s)(%s=%s)(objectclass=%s))",
                attr_name, clean_name,
                id_ctx->opts->service_map[SDAP_AT_SERVICE_PROTOCOL].name,
                clean_protocol,
                id_ctx->opts->service_map[SDAP_OC_SERVICE].name);
    } else {
        state->filter =
                talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                                attr_name, clean_name,
                                id_ctx->opts->service_map[SDAP_OC_SERVICE].name);
    }
    talloc_zfree(clean_name);
    talloc_zfree(clean_protocol);
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to build the base filter\n");
        ret = ENOMEM;
        goto error;
    }
    DEBUG(SSSDBG_TRACE_LIBS,
          "Preparing to search for services with filter [%s]\n",
           state->filter);

    ret = build_attrs_from_map(state, id_ctx->opts->service_map,
                               SDAP_OPTS_SERVICES, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) goto error;

    ret = services_get_retry(req);
    if (ret != EOK) goto error;

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t
services_get_retry(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_services_get_state *state =
            tevent_req_data(req, struct sdap_services_get_state);
    struct tevent_req *subreq;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, services_get_connect_done, req);
    return EOK;
}

static void
services_get_connect_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_services_get_state *state =
            tevent_req_data(req, struct sdap_services_get_state);
    int dp_error = DP_ERR_FATAL;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_get_services_send(state, state->ev,
                                    state->domain, state->sysdb,
                                    state->id_ctx->opts,
                                    state->sdom->service_search_bases,
                                    sdap_id_op_handle(state->op),
                                    state->attrs, state->filter,
                                    dp_opt_get_int(state->id_ctx->opts->basic,
                                                   SDAP_SEARCH_TIMEOUT),
                                    false);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, services_get_done, req);
}

static void
services_get_done(struct tevent_req *subreq)
{
    errno_t ret;
    uint16_t port;
    char *endptr;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_services_get_state *state =
            tevent_req_data(req, struct sdap_services_get_state);
    int dp_error = DP_ERR_FATAL;

    ret = sdap_get_services_recv(NULL, subreq, NULL);
    talloc_zfree(subreq);

    /* Check whether we need to try again with another
     * failover server.
     */
    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = services_get_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        /* Return to the mainloop to retry */
        return;
    }
    state->sdap_ret = ret;

    /* An error occurred. */
    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == ENOENT && state->noexist_delete == true) {
        /* Ensure that this entry is removed from the sysdb */
        switch(state->filter_type) {
        case BE_FILTER_NAME:
            ret = sysdb_svc_delete(state->domain, state->name,
                                   0, state->protocol);
            if (ret != EOK) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        case BE_FILTER_IDNUM:
            port = strtouint16(state->name, &endptr, 10);
            if (errno || *endptr || (state->name == endptr)) {
                tevent_req_error(req, (errno ? errno : EINVAL));
                return;
            }

            ret = sysdb_svc_delete(state->domain, NULL,  port,
                                   state->protocol);
            if (ret != EOK) {
                tevent_req_error(req, ret);
                return;
            }
            break;

        default:
            tevent_req_error(req, EINVAL);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

errno_t
services_get_recv(struct tevent_req *req, int *dp_error_out, int *sdap_ret)
{
    struct sdap_services_get_state *state =
            tevent_req_data(req, struct sdap_services_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
