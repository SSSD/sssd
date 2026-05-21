/*
    Copyright (C) 2025 Red Hat

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
#include <errno.h>

#include "config.h"
#include "providers/failover/failover.h"
#include "providers/failover/failover_transaction.h"
#include "providers/failover/failover_server.h"
#include "providers/failover/ldap/failover_ldap.h"
#include "providers/ldap/sdap_async_private.h"
#include "util/util.h"

struct sss_failover_ldap_connect_state {
    struct sss_failover_ldap_connection *connection;
};

static void sss_failover_ldap_connect_done(struct tevent_req *subreq);

struct tevent_req *
sss_failover_ldap_connect_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct sss_failover_ctx *fctx,
                               struct sss_failover_server *server,
                               bool addr_changed,
                               bool reuse_connection,
                               bool authenticate_connection,
                               bool read_rootdse,
                               enum sss_failover_transaction_tls force_tls,
                               time_t kinit_expiration_time,
                               void *pvt)
{
    struct sss_failover_ldap_connect_state *state;
    struct sdap_options *opts;
    struct tevent_req *subreq;
    struct tevent_req *req;
    enum connect_tls tls;
    errno_t ret;

    /* TODO handle active connection */

    opts = talloc_get_type_abort(pvt, struct sdap_options);

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_ldap_connect_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->connection = talloc_zero(state, struct sss_failover_ldap_connection);
    if (state->connection == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        ret = ENOMEM;
        goto done;
    }

    state->connection->uri = talloc_strdup(state->connection, server->uri);
    if (state->connection->uri == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        ret = ENOMEM;
        goto done;
    }

    switch (force_tls) {
    case SSS_FAILOVER_TRANSACTION_TLS_DEFAULT:
        tls = CON_TLS_DFL;
        break;
    case SSS_FAILOVER_TRANSACTION_TLS_ON:
        tls = CON_TLS_ON;
        break;
    case SSS_FAILOVER_TRANSACTION_TLS_OFF:
        tls = CON_TLS_OFF;
        break;
    }

    subreq = sdap_cli_connect_send(state, ev, opts, server->uri,
                                   server->addr->sockaddr,
                                   server->addr->sockaddr_len, !read_rootdse,
                                   tls, !authenticate_connection,
                                   kinit_expiration_time);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_failover_ldap_connect_done, req);

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void
sss_failover_ldap_connect_done(struct tevent_req *subreq)
{
    struct sss_failover_ldap_connect_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_ldap_connect_state);

    ret = sdap_cli_connect_recv(subreq, state, &state->connection->sh,
                                &state->connection->srv_opts);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    talloc_steal(state->connection, state->connection->sh);
    talloc_steal(state->connection, state->connection->srv_opts);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sss_failover_ldap_connect_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               void **_connection)
{
    struct sss_failover_ldap_connect_state *state;
    state = tevent_req_data(req, struct sss_failover_ldap_connect_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_connection != NULL) {
        *_connection = (void*)talloc_steal(mem_ctx, state->connection);
    }

    return EOK;
}
