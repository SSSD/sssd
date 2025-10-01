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
#include "providers/failover/failover_server.h"
#include "providers/failover/failover_server_resolve.h"
#include "providers/failover/failover_vtable_op.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"
#include "util/util.h"

static void
sss_failover_ldap_kinit_options(struct sdap_options *opts,
                                const char **_keytab,
                                const char **_realm,
                                const char **_principal,
                                bool *_canonicalize,
                                int *_lifetime,
                                int *_timeout)
{
    *_keytab = dp_opt_get_string(opts->basic, SDAP_KRB5_KEYTAB);
    *_realm = sdap_gssapi_realm(opts->basic);
    *_principal = dp_opt_get_string(opts->basic, SDAP_SASL_AUTHID);
    *_canonicalize = dp_opt_get_bool(opts->basic, SDAP_KRB5_CANONICALIZE);
    *_lifetime = dp_opt_get_int(opts->basic, SDAP_KRB5_TICKET_LIFETIME);
    *_timeout = dp_opt_get_int(opts->basic, SDAP_OPT_TIMEOUT);
}

struct sss_failover_ldap_kinit_state {
    time_t expiration_time;
};

static void sss_failover_ldap_kinit_done(struct tevent_req *subreq);

struct tevent_req *
sss_failover_ldap_kinit_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sss_failover_ctx *fctx,
                             struct sss_failover_server *server,
                             bool addr_changed,
                             void *pvt)
{
    struct sss_failover_ldap_kinit_state *state;
    struct sdap_options *opts;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char *keytab;
    const char *principal;
    const char *realm;
    bool canonicalize;
    int timeout;
    int lifetime;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sss_failover_ldap_kinit_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    opts = talloc_get_type_abort(pvt, struct sdap_options);

    sss_failover_ldap_kinit_options(opts, &keytab, &realm, &principal,
                                    &canonicalize, &lifetime, &timeout);

    ret = setenv("KRB5_CANONICALIZE", canonicalize ? "true" : "false", 1);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set KRB5_CANONICALIZE to %s\n",
              canonicalize ? "true" : "false");
        ret = errno;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Attempting kinit (%s, %s, %s, %d, %s)\n",
          keytab != NULL ? keytab : "default", principal, realm, lifetime,
          server->name);

    /* TODO write kdcinfo */

    subreq = sdap_get_tgt_send(state, ev, realm, principal, keytab, lifetime,
                               timeout);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sss_failover_ldap_kinit_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
sss_failover_ldap_kinit_done(struct tevent_req *subreq)
{
    struct sss_failover_ldap_kinit_state *state;
    struct tevent_req *req;
    krb5_error_code kerr;
    char *ccname;
    int result;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_failover_ldap_kinit_state);

    ret = sdap_get_tgt_recv(subreq, state, &result, &kerr, &ccname,
                            &state->expiration_time);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    /* ret is request error, result is child error, kerr is kerberos error */
    switch (ret) {
    case EOK:
        if (result == EOK) {
            /* TGT acquired. */
            ret = setenv("KRB5CCNAME", ccname, 1);
            if (ret != 0) {
                ret = errno;
                DEBUG(SSSDBG_OP_FAILURE,
                      "Unable to set env. variable KRB5CCNAME!\n");
                goto done;
            }
            ret = EOK;
            goto done;
        } else if (kerr == KRB5_KDC_UNREACH) {
            ret = ERR_SERVER_FAILURE;
            goto done;
        } else if (result == EFAULT || result == EIO || result == EPERM) {
            ret = ERR_AUTH_FAILED;
            goto done;
        } else {
            ret = ERR_AUTH_FAILED;
            goto done;
        }
        break;
    case ETIMEDOUT:
        /* The child did not responds. Try another KDC. */
        ret = ERR_SERVER_FAILURE;
        goto done;
    default:
        /* Child did not execute correctly. Terminate. */
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sss_failover_ldap_kinit_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             time_t *_expiration_time)
{
    struct sss_failover_ldap_kinit_state *state = NULL;
    state = tevent_req_data(req, struct sss_failover_ldap_kinit_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_expiration_time != NULL) {
        *_expiration_time = state->expiration_time;
    }

    return EOK;
}
