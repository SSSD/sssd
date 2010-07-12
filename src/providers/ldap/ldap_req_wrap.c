/*
    SSSD

    LDAP tevent_req wrappers

    Authors:
        Martin Nagy <mnagy@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <talloc.h>
#include <tevent.h>

#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async_private.h"

#ifdef HAVE_LDAP_CONNCB
# ifdef LDAP_OPT_CONNECT_ASYNC
#  define IS_CONNECTING(r) ((r) == LDAP_X_CONNECTING)
# endif
#else
# define IS_CONNECTING(r) 0
#endif

/* Older openldap library doesn't have ldap_controls_dup(). */
static LDAPControl **dup_ldap_controls(void *mem_ctx,
                                       LDAPControl *const *controls)
{
    int i;
    LDAPControl **newc;

    if (!controls) return NULL;

    for (i = 0; controls[i]; i++);

    newc = talloc_array(mem_ctx, LDAPControl *, i + 1);
    if (!newc) goto fail;
    for (i = 0; controls[i]; i++) {
        newc[i] = talloc(newc, LDAPControl);
        if (!newc[i]) goto fail;

        if (controls[i]->ldctl_oid) {
            newc[i]->ldctl_oid = talloc_strdup(newc[i], controls[i]->ldctl_oid);
            if (!newc[i]->ldctl_oid) goto fail;
        } else {
            newc[i]->ldctl_oid = NULL;
        }
        if (controls[i]->ldctl_value.bv_val) {
            newc[i]->ldctl_value.bv_len = controls[i]->ldctl_value.bv_len;
            newc[i]->ldctl_value.bv_val = talloc_memdup(newc[i],
                    controls[i]->ldctl_value.bv_val,
                    newc[i]->ldctl_value.bv_len);
            if (!newc[i]->ldctl_value.bv_val) goto fail;
            newc[i]->ldctl_value.bv_val[newc[i]->ldctl_value.bv_len] = '\0';
        } else {
            newc[i]->ldctl_value.bv_len = 0;
            newc[i]->ldctl_value.bv_val = NULL;
        }
        newc[i]->ldctl_iscritical = controls[i]->ldctl_iscritical;
    }
    newc[i] = NULL;

    return newc;

fail:
    DEBUG(1, ("out of memory\n"));
    talloc_free(newc);
    return NULL;
}

/*
 * ldap_sasl_bind()
 */
struct sasl_bind_state {
    struct sdap_handle *sh;
    char *dn;
    char *mechanism;
    struct berval *cred;
    LDAPControl **sctrls;
    LDAPControl **cctrls;

    int msgid;
    int ret;
};

static int ldap_sasl_bind_try(void *cb_data);

struct tevent_req *ldap_sasl_bind_send(void *mem_ctx, struct tevent_context *ev,
                                       struct sdap_handle *sh, const char *dn,
                                       const char *mechanism,
                                       struct berval *cred,
                                       LDAPControl **sctrls,
                                       LDAPControl **cctrls)
{
    struct tevent_req *req;
    struct sasl_bind_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sasl_bind_state);
    if (!req) return NULL;

    state->sh = sh;
    if (dn) {
        state->dn = talloc_strdup(state, dn);
        if (!state->dn) {
            goto fail;
        }
    }
    if (cred) {
        state->cred = ber_dupbv(NULL, cred);
        if (!state->cred) {
            goto fail;
        }
    }
    if (sctrls) {
        state->sctrls = dup_ldap_controls(state, sctrls);
        if (!state->sctrls) {
            goto fail;
        }
    }
    if (cctrls) {
        state->cctrls = dup_ldap_controls(state, cctrls);
        if (!state->cctrls) {
            goto fail;
        }
    }

    if (ldap_sasl_bind_try(req)) {
        tevent_req_post(req, ev);
    }

    return req;

fail:
    tevent_req_error(req, ENOMEM);
    tevent_req_post(req, ev);
    return req;
}

static int ldap_sasl_bind_try(void *cb_data)
{
    struct tevent_req *req;
    struct sasl_bind_state *state;
    int ret;

    req = talloc_get_type(cb_data, struct tevent_req);
    state = tevent_req_data(req, struct sasl_bind_state);

    DEBUG(4, ("calling ldap_sasl_bind(dn = \"%s\")\n", state->dn));
    set_fd_retry_cb(state->sh, ldap_sasl_bind_try, cb_data);
    ret = ldap_sasl_bind(state->sh->ldap, state->dn, state->mechanism,
                         state->cred, state->sctrls, state->cctrls,
                         &state->msgid);
    set_fd_retry_cb(state->sh, NULL, NULL);

    if (IS_CONNECTING(ret)) {
        DEBUG(4, ("connection in progress, will try again later\n"));
        return 0;
    }

    if (ret != LDAP_SUCCESS || state->msgid == -1) {
        ret = ldap_get_option(state->sh->ldap, LDAP_OPT_RESULT_CODE,
                              &state->ret);
        if (ret != LDAP_OPT_SUCCESS) {
            state->ret = LDAP_LOCAL_ERROR;
        }
        DEBUG(1, ("ldap_sasl_bind() failed (%d) [%s]\n", state->ret,
                  ldap_err2string(state->ret)));
        tevent_req_error(req, EIO);
    } else {
        DEBUG(4, ("ldap_sasl_bind() succeeded, msgid = %d\n", state->msgid));
        state->ret = LDAP_SUCCESS;
        tevent_req_done(req);
    }

    return 1;
}

int ldap_sasl_bind_recv(struct tevent_req *req, int *retp, int *msgidp)
{
    struct sasl_bind_state *state;
    state = tevent_req_data(req, struct sasl_bind_state);

    /* Free stuff that we allocated. */
    ber_bvfree(state->cred);

    if (retp) *retp = state->ret;
    if (msgidp) *msgidp = state->msgid;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/*
 * ldap_search_ext()
 */
struct search_ext_state {
    struct sdap_handle *sh;
    char *base;
    int scope;
    char *filter;
    char **attrs;
    int attrsonly;
    LDAPControl **sctrls;
    LDAPControl **cctrls;
    struct timeval *timeout;
    int sizelimit;

    int msgid;
    int ret;
};

static int ldap_search_ext_try(void *cb_data);

struct tevent_req *ldap_search_ext_send(void *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sdap_handle *sh,
                                        const char *base, int scope,
                                        const char *filter, const char **attrs,
                                        int attrsonly, LDAPControl **sctrls,
                                        LDAPControl **cctrls,
                                        const struct timeval *timeout,
                                        int sizelimit)
{
    struct tevent_req *req;
    struct search_ext_state *state;
    int i;

    req = tevent_req_create(mem_ctx, &state, struct search_ext_state);
    if (!req) return NULL;

    state->sh = sh;
    state->scope = scope;
    state->attrsonly = attrsonly;
    state->sizelimit = sizelimit;

    if (base) {
        state->base = talloc_strdup(state, base);
        if (!state->base) goto fail;
    }
    if (filter) {
        state->filter = talloc_strdup(state, filter);
        if (!state->filter) goto fail;
    }
    if (attrs) {
        for (i = 0; attrs[i]; i++);
        state->attrs = talloc_array(state, char *, i + 1);
        if (!state->attrs) goto fail;
        for (i = 0; attrs[i]; i++) {
            state->attrs[i] = talloc_strdup(state->attrs, attrs[i]);
            if (!state->attrs[i]) goto fail;
        }
        state->attrs[i] = NULL;
    }
    if (sctrls) {
        state->sctrls = dup_ldap_controls(state, sctrls);
        if (!state->sctrls) goto fail;
    }
    if (cctrls) {
        state->cctrls = dup_ldap_controls(state, cctrls);
        if (!state->cctrls) goto fail;
    }
    if (timeout) {
        state->timeout = talloc(state, struct timeval);
        if (!state->timeout) goto fail;
        state->timeout->tv_sec = timeout->tv_sec;
        state->timeout->tv_usec = timeout->tv_usec;
    }

    if (ldap_search_ext_try(req)) {
        tevent_req_post(req, ev);
    }

    return req;

fail:
    tevent_req_error(req, ENOMEM);
    tevent_req_post(req, ev);
    return req;
}

static int ldap_search_ext_try(void *cb_data)
{
    struct tevent_req *req;
    struct search_ext_state *state;

    req = talloc_get_type(cb_data, struct tevent_req);
    state = tevent_req_data(req, struct search_ext_state);

    DEBUG(4, ("calling ldap_search_ext()\n"));
    set_fd_retry_cb(state->sh, ldap_search_ext_try, cb_data);
    state->ret = ldap_search_ext(state->sh->ldap, state->base, state->scope,
                                 state->filter, state->attrs, state->attrsonly,
                                 state->sctrls, state->cctrls, state->timeout,
                                 state->sizelimit, &state->msgid);
    set_fd_retry_cb(state->sh, NULL, NULL);

    if (IS_CONNECTING(state->ret)) {
        DEBUG(4, ("connection in progress, will try again later\n"));
        return 0;
    }

    if (state->ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_search_ext() failed (%d) [%s]\n", state->ret,
                  ldap_err2string(state->ret)));
        tevent_req_error(req, EIO);
    } else {
        DEBUG(4, ("ldap_search_ext() succeeded, msgid = %d\n", state->msgid));
        tevent_req_done(req);
    }

    return 1;
}

int ldap_search_ext_recv(struct tevent_req *req, int *retp, int *msgidp)
{
    struct search_ext_state *state;
    state = tevent_req_data(req, struct search_ext_state);

    if (retp) *retp = state->ret;
    if (msgidp) *msgidp = state->msgid;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/*
 * ldap_extended_operation()
 */
struct extended_operation_state {
    struct sdap_handle *sh;
    char *requestoid;
    struct berval *requestdata;
    LDAPControl **sctrls;
    LDAPControl **cctrls;

    int msgid;
    int ret;
};

static int ldap_extended_operation_try(void *cb_data);

struct tevent_req *ldap_extended_operation_send(void *mem_ctx,
                                                struct tevent_context *ev,
                                                struct sdap_handle *sh,
                                                const char *requestoid,
                                                struct berval *requestdata,
                                                LDAPControl **sctrls,
                                                LDAPControl **cctrls)
{
    struct tevent_req *req;
    struct extended_operation_state *state;

    req = tevent_req_create(mem_ctx, &state, struct extended_operation_state);
    if (!req) return NULL;

    state->sh = sh;

    if (requestoid) {
        state->requestoid = talloc_strdup(state, requestoid);
        if (!state->requestoid) goto fail;
    }
    if (requestdata) {
        state->requestdata = ber_dupbv(NULL, requestdata);
        if (!state->requestdata) {
            goto fail;
        }
    }
    if (sctrls) {
        state->sctrls = dup_ldap_controls(state, sctrls);
        if (!state->sctrls) goto fail;
    }
    if (cctrls) {
        state->cctrls = dup_ldap_controls(state, cctrls);
        if (!state->cctrls) goto fail;
    }

    if (ldap_extended_operation_try(req)) {
        tevent_req_post(req, ev);
    }

    return req;

fail:
    tevent_req_error(req, ENOMEM);
    tevent_req_post(req, ev);
    return req;
}

static int ldap_extended_operation_try(void *cb_data)
{
    struct tevent_req *req;
    struct extended_operation_state *state;

    req = talloc_get_type(cb_data, struct tevent_req);
    state = tevent_req_data(req, struct extended_operation_state);

    DEBUG(4, ("calling ldap_extended_operation()\n"));
    set_fd_retry_cb(state->sh, ldap_extended_operation_try, cb_data);
    state->ret = ldap_extended_operation(state->sh->ldap, state->requestoid,
                                         state->requestdata, state->sctrls,
                                         state->cctrls, &state->msgid);
    set_fd_retry_cb(state->sh, NULL, NULL);

    if (IS_CONNECTING(state->ret)) {
        DEBUG(4, ("connection in progress, will try again later\n"));
        return 0;
    }

    if (state->ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_extended_operation() failed (%d) [%s]\n", state->ret,
                  ldap_err2string(state->ret)));
        tevent_req_error(req, EIO);
    } else {
        DEBUG(4, ("ldap_extended_operation() succeeded, msgid = %d\n",
                  state->msgid));
        tevent_req_done(req);
    }

    return 1;
}

int ldap_extended_operation_recv(struct tevent_req *req,
                                 int *retp, int *msgidp)
{
    struct extended_operation_state *state;
    state = tevent_req_data(req, struct extended_operation_state);

    /* Free stuff that we allocated. */
    ber_bvfree(state->requestdata);

    if (retp) *retp = state->ret;
    if (msgidp) *msgidp = state->msgid;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/*
 * ldap_start_tls()
 */
struct start_tls_state {
    struct sdap_handle *sh;
    LDAPControl **sctrls;
    LDAPControl **cctrls;

    int msgid;
    int ret;
};

static int ldap_start_tls_try(void *cb_data);

struct tevent_req *ldap_start_tls_send(void *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sdap_handle *sh,
                                       LDAPControl **sctrls,
                                       LDAPControl **cctrls)
{
    struct tevent_req *req;
    struct start_tls_state *state;

    req = tevent_req_create(mem_ctx, &state, struct start_tls_state);
    if (!req) return NULL;

    state->sh = sh;

    if (sctrls) {
        state->sctrls = dup_ldap_controls(state, sctrls);
        if (!state->sctrls) goto fail;
    }
    if (cctrls) {
        state->cctrls = dup_ldap_controls(state, cctrls);
        if (!state->cctrls) goto fail;
    }

    if (ldap_start_tls_try(req)) {
        tevent_req_post(req, ev);
    }

    return req;

fail:
    tevent_req_error(req, ENOMEM);
    tevent_req_post(req, ev);
    return req;
}

static int ldap_start_tls_try(void *cb_data)
{
    struct tevent_req *req;
    struct start_tls_state *state;
    int optret;
    char *errmsg;

    req = talloc_get_type(cb_data, struct tevent_req);
    state = tevent_req_data(req, struct start_tls_state);

    DEBUG(4, ("calling ldap_start_tls()\n"));
    set_fd_retry_cb(state->sh, ldap_start_tls_try, cb_data);
    state->ret = ldap_start_tls(state->sh->ldap, state->sctrls, state->cctrls,
                                &state->msgid);
    set_fd_retry_cb(state->sh, NULL, NULL);

    if (IS_CONNECTING(state->ret)) {
        DEBUG(4, ("connection in progress, will try again later\n"));
        return 0;
    }

    if (state->ret != LDAP_SUCCESS) {
        optret = ldap_get_option(state->sh->ldap,
                                 SDAP_DIAGNOSTIC_MESSAGE, (void *)&errmsg);
        if (optret == LDAP_SUCCESS) {
            DEBUG(1, ("ldap_start_tls failed: (%d) [%s] [%s]\n",
                      state->ret,
                      ldap_err2string(state->ret),
                      errmsg));
            ldap_memfree(errmsg);
        } else {
            DEBUG(1, ("ldap_start_tls failed: (%d) [%s]\n", state->ret,
                      ldap_err2string(state->ret)));
        }
        tevent_req_error(req, EIO);
    } else {
        DEBUG(4, ("ldap_start_tls() succeeded, msgid = %d\n", state->msgid));
        tevent_req_done(req);
    }

    return 1;
}

int ldap_start_tls_recv(struct tevent_req *req, int *retp, int *msgidp)
{
    struct start_tls_state *state;
    state = tevent_req_data(req, struct start_tls_state);

    if (retp) *retp = state->ret;
    if (msgidp) *msgidp = state->msgid;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/*
 * ldap_sasl_interactive_bind()
 */
struct sasl_interactive_bind_state {
    struct sdap_handle *sh;
    char *dn;
    char *mechanism;
    LDAPControl **sctrls;
    LDAPControl **cctrls;
    unsigned flags;
    LDAP_SASL_INTERACT_PROC *interact;
    void *defaults;
};

static int ldap_sasl_interactive_bind_try(void *cb_data);

struct tevent_req *
ldap_sasl_interactive_bind_send(void *mem_ctx,
                                struct tevent_context *ev,
                                struct sdap_handle *sh,
                                const char *dn,
                                const char *mechanism,
                                LDAPControl **sctrls,
                                LDAPControl **cctrls,
                                unsigned flags,
                                LDAP_SASL_INTERACT_PROC *interact,
                                void *defaults)
{
    struct tevent_req *req;
    struct sasl_interactive_bind_state *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct sasl_interactive_bind_state);
    if (!req) return NULL;

    state->sh = sh;
    state->flags = flags;
    state->interact = interact;
    state->defaults = defaults;
    if (dn) {
        state->dn = talloc_strdup(state, dn);
        if (!state->dn) {
            goto fail;
        }
    }
    if (mechanism) {
        state->mechanism = talloc_strdup(state, mechanism);
        if (!state->mechanism) {
            goto fail;
        }
    }
    if (sctrls) {
        state->sctrls = dup_ldap_controls(state, sctrls);
        if (!state->sctrls) {
            goto fail;
        }
    }
    if (cctrls) {
        state->cctrls = dup_ldap_controls(state, cctrls);
        if (!state->cctrls) {
            goto fail;
        }
    }

    if (ldap_sasl_interactive_bind_try(req)) {
        tevent_req_post(req, ev);
    }

    return req;

fail:
    tevent_req_error(req, ENOMEM);
    tevent_req_post(req, ev);
    return req;
}

static int ldap_sasl_interactive_bind_try(void *cb_data)
{
    struct tevent_req *req;
    struct sasl_interactive_bind_state *state;
    int ret;

    req = talloc_get_type(cb_data, struct tevent_req);
    state = tevent_req_data(req, struct sasl_interactive_bind_state);

    /* FIXME: Warning, this is a sync call!
     * No async variant exist in openldap libraries yet */

    DEBUG(4, ("calling ldap_sasl_interactive_bind_s(dn = \"%s\")\n",
              state->dn));
    set_fd_retry_cb(state->sh, ldap_sasl_interactive_bind_try, cb_data);
    ret = ldap_sasl_interactive_bind_s(state->sh->ldap, state->dn,
                                       state->mechanism, state->sctrls,
                                       state->cctrls, state->flags,
                                       state->interact, state->defaults);
    set_fd_retry_cb(state->sh, NULL, NULL);

    if (IS_CONNECTING(ret)) {
        DEBUG(4, ("connection in progress, will try again later\n"));
        return 0;
    }

    if (ret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_sasl_bind failed (%d) [%s]\n",
                  ret, ldap_err2string(ret)));

        if (ret == LDAP_SERVER_DOWN) {
            tevent_req_error(req, ETIMEDOUT);
        } else {
            tevent_req_error(req, EIO);
        }
    } else {
        DEBUG(4, ("ldap_sasl_interactive_bind() succeeded\n"));
        tevent_req_done(req);
    }

    return 1;
}

int ldap_sasl_interactive_bind_recv(struct tevent_req *req)
{
    struct sasl_interactive_bind_state *state;
    state = tevent_req_data(req, struct sasl_interactive_bind_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
