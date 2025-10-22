/*
   SSSD

   PAM Responder - passkey related requests

   Copyright (C) Justin Stephenson <jstephen@redhat.com> 2022

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

#include <sys/wait.h>

#include "util/child_common.h"
#include "util/authtok.h"
#include "db/sysdb.h"
#include "db/sysdb_passkey_user_verification.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pamsrv_passkey.h"
#include "krb5_plugin/passkey/passkey.h"

#define PASSKEY_PREFIX "passkey:"
#define USER_VERIFICATION "user_verification="
#define USER_VERIFICATION_LEN (sizeof(USER_VERIFICATION) -1)

struct pam_passkey_table_data {
    hash_table_t *table;
    char *key;
    struct pk_child_user_data *data;
};

struct pam_passkey_verification_enum_str {
    enum passkey_user_verification verification;
    const char *option;
};

struct pam_passkey_verification_enum_str pam_passkey_verification_enum_str[] = {
    { PAM_PASSKEY_VERIFICATION_ON, "on" },
    { PAM_PASSKEY_VERIFICATION_OFF, "off" },
    { PAM_PASSKEY_VERIFICATION_OMIT, "unset" },
    { PAM_PASSKEY_VERIFICATION_INVALID, NULL }
};

const char *pam_passkey_verification_enum_to_string(enum passkey_user_verification verification)
{
    size_t c;

    for (c = 0 ; pam_passkey_verification_enum_str[c].option != NULL; c++) {
        if (pam_passkey_verification_enum_str[c].verification == verification) {
            return pam_passkey_verification_enum_str[c].option;
        }
    }

    return "(NULL)";
}

struct passkey_child_op_enum_str {
    enum passkey_child_op op;
    const char *option;
};

struct passkey_child_op_enum_str passkey_child_op_enum_str[] = {
    { PAM_PASSKEY_OP_PREFLIGHT, "preflight" },
    { PAM_PASSKEY_OP_KERBEROS_AUTH, "kerberos auth" },
    { PAM_PASSKEY_OP_LOCAL_AUTH, "local auth" },
    { PAM_PASSKEY_OP_INVALID, NULL }
};

const char *passkey_child_op_enum_to_string(enum passkey_child_op op)
{
    size_t c;

    for (c = 0 ; passkey_child_op_enum_str[c].option != NULL; c++) {
        if (passkey_child_op_enum_str[c].op == op) {
            return passkey_child_op_enum_str[c].option;
        }
    }

    return "(NULL)";
}

void pam_forwarder_passkey_cb(struct tevent_req *req);

/* Provide appropriate passkey child op to passkey_child_execute()
 * to execute these functions from PAM responder, don't call them
 * directly */
static errno_t passkey_preflight(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct pam_auth_req *pam_req,
                                 struct pam_ctx *pam_ctx,
                                 struct pam_data *pd,
                                 enum passkey_child_op op,
                                 int timeout,
                                 bool debug_libfido2,
                                 enum passkey_user_verification verification,
                                 struct pk_child_user_data *data);
static errno_t passkey_local_auth(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct pam_auth_req *pam_req,
                                  struct pam_ctx *pam_ctx,
                                  struct pam_data *pd,
                                  enum passkey_child_op op,
                                  int timeout,
                                  bool debug_libfido2,
                                  enum passkey_user_verification verification,
                                  struct pk_child_user_data *data);
static errno_t passkey_kerberos_auth(struct pam_ctx *pctx,
                                     struct pam_data *pd,
                                     struct pam_auth_req *preq,
                                     enum passkey_child_op op);

errno_t pam_passkey_concatenate_keys(TALLOC_CTX *mem_ctx,
                                     struct pk_child_user_data *pk_data,
                                     bool kerberos_pa,
                                     char **_result_kh,
                                     char **_result_ph);

struct tevent_req *pam_passkey_get_mapping_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct pam_ctx *pam_ctx,
                                                struct pam_data *pd);
void pam_passkey_get_user_done(struct tevent_req *req);
void pam_passkey_get_mapping_done(struct tevent_req *req);
errno_t pam_passkey_get_mapping_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     struct cache_req_result **_result);

struct passkey_get_mapping_state {
    struct pam_data *pd;
    struct cache_req_result *result;
};


void passkey_kerberos_auth_cb(struct tevent_req *req);

static errno_t passkey_kerberos_auth(struct pam_ctx *pctx,
                                     struct pam_data *pd,
                                     struct pam_auth_req *preq,
                                     enum passkey_child_op op)
{
    errno_t ret;
    const char *prompt;
    const char *key;
    const char *pin;
    size_t pin_len;
    struct pk_child_user_data *data;
    struct tevent_req *req;
    int timeout;
    char *verify_opts;
    bool debug_libfido2;
    enum passkey_user_verification verification;

    ret = sss_authtok_get_passkey(preq, preq->pd->authtok,
                                  &prompt, &key, &pin, &pin_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failure to get passkey authtok\n");
        return EIO;
    }

    if (prompt == NULL || key == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Passkey prompt and key are missing or invalid.\n");
        return EIO;
    }

    data = sss_ptr_hash_lookup(pctx->pk_table_data->table, key,
                               struct pk_child_user_data);
    if (data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to lookup passkey authtok\n");
        return EIO;
    }

    ret = confdb_get_int(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_PASSKEY_CHILD_TIMEOUT, PASSKEY_CHILD_TIMEOUT_DEFAULT,
                         &timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read passkey_child_timeout from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_string(pctx->rctx->cdb, preq, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_PASSKEY_VERIFICATION, NULL,
                            &verify_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read '"CONFDB_MONITOR_PASSKEY_VERIFICATION"' from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Always use verification sent from passkey krb5 plugin */
    if (strcasecmp(data->user_verification, "false") == 0) {
        verification = PAM_PASSKEY_VERIFICATION_OFF;
    } else {
        verification = PAM_PASSKEY_VERIFICATION_ON;
    }

    ret = confdb_get_bool(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                          CONFDB_PAM_PASSKEY_DEBUG_LIBFIDO2, false,
                          &debug_libfido2);
	if (ret != EOK) {
		DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read '"CONFDB_PAM_PASSKEY_DEBUG_LIBFIDO2"' from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
		goto done;
	}

    req = pam_passkey_auth_send(preq->cctx, preq->cctx->ev, timeout, debug_libfido2,
                                verification, pd, data, op);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "passkey auth send failed [%d]: [%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    tevent_req_set_callback(req, passkey_kerberos_auth_cb, preq);

    ret = EAGAIN;

done:

    return ret;

}

void passkey_kerberos_auth_cb(struct tevent_req *req)
{
    struct pam_auth_req *preq = tevent_req_callback_data(req,
                                                         struct pam_auth_req);
    errno_t ret = EOK;
    int child_status;
    uint8_t *buf;
    ssize_t buf_len;

    ret = pam_passkey_auth_recv(req, preq->cctx, &child_status, &buf, &buf_len);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "PAM passkey auth failed [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "passkey child finished with status [%d]\n", child_status);

    pam_check_user_search(preq);

done:
    pam_check_user_done(preq, ret);
}

struct tevent_req *pam_passkey_get_mapping_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct pam_ctx *pam_ctx,
                                                struct pam_data *pd)
{

    struct passkey_get_mapping_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    int ret;
    static const char *attrs[] = { SYSDB_NAME, SYSDB_USER_PASSKEY, NULL };

    req = tevent_req_create(mem_ctx, &state, struct passkey_get_mapping_state);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = cache_req_user_by_name_attrs_send(state, ev,
                                               pam_ctx->rctx,
                                               pam_ctx->rctx->ncache, 0,
                                               pd->domain,
                                               pd->user, attrs);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, pam_passkey_get_mapping_done, req);

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

void pam_passkey_get_mapping_done(struct tevent_req *subreq)
{
    struct cache_req_result *result;
    struct tevent_req *req;
    struct passkey_get_mapping_state *state;

    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct passkey_get_mapping_state);

    ret = cache_req_user_by_name_attrs_recv(state, subreq, &result);
    state->result = result;

    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t pam_passkey_get_mapping_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     struct cache_req_result **_result)
{
    struct passkey_get_mapping_state *state = NULL;

    state = tevent_req_data(req, struct passkey_get_mapping_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_result = talloc_steal(mem_ctx, state->result);
    return EOK;
}

struct passkey_get_user_data_state {
    struct pam_ctx *pam_ctx;
    struct pam_data *pd;
    bool debug_libfido2;
    int timeout;
    enum passkey_user_verification verification;
    struct pk_child_user_data *data;
};

static void passkey_get_user_data_done(struct tevent_req *subreq);

struct tevent_req *passkey_get_user_data_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct pam_ctx *pam_ctx,
                                              struct pam_data *pd)
{
    struct passkey_get_user_data_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct passkey_get_user_data_state);
    if (req == NULL) {
        printf("tevent_req_create() failed\n");
        return NULL;
    }

    state->pam_ctx = pam_ctx;
    state->pd = pd;

    subreq = pam_passkey_get_mapping_send(state, ev, pam_ctx, pd);
    if (subreq == NULL) {
        ret = 1;
        goto done;
    }

    tevent_req_set_callback(subreq, passkey_get_user_data_done, req);

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void passkey_get_user_data_done(struct tevent_req *subreq)
{
    struct passkey_get_user_data_state *state;
    struct tevent_req *req;
    char *domain_name = NULL;
    struct cache_req_result *result = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct passkey_get_user_data_state);

    ret = pam_passkey_get_mapping_recv(state, subreq, &result);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "pam_passkey_get_mapping_recv failed\n");
        goto done;
    }

     if (result == NULL) {
         DEBUG(SSSDBG_CRIT_FAILURE, "cache req result == NULL\n");
         ret = ENOMEM;
         goto done;
    }

    state->data = talloc_zero(state->pam_ctx, struct pk_child_user_data);
    if (!state->data) {
        DEBUG(SSSDBG_CRIT_FAILURE, "state->data == NULL\n");
        ret = ENOMEM;
        goto done;
    }

    /* dns_name is used for AD/IPA, for LDAP fallback to domain->name */
    if (result->domain != NULL) {
        domain_name = result->domain->dns_name;
        if (domain_name == NULL) {
            domain_name = result->domain->name;
        }
    }

    if (domain_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Invalid or missing domain name\n");
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Processing passkey data\n");
    ret = process_passkey_data(state->data, result->msgs[0], domain_name, state->data);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "process_passkey_data failed: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_int(state->pam_ctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_PASSKEY_CHILD_TIMEOUT, PASSKEY_CHILD_TIMEOUT_DEFAULT,
                         &state->timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read passkey_child_timeout from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = passkey_local_verification(state->pam_ctx->rctx->cdb,
                                     result->domain->sysdb,
                                     result->domain->dns_name,
                                     &state->verification,
                                     &state->debug_libfido2);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to check passkey verification [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int passkey_get_user_data_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               int *_timeout,
                               bool *_debug_libfido2,
                               enum passkey_user_verification *_verification,
                               struct pk_child_user_data **_data)
{
    struct passkey_get_user_data_state *state = NULL;

    state = tevent_req_data(req, struct passkey_get_user_data_state);

    *_timeout = state->timeout;
    *_debug_libfido2 = state->debug_libfido2;
    *_verification = state->verification;
    *_data = state->data;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct passkey_check_data_ctx {
    struct cli_ctx *cli_ctx;
    struct pam_ctx *pam_ctx;
    struct pam_data *pd;
    struct pam_auth_req *pam_req;
    enum passkey_child_op op;
};

void passkey_child_get_user_data_done(struct tevent_req *req);

errno_t passkey_child_execute(TALLOC_CTX *mem_ctx,
                               struct cli_ctx *cli_ctx,
                               struct tevent_context *ev,
                               struct pam_auth_req *pam_req,
                               struct pam_ctx *pam_ctx,
                               struct pam_data *pd,
                               enum passkey_child_op op)
{
    errno_t ret = EOK;
    struct tevent_req *req;
    struct passkey_check_data_ctx *pk_check_ctx;

    pk_check_ctx = talloc_zero(mem_ctx, struct passkey_check_data_ctx);
    if (!pk_check_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pk_check_ctx == NULL\n");
        return ENOMEM;
    }

    pk_check_ctx->cli_ctx = cli_ctx;
    pk_check_ctx->pam_ctx = pam_ctx;
    pk_check_ctx->pd = pd;
    pk_check_ctx->pam_req = pam_req;
    pk_check_ctx->op = op;

    req = passkey_get_user_data_send(mem_ctx, ev, pam_ctx, pd);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, passkey_child_get_user_data_done, pk_check_ctx);
done:

    if (ret != EOK) {
        talloc_free(pk_check_ctx);
    }
    return ret;
}

void passkey_child_get_user_data_done(struct tevent_req *req)
{
    int ret;
    struct passkey_check_data_ctx *pk_check_ctx;
    int timeout;
    bool debug_libfido2;
    enum passkey_user_verification verification;
    struct pk_child_user_data *data;

    pk_check_ctx = tevent_req_callback_data(req, struct passkey_check_data_ctx);

    ret = passkey_get_user_data_recv(pk_check_ctx, req, &timeout,
                                     &debug_libfido2, &verification,
                                     &data);
    talloc_free(req);

    if (ret == ENOENT) {
        /* No passkey data, continue through to typical auth flow */
        DEBUG(SSSDBG_TRACE_FUNC, "No passkey data found, skipping passkey auth\n");
        pk_check_ctx->pam_req->passkey_data_exists = false;
        pam_check_user_search(pk_check_ctx->pam_req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected passkey error [%d]: %s.\n",
                                 ret, sss_strerror(ret));
        pk_check_ctx->pam_req->passkey_data_exists = false;
        pk_check_ctx->pam_req->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(pk_check_ctx->pam_req);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Executing passkey operation [%s]\n",
                              passkey_child_op_enum_to_string(pk_check_ctx->op));
    switch (pk_check_ctx->op) {
        case PAM_PASSKEY_OP_PREFLIGHT:
            ret = passkey_preflight(pk_check_ctx->cli_ctx,
                                    pk_check_ctx->cli_ctx->ev,
                                    pk_check_ctx->pam_req,
                                    pk_check_ctx->pam_ctx,
                                    pk_check_ctx->pd,
                                    pk_check_ctx->op,
                                    timeout,
                                    debug_libfido2,
                                    verification,
                                    data);
            break;
        case PAM_PASSKEY_OP_KERBEROS_AUTH:
            ret = passkey_kerberos_auth(pk_check_ctx->pam_ctx,
                                        pk_check_ctx->pd,
                                        pk_check_ctx->pam_req,
                                        pk_check_ctx->op);
            break;
        case PAM_PASSKEY_OP_LOCAL_AUTH:
            ret = passkey_local_auth(pk_check_ctx->cli_ctx,
                                     pk_check_ctx->cli_ctx->ev,
                                     pk_check_ctx->pam_req,
                                     pk_check_ctx->pam_ctx,
                                     pk_check_ctx->pd,
                                     pk_check_ctx->op,
                                     timeout,
                                     debug_libfido2,
                                     verification,
                                     data);
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected passkey operation\n");
            pk_check_ctx->pam_req->passkey_data_exists = false;
            pk_check_ctx->pam_req->pd->pam_status = PAM_SYSTEM_ERR;
            pam_reply(pk_check_ctx->pam_req);
    }
}

struct passkey_preflight_ctx {
    struct pam_ctx *pam_ctx;
    struct pam_data *pd;
    struct pam_auth_req *pam_req;
};

void passkey_preflight_done(struct tevent_req *req);

static errno_t passkey_preflight(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct pam_auth_req *pam_req,
                                 struct pam_ctx *pam_ctx,
                                 struct pam_data *pd,
                                 enum passkey_child_op op,
                                 int timeout,
                                 bool debug_libfido2,
                                 enum passkey_user_verification verification,
                                 struct pk_child_user_data *data)
{
    struct tevent_req *req;
    errno_t ret = EOK;

    struct passkey_preflight_ctx *preflight_ctx;

    preflight_ctx = talloc_zero(mem_ctx, struct passkey_preflight_ctx);
    if (!preflight_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "preflight_ctx == NULL\n");
        return ENOMEM;
    }

    preflight_ctx->pam_ctx = pam_ctx;
    preflight_ctx->pd = pd;
    preflight_ctx->pam_req = pam_req;

    req = pam_passkey_auth_send(mem_ctx, ev, timeout,
                                debug_libfido2, verification,
                                pd, data, op);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "pam_passkey_auth_send failed [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    tevent_req_set_callback(req, passkey_preflight_done, preflight_ctx);
done:

    if (ret != EOK) {
        talloc_free(preflight_ctx);
    }
    return ret;
}

void passkey_preflight_done(struct tevent_req *req)
{
    struct passkey_preflight_ctx *preflight_ctx = tevent_req_callback_data(req,
                                                         struct passkey_preflight_ctx);
    errno_t ret = EOK;
    int child_status;
    const char *prompt_pin;
    enum passkey_user_verification verification = PAM_PASSKEY_VERIFICATION_OMIT;
    bool debug_libfido2 = false;
    bool pin_required;
    int attempts = 8;
    uint8_t *buf;
    char *preflight_str;
    ssize_t buf_len;

    ret = pam_passkey_auth_recv(req, preflight_ctx, &child_status, &buf, &buf_len);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "PAM passkey preflight failed [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    buf[buf_len - 1] = '\0';
    preflight_str = talloc_asprintf(preflight_ctx, "%s", buf);
    if (preflight_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "PAM passkey preflight failed [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "passkey preflight child finished with status [%d]\n", child_status);
    DEBUG(SSSDBG_TRACE_FUNC, "read [%zu] bytes from passkey preflight child.\n", buf_len);

    ret = sss_passkey_preflight_from_json(preflight_str, &pin_required, &attempts);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "failed to parse JSON preflight output [%d]: %s\n",
              ret, sss_strerror(ret));
        /* Preflight operation is not critical, even if preflight operation fails,
         * return the default 8 attempts value. Only 3 or less attempts is acted on
         * by pam_sss, so the '8' value is ignored essentially. 8 is also returned
         * by passkey_child --preflight when an invalid key handle is provided */
        attempts = 8;
    }

    /* Make data available inside pam_auth_req, GDM will use this data */
    preflight_ctx->pam_req->pam_pf_data->attempts = attempts;
    preflight_ctx->pam_req->pam_pf_data->pin_required = pin_required;

    ret = pam_add_response(preflight_ctx->pd, SSS_PAM_PASSKEY_INFO, sizeof(uint32_t),
                           (const uint8_t *) &attempts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed. [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = passkey_local_verification(preflight_ctx->pam_ctx->rctx->cdb,
                                     preflight_ctx->pam_req->domain->sysdb,
                                     preflight_ctx->pam_req->domain->dns_name,
                                     &verification, &debug_libfido2);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to check passkey verification [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    prompt_pin = verification == PAM_PASSKEY_VERIFICATION_OFF ? "false" : "true";

    ret = pam_add_response(preflight_ctx->pd, SSS_PAM_PASSKEY_INFO, strlen(prompt_pin) + 1,
                           (const uint8_t *) prompt_pin);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed. [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    preflight_ctx->pam_req->pd->pam_status = PAM_SUCCESS;
    preflight_ctx->pam_req->pam_pf_data->obtained = true;

done:
    pam_check_user_done(preflight_ctx->pam_req, ret);

    if (ret != EOK) {
        preflight_ctx->pam_req->passkey_data_exists = false;
    }

    pam_reply(preflight_ctx->pam_req);

    return;
}

struct passkey_local_auth_ctx {
    struct pam_ctx *pam_ctx;
    struct pam_data *pd;
    struct pam_auth_req *pam_req;
};

static errno_t passkey_local_auth(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct pam_auth_req *pam_req,
                                  struct pam_ctx *pam_ctx,
                                  struct pam_data *pd,
                                  enum passkey_child_op op,
                                  int timeout,
                                  bool debug_libfido2,
                                  enum passkey_user_verification verification,
                                  struct pk_child_user_data *data)
{
    struct tevent_req *req;
    errno_t ret = EOK;

    struct passkey_local_auth_ctx *pk_local_ctx;

    pk_local_ctx = talloc_zero(mem_ctx, struct passkey_local_auth_ctx);
    if (!pk_local_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pk_local_ctx == NULL\n");
        return ENOMEM;
    }

    pk_local_ctx->pam_ctx = pam_ctx;
    pk_local_ctx->pd = pd;
    pk_local_ctx->pam_req = pam_req;

    req = pam_passkey_auth_send(mem_ctx, ev, timeout,
                                debug_libfido2, verification,
                                pd, data, op);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "pam_passkey_auth_send failed [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    tevent_req_set_callback(req, pam_forwarder_passkey_cb, pam_req);
done:

    if (ret != EOK) {
        talloc_free(pk_local_ctx);
    }
    return ret;
}

errno_t read_passkey_conf_verification(TALLOC_CTX *mem_ctx,
                                       const char *verify_opts,
                                       enum passkey_user_verification *_user_verification)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    char **opts;
    size_t c;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (verify_opts == NULL) {
        ret = EOK;
        goto done;
    }

    ret = split_on_separator(tmp_ctx, verify_opts, ',', true, true, &opts,
                             NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed [%d], %s.\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    for (c = 0; opts[c] != NULL; c++) {
        if (strncasecmp(opts[c], USER_VERIFICATION, USER_VERIFICATION_LEN) == 0) {
            if (strcasecmp("true", &opts[c][USER_VERIFICATION_LEN]) == 0) {
                DEBUG(SSSDBG_TRACE_FUNC, "user_verification set to true.\n");
                *_user_verification = PAM_PASSKEY_VERIFICATION_ON;
            } else if (strcasecmp("false", &opts[c][USER_VERIFICATION_LEN]) == 0) {
                DEBUG(SSSDBG_TRACE_FUNC, "user_verification set to false.\n");
                *_user_verification = PAM_PASSKEY_VERIFICATION_OFF;
            }
        } else {
           DEBUG(SSSDBG_MINOR_FAILURE,
                 "Unsupported passkey verification option [%s], " \
                 "skipping.\n", opts[c]);
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

 errno_t passkey_local_verification(struct confdb_ctx *cdb,
                                    struct sysdb_ctx *sysdb,
                                    const char *domain_name,
                                    enum passkey_user_verification *_user_verification,
                                    bool *_debug_libfido2)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *verification_from_ldap;
    char *verify_opts = NULL;
    bool debug_libfido2 = false;
    enum passkey_user_verification verification = PAM_PASSKEY_VERIFICATION_OMIT;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_domain_get_passkey_user_verification(tmp_ctx, sysdb, domain_name,
                                                     &verification_from_ldap);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read passkeyUserVerification from sysdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        /* This is expected for AD and LDAP */
        ret = EOK;
        goto done;
    }

    ret = confdb_get_bool(cdb, CONFDB_PAM_CONF_ENTRY,
                          CONFDB_PAM_PASSKEY_DEBUG_LIBFIDO2, false,
                          &debug_libfido2);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read '"CONFDB_PAM_PASSKEY_DEBUG_LIBFIDO2"' from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* If require user verification setting is set in LDAP, use it */
    if (verification_from_ldap != NULL) {
        if (strcasecmp(verification_from_ldap, "true") == 0) {
            verification = PAM_PASSKEY_VERIFICATION_ON;
        } else if (strcasecmp(verification_from_ldap, "false") == 0) {
            verification = PAM_PASSKEY_VERIFICATION_OFF;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Passkey verification is being enforced from LDAP\n");
    } else {
        /* No verification set in LDAP, fallback to local sssd.conf setting */
        ret = confdb_get_string(cdb, tmp_ctx, CONFDB_MONITOR_CONF_ENTRY,
                                CONFDB_MONITOR_PASSKEY_VERIFICATION, NULL,
                                &verify_opts);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Failed to read '"CONFDB_MONITOR_PASSKEY_VERIFICATION"' from confdb: [%d]: %s\n",
                ret, sss_strerror(ret));
            goto done;
        }


        ret = read_passkey_conf_verification(tmp_ctx, verify_opts, &verification);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Unable to parse passkey verificaton options.\n");
            /* Continue anyway */
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Passkey verification is being enforced from local configuration\n");
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Passkey verification setting [%s]\n",
                             pam_passkey_verification_enum_to_string(verification));

    *_user_verification = verification;
    *_debug_libfido2 = debug_libfido2;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static bool mapping_is_passkey(TALLOC_CTX *tmp_ctx,
                               const char *mapping_str)
{
    int ret;
    char **mappings;

    if (mapping_str == NULL) {
        return false;
    }

    ret = split_on_separator(tmp_ctx, (const char *) mapping_str, ':', true, true,
                             &mappings, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Incorrectly formatted passkey data [%d]: %s\n",
              ret, sss_strerror(ret));
        return false;
    }

    if (strcasecmp(mappings[0], "passkey") != 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Mapping data found is not passkey related\n");
        return false;
    }

    return true;
}

errno_t process_passkey_data(TALLOC_CTX *mem_ctx,
                             struct ldb_message *user_mesg,
                             const char *domain,
                             struct pk_child_user_data *_data)
{
    struct ldb_message_element *el;
    TALLOC_CTX *tmp_ctx;
    int ret;
    int num_creds = 0;
    char **mappings;
    const char **kh_mappings;
    const char **public_keys;
    const char *domain_name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ERROR("talloc_new() failed\n");
        return ENOMEM;
    }

    el = ldb_msg_find_element(user_mesg, SYSDB_USER_PASSKEY);
    if (el == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No passkey data found\n");
        ret = ENOENT;
        goto done;
    }

    kh_mappings = talloc_zero_array(tmp_ctx, const char *, el->num_values + 1);
    if (kh_mappings == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    public_keys = talloc_zero_array(tmp_ctx, const char *, el->num_values + 1);
    if (public_keys == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; i < el->num_values; i++) {
        /* This attribute may contain other mapping data unrelated to passkey. In that case
         * let's skip it. For example, AD user altSecurityIdentities may store ssh public key
         * or smart card mapping data */
        if ((mapping_is_passkey(tmp_ctx, (const char *)el->values[i].data)) == false) {
            continue;
        }
        ret = split_on_separator(tmp_ctx, (const char *) el->values[i].data, ',', true, true,
                                 &mappings, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Incorrectly formatted passkey data [%d]: %s\n",
                                     ret, sss_strerror(ret));
            goto done;
        }

        kh_mappings[num_creds] = talloc_strdup(kh_mappings, mappings[0] + strlen(PASSKEY_PREFIX));
        if (kh_mappings[num_creds] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup key handle failed.\n");
            ret = ENOMEM;
            goto done;
        }

        public_keys[num_creds] = talloc_strdup(public_keys, mappings[1]);
        if (public_keys[num_creds] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup public key failed.\n");
            ret = ENOMEM;
            goto done;
        }

        num_creds++;
    }

    if (num_creds == 0) {
        ret = ENOENT;
        goto done;
    }

    domain_name = talloc_strdup(tmp_ctx, domain);
    if (domain_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup domain failed.\n");
        ret = ENOMEM;
        goto done;
    }

    _data->domain = talloc_steal(mem_ctx, domain_name);
    _data->key_handles = talloc_steal(mem_ctx, kh_mappings);
    _data->public_keys = talloc_steal(mem_ctx, public_keys);
    _data->num_credentials = num_creds;

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

void pam_forwarder_passkey_cb(struct tevent_req *req)
{
    struct pam_auth_req *preq = tevent_req_callback_data(req,
                                                         struct pam_auth_req);
    errno_t ret = EOK;
    int child_status;
    uint8_t *buf;
    ssize_t buf_len;

    ret = pam_passkey_auth_recv(req, preq->cctx, &child_status, &buf, &buf_len);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "PAM passkey auth failed [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    preq->pd->passkey_local_done = true;

    DEBUG(SSSDBG_TRACE_FUNC, "passkey child finished with status [%d]\n", child_status);
    preq->pd->pam_status = PAM_SUCCESS;
    pam_reply(preq);

    return;

done:
    pam_check_user_done(preq, ret);
}

struct pam_passkey_auth_send_state {
    struct pam_data *pd;
    struct tevent_context *ev;
    struct child_io_fds *io;
    const char *logfile;
    const char **extra_args;
    char *verify_opts;
    int timeout;
    int child_status;
    enum passkey_child_op op;
    uint8_t *read_buf;
    ssize_t read_buf_len;
};

static errno_t passkey_child_exec(struct tevent_req *req);
static void pam_passkey_auth_done(int child_status,
                                  struct tevent_signal *sige,
                                  void *pvt);

static int pin_destructor(void *ptr)
{
    uint8_t *pin = talloc_get_type(ptr, uint8_t);
    if (pin == NULL) return EOK;

    sss_erase_talloc_mem_securely(pin);

    return EOK;
}

errno_t get_passkey_child_write_buffer(TALLOC_CTX *mem_ctx,
                                       struct pam_data *pd,
                                       uint8_t **_buf, size_t *_len)
{
    int ret;
    uint8_t *buf;
    size_t len;
    const char *pin = NULL;
    enum sss_authtok_type type;

    if (pd == NULL || pd->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing authtok.\n");
        return EINVAL;
    }

    type = sss_authtok_get_type(pd->authtok);

    if (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_PASSKEY ||
        sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_PASSKEY_KRB) {
        ret = sss_authtok_get_passkey_pin(pd->authtok, &pin, &len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_passkey_pin failed [%d]: %s\n",
                                    ret, sss_strerror(ret));
            return ret;
        }

        if (pin == NULL || len == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Missing PIN.\n");
            return EINVAL;
        }

        buf = talloc_size(mem_ctx, len);
        if (buf == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
            return ENOMEM;
        }

        talloc_set_destructor((void *) buf, pin_destructor);

        safealign_memcpy(buf, pin, len, NULL);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported authtok type [%s].\n",
                                   sss_authtok_type_to_str(type));
        return EINVAL;
    }

    *_len = len;
    *_buf = buf;

    return EOK;
}

static void pam_passkey_child_read_data(struct tevent_req *subreq)
{
    char *str;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct pam_passkey_auth_send_state *state = tevent_req_data(req, struct pam_passkey_auth_send_state);
    int ret;

    ret = read_pipe_recv(subreq, state, &state->read_buf, &state->read_buf_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->op != PAM_PASSKEY_OP_PREFLIGHT) {
        str = malloc(sizeof(char) * state->read_buf_len);
        if (str == NULL) {
            return;
        }

        snprintf(str, state->read_buf_len, "%s", state->read_buf);

        sss_authtok_set_passkey_reply(state->pd->authtok, str, 0);

        free(str);
   }

    tevent_req_done(req);
    return;
}

static void passkey_child_write_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct pam_passkey_auth_send_state *state = tevent_req_data(req, struct pam_passkey_auth_send_state);

    int ret;

    DEBUG(SSSDBG_TRACE_LIBS, "Sending passkey data complete\n");

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    FD_CLOSE(state->io->write_to_child_fd);

    /* Read data back from passkey child. Passkey child in Kerberos auth provides JSON reply.
     * preflight provides PIN attempts output */
    if (state->op == PAM_PASSKEY_OP_KERBEROS_AUTH || state->op == PAM_PASSKEY_OP_PREFLIGHT) {
        subreq = read_pipe_send(state, state->ev, state->io->read_from_child_fd);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "read_pipe_send failed.\n");
            return;
        }

        tevent_req_set_callback(subreq, pam_passkey_child_read_data, req);
    }
}

errno_t pam_passkey_concatenate_keys(TALLOC_CTX *mem_ctx,
                                     struct pk_child_user_data *pk_data,
                                     bool kerberos_pa,
                                     char **_result_kh,
                                     char **_result_pk)
{
    errno_t ret;
    char *result_kh = NULL;
    char *result_pk = NULL;

    result_kh = talloc_strdup(mem_ctx, pk_data->key_handles[0]);
    if (!kerberos_pa) {
        result_pk = talloc_strdup(mem_ctx, pk_data->public_keys[0]);
    }

    for (int i = 1; i < pk_data->num_credentials; i++) {
        result_kh = talloc_strdup_append(result_kh, ",");
        if (result_kh == NULL) {
            ret = ENOMEM;
            goto done;
        }

        result_kh = talloc_strdup_append(result_kh, pk_data->key_handles[i]);
        if (result_kh == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (!kerberos_pa) {
            result_pk = talloc_strdup_append(result_pk, ",");
            if (result_pk == NULL) {
                ret = ENOMEM;
                goto done;
            }

            result_pk = talloc_strdup_append(result_pk, pk_data->public_keys[i]);
            if (result_kh == NULL || result_pk == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    *_result_kh = result_kh;
    *_result_pk = result_pk;

    ret = EOK;
done:
    return ret;
}

struct tevent_req *
pam_passkey_auth_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      int timeout,
                      bool debug_libfido2,
                      enum passkey_user_verification verification,
                      struct pam_data *pd,
                      struct pk_child_user_data *pk_data,
                      enum passkey_child_op op)
{
    struct tevent_req *req;
    struct pam_passkey_auth_send_state *state;
    size_t arg_c = 0;
    char *result_kh;
    char *result_pk;
    int num_args;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct pam_passkey_auth_send_state);
    if (req == NULL) {
        return NULL;
    }

    state->pd = pd;
    state->ev = ev;
    state->timeout = timeout;
    state->op = op;
    state->logfile = PASSKEY_CHILD_LOG_FILE;

    num_args = 11;
    state->extra_args = talloc_zero_array(state, const char *, num_args + 1);
    if (state->extra_args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (op != PAM_PASSKEY_OP_PREFLIGHT) {
        switch (verification) {
            case PAM_PASSKEY_VERIFICATION_ON:
                state->extra_args[arg_c++] = "--user-verification=true";
                DEBUG(SSSDBG_TRACE_FUNC, "Calling child with user-verification true\n");
                break;
            case PAM_PASSKEY_VERIFICATION_OFF:
                state->extra_args[arg_c++] = "--user-verification=false";
                DEBUG(SSSDBG_TRACE_FUNC, "Calling child with user-verification false\n");
                break;
            default:
                DEBUG(SSSDBG_TRACE_FUNC, "Calling child with user-verification unset\n");
                break;
        }
    }

    ret = pam_passkey_concatenate_keys(state, pk_data, op == PAM_PASSKEY_OP_KERBEROS_AUTH,
                                       &result_kh, &result_pk);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "pam_passkey_concatenate keys failed - [%d]: [%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }


    if (op == PAM_PASSKEY_OP_KERBEROS_AUTH) {
        state->extra_args[arg_c++] = pk_data->crypto_challenge;
        state->extra_args[arg_c++] = "--cryptographic-challenge";
        state->extra_args[arg_c++] = result_kh;
        state->extra_args[arg_c++] = "--key-handle";
        state->extra_args[arg_c++] = pk_data->domain;
        state->extra_args[arg_c++] = "--domain";
        state->extra_args[arg_c++] = "--get-assert";
    } else if (op == PAM_PASSKEY_OP_PREFLIGHT) {
        state->extra_args[arg_c++] = result_kh;
        state->extra_args[arg_c++] = "--key-handle";
        state->extra_args[arg_c++] = pk_data->domain;
        state->extra_args[arg_c++] = "--domain";
        state->extra_args[arg_c++] = "--preflight";
    } else if (op == PAM_PASSKEY_OP_LOCAL_AUTH) {
        state->extra_args[arg_c++] = result_pk;
        state->extra_args[arg_c++] = "--public-key";
        state->extra_args[arg_c++] = result_kh;
        state->extra_args[arg_c++] = "--key-handle";
        state->extra_args[arg_c++] = pk_data->domain;
        state->extra_args[arg_c++] = "--domain";
        state->extra_args[arg_c++] = state->pd->user;
        state->extra_args[arg_c++] = "--username";
        state->extra_args[arg_c++] = "--authenticate";
    } else {
        ret = EINVAL;
        DEBUG(SSSDBG_OP_FAILURE, "Invalid passkey op provided\n");
        goto done;
    }

    ret = passkey_child_exec(req);

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
passkey_child_timeout(struct tevent_context *ev,
                      struct tevent_timer *te,
                      struct timeval tv, void *pvt)
{
    struct tevent_req *req =
            talloc_get_type(pvt, struct tevent_req);
    struct pam_passkey_auth_send_state *state =
            tevent_req_data(req, struct pam_passkey_auth_send_state);

    DEBUG(SSSDBG_CRIT_FAILURE, "Timeout reached for passkey child, "
                               "consider increasing passkey_child_timeout\n");
    state->child_status = ETIMEDOUT;
    tevent_req_error(req, ERR_PASSKEY_CHILD_TIMEOUT);
}

static errno_t passkey_child_exec(struct tevent_req *req)
{
    struct pam_passkey_auth_send_state *state;
    struct tevent_req *subreq;
    uint8_t *write_buf = NULL;
    size_t write_buf_len = 0;
    int ret;
    bool local_auth;

    state = tevent_req_data(req, struct pam_passkey_auth_send_state);

    local_auth = (state->op == PAM_PASSKEY_OP_LOCAL_AUTH);

    ret = sss_child_start(state, state->ev,
                          PASSKEY_CHILD_PATH, state->extra_args, false,
                          state->logfile, STDOUT_FILENO,
                          (local_auth) ? pam_passkey_auth_done : NULL, req,
                          state->timeout, passkey_child_timeout, req, true,
                          &(state->io));
    if (ret != EOK) {
        return ERR_PASSKEY_CHILD;
    }

    /* PIN is needed except for Preflight operation */
    if (state->op != PAM_PASSKEY_OP_PREFLIGHT) {
        if (sss_authtok_get_type(state->pd->authtok) != SSS_AUTHTOK_TYPE_EMPTY) {
            ret = get_passkey_child_write_buffer(state, state->pd, &write_buf,
                                                 &write_buf_len);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "get_passkey_child_write_buffer failed [%d]: %s.\n",
                      ret, sss_strerror(ret));
                return ret;
            }
        }
    }

    if (write_buf_len != 0 || state->op == PAM_PASSKEY_OP_PREFLIGHT) {
        subreq = write_pipe_send(state, state->ev, write_buf, write_buf_len,
                                 state->io->write_to_child_fd);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "write_pipe_send failed.\n");
            return ERR_PASSKEY_CHILD;
        }
        tevent_req_set_callback(subreq, passkey_child_write_done, req);
    }
    /* Now either wait for the timeout to fire or the child to finish */
    return EAGAIN;
}

errno_t pam_passkey_auth_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              int *child_status,
                              uint8_t **buf,
                              ssize_t *buf_len)
{
    struct pam_passkey_auth_send_state *state =
                              tevent_req_data(req, struct pam_passkey_auth_send_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *child_status = state->child_status;
    *buf = talloc_steal(mem_ctx, state->read_buf);
    *buf_len = state->read_buf_len;

    return EOK;
}

errno_t decode_pam_passkey_msg(TALLOC_CTX *mem_ctx,
                               uint8_t *buf,
                               size_t len,
                               struct pk_child_user_data **_data)
{

    size_t p = 0;
    size_t pctr = 0;
    errno_t ret;
    size_t offset;
    struct pk_child_user_data *data = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    data = talloc_zero(tmp_ctx, struct pk_child_user_data);
    if (data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to talloc passkey data.\n");
        ret = ENOMEM;
        goto done;
    }

    data->user_verification = talloc_strdup(data, (char *) &buf[p]);
    if (data->user_verification == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to strdup passkey prompt.\n");
        ret = ENOMEM;
        goto done;
    }

    offset = strlen(data->user_verification) + 1;
    if (offset >= len) {
        DEBUG(SSSDBG_OP_FAILURE, "passkey prompt offset failure.\n");
        ret = EIO;
        goto done;
    }

    data->crypto_challenge = talloc_strdup(data, (char *) &buf[p + offset]);
    if (data->crypto_challenge == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to strdup passkey challenge.\n");
        ret = ENOMEM;
        goto done;
    }

    offset += strlen(data->crypto_challenge) + 1;
    if (offset >= len) {
        DEBUG(SSSDBG_OP_FAILURE, "passkey challenge offset failure.\n");
        ret = EIO;
        goto done;
    }


    data->domain = talloc_strdup(data, (char *) &buf[p] + offset);
    if (data->domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to strdup passkey domain.\n");
        ret = ENOMEM;
        goto done;
    }

    offset += strlen(data->domain) + 1;
    if (offset >= len) {
        DEBUG(SSSDBG_OP_FAILURE, "passkey domain offset failure.\n");
        ret = EIO;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&data->num_credentials, &buf[p + offset], &pctr);
    size_t list_sz = (size_t) data->num_credentials;

    offset += sizeof(uint32_t);

    data->key_handles = talloc_zero_array(data, const char *, list_sz);

    for (int i = 0; i < list_sz; i++) {
        data->key_handles[i] = talloc_strdup(data->key_handles, (char *) &buf[p + offset]);
        if (data->key_handles[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to strdup passkey list.\n");
            ret = ENOMEM;
            goto done;
        }

        offset += strlen(data->key_handles[i]) + 1;
    }

    *_data = talloc_steal(mem_ctx, data);

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t save_passkey_data(TALLOC_CTX *mem_ctx,
                          struct pam_ctx *pctx,
                          struct pk_child_user_data *data,
                          struct pam_auth_req *preq)
{
    char *pk_key;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Passkey data (pk_table_data) is stolen onto client ctx, it will
     * be freed when the client closes, and the sss_ptr_hash interface
     * takes care of automatically removing it from the hash table then */
    pctx->pk_table_data = talloc_zero(tmp_ctx, struct pam_passkey_table_data);
    if (pctx->pk_table_data == NULL) {
        return ENOMEM;
    }

    if (pctx->pk_table_data->table == NULL) {
        pctx->pk_table_data->table = sss_ptr_hash_create(pctx->pk_table_data,
                                                         NULL, NULL);
        if (pctx->pk_table_data->table == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    pk_key = talloc_asprintf(tmp_ctx, "%s", data->crypto_challenge);
    if (pk_key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    pctx->pk_table_data->key = talloc_strdup(pctx->pk_table_data, pk_key);
    if (pctx->pk_table_data->key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_ptr_hash_add(pctx->pk_table_data->table, pk_key, data,
                           struct pk_child_user_data);
    if (ret == EEXIST) {
        DEBUG(SSSDBG_TRACE_FUNC, "pk_table key [%s] already exists\n",
                                 pk_key);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to add pk data to hash table "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    talloc_steal(mem_ctx, pctx->pk_table_data);
    pctx->pk_table_data->data = talloc_steal(mem_ctx, data);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t pam_eval_passkey_response(struct pam_ctx *pctx,
                                  struct pam_data *pd,
                                  struct pam_auth_req *preq,
                                  bool *_pk_preauth_done)
{
    struct response_data *pk_resp;
    struct pk_child_user_data *pk_data;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    pk_resp = pd->resp_list;

    while (pk_resp != NULL) {
        switch (pk_resp->type) {
        case SSS_PAM_PASSKEY_KRB_INFO:
            if (!pctx->passkey_auth) {
                /* Passkey auth is disabled. To avoid passkey prompts appearing,
                 * don't send SSS_PAM_PASSKEY_KRB_INFO to the client and
                 * add a dummy response to fallback to normal auth */
                pk_resp->do_not_send_to_client = true;
                ret = pam_add_response(pd, SSS_OTP, 0, NULL);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                    goto done;
                }
                break;
            }
            ret = decode_pam_passkey_msg(tmp_ctx, pk_resp->data, pk_resp->len, &pk_data);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to decode passkey msg\n");
                ret = EIO;
                goto done;
            }

            ret = save_passkey_data(preq->cctx, pctx, pk_data, preq);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to save passkey msg\n");
                ret = EIO;
                goto done;
            }
            break;
        /* Passkey non-kerberos preauth has already run */
        case SSS_PAM_PASSKEY_INFO:
           *_pk_preauth_done = true;
        default:
            break;
        }
        pk_resp = pk_resp->next;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}


static void
pam_passkey_auth_done(int child_status,
                      struct tevent_signal *sige,
                      void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);

    struct pam_passkey_auth_send_state *state =
                              tevent_req_data(req, struct pam_passkey_auth_send_state);
    state->child_status = WEXITSTATUS(child_status);
    if (WIFEXITED(child_status)) {
        if (WEXITSTATUS(child_status) != 0) {
            DEBUG(SSSDBG_OP_FAILURE,
            PASSKEY_CHILD_PATH " failed with status [%d]. Check passkey_child"
            " logs for more information.\n",
            WEXITSTATUS(child_status));
        tevent_req_error(req, ERR_PASSKEY_CHILD);
        return;
        }
    } else if (WIFSIGNALED(child_status)) {
        DEBUG(SSSDBG_OP_FAILURE,
              PASSKEY_CHILD_PATH " was terminated by signal [%d]. Check passkey_child"
              " logs for more information.\n",
              WTERMSIG(child_status));
        tevent_req_error(req, ECHILD);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "passkey data is valid. Mark done\n");

    tevent_req_done(req);
    return;
}

bool may_do_passkey_auth(struct pam_ctx *pctx,
                         struct pam_data *pd)
{
#ifndef BUILD_PASSKEY
    DEBUG(SSSDBG_TRACE_FUNC, "Passkey auth not possible, SSSD built without passkey support!\n");
    return false;
#else
    if (!pctx->passkey_auth) {
        return false;
    }

    if (pd->cmd != SSS_PAM_PREAUTH && pd->cmd != SSS_PAM_AUTHENTICATE) {
        return false;
    }

    if (pd->service == NULL || *pd->service == '\0') {
        return false;
    }

    return true;
#endif /* BUILD_PASSKEY */
}
