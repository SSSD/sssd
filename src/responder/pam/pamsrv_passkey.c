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

#include "util/child_common.h"
#include "util/authtok.h"
#include "db/sysdb.h"
#include "db/sysdb_passkey_user_verification.h"
#include "responder/pam/pamsrv.h"

#include "responder/pam/pamsrv_passkey.h"

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

#define PASSKEY_PREFIX "passkey:"
#define USER_VERIFICATION "user_verification="
#define USER_VERIFICATION_LEN (sizeof(USER_VERIFICATION) -1)

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

struct passkey_ctx {
    struct pam_ctx *pam_ctx;
    struct tevent_context *ev;
    struct pam_data *pd;
    struct pam_auth_req *preq;
};

void pam_forwarder_passkey_cb(struct tevent_req *req);

errno_t pam_passkey_concatenate_keys(TALLOC_CTX *mem_ctx,
                                     struct pk_child_user_data *pk_data,
                                     bool kerberos_pa,
                                     char **_result_kh,
                                     char **_result_ph);

struct tevent_req *pam_passkey_get_mapping_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct passkey_ctx *pctx);
void pam_passkey_get_user_done(struct tevent_req *req);
void pam_passkey_get_mapping_done(struct tevent_req *req);
errno_t pam_passkey_get_mapping_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     struct cache_req_result **_result);

struct passkey_get_mapping_state {
    struct pam_data *pd;
    struct cache_req_result *result;
};

errno_t passkey_local(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct pam_ctx *pam_ctx,
                      struct pam_auth_req *preq,
                      struct pam_data *pd)
{
    struct tevent_req *req;
    struct passkey_ctx *pctx;
    errno_t ret;

    pctx = talloc_zero(mem_ctx, struct passkey_ctx);
    if (pctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "pctx == NULL\n");
        return ENOMEM;
    }

    pctx->pd = pd;
    pctx->pam_ctx = pam_ctx;
    pctx->ev = ev;
    pctx->preq = preq;

    DEBUG(SSSDBG_TRACE_FUNC, "Checking for passkey authentication data\n");

    req = pam_passkey_get_mapping_send(mem_ctx, pctx->ev, pctx);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "pam_passkey_get_mapping_send failed.\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, pam_passkey_get_user_done, pctx);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        talloc_free(pctx);
    }

    return ret;
}

struct tevent_req *pam_passkey_get_mapping_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct passkey_ctx *pk_ctx)
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

    subreq = cache_req_user_by_name_attrs_send(state, pk_ctx->ev,
                                               pk_ctx->pam_ctx->rctx,
                                               pk_ctx->pam_ctx->rctx->ncache, 0,
                                               pk_ctx->pd->domain,
                                               pk_ctx->pd->user, attrs);
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

static errno_t passkey_local_verification(TALLOC_CTX *mem_ctx,
                                          struct passkey_ctx *pctx,
                                          struct confdb_ctx *cdb,
                                          struct sysdb_ctx *sysdb,
                                          const char *domain_name,
                                          struct pk_child_user_data *pk_data,
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

    ret = confdb_get_bool(pctx->pam_ctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
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
        ret = confdb_get_string(pctx->pam_ctx->rctx->cdb, tmp_ctx, CONFDB_MONITOR_CONF_ENTRY,
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

errno_t process_passkey_data(TALLOC_CTX *mem_ctx,
                             struct ldb_message *user_mesg,
                             const char *domain,
                             struct pk_child_user_data *_data)
{
    struct ldb_message_element *el;
    TALLOC_CTX *tmp_ctx;
    int ret;
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
        ret = split_on_separator(tmp_ctx, (const char *) el->values[i].data, ',', true, true,
                                 &mappings, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Incorrectly formatted passkey data [%d]: %s\n",
                                     ret, sss_strerror(ret));
            goto done;
        }

        kh_mappings[i] = talloc_strdup(kh_mappings, mappings[0] + strlen(PASSKEY_PREFIX));
        if (kh_mappings[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup key handle failed.\n");
            ret = ENOMEM;
            goto done;
        }

        public_keys[i] = talloc_strdup(public_keys, mappings[1]);
        if (public_keys[i] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup public key failed.\n");
            ret = ENOMEM;
            goto done;
        }
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
    _data->num_credentials = el->num_values;

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

    ret = pam_passkey_auth_recv(req, &child_status);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "PAM passkey auth failed [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "passkey child finished with status [%d]\n", child_status);
    preq->pd->pam_status = PAM_SUCCESS;
    pam_reply(preq);

    return;

done:
    pam_check_user_done(preq, ret);
}

void pam_passkey_get_user_done(struct tevent_req *req)
{
    int ret;
    struct passkey_ctx *pctx;
    bool debug_libfido2 = false;
    char *domain_name = NULL;
    int timeout;
    struct cache_req_result *result = NULL;
    struct pk_child_user_data *pk_data = NULL;
    enum passkey_user_verification verification = PAM_PASSKEY_VERIFICATION_OMIT;

    pctx = tevent_req_callback_data(req, struct passkey_ctx);

    ret = pam_passkey_get_mapping_recv(pctx, req, &result);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "cache_req_user_by_name_attrs_recv failed [%d]: %s.\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    if (result == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cache req result == NULL\n");
        ret = ENOMEM;
        goto done;
    }

    pk_data = talloc_zero(pctx, struct pk_child_user_data);
    if (!pk_data) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pk_data == NULL\n");
        ret = ENOMEM;
        goto done;
    }

    /* Use dns_name for AD/IPA - for LDAP fallback to domain->name */
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

    /* Get passkey data */
    DEBUG(SSSDBG_TRACE_ALL, "Processing passkey data\n");
    ret = process_passkey_data(pk_data, result->msgs[0], domain_name, pk_data);
    if (ret == ENOENT) {
        goto done;
    }

    /* timeout */
    ret = confdb_get_int(pctx->pam_ctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_PASSKEY_CHILD_TIMEOUT, PASSKEY_CHILD_TIMEOUT_DEFAULT,
                         &timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to read passkey_child_timeout from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = passkey_local_verification(pctx, pctx, pctx->pam_ctx->rctx->cdb,
                                            result->domain->sysdb, result->domain->dns_name,
                                            pk_data, &verification, &debug_libfido2);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to check passkey verification [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Preauth respond with prompt_pin true or false based on user verification */
    if (pctx->pd->cmd == SSS_PAM_PREAUTH) {
        const char *prompt_pin = verification == PAM_PASSKEY_VERIFICATION_OFF ? "false" : "true";

        ret = pam_add_response(pctx->pd, SSS_PAM_PASSKEY_INFO, strlen(prompt_pin) + 1,
                               (const uint8_t *) prompt_pin);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed. [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        pctx->pd->pam_status = PAM_SUCCESS;
        pam_reply(pctx->preq);
        talloc_free(pk_data);
        return;
    }

    req = pam_passkey_auth_send(pctx, pctx->ev, timeout, debug_libfido2,
                                verification, pctx->pd, pk_data, false);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "pam_passkey_auth_send failed [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    tevent_req_set_callback(req, pam_forwarder_passkey_cb, pctx->preq);

done:
    if (pk_data != NULL) {
        talloc_free(pk_data);
    }

    if (ret == ENOENT) {
        /* No passkey data, continue through to typical auth flow */
        DEBUG(SSSDBG_TRACE_FUNC, "No passkey data found, skipping passkey auth\n");
        pctx->preq->passkey_data_exists = false;
        pam_check_user_search(pctx->preq);
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected passkey error [%d]: %s."
                                 " Skipping passkey auth\n",
                                 ret, sss_strerror(ret));
        pam_check_user_search(pctx->preq);
    }

    return;
}


struct pam_passkey_auth_send_state {
    struct pam_data *pd;
    struct tevent_context *ev;
    struct sss_child_ctx_old *child_ctx;
    struct child_io_fds *io;
    const char *logfile;
    const char **extra_args;
    char *verify_opts;
    int timeout;
    int child_status;
    bool kerberos_pa;
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

    if (pd == NULL || pd->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing authtok.\n");
        return EINVAL;
    }

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
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported authtok type [%d].\n",
                                   sss_authtok_get_type(pd->authtok));
        return EINVAL;
    }

    *_len = len;
    *_buf = buf;

    return EOK;
}

static void pam_passkey_child_read_data(struct tevent_req *subreq)
{
    uint8_t *buf;
    ssize_t buf_len;
    char *str;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct pam_passkey_auth_send_state *state = tevent_req_data(req, struct pam_passkey_auth_send_state);
    int ret;

    ret = read_pipe_recv(subreq, state, &buf, &buf_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    str = malloc(sizeof(char) * buf_len);
    if (str == NULL) {
        return;
    }

    snprintf(str, buf_len, "%s", buf);

    sss_authtok_set_passkey_reply(state->pd->authtok, str, 0);

    free(str);

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

    PIPE_FD_CLOSE(state->io->write_to_child_fd);

    if (state->kerberos_pa) {
        /* Read data back from passkey child */
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
                      bool kerberos_pa)
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
    state->kerberos_pa = kerberos_pa;
    state->logfile = PASSKEY_CHILD_LOG_FILE;
    state->io = talloc(state, struct child_io_fds);
    if (state->io == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc child fds failed.\n");
        ret = ENOMEM;
        goto done;
    }
    state->io->write_to_child_fd = -1;
    state->io->read_from_child_fd = -1;
    talloc_set_destructor((void *) state->io, child_io_destructor);

    num_args = 11;
    state->extra_args = talloc_zero_array(state, const char *, num_args + 1);
    if (state->extra_args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

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

    ret = pam_passkey_concatenate_keys(state, pk_data, state->kerberos_pa,
                                       &result_kh, &result_pk);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "pam_passkey_concatenate keys failed - [%d]: [%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }


    if (state->kerberos_pa) {
        state->extra_args[arg_c++] = pk_data->crypto_challenge;
        state->extra_args[arg_c++] = "--cryptographic-challenge";
        state->extra_args[arg_c++] = result_kh;
        state->extra_args[arg_c++] = "--key-handle";
        state->extra_args[arg_c++] = pk_data->domain;
        state->extra_args[arg_c++] = "--domain";
        state->extra_args[arg_c++] = "--get-assert";
    } else {
        state->extra_args[arg_c++] = result_pk;
        state->extra_args[arg_c++] = "--public-key";
        state->extra_args[arg_c++] = result_kh;
        state->extra_args[arg_c++] = "--key-handle";
        state->extra_args[arg_c++] = pk_data->domain;
        state->extra_args[arg_c++] = "--domain";
        state->extra_args[arg_c++] = state->pd->user;
        state->extra_args[arg_c++] = "--username";
        state->extra_args[arg_c++] = "--authenticate";
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

static errno_t passkey_child_exec(struct tevent_req *req)
{
    struct pam_passkey_auth_send_state *state;
    struct tevent_req *subreq;
    int pipefd_from_child[2] = PIPE_INIT;
    int pipefd_to_child[2] = PIPE_INIT;
    pid_t child_pid;
    uint8_t *write_buf = NULL;
    size_t write_buf_len = 0;
    struct timeval tv;
    bool endtime;
    int ret;

    state = tevent_req_data(req, struct pam_passkey_auth_send_state);

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    child_pid = fork();
    if (child_pid == 0) { /* child */
        exec_child_ex(state, pipefd_to_child, pipefd_from_child,
                      PASSKEY_CHILD_PATH, state->logfile, state->extra_args,
                      false, STDIN_FILENO, STDOUT_FILENO);
        /* We should never get here */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Could not exec passkey child\n");
        goto done;
    } else if (child_pid > 0) { /* parent */
        state->io->read_from_child_fd = pipefd_from_child[0];
        PIPE_FD_CLOSE(pipefd_from_child[1]);
        sss_fd_nonblocking(state->io->read_from_child_fd);

        state->io->write_to_child_fd = pipefd_to_child[1];
        PIPE_FD_CLOSE(pipefd_to_child[0]);
        sss_fd_nonblocking(state->io->write_to_child_fd);

        /* Set up SIGCHLD handler */
        if (state->kerberos_pa) {
            ret = child_handler_setup(state->ev, child_pid, NULL, NULL, NULL);
        } else {
            ret = child_handler_setup(state->ev, child_pid,
                                      pam_passkey_auth_done, req,
                                      &state->child_ctx);
        }

        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not set up child handlers [%d]: %s\n",
                  ret, sss_strerror(ret));
            ret = ERR_PASSKEY_CHILD;
            goto done;
        }

        /* Set up timeout handler */
        tv = tevent_timeval_current_ofs(state->timeout, 0);
        endtime = tevent_req_set_endtime(req, state->ev, tv);
        if (endtime == false) {
            ret = ERR_PASSKEY_CHILD;
            goto done;
        }

        /* PIN is needed */
        if (sss_authtok_get_type(state->pd->authtok) != SSS_AUTHTOK_TYPE_EMPTY) {
            ret = get_passkey_child_write_buffer(state, state->pd, &write_buf,
                                     &write_buf_len);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "get_passkey_child_write_buffer failed [%d]: %s.\n",
                      ret, sss_strerror(ret));
                goto done;
            }
        }

        if (write_buf_len != 0) {
            subreq = write_pipe_send(state, state->ev, write_buf, write_buf_len,
                                     state->io->write_to_child_fd);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "write_pipe_send failed.\n");
                ret = ERR_PASSKEY_CHILD;
                goto done;
            }
            tevent_req_set_callback(subreq, passkey_child_write_done, req);
        }
        /* Now either wait for the timeout to fire or the child to finish */
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "fork failed [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    return EAGAIN;

done:
    if (ret != EOK) {
        PIPE_CLOSE(pipefd_from_child);
        PIPE_CLOSE(pipefd_to_child);
    }

    return ret;
}

errno_t pam_passkey_auth_recv(struct tevent_req *req,
                              int *child_status)
{
    struct pam_passkey_auth_send_state *state =
                              tevent_req_data(req, struct pam_passkey_auth_send_state);

    *child_status = state->child_status;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
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
