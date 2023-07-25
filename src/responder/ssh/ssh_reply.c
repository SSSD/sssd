/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

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

#include "config.h"

#include <talloc.h>
#include <ldb.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"
#include "util/cert.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/ssh/ssh_private.h"

/* Locally used flag for libldb's ldb_message_element structure to indicate
 * binary data. Since the related data is only used in memory it is safe. If
 * should be used with care if libldb's I/O operations are involved. */
#define SSS_EL_FLAG_BIN_DATA (1<<4)

static errno_t decode_and_add_base64_data(struct sss_packet *packet,
                                          struct ldb_message_element *el,
                                          bool skip_base64_decode,
                                          size_t fqname_len,
                                          const char *fqname,
                                          size_t *c)
{
    uint8_t *key;
    size_t key_len;
    uint8_t *body;
    size_t body_len;
    int ret;
    size_t d;
    TALLOC_CTX *tmp_ctx;

    if (el == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Mssing element, nothing to do.\n");
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    for (d = 0; d < el->num_values; d++) {
        if (el->values[d].length == 0 && el->values[d].data == NULL) {
            /* skip empty keys, e.g. due to invalid certificate */
            continue;
        }
        if (skip_base64_decode || (el->flags & SSS_EL_FLAG_BIN_DATA)) {
            key = el->values[d].data;
            key_len = el->values[d].length;
        } else  {
            key = sss_base64_decode(tmp_ctx, (const char *) el->values[d].data,
                                    &key_len);
            if (key == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
                ret = ENOMEM;
                goto done;
            }
        }

        ret = sss_packet_grow(packet,
                              3*sizeof(uint32_t) + key_len + fqname_len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
            goto done;
        }
        sss_packet_get_body(packet, &body, &body_len);

        SAFEALIGN_SET_UINT32(body+(*c), 0, c);
        SAFEALIGN_SET_UINT32(body+(*c), fqname_len, c);
        safealign_memcpy(body+(*c), fqname, fqname_len, c);
        SAFEALIGN_SET_UINT32(body+(*c), key_len, c);
        safealign_memcpy(body+(*c), key, key_len, c);

    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

struct ssh_get_output_keys_state {
    struct tevent_context *ev;
    struct cli_ctx *cli_ctx;
    struct ldb_message *msg;
    char *cert_verification_opts;
    int p11_child_timeout;
    struct ssh_ctx *ssh_ctx;
    struct ldb_message_element *user_cert;
    struct ldb_message_element *user_cert_override;
    struct ldb_message_element *current_cert;

    const char *name;
    struct ldb_message_element **elements;
    uint32_t num_keys;
    size_t iter;
};

void ssh_get_output_keys_done(struct tevent_req *subreq);

struct tevent_req *ssh_get_output_keys_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct cli_ctx *cli_ctx,
                                            struct sss_domain_info *domain,
                                            struct ldb_message *msg)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;
    struct ssh_get_output_keys_state *state;

    req = tevent_req_create(mem_ctx, &state, struct ssh_get_output_keys_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->cli_ctx = cli_ctx;
    state->msg = msg;
    state->num_keys = 0;
    state->iter = 0;
    state->ssh_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct ssh_ctx);
    if (state->ssh_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing ssh responder context.\n");
        ret = EINVAL;
        goto done;
    }

    state->name = ldb_msg_find_attr_as_string(state->msg, SYSDB_NAME, NULL);
    if (state->name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing name.\n");
        ret = EINVAL;
        goto done;
    }

    state->elements = talloc_zero_array(state, struct ldb_message_element *, 6);
    if (state->elements == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->elements[state->iter] = ldb_msg_find_element(state->msg,
                                                        SYSDB_SSH_PUBKEY);
    if (state->elements[state->iter] != NULL) {
        state->num_keys += state->elements[state->iter]->num_values;
        state->iter++;
    }

    state->elements[state->iter] = ldb_msg_find_element(state->msg,
                                            ORIGINALAD_PREFIX SYSDB_SSH_PUBKEY);
    if (state->elements[state->iter] != NULL) {
        state->num_keys += state->elements[state->iter]->num_values;
        state->iter++;
    }

    if (DOM_HAS_VIEWS(domain)) {
        state->elements[state->iter] = ldb_msg_find_element(state->msg,
                                              OVERRIDE_PREFIX SYSDB_SSH_PUBKEY);
        if (state->elements[state->iter] != NULL) {
            state->num_keys += state->elements[state->iter]->num_values;
            state->iter++;
        }
    }

    if (!state->ssh_ctx->use_cert_keys) {
        DEBUG(SSSDBG_TRACE_ALL, "Skipping keys from certificates.\n");
        ret = EOK;
        goto done;
    }

    if (state->ssh_ctx->cert_rules_error) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Skipping keys from certificates because there was an error "
              "while processing matching rules.\n");
        ret = EOK;
        goto done;
    }

    ret = confdb_get_string(cli_ctx->rctx->cdb, state,
                            CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_CERT_VERIFICATION, NULL,
                            &state->cert_verification_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read verification options from confdb: [%d] %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    state->p11_child_timeout = -1;
    ret = confdb_get_int(cli_ctx->rctx->cdb, CONFDB_SSH_CONF_ENTRY,
                         CONFDB_PAM_P11_CHILD_TIMEOUT, -1,
                         &state->p11_child_timeout);
    if (ret != EOK || state->p11_child_timeout == -1) {
        /* check pam configuration as well or use default */
        ret = confdb_get_int(cli_ctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                             CONFDB_PAM_P11_CHILD_TIMEOUT,
                             P11_CHILD_TIMEOUT_DEFAULT,
                             &state->p11_child_timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to read p11_child_timeout from confdb: [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    state->user_cert = ldb_msg_find_element(state->msg, SYSDB_USER_CERT);
    if (DOM_HAS_VIEWS(domain)) {
        state->user_cert_override = ldb_msg_find_element(state->msg,
                                               OVERRIDE_PREFIX SYSDB_USER_CERT);
    }

    if (state->user_cert == NULL && state->user_cert_override == NULL) {
        /* no certificates to convert, we are done */
        ret = EOK;
        goto done;
    }

    state->current_cert = state->user_cert != NULL ? state->user_cert
                                                   : state->user_cert_override;

    subreq = cert_to_ssh_key_send(state, state->ev,
                                  P11_CHILD_LOG_FILE,
                                  state->p11_child_timeout,
                                  state->ssh_ctx->ca_db,
                                  state->ssh_ctx->sss_certmap_ctx,
                                  state->current_cert->num_values,
                                  state->current_cert->values,
                                  state->cert_verification_opts);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "cert_to_ssh_key_send failed.\n");
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ssh_get_output_keys_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        if (ret == EOK) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
        tevent_req_post(req, ev);
    }

    return req;
}

void ssh_get_output_keys_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ssh_get_output_keys_state *state = tevent_req_data(req,
                                              struct ssh_get_output_keys_state);
    int ret;
    struct ldb_val *keys;
    size_t valid_keys;

    ret = cert_to_ssh_key_recv(subreq, state, &keys, &valid_keys);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (ret == ERR_P11_CHILD_TIMEOUT) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "cert_to_ssh_key request timeout, "
                  "consider increasing p11_child_timeout.\n");
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "cert_to_ssh_key request failed, ssh keys derived "
                  "from certificates will be skipped.\n");
        }
        /* Ignore ssh keys from certificates and return what we already have */
        tevent_req_done(req);
        return;
    }

    state->elements[state->iter] = talloc_zero(state->elements,
                                                struct ldb_message_element);
    if (state->elements[state->iter] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }
    state->elements[state->iter]->values = talloc_steal(
                                                   state->elements[state->iter],
                                                   keys);
    state->elements[state->iter]->num_values = state->current_cert->num_values;
    state->elements[state->iter]->flags |= SSS_EL_FLAG_BIN_DATA;
    state->num_keys += valid_keys;

    if (state->current_cert == state->user_cert) {
        state->current_cert = state->user_cert_override;
    } else if (state->current_cert == state->user_cert_override) {
        state->current_cert = NULL;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected certificate pointer.\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    if (state->current_cert == NULL) {
        /* done */
        ret = EOK;
        goto done;
    }

    subreq = cert_to_ssh_key_send(state, state->ev, NULL,
                                  state->p11_child_timeout,
                                  state->ssh_ctx->ca_db,
                                  state->ssh_ctx->sss_certmap_ctx,
                                  state->current_cert->num_values,
                                  state->current_cert->values,
                                  state->cert_verification_opts);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "cert_to_ssh_key_send failed.\n");
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ssh_get_output_keys_done, req);
    return;
done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    return;
}

errno_t ssh_get_output_keys_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                                 struct sized_string *name,
                                 struct ldb_message_element ***elements,
                                 uint32_t *num_keys)
{
    struct ssh_get_output_keys_state *state = tevent_req_data(req,
                                              struct ssh_get_output_keys_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (name != NULL) {
        name->str = talloc_strdup(mem_ctx, state->name);
        name->len = strlen(name->str) + 1;
    }

    if (elements != NULL) {
        *elements = talloc_steal(mem_ctx, state->elements);
    }

    if (num_keys != NULL) {
        *num_keys = state->num_keys;
    }

    return EOK;
}

errno_t
ssh_protocol_build_reply(struct sss_packet *packet,
                         struct sized_string name,
                         struct ldb_message_element **elements,
                         uint32_t num_keys)
{
    size_t body_len;
    uint8_t *body;
    size_t c = 0;
    errno_t ret;
    int i;

    ret = sss_packet_grow(packet, 2 * sizeof(uint32_t));
    if (ret != EOK) {
        goto done;
    }

    sss_packet_get_body(packet, &body, &body_len);

    SAFEALIGN_SET_UINT32(&body[c], num_keys, &c);
    SAFEALIGN_SET_UINT32(&body[c], 0, &c);

    if (num_keys == 0) {
        ret = EOK;
        goto done;
    }

    for (i = 0; elements[i] != NULL; i++) {
        ret = decode_and_add_base64_data(packet, elements[i], false,
                                         name.len, name.str, &c);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "decode_and_add_base64_data failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:

    return ret;
}
