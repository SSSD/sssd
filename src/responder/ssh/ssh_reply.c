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

static errno_t get_valid_certs_keys(TALLOC_CTX *mem_ctx,
                                    struct ssh_ctx *ssh_ctx,
                                    struct ldb_message_element *el_cert,
                                    struct ldb_message_element **_el_res)
{
    TALLOC_CTX *tmp_ctx;
    uint8_t *key;
    size_t key_len;
    char *cert_verification_opts;
    struct cert_verify_opts *cert_verify_opts;
    int ret;
    struct ldb_message_element *el_res;
    size_t d;

    if (el_cert == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Mssing element, nothing to do.\n");
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = confdb_get_string(ssh_ctx->rctx->cdb, tmp_ctx,
                            CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_CERT_VERIFICATION, NULL,
                            &cert_verification_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read p11_child_timeout from confdb: [%d] %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = parse_cert_verify_opts(tmp_ctx, cert_verification_opts,
                                 &cert_verify_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to parse verifiy option.\n");
        goto done;
    }

    el_res = talloc_zero(tmp_ctx, struct ldb_message_element);
    if (el_res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    el_res->values = talloc_array(el_res, struct ldb_val, el_cert->num_values);
    if (el_res->values == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (d = 0; d < el_cert->num_values; d++) {
            ret = cert_to_ssh_key(tmp_ctx, ssh_ctx->ca_db,
                                  el_cert->values[d].data,
                                  el_cert->values[d].length,
                                  cert_verify_opts, &key, &key_len);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "cert_to_ssh_key failed, ignoring.\n");
                continue;
            }

            el_res->values[el_res->num_values].data =
                                              talloc_steal(el_res->values, key);
            el_res->values[el_res->num_values].length = key_len;
            el_res->num_values++;
    }

    if (el_res->num_values == 0) {
        *_el_res = NULL;
    } else {
        *_el_res = talloc_steal(mem_ctx, el_res);
    }

    ret = EOK;

done:

    talloc_free(tmp_ctx);

    return ret;
}

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

static errno_t
ssh_get_output_keys(TALLOC_CTX *mem_ctx,
                    struct ssh_ctx *ssh_ctx,
                    struct sss_domain_info *domain,
                    struct ldb_message *msg,
                    struct ldb_message_element ***_elements,
                    uint32_t *_num_keys)
{
    struct ldb_message_element **elements;
    struct ldb_message_element *user_cert;
    uint32_t num_keys = 0;
    uint32_t i = 0;
    errno_t ret;

    elements = talloc_zero_array(mem_ctx, struct ldb_message_element *, 6);
    if (elements == NULL) {
        return ENOMEM;
    }

    elements[i] = ldb_msg_find_element(msg, SYSDB_SSH_PUBKEY);
    if (elements[i] != NULL) {
        num_keys += elements[i]->num_values;
        i++;
    }

    elements[i] = ldb_msg_find_element(msg, ORIGINALAD_PREFIX SYSDB_SSH_PUBKEY);
    if (elements[i] != NULL) {
        num_keys += elements[i]->num_values;
        i++;
    }

    if (DOM_HAS_VIEWS(domain)) {
        elements[i] = ldb_msg_find_element(msg, OVERRIDE_PREFIX SYSDB_SSH_PUBKEY);
        if (elements[i] != NULL) {
            num_keys += elements[i]->num_values;
            i++;
        }
    }

    user_cert = ldb_msg_find_element(msg, SYSDB_USER_CERT);
    if (user_cert != NULL) {
        ret = get_valid_certs_keys(elements, ssh_ctx, user_cert, &elements[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_valid_certs_keys failed.\n");
            goto done;
        }

        if (elements[i] != NULL) {
            elements[i]->flags |= SSS_EL_FLAG_BIN_DATA;
            num_keys += elements[i]->num_values;
            i++;
        }
    }

    if (DOM_HAS_VIEWS(domain)) {
        user_cert = ldb_msg_find_element(msg, OVERRIDE_PREFIX SYSDB_USER_CERT);
        if (user_cert != NULL) {
            ret = get_valid_certs_keys(elements, ssh_ctx, user_cert,
                                       &elements[i]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_valid_certs_keys failed.\n");
                goto done;
            }

            if (elements[i] != NULL) {
                elements[i]->flags |= SSS_EL_FLAG_BIN_DATA;
                num_keys += elements[i]->num_values;
                i++;
            }
        }
    }

    *_elements = elements;
    *_num_keys = num_keys;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(elements);
    }

    return ret;
}

static errno_t
ssh_get_name(struct ldb_message *msg,
             struct sized_string *sz_name)
{
    const char *name;

    name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    if (name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Got unnamed result!\n");
        return ENOENT;
    }

    to_sized_string(sz_name, name);

    return EOK;
}

errno_t
ssh_protocol_build_reply(struct sss_packet *packet,
                         struct ssh_ctx *ssh_ctx,
                         struct cache_req_result *result)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element **elements;
    struct sized_string name;
    uint32_t num_keys;
    size_t body_len;
    uint8_t *body;
    size_t c = 0;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = ssh_get_output_keys(tmp_ctx, ssh_ctx, result->domain,
                              result->msgs[0], &elements, &num_keys);
    if (ret != EOK) {
        goto done;
    }

    ret = ssh_get_name(result->msgs[0], &name);
    if (ret != EOK) {
        goto done;
    }

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
    talloc_free(tmp_ctx);

    return ret;
}
