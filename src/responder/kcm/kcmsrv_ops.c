/*
   SSSD

   KCM Server - the KCM server operations

   Copyright (C) Red Hat, 2016

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

#include <krb5/krb5.h>
#include <dhash.h>

#include "util/sss_iobuf.h"
#include "util/sss_krb5.h"
#include "util/sss_ptr_hash.h"
#include "util/util_creds.h"
#include "responder/kcm/kcmsrv_pvt.h"
#include "responder/kcm/kcmsrv_ops.h"
#include "responder/kcm/kcmsrv_ccache.h"

struct kcm_op_ctx {
    struct kcm_resp_ctx *kcm_data;
    struct kcm_conn_data *conn_data;
    struct cli_creds *client;

    struct sss_iobuf *input;
    struct sss_iobuf *reply;
};

/* Each operation follows the same pattern and is implemented using
 * functions with this prototype. The operation receives an op_ctx
 * that serves as a state of the operation and can be used to keep
 * track of any temporary data. The operation writes its output data
 * into the op_ctx reply IO buffer and returns the op_ret status code
 * separately.
 *
 * The operation always returns EOK unless an internal error occurs,
 * the result of the operation is stored in the op_ret variable
 */
typedef struct tevent_req*
(*kcm_srv_send_method)(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct kcm_op_ctx *op_ctx);
typedef errno_t
(*kcm_srv_recv_method)(struct tevent_req *req,
                       uint32_t *_op_ret);

struct kcm_op {
    const char *name;
    kcm_srv_send_method fn_send;
    kcm_srv_recv_method fn_recv;
};

struct kcm_cmd_state {
    struct kcm_op *op;
    struct tevent_context *ev;

    struct kcm_ops_queue_entry *queue_entry;
    struct kcm_op_ctx *op_ctx;
    struct sss_iobuf *reply;

    uint32_t op_ret;
};

static void kcm_cmd_queue_done(struct tevent_req *subreq);
static void kcm_cmd_done(struct tevent_req *subreq);

struct tevent_req *kcm_cmd_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct kcm_ops_queue_ctx *qctx,
                                struct kcm_resp_ctx *kcm_data,
                                struct kcm_conn_data *conn_data,
                                struct cli_creds *client,
                                struct kcm_data *input,
                                struct kcm_op *op)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_cmd_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_cmd_state);
    if (req == NULL) {
        return NULL;
    }
    state->op = op;
    state->ev = ev;

    if (op == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "KCM operation %s\n", op->name);
    DEBUG(SSSDBG_TRACE_LIBS, "%zu bytes on KCM input\n", input->length);

    state->reply = sss_iobuf_init_empty(state,
                                        KCM_PACKET_INITIAL_SIZE,
                                        KCM_PACKET_MAX_SIZE);
    if (state->reply == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    if (op->fn_send == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "KCM op %s has no handler\n", kcm_opt_name(op));
        ret = ERR_KCM_OP_NOT_IMPLEMENTED;
        goto immediate;
    }

    /* Allocating op_ctx on the heap makes it possible for operations to use
     * op_ctx as their temporary context and avoid tmp_ctx altogether
     */
    state->op_ctx = talloc_zero(state, struct kcm_op_ctx);
    if (state->op_ctx == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    state->op_ctx->kcm_data = kcm_data;
    state->op_ctx->conn_data = conn_data;
    state->op_ctx->client = client;

    state->op_ctx->input = sss_iobuf_init_readonly(state->op_ctx,
                                                   input->data,
                                                   input->length);
    if (state->op_ctx->input == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    /*
     * The internal operation returns the opcode and the buffer separately.
     * The KCM server reply to the client also always contains zero if the
     * operation ran to completion, both are uint32_t.
     * FIXME:
     * Alternatively, we could extend iobuf API so that we can just pass
     * the reply's buffer+sizeof(2*uint32_t) and avoid the useless allocations
     */
    state->op_ctx->reply = sss_iobuf_init_empty(
                                        state,
                                        KCM_PACKET_INITIAL_SIZE,
                                        KCM_PACKET_MAX_SIZE - 2*sizeof(uint32_t));
    if (state->op_ctx->reply == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = kcm_op_queue_send(state, ev, qctx, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_cmd_queue_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_cmd_queue_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct kcm_cmd_state *state = tevent_req_data(req, struct kcm_cmd_state);
    errno_t ret;

    /* When this request finishes, it frees the queue_entry which unblocks
     * other requests by the same UID
     */
    ret = kcm_op_queue_recv(subreq, state, &state->queue_entry);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot acquire queue slot\n");
        tevent_req_error(req, ret);
        return;
    }

    subreq = state->op->fn_send(state, state->ev, state->op_ctx);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_cmd_done, req);
}

static void kcm_cmd_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct kcm_cmd_state *state = tevent_req_data(req, struct kcm_cmd_state);
    errno_t ret;
    krb5_error_code kerr;

    ret = state->op->fn_recv(subreq, &state->op_ret);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "op receive function failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "KCM operation %s returned [%d]: %s\n",
          kcm_opt_name(state->op), state->op_ret, sss_strerror(state->op_ret));

    kerr = sss2krb5_error(state->op_ret);

    /* The first four bytes of the reply is the operation status code */
    ret = sss_iobuf_write_uint32(state->reply, htobe32(kerr));
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = sss_iobuf_write_len(state->reply,
                              sss_iobuf_get_data(state->op_ctx->reply),
                              sss_iobuf_get_len(state->op_ctx->reply));
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_cmd_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     struct sss_iobuf **_reply)
{
    struct kcm_cmd_state *state = NULL;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    state = tevent_req_data(req, struct kcm_cmd_state);

    *_reply = talloc_steal(mem_ctx, state->reply);
    return EOK;
}

/* ======= KCM operations ======= */

/* Operations that don't return any extra information except for the op_ret
 * can use this macro in the _recv function to avoid code duplication
 */
#define KCM_OP_RET_FROM_TYPE(req, state_type, _op_ret_out) do {    \
    state_type *state = NULL;                                    \
    state = tevent_req_data(req, state_type);                    \
    TEVENT_REQ_RETURN_ON_ERROR(req);                             \
    *_op_ret_out = state->op_ret;                                \
    return EOK;                                                  \
} while(0);

struct kcm_op_common_state {
    uint32_t op_ret;
    struct kcm_op_ctx *op_ctx;
    struct tevent_context *ev;
};

static errno_t kcm_op_common_recv(struct tevent_req *req,
                                  uint32_t *_op_ret)
{
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_op_ret = state->op_ret;
    return EOK;
}

/* () -> (name) */
static void kcm_op_gen_new_done(struct tevent_req *subreq);

static struct tevent_req *kcm_op_gen_new_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_common_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;

    subreq = kcm_ccdb_nextid_send(state, ev,
                                  op_ctx->kcm_data->db,
                                  op_ctx->client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_gen_new_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_gen_new_done(struct tevent_req *subreq)
{
    errno_t ret;
    char *newid;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);

    ret = kcm_ccdb_nextid_recv(subreq, state, &newid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot generate a new ID [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Generated a new ID %s\n", newid);

    ret = sss_iobuf_write_stringz(state->op_ctx->reply, newid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot write generated ID %d: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

/* (princ) -> () */
struct kcm_op_initialize_state {
    uint32_t op_ret;
    struct kcm_op_ctx *op_ctx;
    struct tevent_context *ev;

    struct kcm_ccache *new_cc;
    const char *name;
    krb5_principal princ;
};

static void kcm_op_initialize_got_byname(struct tevent_req *subreq);
static void kcm_op_initialize_cc_create_done(struct tevent_req *subreq);
static void kcm_op_initialize_cc_delete_done(struct tevent_req *subreq);
static void kcm_op_initialize_fill_princ_step(struct tevent_req *req);
static void kcm_op_initialize_fill_princ_done(struct tevent_req *subreq);
static void kcm_op_initialize_create_step(struct tevent_req *req);
static void kcm_op_initialize_got_default(struct tevent_req *subreq);
static void kcm_op_initialize_set_default_done(struct tevent_req *subreq);

static struct tevent_req *kcm_op_initialize_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_initialize_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_initialize_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;
    state->ev = ev;

    ret = sss_iobuf_read_stringz(op_ctx->input, &state->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot read input name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Initializing ccache %s\n", state->name);

    ret = kcm_check_name(state->name, op_ctx->client);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Name %s is malformed [%d]: %s\n",
              state->name, ret, sss_strerror(ret));
        goto immediate;
    }

    ret = sss_krb5_unmarshal_princ(op_ctx, op_ctx->input, &state->princ);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot unmarshal principal [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    subreq = kcm_ccdb_getbyname_send(state, ev,
                                     op_ctx->kcm_data->db,
                                     op_ctx->client,
                                     state->name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_initialize_got_byname, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_initialize_got_byname(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_initialize_state *state = tevent_req_data(req,
                                            struct kcm_op_initialize_state);
    bool ok;
    uuid_t uuid;

    ret = kcm_ccdb_getbyname_recv(subreq, state, &state->new_cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get ccache by name [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->new_cc != NULL) {
        if (kcm_cc_get_client_principal(state->new_cc) == NULL) {
            /* This is a cache that was pre-created w/o a principal (sshd does this),
             * let's fill in the principal and set the cache as default if not
             * already
             */
            kcm_op_initialize_fill_princ_step(req);
            return;
        }

        ok = kcm_cc_access(state->new_cc, state->op_ctx->client);
        if (!ok) {
            state->op_ret = EACCES;
            tevent_req_done(req);
            return;
        }

        /* `uuid` is output arg and isn't read in kcm_cc_get_uuid() but
         * since libuuid is opaque for cppcheck it generates false positive here
         */
        /* cppcheck-suppress uninitvar */
        ret = kcm_cc_get_uuid(state->new_cc, uuid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get new ccache UUID [%d]: %s\n",
              ret, sss_strerror(ret));
            return;
        }

        /* Nuke any previous cache and its contents during initialization */
        subreq = kcm_ccdb_delete_cc_send(state,
                                         state->ev,
                                         state->op_ctx->kcm_data->db,
                                         state->op_ctx->client,
                                         uuid);
        if (subreq == NULL) {
            tevent_req_error(req, ret);
            return;
        }
        tevent_req_set_callback(subreq, kcm_op_initialize_cc_delete_done, req);
        return;
    }

    kcm_op_initialize_create_step(req);
}

static void kcm_op_initialize_cc_delete_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    errno_t ret;

    ret = kcm_ccdb_delete_cc_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot delete ccache from the db %d: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    kcm_op_initialize_create_step(req);
}

static void kcm_op_initialize_fill_princ_step(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct kcm_op_initialize_state *state = tevent_req_data(req,
                                            struct kcm_op_initialize_state);
    errno_t ret;
    struct kcm_mod_ctx *mod_ctx;
    uuid_t uuid;

    mod_ctx = kcm_mod_ctx_new(state);
    if (mod_ctx == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    mod_ctx->client = state->princ;

    /* `uuid` is output arg and isn't read in kcm_cc_get_uuid() but
     * since libuuid is opaque for cppcheck it generates false positive here
     */
    /* cppcheck-suppress uninitvar */
    ret = kcm_cc_get_uuid(state->new_cc, uuid);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = kcm_ccdb_mod_cc_send(state,
                                  state->ev,
                                  state->op_ctx->kcm_data->db,
                                  state->op_ctx->client,
                                  uuid,
                                  mod_ctx);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_initialize_fill_princ_done, req);
}

static void kcm_op_initialize_fill_princ_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_initialize_state *state = tevent_req_data(req,
                                            struct kcm_op_initialize_state);
    errno_t ret;

    ret = kcm_ccdb_mod_cc_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot modify ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* Make sure the cache we just initialized is the default one */
    subreq = kcm_ccdb_get_default_send(state, state->ev,
                                       state->op_ctx->kcm_data->db,
                                       state->op_ctx->client);
    if (subreq == NULL) {
        tevent_req_error(req, ret);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_initialize_got_default, req);
}

static void kcm_op_initialize_create_step(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct kcm_op_initialize_state *state = tevent_req_data(req,
                                            struct kcm_op_initialize_state);
    errno_t ret;

    ret = kcm_cc_new(state->op_ctx,
                     state->op_ctx->kcm_data->k5c,
                     state->op_ctx->client,
                     state->name,
                     state->princ,
                     &state->new_cc);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot create new ccache %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = kcm_ccdb_create_cc_send(state,
                                     state->ev,
                                     state->op_ctx->kcm_data->db,
                                     state->op_ctx->client,
                                     state->new_cc);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_initialize_cc_create_done, req);
}

static void kcm_op_initialize_cc_create_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_initialize_state *state = tevent_req_data(req,
                                            struct kcm_op_initialize_state);
    errno_t ret;

    ret = kcm_ccdb_create_cc_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot add ccache to db %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* If there was no previous default ccache, set this one as default */
    subreq = kcm_ccdb_get_default_send(state, state->ev,
                                       state->op_ctx->kcm_data->db,
                                       state->op_ctx->client);
    if (subreq == NULL) {
        tevent_req_error(req, ret);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_initialize_got_default, req);
}

static void kcm_op_initialize_got_default(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_initialize_state *state = tevent_req_data(req,
                                            struct kcm_op_initialize_state);
    errno_t ret;
    uuid_t dfl_uuid;
    uuid_t old_dfl_uuid;

    ret = kcm_ccdb_get_default_recv(subreq, &old_dfl_uuid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get default ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (uuid_is_null(old_dfl_uuid)) {
        /* If there was no previous default ccache, switch to the initialized
         * one by default
         */
        /* `dfl_uuid` is output arg and isn't read in kcm_cc_get_uuid() but
         * since libuuid is opaque for cppcheck it generates false positive here
         */
        /* cppcheck-suppress uninitvar */
        ret = kcm_cc_get_uuid(state->new_cc, dfl_uuid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot get new ccache UUID [%d]: %s\n",
                  ret, sss_strerror(ret));
            return;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "The default ccached was not set, switching to the "
              "initialized\n");
        subreq = kcm_ccdb_set_default_send(state,
                                           state->ev,
                                           state->op_ctx->kcm_data->db,
                                           state->op_ctx->client,
                                           dfl_uuid);
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, kcm_op_initialize_set_default_done, req);
        return;
    }

    /* ENOENT, done */
    state->op_ret = EOK;
    tevent_req_done(req);
}

static void kcm_op_initialize_set_default_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_initialize_state *state = tevent_req_data(req,
                                            struct kcm_op_initialize_state);
    errno_t ret;

    ret = kcm_ccdb_set_default_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot set default ccache %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

static errno_t kcm_op_initialize_recv(struct tevent_req *req,
                                      uint32_t *_op_ret)
{
    KCM_OP_RET_FROM_TYPE(req, struct kcm_op_initialize_state, _op_ret);
}

/* (name) -> () */
static void kcm_op_destroy_getbyname_done(struct tevent_req *subreq);
static void kcm_op_destroy_delete_done(struct tevent_req *subreq);

static struct tevent_req *kcm_op_destroy_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_common_state *state = NULL;
    errno_t ret;
    const char *name;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;
    state->ev = ev;

    ret = sss_iobuf_read_stringz(op_ctx->input, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot unmarshall input name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Destroying credentials of %s\n", name);

    subreq = kcm_ccdb_uuid_by_name_send(state, ev,
                                        op_ctx->kcm_data->db,
                                        op_ctx->client,
                                        name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_destroy_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_destroy_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);
    uuid_t uuid;

    /* `uuid` is output arg and isn't read in kcm_ccdb_uuid_by_name_recv() but
     * since libuuid is opaque for cppcheck it generates false positive here
     */
    /* cppcheck-suppress uninitvar */
    ret = kcm_ccdb_uuid_by_name_recv(subreq, state, uuid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot get matching ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        ret = ERR_NO_MATCHING_CREDS;
        tevent_req_error(req, ret);
        return;
    }

    subreq = kcm_ccdb_delete_cc_send(state,
                                     state->ev,
                                     state->op_ctx->kcm_data->db,
                                     state->op_ctx->client,
                                     uuid);
    if (subreq == NULL) {
        tevent_req_error(req, ret);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_destroy_delete_done, req);
}

static void kcm_op_destroy_delete_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);

    ret = kcm_ccdb_delete_cc_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot delete ccache from the db [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

/* (name, cred) -> () */
struct kcm_op_store_state {
    uint32_t op_ret;
    struct kcm_op_ctx *op_ctx;
    struct tevent_context *ev;

    struct sss_iobuf *cred_blob;
};

static void kcm_op_store_getbyname_done(struct tevent_req *subreq);
static void kcm_op_store_done(struct tevent_req *subreq);

static struct tevent_req *kcm_op_store_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_store_state *state = NULL;
    errno_t ret;
    const char *name;
    size_t creds_len;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_store_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;
    state->ev = ev;

    ret = sss_iobuf_read_stringz(op_ctx->input, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot unmarshall input name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Storing credentials for %s\n", name);

    creds_len = sss_iobuf_get_size(op_ctx->input) - strlen(name) -1;
    if (creds_len > KCM_PACKET_MAX_SIZE) {
        /* Protects against underflows and in general adds sanity */
        ret = E2BIG;
        goto immediate;
    }

    state->cred_blob = sss_iobuf_init_empty(state,
                                            creds_len,
                                            creds_len);
    if (state->cred_blob == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    ret = sss_iobuf_read(op_ctx->input,
                         creds_len,
                         sss_iobuf_get_data(state->cred_blob),
                         NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot unmarshall input cred blob [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    subreq = kcm_ccdb_uuid_by_name_send(state, ev,
                                        op_ctx->kcm_data->db,
                                        op_ctx->client,
                                        name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_store_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_store_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_store_state *state = tevent_req_data(req,
                                                struct kcm_op_store_state);
    uuid_t uuid;

    /* `uuid` is output arg and isn't read in kcm_ccdb_uuid_by_name_recv() but
     * since libuuid is opaque for cppcheck it generates false positive here
     */
    /* cppcheck-suppress uninitvar */
    ret = kcm_ccdb_uuid_by_name_recv(subreq, state, uuid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get ccache by name [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = kcm_ccdb_store_cred_blob_send(state, state->ev,
                                           state->op_ctx->kcm_data->db,
                                           state->op_ctx->client,
                                           uuid,
                                           state->cred_blob);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_store_done, req);
}

static void kcm_op_store_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_store_state *state = tevent_req_data(req,
                                                struct kcm_op_store_state);

    ret = kcm_ccdb_store_cred_blob_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store credentials [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

static errno_t kcm_op_store_recv(struct tevent_req *req,
                                 uint32_t *_op_ret)
{
    KCM_OP_RET_FROM_TYPE(req, struct kcm_op_store_state, _op_ret);
}

/* (name) -> (princ) */
static void kcm_op_get_principal_getbyname_done(struct tevent_req *subreq);

static struct tevent_req *kcm_op_get_principal_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_common_state *state = NULL;
    errno_t ret;
    const char *name;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;

    ret = sss_iobuf_read_stringz(op_ctx->input, &name);
    if (ret != EOK) {
        goto immediate;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Requested principal %s\n", name);

    subreq = kcm_ccdb_getbyname_send(state, ev,
                                     op_ctx->kcm_data->db,
                                     op_ctx->client,
                                     name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_get_principal_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_get_principal_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct kcm_ccache *cc;
    krb5_principal princ;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);

    ret = kcm_ccdb_getbyname_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get ccache by name [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (cc == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No credentials by that name\n");
        state->op_ret = ERR_NO_MATCHING_CREDS;
        tevent_req_done(req);
        return;
    }

    /* Marshall the principal to the reply */
    princ = kcm_cc_get_client_principal(cc);
    if (princ == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Credentials with no principal?\n");
        tevent_req_error(req, EIO);
        return;
    }

    ret = sss_krb5_marshal_princ(princ, state->op_ctx->reply);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot marshall principal [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

static void
kcm_creds_table_delete_cb(hash_entry_t *item,
                          hash_destroy_enum deltype,
                          void *pvt)
{
    /* Delete the old credential if it is being overwritten. */
    talloc_free(item->value.ptr);
}

/* Store credentials in a hash table.
 *
 * If the table already exist we add the new credentials to the table and
 * overwrite the ones that already exist. This allows us to correctly serve
 * also parallel GET_CRED_UUID_LIST requests from the same connection since
 * it will have its own uuid list and cursor on the client side and we make
 * all uuid (old, updated and newly added) available.
 */
static errno_t
kcm_creds_to_table(TALLOC_CTX *mem_ctx,
                   struct kcm_cred *creds,
                   hash_table_t **_table)
{
    char str[UUID_STR_SIZE];
    uuid_t uuid;
    errno_t ret;

    if (*_table == NULL) {
        *_table = sss_ptr_hash_create(mem_ctx, kcm_creds_table_delete_cb, NULL);
        if (*_table == NULL) {
            return ENOMEM;
        }
    }

    for (struct kcm_cred *crd = creds;
         crd != NULL;
         crd = kcm_cc_next_cred(crd)) {
        ret = kcm_cred_get_uuid(crd, uuid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Credential has no UUID, skipping\n");
            continue;
        }
        uuid_unparse(uuid, str);

        ret = sss_ptr_hash_add_or_override(*_table, str, crd, struct kcm_cred);
        if (ret != EOK) {
            return ret;
        }

        talloc_steal(*_table, crd);
    }

    return EOK;
}

static struct kcm_cred *
kcm_creds_lookup(hash_table_t *table, uuid_t uuid)
{
    char str[UUID_STR_SIZE];

    if (uuid == NULL) {
        return NULL;
    }

    uuid_unparse(uuid, str);
    return sss_ptr_hash_lookup(table, str, struct kcm_cred);
}

/* (name) -> (uuid, ...) */
static void kcm_op_get_cred_uuid_list_getbyname_done(struct tevent_req *subreq);

static struct tevent_req *
kcm_op_get_cred_uuid_list_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_common_state *state = NULL;
    errno_t ret;
    const char *name;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;

    ret = sss_iobuf_read_stringz(op_ctx->input, &name);
    if (ret != EOK) {
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Returning UUID list for %s\n", name);

    subreq = kcm_ccdb_getbyname_send(state, ev,
                                     op_ctx->kcm_data->db,
                                     op_ctx->client,
                                     name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_get_cred_uuid_list_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_get_cred_uuid_list_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct kcm_ccache *cc;
    struct kcm_cred *crd;
    struct kcm_conn_data *conn_data;
    uuid_t uuid;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);

    conn_data = state->op_ctx->conn_data;

    ret = kcm_ccdb_getbyname_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get ccache by name [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (cc == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No ccache by that name\n");
        state->op_ret = ERR_NO_CREDS;
        tevent_req_done(req);
        return;
    }

    ret = kcm_creds_to_table(conn_data, kcm_cc_get_cred(cc), &conn_data->creds);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to build credentials hash table "
              "[%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    for (crd = kcm_cc_get_cred(cc);
         crd != NULL;
         crd = kcm_cc_next_cred(crd)) {
        ret = kcm_cred_get_uuid(crd, uuid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Credential has no UUID, skipping\n");
            continue;
        }

        kcm_debug_uuid(uuid);

        ret = sss_iobuf_write_len(state->op_ctx->reply,
                                  uuid, UUID_BYTES);
        if (ret != EOK) {
            char uuid_errbuf[UUID_STR_SIZE];
            uuid_parse(uuid_errbuf, uuid);
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot marshall UUID %s [%d]: %s\n",
                  uuid_errbuf, ret, sss_strerror(ret));
            continue;
        }
    }
    state->op_ret = EOK;
    tevent_req_done(req);
}

static errno_t
kcm_op_get_cred_by_uuid_reply(struct kcm_cred *crd,
                              struct sss_iobuf *reply)
{
    struct sss_iobuf *cred_blob;
    errno_t ret;

    cred_blob = kcm_cred_get_creds(crd);
    if (cred_blob == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Credentials lack the creds blob\n");
        return ERR_NO_CREDS;
    }

    ret = sss_iobuf_write_len(reply, sss_iobuf_get_data(cred_blob),
                              sss_iobuf_get_size(cred_blob));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot write ccache blob [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

struct kcm_op_get_cred_by_uuid_state {
    struct kcm_op_common_state common;
    uuid_t uuid;
};

/* (name, uuid) -> (cred) */
static void kcm_op_get_cred_by_uuid_getbyname_done(struct tevent_req *subreq);

static struct tevent_req *
kcm_op_get_cred_by_uuid_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_get_cred_by_uuid_state *state;
    struct kcm_cred *crd;
    errno_t ret;
    const char *name;

    req = tevent_req_create(mem_ctx, &state,
                            struct kcm_op_get_cred_by_uuid_state);
    if (req == NULL) {
        return NULL;
    }
    state->common.op_ctx = op_ctx;

    ret = sss_iobuf_read_stringz(op_ctx->input, &name);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sss_iobuf_read_len(state->common.op_ctx->input, UUID_BYTES,
                             state->uuid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read input UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    if (op_ctx->conn_data->creds != NULL) {
        crd = kcm_creds_lookup(op_ctx->conn_data->creds, state->uuid);
        if (crd == NULL) {
            /* This should not happen, it can only happen if wrong UUID was
             * requested which suggests bug in the caller application. */
            DEBUG(SSSDBG_MINOR_FAILURE, "No credentials by that UUID\n");
            kcm_debug_uuid(state->uuid);
            state->common.op_ret = ERR_KCM_CC_END;
            ret = EOK;
            goto immediate;
        } else {
            ret = kcm_op_get_cred_by_uuid_reply(crd, op_ctx->reply);
            if (ret == ERR_NO_CREDS) {
                state->common.op_ret = ret;
                ret = EOK;
            }
            goto immediate;
        }
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Returning creds by UUID for %s\n", name);

    subreq = kcm_ccdb_getbyname_send(state, ev,
                                     op_ctx->kcm_data->db,
                                     op_ctx->client,
                                     name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_get_cred_by_uuid_getbyname_done, req);
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_get_cred_by_uuid_getbyname_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_get_cred_by_uuid_state *state = tevent_req_data(req,
                                        struct kcm_op_get_cred_by_uuid_state);
    errno_t ret;
    struct kcm_ccache *cc;
    struct kcm_cred *crd;
    struct kcm_conn_data *conn_data;

    conn_data = state->common.op_ctx->conn_data;

    ret = kcm_ccdb_getbyname_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get ccache by name [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = kcm_creds_to_table(conn_data, kcm_cc_get_cred(cc), &conn_data->creds);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to build credentials hash table "
              "[%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (conn_data->creds != NULL) {
        crd = kcm_creds_lookup(conn_data->creds, state->uuid);
        if (crd == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "No credentials by that UUID\n");
            kcm_debug_uuid(state->uuid);
            state->common.op_ret = ERR_KCM_CC_END;
        } else {
            ret = kcm_op_get_cred_by_uuid_reply(crd, state->common.op_ctx->reply);
            if (ret != EOK && ret != ERR_NO_CREDS) {
                tevent_req_error(req, ret);
                return;
            }
            state->common.op_ret = ret;
        }
    }

    tevent_req_done(req);
}

static errno_t kcm_op_get_cred_by_uuid_recv(struct tevent_req *req,
                                            uint32_t *_op_ret)
{
    struct kcm_op_get_cred_by_uuid_state *state;

    state = tevent_req_data(req, struct kcm_op_get_cred_by_uuid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_op_ret = state->common.op_ret;
    return EOK;
}

/* (name, flags, credtag) -> () */
/* FIXME */
static struct tevent_req *
kcm_op_remove_cred_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct kcm_op_common_state *state = NULL;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;

    state->op_ret = ERR_KCM_OP_NOT_IMPLEMENTED;
    tevent_req_post(req, ev);
    tevent_req_done(req);
    return req;
}

/* () -> (uuid, ...) */
static void kcm_op_get_cache_uuid_list_done(struct tevent_req *subreq);

static struct tevent_req *
kcm_op_get_cache_uuid_list_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_common_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;

    DEBUG(SSSDBG_TRACE_LIBS, "Returning full UUID list\n");

    subreq = kcm_ccdb_list_send(state, ev,
                                op_ctx->kcm_data->db,
                                op_ctx->client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_get_cache_uuid_list_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_get_cache_uuid_list_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);
    errno_t ret;
    uuid_t *uuid_list;

    ret = kcm_ccdb_list_recv(subreq, state, &uuid_list);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot list the ccache DB [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (uuid_list == NULL || uuid_is_null(uuid_list[0])) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Nothing to list\n");
        state->op_ret = ERR_NO_MATCHING_CREDS;
        tevent_req_done(req);
        return;
    }

    for (int i = 0;
         uuid_is_null(uuid_list[i]) == false;
         i++) {
        kcm_debug_uuid(uuid_list[i]);

        ret = sss_iobuf_write_len(state->op_ctx->reply,
                                  uuid_list[i],
                                  UUID_BYTES);
        if (ret != EOK) {
            char uuid_errbuf[UUID_STR_SIZE];
            uuid_parse(uuid_errbuf, uuid_list[i]);
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot marshall UUID %s [%d]: %s\n",
                  uuid_errbuf, ret, sss_strerror(ret));
            tevent_req_done(req);
            return;
        }
    }

    tevent_req_done(req);
}

/* (uuid) -> (name) */
static void kcm_op_get_cache_by_uuid_done(struct tevent_req *subreq);

static struct tevent_req *
kcm_op_get_cache_by_uuid_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_common_state *state = NULL;
    errno_t ret;
    uuid_t uuid_in;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;

    DEBUG(SSSDBG_TRACE_LIBS, "Retrieving cache by UUID\n");

    ret = sss_iobuf_read_len(op_ctx->input,
                             UUID_BYTES, uuid_in);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot read input UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }
    kcm_debug_uuid(uuid_in);

    subreq = kcm_ccdb_getbyuuid_send(state, ev,
                                     op_ctx->kcm_data->db,
                                     op_ctx->client,
                                     uuid_in);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_get_cache_by_uuid_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_get_cache_by_uuid_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct kcm_ccache *cc;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);
    const char *name;

    ret = kcm_ccdb_getbyuuid_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get ccache by UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (cc == NULL) {
        state->op_ret = ERR_KCM_CC_END;
        tevent_req_done(req);
        return;
    }

    name = kcm_cc_get_name(cc);
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found %s by UUID\n", name);

    ret = sss_iobuf_write_stringz(state->op_ctx->reply,
                                  name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot write output name [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

/* () -> (name) */
struct kcm_op_get_default_ccache_state {
    uint32_t op_ret;
    struct kcm_op_ctx *op_ctx;
    struct tevent_context *ev;

    const char *name;
};

static void kcm_op_get_get_default_done(struct tevent_req *subreq);
static void kcm_op_get_default_ccache_byuuid_done(struct tevent_req *subreq);
static void kcm_op_get_default_ccache_list_done(struct tevent_req *subreq);
static errno_t
kcm_op_get_default_ccache_reply_step(struct kcm_op_get_default_ccache_state *state);

static struct tevent_req *
kcm_op_get_default_ccache_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_get_default_ccache_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct kcm_op_get_default_ccache_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;
    state->ev = ev;

    DEBUG(SSSDBG_TRACE_LIBS, "Getting client's default ccache\n");

    subreq = kcm_ccdb_get_default_send(state, ev,
                                       state->op_ctx->kcm_data->db,
                                       state->op_ctx->client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_get_get_default_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_get_get_default_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct kcm_op_get_default_ccache_state *state = tevent_req_data(req,
                                    struct kcm_op_get_default_ccache_state);
    errno_t ret;
    uuid_t dfl_uuid;

    ret = kcm_ccdb_get_default_recv(subreq, &dfl_uuid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get default ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (uuid_is_null(dfl_uuid) == true) {
        /* No cache marked as default -- get an existing ccache for ID
         * and treat the default as simply the first one
         */
        subreq = kcm_ccdb_list_send(state, state->ev,
                                    state->op_ctx->kcm_data->db,
                                    state->op_ctx->client);
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, kcm_op_get_default_ccache_list_done, req);
        return;
    }

    /* Existing default */
    subreq = kcm_ccdb_name_by_uuid_send(state,
                                        state->ev,
                                        state->op_ctx->kcm_data->db,
                                        state->op_ctx->client,
                                        dfl_uuid);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_get_default_ccache_byuuid_done, req);
    return;
}

static void kcm_op_get_default_ccache_byuuid_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct kcm_op_get_default_ccache_state *state = tevent_req_data(req,
                                    struct kcm_op_get_default_ccache_state);
    errno_t ret;

    ret = kcm_ccdb_name_by_uuid_recv(subreq, state, &state->name);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get ccahe by UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        /* Instead of failing the whole operation, return the first
         * ccache as a fallback
         */
        subreq = kcm_ccdb_list_send(state, state->ev,
                                    state->op_ctx->kcm_data->db,
                                    state->op_ctx->client);
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, kcm_op_get_default_ccache_list_done, req);
        return;
    }

    ret = kcm_op_get_default_ccache_reply_step(state);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static void kcm_op_get_default_ccache_list_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct kcm_op_get_default_ccache_state *state = tevent_req_data(req,
                                    struct kcm_op_get_default_ccache_state);
    errno_t ret;
    uuid_t *uuid_list;

    ret = kcm_ccdb_list_recv(subreq, state, &uuid_list);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot list ccaches [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (uuid_list == NULL || uuid_is_null(uuid_list[0])) {
        /* No cache at all, just send back a reply */
        ret = kcm_op_get_default_ccache_reply_step(state);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        tevent_req_done(req);
        return;
    }

    /* Otherwise resolve the first cache and use it as a default */
    subreq = kcm_ccdb_name_by_uuid_send(state,
                                        state->ev,
                                        state->op_ctx->kcm_data->db,
                                        state->op_ctx->client,
                                        uuid_list[0]);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_get_default_ccache_byuuid_done, req);
    return;
}

static errno_t
kcm_op_get_default_ccache_reply_step(struct kcm_op_get_default_ccache_state *state)
{
    errno_t ret;

    if (state->name == NULL) {
        state->name = talloc_asprintf(state,
                                      "%"SPRIuid,
                                      cli_creds_get_uid(state->op_ctx->client));
        if (state->name == NULL) {
            return ENOMEM;
        }
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "The default ccache is %s\n", state->name);

    ret = sss_iobuf_write_stringz(state->op_ctx->reply, state->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot write output name [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static errno_t kcm_op_get_default_ccache_recv(struct tevent_req *req,
                                              uint32_t *_op_ret)
{
    KCM_OP_RET_FROM_TYPE(req, struct kcm_op_get_default_ccache_state, _op_ret);
}

/* (name) -> () */
static void kcm_op_set_default_ccache_getbyname_done(struct tevent_req *subreq);
static void kcm_op_set_default_create_step(struct tevent_req *req);
static void kcm_op_set_default_create_step_done(struct tevent_req *subreq);
static void kcm_op_set_default_step(struct tevent_req *req);
static void kcm_op_set_default_done(struct tevent_req *subreq);

struct kcm_op_set_default_ccache_state {
    uint32_t op_ret;
    struct kcm_op_ctx *op_ctx;
    struct tevent_context *ev;

    const char *name;
    uuid_t dfl_uuid;
    struct kcm_ccache *new_cc;
};

static struct tevent_req *
kcm_op_set_default_ccache_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_set_default_ccache_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx,
                            &state,
                            struct kcm_op_set_default_ccache_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;
    state->ev = ev;

    ret = sss_iobuf_read_stringz(op_ctx->input, &state->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot read input name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Setting default ccache %s\n", state->name);

    subreq = kcm_ccdb_uuid_by_name_send(state, ev,
                                        op_ctx->kcm_data->db,
                                        op_ctx->client,
                                        state->name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_set_default_ccache_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_set_default_ccache_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_set_default_ccache_state *state = tevent_req_data(req,
                                    struct kcm_op_set_default_ccache_state);

    ret = kcm_ccdb_uuid_by_name_recv(subreq, state, state->dfl_uuid);
    talloc_zfree(subreq);
    if (ret == ERR_NO_CREDS) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "The ccache does not exist, creating a new one\n");
        kcm_op_set_default_create_step(req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get ccache by name [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    kcm_op_set_default_step(req);
}

static void kcm_op_set_default_create_step(struct tevent_req *req)
{
    errno_t ret;
    struct tevent_req *subreq;
    struct kcm_op_set_default_ccache_state *state = tevent_req_data(req,
                                    struct kcm_op_set_default_ccache_state);

    /* Only allow to create ccaches for 'self' */
    ret = kcm_check_name(state->name, state->op_ctx->client);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "Name %s is malformed [%d]: %s\n",
            state->name, ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = kcm_cc_new(state->op_ctx,
                     state->op_ctx->kcm_data->k5c,
                     state->op_ctx->client,
                     state->name,
                     NULL,
                     &state->new_cc);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
            "Cannot create new ccache %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = kcm_ccdb_create_cc_send(state,
                                     state->ev,
                                     state->op_ctx->kcm_data->db,
                                     state->op_ctx->client,
                                     state->new_cc);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_set_default_create_step_done, req);
}

static void kcm_op_set_default_create_step_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_set_default_ccache_state *state = tevent_req_data(req,
                                    struct kcm_op_set_default_ccache_state);

    ret = kcm_ccdb_create_cc_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot add ccache to db %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "The ccache was created, switching to it");

    ret = kcm_cc_get_uuid(state->new_cc, state->dfl_uuid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get new ccache UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    kcm_op_set_default_step(req);
}

static void kcm_op_set_default_step(struct tevent_req *req)
{
    struct kcm_op_set_default_ccache_state *state = tevent_req_data(req,
                                    struct kcm_op_set_default_ccache_state);
    struct tevent_req *subreq;

    subreq = kcm_ccdb_set_default_send(state,
                                       state->ev,
                                       state->op_ctx->kcm_data->db,
                                       state->op_ctx->client,
                                       state->dfl_uuid);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_set_default_done, req);
    return;
}

static void kcm_op_set_default_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_set_default_ccache_state *state = tevent_req_data(req,
                                    struct kcm_op_set_default_ccache_state);

    ret = kcm_ccdb_set_default_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot set default ccache %d: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

static errno_t kcm_op_set_default_ccache_recv(struct tevent_req *req,
                                              uint32_t *_op_ret)
{
    KCM_OP_RET_FROM_TYPE(req, struct kcm_op_set_default_ccache_state, _op_ret);
}

/* (name) -> (offset) */
static void kcm_op_get_kdc_offset_getbyname_done(struct tevent_req *subreq);

static struct tevent_req *
kcm_op_get_kdc_offset_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_common_state *state = NULL;
    errno_t ret;
    const char *name;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;

    ret = sss_iobuf_read_stringz(op_ctx->input, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot read input name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Requested offset for principal %s\n", name);

    subreq = kcm_ccdb_getbyname_send(state, ev,
                                     op_ctx->kcm_data->db,
                                     op_ctx->client,
                                     name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_get_kdc_offset_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_get_kdc_offset_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct kcm_ccache *cc;
    int32_t offset;
    int32_t offset_be;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_common_state *state = tevent_req_data(req,
                                                struct kcm_op_common_state);

    ret = kcm_ccdb_getbyname_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get matching ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (cc == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No matching credentials\n");
        state->op_ret = ERR_NO_MATCHING_CREDS;
        tevent_req_done(req);
        return;
    }

    offset = kcm_cc_get_offset(cc);
    DEBUG(SSSDBG_TRACE_LIBS, "KDC offset: %"PRIi32"\n", offset);

    offset_be = htobe32(offset);
    ret = sss_iobuf_write_int32(state->op_ctx->reply, offset_be);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot write KDC offset [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

/* (name, offset) -> () */
/* () -> (name) */
struct kcm_op_set_kdc_offset_state {
    uint32_t op_ret;
    struct kcm_op_ctx *op_ctx;
    struct tevent_context *ev;
};

static void kcm_op_set_kdc_offset_getbyname_done(struct tevent_req *subreq);
static void kcm_op_set_kdc_offset_mod_done(struct tevent_req *subreq);

static struct tevent_req *
kcm_op_set_kdc_offset_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct kcm_op_ctx *op_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_op_set_kdc_offset_state *state = NULL;
    errno_t ret;
    const char *name;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_set_kdc_offset_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;
    state->ev = ev;

    ret = sss_iobuf_read_stringz(op_ctx->input, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot read input name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Setting offset for principal %s\n", name);

    subreq = kcm_ccdb_uuid_by_name_send(state, ev,
                                        op_ctx->kcm_data->db,
                                        op_ctx->client,
                                        name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_op_set_kdc_offset_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_set_kdc_offset_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct kcm_mod_ctx *mod_ctx;
    int32_t offset_be;
    uuid_t uuid;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_set_kdc_offset_state *state = tevent_req_data(req,
                                                struct kcm_op_set_kdc_offset_state);

    /* `uuid` is output arg and isn't read in kcm_ccdb_uuid_by_name_recv() but
     * since libuuid is opaque for cppcheck it generates false positive here
     */
    /* cppcheck-suppress uninitvar */
    ret = kcm_ccdb_uuid_by_name_recv(subreq, state, uuid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get matching ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = sss_iobuf_read_int32(state->op_ctx->input, &offset_be);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot read KDC offset [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    mod_ctx = kcm_mod_ctx_new(state);
    if (mod_ctx == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    mod_ctx->kdc_offset = be32toh(offset_be);

    subreq = kcm_ccdb_mod_cc_send(state,
                                  state->ev,
                                  state->op_ctx->kcm_data->db,
                                  state->op_ctx->client,
                                  uuid,
                                  mod_ctx);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_op_set_kdc_offset_mod_done, req);
}

static void kcm_op_set_kdc_offset_mod_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_op_set_kdc_offset_state *state = tevent_req_data(req,
                                                struct kcm_op_set_kdc_offset_state);

    ret = kcm_ccdb_mod_cc_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot modify ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->op_ret = EOK;
    tevent_req_done(req);
}

static errno_t kcm_op_set_kdc_offset_recv(struct tevent_req *req,
                                          uint32_t *_op_ret)
{
    KCM_OP_RET_FROM_TYPE(req, struct kcm_op_set_kdc_offset_state, _op_ret);
}

static void kcm_op_get_cred_list_done(struct tevent_req *subreq);

static struct tevent_req *
kcm_op_get_cred_list_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct kcm_op_ctx *op_ctx)
{
    struct kcm_op_common_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char *name;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_common_state);
    if (req == NULL) {
        return NULL;
    }
    state->op_ctx = op_ctx;

    ret = sss_iobuf_read_stringz(op_ctx->input, &name);
    if (ret != EOK) {
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Returning credentials for %s\n", name);

    subreq = kcm_ccdb_getbyname_send(state, ev,
                                     op_ctx->kcm_data->db,
                                     op_ctx->client,
                                     name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    tevent_req_set_callback(subreq, kcm_op_get_cred_list_done, req);

    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_get_cred_list_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct kcm_op_common_state *state;
    struct kcm_ccache *cc;
    struct kcm_cred *crd;
    uint32_t num_creds;
    struct sss_iobuf *crd_blob;
    uint8_t *crd_data;
    uint32_t crd_size;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct kcm_op_common_state);

    ret = kcm_ccdb_getbyname_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get ccache by name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (cc == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No ccache by that name\n");
        state->op_ret = ERR_NO_CREDS;
        ret = EOK;
        goto done;
    }

    num_creds = 0;
    for (crd = kcm_cc_get_cred(cc); crd != NULL; crd = kcm_cc_next_cred(crd)) {
        num_creds++;
    }

    ret = sss_iobuf_write_uint32(state->op_ctx->reply, htobe32(num_creds));
    if (ret != EOK) {
        goto done;
    }

    for (crd = kcm_cc_get_cred(cc); crd != NULL; crd = kcm_cc_next_cred(crd)) {
        crd_blob = kcm_cred_get_creds(crd);
        if (crd_blob == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Credentials lack the creds blob\n");
            ret = ERR_NO_CREDS;
            goto done;
        }

        crd_data = sss_iobuf_get_data(crd_blob);
        crd_size = sss_iobuf_get_size(crd_blob);

        ret = sss_iobuf_write_uint32(state->op_ctx->reply, htobe32(crd_size));
        if (ret != EOK) {
            goto done;
        }

        ret = sss_iobuf_write_len(state->op_ctx->reply, crd_data, crd_size);
        if (ret != EOK) {
            goto done;
        }
    }

    state->op_ret = EOK;
    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static struct kcm_op kcm_optable[] = {
    { "NOOP",                NULL, NULL },
    { "GET_NAME",            NULL, NULL },
    { "RESOLVE",             NULL, NULL },
    { "GEN_NEW",             kcm_op_gen_new_send, NULL },
    { "INITIALIZE",          kcm_op_initialize_send, kcm_op_initialize_recv },
    { "DESTROY",             kcm_op_destroy_send, NULL },
    { "STORE",               kcm_op_store_send, kcm_op_store_recv },
    { "RETRIEVE",            NULL, NULL },
    { "GET_PRINCIPAL",       kcm_op_get_principal_send, NULL },
    { "GET_CRED_UUID_LIST",  kcm_op_get_cred_uuid_list_send, NULL },
    { "GET_CRED_BY_UUID",    kcm_op_get_cred_by_uuid_send, kcm_op_get_cred_by_uuid_recv },
    { "REMOVE_CRED",         kcm_op_remove_cred_send, NULL },
    { "SET_FLAGS",           NULL, NULL },
    { "CHOWN",               NULL, NULL },
    { "CHMOD",               NULL, NULL },
    { "GET_INITIAL_TICKET",  NULL, NULL },
    { "GET_TICKET",          NULL, NULL },
    { "MOVE_CACHE",          NULL, NULL },
    { "GET_CACHE_UUID_LIST", kcm_op_get_cache_uuid_list_send, NULL },
    { "GET_CACHE_BY_UUID",   kcm_op_get_cache_by_uuid_send, NULL },
    { "GET_DEFAULT_CACHE",   kcm_op_get_default_ccache_send, kcm_op_get_default_ccache_recv },
    { "SET_DEFAULT_CACHE",   kcm_op_set_default_ccache_send, kcm_op_set_default_ccache_recv },
    { "GET_KDC_OFFSET",      kcm_op_get_kdc_offset_send, NULL },
    { "SET_KDC_OFFSET",      kcm_op_set_kdc_offset_send, kcm_op_set_kdc_offset_recv },
    { "ADD_NTLM_CRED",       NULL, NULL },
    { "HAVE_NTLM_CRED",      NULL, NULL },
    { "DEL_NTLM_CRED",       NULL, NULL },
    { "DO_NTLM_AUTH",        NULL, NULL },
    { "GET_NTLM_USER_LIST",  NULL, NULL },

    { NULL, NULL, NULL }
};

/* MIT EXTENSIONS, see private header src/include/kcm.h in krb5 sources */
#define KCM_MIT_OFFSET 13001
static struct kcm_op kcm_mit_optable[] = {
    { "GET_CRED_LIST", kcm_op_get_cred_list_send, NULL },

    { NULL, NULL, NULL }
};

struct kcm_op *kcm_get_opt(uint16_t opcode)
{
    struct kcm_op *table;
    struct kcm_op *op;
    size_t len;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "The client requested operation %"PRIu16"\n", opcode);

    table = kcm_optable;
    len = sizeof(kcm_optable) / sizeof(struct kcm_op);
    if (opcode >= KCM_MIT_OFFSET) {
        opcode -= KCM_MIT_OFFSET;
        table = kcm_mit_optable;
        len = sizeof(kcm_mit_optable) / sizeof(struct kcm_op);
    }

    if (opcode >= len) {
        return NULL;
    }

    op = &table[opcode];
    if (op->fn_recv == NULL) {
        op->fn_recv = kcm_op_common_recv;
    }

    return op;
}

const char *kcm_opt_name(struct kcm_op *op)
{
    if (op == NULL || op->name == NULL) {
        return "Unknown operation";
    }

    return op->name;
}
