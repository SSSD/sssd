/*
   SSSD

   KCM Server - the KCM server request and reply parsing and dispatching

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

#include <sys/uio.h>
#include <krb5/krb5.h>

#include "config.h"
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/kcm/kcmsrv_pvt.h"
#include "responder/kcm/kcmsrv_ops.h"

/* The first four bytes of a message is always the size */
#define KCM_MSG_LEN_SIZE 4

/* The return code is 32bits */
#define KCM_RETCODE_SIZE 4

/* KCM operation, its raw input and raw output and result */
struct kcm_op_io {
    struct kcm_op *op;
    struct kcm_data request;
    struct sss_iobuf *reply;
};

/**
 * KCM IO-vector operations
 */
struct kcm_iovec {
    /* We don't use iovec b/c void pointers don't allow for
     * pointer arithmetics and it's convenient to keep track
     * of processed bytes
     */
    uint8_t *kiov_base;
    size_t kiov_len;
    size_t nprocessed;
};

static errno_t kcm_iovec_op(int fd, struct kcm_iovec *kiov, bool do_read)
{
    ssize_t len;
    struct iovec iov[1];

    iov[0].iov_base = kiov->kiov_base + kiov->nprocessed;
    iov[0].iov_len = kiov->kiov_len - kiov->nprocessed;
    if (iov[0].iov_len == 0) {
        /* This iovec is full (read) or depleted (write), proceed to the next one */
        return EOK;
    }

    if (do_read) {
        len = readv(fd, iov, 1);
    } else {
        len = writev(fd, iov, 1);
    }

    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return EAGAIN;
        } else {
            return errno;
        }
    }

    if (len == 0) {
        /* Read event on fd that doesn't yield data? error */
        return ENODATA;
    }

    /* Decrease the amount of available free space in the iovec */
    kiov->nprocessed += len;
    return EOK;
}

static errno_t kcm_read_iovec(int fd, struct kcm_iovec *kiov)
{
    return kcm_iovec_op(fd, kiov, true);
}

static errno_t kcm_write_iovec(int fd, struct kcm_iovec *kiov)
{
    return kcm_iovec_op(fd, kiov, false);
}

/**
 * Parsing KCM input
 *
 * The request is received as two IO vectors:
 *
 * first iovec:
 *  length                      32-bit big-endian integer
 *
 * second iovec:
 *  major protocol number       8-bit big-endian integer
 *  minor protocol number       8-bit big-endian integer
 *  opcode                      16-bit big-endian integer
 *  message payload             buffer
 */
struct kcm_reqbuf {
    uint8_t lenbuf[KCM_MSG_LEN_SIZE];
    struct kcm_iovec v_len;

    /* Includes the major, minor versions etc */
    struct kcm_iovec v_msg;
};

static uint32_t kcm_input_get_payload_len(struct kcm_iovec *v)
{
    size_t lc = 0;
    uint32_t len_be = 0;

    /* The first 4 bytes before the payload is message length */
    SAFEALIGN_COPY_UINT32_CHECK(&len_be, v->kiov_base, v->kiov_len, &lc);

    return be32toh(len_be);
}

static errno_t kcm_input_parse(struct kcm_reqbuf *reqbuf,
                               struct kcm_op_io *op_io)
{
    size_t mc = 0;
    uint16_t opcode_be = 0;
    uint32_t msglen;
    uint8_t proto_maj = 0;
    uint8_t proto_min = 0;

    msglen = kcm_input_get_payload_len(&reqbuf->v_len);
    DEBUG(SSSDBG_TRACE_LIBS,
          "Received message with length %"PRIu32"\n", msglen);

    if (msglen == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Illegal zero-length message\n");
        return EBADMSG;
    }

    if (msglen != reqbuf->v_msg.nprocessed) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Sender claims the message is %"PRIu32" bytes, "
              "but received %zu\n",
              msglen, reqbuf->v_msg.nprocessed);
        return EBADMSG;
    }

    /* First 16 bits are 8 bit major and 8bit minor protocol version */
    SAFEALIGN_COPY_UINT8_CHECK(&proto_maj,
                               reqbuf->v_msg.kiov_base + mc,
                               reqbuf->v_msg.kiov_len,
                               &mc);
    SAFEALIGN_COPY_UINT8_CHECK(&proto_min,
                               reqbuf->v_msg.kiov_base + mc,
                               reqbuf->v_msg.kiov_len,
                               &mc);

    if (proto_maj != KCM_PROTOCOL_VERSION_MAJOR) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected major version %d, got %"PRIu16"\n",
              KCM_PROTOCOL_VERSION_MAJOR, (uint16_t) proto_maj);
        return ERR_KCM_MALFORMED_IN_PKT;
    }

    if (proto_min != KCM_PROTOCOL_VERSION_MINOR) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected minor version %d, got %"PRIu16"\n",
              KCM_PROTOCOL_VERSION_MINOR, (uint16_t) proto_maj);
        return ERR_KCM_MALFORMED_IN_PKT;
    }

    SAFEALIGN_COPY_UINT16_CHECK(&opcode_be,
                                reqbuf->v_msg.kiov_base + mc,
                                reqbuf->v_msg.kiov_len,
                                &mc);

    op_io->op = kcm_get_opt(be16toh(opcode_be));
    if (op_io->op == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Did not find a KCM operation handler for the requested opcode\n");
        return ERR_KCM_OP_NOT_IMPLEMENTED;
    }

    /* The operation only receives the payload, not the opcode or the protocol info */
    op_io->request.data = reqbuf->v_msg.kiov_base + mc;
    op_io->request.length = reqbuf->v_msg.nprocessed - mc;

    return EOK;
}

/**
 * Constructing a reply for failure and success
 *
 * The reply consists of three IO vectors:
 * 1) length iovec:
 *  length:     32-bit big-endian
 *
 * 2) return code iovec:
 *  retcode:    32-bit big-endian. Non-zero on failure in the KCM server,
 *              zero if the KCM operation ran (even if the operation itself
 *              failed)
 *
 * 3) reply iovec
 *  message:    buffer, first 32-bits of the buffer is the return code of
 *              the KCM operation, the rest depends on the operation itself.
 *              The buffer's length is specified by the first integer in the
 *              reply (very intuitive, right?)
 *
 *  The client always reads the length and return code iovectors. However, the
 *  client reads the reply iovec only if retcode is 0 in the return code iovector
 *  (see kcmio_unix_socket_read() in the MIT tree)
 */
struct kcm_repbuf {
    uint8_t lenbuf[KCM_MSG_LEN_SIZE];
    struct kcm_iovec v_len;

    uint8_t rcbuf[KCM_RETCODE_SIZE];
    struct kcm_iovec v_rc;

    struct kcm_iovec v_msg;
};

static errno_t kcm_failbuf_construct(errno_t ret,
                                     struct kcm_repbuf *repbuf)
{
    size_t c;

    c = 0;
    SAFEALIGN_SETMEM_UINT32(repbuf->lenbuf, 0, &c);
    c = 0;
    SAFEALIGN_SETMEM_UINT32(repbuf->rcbuf, htobe32(ret), &c);

    DEBUG(SSSDBG_TRACE_LIBS, "Sent reply with error %d\n", ret);
    return EOK;
}

/* retcode is 0 if the operation at least ran, non-zero if there
 * was some kind of internal KCM error, like input couldn't be parsed
 */
static errno_t kcm_output_construct(TALLOC_CTX *mem_ctx,
                                    struct kcm_op_io *op_io,
                                    struct kcm_repbuf *repbuf)
{
    uint8_t *rep;
    size_t replen;
    size_t c;

    replen = sss_iobuf_get_len(op_io->reply);
    if (replen > KCM_PACKET_MAX_SIZE) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Reply exceeds the KCM protocol limit, aborting\n");
        return E2BIG;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "Sending a reply with %zu bytes of payload\n", replen);
    c = 0;
    SAFEALIGN_SETMEM_UINT32(repbuf->lenbuf, htobe32(replen), &c);

    c = 0;
    SAFEALIGN_SETMEM_UINT32(repbuf->rcbuf, 0, &c);

    if (replen > 0) {
        rep = talloc_array(mem_ctx, uint8_t, replen);
        if (rep == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to allocate memory for the message\n");
            return ENOMEM;
        }

        c = 0;
        SAFEALIGN_MEMCPY_CHECK(rep,
                               sss_iobuf_get_data(op_io->reply),
                               replen,
                               replen,
                               &c);

        /* Set the buffer and its length to send to KCM client */
        repbuf->v_msg.kiov_base = rep;
        repbuf->v_msg.kiov_len = replen;
    }

    return EOK;
}

/**
 * Construct a reply buffer and send it to the KCM client
 */
static void kcm_reply_error(struct cli_ctx *cctx,
                            errno_t retcode,
                            struct kcm_repbuf *repbuf)
{
    errno_t ret;
    krb5_error_code kerr;

    DEBUG(retcode == ERR_KCM_OP_NOT_IMPLEMENTED ?
              SSSDBG_MINOR_FAILURE : SSSDBG_OP_FAILURE,
          "KCM operation returns failure [%d]: %s\n",
          retcode, sss_strerror(retcode));
    kerr = sss2krb5_error(retcode);

    ret = kcm_failbuf_construct(kerr, repbuf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot construct the reply buffer, terminating client\n");
        talloc_free(cctx);
        return;
    }

    TEVENT_FD_WRITEABLE(cctx->cfde);
}

/**
 * Request-reply dispatcher
 */
struct kcm_req_ctx {
    /* client context owns per-client buffers including this one */
    struct cli_ctx *cctx;

    /* raw IO buffers */
    struct kcm_reqbuf reqbuf;
    struct kcm_repbuf repbuf;

    /* long-lived responder structures */
    struct kcm_ctx *kctx;

    struct kcm_op_io op_io;
};

static void kcm_send_reply(struct kcm_req_ctx *req_ctx)
{
    struct cli_ctx *cctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Sending a reply\n");

    cctx = req_ctx->cctx;

    ret = kcm_output_construct(cctx, &req_ctx->op_io, &req_ctx->repbuf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot construct the reply buffer, terminating client\n");
        kcm_reply_error(cctx, ret, &req_ctx->repbuf);
        return;
    }

    TEVENT_FD_WRITEABLE(cctx->cfde);
}

static void kcm_cmd_request_done(struct tevent_req *req);

static errno_t kcm_cmd_dispatch(struct kcm_ctx *kctx,
                                struct kcm_req_ctx *req_ctx)
{
    struct tevent_req *req;
    struct cli_ctx *cctx;
    struct kcm_conn_data *conn_data;

    cctx = req_ctx->cctx;
    conn_data = talloc_get_type(cctx->state_ctx, struct kcm_conn_data);

    req = kcm_cmd_send(req_ctx,
                       cctx->ev,
                       kctx->qctx,
                       req_ctx->kctx->kcm_data,
                       conn_data,
                       req_ctx->cctx->creds,
                       &req_ctx->op_io.request,
                       req_ctx->op_io.op);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to schedule KCM operation.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, kcm_cmd_request_done, req_ctx);
    return EOK;
}

static void kcm_cmd_request_done(struct tevent_req *req)
{
    struct kcm_req_ctx *req_ctx;
    errno_t ret;

    req_ctx = tevent_req_callback_data(req, struct kcm_req_ctx);

    ret = kcm_cmd_recv(req_ctx, req,
                       &req_ctx->op_io.reply);
    talloc_free(req);
    if (ret != EOK) {
        if (ret == ERR_KCM_OP_NOT_IMPLEMENTED) {
            DEBUG(SSSDBG_MINOR_FAILURE, "%s\n", sss_strerror(ret));
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "KCM operation failed [%d]: %s\n", ret, sss_strerror(ret));
        }
        kcm_reply_error(req_ctx->cctx, ret, &req_ctx->repbuf);
        return;
    }

    kcm_send_reply(req_ctx);
}

static errno_t kcm_recv_data(TALLOC_CTX *mem_ctx,
                             int fd,
                             struct kcm_reqbuf *reqbuf)
{
    uint8_t *msg;
    uint32_t msglen;
    errno_t ret;

    ret = kcm_read_iovec(fd, &reqbuf->v_len);
    if (ret != EOK) {
        /* Not all errors are fatal, hence we don't print DEBUG messages
         * here, but in the caller
         */
        return ret;
    }

    msglen = kcm_input_get_payload_len(&reqbuf->v_len);
    if (msglen > KCM_PACKET_MAX_SIZE) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Request exceeds the KCM protocol limit, aborting\n");
        return E2BIG;
    }

    msg = talloc_array(mem_ctx, uint8_t, msglen);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate memory for the message\n");
        return ENOMEM;
    }

    /* Set the buffer and its expected len to receive the data */
    reqbuf->v_msg.kiov_base = msg;
    reqbuf->v_msg.kiov_len = msglen;

    ret = kcm_read_iovec(fd, &reqbuf->v_msg);
    if (ret != EOK) {
        /* Not all errors are fatal, hence we don't print DEBUG messages
         * here, but in the caller
         */
        return ret;
    }

    return EOK;
}

/* Mind that kcm_new_req() does not take a mem_ctx argument on purpose as we
 * really want the cctx to be the memory context here so that if the client
 * disconnects, the request goes away. */
static struct kcm_req_ctx *kcm_new_req(struct cli_ctx *cctx,
                                       struct kcm_ctx *kctx)
{
    struct kcm_req_ctx *req;

    req = talloc_zero(cctx, struct kcm_req_ctx);
    if (req == NULL) {
        return NULL;
    }

    req->reqbuf.v_len.kiov_base = req->reqbuf.lenbuf;
    req->reqbuf.v_len.kiov_len = KCM_MSG_LEN_SIZE;

    req->repbuf.v_len.kiov_base = req->repbuf.lenbuf;
    req->repbuf.v_len.kiov_len = KCM_MSG_LEN_SIZE;

    req->repbuf.v_rc.kiov_base = req->repbuf.rcbuf;
    req->repbuf.v_rc.kiov_len = KCM_RETCODE_SIZE;

    req->cctx = cctx;
    req->kctx = kctx;

    return req;
}

static void kcm_recv(struct cli_ctx *cctx)
{
    struct kcm_req_ctx *req;
    struct kcm_ctx *kctx;
    int ret;

    kctx = talloc_get_type(cctx->rctx->pvt_ctx, struct kcm_ctx);
    req = talloc_get_type(cctx->protocol_ctx, struct kcm_req_ctx);
    if (req == NULL) {
        /* A new request comes in, setup data structures. */
        req = kcm_new_req(cctx, kctx);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot set up client connection\n");
            talloc_free(cctx);
            return;
        }

        cctx->protocol_ctx = req;
    }

    /* Shared data between requests that originates in the same connection. */
    if (cctx->state_ctx == NULL) {
        cctx->state_ctx = talloc_zero(cctx, struct kcm_conn_data);
        if (cctx->state_ctx == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot set up client state\n");
            talloc_free(cctx);
            return;
        }
    }

    ret = kcm_recv_data(req, cctx->cfd, &req->reqbuf);
    switch (ret) {
    case ENODATA:
        DEBUG(SSSDBG_TRACE_ALL, "Client closed connection.\n");
        talloc_free(cctx);
        return;
    case EAGAIN:
        DEBUG(SSSDBG_TRACE_ALL, "Retry later\n");
        return;
    case EOK:
        /* all fine */
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to receive data (%d, %s), aborting client\n",
              ret, sss_strerror(ret));
        talloc_free(cctx);
        return;
    }

    ret = kcm_input_parse(&req->reqbuf, &req->op_io);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
            "Failed to parse data (%d, %s), aborting client\n",
            ret, sss_strerror(ret));
        talloc_free(cctx);
        return;
    }

    /* do not read anymore, client is done sending */
    TEVENT_FD_NOT_READABLE(cctx->cfde);

    ret = kcm_cmd_dispatch(kctx, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to dispatch KCM operation [%d]: %s\n",
              ret, sss_strerror(ret));
        /* Fail with reply */
        kcm_reply_error(cctx, ret, &req->repbuf);
        return;
    }

    /* Dispatched request resumes in kcm_cmd_request_done */
    return;
}

static int kcm_send_data(struct cli_ctx *cctx)
{
    struct kcm_req_ctx *req;
    errno_t ret;

    req = talloc_get_type(cctx->protocol_ctx, struct kcm_req_ctx);

    ret = kcm_write_iovec(cctx->cfd, &req->repbuf.v_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to write the length iovec [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = kcm_write_iovec(cctx->cfd, &req->repbuf.v_rc);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to write the retcode iovec [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = kcm_write_iovec(cctx->cfd, &req->repbuf.v_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to write the msg iovec [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static void kcm_send(struct cli_ctx *cctx)
{
    errno_t ret;

    ret = kcm_send_data(cctx);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_ALL, "Sending data again..\n");
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to send data, aborting client!\n");
        talloc_free(cctx);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "All data sent!\n");
    TEVENT_FD_NOT_WRITEABLE(cctx->cfde);
    TEVENT_FD_READABLE(cctx->cfde);
    talloc_zfree(cctx->protocol_ctx);
    return;
}

static void kcm_fd_handler(struct tevent_context *ev,
                           struct tevent_fd *fde,
                           uint16_t flags, void *ptr)
{
    sss_client_fd_handler(ptr, kcm_recv, kcm_send, flags);
}

int kcm_connection_setup(struct cli_ctx *cctx)
{
    cctx->cfd_handler = kcm_fd_handler;
    return EOK;
}

krb5_error_code sss2krb5_error(errno_t err)
{
    switch (err) {
    case EOK:
        return 0;
    case ENOMEM:
        return KRB5_CC_NOMEM;
    case EACCES:
        return KRB5_FCC_PERM;
    case ERR_KCM_OP_NOT_IMPLEMENTED:
        return KRB5_FCC_INTERNAL;
    case ERR_WRONG_NAME_FORMAT:
        return KRB5_CC_BADNAME;
    case ERR_NO_MATCHING_CREDS:
        return KRB5_FCC_NOFILE;
    case ERR_NO_CREDS:
        return KRB5_CC_NOTFOUND;
    case ERR_KCM_CC_END:
        return KRB5_CC_END;
    case ERR_KCM_MALFORMED_IN_PKT:
    case EINVAL:
    case EIO:
        return KRB5_CC_IO;
    }

    return KRB5_FCC_INTERNAL;
}

/* Dummy, not used here but required to link to other responder files */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    return NULL;
}
