/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include "util/util.h"
#include "util/cert.h"
#include "lib/idmap/sss_idmap.h"
#include "responder/nss/nss_protocol.h"
#include <arpa/inet.h>

errno_t
sss_nss_protocol_done(struct cli_ctx *cli_ctx, errno_t error)
{
    struct cli_protocol *pctx;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    switch (error) {
    case EOK:
        /* Create empty packet if none was provided. */
        if (pctx->creq->out == NULL) {
            ret = sss_packet_new(pctx->creq, 0,
                                 sss_packet_get_cmd(pctx->creq->in),
                                 &pctx->creq->out);
            if (ret != EOK) {
                goto done;
            }

            sss_packet_set_error(pctx->creq->out, EOK);
        }

        DEBUG(SSSDBG_TRACE_ALL, "Sending reply: success\n");
        ret = EOK;
        goto done;
    case ENOENT:
        DEBUG(SSSDBG_TRACE_ALL, "Sending reply: not found\n");
        ret = sss_cmd_send_empty(cli_ctx);
        goto done;
    default:
        DEBUG(SSSDBG_TRACE_ALL, "Sending reply: error [%d]: %s\n",
              error, sss_strerror(error));
        ret = sss_cmd_send_error(cli_ctx, error);
        goto done;
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send reply [%d]: %s!\n",
              ret, sss_strerror(ret));
        return ret;
    }

    sss_cmd_done(cli_ctx, NULL);
    return EOK;
}

void sss_nss_protocol_reply(struct cli_ctx *cli_ctx,
                            struct sss_nss_ctx *nss_ctx,
                            struct sss_nss_cmd_ctx *cmd_ctx,
                            struct cache_req_result *result,
                            sss_nss_protocol_fill_packet_fn fill_fn)
{
    struct cli_protocol *pctx;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        goto done;
    }

    ret = fill_fn(nss_ctx, cmd_ctx, pctx->creq->out, result);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_set_error(pctx->creq->out, EOK);

done:
    sss_nss_protocol_done(cli_ctx, ret);
}

errno_t
sss_nss_protocol_parse_name(struct cli_ctx *cli_ctx, const char **_rawname)
{
    struct cli_protocol *pctx;
    const char *rawname;
    uint8_t *body;
    size_t blen;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* If not terminated fail. */
    if (body[blen - 1] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not null terminated!\n");
        return EINVAL;
    }

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(body, blen - 1)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not UTF-8 string!\n");
        return EINVAL;
    }

    rawname = (const char *)body;
    if (rawname[0] == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "An empty name was provided!\n");
        return EINVAL;
    }

    *_rawname = rawname;

    return EOK;
}

errno_t
sss_nss_protocol_parse_name_ex(struct cli_ctx *cli_ctx, const char **_rawname,
                           uint32_t *_flags)
{
    struct cli_protocol *pctx;
    const char *rawname;
    uint8_t *body;
    size_t blen;
    uint8_t *p;
    uint32_t flags;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    if (blen < 1 + sizeof(uint32_t)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body too short!\n");
        return EINVAL;
    }

    /* If first argument not terminated fail. */
    if (body[blen - 1 - sizeof(uint32_t)] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not null terminated!\n");
        return EINVAL;
    }

    p = memchr(body, '\0', blen);
    /* Although body for sure is null terminated, let's add this check here
     * so static analyzers are happier. */
    if (p == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "memchr() returned NULL, body is not null terminated!\n");
        return EINVAL;
    }

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(body, (p - body))) {
        DEBUG(SSSDBG_CRIT_FAILURE, "First argument is not UTF-8 string!\n");
        return EINVAL;
    }

    rawname = (const char *)body;
    if (rawname[0] == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "An empty name was provided!\n");
        return EINVAL;
    }

    p++;
    if ((p - body) + sizeof(uint32_t) != blen) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body has unexpected size!\n");
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&flags, p, NULL);

    *_rawname = rawname;
    *_flags = flags;

    return EOK;
}

errno_t
sss_nss_protocol_parse_id(struct cli_ctx *cli_ctx, uint32_t *_id)
{
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;
    uint32_t id;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&id, body, NULL);

    *_id = id;

    return EOK;
}

errno_t
sss_nss_protocol_parse_id_ex(struct cli_ctx *cli_ctx, uint32_t *_id,
                         uint32_t *_flags)
{
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;
    uint32_t id;
    uint32_t flags;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    if (blen != 2 * sizeof(uint32_t)) {
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&id, body, NULL);
    SAFEALIGN_COPY_UINT32(&flags, body + sizeof(uint32_t), NULL);

    *_id = id;
    *_flags = flags;

    return EOK;
}

errno_t
sss_nss_protocol_parse_limit(struct cli_ctx *cli_ctx, uint32_t *_limit)
{
    return sss_nss_protocol_parse_id(cli_ctx, _limit);
}

errno_t
sss_nss_protocol_parse_svc_name(struct cli_ctx *cli_ctx,
                            const char **_name,
                            const char **_protocol)
{
    struct cli_protocol *pctx;
    const char *protocol;
    const char *name;
    size_t protocol_len;
    size_t name_len;
    uint8_t *body;
    size_t blen;
    int i;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* If not terminated fail. */
    if (body[blen - 1] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not null terminated\n");
        return EINVAL;
    }

    /* Calculate service name length. */
    for (i = 0, name_len = 0; body[i] != '\0'; i++) {
        name_len++;
    }

    /* Calculate protocol name length, use index from previous cycle. */
    for (protocol_len = 0; body[i + 1] != '\0'; i++) {
        protocol_len++;
    }

    if (name_len == 0) {
        return EINVAL;
    }

    name = (const char *)body;
    protocol = protocol_len == 0 ? NULL : (const char *)(body + name_len + 1);

    if (!sss_utf8_check((const uint8_t *)name, name_len)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Name is not UTF-8 string\n");
        return EINVAL;
    }

    if (!sss_utf8_check((const uint8_t *)protocol, protocol_len)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Protocol is not UTF-8 string\n");
        return EINVAL;
    }

    *_name = name;
    *_protocol = protocol;

    return EOK;
}

errno_t
sss_nss_protocol_parse_svc_port(struct cli_ctx *cli_ctx,
                            uint16_t *_port,
                            const char **_protocol)
{
    struct cli_protocol *pctx;
    const char *protocol;
    size_t protocol_len;
    uint16_t port;
    uint8_t *body;
    size_t blen;
    int i;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* If not terminated fail. */
    if (body[blen - 1] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not null terminated\n");
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT16(&port, body, NULL);
    port = ntohs(port);

    /* Move behind the port and padding to get the protocol. */
    body = body + 2 * sizeof(uint16_t) + sizeof(uint32_t);

    /* Calculate protocol name length. */
    for (protocol_len = 0, i = 0; body[i] != '\0'; i++) {
        protocol_len++;
    }

    protocol = protocol_len == 0 ? NULL : (const char *)body;

    if (!sss_utf8_check((const uint8_t *)protocol, protocol_len)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Protocol is not UTF-8 string\n");
        return EINVAL;
    }

    *_port = port;
    *_protocol = protocol;

    return EOK;
}

errno_t
sss_nss_protocol_parse_cert(struct cli_ctx *cli_ctx,
                        const char **_derb64)
{
    struct cli_protocol *pctx;
    const char *derb64;
    size_t pem_size;
    char *pem_cert;
    uint8_t *body;
    size_t blen;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* If not terminated fail. */
    if (body[blen - 1] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not null terminated\n");
        return EINVAL;
    }

    derb64 = (const char *)body;

    DEBUG(SSSDBG_TRACE_ALL, "Input certificate [%s]\n", derb64);

    /* Check input. */
    ret = sss_cert_derb64_to_pem(cli_ctx, derb64, &pem_cert, &pem_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to convert certificate to pem [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    talloc_free(pem_cert);

    *_derb64 = derb64;

    return EOK;
}

errno_t
sss_nss_protocol_parse_sid(struct cli_ctx *cli_ctx,
                       const char **_sid)
{
    struct cli_protocol *pctx;
    struct sss_nss_ctx *nss_ctx;
    const char *sid;
    uint8_t *bin_sid;
    size_t bin_len;
    uint8_t *body;
    size_t blen;
    enum idmap_error_code err;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);
    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct sss_nss_ctx);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* If not terminated fail. */
    if (body[blen - 1] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not null terminated\n");
        return EINVAL;
    }

    sid = (const char *)body;

    /* If the body isn't a SID, fail */
    err = sss_idmap_sid_to_bin_sid(nss_ctx->idmap_ctx, sid, &bin_sid,
                                   &bin_len);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to convert SID to binary [%s].\n", sid);
        return EINVAL;
    }

    sss_idmap_free_bin_sid(nss_ctx->idmap_ctx, bin_sid);

    DEBUG(SSSDBG_TRACE_ALL, "Input SID [%s]\n", sid);

    *_sid = sid;

    return EOK;
}

errno_t
sss_nss_protocol_parse_addr(struct cli_ctx *cli_ctx,
                        uint32_t *_af,
                        uint32_t *_addrlen,
                        uint8_t **_addr)
{
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;
    uint32_t af;
    uint8_t *addr;
    socklen_t addrlen;
    char buf[INET6_ADDRSTRLEN];
    const char *addrstr = NULL;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    if (blen < sizeof(uint32_t) * 2) {
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&af, body, NULL);
    SAFEALIGN_COPY_UINT32(&addrlen, body + sizeof(uint32_t), NULL);

    addr = body + sizeof(uint32_t) * 2;

    /* If the body isn't a addr, fail */
    addrstr = inet_ntop(af, addr, buf, INET6_ADDRSTRLEN);
    if (addrstr == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse address: %s\n", strerror(errno));
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Input address [%s]\n", addrstr);

    *_af = af;
    *_addr = addr;
    *_addrlen = addrlen;

    return EOK;
}
