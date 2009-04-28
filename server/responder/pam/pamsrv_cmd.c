/*
   SSSD

   PAM Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2009
   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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

#include <time.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"
#include "db/sysdb.h"

static int pam_parse_in_data(struct sss_names_ctx *snctx,
                             struct pam_data *pd,
                             uint8_t *body, size_t blen)
{
    int start;
    int end;
    int last;
    int ret;

    last = blen - 1;
    end = 0;

    /* user name */
    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;

    ret = sss_parse_name(pd, snctx, (char *)&body[start], &pd->domain, &pd->user);
    if (ret != EOK) return ret;

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->service = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->tty = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->ruser = (char *) &body[start];

    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;
    pd->rhost = (char *) &body[start];

    start = end;
    pd->authtok_type = (int) body[start];

    start += sizeof(uint32_t);
    pd->authtok_size = (int) body[start];

    start += sizeof(uint32_t);
    end = start + pd->authtok_size;
    if (pd->authtok_size == 0) {
        pd->authtok = NULL;
    } else {
        if (end <= blen) {
            pd->authtok = (uint8_t *) &body[start];
        } else {
            DEBUG(1, ("Invalid authtok size: %d\n", pd->authtok_size));
            return EINVAL;
        }
    }

    start = end;
    pd->newauthtok_type = (int) body[start];

    start += sizeof(uint32_t);
    pd->newauthtok_size = (int) body[start];

    start += sizeof(uint32_t);
    end = start + pd->newauthtok_size;

    if (pd->newauthtok_size == 0) {
        pd->newauthtok = NULL;
    } else {
        if (end <= blen) {
            pd->newauthtok = (uint8_t *) &body[start];
        } else {
            DEBUG(1, ("Invalid newauthtok size: %d\n", pd->newauthtok_size));
            return EINVAL;
        }
    }

    DEBUG_PAM_DATA(4, pd);

    return EOK;
}

static void pam_reply(struct pam_auth_req *preq);
static void pam_reply_delay(struct tevent_context *ev, struct tevent_timer *te,
                            struct timeval tv, void *pvt)
{
    struct pam_auth_req *preq;

    DEBUG(4, ("pam_reply_delay get called.\n"));

    preq = talloc_get_type(pvt, struct pam_auth_req);

    pam_reply(preq);
}

static void pam_reply(struct pam_auth_req *preq)
{
    struct cli_ctx *cctx;
    uint8_t *body;
    size_t blen;
    int ret;
    int err = EOK;
    int32_t resp_c;
    int32_t resp_size;
    struct response_data *resp;
    int p;
    struct timeval tv;
    struct tevent_timer *te;
    struct pam_data *pd;

    pd = preq->pd;

    DEBUG(4, ("pam_reply get called.\n"));

    if ((pd->cmd == SSS_PAM_AUTHENTICATE) &&
        (preq->domain->cache_credentials == true) &&
        (pd->offline_auth == false)) {

        if (pd->pam_status == PAM_SUCCESS) {
            pd->offline_auth = true;
            preq->callback = pam_reply;
            ret = pam_cache_credentials(preq);
            if (ret == EOK) {
                return;
            }
            else {
                DEBUG(0, ("Failed to cache credentials"));
                /* this error is not fatal, continue */
            }
        }

        if (pd->pam_status == PAM_AUTHINFO_UNAVAIL) {
            /* do auth with offline credentials */
            pd->offline_auth = true;
            preq->callback = pam_reply;
            ret = pam_cache_auth(preq);
            if (ret == EOK) {
                return;
            }
            else {
                DEBUG(1, ("Failed to setup offline auth"));
                /* this error is not fatal, continue */
            }
        }
    }

    cctx = preq->cctx;

    if (pd->response_delay > 0) {
        ret = gettimeofday(&tv, NULL);
        if (ret != EOK) {
            DEBUG(1, ("gettimeofday failed [%d][%s].\n",
                      errno, strerror(errno)));
            err = ret;
            goto done;
        }
        tv.tv_sec += pd->response_delay;
        tv.tv_usec = 0;
        pd->response_delay = 0;

        te = tevent_add_timer(cctx->ev, cctx, tv, pam_reply_delay, preq);
        if (te == NULL) {
            DEBUG(1, ("Failed to add event pam_reply_delay.\n"));
            err = ENOMEM;
            goto done;
        }

        return;
    }

    ret = sss_packet_new(cctx->creq, 0, sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        err = ret;
        goto done;
    }

    if (pd->domain != NULL) {
        pam_add_response(pd, PAM_DOMAIN_NAME, strlen(pd->domain)+1,
                         (uint8_t *) pd->domain);
    }

    resp_c = 0;
    resp_size = 0;
    resp = pd->resp_list;
    while(resp != NULL) {
        resp_c++;
        resp_size += resp->len;
        resp = resp->next;
    }

    ret = sss_packet_grow(cctx->creq->out, sizeof(int32_t) +
                                           sizeof(int32_t) +
                                           resp_c * 2* sizeof(int32_t) +
                                           resp_size);
    if (ret != EOK) {
        err = ret;
        goto done;
    }

    sss_packet_get_body(cctx->creq->out, &body, &blen);
    DEBUG(4, ("blen: %d\n", blen));
    p = 0;

    memcpy(&body[p], &pd->pam_status, sizeof(int32_t));
    p += sizeof(int32_t);

    memcpy(&body[p], &resp_c, sizeof(int32_t));
    p += sizeof(int32_t);

    resp = pd->resp_list;
    while(resp != NULL) {
        memcpy(&body[p], &resp->type, sizeof(int32_t));
        p += sizeof(int32_t);
        memcpy(&body[p], &resp->len, sizeof(int32_t));
        p += sizeof(int32_t);
        memcpy(&body[p], resp->data, resp->len);
        p += resp->len;

        resp = resp->next;
    }

done:
    sss_cmd_done(cctx, preq);
}

static void pam_check_user_dp_callback(uint16_t err_maj, uint32_t err_min,
                                       const char *err_msg, void *ptr);
static void pam_check_user_callback(void *ptr, int status,
                                    struct ldb_result *res);
static void pam_dom_forwarder(struct pam_auth_req *preq);

/* TODO: we should probably return some sort of cookie that is set in the
 * PAM_ENVIRONMENT, so that we can save performing some calls and cache
 * data. */

static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd)
{
    struct sss_domain_info *dom;
    struct pam_auth_req *preq;
    struct pam_data *pd;
    uint8_t *body;
    size_t blen;
    int timeout;
    int ret;

    preq = talloc_zero(cctx, struct pam_auth_req);
    if (!preq) {
        return ENOMEM;
    }
    preq->cctx = cctx;

    preq->pd = talloc_zero(preq, struct pam_data);
    if (!preq->pd) {
        talloc_free(preq);
        return ENOMEM;
    }
    pd = preq->pd;

    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen >= sizeof(uint32_t) &&
        ((uint32_t *)(&body[blen - sizeof(uint32_t)]))[0] != END_OF_PAM_REQUEST) {
        DEBUG(1, ("Received data not terminated.\n"));
        talloc_free(preq);
        ret = EINVAL;
        goto done;
    }

    pd->cmd = pam_cmd;
    pd->priv = cctx->priv;
    ret = pam_parse_in_data(cctx->rctx->names, pd, body, blen);
    if (ret != EOK) {
        talloc_free(preq);
        ret = EINVAL;
        goto done;
    }

    /* now check user is valid */
    if (pd->domain) {
        for (dom = cctx->rctx->domains; dom; dom = dom->next) {
            if (strcasecmp(dom->name, pd->domain) == 0) break;
        }
        if (!dom) {
            talloc_free(preq);
            ret = ENOENT;
            goto done;
        }
        preq->domain = dom;
    }
    else {
        for (dom = preq->cctx->rctx->domains; dom; dom = dom->next) {
            if (dom->fqnames) continue;

/* FIXME: need to support negative cache */
#if HAVE_NEG_CACHE
            ncret = sss_ncache_check_user(nctx->ncache, nctx->neg_timeout,
                                          dom->name, cmdctx->name);
            if (ncret == ENOENT) break;
#endif
            break;
        }
        if (!dom) {
            ret = ENOENT;
            goto done;
        }
        preq->domain = dom;
    }

    /* When auth is requested always search the provider first,
     * do not rely on cached data unless the provider is completely
     * offline */
    if (preq->domain->provider &&
        (pam_cmd == SSS_PAM_AUTHENTICATE || pam_cmd == SSS_PAM_SETCRED)) {

        /* no need to re-check later on */
        preq->check_provider = false;
        timeout = SSS_CLI_SOCKET_TIMEOUT/2;

        ret = nss_dp_send_acct_req(preq->cctx->rctx, preq,
                                   pam_check_user_dp_callback, preq,
                                   timeout, preq->domain->name, NSS_DP_USER,
                                   preq->pd->user, 0);
    }
    else {
        preq->check_provider = (preq->domain->provider != NULL);

        ret = sysdb_getpwnam(preq, cctx->rctx->sysdb,
                             preq->domain, preq->pd->user,
                             pam_check_user_callback, preq);
    }

done:
    if (ret != EOK) {
        switch (ret) {
        case ENOENT:
            pd->pam_status = PAM_USER_UNKNOWN;
        default:
            pd->pam_status = PAM_SYSTEM_ERR;
        }
        pam_reply(preq);
    }
    return EOK;
}

static void pam_check_user_dp_callback(uint16_t err_maj, uint32_t err_min,
                                       const char *err_msg, void *ptr)
{
    struct pam_auth_req *preq = talloc_get_type(ptr, struct pam_auth_req);
    struct ldb_result *res = NULL;
    int ret;

    if ((err_maj != DP_ERR_OK) && (err_maj != DP_ERR_OFFLINE)) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
        ret = EFAULT;
        goto done;
    }

    if (err_maj == DP_ERR_OFFLINE) {
         if (preq->data) res = talloc_get_type(preq->data, struct ldb_result);
         if (!res) res = talloc_zero(preq, struct ldb_result);
         if (!res) {
            ret = EFAULT;
            goto done;
        }

        pam_check_user_callback(preq, LDB_SUCCESS, res);
        return;
    }

    ret = sysdb_getpwnam(preq, preq->cctx->rctx->sysdb,
                         preq->domain, preq->pd->user,
                         pam_check_user_callback, preq);

done:
    if (ret != EOK) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
    }
}

static void pam_check_user_callback(void *ptr, int status,
                                    struct ldb_result *res)
{
    struct pam_auth_req *preq = talloc_get_type(ptr, struct pam_auth_req);
    struct sss_domain_info *dom;
    uint64_t lastUpdate;
    bool call_provider = false;
    int timeout;
    int ret;

    if (status != LDB_SUCCESS) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
        return;
    }

    timeout = SSS_CLI_SOCKET_TIMEOUT/2;

    if (preq->check_provider) {
        switch (res->count) {
        case 0:
            call_provider = true;
            break;

        case 1:
            timeout = 30; /* FIXME: read from conf */

            lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                     SYSDB_LAST_UPDATE, 0);
            if (lastUpdate + timeout < time(NULL)) {
                call_provider = true;
            }
            break;

        default:
            DEBUG(1, ("check user call returned more than one result !?!\n"));
            preq->pd->pam_status = PAM_SYSTEM_ERR;
            pam_reply(preq);
            return;
        }
    }

    if (call_provider) {

        /* dont loop forever :-) */
        preq->check_provider = false;

        /* keep around current data in case backend is offline */
        if (res->count) {
            preq->data = talloc_steal(preq, res);
        }

        ret = nss_dp_send_acct_req(preq->cctx->rctx, preq,
                                   pam_check_user_dp_callback, preq,
                                   timeout, preq->domain->name, NSS_DP_USER,
                                   preq->pd->user, 0);
        if (ret != EOK) {
            DEBUG(3, ("Failed to dispatch request: %d(%s)\n",
                      ret, strerror(ret)));
            preq->pd->pam_status = PAM_SYSTEM_ERR;
            pam_reply(preq);
        }
        return;
    }

    switch (res->count) {
    case 0:
        if (!preq->pd->domain) {
            /* search next as the domain was unknown */

            ret = EOK;

            /* skip domains that require FQnames or have negative caches */
            for (dom = preq->domain->next; dom; dom = dom->next) {

                if (dom->fqnames) continue;

#if HAVE_NEG_CACHE
                ncret = nss_ncache_check_user(nctx->ncache,
                                              nctx->neg_timeout,
                                              dom->name, cmdctx->name);
                if (ncret == ENOENT) break;

                neghit = true;
#endif
                break;
            }
#if HAVE_NEG_CACHE
            /* reset neghit if we still have a domain to check */
            if (dom) neghit = false;

           if (neghit) {
                DEBUG(2, ("User [%s] does not exist! (negative cache)\n",
                          cmdctx->name));
                ret = ENOENT;
            }
#endif
            if (dom == NULL) {
                DEBUG(2, ("No matching domain found for [%s], fail!\n",
                          preq->pd->user));
                ret = ENOENT;
            }

            if (ret == EOK) {
                preq->domain = dom;
                preq->data = NULL;

                DEBUG(4, ("Requesting info for [%s@%s]\n",
                          preq->pd->user, preq->domain->name));

                /* When auth is requested always search the provider first,
                 * do not rely on cached data unless the provider is
                 * completely offline */
                if (preq->domain->provider &&
                    (preq->pd->cmd == SSS_PAM_AUTHENTICATE ||
                     preq->pd->cmd == SSS_PAM_SETCRED)) {

                    /* no need to re-check later on */
                    preq->check_provider = false;

                    ret = nss_dp_send_acct_req(preq->cctx->rctx, preq,
                                               pam_check_user_dp_callback,
                                               preq, timeout,
                                               preq->domain->name,
                                               NSS_DP_USER,
                                               preq->pd->user, 0);
                }
                else {
                    preq->check_provider = (preq->domain->provider != NULL);

                    ret = sysdb_getpwnam(preq, preq->cctx->rctx->sysdb,
                                         preq->domain, preq->pd->user,
                                         pam_check_user_callback, preq);
                }
                if (ret != EOK) {
                    DEBUG(1, ("Failed to make request to our cache!\n"));
                }
            }

            /* we made another call, end here */
            if (ret == EOK) return;
        }
        else {
            ret = ENOENT;
        }

        DEBUG(2, ("No results for check user call\n"));

#if HAVE_NEG_CACHE
        /* set negative cache only if not result of cache check */
        if (!neghit) {
            ret = nss_ncache_set_user(nctx->ncache, false,
                                      dctx->domain->name, cmdctx->name);
            if (ret != EOK) {
                NSS_CMD_FATAL_ERROR(cctx);
            }
        }
#endif

        if (ret != EOK) {
            if (ret == ENOENT) {
                preq->pd->pam_status = PAM_USER_UNKNOWN;
            } else {
                preq->pd->pam_status = PAM_SYSTEM_ERR;
            }
            pam_reply(preq);
            return;
        }
        break;

    case 1:

        /* BINGO */
        pam_dom_forwarder(preq);
        return;

    default:
        DEBUG(1, ("check user call returned more than one result !?!\n"));
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
    }
}

static void pam_dom_forwarder(struct pam_auth_req *preq)
{
    int ret;

    if (!preq->pd->domain) {
        preq->pd->domain = preq->domain->name;
    }

    if (!preq->domain->provider) {
        preq->callback = pam_reply;
        ret = LOCAL_pam_handler(preq);
    }
    else {
        preq->callback = pam_reply;
        ret = pam_dp_send_req(preq, SSS_CLI_SOCKET_TIMEOUT/2);
        DEBUG(4, ("pam_dp_send_req returned %d\n", ret));
    }

    if (ret != EOK) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
    }
}

static int pam_cmd_authenticate(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_authenticate\n"));
    return pam_forwarder(cctx, SSS_PAM_AUTHENTICATE);
}

static int pam_cmd_setcred(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_setcred\n"));
    return pam_forwarder(cctx, SSS_PAM_SETCRED);
}

static int pam_cmd_acct_mgmt(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_acct_mgmt\n"));
    return pam_forwarder(cctx, SSS_PAM_ACCT_MGMT);
}

static int pam_cmd_open_session(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_open_session\n"));
    return pam_forwarder(cctx, SSS_PAM_OPEN_SESSION);
}

static int pam_cmd_close_session(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_close_session\n"));
    return pam_forwarder(cctx, SSS_PAM_CLOSE_SESSION);
}

static int pam_cmd_chauthtok(struct cli_ctx *cctx) {
    DEBUG(4, ("entering pam_cmd_chauthtok\n"));
    return pam_forwarder(cctx, SSS_PAM_CHAUTHTOK);
}

struct sss_cmd_table *register_sss_cmds(void) {
    static struct sss_cmd_table sss_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_PAM_AUTHENTICATE, pam_cmd_authenticate},
        {SSS_PAM_SETCRED, pam_cmd_setcred},
        {SSS_PAM_ACCT_MGMT, pam_cmd_acct_mgmt},
        {SSS_PAM_OPEN_SESSION, pam_cmd_open_session},
        {SSS_PAM_CLOSE_SESSION, pam_cmd_close_session},
        {SSS_PAM_CHAUTHTOK, pam_cmd_chauthtok},
        {SSS_CLI_NULL, NULL}
    };

    return sss_cmds;
}
