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
#include "util/auth_utils.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pam_helpers.h"
#include "db/sysdb.h"

enum pam_verbosity {
    PAM_VERBOSITY_NO_MESSAGES = 0,
    PAM_VERBOSITY_IMPORTANT,
    PAM_VERBOSITY_INFO,
    PAM_VERBOSITY_DEBUG
};

#define DEFAULT_PAM_VERBOSITY PAM_VERBOSITY_IMPORTANT

static void pam_reply(struct pam_auth_req *preq);

static int extract_authtok_v2(struct sss_auth_token *tok,
                              size_t data_size, uint8_t *body, size_t blen,
                              size_t *c)
{
    uint32_t auth_token_type;
    uint32_t auth_token_length;
    uint8_t *auth_token_data;
    int ret = EOK;

    if (data_size < sizeof(uint32_t) || *c+data_size > blen ||
        SIZE_T_OVERFLOW(*c, data_size)) return EINVAL;

    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_type, &body[*c], blen, c);
    auth_token_length = data_size - sizeof(uint32_t);
    auth_token_data = body+(*c);

    switch (auth_token_type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        sss_authtok_set_empty(tok);
        break;
    case SSS_AUTHTOK_TYPE_PASSWORD:
        if (auth_token_length == 0) {
            sss_authtok_set_empty(tok);
        } else {
            ret = sss_authtok_set_password(tok, (const char *)auth_token_data,
                                           auth_token_length);
        }
        break;
    default:
        return EINVAL;
    }

    *c += auth_token_length;

    return ret;
}

static int extract_string(char **var, size_t size, uint8_t *body, size_t blen,
                          size_t *c) {
    uint8_t *str;

    if (*c+size > blen || SIZE_T_OVERFLOW(*c, size)) return EINVAL;

    str = body+(*c);

    if (str[size-1]!='\0') return EINVAL;

    /* If the string isn't valid UTF-8, fail */
    if (!sss_utf8_check(str, size-1)) {
        return EINVAL;
    }

    *c += size;

    *var = (char *) str;

    return EOK;
}

static int extract_uint32_t(uint32_t *var, size_t size, uint8_t *body,
                            size_t blen, size_t *c) {

    if (size != sizeof(uint32_t) || *c+size > blen || SIZE_T_OVERFLOW(*c, size))
        return EINVAL;

    SAFEALIGN_COPY_UINT32_CHECK(var, &body[*c], blen, c);

    return EOK;
}

static int pd_set_primary_name(const struct ldb_message *msg,struct pam_data *pd)
{
    const char *name;

    name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    if (!name) {
        DEBUG(SSSDBG_CRIT_FAILURE, "A user with no name?\n");
        return EIO;
    }

    if (strcmp(pd->user, name)) {
        DEBUG(SSSDBG_TRACE_FUNC, "User's primary name is %s\n", name);
        talloc_free(pd->user);
        pd->user = talloc_strdup(pd, name);
        if (!pd->user) return ENOMEM;
    }

    return EOK;
}

static int pam_parse_in_data_v2(struct sss_domain_info *domains,
                                const char *default_domain,
                                struct pam_data *pd,
                                uint8_t *body, size_t blen)
{
    size_t c;
    uint32_t type;
    uint32_t size;
    char *pam_user;
    int ret;
    uint32_t start;
    uint32_t terminator;

    if (blen < 4*sizeof(uint32_t)+2) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Received data is invalid.\n");
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&start, body, NULL);
    SAFEALIGN_COPY_UINT32(&terminator, body + blen - sizeof(uint32_t), NULL);

    if (start != SSS_START_OF_PAM_REQUEST
        || terminator != SSS_END_OF_PAM_REQUEST) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Received data is invalid.\n");
        return EINVAL;
    }

    c = sizeof(uint32_t);
    do {
        SAFEALIGN_COPY_UINT32_CHECK(&type, &body[c], blen, &c);

        if (type == SSS_END_OF_PAM_REQUEST) {
            if (c != blen) return EINVAL;
        } else {
            SAFEALIGN_COPY_UINT32_CHECK(&size, &body[c], blen, &c);
            /* the uint32_t end maker SSS_END_OF_PAM_REQUEST does not count to
             * the remaining buffer */
            if (size > (blen - c - sizeof(uint32_t))) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Invalid data size.\n");
                return EINVAL;
            }

            switch(type) {
                case SSS_PAM_ITEM_USER:
                    ret = extract_string(&pam_user, size, body, blen, &c);
                    if (ret != EOK) return ret;

                    ret = sss_parse_name_for_domains(pd, domains,
                                                     default_domain, pam_user,
                                                     &pd->domain, &pd->user);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_SERVICE:
                    ret = extract_string(&pd->service, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_TTY:
                    ret = extract_string(&pd->tty, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_RUSER:
                    ret = extract_string(&pd->ruser, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_RHOST:
                    ret = extract_string(&pd->rhost, size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_CLI_PID:
                    ret = extract_uint32_t(&pd->cli_pid, size,
                                           body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_AUTHTOK:
                    ret = extract_authtok_v2(pd->authtok,
                                             size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_NEWAUTHTOK:
                    ret = extract_authtok_v2(pd->newauthtok,
                                             size, body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                default:
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Ignoring unknown data type [%d].\n", type);
                    c += size;
            }
        }

    } while(c < blen);

    if (pd->user == NULL || *pd->user == '\0') return EINVAL;

    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    return EOK;

}

static int pam_parse_in_data_v3(struct sss_domain_info *domains,
                                const char *default_domain,
                                struct pam_data *pd,
                                uint8_t *body, size_t blen)
{
    int ret;

    ret = pam_parse_in_data_v2(domains, default_domain, pd, body, blen);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_parse_in_data_v2 failed.\n");
        return ret;
    }

    if (pd->cli_pid == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing client PID.\n");
        return EINVAL;
    }

    return EOK;
}

static int extract_authtok_v1(struct sss_auth_token *tok,
                              uint8_t *body, size_t blen, size_t *c)
{
    uint32_t auth_token_type;
    uint32_t auth_token_length;
    uint8_t *auth_token_data;
    int ret = EOK;

    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_type, &body[*c], blen, c);
    SAFEALIGN_COPY_UINT32_CHECK(&auth_token_length, &body[*c], blen, c);
    auth_token_data = body+(*c);

    switch (auth_token_type) {
    case SSS_AUTHTOK_TYPE_EMPTY:
        sss_authtok_set_empty(tok);
        break;
    case SSS_AUTHTOK_TYPE_PASSWORD:
        ret = sss_authtok_set_password(tok, (const char *)auth_token_data,
                                       auth_token_length);
        break;
    default:
        return EINVAL;
    }

    *c += auth_token_length;

    return ret;
}

static int pam_parse_in_data(struct sss_domain_info *domains,
                             const char *default_domain,
                             struct pam_data *pd,
                             uint8_t *body, size_t blen)
{
    size_t start;
    size_t end;
    size_t last;
    int ret;

    last = blen - 1;
    end = 0;

    /* user name */
    for (start = end; end < last; end++) if (body[end] == '\0') break;
    if (body[end++] != '\0') return EINVAL;

    ret = sss_parse_name_for_domains(pd, domains, default_domain,
                                     (char *)&body[start], &pd->domain, &pd->user);
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

    ret = extract_authtok_v1(pd->authtok, body, blen, &end);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid auth token\n");
        return ret;
    }
    ret = extract_authtok_v1(pd->newauthtok, body, blen, &end);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid new auth token\n");
        return ret;
    }

    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    return EOK;
}

/*=Save-Last-Login-State===================================================*/

static errno_t set_last_login(struct pam_auth_req *preq)
{
    struct sysdb_attrs *attrs;
    errno_t ret;

    attrs = sysdb_new_attrs(preq);
    if (!attrs) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_ONLINE_AUTH, time(NULL));
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_LOGIN, time(NULL));
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_set_user_attr(preq->domain, preq->pd->user, attrs,
                              SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "set_last_login failed.\n");
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        goto fail;
    } else {
        preq->pd->last_auth_saved = true;
    }
    preq->callback(preq);

    return EOK;

fail:
    return ret;
}

static errno_t filter_responses(struct confdb_ctx *cdb,
                                struct response_data *resp_list)
{
    int ret;
    struct response_data *resp;
    uint32_t user_info_type;
    int64_t expire_date;
    int pam_verbosity;

    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_VERBOSITY, DEFAULT_PAM_VERBOSITY,
                         &pam_verbosity);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read PAM verbosity, not fatal.\n");
        pam_verbosity = DEFAULT_PAM_VERBOSITY;
    }

    resp = resp_list;
    while(resp != NULL) {
        if (resp->type == SSS_PAM_USER_INFO) {
            if (resp->len < sizeof(uint32_t)) {
                DEBUG(SSSDBG_CRIT_FAILURE, "User info entry is too short.\n");
                return EINVAL;
            }

            if (pam_verbosity == PAM_VERBOSITY_NO_MESSAGES) {
                resp->do_not_send_to_client = true;
                resp = resp->next;
                continue;
            }

            memcpy(&user_info_type, resp->data, sizeof(uint32_t));

            resp->do_not_send_to_client = false;
            switch (user_info_type) {
                case SSS_PAM_USER_INFO_OFFLINE_AUTH:
                    if (resp->len != sizeof(uint32_t) + sizeof(int64_t)) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "User info offline auth entry is "
                                  "too short.\n");
                        return EINVAL;
                    }
                    memcpy(&expire_date, resp->data + sizeof(uint32_t),
                           sizeof(int64_t));
                    if ((expire_date == 0 &&
                         pam_verbosity < PAM_VERBOSITY_INFO) ||
                        (expire_date > 0 &&
                         pam_verbosity < PAM_VERBOSITY_IMPORTANT)) {
                        resp->do_not_send_to_client = true;
                    }

                    break;
                default:
                    DEBUG(SSSDBG_TRACE_LIBS,
                          "User info type [%d] not filtered.\n",
                           user_info_type);
            }
        } else if (resp->type & SSS_SERVER_INFO) {
            resp->do_not_send_to_client = true;
        }

        resp = resp->next;
    }

    return EOK;
}

static void pam_reply_delay(struct tevent_context *ev, struct tevent_timer *te,
                            struct timeval tv, void *pvt)
{
    struct pam_auth_req *preq;

    DEBUG(SSSDBG_CONF_SETTINGS, "pam_reply_delay get called.\n");

    preq = talloc_get_type(pvt, struct pam_auth_req);

    pam_reply(preq);
}

static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd);
static void pam_handle_cached_login(struct pam_auth_req *preq, int ret,
                                    time_t expire_date, time_t delayed_until);

static void pam_reply(struct pam_auth_req *preq)
{
    struct cli_ctx *cctx;
    uint8_t *body;
    size_t blen;
    int ret;
    int32_t resp_c;
    int32_t resp_size;
    struct response_data *resp;
    int p;
    struct timeval tv;
    struct tevent_timer *te;
    struct pam_data *pd;
    struct pam_ctx *pctx;
    uint32_t user_info_type;
    time_t exp_date = -1;
    time_t delay_until = -1;

    pd = preq->pd;
    cctx = preq->cctx;
    pctx = talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);


    DEBUG(SSSDBG_FUNC_DATA,
          "pam_reply called with result [%d].\n", pd->pam_status);

    if (pd->pam_status == PAM_AUTHINFO_UNAVAIL) {
        switch(pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            if ((preq->domain != NULL) &&
                (preq->domain->cache_credentials == true) &&
                (pd->offline_auth == false)) {
                const char *password = NULL;

                /* do auth with offline credentials */
                pd->offline_auth = true;

                if (preq->domain->sysdb == NULL) {
                    DEBUG(SSSDBG_FATAL_FAILURE,
                          "Fatal: Sysdb CTX not found for domain"
                              " [%s]!\n", preq->domain->name);
                    goto done;
                }

                ret = sss_authtok_get_password(pd->authtok, &password, NULL);
                if (ret) {
                    DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get password.\n");
                    goto done;
                }

                ret = sysdb_cache_auth(preq->domain,
                                       pd->user, password,
                                       pctx->rctx->cdb, false,
                                       &exp_date, &delay_until);

                pam_handle_cached_login(preq, ret, exp_date, delay_until);
                return;
            }
            break;
        case SSS_PAM_CHAUTHTOK_PRELIM:
        case SSS_PAM_CHAUTHTOK:
            DEBUG(SSSDBG_FUNC_DATA,
                  "Password change not possible while offline.\n");
            pd->pam_status = PAM_AUTHTOK_ERR;
            user_info_type = SSS_PAM_USER_INFO_OFFLINE_CHPASS;
            ret = pam_add_response(pd, SSS_PAM_USER_INFO, sizeof(uint32_t),
                                   (const uint8_t *) &user_info_type);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                goto done;
            }
            break;
/* TODO: we need the pam session cookie here to make sure that cached
 * authentication was successful */
        case SSS_PAM_SETCRED:
        case SSS_PAM_ACCT_MGMT:
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_CLOSE_SESSION:
            DEBUG(SSSDBG_OP_FAILURE,
                  "Assuming offline authentication setting status for "
                      "pam call %d to PAM_SUCCESS.\n", pd->cmd);
            pd->pam_status = PAM_SUCCESS;
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknown PAM call [%d].\n", pd->cmd);
            pd->pam_status = PAM_MODULE_UNKNOWN;
        }
    }

    if (pd->response_delay > 0) {
        ret = gettimeofday(&tv, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "gettimeofday failed [%d][%s].\n",
                      errno, strerror(errno));
            goto done;
        }
        tv.tv_sec += pd->response_delay;
        tv.tv_usec = 0;
        pd->response_delay = 0;

        te = tevent_add_timer(cctx->ev, cctx, tv, pam_reply_delay, preq);
        if (te == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add event pam_reply_delay.\n");
            goto done;
        }

        return;
    }

    /* If this was a successful login, save the lastLogin time */
    if (pd->cmd == SSS_PAM_AUTHENTICATE &&
        pd->pam_status == PAM_SUCCESS &&
        preq->domain->cache_credentials &&
        !pd->offline_auth &&
        !pd->last_auth_saved &&
        NEED_CHECK_PROVIDER(preq->domain->provider)) {
        ret = set_last_login(preq);
        if (ret != EOK) {
            goto done;
        }
        return;
    }

    ret = sss_packet_new(cctx->creq, 0, sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        goto done;
    }

    ret = filter_responses(pctx->rctx->cdb, pd->resp_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "filter_responses failed, not fatal.\n");
    }

    if (pd->domain != NULL) {
        ret = pam_add_response(pd, SSS_PAM_DOMAIN_NAME, strlen(pd->domain)+1,
                               (uint8_t *) pd->domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            goto done;
        }
    }

    resp_c = 0;
    resp_size = 0;
    resp = pd->resp_list;
    while(resp != NULL) {
        if (!resp->do_not_send_to_client) {
            resp_c++;
            resp_size += resp->len;
        }
        resp = resp->next;
    }

    ret = sss_packet_grow(cctx->creq->out, sizeof(int32_t) +
                                           sizeof(int32_t) +
                                           resp_c * 2* sizeof(int32_t) +
                                           resp_size);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_get_body(cctx->creq->out, &body, &blen);
    DEBUG(SSSDBG_FUNC_DATA, "blen: %zu\n", blen);
    p = 0;

    memcpy(&body[p], &pd->pam_status, sizeof(int32_t));
    p += sizeof(int32_t);

    memcpy(&body[p], &resp_c, sizeof(int32_t));
    p += sizeof(int32_t);

    resp = pd->resp_list;
    while(resp != NULL) {
        if (!resp->do_not_send_to_client) {
            memcpy(&body[p], &resp->type, sizeof(int32_t));
            p += sizeof(int32_t);
            memcpy(&body[p], &resp->len, sizeof(int32_t));
            p += sizeof(int32_t);
            memcpy(&body[p], resp->data, resp->len);
            p += resp->len;
        }

        resp = resp->next;
    }

done:
    sss_cmd_done(cctx, preq);
}

static void pam_handle_cached_login(struct pam_auth_req *preq, int ret,
                                    time_t expire_date, time_t delayed_until)
{
    uint32_t resp_type;
    size_t resp_len;
    uint8_t *resp;
    int64_t dummy;

    preq->pd->pam_status = cached_login_pam_status(ret);

    switch (preq->pd->pam_status) {
        case PAM_SUCCESS:
            resp_type = SSS_PAM_USER_INFO_OFFLINE_AUTH;
            resp_len = sizeof(uint32_t) + sizeof(int64_t);
            resp = talloc_size(preq->pd, resp_len);
            if (resp == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "talloc_size failed, cannot prepare user info.\n");
            } else {
                memcpy(resp, &resp_type, sizeof(uint32_t));
                dummy = (int64_t) expire_date;
                memcpy(resp+sizeof(uint32_t), &dummy, sizeof(int64_t));
                ret = pam_add_response(preq->pd, SSS_PAM_USER_INFO, resp_len,
                                       (const uint8_t *) resp);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                }
            }
            break;
        case PAM_PERM_DENIED:
            if (delayed_until >= 0) {
                resp_type = SSS_PAM_USER_INFO_OFFLINE_AUTH_DELAYED;
                resp_len = sizeof(uint32_t) + sizeof(int64_t);
                resp = talloc_size(preq->pd, resp_len);
                if (resp == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "talloc_size failed, cannot prepare user info.\n");
                } else {
                    memcpy(resp, &resp_type, sizeof(uint32_t));
                    dummy = (int64_t) delayed_until;
                    memcpy(resp+sizeof(uint32_t), &dummy, sizeof(int64_t));
                    ret = pam_add_response(preq->pd, SSS_PAM_USER_INFO, resp_len,
                                           (const uint8_t *) resp);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "pam_add_response failed.\n");
                    }
                }
            }
            break;
        default:
            DEBUG(SSSDBG_TRACE_LIBS,
                  "cached login returned: %d\n", preq->pd->pam_status);
    }

    pam_reply(preq);
    return;
}

static void pam_forwarder_cb(struct tevent_req *req);
static void pam_check_user_dp_callback(uint16_t err_maj, uint32_t err_min,
                                       const char *err_msg, void *ptr);
static int pam_check_user_search(struct pam_auth_req *preq);
static int pam_check_user_done(struct pam_auth_req *preq, int ret);
static void pam_dom_forwarder(struct pam_auth_req *preq);

/* TODO: we should probably return some sort of cookie that is set in the
 * PAM_ENVIRONMENT, so that we can save performing some calls and cache
 * data. */

errno_t pam_forwarder_parse_data(struct cli_ctx *cctx, struct pam_data *pd)
{
    uint8_t *body;
    size_t blen;
    errno_t ret;
    uint32_t terminator;

    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen >= sizeof(uint32_t)) {
        SAFEALIGN_COPY_UINT32(&terminator,
                              body + blen - sizeof(uint32_t),
                              NULL);
        if (terminator != SSS_END_OF_PAM_REQUEST) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Received data not terminated.\n");
            ret = EINVAL;
            goto done;
        }
    }

    switch (cctx->cli_protocol_version->version) {
        case 1:
            ret = pam_parse_in_data(cctx->rctx->domains,
                                    cctx->rctx->default_domain, pd,
                                    body, blen);
            break;
        case 2:
            ret = pam_parse_in_data_v2(cctx->rctx->domains,
                                       cctx->rctx->default_domain, pd,
                                       body, blen);
            break;
        case 3:
            ret = pam_parse_in_data_v3(cctx->rctx->domains,
                                       cctx->rctx->default_domain, pd,
                                       body, blen);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Illegal protocol version [%d].\n",
                      cctx->cli_protocol_version->version);
            ret = EINVAL;
    }

done:
    return ret;
}

static int pam_auth_req_destructor(struct pam_auth_req *preq)
{
    if (preq && preq->dpreq_spy) {
        /* If there is still a request pending, tell the spy
         * the client is going away
         */
        preq->dpreq_spy->preq = NULL;
    }
    return 0;
}

static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd)
{
    struct sss_domain_info *dom;
    struct pam_auth_req *preq;
    struct pam_data *pd;
    int ret;
    errno_t ncret;
    struct pam_ctx *pctx =
            talloc_get_type(cctx->rctx->pvt_ctx, struct pam_ctx);
    struct tevent_req *req;

    preq = talloc_zero(cctx, struct pam_auth_req);
    if (!preq) {
        return ENOMEM;
    }
    talloc_set_destructor(preq, pam_auth_req_destructor);
    preq->cctx = cctx;

    preq->pd = create_pam_data(preq);
    if (!preq->pd) {
        talloc_free(preq);
        return ENOMEM;
    }
    pd = preq->pd;

    pd->cmd = pam_cmd;
    pd->priv = cctx->priv;

    ret = pam_forwarder_parse_data(cctx, pd);
    if (ret == EAGAIN) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true, pd->domain);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(req, pam_forwarder_cb, preq);
            ret = EAGAIN;
        }
        goto done;
    } else if (ret != EOK) {
        ret = EINVAL;
        goto done;
    }

    /* now check user is valid */
    if (pd->domain) {
        preq->domain = responder_get_domain(cctx->rctx, pd->domain);
        if (!preq->domain) {
            ret = ENOENT;
            goto done;
        }

        ncret = sss_ncache_check_user(pctx->ncache, pctx->neg_timeout,
                                      preq->domain, pd->user);
        if (ncret == EEXIST) {
            /* User found in the negative cache */
            ret = ENOENT;
            goto done;
        }
    } else {
        for (dom = preq->cctx->rctx->domains;
             dom;
             dom = get_next_domain(dom, false)) {
            if (dom->fqnames) continue;

            ncret = sss_ncache_check_user(pctx->ncache, pctx->neg_timeout,
                                          dom, pd->user);
            if (ncret == ENOENT) {
                /* User not found in the negative cache
                 * Proceed with PAM actions
                 */
                break;
            }

            /* Try the next domain */
            DEBUG(SSSDBG_TRACE_FUNC,
                  "User [%s@%s] filtered out (negative cache). "
                   "Trying next domain.\n", pd->user, dom->name);
        }
        if (!dom) {
            ret = ENOENT;
            goto done;
        }
        preq->domain = dom;
    }

    if (preq->domain->provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Domain [%s] has no auth provider.\n", preq->domain->name);
        ret = EINVAL;
        goto done;
    }

    preq->check_provider = NEED_CHECK_PROVIDER(preq->domain->provider);

    ret = pam_check_user_search(preq);
    if (ret == EOK) {
        pam_dom_forwarder(preq);
    }

done:
    return pam_check_user_done(preq, ret);
}

static void pam_forwarder_cb(struct tevent_req *req)
{
    struct pam_auth_req *preq = tevent_req_callback_data(req,
                                                         struct pam_auth_req);
    struct cli_ctx *cctx = preq->cctx;
    struct pam_data *pd;
    errno_t ret = EOK;

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        goto done;
    }

    pd = preq->pd;

    ret = pam_forwarder_parse_data(cctx, pd);
    if (ret != EOK) {
        ret = EINVAL;
        goto done;
    }

    if (preq->pd->domain) {
        preq->domain = responder_get_domain(cctx->rctx, preq->pd->domain);
        if (preq->domain == NULL) {
            ret = ENOENT;
            goto done;
        }
    }

    ret = pam_check_user_search(preq);
    if (ret == EOK) {
        pam_dom_forwarder(preq);
    }

done:
    pam_check_user_done(preq, ret);
}

static void pam_dp_send_acct_req_done(struct tevent_req *req);

static int pam_check_user_search(struct pam_auth_req *preq)
{
    struct sss_domain_info *dom = preq->domain;
    char *name = NULL;
    time_t cacheExpire;
    int ret;
    struct tevent_req *dpreq;
    struct dp_callback_ctx *cb_ctx;
    struct pam_ctx *pctx =
            talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && !preq->pd->domain && dom->fqnames) {
            dom = get_next_domain(dom, false);
        }

        if (!dom) break;

        if (dom != preq->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            preq->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the preq if we changed domain */
        preq->domain = dom;

        talloc_free(name);
        name = sss_get_cased_name(preq, preq->pd->user,
                                  dom->case_sensitive);
        if (!name) {
            return ENOMEM;
        }

        /* Refresh the user's cache entry on any PAM query
         * We put a timeout in the client context so that we limit
         * the number of updates within a reasonable timeout
         */
        if (preq->check_provider) {
            ret = pam_initgr_check_timeout(pctx->id_table, name);
            if (ret != EOK
                    && ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Could not look up initgroup timout\n");
                return EIO;
            } else if (ret == ENOENT) {
                /* Call provider first */
                break;
            }
            /* Entry is still valid, get it from the sysdb */
        }

        DEBUG(SSSDBG_CONF_SETTINGS,
              "Requesting info for [%s@%s]\n", name, dom->name);

        if (dom->sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            preq->pd->pam_status = PAM_SYSTEM_ERR;
            return EFAULT;
        }

        ret = sysdb_getpwnam(preq, dom, name, &preq->res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to make request to our cache!\n");
            return EIO;
        }

        if (preq->res->count > 1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "getpwnam call returned more than one result !?!\n");
            return ENOENT;
        }

        if (preq->res->count == 0) {
            if (preq->check_provider == false) {
                /* set negative cache only if not result of cache check */
                ret = sss_ncache_set_user(pctx->ncache, false, dom, name);
                if (ret != EOK) {
                    /* Should not be fatal, just slower next time */
                    DEBUG(SSSDBG_MINOR_FAILURE,
                           "Cannot set ncache for [%s@%s]\n", name,
                            dom->name);
                }
            }

            /* if a multidomain search, try with next */
            if (!preq->pd->domain) {
                dom = get_next_domain(dom, false);
                continue;
            }

            DEBUG(SSSDBG_OP_FAILURE, "No results for getpwnam call\n");

            /* TODO: store negative cache ? */

            return ENOENT;
        }

        /* One result found */

        /* if we need to check the remote account go on */
        if (preq->check_provider) {
            cacheExpire = ldb_msg_find_attr_as_uint64(preq->res->msgs[0],
                                                      SYSDB_CACHE_EXPIRE, 0);
            if (cacheExpire < time(NULL)) {
                break;
            }
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "Returning info for user [%s@%s]\n", name, dom->name);

        /* We might have searched by alias. Pass on the primary name */
        ret = pd_set_primary_name(preq->res->msgs[0], preq->pd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not canonicalize username\n");
            return ret;
        }

        return EOK;
    }

    if (!dom) {
        /* Ensure that we don't try to check a provider without a domain,
         * since this will cause a NULL-dereference below.
         */
        preq->check_provider = false;
    }

    if (preq->check_provider) {

        /* dont loop forever :-) */
        preq->check_provider = false;

        dpreq = sss_dp_get_account_send(preq, preq->cctx->rctx,
                                        dom, false, SSS_DP_INITGROUPS,
                                        name, 0, NULL);
        if (!dpreq) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
            return ENOMEM;
        }

        cb_ctx = talloc_zero(preq, struct dp_callback_ctx);
        if(!cb_ctx) {
            talloc_zfree(dpreq);
            return ENOMEM;
        }

        cb_ctx->callback = pam_check_user_dp_callback;
        cb_ctx->ptr = preq;
        cb_ctx->cctx = preq->cctx;
        cb_ctx->mem_ctx = preq;

        tevent_req_set_callback(dpreq, pam_dp_send_acct_req_done, cb_ctx);

        /* tell caller we are in an async call */
        return EAGAIN;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          "No matching domain found for [%s], fail!\n", preq->pd->user);
    return ENOENT;
}

static void pam_dp_send_acct_req_done(struct tevent_req *req)
{
    struct dp_callback_ctx *cb_ctx =
            tevent_req_callback_data(req, struct dp_callback_ctx);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_account_recv(cb_ctx->mem_ctx, req,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Fatal error, killing connection!\n");
        talloc_free(cb_ctx->cctx);
        return;
    }

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}

static int pam_check_user_done(struct pam_auth_req *preq, int ret)
{
    switch (ret) {
    case EOK:
        break;

    case EAGAIN:
        /* performing async request, just return */
        break;

    case ENOENT:
        preq->pd->pam_status = PAM_USER_UNKNOWN;
        pam_reply(preq);
        break;

    default:
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
        break;
    }

    return EOK;
}

static void pam_check_user_dp_callback(uint16_t err_maj, uint32_t err_min,
                                       const char *err_msg, void *ptr)
{
    struct pam_auth_req *preq = talloc_get_type(ptr, struct pam_auth_req);
    int ret;
    struct pam_ctx *pctx =
            talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);
    char *name;

    if (err_maj) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg);
    }

    ret = pam_check_user_search(preq);
    if (ret == EOK) {
        /* Make sure we don't go to the ID provider too often */
        name = preq->domain->case_sensitive ?
                talloc_strdup(preq, preq->pd->user) :
                sss_tc_utf8_str_tolower(preq, preq->pd->user);
        if (!name) {
            ret = ENOMEM;
            goto done;
        }

        ret = pam_initgr_cache_set(pctx->rctx->ev, pctx->id_table,
                                   name, pctx->id_timeout);
        talloc_free(name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not save initgr timestamp. "
                   "Proceeding with PAM actions\n");
            /* This is non-fatal, we'll just end up going to the
             * data provider again next time.
             */
        }

        pam_dom_forwarder(preq);
    }

    ret = pam_check_user_done(preq, ret);

done:
    if (ret) {
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

    if (!NEED_CHECK_PROVIDER(preq->domain->provider)) {
        preq->callback = pam_reply;
        ret = LOCAL_pam_handler(preq);
    }
    else {
        preq->callback = pam_reply;
        ret = pam_dp_send_req(preq, SSS_CLI_SOCKET_TIMEOUT/2);
        DEBUG(SSSDBG_CONF_SETTINGS, "pam_dp_send_req returned %d\n", ret);
    }

    if (ret != EOK) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
    }
}

static int pam_cmd_authenticate(struct cli_ctx *cctx) {
    DEBUG(SSSDBG_CONF_SETTINGS, "entering pam_cmd_authenticate\n");
    return pam_forwarder(cctx, SSS_PAM_AUTHENTICATE);
}

static int pam_cmd_setcred(struct cli_ctx *cctx) {
    DEBUG(SSSDBG_CONF_SETTINGS, "entering pam_cmd_setcred\n");
    return pam_forwarder(cctx, SSS_PAM_SETCRED);
}

static int pam_cmd_acct_mgmt(struct cli_ctx *cctx) {
    DEBUG(SSSDBG_CONF_SETTINGS, "entering pam_cmd_acct_mgmt\n");
    return pam_forwarder(cctx, SSS_PAM_ACCT_MGMT);
}

static int pam_cmd_open_session(struct cli_ctx *cctx) {
    DEBUG(SSSDBG_CONF_SETTINGS, "entering pam_cmd_open_session\n");
    return pam_forwarder(cctx, SSS_PAM_OPEN_SESSION);
}

static int pam_cmd_close_session(struct cli_ctx *cctx) {
    DEBUG(SSSDBG_CONF_SETTINGS, "entering pam_cmd_close_session\n");
    return pam_forwarder(cctx, SSS_PAM_CLOSE_SESSION);
}

static int pam_cmd_chauthtok(struct cli_ctx *cctx) {
    DEBUG(SSSDBG_CONF_SETTINGS, "entering pam_cmd_chauthtok\n");
    return pam_forwarder(cctx, SSS_PAM_CHAUTHTOK);
}

static int pam_cmd_chauthtok_prelim(struct cli_ctx *cctx) {
    DEBUG(SSSDBG_CONF_SETTINGS, "entering pam_cmd_chauthtok_prelim\n");
    return pam_forwarder(cctx, SSS_PAM_CHAUTHTOK_PRELIM);
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version pam_cli_protocol_version[] = {
        {3, "2009-09-14", "make cli_pid mandatory"},
        {2, "2009-05-12", "new format <type><size><data>"},
        {1, "2008-09-05", "initial version, \\0 terminated strings"},
        {0, NULL, NULL}
    };

    return pam_cli_protocol_version;
}

struct sss_cmd_table *get_pam_cmds(void)
{
    static struct sss_cmd_table sss_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_PAM_AUTHENTICATE, pam_cmd_authenticate},
        {SSS_PAM_SETCRED, pam_cmd_setcred},
        {SSS_PAM_ACCT_MGMT, pam_cmd_acct_mgmt},
        {SSS_PAM_OPEN_SESSION, pam_cmd_open_session},
        {SSS_PAM_CLOSE_SESSION, pam_cmd_close_session},
        {SSS_PAM_CHAUTHTOK, pam_cmd_chauthtok},
        {SSS_PAM_CHAUTHTOK_PRELIM, pam_cmd_chauthtok_prelim},
        {SSS_CLI_NULL, NULL}
    };

    return sss_cmds;
}
