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

#define _GNU_SOURCE

#include <time.h>
#include <string.h>
#include "util/util.h"
#include "util/auth_utils.h"
#include "util/find_uid.h"
#include "util/sss_ptr_hash.h"
#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pamsrv_passkey.h"
#include "responder/pam/pam_helpers.h"
#include "responder/common/cache_req/cache_req.h"

enum pam_verbosity {
    PAM_VERBOSITY_NO_MESSAGES = 0,
    PAM_VERBOSITY_IMPORTANT,
    PAM_VERBOSITY_INFO,
    PAM_VERBOSITY_DEBUG
};

#define DEFAULT_PAM_VERBOSITY PAM_VERBOSITY_IMPORTANT

struct pam_initgroup_enum_str {
    enum pam_initgroups_scheme scheme;
    const char *option;
};

struct pam_initgroup_enum_str pam_initgroup_enum_str[] = {
    { PAM_INITGR_NEVER, "never" },
    { PAM_INITGR_NO_SESSION, "no_session" },
    { PAM_INITGR_ALWAYS, "always" },
    { PAM_INITGR_INVALID, NULL }
};

enum pam_initgroups_scheme pam_initgroups_string_to_enum(const char *str)
{
    size_t c;

    for (c = 0 ; pam_initgroup_enum_str[c].option != NULL; c++) {
        if (strcasecmp(pam_initgroup_enum_str[c].option, str) == 0) {
            return pam_initgroup_enum_str[c].scheme;
        }
    }

    return PAM_INITGR_INVALID;
}

const char *pam_initgroup_enum_to_string(enum pam_initgroups_scheme scheme)
{
    size_t c;

    for (c = 0 ; pam_initgroup_enum_str[c].option != NULL; c++) {
        if (pam_initgroup_enum_str[c].scheme == scheme) {
            return pam_initgroup_enum_str[c].option;
        }
    }

    return "(NULL)";
}

static errno_t
pam_null_last_online_auth_with_curr_token(struct sss_domain_info *domain,
                                          const char *username);
static errno_t
pam_get_last_online_auth_with_curr_token(struct sss_domain_info *domain,
                                         const char *name,
                                         uint64_t *_value);

void pam_reply(struct pam_auth_req *preq);

static errno_t check_cert(TALLOC_CTX *mctx,
                          struct tevent_context *ev,
                          struct pam_ctx *pctx,
                          struct pam_auth_req *preq,
                          struct pam_data *pd);

int pam_check_user_done(struct pam_auth_req *preq, int ret);

static errno_t pack_user_info_msg(TALLOC_CTX *mem_ctx,
                                  const char *user_error_message,
                                  size_t *resp_len,
                                  uint8_t **_resp)
{
    uint32_t resp_type = SSS_PAM_USER_INFO_ACCOUNT_EXPIRED;
    size_t err_len;
    uint8_t *resp;
    size_t p;

    err_len = strlen(user_error_message);
    *resp_len = 2 * sizeof(uint32_t) + err_len;
    resp = talloc_size(mem_ctx, *resp_len);
    if (resp == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    p = 0;
    SAFEALIGN_SET_UINT32(&resp[p], resp_type, &p);
    SAFEALIGN_SET_UINT32(&resp[p], err_len, &p);
    safealign_memcpy(&resp[p], user_error_message, err_len, &p);
    if (p != *resp_len) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Size mismatch\n");
    }

    *_resp = resp;
    return EOK;
}

static void inform_user(struct pam_data* pd, const char *pam_message)
{
    size_t msg_len;
    uint8_t *msg;
    errno_t ret;

    ret = pack_user_info_msg(pd, pam_message, &msg_len, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pack_user_info_msg failed.\n");
    } else {
        ret = pam_add_response(pd, SSS_PAM_USER_INFO, msg_len, msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }
    }
}

static bool is_domain_requested(struct pam_data *pd, const char *domain_name)
{
    int i;

    /* If none specific domains got requested via pam, all domains are allowed.
     * Which mimics the default/original behaviour.
     */
    if (!pd->requested_domains) {
        return true;
    }

    for (i = 0; pd->requested_domains[i]; i++) {
        if (strcasecmp(domain_name, pd->requested_domains[i])) {
            continue;
        }

        return true;
    }

    return false;
}

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
    case SSS_AUTHTOK_TYPE_2FA:
    case SSS_AUTHTOK_TYPE_2FA_SINGLE:
    case SSS_AUTHTOK_TYPE_SC_PIN:
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
    case SSS_AUTHTOK_TYPE_OAUTH2:
    case SSS_AUTHTOK_TYPE_PASSKEY:
    case SSS_AUTHTOK_TYPE_PASSKEY_KRB:
    case SSS_AUTHTOK_TYPE_PASSKEY_REPLY:
        ret = sss_authtok_set(tok, auth_token_type,
                              auth_token_data, auth_token_length);
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

static int pam_parse_in_data_v2(struct pam_data *pd,
                                uint8_t *body, size_t blen)
{
    size_t c;
    uint32_t type;
    uint32_t size;
    int ret;
    uint32_t start;
    uint32_t terminator;
    char *requested_domains;

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
                    ret = extract_string(&pd->logon_name, size, body, blen, &c);
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
                case SSS_PAM_ITEM_REQUESTED_DOMAINS:
                    ret = extract_string(&requested_domains, size, body, blen,
                                         &c);
                    if (ret != EOK) return ret;

                    ret = split_on_separator(pd, requested_domains, ',', true,
                                             true, &pd->requested_domains,
                                             NULL);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Failed to parse requested_domains list!\n");
                        return ret;
                    }
                    break;
                case SSS_PAM_ITEM_CLI_PID:
                    ret = extract_uint32_t(&pd->cli_pid, size,
                                           body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                case SSS_PAM_ITEM_CHILD_PID:
                    /* This is optional. */
                    ret = extract_uint32_t(&pd->child_pid, size,
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
                case SSS_PAM_ITEM_FLAGS:
                    ret = extract_uint32_t(&pd->cli_flags, size,
                                           body, blen, &c);
                    if (ret != EOK) return ret;
                    break;
                default:
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Ignoring unknown data type [%d].\n", type);
                    c += size;
            }
        }

    } while(c < blen);

    return EOK;

}

static int pam_parse_in_data_v3(struct pam_data *pd,
                                uint8_t *body, size_t blen)
{
    int ret;

    ret = pam_parse_in_data_v2(pd, body, blen);
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

static int pam_parse_in_data(struct pam_data *pd,
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
    pd->logon_name = (char *) &body[start];

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

static errno_t
pam_get_local_auth_policy(struct sss_domain_info *domain,
                          const char *name,
                          bool *_sc_allow,
                          bool *_passkey_allow)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *attrs[] = { SYSDB_LOCAL_SMARTCARD_AUTH, SYSDB_LOCAL_PASSKEY_AUTH, NULL };
    struct ldb_message *ldb_msg;
    bool sc_allow = false;
    bool passkey_allow = false;
    errno_t ret;

    if (name == NULL || *name == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing user name.\n");
        ret = EINVAL;
        goto done;
    }

    if (domain->sysdb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing sysdb db context.\n");
        ret = EINVAL;
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_user_by_name(tmp_ctx, domain, name, attrs, &ldb_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_search_user_by_name failed [%d][%s].\n",
              ret, strerror(ret));
        goto done;
    }

    sc_allow = ldb_msg_find_attr_as_bool(ldb_msg, SYSDB_LOCAL_SMARTCARD_AUTH,
                                         false);

    passkey_allow = ldb_msg_find_attr_as_bool(ldb_msg, SYSDB_LOCAL_PASSKEY_AUTH,
                                              true);

    ret = EOK;

done:
    if (ret == EOK) {
        *_sc_allow = sc_allow;
        *_passkey_allow = passkey_allow;
    }

    talloc_free(tmp_ctx);
    return ret;
}
static errno_t set_local_auth_type(struct pam_auth_req *preq,
                                   bool sc_allow,
                                   bool passkey_allow)
{
    struct sysdb_attrs *attrs;
    errno_t ret;

    attrs = sysdb_new_attrs(preq);
    if (!attrs) {
        ret = ENOMEM;
        goto fail;
    }

    ret = sysdb_attrs_add_bool(attrs, SYSDB_LOCAL_SMARTCARD_AUTH, sc_allow);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_attrs_add_bool(attrs, SYSDB_LOCAL_PASSKEY_AUTH, passkey_allow);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_set_user_attr(preq->domain, preq->pd->user, attrs,
                              SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "set_local_auth_type failed.\n");
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        goto fail;
    }

    return EOK;

fail:
    return ret;
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

    ret = sysdb_attrs_add_time_t(attrs,
                                 SYSDB_LAST_ONLINE_AUTH_WITH_CURR_TOKEN,
                                 time(NULL));
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

static errno_t filter_responses_env(struct response_data *resp,
                                    struct pam_data *pd,
                                    char * const *pam_filter_opts)
{
    size_t c;
    const char *var_name;
    size_t var_name_len;
    const char *service;

    if (pam_filter_opts == NULL) {
        return EOK;
    }

    for (c = 0; pam_filter_opts[c] != NULL; c++) {
        if (strncmp(pam_filter_opts[c], "ENV", 3) != 0) {
            continue;
        }

        var_name = NULL;
        var_name_len = 0;
        service = NULL;
        if (pam_filter_opts[c][3] != '\0') {
            if (pam_filter_opts[c][3] != ':') {
                /* Neither plain ENV nor ENV:, ignored */
                continue;
            }

            var_name = pam_filter_opts[c] + 4;
            /* check if there is a second ':' in the option and use the following
             * data, if any, as service name. */
            service = strchr(var_name, ':');
            if (service == NULL) {
                var_name_len = strlen(var_name);
            } else {
                var_name_len = service - var_name;

                service++;
                /* handle empty service name "ENV:var:" */
                if (*service == '\0') {
                    service = NULL;
                }
            }
        }
        /* handle empty var name "ENV:" or "ENV::service" */
        if (var_name_len == 0) {
            var_name = NULL;
        }

        DEBUG(SSSDBG_TRACE_ALL,
              "Found PAM ENV filter for variable [%.*s] and service [%s].\n",
              (int) var_name_len,
              (var_name ? var_name : "(NULL)"),
              (service ? service : "(NULL)"));

        if (service != NULL && pd->service != NULL
                    && strcmp(service, pd->service) != 0) {
            /* current service does not match the filter */
            continue;
        }

        if (var_name == NULL) {
            /* All environment variables should be filtered */
            resp->do_not_send_to_client = true;
            continue;
        }

        if (resp->len > var_name_len && resp->data[var_name_len] == '='
                    && memcmp(resp->data, var_name, var_name_len) == 0) {
            resp->do_not_send_to_client = true;
        }
    }

    return EOK;
}

errno_t filter_responses(struct pam_ctx *pctx,
                         struct response_data *resp_list,
                         struct pam_data *pd)
{
    int ret;
    struct response_data *resp;
    uint32_t user_info_type;
    int64_t expire_date = 0;
    int pam_verbosity = DEFAULT_PAM_VERBOSITY;
    char **new_opts;
    size_t c;
    const char *default_pam_response_filter[] = { "ENV:KRB5CCNAME:sudo",
                                                  "ENV:KRB5CCNAME:sudo-i",
                                                  NULL };

    ret = confdb_get_int(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_VERBOSITY, DEFAULT_PAM_VERBOSITY,
                         &pam_verbosity);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read PAM verbosity, not fatal.\n");
        pam_verbosity = DEFAULT_PAM_VERBOSITY;
    }

    if (pctx->pam_filter_opts == NULL) {
        ret = confdb_get_string_as_list(pctx->rctx->cdb, pctx,
                                        CONFDB_PAM_CONF_ENTRY,
                                        CONFDB_PAM_RESPONSE_FILTER,
                                        &pctx->pam_filter_opts);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to read values of [%s], not fatal.\n",
                  CONFDB_PAM_RESPONSE_FILTER);
            pctx->pam_filter_opts = NULL;
        } else {
            if (pctx->pam_filter_opts == NULL
                        || *pctx->pam_filter_opts[0] == '+'
                        || *pctx->pam_filter_opts[0] == '-') {
                ret = mod_defaults_list(pctx, default_pam_response_filter,
                                        pctx->pam_filter_opts, &new_opts);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Failed to modify [%s] defaults.\n",
                          CONFDB_PAM_RESPONSE_FILTER);
                    return ret;
                }
                talloc_free(pctx->pam_filter_opts);
                pctx->pam_filter_opts = new_opts;
            }
        }

        if (pctx->pam_filter_opts == NULL) {
            DEBUG(SSSDBG_CONF_SETTINGS, "No PAM response filter set.\n");
        } else {
            /* Make sure there are no '+' or '-' prefixes anymore */
            for (c = 0; pctx->pam_filter_opts[c] != NULL; c++) {
                    if (*pctx->pam_filter_opts[0] == '+'
                            || *pctx->pam_filter_opts[0] == '-') {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "Unsupport mix of prefixed and not prefixed "
                              "values of [%s].\n", CONFDB_PAM_RESPONSE_FILTER);
                        return EINVAL;
                    }
                    DEBUG(SSSDBG_CONF_SETTINGS,
                          "PAM response filter: [%s].\n",
                          pctx->pam_filter_opts[c]);
            }
        }
    }

    resp = resp_list;
    while(resp != NULL) {
        if (resp->type == SSS_PAM_USER_INFO) {
            if (resp->len < sizeof(uint32_t)) {
                DEBUG(SSSDBG_CRIT_FAILURE, "User info entry is too short.\n");
                ret = EINVAL;
                goto done;
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
                        ret = EINVAL;
                        goto done;
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
        } else if (resp->type == SSS_PAM_ENV_ITEM) {
            resp->do_not_send_to_client = false;
            ret = filter_responses_env(resp, pd, pctx->pam_filter_opts);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "filter_responses_env failed.\n");
                goto done;
            }
        } else if (resp->type & SSS_SERVER_INFO) {
            resp->do_not_send_to_client = true;
        }

        resp = resp->next;
    }

    ret = EOK;
done:

    return ret;
}

static void do_not_send_cert_info(struct pam_data *pd)
{
    struct response_data *resp;

    resp = pd->resp_list;
    while (resp != NULL) {
        switch (resp->type) {
        case SSS_PAM_CERT_INFO:
        case SSS_PAM_CERT_INFO_WITH_HINT:
            resp->do_not_send_to_client = true;
            break;
        default:
            break;
        }
        resp = resp->next;
    }
}

errno_t pam_get_auth_types(struct pam_data *pd,
                           struct pam_resp_auth_type *_auth_types)
{
    int ret;
    struct response_data *resp;
    struct pam_resp_auth_type types = {0};
    bool found_cert_info = false;

    resp = pd->resp_list;
    while (resp != NULL) {
        switch (resp->type) {
        case SSS_PAM_OTP_INFO:
            types.otp_auth = true;
            break;
        case SSS_PAM_CERT_INFO:
        case SSS_PAM_CERT_INFO_WITH_HINT:
            found_cert_info = true;
            break;
        case SSS_PAM_PASSKEY_INFO:
        case SSS_PAM_PASSKEY_KRB_INFO:
            types.passkey_auth = true;
            break;
        case SSS_PASSWORD_PROMPTING:
            types.password_auth = true;
            break;
        case SSS_CERT_AUTH_PROMPTING:
            types.cert_auth = true;
            break;
        default:
            break;
        }
        resp = resp->next;
    }

    if (!types.password_auth && !types.otp_auth && !types.cert_auth && !types.passkey_auth) {
        /* If the backend cannot determine which authentication types are
         * available the default would be to prompt for a password. */
        types.password_auth = true;
    }

    if (found_cert_info && !types.cert_auth) {
        do_not_send_cert_info(pd);
    }

    DEBUG(SSSDBG_TRACE_ALL, "Authentication types for user [%s] and service "
                            "[%s]:%s%s%s%s\n", pd->user, pd->service,
                            types.password_auth ? " password": "",
                            types.otp_auth ? " two-factor" : "",
                            types.passkey_auth ? " passkey" : "",
                            types.cert_auth ? " smartcard" : "");

    ret = EOK;

    *_auth_types = types;

    return ret;
}

static errno_t pam_eval_local_auth_policy(TALLOC_CTX *mem_ctx,
                                          struct pam_ctx *pctx,
                                          struct pam_data *pd,
                                          struct pam_auth_req *preq,
                                          bool *_sc_allow,
                                          bool *_passkey_allow,
                                          char **_local_policy) {

    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *domain_cdb;
    char *local_policy = NULL;
    bool sc_allow = false;
    bool passkey_allow = false;
    struct pam_resp_auth_type auth_types;
    char **opts;
    size_t c;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Check local auth policy */
    domain_cdb = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL, preq->domain->name);
    if (domain_cdb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_get_string(pctx->rctx->cdb, tmp_ctx, domain_cdb,
                            CONFDB_DOMAIN_LOCAL_AUTH_POLICY,
                            "match", &local_policy);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get the confdb local_auth_policy\n");
        return ret;
    }

    /* "only" ignores online methods and allows all local ones */
    if (strcasecmp(local_policy, "only") == 0) {
        sc_allow = true;
        passkey_allow = true;
    /* Match what the KDC supports and provides */
    } else if (strcasecmp(local_policy, "match") == 0) {
        /* Don't overwrite the local auth type when offline */
        if (pd->pam_status == PAM_SUCCESS && pd->cmd == SSS_PAM_PREAUTH &&
            !is_domain_provider(preq->domain, "ldap")) {
            ret = pam_get_auth_types(pd, &auth_types);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to get authentication types\n");
                goto done;
            }

            if (auth_types.cert_auth) {
                sc_allow = true;
            } else if (auth_types.passkey_auth) {
                passkey_allow = true;
            }

            /* Store the local auth types, in case we go offline */
            if (!auth_types.password_auth) {
                ret = set_local_auth_type(preq, sc_allow, passkey_allow);
                if (ret != EOK) {
                    DEBUG(SSSDBG_FATAL_FAILURE,
                          "Failed to evaluate local auth policy\n");
                    goto done;
                }
            }
        }

        /* Read the latest auth types */
        ret = pam_get_local_auth_policy(preq->domain, preq->pd->user,
                                        &sc_allow, &passkey_allow);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to get PAM local auth policy\n");
            goto done;
        }
    /* Check for enable */
    } else {
        ret = split_on_separator(tmp_ctx, local_policy, ',', true, true, &opts,
                                 NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed [%d], %s.\n",
                                     ret, sss_strerror(ret));
            goto done;
        }

        for (c = 0; opts[c] != NULL; c++) {
            if (strcasestr(opts[c], "passkey") != NULL) {
                passkey_allow = strstr(opts[c], "enable") ? true : false;
            } else if (strcasestr(opts[c], "smartcard") != NULL) {
                sc_allow = strstr(opts[c], "enable") ? true : false;
            } else {
               DEBUG(SSSDBG_MINOR_FAILURE,
                     "Unexpected local auth policy option [%s], " \
                     "skipping.\n", opts[c]);
            }
        }

        /* if passkey is enabled but local Smartcard authentication is not but
         * possible, the cert info data has to be remove as well if only local
         * Smartcard authentication is possible. If Smartcard authentication
         * is possible on the server side we have to keep it because the
         * 'enable' option should only add local methods but not reject remote
         * ones. */
        if (!sc_allow) {
            /* We do not need the auth_types here but the call will remove
             * the cert info data if the server does not support Smartcard
             * authentication. */
            ret = pam_get_auth_types(pd, &auth_types);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to get authentication types\n");
                goto done;
            }
        }
    }

    *_sc_allow = sc_allow;
    *_passkey_allow = passkey_allow;
    *_local_policy = talloc_steal(mem_ctx, local_policy);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void pam_reply_delay(struct tevent_context *ev, struct tevent_timer *te,
                            struct timeval tv, void *pvt)
{
    struct pam_auth_req *preq;

    DEBUG(SSSDBG_CONF_SETTINGS, "pam_reply_delay get called.\n");

    preq = talloc_get_type(pvt, struct pam_auth_req);

    pam_reply(preq);
}

static errno_t get_password_for_cache_auth(struct sss_auth_token *authtok,
                                           const char **password)
{
    int ret;
    size_t pw_len;
    const char *fa2;
    size_t fa2_len;

    switch (sss_authtok_get_type(authtok)) {
    case SSS_AUTHTOK_TYPE_PASSWORD:
        ret = sss_authtok_get_password(authtok, password, NULL);
        break;
    case SSS_AUTHTOK_TYPE_2FA:
        ret = sss_authtok_get_2fa(authtok, password, &pw_len, &fa2, &fa2_len);
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE, "Unsupported auth token type [%d].\n",
              sss_authtok_get_type(authtok));
        ret = EINVAL;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get password.\n");
        return ret;
    }

    return EOK;
}

static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd);
static void pam_handle_cached_login(struct pam_auth_req *preq, int ret,
                                    time_t expire_date, time_t delayed_until, bool cached_auth);

/*
 * Add a request to add a variable to the PAM user environment, containing the
 * actual (not overridden) user shell, in case session recording is enabled.
 */
static int pam_reply_sr_export_shell(struct pam_auth_req *preq,
                                     const char *var_name)
{
    int ret;
    TALLOC_CTX *ctx = NULL;
    bool enabled;
    const char *enabled_str;
    const char *shell;
    char *buf;

    /* Create temporary talloc context */
    ctx = talloc_new(NULL);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Check if session recording is enabled */
    if (preq->cctx->rctx->sr_conf.scope ==
            SESSION_RECORDING_SCOPE_NONE) {
        enabled = false;
    } else {
        enabled_str = ldb_msg_find_attr_as_string(preq->user_obj,
                                                  SYSDB_SESSION_RECORDING, NULL);
        if (enabled_str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "%s attribute not found\n", SYSDB_SESSION_RECORDING);
            ret = ENOENT;
            goto done;
        } else if (strcmp(enabled_str, "TRUE") == 0) {
            enabled = true;
        } else if (strcmp(enabled_str, "FALSE") == 0) {
            enabled = false;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "invalid value of %s attribute: %s\n",
                  SYSDB_SESSION_RECORDING, enabled_str);
            ret = ENOENT;
            goto done;
        }
    }

    /* Export original shell if recording is enabled and so it's overridden */
    if (enabled) {
        /* Extract the shell */
        shell = sss_resp_get_shell_override(preq->user_obj,
                                            preq->cctx->rctx, preq->domain);
        if (shell == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "user has no shell\n");
            ret = ENOENT;
            goto done;
        }

        /* Format environment entry */
        buf = talloc_asprintf(ctx, "%s=%s", var_name, shell);
        if (buf == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }

        /* Add request to add the entry to user environment */
        ret = pam_add_response(preq->pd, SSS_PAM_ENV_ITEM,
                               strlen(buf) + 1, (uint8_t *)buf);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(ctx);
    return ret;
}

void pam_reply(struct pam_auth_req *preq)
{
    struct cli_ctx *cctx;
    struct cli_protocol *prctx;
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
    char *local_policy = NULL;
    struct pam_ctx *pctx;
    uint32_t user_info_type;
    time_t exp_date = -1;
    time_t delay_until = -1;
    char* pam_account_expired_message;
    char* pam_account_locked_message;
    int pam_verbosity;
    bool local_sc_auth_allow = false;
    bool local_passkey_auth_allow = false;
#ifdef BUILD_PASSKEY
    bool pk_preauth_done = false;
#endif /* BUILD_PASSKEY */

    pd = preq->pd;
    cctx = preq->cctx;
    pctx = talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);
    prctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    ret = confdb_get_int(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_VERBOSITY, DEFAULT_PAM_VERBOSITY,
                         &pam_verbosity);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read PAM verbosity, not fatal.\n");
        pam_verbosity = DEFAULT_PAM_VERBOSITY;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "pam_reply initially called with result [%d]: %s. "
          "this result might be changed during processing\n",
          pd->pam_status, pam_strerror(NULL, pd->pam_status));

    if (preq->domain != NULL && preq->domain->name != NULL) {
        ret = pam_eval_local_auth_policy(cctx, pctx, pd, preq,
                                         &local_sc_auth_allow,
                                         &local_passkey_auth_allow,
                                         &local_policy);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to evaluate local auth policy\n");
            goto done;
        }
    }

   /* Ignore local_auth_policy for the files provider, allow local
    * smartcard auth (default behavior prior to local_auth_policy) */
    if (is_domain_provider(preq->domain, "files")) {
        local_sc_auth_allow = true;
    /* For the ldap auth provider we currently only support
     * password based authentication */
    } else if (is_domain_provider(preq->domain, "ldap") && local_policy != NULL
              && strcasecmp(local_policy, "match") == 0) {
        local_passkey_auth_allow = false;
        local_sc_auth_allow = false;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Local auth policy allowed: smartcard [%s], passkey [%s]\n",
                             local_sc_auth_allow ? "True" : "False",
                             local_passkey_auth_allow ? "True" : "False");

    if (pd->cmd == SSS_PAM_AUTHENTICATE
            && !preq->cert_auth_local
            && (pd->pam_status == PAM_AUTHINFO_UNAVAIL
                || pd->pam_status == PAM_NO_MODULE_DATA
                || pd->pam_status == PAM_BAD_ITEM)
            && may_do_cert_auth(pctx, pd)) {
        /* We have Smartcard credentials and the backend indicates that it is
         * offline (PAM_AUTHINFO_UNAVAIL) or cannot handle the credentials
         * (PAM_BAD_ITEM), so let's try authentication against the Smartcard
         * PAM_NO_MODULE_DATA is returned by the krb5 backend if no
         * authentication method was found at all, this might happen if the
         * user has a Smartcard assigned but the pkint plugin is not available
         * on the client. */
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Backend cannot handle Smartcard authentication, "
              "trying local Smartcard authentication.\n");
        if (local_sc_auth_allow) {
            preq->cert_auth_local = true;
            ret = check_cert(cctx, cctx->ev, pctx, preq, pd);
            pam_check_user_done(preq, ret);
            return;
        } else {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "Local smartcard auth not allowed by local_auth_policy");
        }
    }

    if (pd->pam_status == PAM_AUTHINFO_UNAVAIL || preq->use_cached_auth) {

        switch(pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
            if ((preq->domain != NULL) &&
                (preq->domain->cache_credentials == true) &&
                (pd->offline_auth == false)) {
                const char *password = NULL;
                bool use_cached_auth;

                /* backup value of preq->use_cached_auth*/
                use_cached_auth = preq->use_cached_auth;
                /* set to false to avoid entering this branch when pam_reply()
                 * is recursively called from pam_handle_cached_login() */
                preq->use_cached_auth = false;

                /* do auth with offline credentials */
                pd->offline_auth = true;

                if (preq->domain->sysdb == NULL) {
                    DEBUG(SSSDBG_FATAL_FAILURE,
                          "Fatal: Sysdb CTX not found for domain"
                              " [%s]!\n", preq->domain->name);
                    goto done;
                }

                ret = get_password_for_cache_auth(pd->authtok, &password);
                if (ret != EOK) {
                    DEBUG(SSSDBG_FATAL_FAILURE,
                          "get_password_and_type_for_cache_auth failed.\n");
                    goto done;
                }

                ret = sysdb_cache_auth(preq->domain,
                                       pd->user, password,
                                       pctx->rctx->cdb, false,
                                       &exp_date, &delay_until);

                pam_handle_cached_login(preq, ret, exp_date, delay_until,
                                        use_cached_auth);
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
        case SSS_PAM_PREAUTH:
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

    if (pd->pam_status == PAM_SUCCESS && pd->cmd == SSS_PAM_CHAUTHTOK) {
        ret = pam_null_last_online_auth_with_curr_token(preq->domain,
                                                        pd->user);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sysdb_null_last_online_auth_with_curr_token failed: "
                  "%s [%d].\n", sss_strerror(ret), ret);
            goto done;
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
        preq->domain &&
        preq->domain->cache_credentials &&
        !pd->offline_auth &&
        !pd->last_auth_saved &&
        !is_files_provider(preq->domain)) {
        ret = set_last_login(preq);
        if (ret != EOK) {
            goto done;
        }
        return;
    }

    ret = sss_packet_new(prctx->creq, 0, sss_packet_get_cmd(prctx->creq->in),
                         &prctx->creq->out);
    if (ret != EOK) {
        goto done;
    }

    /* Passkey auth user notification if no TGT is granted */
    if (pd->cmd == SSS_PAM_AUTHENTICATE &&
        pd->pam_status == PAM_SUCCESS &&
        preq->pd->passkey_local_done) {
            user_info_type = SSS_PAM_USER_INFO_NO_KRB_TGT;
            pam_add_response(pd, SSS_PAM_USER_INFO,
            sizeof(uint32_t), (const uint8_t *) &user_info_type);
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "User [%s] logged in with local passkey authentication, single "
                  "sign on ticket is not obtained.\n", pd->user);
    }

    /* Account expiration warning is printed for sshd. If pam_verbosity
     * is equal or above PAM_VERBOSITY_INFO then all services are informed
     * about account expiration.
     */
    if (pd->pam_status == PAM_ACCT_EXPIRED &&
        ((pd->service != NULL && strcasecmp(pd->service, "sshd") == 0) ||
         pam_verbosity >= PAM_VERBOSITY_INFO)) {

        ret = confdb_get_string(pctx->rctx->cdb, pd, CONFDB_PAM_CONF_ENTRY,
                                CONFDB_PAM_ACCOUNT_EXPIRED_MESSAGE, "",
                                &pam_account_expired_message);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to get expiration message: %d:[%s].\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        inform_user(pd, pam_account_expired_message);
    }

    if (pd->account_locked) {

        ret = confdb_get_string(pctx->rctx->cdb, pd, CONFDB_PAM_CONF_ENTRY,
                                CONFDB_PAM_ACCOUNT_LOCKED_MESSAGE, "",
                                &pam_account_locked_message);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to get expiration message: %d:[%s].\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        inform_user(pd, pam_account_locked_message);
    }

    ret = filter_responses(pctx, pd->resp_list, pd);
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

    if (pd->cmd == SSS_PAM_PREAUTH) {
        ret = pam_eval_prompting_config(pctx, pd);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add prompting information, "
                                     "using defaults.\n");
        }

#ifdef BUILD_PASSKEY
        ret = pam_eval_passkey_response(pctx, pd, preq, &pk_preauth_done);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to eval passkey response\n");
            goto done;
        }

        if (may_do_passkey_auth(pctx, pd)
            && !pk_preauth_done
            && preq->passkey_data_exists
            && local_passkey_auth_allow) {
            ret = passkey_local(cctx, cctx->ev, pctx, preq, pd);
            pam_check_user_done(preq, ret);
            return;
        }
#endif /* BUILD_PASSKEY */
    }

    /*
     * Export non-overridden shell to tlog-rec-session when opening the session
     */
    if (pd->cmd == SSS_PAM_OPEN_SESSION && pd->pam_status == PAM_SUCCESS) {
        ret = pam_reply_sr_export_shell(preq, "TLOG_REC_SESSION_SHELL");
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "failed to export the shell to tlog-rec-session.\n");
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

    ret = sss_packet_grow(prctx->creq->out, sizeof(int32_t) +
                                           sizeof(int32_t) +
                                           resp_c * 2* sizeof(int32_t) +
                                           resp_size);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_get_body(prctx->creq->out, &body, &blen);
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
    DEBUG(SSSDBG_FUNC_DATA, "Returning [%d]: %s to the client\n",
          pd->pam_status, pam_strerror(NULL, pd->pam_status));
    sss_cmd_done(cctx, preq);
}

static void pam_dom_forwarder(struct pam_auth_req *preq);

static void pam_handle_cached_login(struct pam_auth_req *preq, int ret,
                                    time_t expire_date, time_t delayed_until,
                                    bool use_cached_auth)
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
        case PAM_AUTH_ERR:
            /* Was this attempt to authenticate from cache? */
            if (use_cached_auth) {
                /* Don't try cached authentication again, try online check. */
                DEBUG(SSSDBG_FUNC_DATA,
                      "Cached authentication failed for: %s\n",
                      preq->pd->user);
                preq->cached_auth_failed = true;
                pam_dom_forwarder(preq);
                return;
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
static void pam_forwarder_cert_cb(struct tevent_req *req);
int pam_check_user_search(struct pam_auth_req *preq);


/* TODO: we should probably return some sort of cookie that is set in the
 * PAM_ENVIRONMENT, so that we can save performing some calls and cache
 * data. */

static errno_t pam_forwarder_parse_data(struct cli_ctx *cctx, struct pam_data *pd)
{
    struct cli_protocol *prctx;
    uint8_t *body;
    size_t blen;
    errno_t ret;
    uint32_t terminator;
    const char *key_id;

    prctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(prctx->creq->in, &body, &blen);
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

    switch (prctx->cli_protocol_version->version) {
        case 1:
            ret = pam_parse_in_data(pd, body, blen);
            break;
        case 2:
            ret = pam_parse_in_data_v2(pd, body, blen);
            break;
        case 3:
            ret = pam_parse_in_data_v3(pd, body, blen);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Illegal protocol version [%d].\n",
                      prctx->cli_protocol_version->version);
            ret = EINVAL;
    }
    if (ret != EOK) {
        goto done;
    }

    if (pd->logon_name != NULL) {
        ret = sss_parse_name_for_domains(pd, cctx->rctx->domains,
                                         cctx->rctx->default_domain,
                                         pd->logon_name,
                                         &pd->domain, &pd->user);
    } else {
        /* SSS_PAM_PREAUTH request may have a missing name, e.g. if the
         * name is determined with the help of a certificate. During
         * SSS_PAM_AUTHENTICATE at least a key ID is needed to identify the
         * selected certificate. */
        if (pd->cmd == SSS_PAM_AUTHENTICATE
                && may_do_cert_auth(talloc_get_type(cctx->rctx->pvt_ctx,
                                                    struct pam_ctx), pd)
                && (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_SC_PIN
                    || sss_authtok_get_type(pd->authtok)
                                               == SSS_AUTHTOK_TYPE_SC_KEYPAD)) {
            ret = sss_authtok_get_sc(pd->authtok, NULL, NULL, NULL, NULL, NULL,
                                     NULL, &key_id, NULL, NULL, NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_sc failed.\n");
                goto done;
            }

            if (key_id == NULL || *key_id == '\0') {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Missing logon and Smartcard key ID during "
                      "authentication.\n");
                ret = ERR_NO_CREDS;
                goto done;
            }

            ret = EOK;
        } else if (pd->cmd == SSS_PAM_PREAUTH
                && may_do_cert_auth(talloc_get_type(cctx->rctx->pvt_ctx,
                                                    struct pam_ctx), pd)) {
            ret = EOK;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing logon name in PAM request.\n");
            ret = ERR_NO_CREDS;
            goto done;
        }
    }

    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

done:
    return ret;
}

static bool is_uid_trusted(struct cli_creds *creds,
                           size_t trusted_uids_count,
                           uid_t *trusted_uids)
{
    errno_t ret;

    /* root is always trusted */
    if (client_euid(creds) == 0) {
        return true;
    }

    /* All uids are allowed */
    if (trusted_uids_count == 0) {
        return true;
    }

    ret = check_allowed_uids(client_euid(creds), trusted_uids_count, trusted_uids);
    if (ret == EOK) return true;

    return false;
}

static bool is_domain_public(char *name,
                             char **public_dom_names,
                             size_t public_dom_names_count)
{
    size_t i;

    for(i=0; i < public_dom_names_count; i++) {
        if (strcasecmp(name, public_dom_names[i]) == 0) {
            return true;
        }
    }
    return false;
}

static enum cache_req_dom_type
get_domain_request_type(struct pam_auth_req *preq,
                        struct pam_ctx *pctx)
{
    enum cache_req_dom_type req_dom_type;

    /* By default, only POSIX domains are to be contacted */
    req_dom_type = CACHE_REQ_POSIX_DOM;

    for (int i = 0; pctx->app_services[i]; i++) {
        if (strcmp(pctx->app_services[i], preq->pd->service) == 0) {
            req_dom_type = CACHE_REQ_APPLICATION_DOM;
            break;
        }
    }

    return req_dom_type;
}

static errno_t check_cert(TALLOC_CTX *mctx,
                          struct tevent_context *ev,
                          struct pam_ctx *pctx,
                          struct pam_auth_req *preq,
                          struct pam_data *pd)
{
    int p11_child_timeout;
    int wait_for_card_timeout;
    char *cert_verification_opts;
    errno_t ret;
    struct tevent_req *req;
    char *uri = NULL;

    ret = confdb_get_int(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_P11_CHILD_TIMEOUT,
                         P11_CHILD_TIMEOUT_DEFAULT,
                         &p11_child_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read p11_child_timeout from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }
    if ((pd->cli_flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH) && pd->priv == 1) {
        ret = confdb_get_int(pctx->rctx->cdb, CONFDB_PAM_CONF_ENTRY,
                             CONFDB_PAM_WAIT_FOR_CARD_TIMEOUT,
                             P11_WAIT_FOR_CARD_TIMEOUT_DEFAULT,
                             &wait_for_card_timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to read [%s] from confdb: [%d]: %s\n",
                  CONFDB_PAM_WAIT_FOR_CARD_TIMEOUT, ret, sss_strerror(ret));
            return ret;
        }

        p11_child_timeout += wait_for_card_timeout;
    }

    ret = confdb_get_string(pctx->rctx->cdb, mctx, CONFDB_PAM_CONF_ENTRY,
                            CONFDB_PAM_CERT_VERIFICATION,
                            NULL, &cert_verification_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read '"CONFDB_PAM_CERT_VERIFICATION"' from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    if (cert_verification_opts == NULL) {
        ret = confdb_get_string(pctx->rctx->cdb, mctx, CONFDB_MONITOR_CONF_ENTRY,
                                CONFDB_MONITOR_CERT_VERIFICATION, NULL,
                                &cert_verification_opts);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                "Failed to read '"CONFDB_MONITOR_CERT_VERIFICATION"' from confdb: [%d]: %s\n",
                ret, sss_strerror(ret));
            return ret;
        }
    }

    ret = confdb_get_string(pctx->rctx->cdb, mctx, CONFDB_PAM_CONF_ENTRY,
                            CONFDB_PAM_P11_URI, NULL, &uri);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read '"CONFDB_PAM_P11_URI"' from confdb: [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    req = pam_check_cert_send(mctx, ev,
                              pctx->ca_db, p11_child_timeout,
                              cert_verification_opts, pctx->sss_certmap_ctx,
                              uri, pd);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "pam_check_cert_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, pam_forwarder_cert_cb, preq);
    return EAGAIN;
}


static int pam_forwarder(struct cli_ctx *cctx, int pam_cmd)
{
    struct pam_auth_req *preq;
    struct pam_data *pd;
    int ret;
    struct pam_ctx *pctx =
            talloc_get_type(cctx->rctx->pvt_ctx, struct pam_ctx);
    struct tevent_req *req;

    preq = talloc_zero(cctx, struct pam_auth_req);
    if (!preq) {
        return ENOMEM;
    }
    preq->cctx = cctx;
    preq->cert_auth_local = false;
    preq->client_id_num = cctx->client_id_num;

    preq->pd = create_pam_data(preq);
    if (!preq->pd) {
        talloc_free(preq);
        return ENOMEM;
    }
    pd = preq->pd;

    preq->is_uid_trusted = is_uid_trusted(cctx->creds,
                                          pctx->trusted_uids_count,
                                          pctx->trusted_uids);

    if (!preq->is_uid_trusted) {
        DEBUG(SSSDBG_MINOR_FAILURE, "uid %"SPRIuid" is not trusted.\n",
              client_euid(cctx->creds));
    }


    pd->cmd = pam_cmd;
    pd->priv = cctx->priv;
    pd->client_id_num = cctx->client_id_num;

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
        goto done;
    }

    /* Determine what domain type to contact */
    preq->req_dom_type = get_domain_request_type(preq, pctx);

    if (pd->cmd == SSS_PAM_AUTHENTICATE
            && (pd->cli_flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH)
            && !IS_SC_AUTHTOK(pd->authtok)) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Smartcard authentication required but authentication "
              "token [%d][%s] is not suitable.\n",
              sss_authtok_get_type(pd->authtok),
              sss_authtok_type_to_str(sss_authtok_get_type(pd->authtok)));
        ret = ERR_NO_CREDS;
        goto done;
    }

    /* Try backend first for authentication before doing local Smartcard
     * authentication if a logon name is available. Otherwise try to derive
     * the logon name from the certificate first. */
    if ((pd->cmd != SSS_PAM_AUTHENTICATE
                || (pd->cmd == SSS_PAM_AUTHENTICATE && pd->logon_name == NULL))
            && may_do_cert_auth(pctx, pd)) {
        ret = check_cert(cctx, cctx->ev, pctx, preq, pd);
        /* Finish here */
        goto done;
    }

    /* This is set to false inside passkey_local() if no passkey data is found.
     * It is checked in pam_reply() to avoid an endless loop */
    preq->passkey_data_exists = true;

#ifdef BUILD_PASSKEY
    if ((pd->cmd == SSS_PAM_AUTHENTICATE)) {
        if (may_do_passkey_auth(pctx, pd)) {
            if (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_PASSKEY_KRB) {
                ret = passkey_kerberos(pctx, preq->pd, preq);
                goto done;
            } else if ((sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_PASSKEY) ||
                      (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_EMPTY)) {
                ret = passkey_local(cctx, cctx->ev, pctx, preq, pd);
                goto done;
            }
        }
    }
#endif /* BUILD_PASSKEY */

    ret = pam_check_user_search(preq);

done:
    return pam_check_user_done(preq, ret);
}

static errno_t pam_user_by_cert_step(struct pam_auth_req *preq);
static void pam_forwarder_lookup_by_cert_done(struct tevent_req *req);
static void pam_forwarder_cert_cb(struct tevent_req *req)
{
    struct pam_auth_req *preq = tevent_req_callback_data(req,
                                                         struct pam_auth_req);
    struct pam_data *pd;
    errno_t ret = EOK;
    const char *cert;

    ret = pam_check_cert_recv(req, preq, &preq->cert_list);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_cert request failed.\n");
        goto done;
    }

    pd = preq->pd;

    cert = sss_cai_get_cert(preq->cert_list);

    if (cert == NULL) {
        if (pd->logon_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "No certificate found and no logon name given, " \
                  "authentication not possible.\n");
            ret = ENOENT;
        } else if (pd->cmd == SSS_PAM_PREAUTH
                        && (pd->cli_flags & PAM_CLI_FLAGS_TRY_CERT_AUTH)) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "try_cert_auth flag set but no certificate available, "
                  "request finished.\n");
            preq->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
            pam_reply(preq);
            return;
        } else {
            if (pd->cmd == SSS_PAM_AUTHENTICATE) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "No certificate returned, authentication failed.\n");
                preq->pd->pam_status = PAM_AUTH_ERR;
                pam_reply(preq);
                return;
            } else {
                ret = pam_check_user_search(preq);
            }

        }
        goto done;
    }

    preq->current_cert = preq->cert_list;
    ret = pam_user_by_cert_step(preq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "pam_user_by_cert_step failed.\n");
        goto done;
    }

    return;

done:
    pam_check_user_done(preq, ret);
}

static errno_t pam_user_by_cert_step(struct pam_auth_req *preq)
{
    struct cli_ctx *cctx = preq->cctx;
    struct tevent_req *req;
    struct pam_ctx *pctx =
            talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);

    if (preq->current_cert == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing certificate data.\n");
        return EINVAL;
    }

    req = cache_req_user_by_cert_send(preq, cctx->ev, cctx->rctx,
                                      pctx->rctx->ncache, 0,
                                      preq->req_dom_type, NULL,
                                      sss_cai_get_cert(preq->current_cert));
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "cache_req_user_by_cert_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, pam_forwarder_lookup_by_cert_done, preq);
    return EOK;
}

static errno_t get_results_from_all_domains(TALLOC_CTX *mem_ctx,
                                            struct cache_req_result **results,
                                            struct ldb_result **ldb_results)
{
    int ret;
    size_t count = 0;
    size_t c;
    size_t d;
    size_t r = 0;
    struct ldb_result *res;

    for (d = 0; results != NULL && results[d] != NULL; d++) {
        count += results[d]->count;
    }

    res = talloc_zero(mem_ctx, struct ldb_result);
    if (res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    if (count == 0) {
        *ldb_results = res;
        return EOK;
    }

    res->msgs = talloc_zero_array(res, struct ldb_message *, count);
    if (res->msgs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        return ENOMEM;
    }
    res->count = count;

    for (d = 0; results != NULL && results[d] != NULL; d++) {
        for (c = 0; c < results[d]->count; c++) {
            if (r >= count) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "More results found then counted before.\n");
                ret = EINVAL;
                goto done;
            }
            res->msgs[r++] = talloc_steal(res->msgs, results[d]->msgs[c]);
        }
    }

    *ldb_results = res;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(res);
    }

    return ret;
}

/* Return true if hint is set for at least one domain */
static bool get_user_name_hint(struct sss_domain_info *domains)
{
    struct sss_domain_info *d;

    DLIST_FOR_EACH(d, domains) {
        if (d->user_name_hint == true) {
            return true;
        }
    }

    return false;
}

static void pam_forwarder_lookup_by_cert_done(struct tevent_req *req)
{
    int ret;
    struct cache_req_result **results;
    struct pam_auth_req *preq = tevent_req_callback_data(req,
                                                         struct pam_auth_req);
    const char *cert_user = NULL;
    size_t cert_count = 0;
    size_t cert_user_count = 0;
    struct ldb_result *cert_user_objs;

    ret = cache_req_recv(preq, req, &results);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "cache_req_user_by_cert request failed.\n");
        goto done;
    }

    if (ret == EOK) {
        ret = get_results_from_all_domains(preq, results,
                                           &cert_user_objs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_results_from_all_domains failed.\n");
            goto done;
        }

        sss_cai_set_cert_user_objs(preq->current_cert, cert_user_objs);
    }

    preq->current_cert = sss_cai_get_next(preq->current_cert);
    if (preq->current_cert != NULL) {
        ret = pam_user_by_cert_step(preq);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "pam_user_by_cert_step failed.\n");
            goto done;
        }
        return;
    }

    sss_cai_check_users(&preq->cert_list, &cert_count, &cert_user_count);
    DEBUG(SSSDBG_TRACE_ALL,
          "Found [%zu] certificates and [%zu] related users.\n",
          cert_count, cert_user_count);

    if (cert_user_count == 0) {
        if (preq->pd->logon_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing logon name and no certificate user found.\n");
            ret = ENOENT;
            goto done;
        }
    } else {

        if (preq->pd->logon_name == NULL) {
            if (preq->pd->cmd != SSS_PAM_PREAUTH
                    && preq->pd->cmd != SSS_PAM_AUTHENTICATE) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Missing logon name only allowed during (pre-)auth.\n");
                ret = ENOENT;
                goto done;
            }

            if (cert_count > 1) {
                for (preq->current_cert = preq->cert_list;
                     preq->current_cert != NULL;
                     preq->current_cert = sss_cai_get_next(preq->current_cert)) {

                    ret = add_pam_cert_response(preq->pd,
                                   preq->cctx->rctx->domains, "",
                                   preq->current_cert,
                                   get_user_name_hint(preq->cctx->rctx->domains)
                                            ? SSS_PAM_CERT_INFO_WITH_HINT
                                            : SSS_PAM_CERT_INFO);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "add_pam_cert_response failed.\n");
                        preq->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
                    }
                }

                ret = EOK;
                preq->pd->pam_status = PAM_SUCCESS;
                pam_reply(preq);
                goto done;
            }

            if (cert_user_count == 1) {
                cert_user_objs = sss_cai_get_cert_user_objs(preq->cert_list);
                if (cert_user_objs == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Missing certificate user.\n");
                    ret = ENOENT;
                    goto done;
                }

                cert_user = ldb_msg_find_attr_as_string(
                                                  cert_user_objs->msgs[0],
                                                  SYSDB_NAME, NULL);
                if (cert_user == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Certificate user object has not name.\n");
                    ret = ENOENT;
                    goto done;
                }

                DEBUG(SSSDBG_FUNC_DATA,
                      "Found certificate user [%s].\n", cert_user);

                ret = sss_parse_name_for_domains(preq->pd,
                                               preq->cctx->rctx->domains,
                                               preq->cctx->rctx->default_domain,
                                               cert_user,
                                               &preq->pd->domain,
                                               &preq->pd->user);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sss_parse_name_for_domains failed.\n");
                    goto done;
                }
            }

            if (get_user_name_hint(preq->cctx->rctx->domains)
                    && preq->pd->cmd == SSS_PAM_PREAUTH) {
                ret = add_pam_cert_response(preq->pd,
                                            preq->cctx->rctx->domains, cert_user,
                                            preq->cert_list,
                                            SSS_PAM_CERT_INFO_WITH_HINT);
                preq->pd->pam_status = PAM_SUCCESS;
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "add_pam_cert_response failed.\n");
                    preq->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
                }
                ret = EOK;
                pam_reply(preq);
                goto done;
            }

            /* Without user name hints the certificate must map to single user
             * if no login name was given */
            if (cert_user == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "More than one user mapped to certificate.\n");
                ret = ERR_NO_CREDS;
                goto done;
            }

            /* If logon_name was not given during authentication add a
             * SSS_PAM_CERT_INFO message to send the name to the caller. */
            if (preq->pd->cmd == SSS_PAM_AUTHENTICATE
                    && preq->pd->logon_name == NULL) {
                ret = add_pam_cert_response(preq->pd,
                                            preq->cctx->rctx->domains, cert_user,
                                            preq->cert_list,
                                            SSS_PAM_CERT_INFO);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "add_pam_cert_response failed.\n");
                    preq->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
                    goto done;
                }
            }

            /* cert_user will be returned to the PAM client as user name, so
             * we can use it here already e.g. to set in initgroups timeout */
            preq->pd->logon_name = talloc_strdup(preq->pd, cert_user);
            if (preq->pd->logon_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        }
    }

    if (preq->user_obj == NULL) {
        ret = pam_check_user_search(preq);
    } else {
        ret = EOK;
    }

    if (ret == EOK) {
        pam_dom_forwarder(preq);
    }

done:
    pam_check_user_done(preq, ret);
}

static void pam_forwarder_cb(struct tevent_req *req)
{
    struct pam_auth_req *preq = tevent_req_callback_data(req,
                                                         struct pam_auth_req);
    struct cli_ctx *cctx = preq->cctx;
    struct pam_data *pd;
    errno_t ret = EOK;
    struct pam_ctx *pctx =
            talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        goto done;
    }

    ret = p11_refresh_certmap_ctx(pctx, pctx->rctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "p11_refresh_certmap_ctx failed, "
              "certificate matching might not work as expected");
    }

    pd = preq->pd;

    ret = pam_forwarder_parse_data(cctx, pd);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_FUNC, "Assuming %s is a UPN\n", pd->logon_name);
        /* If not, cache_req will error out later */
        pd->user = talloc_strdup(pd, pd->logon_name);
        if (pd->user == NULL) {
            ret = ENOMEM;
            goto done;
        }
        pd->domain = NULL;
    } else if (ret != EOK) {
        ret = EINVAL;
        goto done;
    }

    /* try backend first for authentication before doing local Smartcard
     * authentication */
    if (pd->cmd != SSS_PAM_AUTHENTICATE && may_do_cert_auth(pctx, pd)) {
        ret = check_cert(cctx, cctx->ev, pctx, preq, pd);
        /* Finish here */
        goto done;
    }

#ifdef BUILD_PASSKEY
    /* This is set to false inside passkey_local() if no passkey data is found.
     * It is checked in pam_reply() to avoid an endless loop */
    preq->passkey_data_exists = true;

    if ((pd->cmd == SSS_PAM_AUTHENTICATE)) {
        if (may_do_passkey_auth(pctx, pd)) {
            if (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_PASSKEY_KRB) {
                ret = passkey_kerberos(pctx, preq->pd, preq);
                goto done;
            } else if ((sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_PASSKEY) ||
                      (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_EMPTY)) {
                ret = passkey_local(cctx, cctx->ev, pctx, preq, pd);
                goto done;
            }
        }
    }
#endif /* BUILD_PASSKEY */

    ret = pam_check_user_search(preq);

done:
    pam_check_user_done(preq, ret);
}

static void pam_check_user_search_next(struct tevent_req *req);
static void pam_check_user_search_lookup(struct tevent_req *req);
static void pam_check_user_search_done(struct pam_auth_req *preq, int ret,
                                       struct cache_req_result *result);

/* lookup the user uid from the cache first,
 * then we'll refresh initgroups if needed */
int pam_check_user_search(struct pam_auth_req *preq)
{
    struct tevent_req *dpreq;
    struct cache_req_data *data;

    data = cache_req_data_name(preq,
                               CACHE_REQ_INITGROUPS,
                               preq->pd->logon_name);
    if (data == NULL) {
        return ENOMEM;
    }

    cache_req_data_set_bypass_cache(data, false);
    cache_req_data_set_bypass_dp(data, true);
    cache_req_data_set_requested_domains(data, preq->pd->requested_domains);

    dpreq = cache_req_send(preq,
                           preq->cctx->rctx->ev,
                           preq->cctx->rctx,
                           preq->cctx->rctx->ncache,
                           0,
                           preq->req_dom_type,
                           NULL,
                           data);
    if (!dpreq) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Out of memory sending data provider request\n");
        return ENOMEM;
    }

    tevent_req_set_callback(dpreq, pam_check_user_search_next, preq);

    /* tell caller we are in an async call */
    return EAGAIN;
}

static void pam_check_user_search_next(struct tevent_req *req)
{
    struct pam_auth_req *preq;
    struct pam_ctx *pctx;
    struct cache_req_result *result = NULL;
    struct cache_req_data *data;
    struct tevent_req *dpreq;
    int ret;

    preq = tevent_req_callback_data(req, struct pam_auth_req);
    pctx = talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);

    ret = cache_req_single_domain_recv(preq, req, &result);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "Cache lookup failed, trying to get fresh "
                                 "data from the backend.\n");
    }

    DEBUG(SSSDBG_TRACE_ALL, "PAM initgroups scheme [%s].\n",
          pam_initgroup_enum_to_string(pctx->initgroups_scheme));

    if (ret == EOK) {
        bool user_has_session = false;

        if (pctx->initgroups_scheme == PAM_INITGR_NO_SESSION) {
            uid_t uid = ldb_msg_find_attr_as_uint64(result->msgs[0],
                                                    SYSDB_UIDNUM, 0);
            if (!uid) {
                DEBUG(SSSDBG_CRIT_FAILURE, "A user with no UID?\n");
                talloc_zfree(preq->cctx);
                return;
            }

            /* If a user already has a session on the system, we take the
             * cache for granted and do not force an online lookup. This is
             * because in most cases the user is just trying to authenticate
             * but not create a new session (sudo, lockscreen, polkit, etc.)
             * An online refresh in this situation would just delay operations
             * without providing any useful additional information.
             */
            (void)check_if_uid_is_active(uid, &user_has_session);

            DEBUG(SSSDBG_TRACE_ALL, "Found %s session for uid %"SPRIuid".\n",
                                    user_has_session ? "a" : "no", uid);
        }

        /* The initgr cache is used to make sure that during a single PAM
         * session (auth, acct_mgtm, ....) the backend is contacted only
         * once. logon_name is the name provided by the PAM client and
         * will not be modified during the request, so it makes sense to
         * use it here instead od the pd->user.
         */
        ret = pam_initgr_check_timeout(pctx->id_table, preq->pd->logon_name);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not look up initgroup timeout\n");
        }

        if ((ret == EOK) || user_has_session
                || pctx->initgroups_scheme == PAM_INITGR_NEVER) {
            DEBUG(SSSDBG_TRACE_ALL, "No new initgroups needed because:\n");
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_ALL, "PAM initgr cache still valid.\n");
            } else if (user_has_session) {
                DEBUG(SSSDBG_TRACE_ALL, "there is a active session for "
                                        "user [%s].\n", preq->pd->logon_name);
            } else if (pctx->initgroups_scheme == PAM_INITGR_NEVER) {
                DEBUG(SSSDBG_TRACE_ALL, "initgroups scheme is 'never'.\n");
            }
            pam_check_user_search_done(preq, EOK, result);
            return;
        }
    }

    /* If we get here it means the user was not found or does not have a
     * session, or initgr has not been cached before, so we force a new
     * online lookup */
    data = cache_req_data_name(preq,
                               CACHE_REQ_INITGROUPS,
                               preq->pd->logon_name);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        talloc_zfree(preq->cctx);
        return;
    }
    cache_req_data_set_bypass_cache(data, true);
    cache_req_data_set_bypass_dp(data, false);
    cache_req_data_set_requested_domains(data, preq->pd->requested_domains);

    dpreq = cache_req_send(preq,
                           preq->cctx->rctx->ev,
                           preq->cctx->rctx,
                           preq->cctx->rctx->ncache,
                           0,
                           preq->req_dom_type,
                           NULL,
                           data);
    if (!dpreq) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Out of memory sending data provider request\n");
        talloc_zfree(preq->cctx);
        return;
    }

    tevent_req_set_callback(dpreq, pam_check_user_search_lookup, preq);
}

static void pam_check_user_search_lookup(struct tevent_req *req)
{
    struct cache_req_result *result;
    struct pam_auth_req *preq;
    int ret;

    preq = tevent_req_callback_data(req, struct pam_auth_req);

    ret = cache_req_single_domain_recv(preq, req, &result);
    talloc_zfree(req);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Fatal error, killing connection!\n");
        talloc_zfree(preq->cctx);
        return;
    }

    pam_check_user_search_done(preq, ret, result);
}

static void pam_check_user_search_done(struct pam_auth_req *preq, int ret,
                                       struct cache_req_result *result)
{
    struct pam_ctx *pctx;

    pctx = talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);

    if (ret == EOK) {
        preq->user_obj = result->msgs[0];
        pd_set_primary_name(preq->user_obj, preq->pd);
        preq->domain = result->domain;

        ret = pam_initgr_cache_set(pctx->rctx->ev,
                                   pctx->id_table,
                                   preq->pd->logon_name,
                                   pctx->id_timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not save initgr timestamp."
                  "Proceeding with PAM actions\n");
        }

        pam_dom_forwarder(preq);
    }

    ret = pam_check_user_done(preq, ret);
    if (ret != EOK) {
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
    }
}

int pam_check_user_done(struct pam_auth_req *preq, int ret)
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

    case ERR_P11_PIN_LOCKED:
        preq->pd->pam_status = PAM_AUTH_ERR;
        pam_reply(preq);
        break;

    case ERR_NO_CREDS:
        preq->pd->pam_status = PAM_CRED_INSUFFICIENT;
        pam_reply(preq);
        break;

    default:
        preq->pd->pam_status = PAM_SYSTEM_ERR;
        pam_reply(preq);
        break;
    }

    return EOK;
}

static errno_t pam_is_last_online_login_fresh(struct sss_domain_info *domain,
                                              const char* user,
                                              int cached_auth_timeout,
                                              bool *_result)
{
    errno_t ret;
    bool result = true;
    uint64_t last_login;

    ret = pam_get_last_online_auth_with_curr_token(domain, user, &last_login);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sysdb_get_last_online_auth_with_curr_token failed: %s:[%d]\n",
              sss_strerror(ret), ret);
        goto done;
    }

    result = time(NULL) < (last_login + cached_auth_timeout);
    ret = EOK;

done:
    if (ret == EOK) {
        *_result = result;
    }
    return ret;
}

static bool pam_is_authtok_cachable(struct sss_auth_token *authtok)
{
    enum sss_authtok_type type;
    bool cachable = false;

    type = sss_authtok_get_type(authtok);
    if (type == SSS_AUTHTOK_TYPE_PASSWORD) {
        cachable = true;
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "Authentication token can't be cached\n");
    }

    return cachable;
}

static bool pam_can_user_cache_auth(struct sss_domain_info *domain,
                                    int pam_cmd,
                                    struct sss_auth_token *authtok,
                                    const char* user,
                                    bool cached_auth_failed)
{
    errno_t ret;
    bool result = false;

    if (cached_auth_failed) {
        /* Do not retry indefinitely */
        return false;
    }

    if (!domain->cache_credentials || domain->cached_auth_timeout <= 0) {
        return false;
    }

    if (pam_cmd == SSS_PAM_PREAUTH
        || (pam_cmd == SSS_PAM_AUTHENTICATE
            && pam_is_authtok_cachable(authtok))) {

        ret = pam_is_last_online_login_fresh(domain, user,
                                             domain->cached_auth_timeout,
                                             &result);
        if (ret != EOK) {
            /* non-critical, consider fail as 'non-fresh value' */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "pam_is_last_online_login_fresh failed: %s:[%d]\n",
                  sss_strerror(ret), ret);
        }
    }

    return result;
}

static void pam_dom_forwarder(struct pam_auth_req *preq)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;
    struct pam_ctx *pctx =
            talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);
    const char *cert_user;
    struct ldb_result *cert_user_objs;
    bool sc_auth;
    bool passkey_auth;
    size_t c;
    char *local_policy = NULL;
    bool found = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return;
    }

    if (!preq->pd->domain) {
        preq->pd->domain = preq->domain->name;
    }

    /* Untrusted users can access only public domains. */
    if (!preq->is_uid_trusted &&
            !is_domain_public(preq->pd->domain, pctx->public_domains,
                            pctx->public_domains_count)) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Untrusted user %"SPRIuid" cannot access non-public domain %s.\n",
              client_euid(preq->cctx->creds), preq->pd->domain);
        preq->pd->pam_status = PAM_PERM_DENIED;
        pam_reply(preq);
        return;
    }

    /* skip this domain if not requested and the user is trusted
     * as untrusted users can't request a domain */
    if (preq->is_uid_trusted &&
            !is_domain_requested(preq->pd, preq->pd->domain)) {
        preq->pd->pam_status = PAM_USER_UNKNOWN;
        pam_reply(preq);
        return;
    }

    if (pam_can_user_cache_auth(preq->domain,
                                preq->pd->cmd,
                                preq->pd->authtok,
                                preq->pd->user,
                                preq->cached_auth_failed)) {
        preq->use_cached_auth = true;
        pam_reply(preq);
        return;
    }

    /* Skip online auth when local auth policy = only  */
#ifdef BUILD_PASSKEY
    if (may_do_cert_auth(pctx, preq->pd) || may_do_passkey_auth(pctx, preq->pd)) {
#else
    if (may_do_cert_auth(pctx, preq->pd)) {
#endif /* BUILD_PASSKEY */
        if (preq->domain->name != NULL) {
            ret = pam_eval_local_auth_policy(preq->cctx, pctx, preq->pd, preq,
                                             &sc_auth,
                                             &passkey_auth,
                                             &local_policy);
            if (ret != EOK) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Failed to evaluate local auth policy\n");
                preq->pd->pam_status = PAM_AUTH_ERR;
                pam_reply(preq);
                return;
            }
        }
    }

    if (may_do_cert_auth(pctx, preq->pd) && preq->cert_list != NULL) {
        /* Check if user matches certificate user */
        found = false;
        for (preq->current_cert = preq->cert_list;
             preq->current_cert != NULL;
             preq->current_cert = sss_cai_get_next(preq->current_cert)) {

            cert_user_objs = sss_cai_get_cert_user_objs(preq->current_cert);
            if (cert_user_objs == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Unexpected missing certificate user, "
                      "trying next certificate.\n");
                continue;
            }

            for (c = 0; c < cert_user_objs->count; c++) {
                cert_user = ldb_msg_find_attr_as_string(cert_user_objs->msgs[c],
                                                        SYSDB_NAME, NULL);
                if (cert_user == NULL) {
                    /* Even if there might be other users mapped to the
                     * certificate a missing SYSDB_NAME indicates some critical
                     * condition which justifies that the whole request is aborted
                     * */
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Certificate user object has no name.\n");
                    preq->pd->pam_status = PAM_USER_UNKNOWN;
                    pam_reply(preq);
                    return;
                }

                if (ldb_dn_compare(cert_user_objs->msgs[c]->dn,
                                   preq->user_obj->dn) == 0) {
                    found = true;
                    if (preq->pd->cmd == SSS_PAM_PREAUTH) {
                        ret = sss_authtok_set_sc(preq->pd->authtok,
                                 SSS_AUTHTOK_TYPE_SC_PIN, NULL, 0,
                                 sss_cai_get_token_name(preq->current_cert), 0,
                                 sss_cai_get_module_name(preq->current_cert), 0,
                                 sss_cai_get_key_id(preq->current_cert), 0,
                                 sss_cai_get_label(preq->current_cert), 0);
                        if (ret != EOK) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "sss_authtok_set_sc failed, Smartcard "
                                  "authentication detection might fail in "
                                  "the backend.\n");
                        }

                        ret = add_pam_cert_response(preq->pd,
                                                    preq->cctx->rctx->domains,
                                                    cert_user,
                                                    preq->current_cert,
                                                    SSS_PAM_CERT_INFO);
                        if (ret != EOK) {
                            DEBUG(SSSDBG_OP_FAILURE, "add_pam_cert_response failed.\n");
                            preq->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
                        }
                    }

                }
            }
        }

        if (found) {
            if (local_policy != NULL && strcasecmp(local_policy, "only") == 0) {
                talloc_free(tmp_ctx);
                DEBUG(SSSDBG_IMPORTANT_INFO, "Local auth only set, skipping online auth\n");
                if (preq->pd->cmd == SSS_PAM_PREAUTH) {
                    preq->pd->pam_status = PAM_SUCCESS;
                } else if (preq->pd->cmd == SSS_PAM_AUTHENTICATE
                                && IS_SC_AUTHTOK(preq->pd->authtok)
                                && preq->cert_auth_local) {
                    preq->pd->pam_status = PAM_SUCCESS;
                    preq->callback = pam_reply;
                }

                pam_reply(preq);
                return;
            }

            /* We are done if we do not have to call the backend */
            if (preq->pd->cmd == SSS_PAM_AUTHENTICATE
                    && preq->cert_auth_local) {
                preq->pd->pam_status = PAM_SUCCESS;
                preq->callback = pam_reply;
                pam_reply(preq);
                return;
            }
        } else {
            if (preq->pd->cmd == SSS_PAM_PREAUTH) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "User and certificate user do not match, "
                      "continue with other authentication methods.\n");
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "User and certificate user do not match.\n");
                preq->pd->pam_status = PAM_AUTH_ERR;
                pam_reply(preq);
                return;
            }
        }
    }

    if (local_policy != NULL && strcasecmp(local_policy, "only") == 0) {
        talloc_free(tmp_ctx);
        DEBUG(SSSDBG_IMPORTANT_INFO, "Local auth only set, skipping online auth\n");
        if (preq->pd->cmd == SSS_PAM_PREAUTH) {
            preq->pd->pam_status = PAM_SUCCESS;
        } else if (preq->pd->cmd == SSS_PAM_AUTHENTICATE && IS_SC_AUTHTOK(preq->pd->authtok)) {
            /* Trigger offline smartcardcard autheitcation */
            preq->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        }

        pam_reply(preq);
        return;
    }

    preq->callback = pam_reply;
    ret = pam_dp_send_req(preq);
    DEBUG(SSSDBG_CONF_SETTINGS, "pam_dp_send_req returned %d\n", ret);

    talloc_free(tmp_ctx);

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

static int pam_cmd_preauth(struct cli_ctx *cctx)
{
    DEBUG(SSSDBG_CONF_SETTINGS, "entering pam_cmd_preauth\n");
    return pam_forwarder(cctx, SSS_PAM_PREAUTH);
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
        {SSS_PAM_PREAUTH, pam_cmd_preauth},
        {SSS_GSSAPI_INIT, pam_cmd_gssapi_init},
        {SSS_GSSAPI_SEC_CTX, pam_cmd_gssapi_sec_ctx},
        {SSS_CLI_NULL, NULL}
    };

    return sss_cmds;
}

errno_t
pam_set_last_online_auth_with_curr_token(struct sss_domain_info *domain,
                                         const char *username,
                                         uint64_t value)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *attrs;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs,
                                 SYSDB_LAST_ONLINE_AUTH_WITH_CURR_TOKEN,
                                 value);
    if (ret != EOK) { goto done; }

    ret = sysdb_set_user_attr(domain, username, attrs, SYSDB_MOD_REP);
    if (ret != EOK) { goto done; }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, sss_strerror(ret));
    }

    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t
pam_null_last_online_auth_with_curr_token(struct sss_domain_info *domain,
                                          const char *username)
{
    return pam_set_last_online_auth_with_curr_token(domain, username, 0);
}

static errno_t
pam_get_last_online_auth_with_curr_token(struct sss_domain_info *domain,
                                         const char *name,
                                         uint64_t *_value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *attrs[] = { SYSDB_LAST_ONLINE_AUTH_WITH_CURR_TOKEN, NULL };
    struct ldb_message *ldb_msg;
    uint64_t value = 0;
    errno_t ret;

    if (name == NULL || *name == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing user name.\n");
        ret = EINVAL;
        goto done;
    }

    if (domain->sysdb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing sysdb db context.\n");
        ret = EINVAL;
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_user_by_name(tmp_ctx, domain, name, attrs, &ldb_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_search_user_by_name failed [%d][%s].\n",
              ret, strerror(ret));
        goto done;
    }

    /* Check offline_auth_cache_timeout */
    value = ldb_msg_find_attr_as_uint64(ldb_msg,
                                        SYSDB_LAST_ONLINE_AUTH_WITH_CURR_TOKEN,
                                        0);
    ret = EOK;

done:
    if (ret == EOK) {
        *_value = value;
    }

    talloc_free(tmp_ctx);
    return ret;
}
