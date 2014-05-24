/*
    SSSD

    LDAP Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2008 Red Hat
    Copyright (C) 2010, rhafer@suse.de, Novell Inc.

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

#ifdef WITH_MOZLDAP
#define LDAP_OPT_SUCCESS LDAP_SUCCESS
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID  ((ber_tag_t) 0x80U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_OLD ((ber_tag_t) 0x81U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW ((ber_tag_t) 0x82U)
#endif

#include "config.h"

#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <strings.h>

#include <shadow.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/user_info_msg.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_private.h"

#define LDAP_PWEXPIRE_WARNING_TIME 0

enum pwexpire {
    PWEXPIRE_NONE = 0,
    PWEXPIRE_LDAP_PASSWORD_POLICY,
    PWEXPIRE_KERBEROS,
    PWEXPIRE_SHADOW
};

static errno_t add_expired_warning(struct pam_data *pd, long exp_time)
{
    int ret;
    uint32_t *data;

    if (exp_time < 0 || exp_time > UINT32_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Time to expire out of range.\n");
        return EINVAL;
    }

    data = talloc_array(pd, uint32_t, 2);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    data[0] = SSS_PAM_USER_INFO_EXPIRE_WARN;
    data[1] = (uint32_t) exp_time;

    ret = pam_add_response(pd, SSS_PAM_USER_INFO, 2 * sizeof(uint32_t),
                           (uint8_t *) data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
    }

    return EOK;
}

static errno_t check_pwexpire_kerberos(const char *expire_date, time_t now,
                                       struct pam_data *pd,
                                       int pwd_exp_warning)
{
    char *end;
    struct tm tm;
    time_t expire_time;
    int expiration_warning;
    int ret = ERR_INTERNAL;

    memset(&tm, 0, sizeof(tm));

    end = strptime(expire_date, "%Y%m%d%H%M%SZ", &tm);
    if (end == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Kerberos expire date [%s] invalid.\n", expire_date);
        return EINVAL;
    }
    if (*end != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Kerberos expire date [%s] contains extra characters.\n",
                  expire_date);
        return EINVAL;
    }

    expire_time = mktime(&tm);
    if (expire_time == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "mktime failed to convert [%s].\n", expire_date);
        return EINVAL;
    }

    tzset();
    expire_time -= timezone;
    DEBUG(SSSDBG_TRACE_ALL,
          "Time info: tzname[0] [%s] tzname[1] [%s] timezone [%ld] "
           "daylight [%d] now [%ld] expire_time [%ld].\n", tzname[0],
           tzname[1], timezone, daylight, now, expire_time);

    if (difftime(now, expire_time) > 0.0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Kerberos password expired.\n");
        ret = ERR_PASSWORD_EXPIRED;
    } else {
        if (pwd_exp_warning >= 0) {
            expiration_warning = pwd_exp_warning;
        } else {
            expiration_warning = KERBEROS_PWEXPIRE_WARNING_TIME;
        }
        if (pd != NULL &&
            (difftime(now + expiration_warning, expire_time) > 0.0 ||
            expiration_warning == 0)) {
            ret = add_expired_warning(pd, (long) difftime(expire_time, now));
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "add_expired_warning failed.\n");
            }
        }
        ret = EOK;
    }

    return ret;
}

static errno_t check_pwexpire_shadow(struct spwd *spwd, time_t now,
                                     struct pam_data *pd)
{
    long today;
    long password_age;
    long exp;
    int ret;

    if (spwd->sp_lstchg <= 0) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Last change day is not set, new password needed.\n");
        return ERR_PASSWORD_EXPIRED;
    }

    today = (long) (now / (60 * 60 *24));
    password_age = today - spwd->sp_lstchg;
    if (password_age < 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "The last password change time is in the future!.\n");
        return EOK;
    }

    if ((spwd->sp_expire != -1 && today > spwd->sp_expire) ||
        (spwd->sp_max != -1 && spwd->sp_inact != -1 &&
         password_age > spwd->sp_max + spwd->sp_inact))
    {
        DEBUG(SSSDBG_CONF_SETTINGS, "Account expired.\n");
        return ERR_ACCOUNT_EXPIRED;
    }

    if (spwd->sp_max != -1 && password_age > spwd->sp_max) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Password expired.\n");
        return ERR_PASSWORD_EXPIRED;
    }

    if (pd != NULL && spwd->sp_max != -1 && spwd->sp_warn != -1 &&
        password_age > spwd->sp_max - spwd->sp_warn ) {

        /* add_expired_warning() expects time in seconds */
        exp = (spwd->sp_max - password_age) * (60 * 60 * 24);
        if (exp == 0) {
            /* Seconds until next midnight */
            exp = ((today + 1) * (60 * 60 * 24)) - now;
        }

        ret = add_expired_warning(pd, exp);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "add_expired_warning failed.\n");
        }
    }

    return EOK;
}

static errno_t check_pwexpire_ldap(struct pam_data *pd,
                                   struct sdap_ppolicy_data *ppolicy,
                                   int pwd_exp_warning)
{
    int ret = EOK;

    if (ppolicy->grace >= 0 || ppolicy->expire > 0) {
        uint32_t *data;
        uint32_t *ptr;

        if (pwd_exp_warning < 0) {
            pwd_exp_warning = 0;
        }

        data = talloc_size(pd, 2* sizeof(uint32_t));
        if (data == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
            return ENOMEM;
        }

        ptr = data;
        if (ppolicy->grace >= 0) {
            *ptr = SSS_PAM_USER_INFO_GRACE_LOGIN;
            ptr++;
            *ptr = ppolicy->grace;
        } else if (ppolicy->expire > 0) {
            if (pwd_exp_warning != 0 && ppolicy->expire > pwd_exp_warning) {
                /* do not warn */
                goto done;
            }

            /* send warning */
            *ptr = SSS_PAM_USER_INFO_EXPIRE_WARN;
            ptr++;
            *ptr = ppolicy->expire;
        }

        ret = pam_add_response(pd, SSS_PAM_USER_INFO, 2* sizeof(uint32_t),
                               (uint8_t*)data);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }
    }

done:
    return ret;
}

static errno_t find_password_expiration_attributes(TALLOC_CTX *mem_ctx,
                                               const struct ldb_message *msg,
                                               struct dp_option *opts,
                                               enum pwexpire *type, void **data)
{
    const char *mark;
    const char *val;
    struct spwd *spwd;
    const char *pwd_policy;
    int ret;

    *type = PWEXPIRE_NONE;
    *data = NULL;

    pwd_policy = dp_opt_get_string(opts, SDAP_PWD_POLICY);
    if (pwd_policy == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing password policy.\n");
        return EINVAL;
    }

    if (strcasecmp(pwd_policy, PWD_POL_OPT_NONE) == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "No password policy requested.\n");
        return EOK;
    } else if (strcasecmp(pwd_policy, PWD_POL_OPT_MIT) == 0) {
        mark = ldb_msg_find_attr_as_string(msg, SYSDB_KRBPW_LASTCHANGE, NULL);
        if (mark != NULL) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Found Kerberos password expiration attributes.\n");
            val = ldb_msg_find_attr_as_string(msg, SYSDB_KRBPW_EXPIRATION,
                                              NULL);
            if (val != NULL) {
                *data = talloc_strdup(mem_ctx, val);
                if (*data == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
                    return ENOMEM;
                }
                *type = PWEXPIRE_KERBEROS;

                return EOK;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "No Kerberos password expiration attributes found, "
                      "but MIT Kerberos password policy was requested. "
                      "Access will be denied.\n");
            return EACCES;
        }
    } else if (strcasecmp(pwd_policy, PWD_POL_OPT_SHADOW) == 0) {
        mark = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_LASTCHANGE, NULL);
        if (mark != NULL) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Found shadow password expiration attributes.\n");
            spwd = talloc_zero(mem_ctx, struct spwd);
            if (spwd == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
                return ENOMEM;
            }

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_LASTCHANGE, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_lstchg);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_MIN, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_min);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_MAX, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_max);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_WARNING, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_warn);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_INACTIVE, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_inact);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_EXPIRE, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_expire);
            if (ret != EOK) goto shadow_fail;

            *data = spwd;
            *type = PWEXPIRE_SHADOW;

            return EOK;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "No shadow password attributes found, "
                      "but shadow password policy was requested. "
                      "Access will be denied.\n");
            return EACCES;
        }
    }

    DEBUG(SSSDBG_TRACE_ALL, "No password expiration attributes found.\n");
    return EOK;

shadow_fail:
        talloc_free(spwd);
        return ret;
}

/* ==Get-User-DN========================================================== */
struct get_user_dn_state {
    const char *username;

    char *orig_dn;
};

static void get_user_dn_done(struct tevent_req *subreq);

static struct tevent_req *get_user_dn_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sss_domain_info *domain,
                                           struct sdap_handle *sh,
                                           struct sdap_options *opts,
                                           const char *username)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct get_user_dn_state *state;
    char *clean_name;
    char *filter;
    const char **attrs;
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct get_user_dn_state);
    if (!req) return NULL;

    state->username = username;

    ret = sss_filter_sanitize(state, username, &clean_name);
    if (ret != EOK) {
        goto done;
    }

    filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                             opts->user_map[SDAP_AT_USER_NAME].name,
                             clean_name,
                             opts->user_map[SDAP_OC_USER].name);
    talloc_zfree(clean_name);
    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build the base filter\n");
        ret = ENOMEM;
        goto done;
    }

    /* We're mostly interested in the DN anyway */
    attrs = talloc_array(state, const char *, 3);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }
    attrs[0] = "objectclass";
    attrs[1] = opts->user_map[SDAP_AT_USER_NAME].name;
    attrs[2] = NULL;

    subreq = sdap_search_user_send(state, ev, domain, opts,
                                   opts->sdom->user_search_bases,
                                   sh, attrs, filter,
                                   dp_opt_get_int(opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, get_user_dn_done, req);
    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void get_user_dn_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_user_dn_state *state = tevent_req_data(req,
                                                    struct get_user_dn_state);
    struct ldb_message_element *el;
    struct sysdb_attrs **users;
    size_t count;

    ret = sdap_search_user_recv(state, subreq, NULL, &users, &count);
    talloc_zfree(subreq);
    if (ret && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve users\n");
        tevent_req_error(req, ret);
        return;
    }

    if (count == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "No such user\n");
        tevent_req_error(req, ENOMEM);
        return;
    } else if (count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Multiple users matched\n");
        tevent_req_error(req, EIO);
        return;
    }

    /* exactly one user. Get the originalDN */
    ret = sysdb_attrs_get_el_ext(users[0], SYSDB_ORIG_DN, false, &el);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "originalDN is not available for [%s].\n", state->username);
        tevent_req_error(req, ret);
        return;
    }

    state->orig_dn = talloc_strdup(state, (const char *) el->values[0].data);
    if (state->orig_dn == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Found originalDN [%s] for [%s]\n",
          state->orig_dn, state->username);
    tevent_req_done(req);
}

static int get_user_dn_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req,
                            char **orig_dn)
{
    struct get_user_dn_state *state = tevent_req_data(req,
                                                    struct get_user_dn_state);

    if (orig_dn) {
        *orig_dn = talloc_move(mem_ctx, &state->orig_dn);
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static int get_user_dn(TALLOC_CTX *memctx,
                       struct sss_domain_info *domain,
                       struct sdap_options *opts,
                       const char *username,
                       char **user_dn,
                       enum pwexpire *user_pw_expire_type,
                       void **user_pw_expire_data)
{
    TALLOC_CTX *tmpctx;
    enum pwexpire pw_expire_type;
    void *pw_expire_data;
    struct ldb_result *res;
    const char **attrs;
    const char *dn;
    int ret;

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    attrs = talloc_array(tmpctx, const char *, 11);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    attrs[0] = SYSDB_ORIG_DN;
    attrs[1] = SYSDB_SHADOWPW_LASTCHANGE;
    attrs[2] = SYSDB_SHADOWPW_MIN;
    attrs[3] = SYSDB_SHADOWPW_MAX;
    attrs[4] = SYSDB_SHADOWPW_WARNING;
    attrs[5] = SYSDB_SHADOWPW_INACTIVE;
    attrs[6] = SYSDB_SHADOWPW_EXPIRE;
    attrs[7] = SYSDB_KRBPW_LASTCHANGE;
    attrs[8] = SYSDB_KRBPW_EXPIRATION;
    attrs[9] = SYSDB_PWD_ATTRIBUTE;
    attrs[10] = NULL;

    ret = sysdb_get_user_attr(tmpctx, domain, username, attrs, &res);
    if (ret) {
        goto done;
    }

    switch (res->count) {
    case 0:
        /* No such user entry? Look it up */
        ret = EAGAIN;
        break;

    case 1:
        dn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_ORIG_DN, NULL);
        if (dn == NULL) {
            /* The user entry has no original DN. This is the case when the ID
             * provider is not LDAP-based (proxy perhaps) */
            ret = EAGAIN;
            break;
        }

        dn = talloc_strdup(tmpctx, dn);
        if (!dn) {
            ret = ENOMEM;
            break;
        }

        ret = find_password_expiration_attributes(tmpctx,
                                                  res->msgs[0],
                                                  opts->basic,
                                                  &pw_expire_type,
                                                  &pw_expire_data);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "find_password_expiration_attributes failed.\n");
        }
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "User search by name (%s) returned > 1 results!\n",
                  username);
        ret = EFAULT;
        break;
    }

done:
    if (ret == EOK) {
        *user_dn = talloc_strdup(memctx, dn);
        if (!*user_dn) {
            ret = ENOMEM;
        }
        /* pw_expire_data may be NULL */
        *user_pw_expire_data = talloc_steal(memctx, pw_expire_data);
        *user_pw_expire_type = pw_expire_type;
    }

    talloc_zfree(tmpctx);
    return ret;
}

/* ==Authenticate-User==================================================== */

struct auth_state {
    struct tevent_context *ev;
    struct sdap_auth_ctx *ctx;
    const char *username;
    struct sss_auth_token *authtok;
    struct sdap_service *sdap_service;

    struct sdap_handle *sh;

    char *dn;
    enum pwexpire pw_expire_type;
    void *pw_expire_data;

    struct fo_server *srv;
};

static struct tevent_req *auth_get_server(struct tevent_req *req);
static void auth_get_dn_done(struct tevent_req *subreq);
static void auth_do_bind(struct tevent_req *req);
static void auth_resolve_done(struct tevent_req *subreq);
static void auth_connect_done(struct tevent_req *subreq);
static void auth_bind_user_done(struct tevent_req *subreq);

static struct tevent_req *auth_send(TALLOC_CTX *memctx,
                                    struct tevent_context *ev,
                                    struct sdap_auth_ctx *ctx,
                                    const char *username,
                                    struct sss_auth_token *authtok,
                                    bool try_chpass_service)
{
    struct tevent_req *req;
    struct auth_state *state;

    req = tevent_req_create(memctx, &state, struct auth_state);
    if (!req) return NULL;

    /* The token must be a password token */
    if (sss_authtok_get_type(authtok) != SSS_AUTHTOK_TYPE_PASSWORD) {
        tevent_req_error(req, ERR_AUTH_FAILED);
        return tevent_req_post(req, ev);
    }

    state->ev = ev;
    state->ctx = ctx;
    state->username = username;
    state->authtok = authtok;
    state->srv = NULL;
    if (try_chpass_service && ctx->chpass_service != NULL &&
        ctx->chpass_service->name != NULL) {
        state->sdap_service = ctx->chpass_service;
    } else {
        state->sdap_service = ctx->service;
    }

    if (!auth_get_server(req)) goto fail;

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static struct tevent_req *auth_get_server(struct tevent_req *req)
{
    struct tevent_req *next_req;
    struct auth_state *state = tevent_req_data(req,
                                               struct auth_state);

     /* NOTE: this call may cause service->uri to be refreshed
      * with a new valid server. Do not use service->uri before */
    next_req = be_resolve_server_send(state,
                                      state->ev,
                                      state->ctx->be,
                                      state->sdap_service->name,
                                      state->srv == NULL ? true : false);
    if (!next_req) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_resolve_server_send failed.\n");
        return NULL;
    }

    tevent_req_set_callback(next_req, auth_resolve_done, req);
    return next_req;
}

static void auth_resolve_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;
    bool use_tls;

    ret = be_resolve_server_recv(subreq, &state->srv);
    talloc_zfree(subreq);
    if (ret) {
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, ETIMEDOUT);
        return;
    }

    /* Determine whether we need to use TLS */
    if (sdap_is_secure_uri(state->ctx->service->uri)) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "[%s] is a secure channel. No need to run START_TLS\n",
                  state->ctx->service->uri);
        use_tls = false;
    } else {

        /* Check for undocumented debugging feature to disable TLS
         * for authentication. This should never be used in production
         * for obvious reasons.
         */
        use_tls = !dp_opt_get_bool(state->ctx->opts->basic, SDAP_DISABLE_AUTH_TLS);
        if (!use_tls) {
            sss_log(SSS_LOG_ALERT, "LDAP authentication being performed over "
                                   "insecure connection. This should be done "
                                   "for debugging purposes only.");
        }
    }

    subreq = sdap_connect_send(state, state->ev, state->ctx->opts,
                               state->sdap_service->uri,
                               state->sdap_service->sockaddr, use_tls);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, auth_connect_done, req);
}

static void auth_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;

    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret) {
        if (state->srv) {
            /* mark this server as bad if connection failed */
            be_fo_set_port_status(state->ctx->be,
                                  state->sdap_service->name,
                                  state->srv, PORT_NOT_WORKING);
        }

        if (auth_get_server(req) == NULL) {
            tevent_req_error(req, ENOMEM);
        }
        return;
    } else if (state->srv) {
        be_fo_set_port_status(state->ctx->be, state->sdap_service->name,
                              state->srv, PORT_WORKING);
    }

    ret = get_user_dn(state, state->ctx->be->domain,
                      state->ctx->opts, state->username, &state->dn,
                      &state->pw_expire_type, &state->pw_expire_data);
    if (ret == EOK) {
        /* All required user data was pre-cached during an identity lookup.
         * We can proceed with the bind */
        auth_do_bind(req);
        return;
    } else if (ret == EAGAIN) {
        /* The cached user entry was missing the bind DN. Need to look
         * it up based on user name in order to perform the bind */
        subreq = get_user_dn_send(req, state->ev, state->ctx->be->domain,
                                  state->sh, state->ctx->opts, state->username);
        if (subreq == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, auth_get_dn_done, req);
        return;
    }

    tevent_req_error(req, ret);
    return;
}

static void auth_get_dn_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req, struct auth_state);
    errno_t ret;

    ret = get_user_dn_recv(state, subreq, &state->dn);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ERR_ACCOUNT_UNKNOWN);
        return;
    }

    /* The DN was found with an LDAP lookup
     * We can proceed with the bind */
    return auth_do_bind(req);
}

static void auth_do_bind(struct tevent_req *req)
{
    struct auth_state *state = tevent_req_data(req, struct auth_state);
    struct tevent_req *subreq;

    subreq = sdap_auth_send(state, state->ev, state->sh,
                            NULL, NULL, state->dn,
                            state->authtok);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, auth_bind_user_done, req);
}

static void auth_bind_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;
    struct sdap_ppolicy_data *ppolicy = NULL;

    ret = sdap_auth_recv(subreq, state, &ppolicy);
    talloc_zfree(subreq);
    if (ppolicy != NULL) {
        DEBUG(SSSDBG_TRACE_ALL,"Found ppolicy data, "
                 "assuming LDAP password policies are active.\n");
        state->pw_expire_type = PWEXPIRE_LDAP_PASSWORD_POLICY;
        state->pw_expire_data = ppolicy;
    }
    switch (ret) {
    case EOK:
        break;
    case ETIMEDOUT:
    case ERR_NETWORK_IO:
        if (auth_get_server(req) == NULL) {
            tevent_req_error(req, ENOMEM);
        }
        return;
    default:
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t auth_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                         struct sdap_handle **sh, char **dn,
                         enum pwexpire *pw_expire_type, void **pw_expire_data)
{
    struct auth_state *state = tevent_req_data(req, struct auth_state);

    if (sh != NULL) {
        *sh = talloc_steal(memctx, state->sh);
        if (*sh == NULL) return ENOMEM;
    }

    if (dn != NULL) {
        *dn = talloc_steal(memctx, state->dn);
        if (*dn == NULL) return ENOMEM;
    }

    if (pw_expire_data != NULL) {
        *pw_expire_data = talloc_steal(memctx, state->pw_expire_data);
    }

    *pw_expire_type = state->pw_expire_type;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==Perform-Password-Change===================== */

struct sdap_pam_chpass_state {
    struct be_req *breq;
    struct pam_data *pd;
    const char *username;
    char *dn;
    struct sdap_handle *sh;

    struct sdap_auth_ctx *ctx;
};

static void sdap_auth4chpass_done(struct tevent_req *req);
static void sdap_pam_chpass_done(struct tevent_req *req);

void sdap_pam_chpass_handler(struct be_req *breq)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(breq);
    struct sdap_pam_chpass_state *state;
    struct sdap_auth_ctx *ctx;
    struct tevent_req *subreq;
    struct pam_data *pd;
    int dp_err = DP_ERR_FATAL;

    ctx = talloc_get_type(be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                          struct sdap_auth_ctx);
    pd = talloc_get_type(be_req_get_data(breq), struct pam_data);

    if (be_is_offline(ctx->be)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Backend is marked offline, retry later!\n");
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    if ((pd->priv == 1) && (pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) &&
        (sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_PASSWORD)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Password reset by root is not supported.\n");
        pd->pam_status = PAM_PERM_DENIED;
        dp_err = DP_ERR_OK;
        goto done;
    }

    DEBUG(SSSDBG_OP_FAILURE,
          "starting password change request for user [%s].\n", pd->user);

    pd->pam_status = PAM_SYSTEM_ERR;

    if (pd->cmd != SSS_PAM_CHAUTHTOK && pd->cmd != SSS_PAM_CHAUTHTOK_PRELIM) {
        DEBUG(SSSDBG_OP_FAILURE,
              "chpass target was called by wrong pam command.\n");
        goto done;
    }

    state = talloc_zero(breq, struct sdap_pam_chpass_state);
    if (!state) goto done;

    state->breq = breq;
    state->pd = pd;
    state->username = pd->user;
    state->ctx = ctx;

    subreq = auth_send(breq, be_ctx->ev, ctx,
                       state->username, pd->authtok, true);
    if (!subreq) goto done;

    tevent_req_set_callback(subreq, sdap_auth4chpass_done, state);
    return;

done:
    be_req_terminate(breq, dp_err, pd->pam_status, NULL);
}

static void sdap_lastchange_done(struct tevent_req *req);
static void sdap_auth4chpass_done(struct tevent_req *req)
{
    struct sdap_pam_chpass_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_chpass_state);
    struct be_ctx *be_ctx = be_req_get_be_ctx(state->breq);
    struct tevent_req *subreq;
    enum pwexpire pw_expire_type;
    void *pw_expire_data;
    int dp_err = DP_ERR_FATAL;
    int ret;
    size_t msg_len;
    uint8_t *msg;

    ret = auth_recv(req, state, &state->sh, &state->dn,
                    &pw_expire_type, &pw_expire_data);
    talloc_zfree(req);
    if ((ret == EOK || ret == ERR_PASSWORD_EXPIRED) &&
        state->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Initial authentication for change password operation "
                  "successful.\n");
        state->pd->pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        goto done;
    }

    if (ret == EOK) {
        switch (pw_expire_type) {
        case PWEXPIRE_SHADOW:
            ret = check_pwexpire_shadow(pw_expire_data, time(NULL), NULL);
            break;
        case PWEXPIRE_KERBEROS:
            ret = check_pwexpire_kerberos(pw_expire_data, time(NULL), NULL,
                                          be_ctx->domain->pwd_expiration_warning);

            if (ret == ERR_PASSWORD_EXPIRED) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "LDAP provider cannot change kerberos "
                          "passwords.\n");
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            break;
        case PWEXPIRE_LDAP_PASSWORD_POLICY:
        case PWEXPIRE_NONE:
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknow pasword expiration type.\n");
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
        }
    }

    switch (ret) {
    case EOK:
    case ERR_PASSWORD_EXPIRED:
        DEBUG(SSSDBG_TRACE_LIBS,
              "user [%s] successfully authenticated.\n", state->dn);
        if (pw_expire_type == PWEXPIRE_SHADOW) {
/* TODO: implement async ldap modify request */
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Changing shadow password attributes not implemented.\n");
            state->pd->pam_status = PAM_MODULE_UNKNOWN;
            goto done;
        } else {
            const char *password;
            const char *new_password;

            ret = sss_authtok_get_password(state->pd->authtok,
                                           &password, NULL);
            if (ret) {
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            ret = sss_authtok_get_password(state->pd->newauthtok,
                                           &new_password, NULL);
            if (ret) {
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
            }

            subreq = sdap_exop_modify_passwd_send(state, be_ctx->ev,
                                                  state->sh, state->dn,
                                                  password, new_password);
            if (!subreq) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to change password for %s\n", state->username);
                goto done;
            }
            tevent_req_set_callback(subreq, sdap_pam_chpass_done, state);
            return;
        }
        break;
    case ERR_AUTH_DENIED:
    case ERR_AUTH_FAILED:
        state->pd->pam_status = PAM_AUTH_ERR;
        ret = pack_user_info_chpass_error(state->pd, "Old password not accepted.",
                                          &msg_len, &msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "pack_user_info_chpass_error failed.\n");
        } else {
            ret = pam_add_response(state->pd, SSS_PAM_USER_INFO, msg_len,
                                    msg);
            if (ret != EOK) {
               DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            }
        }

        break;
    case ETIMEDOUT:
    case ERR_NETWORK_IO:
        state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        be_mark_offline(be_ctx);
        dp_err = DP_ERR_OFFLINE;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }

done:
    be_req_terminate(state->breq, dp_err, state->pd->pam_status, NULL);
}

static void sdap_pam_chpass_done(struct tevent_req *req)
{
    struct sdap_pam_chpass_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_chpass_state);
    struct be_ctx *be_ctx = be_req_get_be_ctx(state->breq);
    int dp_err = DP_ERR_FATAL;
    int ret;
    char *user_error_message = NULL;
    char *lastchanged_name;
    struct tevent_req *subreq;
    size_t msg_len;
    uint8_t *msg;

    ret = sdap_exop_modify_passwd_recv(req, state, &user_error_message);
    talloc_zfree(req);

    switch (ret) {
    case EOK:
        state->pd->pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        break;
    case ERR_CHPASS_DENIED:
        state->pd->pam_status = PAM_NEW_AUTHTOK_REQD;
        break;
    case ERR_NETWORK_IO:
        state->pd->pam_status = PAM_AUTHTOK_ERR;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
        break;
    }

    if (state->pd->pam_status != PAM_SUCCESS && user_error_message != NULL) {
        ret = pack_user_info_chpass_error(state->pd, user_error_message,
                                            &msg_len, &msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pack_user_info_chpass_error failed.\n");
        } else {
            ret = pam_add_response(state->pd, SSS_PAM_USER_INFO, msg_len,
                                    msg);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            }
        }
    }

    if (state->pd->pam_status == PAM_SUCCESS &&
        dp_opt_get_bool(state->ctx->opts->basic,
                        SDAP_CHPASS_UPDATE_LAST_CHANGE)) {
        lastchanged_name = state->ctx->opts->user_map[SDAP_AT_SP_LSTCHG].name;

        subreq = sdap_modify_shadow_lastchange_send(state, be_ctx->ev,
                                                    state->sh, state->dn,
                                                    lastchanged_name);
        if (subreq == NULL) {
            state->pd->pam_status = PAM_SYSTEM_ERR;
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_lastchange_done, state);
        return;
    }

done:
    be_req_terminate(state->breq, dp_err, state->pd->pam_status, NULL);
}

static void sdap_lastchange_done(struct tevent_req *req)
{
    struct sdap_pam_chpass_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_chpass_state);
    int dp_err = DP_ERR_FATAL;
    errno_t ret;

    ret = sdap_modify_shadow_lastchange_recv(req);
    if (ret != EOK) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    dp_err = DP_ERR_OK;
    state->pd->pam_status = PAM_SUCCESS;

done:
    be_req_terminate(state->breq, dp_err, state->pd->pam_status, NULL);
}

/* ==Perform-User-Authentication-and-Password-Caching===================== */

struct sdap_pam_auth_state {
    struct be_req *breq;
    struct pam_data *pd;
};

static void sdap_pam_auth_done(struct tevent_req *req);

void sdap_pam_auth_handler(struct be_req *breq)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(breq);
    struct sdap_pam_auth_state *state;
    struct sdap_auth_ctx *ctx;
    struct tevent_req *subreq;
    struct pam_data *pd;
    int dp_err = DP_ERR_FATAL;

    ctx = talloc_get_type(be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                          struct sdap_auth_ctx);
    pd = talloc_get_type(be_req_get_data(breq), struct pam_data);

    if (be_is_offline(ctx->be)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Backend is marked offline, retry later!\n");
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    pd->pam_status = PAM_SYSTEM_ERR;

    switch (pd->cmd) {
    case SSS_PAM_AUTHENTICATE:
    case SSS_PAM_CHAUTHTOK_PRELIM:

        state = talloc_zero(breq, struct sdap_pam_auth_state);
        if (!state) goto done;

        state->breq = breq;
        state->pd = pd;

        subreq = auth_send(breq, be_ctx->ev, ctx,
                           pd->user, pd->authtok,
                           pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM ? true : false);
        if (!subreq) goto done;

        tevent_req_set_callback(subreq, sdap_pam_auth_done, state);
        return;

    case SSS_PAM_CHAUTHTOK:
        break;

    case SSS_PAM_ACCT_MGMT:
    case SSS_PAM_SETCRED:
    case SSS_PAM_OPEN_SESSION:
    case SSS_PAM_CLOSE_SESSION:
        pd->pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        break;
    default:
        pd->pam_status = PAM_MODULE_UNKNOWN;
        dp_err = DP_ERR_OK;
    }

done:
    be_req_terminate(breq, dp_err, pd->pam_status, NULL);
}

static void sdap_pam_auth_done(struct tevent_req *req)
{
    struct sdap_pam_auth_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_auth_state);
    struct be_ctx *be_ctx = be_req_get_be_ctx(state->breq);
    enum pwexpire pw_expire_type;
    void *pw_expire_data;
    const char *password;
    int dp_err = DP_ERR_OK;
    int ret;

    ret = auth_recv(req, state, NULL, NULL,
                    &pw_expire_type, &pw_expire_data);
    talloc_zfree(req);

    if (ret == EOK) {
        switch (pw_expire_type) {
        case PWEXPIRE_SHADOW:
            ret = check_pwexpire_shadow(pw_expire_data, time(NULL), state->pd);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "check_pwexpire_shadow failed.\n");
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            break;
        case PWEXPIRE_KERBEROS:
            ret = check_pwexpire_kerberos(pw_expire_data, time(NULL),
                                          state->pd,
                                          be_ctx->domain->pwd_expiration_warning);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "check_pwexpire_kerberos failed.\n");
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            break;
        case PWEXPIRE_LDAP_PASSWORD_POLICY:
            ret = check_pwexpire_ldap(state->pd, pw_expire_data,
                                      be_ctx->domain->pwd_expiration_warning);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "check_pwexpire_ldap failed.\n");
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            break;
        case PWEXPIRE_NONE:
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknow pasword expiration type.\n");
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
        }
    }

    switch (ret) {
    case EOK:
        state->pd->pam_status = PAM_SUCCESS;
        break;
    case ERR_AUTH_DENIED:
        state->pd->pam_status = PAM_PERM_DENIED;
        break;
    case ERR_AUTH_FAILED:
        state->pd->pam_status = PAM_AUTH_ERR;
        break;
    case ETIMEDOUT:
    case ERR_NETWORK_IO:
        state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        break;
    case ERR_ACCOUNT_EXPIRED:
        state->pd->pam_status = PAM_ACCT_EXPIRED;
        break;
    case ERR_PASSWORD_EXPIRED:
        state->pd->pam_status = PAM_NEW_AUTHTOK_REQD;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
        dp_err = DP_ERR_FATAL;
    }

    if (ret == ETIMEDOUT || ret == ERR_NETWORK_IO) {
        be_mark_offline(be_ctx);
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    if (ret == EOK && be_ctx->domain->cache_credentials) {

        ret = sss_authtok_get_password(state->pd->authtok, &password, NULL);
        if (ret == EOK) {
            ret = sysdb_cache_password(be_ctx->domain, state->pd->user,
                                       password);
        }

        /* password caching failures are not fatal errors */
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to cache password for %s\n",
                      state->pd->user);
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS, "Password successfully cached for %s\n",
                      state->pd->user);
        }
    }

done:
    be_req_terminate(state->breq, dp_err, state->pd->pam_status, NULL);
}
