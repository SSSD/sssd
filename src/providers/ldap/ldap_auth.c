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

#ifdef HAVE_SHADOW_H
#include <shadow.h>
#else
struct spwd {
    char          *sp_namp;
    char          *sp_pwdp;
    long int       sp_lstchg;
    long int       sp_min;
    long int       sp_max;
    long int       sp_warn;
    long int       sp_inact;
    long int       sp_expire;
    unsigned long int   sp_flag;
};
#endif
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/user_info_msg.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_auth.h"


#define LDAP_PWEXPIRE_WARNING_TIME 0

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
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed.\n");
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
    time_t expire_time;
    int expiration_warning;
    int ret = ERR_INTERNAL;

    ret = sss_utc_to_time_t(expire_date, "%Y%m%d%H%M%SZ",
                            &expire_time);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_utc_to_time_t failed with %d:%s.\n",
              ret, sss_strerror(ret));
        return ret;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Time info: tzname[0] [%s] tzname[1] [%s] timezone [%ld] "
          "daylight [%d] now [%"SPRItime"] expire_time [%"SPRItime"].\n",
          tzname[0], tzname[1], timezone, daylight, now, expire_time);

    if (expire_time == 0) {
        /* Used by the MIT LDAP KDB plugin to indicate "never" */
        ret = EOK;
    } else if (difftime(now, expire_time) > 0.0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Kerberos password expired.\n");
        if (pd != NULL) {
            ret = add_expired_warning(pd, 0);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "add_expired_warning failed.\n");
            }
        }
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

    if ((spwd->sp_expire != -1 && today >= spwd->sp_expire) ||
        (spwd->sp_max != -1 && spwd->sp_inact != -1 &&
         password_age > spwd->sp_max + spwd->sp_inact))
    {
        DEBUG(SSSDBG_CONF_SETTINGS, "Account expired.\n");
        return ERR_ACCOUNT_EXPIRED;
    }

    if (spwd->sp_max != -1 && password_age > spwd->sp_max) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Password expired.\n");
        if (pd != NULL) {
            ret = add_expired_warning(pd, 0);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "add_expired_warning failed.\n");
            }
        }
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
                                   int pwd_exp_warning,
                                   struct sdap_options *opts)
{
    int ret = EOK;

    if (ppolicy->grace >= 0 || ppolicy->expire > 0) {
        uint32_t *data;
        uint32_t *ptr;
        int pwd_change_thold;

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
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "pam_add_response failed: %s\n",
                  sss_strerror(ret));
            return ret;
        }

        /*
         * Either password is expired or this is a grace login.
         * Check the grace loging password change threshold.
         */
        pwd_change_thold = dp_opt_get_int(opts->basic, SDAP_PPOLICY_PWD_CHANGE_THRESHOLD);
        if (pwd_change_thold > 0 && ppolicy->grace > 0 && ppolicy->grace <= pwd_change_thold) {
            ret = ERR_PASSWORD_EXPIRED;
        }
    }

done:
    return ret;
}

errno_t check_pwexpire_policy(enum pwexpire pw_expire_type,
                              void *pw_expire_data,
                              struct pam_data *pd,
                              int pwd_expiration_warning,
                              struct sdap_options *opts)
{
    errno_t ret;

    switch (pw_expire_type) {
    case PWEXPIRE_SHADOW:
        ret = check_pwexpire_shadow(pw_expire_data, time(NULL), pd);
        break;
    case PWEXPIRE_KERBEROS:
        ret = check_pwexpire_kerberos(pw_expire_data, time(NULL), pd,
                                      pwd_expiration_warning);
        break;
    case PWEXPIRE_LDAP_PASSWORD_POLICY:
        ret = check_pwexpire_ldap(pd, pw_expire_data,
                                  pwd_expiration_warning,
                                  opts);
        break;
    case PWEXPIRE_NONE:
        ret = EOK;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown password expiration type %d.\n", pw_expire_type);
        ret = EINVAL;
    }

    return ret;
}

static errno_t
find_password_expiration_attributes(TALLOC_CTX *mem_ctx,
                                    const struct ldb_message *msg,
                                    enum sdap_access_type access_type,
                                    struct dp_option *opts,
                                    enum pwexpire *pwd_exp_type,
                                    void **data)
{
    const char *mark;
    const char *val;
    struct spwd *spwd;
    const char *pwd_policy;
    int ret;

    *pwd_exp_type = PWEXPIRE_NONE;
    *data = NULL;

    switch (access_type) {
    case SDAP_TYPE_IPA:
        /* MIT-Kerberos is the only option for IPA */
        pwd_policy = PWD_POL_OPT_MIT;
        break;
    case SDAP_TYPE_LDAP:
        pwd_policy = dp_opt_get_string(opts, SDAP_PWD_POLICY);
        if (pwd_policy == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing password policy.\n");
            return EINVAL;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,"Unknown access_type [%i].\n", access_type);
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
                *pwd_exp_type = PWEXPIRE_KERBEROS;

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
            *pwd_exp_type = PWEXPIRE_SHADOW;

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
    char *username;

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

    ret = sss_parse_internal_fqname(state, username,
                                    &state->username, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot parse %s\n", username);
        goto done;
    }

    ret = sss_filter_sanitize(state, state->username, &clean_name);
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
                                   SDAP_LOOKUP_SINGLE);
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

int get_user_dn(TALLOC_CTX *memctx,
                       struct sss_domain_info *domain,
                       enum sdap_access_type access_type,
                       struct sdap_options *opts,
                       const char *username,
                       char **user_dn,
                       enum pwexpire *user_pw_expire_type,
                       void **user_pw_expire_data)
{
    TALLOC_CTX *tmpctx;
    enum pwexpire pw_expire_type = PWEXPIRE_NONE;
    void *pw_expire_data;
    struct ldb_result *res;
    const char **attrs;
    const char *dn = NULL;
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
                                                  access_type,
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
};

static struct tevent_req *auth_connect_send(struct tevent_req *req);
static void auth_get_dn_done(struct tevent_req *subreq);
static void auth_do_bind(struct tevent_req *req);
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
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct auth_state);
    if (!req) return NULL;

    /* The token must be a password token */
    if (sss_authtok_get_type(authtok) != SSS_AUTHTOK_TYPE_PASSWORD &&
        sss_authtok_get_type(authtok) != SSS_AUTHTOK_TYPE_PAM_STACKED) {
        if (sss_authtok_get_type(authtok) == SSS_AUTHTOK_TYPE_SC_PIN
            || sss_authtok_get_type(authtok) == SSS_AUTHTOK_TYPE_SC_KEYPAD) {
            /* Tell frontend that we do not support Smartcard authentication */
            ret = ERR_SC_AUTH_NOT_SUPPORTED;
        } else {
            ret = ERR_AUTH_FAILED;
        }
        goto fail;
    }

    state->ev = ev;
    state->ctx = ctx;
    state->username = username;
    state->authtok = authtok;
    if (try_chpass_service && ctx->chpass_service != NULL &&
        ctx->chpass_service->name != NULL) {
        state->sdap_service = ctx->chpass_service;
    } else {
        state->sdap_service = ctx->service;
    }

    ret = get_user_dn(state, state->ctx->be->domain, SDAP_TYPE_LDAP,
                      state->ctx->opts, state->username, &state->dn,
                      &state->pw_expire_type, &state->pw_expire_data);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Need to look up the DN of %s later\n", state->username);
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get user DN [%d]: %s\n", ret, sss_strerror(ret));
        goto fail;
    }

    if (auth_connect_send(req) == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static struct tevent_req *auth_connect_send(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct auth_state *state = tevent_req_data(req,
                                               struct auth_state);
    bool use_tls;
    bool skip_conn_auth = false;
    const char *sasl_mech;

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

    if (state->dn != NULL) {
        /* In case the user's DN is known, the connection will only be used
         * to bind as the user to perform the authentication. In that case,
         * we don't need to authenticate the connection, because we're not
         * looking up any information using the connection. This might be
         * needed e.g. in case both ID and AUTH providers are set to LDAP
         * and the server is AD, because otherwise the connection would both
         * do a startTLS and later bind using GSSAPI or GSS-SPNEGO which
         * doesn't work well with AD.
         */
        skip_conn_auth = true;
    }

    if (skip_conn_auth == false) {
        sasl_mech = dp_opt_get_string(state->ctx->opts->basic,
                                      SDAP_SASL_MECH);
        if (sasl_mech && sdap_sasl_mech_needs_kinit(sasl_mech)) {
            /* Don't force TLS on if we're told to use GSSAPI or GSS-SPNEGO */
            use_tls = false;
        }
    }

    if (ldap_is_ldapi_url(state->sdap_service->uri)) {
        /* Don't force TLS on if we're a unix domain socket */
        use_tls = false;
    }

    subreq = sdap_cli_resolve_and_connect_send(state, state->ev,
                                               state->ctx->opts,
                                               state->ctx->be,
                                               state->sdap_service, false,
                                               use_tls ? CON_TLS_ON : CON_TLS_OFF,
                                               skip_conn_auth);

    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return NULL;
    }

    tevent_req_set_callback(subreq, auth_connect_done, req);

    return subreq;
}

static bool check_encryption_used(LDAP *ldap)
{
    ber_len_t sasl_ssf = 0;
    int tls_inplace = 0;
    int ret;

    ret = ldap_get_option(ldap, LDAP_OPT_X_SASL_SSF, &sasl_ssf);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_TRACE_LIBS, "ldap_get_option failed to get sasl ssf, "
                                 "assuming SASL is not used.\n");
        sasl_ssf = 0;
    }

    tls_inplace = ldap_tls_inplace(ldap);

    DEBUG(SSSDBG_TRACE_ALL,
          "Encryption used: SASL SSF [%lu] tls_inplace [%s].\n", sasl_ssf,
          tls_inplace == 1 ? "TLS inplace" : "TLS NOT inplace");

    if (sasl_ssf <= 1 && tls_inplace != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "No encryption detected on LDAP connection.\n");
        sss_log(SSS_LOG_CRIT, "No encryption detected on LDAP connection.\n");
        return false;
    }

    return true;
}

static void auth_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;

    ret = sdap_cli_resolve_and_connect_recv(subreq, state, NULL, &state->sh,
                                            NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* As sdap_cli_resolve_and_connect_recv() returns EIO in case all the
         * servers are down and we have to go offline, let's treat it
         * accordingly here and allow the PAM responder to switch to offline
         * authentication.
         *
         * Unfortunately, there's not much pattern within our code and the way
         * to indicate we're going down in this part of the code is returning an
         * ETIMEDOUT.
         */
        if (ret == EIO) {
            tevent_req_error(req, ETIMEDOUT);
        } else {
            if (auth_connect_send(req) == NULL) {
                tevent_req_error(req, ENOMEM);
            }
        }
        return;
    }

    if (!ldap_is_ldapi_url(state->sdap_service->uri) &&
            !check_encryption_used(state->sh->ldap) &&
            !dp_opt_get_bool(state->ctx->opts->basic, SDAP_DISABLE_AUTH_TLS)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Aborting the authentication request.\n");
        sss_log(SSS_LOG_CRIT, "Aborting the authentication request.\n");
        tevent_req_error(req, ERR_AUTH_FAILED);
        return;
    }

    if (state->dn == NULL) {
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

    /* All required user data was pre-cached during an identity lookup.
     * We can proceed with the bind */
    auth_do_bind(req);
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
    bool use_ppolicy = dp_opt_get_bool(state->ctx->opts->basic,
                                       SDAP_USE_PPOLICY);
    int timeout = dp_opt_get_int(state->ctx->opts->basic, SDAP_OPT_TIMEOUT);

    subreq = sdap_auth_send(state, state->ev, state->sh,
                            NULL, NULL, state->dn,
                            state->authtok,
                            timeout, use_ppolicy,
                            state->ctx->opts->pwmodify_mode);
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
        if (auth_connect_send(req) == NULL) {
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

struct sdap_pam_auth_handler_state {
    struct pam_data *pd;
    struct be_ctx *be_ctx;
    struct sdap_auth_ctx *auth_ctx;
};

static void sdap_pam_auth_handler_done(struct tevent_req *subreq);

struct tevent_req *
sdap_pam_auth_handler_send(TALLOC_CTX *mem_ctx,
                           struct sdap_auth_ctx *auth_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params)
{
    struct sdap_pam_auth_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_pam_auth_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->be_ctx = params->be_ctx;
    state->auth_ctx = auth_ctx;
    pd->pam_status = PAM_SYSTEM_ERR;

    switch (pd->cmd) {
    case SSS_PAM_AUTHENTICATE:
        subreq = auth_send(state, params->ev, auth_ctx,
                           pd->user, pd->authtok, false);
        if (subreq == NULL) {
            pd->pam_status = PAM_SYSTEM_ERR;
            goto immediately;
        }

        tevent_req_set_callback(subreq, sdap_pam_auth_handler_done, req);
        break;
    case SSS_PAM_CHAUTHTOK_PRELIM:
        subreq = auth_send(state, params->ev, auth_ctx,
                           pd->user, pd->authtok, true);
        if (subreq == NULL) {
            pd->pam_status = PAM_SYSTEM_ERR;
            goto immediately;
        }

        tevent_req_set_callback(subreq, sdap_pam_auth_handler_done, req);
        break;
    case SSS_PAM_CHAUTHTOK:
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;

    case SSS_PAM_ACCT_MGMT:
    case SSS_PAM_SETCRED:
    case SSS_PAM_OPEN_SESSION:
    case SSS_PAM_CLOSE_SESSION:
        pd->pam_status = PAM_SUCCESS;
        goto immediately;
    default:
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto immediately;
    }

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void sdap_pam_auth_handler_done(struct tevent_req *subreq)
{
    struct sdap_pam_auth_handler_state *state;
    struct tevent_req *req;
    enum pwexpire pw_expire_type;
    void *pw_expire_data;
    const char *password;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_pam_auth_handler_state);

    ret = auth_recv(subreq, state, NULL, NULL,
                    &pw_expire_type, &pw_expire_data);
    talloc_free(subreq);

    if (ret == EOK) {
        ret = check_pwexpire_policy(pw_expire_type, pw_expire_data, state->pd,
                                state->be_ctx->domain->pwd_expiration_warning,
                                state->auth_ctx->opts);
        if (ret == EINVAL) {
            /* Unknown password expiration type. */
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
        be_mark_offline(state->be_ctx);
        break;
    case ERR_ACCOUNT_EXPIRED:
        state->pd->pam_status = PAM_ACCT_EXPIRED;
        break;
    case ERR_PASSWORD_EXPIRED:
        state->pd->pam_status = PAM_NEW_AUTHTOK_REQD;
        break;
    case ERR_ACCOUNT_LOCKED:
        state->pd->account_locked = true;
        state->pd->pam_status = PAM_PERM_DENIED;
        break;
    case ERR_SC_AUTH_NOT_SUPPORTED:
        state->pd->pam_status = PAM_BAD_ITEM;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
        break;
    }

    if (ret == EOK && state->be_ctx->domain->cache_credentials) {
        ret = sss_authtok_get_password(state->pd->authtok, &password, NULL);
        if (ret == EOK) {
            ret = sysdb_cache_password(state->be_ctx->domain, state->pd->user,
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
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
sdap_pam_auth_handler_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct pam_data **_data)
{
    struct sdap_pam_auth_handler_state *state = NULL;

    state = tevent_req_data(req, struct sdap_pam_auth_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}

struct sdap_pam_change_password_state {
    enum pwmodify_mode mode;
    char *user_error_message;
};

static void sdap_pam_change_password_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_pam_change_password_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct sdap_handle *sh,
                              struct sdap_options *opts,
                              struct pam_data *pd,
                              char *user_dn)
{
    struct sdap_pam_change_password_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char *password;
    const char *new_password;
    char *pwd_attr;
    int timeout;
    errno_t ret;
    bool use_ppolicy;

    pwd_attr = opts->user_map[SDAP_AT_USER_PWD].name;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_pam_change_password_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->mode = opts->pwmodify_mode;

    ret = sss_authtok_get_password(pd->authtok, &password, NULL);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_authtok_get_password(pd->newauthtok, &new_password, NULL);
    if (ret != EOK) {
        goto done;
    }

    timeout = dp_opt_get_int(opts->basic, SDAP_OPT_TIMEOUT);

    switch (opts->pwmodify_mode) {
    case SDAP_PWMODIFY_EXOP:
    case SDAP_PWMODIFY_EXOP_FORCE:
        use_ppolicy = dp_opt_get_bool(opts->basic, SDAP_USE_PPOLICY);
        subreq = sdap_exop_modify_passwd_send(state, ev, sh, user_dn,
                                              password, new_password,
                                              timeout, use_ppolicy);
        break;
    case SDAP_PWMODIFY_LDAP:
        subreq = sdap_modify_passwd_send(state, ev, sh, timeout, pwd_attr,
                                         user_dn, new_password);
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE, "Unrecognized pwmodify mode: %d\n",
              opts->pwmodify_mode);
        ret = EINVAL;
        goto done;
    }
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_pam_change_password_done, req);

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sdap_pam_change_password_done(struct tevent_req *subreq)
{
    struct sdap_pam_change_password_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_pam_change_password_state);

    switch (state->mode) {
    case SDAP_PWMODIFY_EXOP:
    case SDAP_PWMODIFY_EXOP_FORCE:
        ret = sdap_exop_modify_passwd_recv(subreq, state,
                                           &state->user_error_message);
        break;
    case SDAP_PWMODIFY_LDAP:
        ret = sdap_modify_passwd_recv(subreq, state,
                                      &state->user_error_message);
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE, "Unrecognized pwmodify mode: %d\n",
              state->mode);
        ret = EINVAL;
    }
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static errno_t
sdap_pam_change_password_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              char **_user_error_message)
{
    struct sdap_pam_change_password_state *state;
    state = tevent_req_data(req, struct sdap_pam_change_password_state);

    /* We want to return the error message even on failure */
    *_user_error_message = talloc_steal(mem_ctx, state->user_error_message);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


struct sdap_pam_chpass_handler_state {
    struct be_ctx *be_ctx;
    struct tevent_context *ev;
    struct sdap_auth_ctx *auth_ctx;
    struct pam_data *pd;
    struct sdap_handle *sh;
    char *dn;
    enum pwexpire pw_expire_type;
};

static void sdap_pam_chpass_handler_auth_done(struct tevent_req *subreq);
static int
sdap_pam_chpass_handler_change_step(struct sdap_pam_chpass_handler_state *state,
                                    struct tevent_req *req,
                                    enum pwexpire pw_expire_type);
static void sdap_pam_chpass_handler_chpass_done(struct tevent_req *subreq);
static void sdap_pam_chpass_handler_last_done(struct tevent_req *subreq);

struct tevent_req *
sdap_pam_chpass_handler_send(TALLOC_CTX *mem_ctx,
                           struct sdap_auth_ctx *auth_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params)
{
    struct sdap_pam_chpass_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_pam_chpass_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->be_ctx = params->be_ctx;
    state->auth_ctx = auth_ctx;
    state->ev = params->ev;

    if (be_is_offline(state->be_ctx)) {
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        goto immediately;
    }

    if ((pd->priv == 1) && (pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) &&
        (sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_PASSWORD)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Password reset by root is not supported.\n");
        pd->pam_status = PAM_PERM_DENIED;
        goto immediately;
    }

    DEBUG(SSSDBG_OP_FAILURE,
          "starting password change request for user [%s].\n", pd->user);

    pd->pam_status = PAM_SYSTEM_ERR;

    if (pd->cmd != SSS_PAM_CHAUTHTOK && pd->cmd != SSS_PAM_CHAUTHTOK_PRELIM) {
        DEBUG(SSSDBG_OP_FAILURE,
              "chpass target was called by wrong pam command.\n");
        goto immediately;
    }

    subreq = auth_send(state, params->ev, auth_ctx,
                       pd->user, pd->authtok, true);
    if (subreq == NULL) {
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_pam_chpass_handler_auth_done, req);

    return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static bool confdb_is_set_explicit(struct confdb_ctx *cdb, const char *section,
                                   const char *attribute)
{
    int ret;
    char **vals = NULL;
    bool update_option_set_explictly = false;

    ret = confdb_get_param(cdb, NULL, section, attribute, &vals);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to check if [%s] is set "
              "explicitly in sssd.conf, assuming it is not set.\n",
              attribute);
    } else if (vals != NULL && vals[0] != NULL) {
        update_option_set_explictly = true;
    }
    talloc_free(vals);

    return update_option_set_explictly;
}

static void sdap_pam_chpass_handler_auth_done(struct tevent_req *subreq)
{
    struct sdap_pam_chpass_handler_state *state;
    struct tevent_req *req;
    void *pw_expire_data;
    size_t msg_len;
    uint8_t *msg;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_pam_chpass_handler_state);

    ret = auth_recv(subreq, state, &state->sh, &state->dn,
                    &state->pw_expire_type, &pw_expire_data);
    talloc_free(subreq);

    if ((ret == EOK || ret == ERR_PASSWORD_EXPIRED) &&
        state->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
        DEBUG(SSSDBG_TRACE_ALL, "Initial authentication for change "
              "password operation successful.\n");
        state->pd->pam_status = PAM_SUCCESS;
        goto done;
    }

    if (ret == EOK) {
        switch (state->pw_expire_type) {
        case PWEXPIRE_SHADOW:
            ret = check_pwexpire_shadow(pw_expire_data, time(NULL), NULL);
            break;
        case PWEXPIRE_KERBEROS:
            ret = check_pwexpire_kerberos(pw_expire_data, time(NULL), NULL,
                              state->be_ctx->domain->pwd_expiration_warning);

            if (ret == ERR_PASSWORD_EXPIRED) {
                DEBUG(SSSDBG_CRIT_FAILURE, "LDAP provider cannot change "
                      "kerberos passwords.\n");
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
            break;
        case PWEXPIRE_LDAP_PASSWORD_POLICY:
        case PWEXPIRE_NONE:
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unknown password expiration type %d.\n",
                  state->pw_expire_type);
            state->pd->pam_status = PAM_SYSTEM_ERR;
            goto done;
        }
    }

    switch (ret) {
        case EOK:
        case ERR_PASSWORD_EXPIRED:
            DEBUG(SSSDBG_TRACE_LIBS,
                  "user [%s] successfully authenticated.\n", state->dn);
            ret = sdap_pam_chpass_handler_change_step(state, req,
                                                      state->pw_expire_type);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sdap_pam_chpass_handler_change_step() failed.\n");
                goto done;
            }
            return;
            break;
        case ERR_AUTH_DENIED:
        case ERR_AUTH_FAILED:
            state->pd->pam_status = PAM_AUTH_ERR;
            ret = pack_user_info_chpass_error(state->pd, "Old password not "
                                              "accepted.", &msg_len, &msg);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "pack_user_info_chpass_error failed.\n");
            } else {
                ret = pam_add_response(state->pd, SSS_PAM_USER_INFO,
                                       msg_len, msg);
                if (ret != EOK) {
                   DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                }
            }
            break;
        case ETIMEDOUT:
        case ERR_NETWORK_IO:
            state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
            be_mark_offline(state->be_ctx);
            break;
        default:
            state->pd->pam_status = PAM_SYSTEM_ERR;
            break;
        }

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

static int
sdap_pam_chpass_handler_change_step(struct sdap_pam_chpass_handler_state *state,
                                    struct tevent_req *req,
                                    enum pwexpire pw_expire_type)
{
    int ret;
    struct tevent_req *subreq;
    bool update_option_set_explictly = false;

    if (pw_expire_type == PWEXPIRE_SHADOW) {

        update_option_set_explictly = confdb_is_set_explicit(
                   state->be_ctx->cdb, state->be_ctx->conf_path,
                   state->auth_ctx->opts->basic[SDAP_CHPASS_UPDATE_LAST_CHANGE].opt_name);

        if (!dp_opt_get_bool(state->auth_ctx->opts->basic,
                             SDAP_CHPASS_UPDATE_LAST_CHANGE)
                    && !update_option_set_explictly) {
            DEBUG(SSSDBG_CRIT_FAILURE,
               "Shadow password policy is selected but "
               "ldap_chpass_update_last_change is not set, please "
               "make sure your LDAP server can update the [%s] "
               "attribute automatically. Otherwise SSSD might "
               "consider your password as expired.\n",
               state->auth_ctx->opts->user_map[SDAP_AT_SP_LSTCHG].name);
        }
        ret = sysdb_invalidate_cache_entry(state->be_ctx->domain,
                                           state->pd->user, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
               "Failed to invalidate cache entry for user [%s] with error code "
               "[%d][%s]. The last changed attribute [%s] might not get "
               "refreshed after the password and the password might still be "
               "considered as expired. Call sss_cache for this user "
               "to expire the entry manually in this case.\n",
               state->pd->user, ret, sss_strerror(ret),
               state->auth_ctx->opts->user_map[SDAP_AT_SP_LSTCHG].name);
        }
    }
    subreq = sdap_pam_change_password_send(state, state->ev,
                                           state->sh,
                                           state->auth_ctx->opts,
                                           state->pd,
                                           state->dn);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to change password for "
              "%s\n", state->pd->user);
        state->pd->pam_status = PAM_SYSTEM_ERR;
        return ENOMEM;
    }

    tevent_req_set_callback(subreq,
                            sdap_pam_chpass_handler_chpass_done,
                            req);
    return EOK;
}

static void sdap_pam_chpass_handler_chpass_done(struct tevent_req *subreq)
{
    struct sdap_pam_chpass_handler_state *state;
    struct tevent_req *req;
    char *user_error_message = NULL;
    char *lastchanged_name;
    size_t msg_len;
    uint8_t *msg;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_pam_chpass_handler_state);

    ret = sdap_pam_change_password_recv(state, subreq, &user_error_message);
    talloc_free(subreq);

    switch (ret) {
    case EOK:
        if (state->pw_expire_type == PWEXPIRE_SHADOW) {
            ret = sysdb_update_user_shadow_last_change(state->be_ctx->domain,
                    state->pd->user, SYSDB_SHADOWPW_LASTCHANGE);
            if (ret != EOK) {
                state->pd->pam_status = PAM_SYSTEM_ERR;
                goto done;
            }
        }

        state->pd->pam_status = PAM_SUCCESS;
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
            ret = pam_add_response(state->pd, SSS_PAM_USER_INFO, msg_len, msg);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            }
        }
    }

    if (state->pd->pam_status == PAM_SUCCESS &&
        dp_opt_get_bool(state->auth_ctx->opts->basic,
                        SDAP_CHPASS_UPDATE_LAST_CHANGE)) {
        lastchanged_name = state->auth_ctx->opts->user_map[SDAP_AT_SP_LSTCHG].name;

        subreq = sdap_modify_shadow_lastchange_send(state, state->ev,
                                                    state->sh, state->dn,
                                                    lastchanged_name);
        if (subreq == NULL) {
            state->pd->pam_status = PAM_SYSTEM_ERR;
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_pam_chpass_handler_last_done, req);
        return;
    }

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

static void sdap_pam_chpass_handler_last_done(struct tevent_req *subreq)
{
    struct sdap_pam_chpass_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_pam_chpass_handler_state);

    ret = sdap_modify_shadow_lastchange_recv(subreq);
    talloc_free(subreq);

    if (ret != EOK) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    state->pd->pam_status = PAM_SUCCESS;

done:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
}

errno_t
sdap_pam_chpass_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data)
{
    struct sdap_pam_chpass_handler_state *state = NULL;

    state = tevent_req_data(req, struct sdap_pam_chpass_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
