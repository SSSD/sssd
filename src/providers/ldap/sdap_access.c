/*
    SSSD

    sdap_access.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <time.h>
#include <security/pam_modules.h>
#include <talloc.h>
#include <tevent.h>
#include <errno.h>

#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_async.h"
#include "providers/data_provider.h"
#include "providers/backend.h"
#include "providers/ldap/ldap_auth.h"
#include "providers/ipa/ipa_common.h"

#define PERMANENTLY_LOCKED_ACCOUNT "000001010000Z"
#define MALFORMED_FILTER "Malformed access control filter [%s]\n"

enum sdap_pwpolicy_mode {
    PWP_LOCKOUT_ONLY,
    PWP_LOCKOUT_EXPIRE,
    PWP_SENTINEL,
};

static errno_t perform_pwexpire_policy(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *domain,
                                       struct pam_data *pd,
                                       enum sdap_access_type access_type,
                                       struct sdap_options *opts);

static errno_t sdap_save_user_cache_bool(struct sss_domain_info *domain,
                                         const char *username,
                                         const char *attr_name,
                                         bool value);

static errno_t sdap_get_basedn_user_entry(struct ldb_message *user_entry,
                                          const char *username,
                                          const char **_basedn);

static struct tevent_req *
sdap_access_ppolicy_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct be_ctx *be_ctx,
                         struct sss_domain_info *domain,
                         struct sdap_access_ctx *access_ctx,
                         struct sdap_id_conn_ctx *conn,
                         const char *username,
                         struct ldb_message *user_entry,
                         enum sdap_pwpolicy_mode pwpol_mod);

static struct tevent_req *sdap_access_filter_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct be_ctx *be_ctx,
                                             struct sss_domain_info *domain,
                                             struct sdap_access_ctx *access_ctx,
                                             struct sdap_id_conn_ctx *conn,
                                             const char *username,
                                             struct ldb_message *user_entry);

static errno_t sdap_access_filter_recv(struct tevent_req *req);

static errno_t sdap_access_ppolicy_recv(struct tevent_req *req);

static errno_t sdap_account_expired(struct sdap_access_ctx *access_ctx,
                                    struct pam_data *pd,
                                    struct ldb_message *user_entry);

static  errno_t sdap_access_service(struct pam_data *pd,
                                    struct ldb_message *user_entry);

static errno_t sdap_access_host(struct ldb_message *user_entry);

errno_t sdap_access_rhost(struct ldb_message *user_entry, char *rhost);

enum sdap_access_control_type {
    SDAP_ACCESS_CONTROL_FILTER,
    SDAP_ACCESS_CONTROL_PPOLICY_LOCK,
};

struct sdap_access_req_ctx {
    struct pam_data *pd;
    struct tevent_context *ev;
    struct sdap_access_ctx *access_ctx;
    struct sdap_id_conn_ctx *conn;
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;
    struct ldb_message *user_entry;
    size_t current_rule;
    enum sdap_access_control_type ac_type;
};

static errno_t sdap_access_check_next_rule(struct sdap_access_req_ctx *state,
                                           struct tevent_req *req);
static void sdap_access_done(struct tevent_req *subreq);

struct tevent_req *
sdap_access_send(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 struct be_ctx *be_ctx,
                 struct sss_domain_info *domain,
                 struct sdap_access_ctx *access_ctx,
                 struct sdap_id_conn_ctx *conn,
                 struct pam_data *pd)
{
    errno_t ret;
    struct sdap_access_req_ctx *state;
    struct tevent_req *req;
    struct ldb_result *res;
    const char *attrs[] = { "*", NULL };

    req = tevent_req_create(mem_ctx, &state, struct sdap_access_req_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->be_ctx = be_ctx;
    state->domain = domain;
    state->pd = pd;
    state->ev = ev;
    state->access_ctx = access_ctx;
    state->conn = conn;
    state->current_rule = 0;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Performing access check for user [%s]\n", pd->user);

    if (access_ctx->access_rule[0] == LDAP_ACCESS_EMPTY) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No access rules defined, access denied.\n");
        ret = ERR_ACCESS_DENIED;
        goto done;
    }

    /* Get original user DN, domain already points to the right (sub)domain */
    ret = sysdb_get_user_attr(state, domain, pd->user, attrs, &res);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* If we can't find the user, return access denied */
            ret = ERR_ACCESS_DENIED;
            goto done;
        }
        goto done;
    }
    else {
        if (res->count == 0) {
            /* If we can't find the user, return access denied */
            ret = ERR_ACCESS_DENIED;
            goto done;
        }

        if (res->count != 1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid response from sysdb_get_user_attr\n");
            ret = EINVAL;
            goto done;
        }
    }

    state->user_entry = res->msgs[0];

    ret = sdap_access_check_next_rule(state, req);
    if (ret == EAGAIN) {
        return req;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t sdap_access_check_next_rule(struct sdap_access_req_ctx *state,
                                           struct tevent_req *req)
{
    struct tevent_req *subreq;
    int ret = EOK;

    while (ret == EOK) {
        switch (state->access_ctx->access_rule[state->current_rule]) {
        case LDAP_ACCESS_EMPTY:
            /* we are done with no errors */
            return EOK;

        /* This option is deprecated by LDAP_ACCESS_PPOLICY */
        case LDAP_ACCESS_LOCKOUT:
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "WARNING: %s option is deprecated and might be removed in "
                  "a future release. Please migrate to %s option instead.\n",
                  LDAP_ACCESS_LOCK_NAME, LDAP_ACCESS_PPOLICY_NAME);

            subreq = sdap_access_ppolicy_send(state, state->ev, state->be_ctx,
                                              state->domain,
                                              state->access_ctx,
                                              state->conn,
                                              state->pd->user,
                                              state->user_entry,
                                              PWP_LOCKOUT_ONLY);
            if (subreq == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_access_ppolicy_send failed.\n");
                return ENOMEM;
            }

            state->ac_type = SDAP_ACCESS_CONTROL_PPOLICY_LOCK;

            tevent_req_set_callback(subreq, sdap_access_done, req);
            return EAGAIN;

        case LDAP_ACCESS_PPOLICY:
            subreq = sdap_access_ppolicy_send(state, state->ev, state->be_ctx,
                                              state->domain,
                                              state->access_ctx,
                                              state->conn,
                                              state->pd->user,
                                              state->user_entry,
                                              PWP_LOCKOUT_EXPIRE);
            if (subreq == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_access_ppolicy_send failed.\n");
                return ENOMEM;
            }

            state->ac_type = SDAP_ACCESS_CONTROL_PPOLICY_LOCK;

            tevent_req_set_callback(subreq, sdap_access_done, req);
            return EAGAIN;

        case LDAP_ACCESS_FILTER:
            subreq = sdap_access_filter_send(state, state->ev, state->be_ctx,
                                             state->domain,
                                             state->access_ctx,
                                             state->conn,
                                             state->pd->user,
                                             state->user_entry);
            if (subreq == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "sdap_access_filter_send failed.\n");
                return ENOMEM;
            }

            state->ac_type = SDAP_ACCESS_CONTROL_FILTER;

            tevent_req_set_callback(subreq, sdap_access_done, req);
            return EAGAIN;

        case LDAP_ACCESS_EXPIRE:
            ret = sdap_account_expired(state->access_ctx,
                                       state->pd, state->user_entry);
            break;

        case LDAP_ACCESS_EXPIRE_POLICY_REJECT:
            ret = perform_pwexpire_policy(state, state->domain, state->pd,
                                          state->access_ctx->type,
                                          state->access_ctx->id_ctx->opts);
            if (ret == ERR_PASSWORD_EXPIRED) {
                ret = ERR_PASSWORD_EXPIRED_REJECT;
            }
            break;

        case LDAP_ACCESS_EXPIRE_POLICY_WARN:
            ret = perform_pwexpire_policy(state, state->domain, state->pd,
                                          state->access_ctx->type,
                                          state->access_ctx->id_ctx->opts);
            if (ret == ERR_PASSWORD_EXPIRED) {
                ret = ERR_PASSWORD_EXPIRED_WARN;
            }
            break;

        case LDAP_ACCESS_EXPIRE_POLICY_RENEW:
            ret = perform_pwexpire_policy(state, state->domain, state->pd,
                                          state->access_ctx->type,
                                          state->access_ctx->id_ctx->opts);
            if (ret == ERR_PASSWORD_EXPIRED) {
                ret = ERR_PASSWORD_EXPIRED_RENEW;
            }
            break;

        case LDAP_ACCESS_SERVICE:
            ret = sdap_access_service( state->pd, state->user_entry);
            break;

        case LDAP_ACCESS_HOST:
            ret = sdap_access_host(state->user_entry);
            break;

        case LDAP_ACCESS_RHOST:
            ret = sdap_access_rhost(state->user_entry, state->pd->rhost);
            break;

        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected access rule type %d. Access denied.\n",
                  state->access_ctx->access_rule[state->current_rule]);
            ret = ERR_ACCESS_DENIED;
        }

        state->current_rule++;
    }

    return ret;
}

static void sdap_access_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_access_req_ctx *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_access_req_ctx);

    /* process subrequest */
    switch(state->ac_type) {
    case SDAP_ACCESS_CONTROL_FILTER:
        ret = sdap_access_filter_recv(subreq);
        break;
    case SDAP_ACCESS_CONTROL_PPOLICY_LOCK:
        ret = sdap_access_ppolicy_recv(subreq);
        break;
    default:
        ret = EINVAL;
        DEBUG(SSSDBG_MINOR_FAILURE, "Unknown access control type: %d.\n",
              state->ac_type);
        break;
    }

    talloc_zfree(subreq);
    if (ret != EOK) {
        if (ret == ERR_ACCESS_DENIED) {
            DEBUG(SSSDBG_TRACE_FUNC, "Access was denied.\n");
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Error retrieving access check result.\n");
        }
        tevent_req_error(req, ret);
        return;
    }

    state->current_rule++;

    ret = sdap_access_check_next_rule(state, req);
    switch (ret) {
    case EAGAIN:
        return;
    case EOK:
        tevent_req_done(req);
        return;
    default:
        tevent_req_error(req, ret);
        return;
    }
}

errno_t sdap_access_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

#define SHADOW_EXPIRE_MSG "Account expired according to shadow attributes"

static errno_t sdap_account_expired_shadow(struct pam_data *pd,
                                           struct ldb_message *user_entry)
{
    int ret;
    const char *val;
    long sp_expire;
    long today;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Performing access shadow check for user [%s]\n", pd->user);

    val = ldb_msg_find_attr_as_string(user_entry, SYSDB_SHADOWPW_EXPIRE, NULL);
    if (val == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Shadow expire attribute not found. "
                  "Access will be granted.\n");
        return EOK;
    }
    ret = string_to_shadowpw_days(val, &sp_expire);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to retrieve shadow expire date.\n");
        return ret;
    }

    today = (long) (time(NULL) / (60 * 60 * 24));
    if (sp_expire > 0 && today >= sp_expire) {

        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(SHADOW_EXPIRE_MSG),
                               (const uint8_t *) SHADOW_EXPIRE_MSG);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }

        return ERR_ACCOUNT_EXPIRED;
    }

    return EOK;
}

#define UAC_ACCOUNTDISABLE 0x00000002
#define AD_NEVER_EXP 0x7fffffffffffffffLL
#define AD_TO_UNIX_TIME_CONST 11644473600LL
#define AD_DISABLE_MESSAGE "The user account is disabled on the AD server"
#define AD_EXPIRED_MESSAGE "The user account is expired on the AD server"

static bool ad_account_expired(uint64_t expiration_time)
{
    time_t now;
    int err;
    uint64_t nt_now;

    if (expiration_time == 0 || expiration_time == AD_NEVER_EXP) {
        return false;
    }

    now = time(NULL);
    if (now == ((time_t) -1)) {
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "time failed [%d][%s].\n", err, strerror(err));
        return true;
    }

    /* NT timestamps start at 1601-01-01 and use a 100ns base */
    nt_now = (now + AD_TO_UNIX_TIME_CONST) * 1000 * 1000 * 10;

    if (nt_now > expiration_time) {
        return true;
    }

    return false;
}

static errno_t sdap_account_expired_ad(struct pam_data *pd,
                                       struct ldb_message *user_entry)
{
    uint32_t uac;
    uint64_t expiration_time;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Performing AD access check for user [%s]\n", pd->user);

    uac = ldb_msg_find_attr_as_uint(user_entry, SYSDB_AD_USER_ACCOUNT_CONTROL,
                                    0);
    DEBUG(SSSDBG_TRACE_ALL, "User account control for user [%s] is [%X].\n",
              pd->user, uac);

    expiration_time = ldb_msg_find_attr_as_uint64(user_entry,
                                                  SYSDB_AD_ACCOUNT_EXPIRES, 0);
    DEBUG(SSSDBG_TRACE_ALL,
          "Expiration time for user [%s] is [%"PRIu64"].\n",
           pd->user, expiration_time);

    if (uac & UAC_ACCOUNTDISABLE) {

        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(AD_DISABLE_MESSAGE),
                               (const uint8_t *) AD_DISABLE_MESSAGE);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }

        return ERR_ACCESS_DENIED;

    } else if (ad_account_expired(expiration_time)) {

        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(AD_EXPIRED_MESSAGE),
                               (const uint8_t *) AD_EXPIRED_MESSAGE);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }

        return ERR_ACCOUNT_EXPIRED;
    }

    return EOK;
}

#define RHDS_LOCK_MSG "The user account is locked on the server"

static errno_t sdap_account_expired_rhds(struct pam_data *pd,
                                         struct ldb_message *user_entry)
{
    bool locked;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Performing RHDS access check for user [%s]\n", pd->user);

    locked = ldb_msg_find_attr_as_bool(user_entry, SYSDB_NS_ACCOUNT_LOCK, false);
    DEBUG(SSSDBG_TRACE_ALL, "Account for user [%s] is%s locked.\n", pd->user,
              locked ? "" : " not" );

    if (locked) {
        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(RHDS_LOCK_MSG),
                               (const uint8_t *) RHDS_LOCK_MSG);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }

        return ERR_ACCESS_DENIED;
    }

    return EOK;
}

#define NDS_DISABLE_MSG "The user account is disabled on the server"
#define NDS_EXPIRED_MSG "The user account is expired"
#define NDS_TIME_MAP_MSG "The user account is not allowed at this time"

bool nds_check_expired(const char *exp_time_str)
{
    time_t expire_time;
    time_t now;
    errno_t ret;

    if (exp_time_str == NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "ndsLoginExpirationTime is not set, access granted.\n");
        return false;
    }

    ret = sss_utc_to_time_t(exp_time_str, "%Y%m%d%H%M%SZ",
                            &expire_time);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sss_utc_to_time_t failed with %d:%s.\n",
              ret, sss_strerror(ret));
        return true;
    }

    now = time(NULL);
    DEBUG(SSSDBG_TRACE_ALL,
          "Time info: tzname[0] [%s] tzname[1] [%s] timezone [%ld] "
          "daylight [%d] now [%"SPRItime"] expire_time [%"SPRItime"].\n",
          tzname[0], tzname[1], timezone, daylight, now, expire_time);

    if (difftime(now, expire_time) > 0.0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "NDS account expired.\n");
        return true;
    }

    return false;
}

/* There is no real documentation of the byte string value of
 * loginAllowedTimeMap, but some good example code in
 * http://http://developer.novell.com/documentation/samplecode/extjndi_sample/CheckBind.java.html
 */
static bool nds_check_time_map(const struct ldb_val *time_map)
{
    time_t now;
    struct tm *tm_now;
    size_t map_index;
    div_t q;
    uint8_t mask = 0;

    if (time_map == NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "loginAllowedTimeMap is missing, access granted.\n");
        return false;
    }

    if (time_map->length != 42) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Allowed time map has the wrong size, "
               "got [%zu], expected 42.\n", time_map->length);
        return true;
    }

    now = time(NULL);
    tm_now = gmtime(&now);

    map_index = tm_now->tm_wday * 48 + tm_now->tm_hour * 2 +
                (tm_now->tm_min < 30 ? 0 : 1);

    if (map_index > 335) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected index value [%zu] for time map.\n", map_index);
        return true;
    }

    q = div(map_index, 8);

    if (q.quot > 41 || q.quot < 0 || q.rem > 7 || q.rem < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected result of div(), [%zu][%d][%d].\n",
               map_index, q.quot, q.rem);
        return true;
    }

    if (q.rem > 0) {
        mask = 1 << q.rem;
    }

    if (time_map->data[q.quot] & mask) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Access allowed by time map.\n");
        return false;
    }

    return true;
}

static errno_t sdap_account_expired_nds(struct pam_data *pd,
                                         struct ldb_message *user_entry)
{
    bool locked = true;
    int ret;
    const char *exp_time_str;
    const struct ldb_val *time_map;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Performing NDS access check for user [%s]\n", pd->user);

    locked = ldb_msg_find_attr_as_bool(user_entry, SYSDB_NDS_LOGIN_DISABLED,
                                       false);
    DEBUG(SSSDBG_TRACE_ALL, "Account for user [%s] is%s disabled.\n", pd->user,
              locked ? "" : " not");

    if (locked) {
        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(NDS_DISABLE_MSG),
                               (const uint8_t *) NDS_DISABLE_MSG);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }

        return ERR_ACCESS_DENIED;

    } else {
        exp_time_str = ldb_msg_find_attr_as_string(user_entry,
                                                SYSDB_NDS_LOGIN_EXPIRATION_TIME,
                                                NULL);
        locked = nds_check_expired(exp_time_str);

        DEBUG(SSSDBG_TRACE_ALL,
              "Account for user [%s] is%s expired.\n", pd->user,
                  locked ? "" : " not");

        if (locked) {
            ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                                   sizeof(NDS_EXPIRED_MSG),
                                   (const uint8_t *) NDS_EXPIRED_MSG);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            }

            return ERR_ACCESS_DENIED;

        } else {
            time_map = ldb_msg_find_ldb_val(user_entry,
                                            SYSDB_NDS_LOGIN_ALLOWED_TIME_MAP);

            locked = nds_check_time_map(time_map);

            DEBUG(SSSDBG_TRACE_ALL,
                  "Account for user [%s] is%s locked at this time.\n",
                      pd->user, locked ? "" : " not");

            if (locked) {
                ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                                       sizeof(NDS_TIME_MAP_MSG),
                                       (const uint8_t *) NDS_TIME_MAP_MSG);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
                }

                return ERR_ACCESS_DENIED;
            }
        }
    }

    return EOK;
}

static errno_t sdap_account_expired(struct sdap_access_ctx *access_ctx,
                                    struct pam_data *pd,
                                    struct ldb_message *user_entry)
{
    const char *expire;
    int ret;

    expire = dp_opt_get_cstring(access_ctx->id_ctx->opts->basic,
                                SDAP_ACCOUNT_EXPIRE_POLICY);
    if (expire == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing account expire policy. Access denied\n");
        return ERR_ACCESS_DENIED;
    } else {
        if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_SHADOW) == 0) {
            ret = sdap_account_expired_shadow(pd, user_entry);
            if (ret == ERR_ACCOUNT_EXPIRED) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "sdap_account_expired_shadow: %s.\n", sss_strerror(ret));
            } else if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_account_expired_shadow failed.\n");
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_AD) == 0) {
            ret = sdap_account_expired_ad(pd, user_entry);
            if (ret == ERR_ACCOUNT_EXPIRED || ret == ERR_ACCESS_DENIED) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "sdap_account_expired_ad: %s.\n", sss_strerror(ret));
            } else if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "sdap_account_expired_ad failed.\n");
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_RHDS) == 0 ||
                   strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_IPA) == 0 ||
                   strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_389DS) == 0) {
            ret = sdap_account_expired_rhds(pd, user_entry);
            if (ret == ERR_ACCESS_DENIED) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "sdap_account_expired_rhds: %s.\n", sss_strerror(ret));
            } else if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_account_expired_rhds failed.\n");
            }

            if (ret == EOK &&
                    strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_IPA) == 0) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "IPA access control succeeded, checking AD "
                      "access control\n");
                ret = sdap_account_expired_ad(pd, user_entry);
                if (ret == ERR_ACCOUNT_EXPIRED || ret == ERR_ACCESS_DENIED) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                        "sdap_account_expired_ad: %s.\n", sss_strerror(ret));
                } else if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "sdap_account_expired_ad failed.\n");
                }
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_NDS) == 0) {
            ret = sdap_account_expired_nds(pd, user_entry);
            if (ret == ERR_ACCESS_DENIED) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "sdap_account_expired_nds: %s.\n", sss_strerror(ret));
            } else if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_account_expired_nds failed.\n");
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unsupported LDAP account expire policy [%s]. "
                      "Access denied.\n", expire);
            ret = ERR_ACCESS_DENIED;
        }
    }

    return ret;
}

static errno_t perform_pwexpire_policy(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *domain,
                                       struct pam_data *pd,
                                       enum sdap_access_type access_type,
                                       struct sdap_options *opts)
{
    enum pwexpire pw_expire_type;
    void *pw_expire_data;
    errno_t ret;
    char *dn;

    ret = get_user_dn(mem_ctx, domain, access_type, opts, pd->user, &dn,
                      &pw_expire_type, &pw_expire_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "get_user_dn returned %d:[%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = check_pwexpire_policy(pw_expire_type, pw_expire_data, pd,
                                domain->pwd_expiration_warning, opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "check_pwexpire_policy returned %d:[%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    return ret;
}

struct sdap_access_filter_req_ctx {
    const char *username;
    const char *filter;
    struct tevent_context *ev;
    struct sdap_access_ctx *access_ctx;
    struct sdap_options *opts;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *sdap_op;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;
    /* cached result of access control checks */
    bool cached_access;
    const char *basedn;
};

static errno_t sdap_access_decide_offline(bool cached_ac);
static int sdap_access_filter_retry(struct tevent_req *req);
static void sdap_access_ppolicy_connect_done(struct tevent_req *subreq);
static errno_t sdap_access_ppolicy_get_lockout_step(struct tevent_req *req);
static void sdap_access_filter_connect_done(struct tevent_req *subreq);
static void sdap_access_filter_done(struct tevent_req *req);
static struct tevent_req *sdap_access_filter_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct be_ctx *be_ctx,
                                             struct sss_domain_info *domain,
                                             struct sdap_access_ctx *access_ctx,
                                             struct sdap_id_conn_ctx *conn,
                                             const char *username,
                                             struct ldb_message *user_entry)
{
    struct sdap_access_filter_req_ctx *state;
    struct tevent_req *req;
    char *clean_username;
    errno_t ret = ERR_INTERNAL;
    char *name;

    req = tevent_req_create(mem_ctx, &state, struct sdap_access_filter_req_ctx);
    if (req == NULL) {
        return NULL;
    }

    if (access_ctx->filter == NULL || *access_ctx->filter == '\0') {
        /* If no filter is set, default to restrictive */
        DEBUG(SSSDBG_TRACE_FUNC, "No filter set. Access is denied.\n");
        ret = ERR_ACCESS_DENIED;
        goto done;
    }

    state->filter = NULL;
    state->username = username;
    state->opts = access_ctx->id_ctx->opts;
    state->conn = conn;
    state->ev = ev;
    state->access_ctx = access_ctx;
    state->domain = domain;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Performing access filter check for user [%s]\n", username);

    state->cached_access = ldb_msg_find_attr_as_bool(user_entry,
                                                     SYSDB_LDAP_ACCESS_FILTER,
                                                     false);

    /* Ok, we have one result, check if we are online or offline */
    if (be_is_offline(be_ctx)) {
        /* Ok, we're offline. Return from the cache */
        ret = sdap_access_decide_offline(state->cached_access);
        goto done;
    }

    ret = sdap_get_basedn_user_entry(user_entry, state->username,
                                     &state->basedn);
    if (ret != EOK) {
        goto done;
    }

    /* Construct the filter */
    ret = sss_parse_internal_fqname(state, username, &name, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not parse [%s] into name and "
              "domain components, access might fail\n", username);
        name = discard_const(username);
    }

    ret = sss_filter_sanitize(state, name, &clean_username);
    if (ret != EOK) {
        goto done;
    }

    state->filter = talloc_asprintf(
        state,
        "(&(%s=%s)(objectclass=%s)%s)",
        state->opts->user_map[SDAP_AT_USER_NAME].name,
        clean_username,
        state->opts->user_map[SDAP_OC_USER].name,
        state->access_ctx->filter);
    if (state->filter == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not construct access filter\n");
        ret = ENOMEM;
        goto done;
    }
    talloc_zfree(clean_username);

    DEBUG(SSSDBG_TRACE_FUNC, "Checking filter against LDAP\n");

    state->sdap_op = sdap_id_op_create(state,
                                       state->conn->conn_cache);
    if (!state->sdap_op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sdap_access_filter_retry(req);
    if (ret != EOK) {
        goto done;
    }

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

/* Helper function,
 * cached_ac => access granted
 * !cached_ac => access denied
 */
static errno_t sdap_access_decide_offline(bool cached_ac)
{
    if (cached_ac) {
        DEBUG(SSSDBG_TRACE_FUNC, "Access granted by cached credentials\n");
        return EOK;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Access denied by cached credentials\n");
        return ERR_ACCESS_DENIED;
    }
}

static int sdap_access_filter_retry(struct tevent_req *req)
{
    struct sdap_access_filter_req_ctx *state =
            tevent_req_data(req, struct sdap_access_filter_req_ctx);
    struct tevent_req *subreq;
    int ret;

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (!subreq) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_id_op_connect_send failed: %d (%s)\n", ret, strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_access_filter_connect_done, req);
    return EOK;
}

static void sdap_access_filter_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_access_filter_req_ctx *state =
            tevent_req_data(req, struct sdap_access_filter_req_ctx);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            ret = sdap_access_decide_offline(state->cached_access);
            if (ret == EOK) {
                tevent_req_done(req);
                return;
            }
        }

        tevent_req_error(req, ret);
        return;
    }

    /* Connection to LDAP succeeded
     * Send filter request
     */
    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->basedn,
                                   LDAP_SCOPE_BASE,
                                   state->filter, NULL,
                                   NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not start LDAP communication\n");
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq, sdap_access_filter_done, req);
}

static void sdap_access_filter_done(struct tevent_req *subreq)
{
    int ret, tret, dp_error;
    size_t num_results;
    bool found = false;
    struct sysdb_attrs **results;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_filter_req_ctx *state =
            tevent_req_data(req, struct sdap_access_filter_req_ctx);

    ret = sdap_get_generic_recv(subreq, state,
                                &num_results, &results);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OK) {
            /* retry */
            tret = sdap_access_filter_retry(req);
            if (tret == EOK) {
                return;
            }
        } else if (dp_error == DP_ERR_OFFLINE) {
            ret = sdap_access_decide_offline(state->cached_access);
        } else if (ret == ERR_INVALID_FILTER) {
            sss_log(SSS_LOG_ERR, MALFORMED_FILTER, state->filter);
            DEBUG(SSSDBG_CRIT_FAILURE, MALFORMED_FILTER, state->filter);
            ret = ERR_ACCESS_DENIED;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_get_generic_send() returned error [%d][%s]\n",
                      ret, sss_strerror(ret));
        }

        goto done;
    }

    /* Check the number of responses we got
     * If it's exactly 1, we passed the check
     * If it's < 1, we failed the check
     * Anything else is an error
     */
    if (num_results < 1) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "User [%s] was not found with the specified filter. "
                  "Denying access.\n", state->username);
        found = false;
    }
    else if (results == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "num_results > 0, but results is NULL\n");
        ret = ERR_INTERNAL;
        goto done;
    }
    else if (num_results > 1) {
        /* It should not be possible to get more than one reply
         * here, since we're doing a base-scoped search
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Received multiple replies\n");
        ret = ERR_INTERNAL;
        goto done;
    }
    else { /* Ok, we got a single reply */
        found = true;
    }

    if (found) {
        /* Save "allow" to the cache for future offline access checks. */
        DEBUG(SSSDBG_TRACE_FUNC, "Access granted by online lookup\n");
        ret = EOK;
    }
    else {
        /* Save "disallow" to the cache for future offline
         * access checks.
         */
        DEBUG(SSSDBG_TRACE_FUNC, "Access denied by online lookup\n");
        ret = ERR_ACCESS_DENIED;
    }

    tret = sdap_save_user_cache_bool(state->domain, state->username,
                                     SYSDB_LDAP_ACCESS_FILTER, found);
    if (tret != EOK) {
        /* Failing to save to the cache is non-fatal.
         * Just return the result.
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set user access attribute\n");
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    }
    else {
        tevent_req_error(req, ret);
    }
}

static errno_t sdap_access_filter_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

#define AUTHR_SRV_MISSING_MSG "Authorized service attribute missing, " \
                              "access denied"
#define AUTHR_SRV_DENY_MSG "Access denied by authorized service attribute"
#define AUTHR_SRV_NO_MATCH_MSG "Authorized service attribute has " \
                               "no matching rule, access denied"

static errno_t sdap_access_service(struct pam_data *pd,
                                   struct ldb_message *user_entry)
{
    errno_t ret, tret;
    struct ldb_message_element *el;
    unsigned int i;
    char *service;

    el = ldb_msg_find_element(user_entry, SYSDB_AUTHORIZED_SERVICE);
    if (!el || el->num_values == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing authorized services. Access denied\n");

        tret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(AUTHR_SRV_MISSING_MSG),
                               (const uint8_t *) AUTHR_SRV_MISSING_MSG);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }

        return ERR_ACCESS_DENIED;
    }

    ret = ENOENT;

    for (i = 0; i < el->num_values; i++) {
        service = (char *)el->values[i].data;
        if (service[0] == '!' &&
                strcasecmp(pd->service, service+1) == 0) {
            /* This service is explicitly denied */
            DEBUG(SSSDBG_CONF_SETTINGS, "Access denied by [%s]\n", service);

            tret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                                   sizeof(AUTHR_SRV_DENY_MSG),
                                   (const uint8_t *) AUTHR_SRV_DENY_MSG);
            if (tret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
            }

            /* A denial trumps all. Break here */
            return ERR_ACCESS_DENIED;

        } else if (strcasecmp(pd->service, service) == 0) {
            /* This service is explicitly allowed */
            DEBUG(SSSDBG_CONF_SETTINGS, "Access granted for [%s]\n", service);
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
            ret = EOK;
        } else if (strcmp("*", service) == 0) {
            /* This user has access to all services */
            DEBUG(SSSDBG_CONF_SETTINGS, "Access granted to all services\n");
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
            ret = EOK;
        }
    }

    if (ret == ENOENT) {
        DEBUG(SSSDBG_CONF_SETTINGS, "No matching service rule found\n");

        tret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(AUTHR_SRV_NO_MATCH_MSG),
                               (const uint8_t *) AUTHR_SRV_NO_MATCH_MSG);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }

        ret = ERR_ACCESS_DENIED;
    }

    return ret;
}

static errno_t sdap_save_user_cache_bool(struct sss_domain_info *domain,
                                         const char *username,
                                         const char *attr_name,
                                         bool value)
{
    errno_t ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(NULL);
    if (attrs == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not create attrs\n");
        goto done;
    }

    ret = sysdb_attrs_add_bool(attrs, attr_name, value);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up attr value\n");
        goto done;
    }

    ret = sysdb_set_user_attr(domain, username, attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set user access attribute\n");
        goto done;
    }

done:
    talloc_free(attrs);
    return ret;
}

static errno_t sdap_access_host_comp(struct ldb_message_element *el, char *hostname)
{
    errno_t ret = ENOENT;
    unsigned int i;
    char *host;

    for (i = 0; i < el->num_values; i++) {
        host = (char *)el->values[i].data;
        if (host[0] == '!' &&
                strcasecmp(hostname, host+1) == 0) {
            /* This host is explicitly denied */
            DEBUG(SSSDBG_CONF_SETTINGS, "Access denied by [%s]\n", host);
            /* A denial trumps all. Break here */
            return ERR_ACCESS_DENIED;

        } else if (strcasecmp(hostname, host) == 0) {
            /* This host is explicitly allowed */
            DEBUG(SSSDBG_CONF_SETTINGS, "Access granted for [%s]\n", host);
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
            ret = EOK;
        } else if (strcmp("*", host) == 0) {
            /* This user has access to all hosts */
            DEBUG(SSSDBG_CONF_SETTINGS, "Access granted to all hosts\n");
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
            ret = EOK;
        }
    }
    return ret;
}

static errno_t sdap_access_host(struct ldb_message *user_entry)
{
    errno_t ret;
    struct ldb_message_element *el;
    char hostname[HOST_NAME_MAX + 1];
    struct addrinfo *res = NULL;
    struct addrinfo hints;

    el = ldb_msg_find_element(user_entry, SYSDB_AUTHORIZED_HOST);
    if (!el || el->num_values == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing hosts. Access denied\n");
        return ERR_ACCESS_DENIED;
    }

    if (gethostname(hostname, sizeof(hostname)) == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to get system hostname. Access denied\n");
        return ERR_ACCESS_DENIED;
    }
    hostname[HOST_NAME_MAX] = '\0';

    /* Canonicalize the hostname */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_CANONNAME;
    ret = getaddrinfo(hostname, NULL, &hints, &res);
    if (ret != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to canonicalize hostname\n");
        freeaddrinfo(res);
        res = NULL;
    }

    ret = sdap_access_host_comp(el, hostname);
    if (ret == ENOENT && res != NULL && res->ai_canonname != NULL) {
        ret = sdap_access_host_comp(el, res->ai_canonname);
    }
    freeaddrinfo(res);

    if (ret == ENOENT) {
        DEBUG(SSSDBG_CONF_SETTINGS, "No matching host rule found\n");
        ret = ERR_ACCESS_DENIED;
    }

    return ret;
}

errno_t sdap_access_rhost(struct ldb_message *user_entry, char *pam_rhost)
{
    errno_t ret;
    struct ldb_message_element *el;
    char *be_rhost_rule;
    unsigned int i;

    /* If user_entry is NULL do not perform any checks */
    if (user_entry == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "user_entry is NULL, that is not possible, "
              "so we just reject access\n");
        return ERR_ACCESS_DENIED;
    }

    /* If pam_rhost is NULL do not perform any checks */
    if (pam_rhost == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pam_rhost is NULL, no rhost check is possible\n");
        return EOK;
    }

    /* When the access is local we get empty string as pam_rhost
       in which case we should not evaluate rhost access rules */
    /* FIXME: I think ideally should have LDAP to define what to do in
     * this case */
    if (pam_rhost[0] == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pam_rhost is empty, possible local access, "
              "no rhost check possible\n");
        return EOK;
    }

    /* If rhost validation is enabled and entry has no relevant attribute -
     * deny access */
    el = ldb_msg_find_element(user_entry, SYSDB_AUTHORIZED_RHOST);
    if (!el || el->num_values == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Missing rhost entries. Access denied\n");
        return ERR_ACCESS_DENIED;
    }

    ret = ENOENT;

    for (i = 0; i < el->num_values; i++) {
        be_rhost_rule = (char *)el->values[i].data;
        if (be_rhost_rule[0] == '!'
                && strcasecmp(pam_rhost, be_rhost_rule+1) == 0) {
            /* This rhost is explicitly denied */
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Access from [%s] denied by [%s]\n",
                  pam_rhost, be_rhost_rule);
            /* A denial trumps all. Break here */
            return ERR_ACCESS_DENIED;
        } else if (strcasecmp(pam_rhost, be_rhost_rule) == 0) {
            /* This rhost is explicitly allowed */
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Access from [%s] granted by [%s]\n",
                  pam_rhost, be_rhost_rule);
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
            ret = EOK;
        } else if (strcmp("*", be_rhost_rule) == 0) {
            /* This user has access from anywhere */
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Access from [%s] granted by [*]\n", pam_rhost);
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
            ret = EOK;
        }
    }

    if (ret == ENOENT) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No matching rhost rules found\n");
        ret = ERR_ACCESS_DENIED;
    }

    return ret;
}

static void sdap_access_ppolicy_get_lockout_done(struct tevent_req *subreq);
static int sdap_access_ppolicy_retry(struct tevent_req *req);
static errno_t sdap_access_ppolicy_step(struct tevent_req *req);
static void sdap_access_ppolicy_step_done(struct tevent_req *subreq);

struct sdap_access_ppolicy_req_ctx {
    const char *username;
    const char *filter;
    struct tevent_context *ev;
    struct sdap_access_ctx *access_ctx;
    struct sdap_options *opts;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *sdap_op;
    struct sysdb_handle *handle;
    struct sss_domain_info *domain;
    /* cached results of access control checks */
    bool cached_access;
    const char *basedn;
    /* default DNs to ppolicy */
    const char **ppolicy_dns;
    unsigned int ppolicy_dns_index;
    enum sdap_pwpolicy_mode pwpol_mode;
};

static struct tevent_req *
sdap_access_ppolicy_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct be_ctx *be_ctx,
                         struct sss_domain_info *domain,
                         struct sdap_access_ctx *access_ctx,
                         struct sdap_id_conn_ctx *conn,
                         const char *username,
                         struct ldb_message *user_entry,
                         enum sdap_pwpolicy_mode pwpol_mode)
{
    struct sdap_access_ppolicy_req_ctx *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx,
                            &state, struct sdap_access_ppolicy_req_ctx);
    if (req == NULL) {
        return NULL;
    }

    state->filter = NULL;
    state->username = username;
    state->opts = access_ctx->id_ctx->opts;
    state->conn = conn;
    state->ev = ev;
    state->access_ctx = access_ctx;
    state->domain = domain;
    state->ppolicy_dns_index = 0;
    state->pwpol_mode = pwpol_mode;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Performing access ppolicy check for user [%s]\n", username);

    state->cached_access = ldb_msg_find_attr_as_bool(
        user_entry, SYSDB_LDAP_ACCESS_CACHED_LOCKOUT, false);

    /* Ok, we have one result, check if we are online or offline */
    if (be_is_offline(be_ctx)) {
        /* Ok, we're offline. Return from the cache */
        ret = sdap_access_decide_offline(state->cached_access);
        goto done;
    }

    ret = sdap_get_basedn_user_entry(user_entry, state->username,
                                     &state->basedn);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Checking ppolicy against LDAP\n");

    state->sdap_op = sdap_id_op_create(state,
                                       state->conn->conn_cache);
    if (!state->sdap_op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sdap_access_ppolicy_retry(req);
    if (ret != EOK) {
        goto done;
    }

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

static int sdap_access_ppolicy_retry(struct tevent_req *req)
{
    struct sdap_access_ppolicy_req_ctx *state;
    struct tevent_req *subreq;
    int ret;

    state = tevent_req_data(req, struct sdap_access_ppolicy_req_ctx);
    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (!subreq) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_id_op_connect_send failed: %d (%s)\n",
              ret, sss_strerror(ret));
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_access_ppolicy_connect_done, req);
    return EOK;
}

static const char**
get_default_ppolicy_dns(TALLOC_CTX *mem_ctx, struct sdap_domain *sdom)
{
    const char **ppolicy_dns;
    int count = 0;
    int i;

    while(sdom->search_bases[count] != NULL) {
        count++;
    }

    /* +1 to have space for final NULL */
    ppolicy_dns = talloc_array(mem_ctx, const char*, count + 1);

    for(i = 0; i < count; i++) {
        ppolicy_dns[i] = talloc_asprintf(mem_ctx, "cn=ppolicy,ou=policies,%s",
                                         sdom->search_bases[i]->basedn);
    }

    ppolicy_dns[count] = NULL;
    return ppolicy_dns;
}

static void sdap_access_ppolicy_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_access_ppolicy_req_ctx *state;
    int ret, dp_error;
    const char *ppolicy_dn;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_access_ppolicy_req_ctx);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            ret = sdap_access_decide_offline(state->cached_access);
            if (ret == EOK) {
                tevent_req_done(req);
                return;
            }
        }

        tevent_req_error(req, ret);
        return;
    }

    ppolicy_dn = dp_opt_get_string(state->opts->basic,
                                   SDAP_PWDLOCKOUT_DN);

    /* option was configured */
    if (ppolicy_dn != NULL) {
        state->ppolicy_dns = talloc_array(state, const char*, 2);
        if (state->ppolicy_dns == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not allocate ppolicy_dns.\n");
            tevent_req_error(req, ERR_INTERNAL);
            return;
        }

        state->ppolicy_dns[0] = ppolicy_dn;
        state->ppolicy_dns[1] = NULL;

    } else {
        /* try to determine default value */
        DEBUG(SSSDBG_CONF_SETTINGS,
              "ldap_pwdlockout_dn was not defined in configuration file.\n");

        state->ppolicy_dns = get_default_ppolicy_dns(state, state->opts->sdom);
        if (state->ppolicy_dns == NULL) {
            tevent_req_error(req, ERR_INTERNAL);
            return;
        }
    }

    /* Connection to LDAP succeeded
     * Send 'pwdLockout' request
     */
    ret = sdap_access_ppolicy_get_lockout_step(req);
    if (ret != EOK && ret != EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sdap_access_ppolicy_get_lockout_step failed: [%d][%s]\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ERR_INTERNAL);
        return;
    }

    if (ret == EOK) {
        tevent_req_done(req);
    }
}

static errno_t
sdap_access_ppolicy_get_lockout_step(struct tevent_req *req)
{
    const char *attrs[] = { SYSDB_LDAP_ACCESS_LOCKOUT, NULL };
    struct sdap_access_ppolicy_req_ctx *state;
    struct tevent_req *subreq;
    errno_t ret;

    state = tevent_req_data(req, struct sdap_access_ppolicy_req_ctx);

    /* no more DNs to try */
    if (state->ppolicy_dns[state->ppolicy_dns_index] == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No more DNs to try.\n");
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Trying to find out if ppolicy is enabled using the DN: %s\n",
          state->ppolicy_dns[state->ppolicy_dns_index]);

    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->ppolicy_dns[state->ppolicy_dns_index],
                                   LDAP_SCOPE_BASE,
                                   NULL, attrs,
                                   NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not start LDAP communication\n");
        ret = EIO;
        goto done;
    }

    /* try next basedn */
    state->ppolicy_dns_index++;
    tevent_req_set_callback(subreq, sdap_access_ppolicy_get_lockout_done, req);

    ret = EAGAIN;

done:
    return ret;
}

static void sdap_access_ppolicy_get_lockout_done(struct tevent_req *subreq)
{
    int ret, tret, dp_error;
    size_t num_results;
    bool pwdLockout = false;
    struct sysdb_attrs **results;
    struct tevent_req *req;
    struct sdap_access_ppolicy_req_ctx *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_access_ppolicy_req_ctx);

    ret = sdap_get_generic_recv(subreq, state, &num_results, &results);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot retrieve ppolicy\n");
        ret = ERR_NETWORK_IO;
        goto done;
    }

    /* Check the number of responses we got
     * If it's exactly 1, we passed the check
     * If it's < 1, we failed the check
     * Anything else is an error
     */
    /* Didn't find ppolicy attribute */
    if (num_results < 1) {
        /* Try using next $search_base */
        ret = sdap_access_ppolicy_get_lockout_step(req);
        if (ret == EOK) {
            /* No more search bases to try */
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "[%s] was not found. Granting access.\n",
                  SYSDB_LDAP_ACCESS_LOCKOUT);
        } else {
            if (ret != EAGAIN) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_access_ppolicy_get_lockout_step failed: "
                      "[%d][%s]\n",
                      ret, sss_strerror(ret));
            }
            goto done;
        }
    } else if (results == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "num_results > 0, but results is NULL\n");
        ret = ERR_INTERNAL;
        goto done;
    } else if (num_results > 1) {
        /* It should not be possible to get more than one reply
         * here, since we're doing a base-scoped search
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Received multiple replies\n");
        ret = ERR_INTERNAL;
        goto done;
    } else { /* Ok, we got a single reply */
        ret = sysdb_attrs_get_bool(results[0], SYSDB_LDAP_ACCESS_LOCKOUT,
                                   &pwdLockout);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Error reading %s: [%s]\n", SYSDB_LDAP_ACCESS_LOCKOUT,
                  sss_strerror(ret));
            ret = ERR_INTERNAL;
            goto done;
        }
    }

    if (pwdLockout) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Password policy is enabled on LDAP server.\n");

        /* ppolicy is enabled => find out if account is locked */
        ret = sdap_access_ppolicy_step(req);
        if (ret != EOK && ret != EAGAIN) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_access_ppolicy_step failed: [%d][%s].\n",
                  ret, sss_strerror(ret));
        }
        goto done;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Password policy is disabled on LDAP server "
              "- storing 'access granted' in sysdb.\n");
        tret = sdap_save_user_cache_bool(state->domain, state->username,
                                         SYSDB_LDAP_ACCESS_CACHED_LOCKOUT,
                                         true);
        if (tret != EOK) {
            /* Failing to save to the cache is non-fatal.
             * Just return the result.
             */
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to set user locked attribute\n");
            goto done;
        }

        ret = EOK;
        goto done;
    }

done:
    if (ret != EAGAIN) {
        /* release connection */
        tret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_get_generic_send() returned error [%d][%s]\n",
                  ret, sss_strerror(ret));
        }

        if (ret == EOK) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
    }
}

errno_t sdap_access_ppolicy_step(struct tevent_req *req)
{
    errno_t ret;
    struct tevent_req *subreq;
    struct sdap_access_ppolicy_req_ctx *state;
    const char *attrs[] = { SYSDB_LDAP_ACCESS_LOCKED_TIME,
                            SYSDB_LDAP_ACESS_LOCKOUT_DURATION,
                            NULL };

    state = tevent_req_data(req, struct sdap_access_ppolicy_req_ctx);

    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->basedn,
                                   LDAP_SCOPE_BASE,
                                   NULL, attrs,
                                   NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);

    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_get_generic_send failed.\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_access_ppolicy_step_done, req);
    ret = EAGAIN;

done:
    return ret;
}

static errno_t
is_account_locked(const char *pwdAccountLockedTime,
                  const char *pwdAccountLockedDurationTime,
                  enum sdap_pwpolicy_mode pwpol_mode,
                  const char *username,
                  bool *_locked)
{
    errno_t ret;
    time_t lock_time;
    time_t duration;
    time_t now;
    bool locked;
    char *endptr;

    /* Default action is to consider account to be locked. */
    locked = true;

    /* account is permanently locked */
    if (strcasecmp(pwdAccountLockedTime,
                   PERMANENTLY_LOCKED_ACCOUNT) == 0) {
        ret = EOK;
        goto done;
    }

    switch(pwpol_mode) {
    case PWP_LOCKOUT_ONLY:
        /* We do *not* care about exact value of account locked time, we
         * only *do* care if the value is equal to
         * PERMANENTLY_LOCKED_ACCOUNT, which means that account is locked
         * permanently.
         */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Account of: %s is being blocked by password policy, "
              "but value: [%s] value is ignored by SSSD.\n",
              username, pwdAccountLockedTime);
        locked = false;
        break;
    case PWP_LOCKOUT_EXPIRE:
        /* Account may be locked out from natural reasons (too many attempts,
         * expired password). In this case, pwdAccountLockedTime is also set,
         * to the time of lock out.
         */
        ret = sss_utc_to_time_t(pwdAccountLockedTime, "%Y%m%d%H%M%SZ",
                                &lock_time);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, "sss_utc_to_time_t failed with %d:%s.\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        now = time(NULL);

        /* Account was NOT locked in past. */
        if (difftime(lock_time, now) > 0.0) {
            locked = false;
        } else if (pwdAccountLockedDurationTime != NULL) {
            duration = strtouint32(pwdAccountLockedDurationTime, &endptr, 0);
            if (errno || *endptr) {
                ret = errno ? errno : EINVAL;
                goto done;
            }
            /* Lockout has expired */
            if (duration != 0 && difftime(now, lock_time) > duration) {
                locked = false;
            }
        }
        break;
    case PWP_SENTINEL:
    default:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Unexpected value of password policy mode: %d.\n", pwpol_mode);
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_locked = locked;
    }

    return ret;
}

static void sdap_access_ppolicy_step_done(struct tevent_req *subreq)
{
    int ret, tret, dp_error;
    size_t num_results;
    bool locked = false;
    const char *pwdAccountLockedTime;
    const char *pwdAccountLockedDurationTime;
    struct sysdb_attrs **results;
    struct tevent_req *req;
    struct sdap_access_ppolicy_req_ctx *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_access_ppolicy_req_ctx);

    ret = sdap_get_generic_recv(subreq, state, &num_results, &results);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OK) {
            /* retry */
            tret = sdap_access_ppolicy_retry(req);
            if (tret == EOK) {
                return;
            }
        } else if (dp_error == DP_ERR_OFFLINE) {
            ret = sdap_access_decide_offline(state->cached_access);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_id_op_done() returned error [%d][%s]\n",
                  ret, sss_strerror(ret));
        }

        goto done;
    }

    /* Check the number of responses we got
     * If it's exactly 1, we passed the check
     * If it's < 1, we failed the check
     * Anything else is an error
     */
    if (num_results < 1) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "User [%s] was not found with the specified filter. "
              "Denying access.\n", state->username);
    } else if (results == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "num_results > 0, but results is NULL\n");
        ret = ERR_INTERNAL;
        goto done;
    } else if (num_results > 1) {
        /* It should not be possible to get more than one reply
         * here, since we're doing a base-scoped search
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Received multiple replies\n");
        ret = ERR_INTERNAL;
        goto done;
    } else { /* Ok, we got a single reply */
        ret = sysdb_attrs_get_string(results[0], SYSDB_LDAP_ACESS_LOCKOUT_DURATION,
                                     &pwdAccountLockedDurationTime);
        if (ret != EOK) {
            /* This attribute might not be set even if account is locked */
            pwdAccountLockedDurationTime = NULL;
        }

        ret = sysdb_attrs_get_string(results[0], SYSDB_LDAP_ACCESS_LOCKED_TIME,
                                     &pwdAccountLockedTime);
        if (ret == EOK) {

            ret = is_account_locked(pwdAccountLockedTime,
                                    pwdAccountLockedDurationTime,
                                    state->pwpol_mode,
                                    state->username,
                                    &locked);
            if (ret != EOK) {
                if (ret == ERR_TIMESPEC_NOT_SUPPORTED) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "timezone specifier in ppolicy is not supported\n");
                } else {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "is_account_locked failed: %d:[%s].\n",
                          ret, sss_strerror(ret));
                }

                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Account will be considered to be locked.\n");
                locked = true;
            }
        } else {
            /* Attribute SYSDB_LDAP_ACCESS_LOCKED_TIME in not be present unless
             * user's account is blocked by password policy.
             */
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Attribute %s failed to be obtained - [%d][%s].\n",
                  SYSDB_LDAP_ACCESS_LOCKED_TIME, ret, strerror(ret));
        }
    }

    if (locked) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Access denied by online lookup - account is locked.\n");
        ret = ERR_ACCESS_DENIED;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Access granted by online lookup - account is not locked.\n");
        ret = EOK;
    }

    /* Save '!locked' to the cache for future offline access checks.
     * Locked == true => access denied,
     * Locked == false => access granted
     */
    tret = sdap_save_user_cache_bool(state->domain, state->username,
                                     SYSDB_LDAP_ACCESS_CACHED_LOCKOUT,
                                     !locked);

    if (tret != EOK) {
        /* Failing to save to the cache is non-fatal.
         * Just return the result.
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set user locked attribute\n");
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static errno_t sdap_access_ppolicy_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static errno_t sdap_get_basedn_user_entry(struct ldb_message *user_entry,
                                          const char *username,
                                          const char **_basedn)
{
    const char *basedn;
    errno_t ret;

    basedn = ldb_msg_find_attr_as_string(user_entry, SYSDB_ORIG_DN, NULL);
    if (basedn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,"Could not find originalDN for user [%s]\n",
              username);
        ret = EINVAL;
        goto done;
    }

    *_basedn = basedn;
    ret = EOK;

done:
    return ret;
}

static errno_t get_access_filter(TALLOC_CTX *mem_ctx,
                                 struct dp_option *opts,
                                 const char **_filter)
{
    const char *filter;

    filter = dp_opt_get_cstring(opts, SDAP_ACCESS_FILTER);
    if (filter == NULL) {
        /* It's okay if this is NULL. In that case we will simply act
         * like the 'deny' provider.
         */
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Warning: LDAP access rule 'filter' is set, "
              "but no ldap_access_filter configured. "
              "All domain users will be denied access.\n");
        return EOK;
    }

    filter = sdap_get_access_filter(mem_ctx, filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    *_filter = filter;

    return EOK;
}

static errno_t check_expire_policy(struct dp_option *opts)
{
    const char *expire_policy;
    bool matched_policy = false;
    const char *policies[] = {LDAP_ACCOUNT_EXPIRE_SHADOW,
                              LDAP_ACCOUNT_EXPIRE_AD,
                              LDAP_ACCOUNT_EXPIRE_NDS,
                              LDAP_ACCOUNT_EXPIRE_RHDS,
                              LDAP_ACCOUNT_EXPIRE_IPA,
                              LDAP_ACCOUNT_EXPIRE_389DS,
                              NULL};

    expire_policy = dp_opt_get_cstring(opts, SDAP_ACCOUNT_EXPIRE_POLICY);
    if (expire_policy == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Warning: LDAP access rule 'expire' is set, "
              "but no ldap_account_expire_policy configured. "
              "All domain users will be denied access.\n");
        return EOK;
    }

    for (unsigned i = 0; policies[i] != NULL; i++) {
        if (strcasecmp(expire_policy, policies[i]) == 0) {
            matched_policy = true;
            break;
        }
    }

    if (matched_policy == false) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unsupported LDAP account expire policy [%s].\n",
              expire_policy);
        return EINVAL;
    }

    return EOK;
}

/* Please use this only for short lists */
static errno_t check_order_list_for_duplicates(char **list,
                                               bool case_sensitive)
{
    size_t c;
    size_t d;
    int cmp;

    for (c = 0; list[c] != NULL; c++) {
        for (d = c + 1; list[d] != NULL; d++) {
            if (case_sensitive) {
                cmp = strcmp(list[c], list[d]);
            } else {
                cmp = strcasecmp(list[c], list[d]);
            }
            if (cmp == 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Duplicate string [%s] found.\n", list[c]);
                return EINVAL;
            }
        }
    }

    return EOK;
}

static errno_t get_access_order_list(TALLOC_CTX *mem_ctx,
                                     const char *order,
                                     char ***_order_list)
{
    errno_t ret;
    char **order_list;
    int order_list_len;

    ret = split_on_separator(mem_ctx, order, ',', true, true,
                             &order_list, &order_list_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "split_on_separator failed.\n");
        goto done;
    }

    ret = check_order_list_for_duplicates(order_list, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "check_order_list_for_duplicates failed.\n");
        goto done;
    }

    if (order_list_len > LDAP_ACCESS_LAST) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Currently only [%d] different access rules are supported.\n",
              LDAP_ACCESS_LAST);
        ret = EINVAL;
        goto done;
    }

    *_order_list = order_list;

done:
    if (ret != EOK) {
        talloc_free(order_list);
    }

    return ret;
}


static errno_t get_order_list(TALLOC_CTX *mem_ctx,
                              enum sdap_access_type type,
                              struct dp_option *opts,
                              char ***_order_list)
{
    errno_t ret = EOK;
    const char *order;

    switch (type) {
    case SDAP_TYPE_LDAP:
        order = dp_opt_get_cstring(opts, SDAP_ACCESS_ORDER);
        if (order == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_access_order not given, using 'filter'.\n");
            order = "filter";
        }
        break;
    case SDAP_TYPE_IPA:
        order = dp_opt_get_cstring(opts, IPA_ACCESS_ORDER);
        if (order == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ipa_access_order not given, using 'expire'.\n");
            order = "expire";
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown sdap_access_type [%i].\n", type);
        ret = EINVAL;
        goto done;
    }

    /* We can pass _order_list because it is the last operation.
     * Should this ever change, this would require an intermediate variable and
     * to assign the value to _order_list on success at the very last moment. */
    ret = get_access_order_list(mem_ctx, order, _order_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "get_access_order_list failed: [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    return ret;
}


static errno_t set_sdap_access_rules(TALLOC_CTX *mem_ctx,
                                     struct dp_option *opts,
                                     char **order_list,
                                     struct sdap_access_ctx *access_ctx)
{
    int ret = EOK;
    int c;
    const char *filter = NULL;


    for (c = 0; order_list[c] != NULL; c++) {
        if (strcasecmp(order_list[c], LDAP_ACCESS_FILTER_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_FILTER;
            if (get_access_filter(mem_ctx, opts, &filter) != EOK) {
                goto done;
            }

        } else if (strcasecmp(order_list[c], LDAP_ACCESS_EXPIRE_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE;
            if (check_expire_policy(opts) != EOK) {
                goto done;
            }

        } else if (strcasecmp(order_list[c], LDAP_ACCESS_SERVICE_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_SERVICE;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_HOST_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_HOST;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_RHOST_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_RHOST;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_LOCK_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_LOCKOUT;
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_REJECT_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_REJECT;
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_WARN_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_WARN;
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_RENEW_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_RENEW;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_PPOLICY_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_PPOLICY;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected access rule name [%s].\n", order_list[c]);
            ret = EINVAL;
            goto done;
        }
    }
    access_ctx->access_rule[c] = LDAP_ACCESS_EMPTY;
    if (c == 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Warning: access_provider=ldap set, "
              "but ldap_access_order is empty. "
              "All domain users will be denied access.\n");
    }

done:
    if (ret == EOK) {
        access_ctx->filter = filter;
    } else {
        talloc_zfree(filter);
    }

    return ret;
}


static errno_t set_ipa_access_rules(TALLOC_CTX *mem_ctx,
                                    struct dp_option *opts,
                                    char **order_list,
                                    struct sdap_access_ctx *access_ctx)
{
    int ret = EOK;
    int c;
    const char *filter = NULL;


    for (c = 0; order_list[c] != NULL; c++) {
        if (strcasecmp(order_list[c], LDAP_ACCESS_EXPIRE_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE;
            if (check_expire_policy(opts) != EOK) {
                goto done;
            }
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_REJECT_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_REJECT;
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_WARN_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_WARN;
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_RENEW_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_RENEW;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_PPOLICY_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_PPOLICY;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected access rule name [%s].\n", order_list[c]);
            ret = EINVAL;
            goto done;
        }
    }
    access_ctx->access_rule[c] = LDAP_ACCESS_EMPTY;
    if (c == 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Warning: access_provider=ipa set, "
              "but ipa_access_order is empty. "
              "All domain users will be denied access.\n");
    }

done:
    if (ret == EOK) {
        access_ctx->filter = filter;
    } else {
        talloc_zfree(filter);
    }

    return ret;
}


errno_t sdap_set_access_rules(TALLOC_CTX *mem_ctx,
                              struct sdap_access_ctx *access_ctx,
                              struct dp_option *opts,
                              struct dp_option *more_opts)
{
    errno_t ret;
    char **order_list = NULL;

    ret = get_order_list(mem_ctx, access_ctx->type, opts, &order_list);
    if (ret != EOK) {
        goto done;
    }

    switch (access_ctx->type) {
    case SDAP_TYPE_LDAP:
        ret = set_sdap_access_rules(mem_ctx, opts, order_list, access_ctx);
        break;
    case SDAP_TYPE_IPA:
        ret = set_ipa_access_rules(mem_ctx, more_opts, order_list, access_ctx);
        break;
    default:
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Invalid sdap_access_type [%i].\n", access_ctx->type);
        break;
    }

done:
    talloc_free(order_list);
    return ret;
}
