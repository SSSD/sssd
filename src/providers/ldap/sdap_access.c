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

#define _XOPEN_SOURCE 500 /* for strptime() */
#include <time.h>
#undef _XOPEN_SOURCE
#include <sys/param.h>
#include <security/pam_modules.h>
#include <talloc.h>
#include <tevent.h>
#include <errno.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_async.h"
#include "providers/data_provider.h"
#include "providers/dp_backend.h"

static void sdap_access_reply(struct be_req *be_req, int pam_status)
{
    struct pam_data *pd;
    pd = talloc_get_type(be_req->req_data, struct pam_data);
    pd->pam_status = pam_status;

    if (pam_status == PAM_SUCCESS || pam_status == PAM_PERM_DENIED) {
        be_req->fn(be_req, DP_ERR_OK, pam_status, NULL);
    }

    else {
        be_req->fn(be_req, DP_ERR_FATAL, pam_status, NULL);
    }
}

static struct tevent_req *sdap_access_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct be_ctx *be_ctx,
                                           struct sdap_access_ctx *access_ctx,
                                           struct pam_data *pd);

static struct tevent_req *sdap_access_filter_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct be_ctx *be_ctx,
                                             struct sdap_access_ctx *access_ctx,
                                             const char *username,
                                             struct ldb_message *user_entry);
static void sdap_access_filter_done(struct tevent_req *subreq);

static struct tevent_req *sdap_account_expired_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sdap_access_ctx *access_ctx,
                                             struct pam_data *pd,
                                             struct ldb_message *user_entry);
static errno_t sdap_access_service_recv(struct tevent_req *req,
                                        int *pam_status);
static void sdap_access_service_done(struct tevent_req *subreq);

static struct tevent_req *sdap_access_service_send(
        TALLOC_CTX *mem_ctx,
        struct tevent_context *ev,
        struct pam_data *pd,
        struct ldb_message *user_entry);

static void sdap_account_expired_done(struct tevent_req *subreq);

static errno_t sdap_access_host_recv(struct tevent_req *req,
                                        int *pam_status);
static void sdap_access_host_done(struct tevent_req *subreq);

static struct tevent_req *sdap_access_host_send(
        TALLOC_CTX *mem_ctx,
        struct tevent_context *ev,
        struct ldb_message *user_entry);

static void sdap_access_done(struct tevent_req *req);
void sdap_pam_access_handler(struct be_req *breq)
{
    struct pam_data *pd;
    struct tevent_req *req;
    struct sdap_access_ctx *access_ctx;

    pd = talloc_get_type(breq->req_data, struct pam_data);

    access_ctx =
            talloc_get_type(breq->be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                            struct sdap_access_ctx);

    req = sdap_access_send(breq,
                           breq->be_ctx->ev,
                           breq->be_ctx,
                           access_ctx,
                           pd);
    if (req == NULL) {
        DEBUG(1, ("Unable to start sdap_access request\n"));
        sdap_access_reply(breq, PAM_SYSTEM_ERR);
        return;
    }

    tevent_req_set_callback(req, sdap_access_done, breq);
}

struct sdap_access_req_ctx {
    struct pam_data *pd;
    struct tevent_context *ev;
    struct sdap_access_ctx *access_ctx;
    struct be_ctx *be_ctx;
    int pam_status;
    struct ldb_message *user_entry;
    size_t current_rule;
};

static errno_t select_next_rule(struct tevent_req *req);
static struct tevent_req *sdap_access_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct be_ctx *be_ctx,
                                           struct sdap_access_ctx *access_ctx,
                                           struct pam_data *pd)
{
    errno_t ret;
    struct sdap_access_req_ctx *state;
    struct tevent_req *req;
    struct ldb_result *res;
    const char *attrs[] = { "*", NULL };

    req = tevent_req_create(mem_ctx, &state, struct sdap_access_req_ctx);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->be_ctx = be_ctx;
    state->pd = pd;
    state->pam_status = PAM_SYSTEM_ERR;
    state->ev = ev;
    state->access_ctx = access_ctx;
    state->current_rule = 0;

    DEBUG(6, ("Performing access check for user [%s]\n", pd->user));

    if (access_ctx->access_rule[0] == LDAP_ACCESS_EMPTY) {
        DEBUG(3, ("No access rules defined, access denied.\n"));
        state->pam_status = PAM_PERM_DENIED;
        ret = EOK;
        goto done;
    }

    /* Get original user DN */
    ret = sysdb_get_user_attr(state, be_ctx->sysdb, pd->user, attrs, &res);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* If we can't find the user, return permission denied */
            state->pam_status = PAM_PERM_DENIED;
            ret = EOK;
            goto done;
        }
        goto done;
    }
    else {
        if (res->count == 0) {
            /* If we can't find the user, return permission denied */
            state->pam_status = PAM_PERM_DENIED;
            ret = EOK;
            goto done;
        }

        if (res->count != 1) {
            DEBUG(1, ("Invalid response from sysdb_get_user_attr\n"));
            ret = EINVAL;
            goto done;
        }
    }

    state->user_entry = res->msgs[0];

    ret = select_next_rule(req);
    if (ret != EOK) {
        if (ret == EACCES) {
            state->pam_status = PAM_PERM_DENIED;
            ret = EOK;
            goto done;
        }
        DEBUG(1, ("select_next_rule failed.\n"));
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

static errno_t select_next_rule(struct tevent_req *req)
{
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);
    struct tevent_req *subreq;

    switch (state->access_ctx->access_rule[state->current_rule]) {
        case LDAP_ACCESS_EMPTY:
            return ENOENT;
            break;

        case LDAP_ACCESS_FILTER:
            subreq = sdap_access_filter_send(state, state->ev, state->be_ctx,
                                             state->access_ctx,
                                             state->pd->user,
                                             state->user_entry);
            if (subreq == NULL) {
                DEBUG(1, ("sdap_access_filter_send failed.\n"));
                return ENOMEM;
            }

            tevent_req_set_callback(subreq, sdap_access_filter_done, req);
            return EOK;

        case LDAP_ACCESS_EXPIRE:
            subreq = sdap_account_expired_send(state, state->ev,
                                               state->access_ctx,
                                               state->pd,
                                               state->user_entry);
            if (subreq == NULL) {
                DEBUG(1, ("sdap_account_expired_send failed.\n"));
                return ENOMEM;
            }

            tevent_req_set_callback(subreq, sdap_account_expired_done, req);
            return EOK;

        case LDAP_ACCESS_SERVICE:
            subreq = sdap_access_service_send(state, state->ev,
                                              state->pd,
                                              state->user_entry);
            if (subreq == NULL) {
                DEBUG(1, ("sdap_access_service_send failed.\n"));
                return ENOMEM;
            }
            tevent_req_set_callback(subreq, sdap_access_service_done, req);
            return EOK;

        case LDAP_ACCESS_HOST:
            subreq = sdap_access_host_send(state, state->ev,
                                           state->user_entry);
            if (subreq == NULL) {
                DEBUG(1, ("sdap_access_host_send failed.\n"));
                return ENOMEM;
            }
            tevent_req_set_callback(subreq, sdap_access_host_done, req);
            return EOK;

        default:
            DEBUG(1, ("Unexpected access rule type. Access denied.\n"));
    }

    return EACCES;
}

static void next_access_rule(struct tevent_req *req)
{
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);
    int ret;

    if (state->pam_status == PAM_PERM_DENIED ||
        state->pam_status == PAM_ACCT_EXPIRED) {
        tevent_req_done(req);
        return;
    }

    state->current_rule++;

    ret = select_next_rule(req);
    if (ret != EOK) {
        if (ret == ENOENT) {
            state->pam_status = PAM_SUCCESS;
            tevent_req_done(req);
            return;
        } else if (ret == EACCES) {
            state->pam_status = PAM_PERM_DENIED;
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
    }

    return;
}

#define SHADOW_EXPIRE_MSG "Account expired according to shadow attributes"

static errno_t sdap_account_expired_shadow(struct pam_data *pd,
                                           struct ldb_message *user_entry,
                                           int *pam_status)
{
    int ret;
    const char *val;
    long sp_expire;
    long today;

    DEBUG(6, ("Performing access shadow check for user [%s]\n", pd->user));

    val = ldb_msg_find_attr_as_string(user_entry, SYSDB_SHADOWPW_EXPIRE, NULL);
    if (val == NULL) {
        DEBUG(3, ("Shadow expire attribute not found. "
                  "Access will be granted.\n"));
        *pam_status = PAM_SUCCESS;
        return EOK;
    }
    ret = string_to_shadowpw_days(val, &sp_expire);
    if (ret != EOK) {
        DEBUG(1, ("Failed to retrieve shadow expire date.\n"));
        return ret;
    }

    today = (long) (time(NULL) / (60 * 60 * 24));
    if (sp_expire > 0 && today > sp_expire) {
        *pam_status = PAM_ACCT_EXPIRED;

        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(SHADOW_EXPIRE_MSG),
                               (const uint8_t *) SHADOW_EXPIRE_MSG);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }
    } else {
        *pam_status = PAM_SUCCESS;
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
        DEBUG(1, ("time failed [%d][%s].\n", err, strerror(err)));
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
                                       struct ldb_message *user_entry,
                                       int *pam_status)
{
    uint32_t uac;
    uint64_t expiration_time;
    int ret;

    DEBUG(6, ("Performing AD access check for user [%s]\n", pd->user));

    uac = ldb_msg_find_attr_as_uint(user_entry, SYSDB_AD_USER_ACCOUNT_CONTROL,
                                    0);
    DEBUG(9, ("User account control for user [%s] is [%X].\n",
              pd->user, uac));

    expiration_time = ldb_msg_find_attr_as_uint64(user_entry,
                                                  SYSDB_AD_ACCOUNT_EXPIRES, 0);
    DEBUG(9, ("Expiration time for user [%s] is [%lld].\n",
              pd->user, expiration_time));

    if (uac & UAC_ACCOUNTDISABLE) {
        *pam_status = PAM_PERM_DENIED;

        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(AD_DISABLE_MESSAGE),
                               (const uint8_t *) AD_DISABLE_MESSAGE);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }
    } else if (ad_account_expired(expiration_time)) {
        *pam_status = PAM_ACCT_EXPIRED;

        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(AD_EXPIRED_MESSAGE),
                               (const uint8_t *) AD_EXPIRED_MESSAGE);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }
    } else {
        *pam_status = PAM_SUCCESS;
    }

    return EOK;
}

#define RHDS_LOCK_MSG "The user account is locked on the server"

static errno_t sdap_account_expired_rhds(struct pam_data *pd,
                                         struct ldb_message *user_entry,
                                         int *pam_status)
{
    bool locked;
    int ret;

    DEBUG(6, ("Performing RHDS access check for user [%s]\n", pd->user));

    locked = ldb_msg_find_attr_as_bool(user_entry, SYSDB_NS_ACCOUNT_LOCK, false);
    DEBUG(9, ("Account for user [%s] is%s locked.\n", pd->user,
              locked ? "" : " not" ));

    if (locked) {
        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(RHDS_LOCK_MSG),
                               (const uint8_t *) RHDS_LOCK_MSG);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }
    }

    *pam_status = locked ? PAM_PERM_DENIED : PAM_SUCCESS;

    return EOK;
}

#define NDS_DISABLE_MSG "The user account is disabled on the server"
#define NDS_EXPIRED_MSG "The user account is expired"
#define NDS_TIME_MAP_MSG "The user account is not allowed at this time"

static bool nds_check_expired(const char *exp_time_str)
{
    char *end;
    struct tm tm;
    time_t expire_time;
    time_t now;

    if (exp_time_str == NULL) {
        DEBUG(9, ("ndsLoginExpirationTime is not set, access granted.\n"));
        return false;
    }

    memset(&tm, 0, sizeof(tm));

    end = strptime(exp_time_str, "%Y%m%d%H%M%SZ", &tm);
    if (end == NULL) {
        DEBUG(1, ("NDS expire date [%s] invalid.\n", exp_time_str));
        return true;
    }
    if (*end != '\0') {
        DEBUG(1, ("NDS expire date [%s] contains extra characters.\n",
                  exp_time_str));
        return true;
    }

    expire_time = mktime(&tm);
    if (expire_time == -1) {
        DEBUG(1, ("mktime failed to convert [%s].\n", exp_time_str));
        return true;
    }

    tzset();
    expire_time -= timezone;
    now = time(NULL);
    DEBUG(9, ("Time info: tzname[0] [%s] tzname[1] [%s] timezone [%d] "
              "daylight [%d] now [%d] expire_time [%d].\n", tzname[0],
              tzname[1], timezone, daylight, now, expire_time));

    if (difftime(now, expire_time) > 0.0) {
        DEBUG(4, ("NDS account expired.\n"));
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
        DEBUG(9, ("loginAllowedTimeMap is missing, access granted.\n"));
        return false;
    }

    if (time_map->length != 42) {
        DEBUG(4, ("Allowed time map has the wrong size, "
                  "got [%d], expected 42.\n", time_map->length));
        return true;
    }

    now = time(NULL);
    tm_now = gmtime(&now);

    map_index = tm_now->tm_wday * 48 + tm_now->tm_hour * 2 +
                (tm_now->tm_min < 30 ? 0 : 1);

    if (map_index > 335) {
        DEBUG(1, ("Unexpected index value [%d] for time map.\n", index));
        return true;
    }

    q = div(map_index, 8);

    if (q.quot > 41 || q.quot < 0 || q.rem > 7 || q.rem < 0) {
        DEBUG(1, ("Unexpected result of div(), [%d][%d][%d].\n",
                  index, q.quot, q.rem));
        return true;
    }

    if (q.rem > 0) {
        mask = 1 << q.rem;
    }

    if (time_map->data[q.quot] & mask) {
        DEBUG(4, ("Access allowed by time map.\n"));
        return false;
    }

    return true;
}

static errno_t sdap_account_expired_nds(struct pam_data *pd,
                                         struct ldb_message *user_entry,
                                         int *pam_status)
{
    bool locked = true;
    int ret;
    const char *exp_time_str;
    const struct ldb_val *time_map;

    DEBUG(6, ("Performing NDS access check for user [%s]\n", pd->user));

    locked = ldb_msg_find_attr_as_bool(user_entry, SYSDB_NDS_LOGIN_DISABLED,
                                       false);
    DEBUG(9, ("Account for user [%s] is%s disabled.\n", pd->user,
              locked ? "" : " not"));

    if (locked) {
        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(NDS_DISABLE_MSG),
                               (const uint8_t *) NDS_DISABLE_MSG);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }
    } else {
        exp_time_str = ldb_msg_find_attr_as_string(user_entry,
                                                SYSDB_NDS_LOGIN_EXPIRATION_TIME,
                                                NULL);
        locked = nds_check_expired(exp_time_str);

        DEBUG(9, ("Account for user [%s] is%s expired.\n", pd->user,
                  locked ? "" : " not"));

        if (locked) {
            ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                                   sizeof(NDS_EXPIRED_MSG),
                                   (const uint8_t *) NDS_EXPIRED_MSG);
            if (ret != EOK) {
                DEBUG(1, ("pam_add_response failed.\n"));
            }
        } else {
            time_map = ldb_msg_find_ldb_val(user_entry,
                                            SYSDB_NDS_LOGIN_ALLOWED_TIME_MAP);

            locked = nds_check_time_map(time_map);

            DEBUG(9, ("Account for user [%s] is%s locked at this time.\n",
                      pd->user, locked ? "" : " not"));

            if (locked) {
                ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                                       sizeof(NDS_TIME_MAP_MSG),
                                       (const uint8_t *) NDS_TIME_MAP_MSG);
                if (ret != EOK) {
                    DEBUG(1, ("pam_add_response failed.\n"));
                }
            }
        }
    }

    *pam_status = locked ? PAM_PERM_DENIED : PAM_SUCCESS;

    return EOK;
}

struct sdap_account_expired_req_ctx {
    int pam_status;
};

static struct tevent_req *sdap_account_expired_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sdap_access_ctx *access_ctx,
                                             struct pam_data *pd,
                                             struct ldb_message *user_entry)
{
    struct tevent_req *req;
    struct sdap_account_expired_req_ctx *state;
    int ret;
    const char *expire;

    req = tevent_req_create(mem_ctx, &state, struct sdap_account_expired_req_ctx);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->pam_status = PAM_SYSTEM_ERR;

    expire = dp_opt_get_cstring(access_ctx->id_ctx->opts->basic,
                                SDAP_ACCOUNT_EXPIRE_POLICY);
    if (expire == NULL) {
        DEBUG(1, ("Missing account expire policy. Access denied\n"));
        state->pam_status = PAM_PERM_DENIED;
        ret = EOK;
        goto done;
    } else {
        if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_SHADOW) == 0) {
            ret = sdap_account_expired_shadow(pd, user_entry,
                                              &state->pam_status);
            if (ret != EOK) {
                DEBUG(1, ("sdap_account_expired_shadow failed.\n"));
                goto done;
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_AD) == 0) {
            ret = sdap_account_expired_ad(pd, user_entry,
                                          &state->pam_status);
            if (ret != EOK) {
                DEBUG(1, ("sdap_account_expired_ad failed.\n"));
                goto done;
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_RHDS) == 0 ||
                   strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_IPA) == 0 ||
                   strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_389DS) == 0) {
            ret = sdap_account_expired_rhds(pd, user_entry,
                                            &state->pam_status);
            if (ret != EOK) {
                DEBUG(1, ("sdap_account_expired_rhds failed.\n"));
                goto done;
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_NDS) == 0) {
            ret = sdap_account_expired_nds(pd, user_entry, &state->pam_status);
            if (ret != EOK) {
                DEBUG(1, ("sdap_account_expired_nds failed.\n"));
                goto done;
            }
        } else {
            DEBUG(1, ("Unsupported LDAP account expire policy [%s]. "
                      "Access denied.\n", expire));
            state->pam_status = PAM_PERM_DENIED;
            ret = EOK;
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t sdap_account_expired_recv(struct tevent_req *req, int *pam_status)
{
    struct sdap_account_expired_req_ctx *state =
            tevent_req_data(req, struct sdap_account_expired_req_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *pam_status = state->pam_status;

    return EOK;
}

static void sdap_account_expired_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    ret = sdap_account_expired_recv(subreq, &state->pam_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Error retrieving access check result.\n"));
        state->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, ret);
        return;
    }

    next_access_rule(req);

    return;
}



struct sdap_access_filter_req_ctx {
    const char *username;
    const char *filter;
    struct tevent_context *ev;
    struct sdap_access_ctx *access_ctx;
    struct sdap_id_ctx *sdap_ctx;
    struct sdap_id_op *sdap_op;
    struct sysdb_handle *handle;
    struct be_ctx *be_ctx;
    int pam_status;
    bool cached_access;
    char *basedn;
};

static void sdap_access_filter_decide_offline(struct tevent_req *req);
static int sdap_access_filter_retry(struct tevent_req *req);
static void sdap_access_filter_connect_done(struct tevent_req *subreq);
static void sdap_access_filter_get_access_done(struct tevent_req *req);
static struct tevent_req *sdap_access_filter_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct be_ctx *be_ctx,
                                             struct sdap_access_ctx *access_ctx,
                                             const char *username,
                                             struct ldb_message *user_entry)
{
    errno_t ret;
    struct sdap_access_filter_req_ctx *state;
    struct tevent_req *req;
    const char *basedn;
    char *clean_username;

    req = tevent_req_create(mem_ctx, &state, struct sdap_access_filter_req_ctx);
    if (req == NULL) {
        return NULL;
    }

    if (access_ctx->filter == NULL || *access_ctx->filter == '\0') {
        /* If no filter is set, default to restrictive */
        DEBUG(6, ("No filter set. Access is denied.\n"));
        state->pam_status = PAM_PERM_DENIED;
        tevent_req_done(req);
        tevent_req_post(req, be_ctx->ev);
        return req;
    }

    state->filter = NULL;
    state->be_ctx = be_ctx;
    state->username = username;
    state->pam_status = PAM_SYSTEM_ERR;
    state->sdap_ctx = access_ctx->id_ctx;
    state->ev = ev;
    state->access_ctx = access_ctx;

    DEBUG(6, ("Performing access filter check for user [%s]\n", username));

    state->cached_access = ldb_msg_find_attr_as_bool(user_entry,
                                                     SYSDB_LDAP_ACCESS_FILTER,
                                                     false);
    /* Ok, we have one result, check if we are online or offline */
    if (be_is_offline(state->be_ctx)) {
        /* Ok, we're offline. Return from the cache */
        sdap_access_filter_decide_offline(req);
        goto finished;
    }

    /* Perform online operation */
    basedn = ldb_msg_find_attr_as_string(user_entry,
                                         SYSDB_ORIG_DN,
                                         NULL);
    if(basedn == NULL) {
        DEBUG(1,("Could not find originalDN for user [%s]\n",
                 state->username));
        goto failed;
    }

    state->basedn = talloc_strdup(state, basedn);
    if (state->basedn == NULL) {
        DEBUG(1, ("Could not allocate memory for originalDN\n"));
        goto failed;
    }

    /* Construct the filter */

    ret = sss_filter_sanitize(state, state->username, &clean_username);
    if (ret != EOK) {
        goto failed;
    }

    state->filter = talloc_asprintf(
        state,
        "(&(%s=%s)(objectclass=%s)%s)",
        state->sdap_ctx->opts->user_map[SDAP_AT_USER_NAME].name,
        clean_username,
        state->sdap_ctx->opts->user_map[SDAP_OC_USER].name,
        state->access_ctx->filter);
    if (state->filter == NULL) {
        DEBUG(0, ("Could not construct access filter\n"));
        goto failed;
    }
    talloc_zfree(clean_username);

    DEBUG(6, ("Checking filter against LDAP\n"));

    state->sdap_op = sdap_id_op_create(state, state->sdap_ctx->conn_cache);
    if (!state->sdap_op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
        goto failed;
    }

    ret = sdap_access_filter_retry(req);
    if (ret != EOK) {
        goto failed;
    }

    return req;

failed:
    talloc_free(req);
    return NULL;

finished:
    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_access_filter_decide_offline(struct tevent_req *req)
{
    struct sdap_access_filter_req_ctx *state =
            tevent_req_data(req, struct sdap_access_filter_req_ctx);

    if (state->cached_access) {
        DEBUG(6, ("Access granted by cached credentials\n"));
        state->pam_status = PAM_SUCCESS;
    } else {
        DEBUG(6, ("Access denied by cached credentials\n"));
        state->pam_status = PAM_PERM_DENIED;
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
        DEBUG(2, ("sdap_id_op_connect_send failed: %d (%s)\n", ret, strerror(ret)));
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
            sdap_access_filter_decide_offline(req);
            tevent_req_done(req);
            return;
        }

        tevent_req_error(req, ret);
        return;
    }

    /* Connection to LDAP succeeded
     * Send filter request
     */
    subreq = sdap_get_generic_send(state,
                                   state->ev,
                                   state->sdap_ctx->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->basedn,
                                   LDAP_SCOPE_BASE,
                                   state->filter, NULL,
                                   NULL, 0,
                                   dp_opt_get_int(state->sdap_ctx->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        DEBUG(1, ("Could not start LDAP communication\n"));
        state->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq, sdap_access_filter_get_access_done, req);
}

static void sdap_access_filter_get_access_done(struct tevent_req *subreq)
{
    int ret, dp_error;
    size_t num_results;
    bool found = false;
    struct sysdb_attrs *attrs;
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
            ret = sdap_access_filter_retry(req);
            if (ret == EOK) {
                return;
            }
            state->pam_status = PAM_SYSTEM_ERR;
        } else if (dp_error == DP_ERR_OFFLINE) {
            sdap_access_filter_decide_offline(req);
        } else {
            DEBUG(1, ("sdap_get_generic_send() returned error [%d][%s]\n",
                      ret, strerror(ret)));
            state->pam_status = PAM_SYSTEM_ERR;
        }

        goto done;
    }

    /* Check the number of responses we got
     * If it's exactly 1, we passed the check
     * If it's < 1, we failed the check
     * Anything else is an error
     */
    if (num_results < 1) {
        DEBUG(4, ("User [%s] was not found with the specified filter. "
                  "Denying access.\n", state->username));
        found = false;
    }
    else if (results == NULL) {
        DEBUG(1, ("num_results > 0, but results is NULL\n"));
        ret = EIO;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    else if (num_results > 1) {
        /* It should not be possible to get more than one reply
         * here, since we're doing a base-scoped search
         */
        DEBUG(1, ("Received multiple replies\n"));
        ret = EIO;
        state->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }
    else { /* Ok, we got a single reply */
        found = true;
    }

    if (found) {
        /* Save "allow" to the cache for future offline
         * access checks.
         */
        DEBUG(6, ("Access granted by online lookup\n"));
        state->pam_status = PAM_SUCCESS;
    }
    else {
        /* Save "disallow" to the cache for future offline
         * access checks.
         */
        DEBUG(6, ("Access denied by online lookup\n"));
        state->pam_status = PAM_PERM_DENIED;
    }

    attrs = sysdb_new_attrs(state);
    if (attrs == NULL) {
        ret = ENOMEM;
        DEBUG(1, ("Could not set up attrs\n"));
        goto done;
    }

    ret = sysdb_attrs_add_bool(attrs, SYSDB_LDAP_ACCESS_FILTER,
                               state->pam_status == PAM_SUCCESS ?
                                                    true :
                                                    false);
    if (ret != EOK) {
        /* Failing to save to the cache is non-fatal.
         * Just return the result.
         */
        ret = EOK;
        DEBUG(1, ("Could not set up attrs\n"));
        goto done;
    }

    ret = sysdb_set_user_attr(state->be_ctx->sysdb,
                              state->username,
                              attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        /* Failing to save to the cache is non-fatal.
         * Just return the result.
         */
        ret = EOK;
        DEBUG(1, ("Failed to set user access attribute\n"));
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

static errno_t sdap_access_filter_recv(struct tevent_req *req, int *pam_status)
{
    struct sdap_access_filter_req_ctx *state =
            tevent_req_data(req, struct sdap_access_filter_req_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *pam_status = state->pam_status;

    return EOK;
}

static void sdap_access_filter_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    ret = sdap_access_filter_recv(subreq, &state->pam_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Error retrieving access check result.\n"));
        state->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, ret);
        return;
    }

    next_access_rule(req);

    return;
}


struct sdap_access_service_ctx {
    int pam_status;
};

#define AUTHR_SRV_MISSING_MSG "Authorized service attribute missing, " \
                              "access denied"
#define AUTHR_SRV_DENY_MSG "Access denied by authorized service attribute"
#define AUTHR_SRV_NO_MATCH_MSG "Authorized service attribute has " \
                               "no matching rule, access denied"

static struct tevent_req *sdap_access_service_send(
        TALLOC_CTX *mem_ctx,
        struct tevent_context *ev,
        struct pam_data *pd,
        struct ldb_message *user_entry)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_access_service_ctx *state;
    struct ldb_message_element *el;
    unsigned int i;
    char *service;

    req = tevent_req_create(mem_ctx, &state, struct sdap_access_service_ctx);
    if (!req) {
        return NULL;
    }

    state->pam_status = PAM_PERM_DENIED;

    el = ldb_msg_find_element(user_entry, SYSDB_AUTHORIZED_SERVICE);
    if (!el || el->num_values == 0) {
        DEBUG(1, ("Missing authorized services. Access denied\n"));

        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(AUTHR_SRV_MISSING_MSG),
                               (const uint8_t *) AUTHR_SRV_MISSING_MSG);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }

        ret = EOK;
        goto done;
    }

    for (i = 0; i < el->num_values; i++) {
        service = (char *)el->values[i].data;
        if (service[0] == '!' &&
                strcasecmp(pd->service, service+1) == 0) {
            /* This service is explicitly denied */
            state->pam_status = PAM_PERM_DENIED;
            DEBUG(4, ("Access denied by [%s]\n", service));

            ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                                   sizeof(AUTHR_SRV_DENY_MSG),
                                   (const uint8_t *) AUTHR_SRV_DENY_MSG);
            if (ret != EOK) {
                DEBUG(1, ("pam_add_response failed.\n"));
            }

            /* A denial trumps all. Break here */
            ret = EOK;
            goto done;

        } else if (strcasecmp(pd->service, service) == 0) {
            /* This service is explicitly allowed */
            state->pam_status = PAM_SUCCESS;
            DEBUG(4, ("Access granted for [%s]\n", service));
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
        } else if (strcmp("*", service) == 0) {
            /* This user has access to all services */
            state->pam_status = PAM_SUCCESS;
            DEBUG(4, ("Access granted to all services\n"));
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
        }
    }

    if (state->pam_status != PAM_SUCCESS) {
        DEBUG(4, ("No matching service rule found\n"));

        ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                               sizeof(AUTHR_SRV_NO_MATCH_MSG),
                               (const uint8_t *) AUTHR_SRV_NO_MATCH_MSG);
        if (ret != EOK) {
            DEBUG(1, ("pam_add_response failed.\n"));
        }
    }

    ret = EOK;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t sdap_access_service_recv(struct tevent_req *req,
                                        int *pam_status)
{
    struct sdap_access_service_ctx *state =
            tevent_req_data(req, struct sdap_access_service_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *pam_status = state->pam_status;

    return EOK;
}

static void sdap_access_service_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    ret = sdap_access_service_recv(subreq, &state->pam_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Error retrieving access check result.\n"));
        state->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, ret);
        return;
    }

    next_access_rule(req);

    return;
}

struct sdap_access_host_ctx {
    int pam_status;
};

static struct tevent_req *sdap_access_host_send(
        TALLOC_CTX *mem_ctx,
        struct tevent_context *ev,
        struct ldb_message *user_entry)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_access_host_ctx *state;
    struct ldb_message_element *el;
    unsigned int i;
    char *host;
    char hostname[HOST_NAME_MAX+1];

    req = tevent_req_create(mem_ctx, &state, struct sdap_access_host_ctx);
    if (!req) {
        return NULL;
    }

    state->pam_status = PAM_PERM_DENIED;

    el = ldb_msg_find_element(user_entry, SYSDB_AUTHORIZED_HOST);
    if (!el || el->num_values == 0) {
        DEBUG(1, ("Missing hosts. Access denied\n"));
        ret = EOK;
        goto done;
    }

    if (gethostname(hostname, sizeof(hostname)) == -1) {
        DEBUG(1, ("Unable to get system hostname. Access denied\n"));
        ret = EOK;
        goto done;
    }

    /* FIXME: PADL's pam_ldap also calls gethostbyname() on the hostname
     *        in some attempt to get aliases and/or FQDN for the machine.
     *        Not sure this is a good idea, but we might want to add it in
     *        order to be compatible...
     */

    for (i = 0; i < el->num_values; i++) {
        host = (char *)el->values[i].data;
        if (host[0] == '!' &&
                strcasecmp(hostname, host+1) == 0) {
            /* This host is explicitly denied */
            state->pam_status = PAM_PERM_DENIED;
            DEBUG(4, ("Access denied by [%s]\n", host));
            /* A denial trumps all. Break here */
            break;

        } else if (strcasecmp(hostname, host) == 0) {
            /* This host is explicitly allowed */
            state->pam_status = PAM_SUCCESS;
            DEBUG(4, ("Access granted for [%s]\n", host));
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
        } else if (strcmp("*", host) == 0) {
            /* This user has access to all hosts */
            state->pam_status = PAM_SUCCESS;
            DEBUG(4, ("Access granted to all hosts\n"));
            /* We still need to loop through to make sure
             * that it's not also explicitly denied
             */
        }
    }

    if (state->pam_status != PAM_SUCCESS) {
        DEBUG(4, ("No matching host rule found\n"));
    }

    ret = EOK;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t sdap_access_host_recv(struct tevent_req *req,
                                        int *pam_status)
{
    struct sdap_access_host_ctx *state =
            tevent_req_data(req, struct sdap_access_host_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *pam_status = state->pam_status;

    return EOK;
}

static void sdap_access_host_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    ret = sdap_access_host_recv(subreq, &state->pam_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Error retrieving access check result.\n"));
        state->pam_status = PAM_SYSTEM_ERR;
        tevent_req_error(req, ret);
        return;
    }

    next_access_rule(req);

    return;
}

static errno_t sdap_access_recv(struct tevent_req *req, int *pam_status)
{
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *pam_status = state->pam_status;

    return EOK;
}

static void sdap_access_done(struct tevent_req *req)
{
    errno_t ret;
    int pam_status = PAM_SYSTEM_ERR;
    struct be_req *breq =
            tevent_req_callback_data(req, struct be_req);

    ret = sdap_access_recv(req, &pam_status);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(1, ("Error retrieving access check result.\n"));
        pam_status = PAM_SYSTEM_ERR;
    }

    sdap_access_reply(breq, pam_status);
}
