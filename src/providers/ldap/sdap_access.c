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

static struct tevent_req *sdap_access_filter_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct be_ctx *be_ctx,
                                             struct sss_domain_info *domain,
                                             struct sdap_access_ctx *access_ctx,
                                             struct sdap_id_conn_ctx *conn,
                                             const char *username,
                                             struct ldb_message *user_entry);
static errno_t sdap_access_filter_recv(struct tevent_req *req);

static errno_t sdap_account_expired(struct sdap_access_ctx *access_ctx,
                                    struct pam_data *pd,
                                    struct ldb_message *user_entry);

static  errno_t sdap_access_service(struct pam_data *pd,
                                    struct ldb_message *user_entry);

static errno_t sdap_access_host(struct ldb_message *user_entry);

struct sdap_access_req_ctx {
    struct pam_data *pd;
    struct tevent_context *ev;
    struct sdap_access_ctx *access_ctx;
    struct sdap_id_conn_ctx *conn;
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;
    struct ldb_message *user_entry;
    size_t current_rule;
};

static errno_t check_next_rule(struct sdap_access_req_ctx *state,
                               struct tevent_req *req);
static void sdap_access_filter_done(struct tevent_req *subreq);

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

    ret = check_next_rule(state, req);
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

static errno_t check_next_rule(struct sdap_access_req_ctx *state,
                               struct tevent_req *req)
{
    struct tevent_req *subreq;
    int ret = EOK;

    while (ret == EOK) {
        switch (state->access_ctx->access_rule[state->current_rule]) {
        case LDAP_ACCESS_EMPTY:
            /* we are done with no errors */
            return EOK;

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

            tevent_req_set_callback(subreq, sdap_access_filter_done, req);
            return EAGAIN;

        case LDAP_ACCESS_EXPIRE:
            ret = sdap_account_expired(state->access_ctx,
                                       state->pd, state->user_entry);
            break;

        case LDAP_ACCESS_SERVICE:
            ret = sdap_access_service( state->pd, state->user_entry);
            break;

        case LDAP_ACCESS_HOST:
            ret = sdap_access_host(state->user_entry);
            break;

        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected access rule type. Access denied.\n");
            ret = ERR_ACCESS_DENIED;
        }

        state->current_rule++;
    }

    return ret;
}

static void sdap_access_filter_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_access_req_ctx *state =
            tevent_req_data(req, struct sdap_access_req_ctx);

    ret = sdap_access_filter_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error retrieving access check result.\n");
        tevent_req_error(req, ret);
        return;
    }

    state->current_rule++;

    ret = check_next_rule(state, req);
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
    if (sp_expire > 0 && today > sp_expire) {

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

static bool nds_check_expired(const char *exp_time_str)
{
    char *end;
    struct tm tm;
    time_t expire_time;
    time_t now;

    if (exp_time_str == NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "ndsLoginExpirationTime is not set, access granted.\n");
        return false;
    }

    memset(&tm, 0, sizeof(tm));

    end = strptime(exp_time_str, "%Y%m%d%H%M%SZ", &tm);
    if (end == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "NDS expire date [%s] invalid.\n", exp_time_str);
        return true;
    }
    if (*end != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "NDS expire date [%s] contains extra characters.\n",
                  exp_time_str);
        return true;
    }

    expire_time = mktime(&tm);
    if (expire_time == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "mktime failed to convert [%s].\n", exp_time_str);
        return true;
    }

    tzset();
    expire_time -= timezone;
    now = time(NULL);
    DEBUG(SSSDBG_TRACE_ALL,
          "Time info: tzname[0] [%s] tzname[1] [%s] timezone [%ld] "
           "daylight [%d] now [%ld] expire_time [%ld].\n", tzname[0],
           tzname[1], timezone, daylight, now, expire_time);

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
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_account_expired_shadow failed.\n");
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_AD) == 0) {
            ret = sdap_account_expired_ad(pd, user_entry);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "sdap_account_expired_ad failed.\n");
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_RHDS) == 0 ||
                   strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_IPA) == 0 ||
                   strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_389DS) == 0) {
            ret = sdap_account_expired_rhds(pd, user_entry);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sdap_account_expired_rhds failed.\n");
            }
        } else if (strcasecmp(expire, LDAP_ACCOUNT_EXPIRE_NDS) == 0) {
            ret = sdap_account_expired_nds(pd, user_entry);
            if (ret != EOK) {
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
    bool cached_access;
    char *basedn;
};

static errno_t sdap_access_filter_decide_offline(struct tevent_req *req);
static int sdap_access_filter_retry(struct tevent_req *req);
static void sdap_access_filter_connect_done(struct tevent_req *subreq);
static void sdap_access_filter_get_access_done(struct tevent_req *req);
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
    const char *basedn;
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
        ret = sdap_access_filter_decide_offline(req);
        goto done;
    }

    /* Perform online operation */
    basedn = ldb_msg_find_attr_as_string(user_entry, SYSDB_ORIG_DN, NULL);
    if (basedn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,"Could not find originalDN for user [%s]\n",
                 state->username);
        ret = EINVAL;
        goto done;
    }

    state->basedn = talloc_strdup(state, basedn);
    if (state->basedn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for originalDN\n");
        ret = ENOMEM;
        goto done;
    }

    /* Construct the filter */
    /* Subdomain users are identified by FQDN. We need to use just the username */
    ret = sss_parse_name(state, domain->names, username, NULL, &name);
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

static errno_t sdap_access_filter_decide_offline(struct tevent_req *req)
{
    struct sdap_access_filter_req_ctx *state =
            tevent_req_data(req, struct sdap_access_filter_req_ctx);

    if (state->cached_access) {
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
            ret = sdap_access_filter_decide_offline(req);
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

    tevent_req_set_callback(subreq, sdap_access_filter_get_access_done, req);
}

static void sdap_access_filter_get_access_done(struct tevent_req *subreq)
{
    int ret, tret, dp_error;
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
            tret = sdap_access_filter_retry(req);
            if (tret == EOK) {
                return;
            }
        } else if (dp_error == DP_ERR_OFFLINE) {
            ret = sdap_access_filter_decide_offline(req);
        } else if (ret == ERR_INVALID_FILTER) {
            sss_log(SSS_LOG_ERR,
                    "Malformed access control filter [%s]\n", state->filter);
            DEBUG(SSSDBG_CRIT_FAILURE,
                "Malformed access control filter [%s]\n", state->filter);
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
        /* Save "allow" to the cache for future offline
         :q* access checks.
         */
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

    attrs = sysdb_new_attrs(state);
    if (attrs == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up attrs\n");
        goto done;
    }

    tret = sysdb_attrs_add_bool(attrs, SYSDB_LDAP_ACCESS_FILTER,
                                ret == EOK ?  true : false);
    if (tret != EOK) {
        /* Failing to save to the cache is non-fatal.
         * Just return the result.
         */
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up attrs\n");
        goto done;
    }

    tret = sysdb_set_user_attr(state->domain, state->username, attrs,
                               SYSDB_MOD_REP);
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

static errno_t sdap_access_host(struct ldb_message *user_entry)
{
    errno_t ret;
    struct ldb_message_element *el;
    unsigned int i;
    char *host;
    char hostname[HOST_NAME_MAX + 1];

    el = ldb_msg_find_element(user_entry, SYSDB_AUTHORIZED_HOST);
    if (!el || el->num_values == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing hosts. Access denied\n");
        return ERR_ACCESS_DENIED;
    }

    if (gethostname(hostname, HOST_NAME_MAX) == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to get system hostname. Access denied\n");
        return ERR_ACCESS_DENIED;
    }
    hostname[HOST_NAME_MAX] = '\0';

    /* FIXME: PADL's pam_ldap also calls gethostbyname() on the hostname
     *        in some attempt to get aliases and/or FQDN for the machine.
     *        Not sure this is a good idea, but we might want to add it in
     *        order to be compatible...
     */

    ret = ENOENT;

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

    if (ret == ENOENT) {
        DEBUG(SSSDBG_CONF_SETTINGS, "No matching host rule found\n");
        ret = ERR_ACCESS_DENIED;
    }

    return ret;
}
