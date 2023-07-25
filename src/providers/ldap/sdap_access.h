/*
    SSSD

    sdap_access.h

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

#ifndef SDAP_ACCESS_H_
#define SDAP_ACCESS_H_

#include "providers/backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_id_op.h"

/* Attributes in sysdb, used for caching last values of lockout or filter
 * access control checks.
 */
#define SYSDB_LDAP_ACCESS_FILTER "ldap_access_filter_allow"
#define SYSDB_LDAP_ACCESS_CACHED_LOCKOUT "ldap_access_lockout_allow"
/* names of ppolicy attributes */
#define SYSDB_LDAP_ACCESS_LOCKED_TIME "pwdAccountLockedTime"
#define SYSDB_LDAP_ACESS_LOCKOUT_DURATION "pwdLockoutDuration"
#define SYSDB_LDAP_ACCESS_LOCKOUT "pwdLockout"

#define LDAP_ACCESS_FILTER_NAME "filter"
#define LDAP_ACCESS_EXPIRE_NAME "expire"
#define LDAP_ACCESS_EXPIRE_POLICY_REJECT_NAME "pwd_expire_policy_reject"
#define LDAP_ACCESS_EXPIRE_POLICY_WARN_NAME "pwd_expire_policy_warn"
#define LDAP_ACCESS_EXPIRE_POLICY_RENEW_NAME "pwd_expire_policy_renew"
#define LDAP_ACCESS_SERVICE_NAME "authorized_service"
#define LDAP_ACCESS_HOST_NAME "host"
#define LDAP_ACCESS_RHOST_NAME "rhost"
#define LDAP_ACCESS_LOCK_NAME "lockout"
#define LDAP_ACCESS_PPOLICY_NAME "ppolicy"

#define LDAP_ACCOUNT_EXPIRE_SHADOW "shadow"
#define LDAP_ACCOUNT_EXPIRE_AD "ad"
#define LDAP_ACCOUNT_EXPIRE_RHDS "rhds"
#define LDAP_ACCOUNT_EXPIRE_IPA "ipa"
#define LDAP_ACCOUNT_EXPIRE_389DS "389ds"
#define LDAP_ACCOUNT_EXPIRE_NDS "nds"

enum ldap_access_rule {
    LDAP_ACCESS_EMPTY = -1,
    LDAP_ACCESS_FILTER = 0,
    LDAP_ACCESS_EXPIRE,
    LDAP_ACCESS_SERVICE,
    LDAP_ACCESS_HOST,
    LDAP_ACCESS_RHOST,
    LDAP_ACCESS_LOCKOUT,
    LDAP_ACCESS_EXPIRE_POLICY_REJECT,
    LDAP_ACCESS_EXPIRE_POLICY_WARN,
    LDAP_ACCESS_EXPIRE_POLICY_RENEW,
    LDAP_ACCESS_PPOLICY,
    LDAP_ACCESS_LAST
};

enum sdap_access_type {
    SDAP_TYPE_LDAP,
    SDAP_TYPE_IPA
};

struct sdap_access_ctx {
    enum sdap_access_type type;
    struct sdap_id_ctx *id_ctx;
    const char *filter;
    int access_rule[LDAP_ACCESS_LAST + 1];
};

struct tevent_req *
sdap_pam_access_handler_send(TALLOC_CTX *mem_ctx,
                           struct sdap_access_ctx *access_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params);

errno_t
sdap_pam_access_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data);

struct tevent_req *
sdap_access_send(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 struct be_ctx *be_ctx,
                 struct sss_domain_info *domain,
                 struct sdap_access_ctx *access_ctx,
                 struct sdap_id_conn_ctx *conn,
                 struct pam_data *pd);
errno_t sdap_access_recv(struct tevent_req *req);

/* Set the access rules based on ldap_access_order */
errno_t sdap_set_access_rules(TALLOC_CTX *mem_ctx,
                              struct sdap_access_ctx *access_ctx,
                              struct dp_option *opts,
                              struct dp_option *more_opts);

#endif /* SDAP_ACCESS_H_ */
