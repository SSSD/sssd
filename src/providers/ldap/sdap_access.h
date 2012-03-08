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

#include "providers/dp_backend.h"

#define SYSDB_LDAP_ACCESS_FILTER "ldap_access_filter_allow"

#define LDAP_ACCESS_FILTER_NAME "filter"
#define LDAP_ACCESS_EXPIRE_NAME "expire"
#define LDAP_ACCESS_SERVICE_NAME "authorized_service"
#define LDAP_ACCESS_HOST_NAME "host"

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
    LDAP_ACCESS_LAST
};

struct sdap_access_ctx {
    struct sdap_id_ctx *id_ctx;
    const char *filter;
    int access_rule[LDAP_ACCESS_LAST + 1];
};

struct tevent_req *
sdap_access_send(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 struct be_ctx *be_ctx,
                 struct sdap_access_ctx *access_ctx,
                 struct pam_data *pd);
errno_t
sdap_access_recv(struct tevent_req *req, int *pam_status);

#endif /* SDAP_ACCESS_H_ */
