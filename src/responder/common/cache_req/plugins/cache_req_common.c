/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <talloc.h>
#include <ldb.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "providers/data_provider.h"
#include "responder/common/cache_req/cache_req_plugin.h"

static struct ldb_message *
cache_req_well_known_sid_msg(TALLOC_CTX *mem_ctx,
                             const char *sid,
                             const char *name)
{
    struct ldb_message *msg;
    const char *dup_sid;
    const char *dup_name;
    int ldberr;

    msg = ldb_msg_new(NULL);
    if (msg == NULL) {
        return NULL;
    }

    dup_sid = talloc_strdup(msg, sid);
    if (dup_sid == NULL) {
        ldberr = LDB_ERR_OTHER;
        goto done;
    }

    dup_name = talloc_strdup(msg, name);
    if (name == NULL) {
        ldberr = LDB_ERR_OTHER;
        goto done;
    }

    ldberr = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS, SYSDB_GROUP_CLASS);
    if (ldberr != LDB_SUCCESS) {
        goto done;
    }

    ldberr = ldb_msg_add_string(msg, SYSDB_NAME, dup_name);
    if (ldberr != LDB_SUCCESS) {
        goto done;
    }

    ldberr = ldb_msg_add_string(msg, SYSDB_SID_STR, dup_sid);
    if (ldberr != LDB_SUCCESS) {
        goto done;
    }

done:
    if (ldberr != LDB_SUCCESS) {
        talloc_free(msg);
        return NULL;
    }

    return msg;
}

struct cache_req_result *
cache_req_well_known_sid_result(TALLOC_CTX *mem_ctx,
                                struct cache_req *cr,
                                const char *domname,
                                const char *sid,
                                const char *name)
{
    struct cache_req_result *result;
    struct sss_domain_info *domain;
    struct ldb_message *msg;

    msg = cache_req_well_known_sid_msg(NULL, sid, name);
    if (msg == NULL) {
        return NULL;
    }

    if (domname != NULL) {
        domain = find_domain_by_name(cr->rctx->domains, domname, true);
    } else {
        domain = NULL;
    }

    result = cache_req_create_result_from_msg(mem_ctx, domain, msg,
                                              name, domname);
    if (result == NULL) {
        talloc_free(msg);
    }

    return result;
}
