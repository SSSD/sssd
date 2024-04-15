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

errno_t cache_req_idminmax_check(struct cache_req_data *data,
                                 struct sss_domain_info *domain)
{
   if (((domain->id_min != 0) && (data->id < domain->id_min)) ||
       ((domain->id_max != 0) && (data->id > domain->id_max))) {
        DEBUG(SSSDBG_FUNC_DATA, "id exceeds min/max boundaries\n");
        return ERR_ID_OUTSIDE_RANGE;
   }
   return EOK;
}

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

    ldberr = ldb_msg_add_string(msg, SYSDB_OBJECTCATEGORY, SYSDB_GROUP_CLASS);
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

bool
cache_req_common_process_dp_reply(struct cache_req *cr,
                                  errno_t ret,
                                  uint16_t err_maj,
                                  uint32_t err_min,
                                  const char *err_msg)
{
    bool bret;

    if (ret != EOK) {
        int msg_level = SSSDBG_IMPORTANT_INFO;
        /* ERR_DOMAIN_NOT_FOUND: 'ad_enabled_domains' option can exclude domain */
        if (ret == ERR_DOMAIN_NOT_FOUND) msg_level = SSSDBG_CONF_SETTINGS;
        CACHE_REQ_DEBUG(msg_level, cr,
                        "Could not get account info [%d]: %s\n",
                        ret, sss_strerror(ret));
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                        "Due to an error we will return cached data\n");

        bret = false;
        goto done;
    }

    if (err_maj) {
        CACHE_REQ_DEBUG(SSSDBG_IMPORTANT_INFO, cr,
                        "Data Provider Error: %u, %u, %s\n",
                        (unsigned int)err_maj, (unsigned int)err_min, err_msg);
        CACHE_REQ_DEBUG(SSSDBG_TRACE_FUNC, cr,
                        "Due to an error we will return cached data\n");

        bret = false;
        goto done;
    }

    bret = true;

done:
    return bret;
}

bool
cache_req_common_dp_recv(struct tevent_req *subreq,
                         struct cache_req *cr)
{
    const char *err_msg;
    uint16_t err_maj;
    uint32_t err_min;
    errno_t ret;
    bool bret;

    /* Use subreq as memory context so err_msg is freed with it. */
    ret = sss_dp_get_account_recv(subreq, subreq, &err_maj, &err_min, &err_msg);
    bret = cache_req_common_process_dp_reply(cr, ret, err_maj,
                                             err_min, err_msg);

    return bret;
}

errno_t
cache_req_common_get_acct_domain_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *subreq,
                                      struct cache_req *cr,
                                      char **_domain)
{
    errno_t ret;

    ret = sss_dp_get_account_domain_recv(mem_ctx, subreq, _domain);
    if (ret != EOK) {
        CACHE_REQ_DEBUG(SSSDBG_MINOR_FAILURE, cr,
                        "Could not get account domain [%d]: %s\n",
                        ret, sss_strerror(ret));
    }
    return ret;
}
