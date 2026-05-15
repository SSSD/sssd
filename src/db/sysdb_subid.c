/*
    Copyright (C) 2021 Red Hat

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

#include "db/sysdb_private.h"
#include "db/sysdb_subid.h"

#define SUBID_SUBDIR "subid_ranges"


errno_t sysdb_store_subid_range(struct sss_domain_info *domain,
                                const char *name,
                                int expiration_period,
                                struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret, sret;
    bool in_transaction = false;
    time_t now = time(NULL);

    DEBUG(SSSDBG_TRACE_FUNC, "Storing subid ranges for %s, expiration period = %d\n",
          name, expiration_period);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS, SYSDB_SUBID_RANGE_OC);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set object class [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set name attribute [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set sysdb lastUpdate [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 expiration_period ? (now + expiration_period) : 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set sysdb cache expire [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_store_custom(domain, name, SUBID_SUBDIR, attrs);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }

    in_transaction = false;

    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_get_subid_ranges(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               const char *name,
                               const char **attrs,
                               struct ldb_message **_range)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *filter;
    struct ldb_message **ranges;
    size_t num_ranges;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(%s=%s))",
                             SYSDB_OBJECTCLASS, SYSDB_SUBID_RANGE_OC,
                             SYSDB_NAME, name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              SUBID_SUBDIR, attrs,
                              &num_ranges, &ranges);
    if (ret != EOK) {
        goto done;
    }

    if (num_ranges > 1) {
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one range with name %s\n", name);
        goto done;
    }

    *_range = talloc_steal(mem_ctx, ranges[0]);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_delete_subid_range(struct sss_domain_info *domain,
                                 const char *name)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Deleting subid ranges for %s\n", name);
    return sysdb_delete_custom(domain, name, SUBID_SUBDIR);
}
