/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>
        David Mulder <dmulder@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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

#include <arpa/inet.h>

#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "db/sysdb_computer.h"

static errno_t
sysdb_search_computer(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *filter,
                      const char **attrs,
                      size_t *_num_hosts,
                      struct ldb_message ***_hosts)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message **results;
    size_t num_results;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_search_custom(tmp_ctx, domain, filter,
                              COMPUTERS_SUBDIR, attrs,
                              &num_results, &results);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error looking up host [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such host\n");
        *_hosts = NULL;
        *_num_hosts = 0;
        goto done;
    }

    *_hosts = talloc_steal(mem_ctx, results);
    *_num_hosts = num_results;
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

int
sysdb_get_computer(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *computer_name,
                   const char **attrs,
                   struct ldb_message **_computer)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *filter;
    struct ldb_message **hosts;
    size_t num_hosts;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx, SYSDB_COMP_FILTER, computer_name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_computer(tmp_ctx, domain, filter, attrs,
                                &num_hosts, &hosts);
    if (ret != EOK) {
        goto done;
    }

    if (num_hosts != 1) {
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Did not find a single host with name %s\n", computer_name);
        goto done;
    }

    *_computer = talloc_steal(mem_ctx, hosts[0]);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

int
sysdb_set_computer(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *computer_name,
                   const char *sid_str,
                   int cache_timeout,
                   time_t now)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct sysdb_attrs *attrs;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, sid_str);
    if (ret) goto done;

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS, SYSDB_COMPUTER_CLASS);
    if (ret) goto done;

    ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, computer_name);
    if (ret) goto done;

    /* creation time */
    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CREATE_TIME, now);
    if (ret) goto done;

    /* Set a cache expire time. There is a periodic task that cleans up
     * expired entries from the cache even when enumeration is disabled */
    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 cache_timeout ? (now + cache_timeout) : 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set sysdb cache expire [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_store_custom(domain, computer_name, COMPUTERS_SUBDIR, attrs);
    if (ret) goto done;

    /* FIXME As a future improvement we have to extend domain enumeration.
     * When 'enumerate = true' for a domain, sssd starts a periodic task
     * that brings all users and groups to the cache, cleaning up
     * stale objects after each run. If enumeration is disabled, the cleanup
     * task for expired entries is started instead.
     *
     * We have to extend the enumeration task to fetch 'computer'
     * objects as well (see ad_id_enumeration_send, the entry point of the
     * enumeration task for the  id provider).
     */
done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(tmp_ctx);

    return ret;
}
