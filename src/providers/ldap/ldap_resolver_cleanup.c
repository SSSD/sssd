/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

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

#include "providers/ldap/ldap_common.h"
#include "db/sysdb_iphosts.h"
#include "db/sysdb_ipnetworks.h"

static errno_t
cleanup_iphosts(struct sdap_options *opts,
                struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *attrs[] = { SYSDB_NAME, NULL };
    time_t now = time(NULL);
    char *subfilter;
    char *ts_subfilter;
    struct ldb_message **msgs;
    size_t count;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    subfilter = talloc_asprintf(tmp_ctx, "(!(%s=0))", SYSDB_CACHE_EXPIRE);
    if (subfilter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    ts_subfilter = talloc_asprintf(tmp_ctx, "(&(!(%s=0))(%s<=%"SPRItime"))",
                                   SYSDB_CACHE_EXPIRE, SYSDB_CACHE_EXPIRE, now);
    if (ts_subfilter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_hosts(tmp_ctx, domain, /* subfilter, */
                             ts_subfilter, attrs, &count, &msgs);
    if (ret == ENOENT) {
        count = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to search ip hosts [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Found %zu expired ip host entries!\n", count);

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    for (i = 0; i < count; i++) {
        const char *name;

        name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Entry %s has no Name Attribute ?!?\n",
                  ldb_dn_get_linearized(msgs[i]->dn));
            continue;
        }

        DEBUG(SSSDBG_TRACE_INTERNAL, "About to delete ip host %s\n", name);
        ret = sysdb_host_delete(domain, name, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "IP host delete returned [%d]: (%s)\n",
                  ret, sss_strerror(ret));
            continue;
        }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
cleanup_ipnetworks(struct sdap_options *opts,
                   struct sss_domain_info *domain)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *attrs[] = { SYSDB_NAME, NULL };
    time_t now = time(NULL);
    char *subfilter;
    char *ts_subfilter;
    struct ldb_message **msgs;
    size_t count;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    subfilter = talloc_asprintf(tmp_ctx, "(!(%s=0))", SYSDB_CACHE_EXPIRE);
    if (subfilter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    ts_subfilter = talloc_asprintf(tmp_ctx, "(&(!(%s=0))(%s<=%"SPRItime"))",
                                   SYSDB_CACHE_EXPIRE, SYSDB_CACHE_EXPIRE, now);
    if (ts_subfilter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_ipnetworks(tmp_ctx, domain, /* subfilter, */
                                  ts_subfilter, attrs, &count, &msgs);
    if (ret == ENOENT) {
        count = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to search IP networks [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Found %zu expired IP network entries!\n", count);

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    for (i = 0; i < count; i++) {
        const char *name;

        name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Entry %s has no Name Attribute ?!?\n",
                  ldb_dn_get_linearized(msgs[i]->dn));
            continue;
        }

        DEBUG(SSSDBG_TRACE_INTERNAL, "About to delete IP network %s\n", name);
        ret = sysdb_ipnetwork_delete(domain, name, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "IP network delete returned [%d]: (%s)\n",
                  ret, sss_strerror(ret));
            continue;
        }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ldap_resolver_cleanup(struct sdap_resolver_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    struct sdap_id_ctx *id_ctx;
    struct sdap_domain *sdom;
    bool in_transaction = false;
    errno_t ret, tret;

    tmp_ctx = talloc_new(ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    id_ctx = ctx->id_ctx;
    sdom = id_ctx->opts->sdom;

    ret = sysdb_transaction_start(sdom->dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    ret = cleanup_iphosts(id_ctx->opts, sdom->dom);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    ret = cleanup_ipnetworks(id_ctx->opts, sdom->dom);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    ret = sysdb_transaction_commit(sdom->dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    ctx->last_purge = tevent_timeval_current();
    ret = EOK;

done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(sdom->dom->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}
