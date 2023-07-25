/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2020 SUSE LINUX GmbH, Nuernberg, Germany.

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
#include "db/sysdb_ipnetworks.h"

static errno_t
sysdb_ipnetwork_update(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char **aliases,
                       const char *address);

static errno_t
sysdb_ipnetwork_remove_alias(struct sysdb_ctx *sysdb,
                             struct ldb_dn *dn,
                             const char *alias);

errno_t sysdb_getipnetworkbyname(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *name,
                                 struct ldb_result **_res)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = {
        SYSDB_NAME,
        SYSDB_NAME_ALIAS,
        SYSDB_IP_NETWORK_ATTR_NUMBER,
        SYSDB_DEFAULT_ATTRS,
        NULL,
    };
    char *sanitized_name;
    char *subfilter;
    struct ldb_result *res = NULL;
    struct ldb_message **msgs;
    size_t msgs_count;

    DEBUG(SSSDBG_TRACE_FUNC, "Searching network by name [%s] in domain [%s]\n",
          name, domain->name);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_filter_sanitize(tmp_ctx, name, &sanitized_name);
    if (ret != EOK) {
        goto done;
    }

    subfilter = talloc_asprintf(tmp_ctx, SYSDB_IP_NETWORK_BYNAME_SUBFILTER,
                                sanitized_name, sanitized_name);
    if (subfilter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_ipnetworks(tmp_ctx, domain, subfilter, attrs,
                                  &msgs_count, &msgs);
    if (ret == EOK) {
        res = talloc_zero(mem_ctx, struct ldb_result);
        if (res == NULL) {
            ret = ENOMEM;
            goto done;
        }
        res->count = msgs_count;
        res->msgs = talloc_steal(res, msgs);
    }

    *_res = res;

done:
    talloc_free(tmp_ctx);

    return ret;

}

errno_t sysdb_getipnetworkbyaddr(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *address,
                                 struct ldb_result **_res)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = {
        SYSDB_NAME,
        SYSDB_NAME_ALIAS,
        SYSDB_IP_NETWORK_ATTR_NUMBER,
        NULL,
    };
    char *sanitized_address;
    char *subfilter;
    struct ldb_result *res = NULL;
    struct ldb_message **msgs;
    size_t msgs_count;
    char *canonical_address;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* IP addresses are stored in canonical form, canonicalize the given
     * address before search */
    ret = sss_canonicalize_ip_address(tmp_ctx, address, &canonical_address);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Searching network by address [%s] in domain [%s]\n",
          canonical_address, domain->name);

    ret = sss_filter_sanitize(tmp_ctx, canonical_address, &sanitized_address);
    if (ret != EOK) {
        goto done;
    }

    subfilter = talloc_asprintf(tmp_ctx, SYSDB_IP_NETWORK_BYADDR_SUBFILTER,
                                sanitized_address);
    if (subfilter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_ipnetworks(tmp_ctx, domain, subfilter, attrs,
                                  &msgs_count, &msgs);
    if (ret == EOK) {
        res = talloc_zero(mem_ctx, struct ldb_result);
        if (res == NULL) {
            ret = ENOMEM;
            goto done;
        }
        res->count = msgs_count;
        res->msgs = talloc_steal(res, msgs);
    }

    *_res = res;

done:
    talloc_free(tmp_ctx);

    return ret;

}

errno_t
sysdb_store_ipnetwork(struct sss_domain_info *domain,
                      const char *primary_name,
                      const char **aliases,
                      const char *address,
                      struct sysdb_attrs *extra_attrs,
                      char **remove_attrs,
                      uint64_t cache_timeout,
                      time_t now)
{
    errno_t ret;
    errno_t sret;
    TALLOC_CTX *tmp_ctx;
    bool in_transaction = false;
    struct ldb_result *res = NULL;
    const char *name;
    unsigned int i, j;
    struct ldb_dn *update_dn = NULL;
    struct sysdb_attrs *attrs;
    struct sysdb_ctx *sysdb;

    DEBUG(SSSDBG_TRACE_FUNC, "Storing network [%s] into cache, domain [%s]\n",
          primary_name, domain->name);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
	    return ENOMEM;
    }

    sysdb = domain->sysdb;

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    /* Check that the address is unique. If the address appears for any
     * network other than the one matching the primary_name, we need to
     * remove it so that getnetbyaddr() can work properly.
     * Last entry saved to the cache should always "win".
     */
    ret = sysdb_getipnetworkbyaddr(tmp_ctx, domain, address, &res);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    } else if (ret != ENOENT) {
        if (res->count != 1) {
            /* Somehow the cache has multiple entries with  the same
             * address. This is corrupted. We'll delete them all to
             * sort it out.
             */
            for (j = 0; j < res->count; j++) {
                DEBUG(SSSDBG_TRACE_FUNC,
                        "Corrupt cache entry [%s] detected. Deleting\n",
                        ldb_dn_canonical_string(tmp_ctx,
                                                res->msgs[j]->dn));

                ret = sysdb_delete_entry(sysdb, res->msgs[j]->dn, true);
                if (ret != EOK) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                            "Could not delete corrupt cache entry [%s]\n",
                            ldb_dn_canonical_string(tmp_ctx,
                                                    res->msgs[j]->dn));
                    goto done;
                }
            }
        } else {
            /* Check whether this is the same name as we're currently
             * saving to the cache.
             */
            name = ldb_msg_find_attr_as_string(res->msgs[0],
                                                SYSDB_NAME,
                                                NULL);
            if (name == NULL || strcmp(name, primary_name) != 0) {
                if (name == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "A network with no name?\n");
                    /* Corrupted */
                }

                /* Either this is a corrupt entry or it's another network
                 * claiming ownership of this address. In order to account
                 * for address reassignments, we need to delete the old
                 * entry.
                 */
                DEBUG(SSSDBG_TRACE_FUNC,
                        "Corrupt or replaced cache entry [%s] detected. "
                        "Deleting\n",
                        ldb_dn_canonical_string(tmp_ctx,
                                                res->msgs[0]->dn));

                ret = sysdb_delete_entry(sysdb, res->msgs[0]->dn, true);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                            "Could not delete cache entry [%s]\n",
                            ldb_dn_canonical_string(tmp_ctx,
                                                    res->msgs[0]->dn));
                }
            }
        }
    }
    talloc_zfree(res);

    /* Address is now unique. look the network up by name to determine if
     * we need to update existing entries or modify aliases.
     */
    ret = sysdb_getipnetworkbyname(tmp_ctx, domain, primary_name, &res);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    } else if (ret != ENOENT) {
        for (i = 0; i < res->count; i++) {
            /* Check whether this is the same name as we're currently
             * saving to the cache.
             */
            name = ldb_msg_find_attr_as_string(res->msgs[i],
                                               SYSDB_NAME,
                                               NULL);
            if (name == NULL) {
                /* Corrupted */
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "A network with no name?\n");
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Corrupt cache entry [%s] detected. Deleting\n",
                       ldb_dn_canonical_string(tmp_ctx,
                                               res->msgs[i]->dn));

                ret = sysdb_delete_entry(sysdb, res->msgs[i]->dn, true);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Could not delete corrupt cache entry [%s]\n",
                           ldb_dn_canonical_string(tmp_ctx,
                                                   res->msgs[i]->dn));
                    goto done;
                }
            } else if (strcmp(name, primary_name) == 0) {
                /* This is the same network name, so we need
                 * to update this entry with the values provided.
                 */
                if (update_dn) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Two existing networks with the same name: [%s]? "
                           "Deleting both.\n",
                           primary_name);

                    /* Delete the entry from the previous pass */
                    ret = sysdb_delete_entry(sysdb, update_dn, true);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "Could not delete cache entry [%s]\n",
                               ldb_dn_canonical_string(tmp_ctx,
                                                       update_dn));
                        goto done;
                    }

                    /* Delete the new entry as well */
                    ret = sysdb_delete_entry(sysdb, res->msgs[i]->dn, true);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_MINOR_FAILURE,
                              "Could not delete cache entry [%s]\n",
                               ldb_dn_canonical_string(tmp_ctx,
                                                       res->msgs[i]->dn));
                        goto done;
                    }

                    update_dn = NULL;
                } else {
                    update_dn = talloc_steal(tmp_ctx, res->msgs[i]->dn);
                }
            } else {
                /* Another network is claiming this name as an alias.
                 * In order to account for aliases being promoted to
                 * primary names, we need to make sure to remove the
                 * old alias entry.
                 */
                ret = sysdb_ipnetwork_remove_alias(sysdb,
                                                   res->msgs[i]->dn,
                                                   primary_name);
                if (ret != EOK) {
                    goto done;
                }
            }
        }
        talloc_zfree(res);
    }

    if (update_dn) {
        /* Update the existing entry */
        ret = sysdb_ipnetwork_update(sysdb, update_dn, aliases, address);
    } else {
        /* Add a new entry */
        ret = sysdb_ipnetwork_add(tmp_ctx, domain, primary_name,
                                  aliases, address, &update_dn);
    }

    if (ret != EOK) {
        goto done;
    }

    if (extra_attrs == NULL) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (attrs == NULL) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        attrs = extra_attrs;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret) {
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 ((cache_timeout) ?
                                  (now + cache_timeout) : 0));
    if (ret) {
        goto done;
    }

    ret = sysdb_set_entry_attr(sysdb, update_dn, attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        goto done;
    }

    if (remove_attrs) {
        ret = sysdb_remove_attrs(domain, primary_name,
                                 SYSDB_MEMBER_IP_NETWORK,
                                 remove_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not remove missing attributes: [%s]\n",
                   strerror(ret));
            goto done;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

struct ldb_dn *sysdb_ipnetwork_dn(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *name)
{
    errno_t ret;
    char *clean_name;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, name, &clean_name);
    if (ret != EOK) {
        return NULL;
    }

    dn = ldb_dn_new_fmt(mem_ctx, domain->sysdb->ldb, SYSDB_TMPL_IP_NETWORK,
                        clean_name, domain->name);
    talloc_free(clean_name);

    return dn;
}

errno_t sysdb_ipnetwork_add(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *primary_name,
                            const char **aliases,
                            const char *address,
                            struct ldb_dn **dn)
{
    errno_t ret;
    int lret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    unsigned long i;
    size_t len;
    char *canonical_addr = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Adding network [%s] to domain [%s]\n",
          primary_name, domain->name);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* network dn */
    msg->dn = sysdb_ipnetwork_dn(msg, domain, primary_name);
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Objectclass */
    ret = sysdb_add_string(msg, SYSDB_OBJECTCLASS, SYSDB_IP_NETWORK_CLASS);
    if (ret != EOK) {
        goto done;
    }

    /* Set the primary name */
    ret = sysdb_add_string(msg, SYSDB_NAME, primary_name);
    if (ret != EOK) {
        goto done;
    }

    /* If this network has any aliases, include them */
    if (aliases != NULL && aliases[0] != NULL) {
        /* Set the name aliases */
        lret = ldb_msg_add_empty(msg, SYSDB_NAME_ALIAS,
                                 LDB_FLAG_MOD_ADD, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }

        len = talloc_array_length(aliases);
        for (i = 0; i < len && aliases[i] != NULL ; i++) {
            lret = ldb_msg_add_string(msg, SYSDB_NAME_ALIAS, aliases[i]);
            if (lret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(lret);
                goto done;
            }
        }
    }

    /* Set the address */
    ret = sss_canonicalize_ip_address(msg, address, &canonical_addr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to canonicalize network address [%s]: %s\n",
              address, sss_strerror(ret));
        goto done;
    }

    lret = ldb_msg_add_string(msg, SYSDB_IP_NETWORK_ATTR_NUMBER,
                              canonical_addr);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    /* creation time */
    ret = sysdb_add_ulong(msg, SYSDB_CREATE_TIME, (unsigned long)time(NULL));
    if (ret != 0) {
        goto done;
    }

    lret = ldb_add(domain->sysdb->ldb, msg);
    ret = sysdb_error_to_errno(lret);

    if (ret == EOK && dn != NULL) {
        *dn = talloc_steal(mem_ctx, msg->dn);
    }

done:
    if (ret != 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_ipnetwork_delete(struct sss_domain_info *domain,
                               const char *name,
                               const char *address)
{
    errno_t ret, sret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    unsigned int i;
    bool in_transaction = false;
    struct sysdb_ctx *sysdb = domain->sysdb;

    DEBUG(SSSDBG_TRACE_FUNC, "Deleting network [%s] - [%s] from domain [%s]\n",
          name, address, domain->name);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    if (name != NULL) {
        ret = sysdb_getipnetworkbyname(tmp_ctx, domain, name, &res);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }

        if (ret == ENOENT) {
            /* Doesn't exist in the DB. Nothing to do */
            ret = EOK;
            goto done;
        }
    } else if (address != NULL) {
        ret = sysdb_getipnetworkbyaddr(tmp_ctx, domain, address, &res);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }

        if (ret == ENOENT) {
            /* Doesn't exist in the DB. Nothing to do */
            ret = EOK;
            goto done;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Deleting network failed. Network name or address needed\n");
        ret = EINVAL;
        goto done;
    }

    /* There should only be one matching entry,
     * but if there are multiple, we should delete
     * them all to de-corrupt the DB.
     */
    for (i = 0; i < res->count; i++) {
        ret = sysdb_delete_entry(sysdb, res->msgs[i]->dn, false);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not cancel transaction\n");
        }
    }

    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_search_ipnetworks(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char *sub_filter,
                                const char **attrs,
                                size_t *msgs_count,
                                struct ldb_message ***msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *basedn;
    char *filter;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Searching networks with subfilter [%s] in "
          "domain [%s]\n", sub_filter, domain->name);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory\n");
        return ENOMEM;
    }

    basedn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                            SYSDB_TMPL_IP_NETWORK_BASE, domain->name);
    if (basedn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build base dn\n");
        ret = ENOMEM;
        goto fail;
    }

    filter = talloc_asprintf(tmp_ctx, "(&(%s)%s)",
                             SYSDB_IP_NETWORK_CLASS_FILTER,
                             sub_filter);
    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Searching networks with filter [%s] in "
          "domain [%s]\n", filter, domain->name);

    ret = sysdb_search_entry(mem_ctx, domain->sysdb, basedn,
                             LDB_SCOPE_SUBTREE, filter, attrs,
                             msgs_count, msgs);
    if (ret) {
        goto fail;
    }

    talloc_free(tmp_ctx);

    return EOK;

fail:
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No such entry\n");
    }
    else if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error: %d (%s)\n", ret, strerror(ret));
    }

    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
sysdb_ipnetwork_update(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char **aliases,
                       const char *address)
{
    errno_t ret;
    struct ldb_message *msg;
    int lret;
    unsigned int i;
    size_t len;
    char *canonical_addr = NULL;

    if (dn == NULL || address == NULL) {
        return EINVAL;
    }

    msg = ldb_msg_new(NULL);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = dn;

    if (aliases != NULL && aliases[0] != NULL) {
        /* Update the aliases */
        lret = ldb_msg_add_empty(msg, SYSDB_NAME_ALIAS, SYSDB_MOD_REP, NULL);
        if (lret != LDB_SUCCESS) {
            ret = ENOMEM;
            goto done;
        }

        len = talloc_array_length(aliases);
        for (i = 0; i < len && aliases[i] != NULL; i++) {
            lret = ldb_msg_add_string(msg, SYSDB_NAME_ALIAS, aliases[i]);
            if (lret != LDB_SUCCESS) {
                ret = EINVAL;
                goto done;
            }
        }
    }

    /* Update the addresses */
    ret = sss_canonicalize_ip_address(msg, address, &canonical_addr);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to canonicalize network address [%s]: %s\n",
              address, sss_strerror(ret));
        goto done;
    }

    lret = ldb_msg_add_empty(msg, SYSDB_IP_NETWORK_ATTR_NUMBER,
                             SYSDB_MOD_REP, NULL);
    if (lret != LDB_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    lret = ldb_msg_add_string(msg, SYSDB_IP_NETWORK_ATTR_NUMBER,
                              canonical_addr);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    lret = ldb_modify(sysdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_modify failed: [%s](%d)[%s]\n",
              ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb));
    }
    ret = sysdb_error_to_errno(lret);

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_free(msg);
    return ret;
}

errno_t
sysdb_ipnetwork_remove_alias(struct sysdb_ctx *sysdb,
                             struct ldb_dn *dn,
                             const char *alias)
{
    errno_t ret;
    struct ldb_message *msg;
    int lret;

    msg = ldb_msg_new(NULL);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = dn;

    ret = sysdb_delete_string(msg, SYSDB_NAME_ALIAS, alias);
    if (ret != EOK) {
        goto done;
    }

    lret = ldb_modify(sysdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_modify failed: [%s](%d)[%s]\n",
              ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb));
    }
    ret = sysdb_error_to_errno(lret);

done:
    if (ret) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Error: %d (%s)\n", ret, strerror(ret));
    }
    talloc_zfree(msg);
    return ret;
}

errno_t
sysdb_enumnetent(TALLOC_CTX *mem_ctx,
                 struct sss_domain_info *domain,
                 struct ldb_result **_res)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = {
        SYSDB_NAME,
        SYSDB_NAME_ALIAS,
        SYSDB_IP_NETWORK_ATTR_NUMBER,
        NULL,
    };
    struct ldb_result *res = NULL;
    struct ldb_message **msgs;
    size_t msgs_count;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_ipnetworks(tmp_ctx, domain, "", attrs,
                                  &msgs_count, &msgs);
    if (ret == EOK) {
        res = talloc_zero(mem_ctx, struct ldb_result);
        if (res == NULL) {
            ret = ENOMEM;
            goto done;
	}
        res->count = msgs_count;
        res->msgs = talloc_steal(res, msgs);
    }

    *_res = res;

done:
    talloc_free(tmp_ctx);
    return ret;
}
