/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "db/sysdb_ssh.h"
#include "db/sysdb_private.h"

static struct ldb_dn *
sysdb_ssh_host_dn(TALLOC_CTX *mem_ctx,
                  struct sss_domain_info *domain,
                  const char *name)
{
    return sysdb_custom_dn(mem_ctx, domain, name, SSH_HOSTS_SUBDIR);
}

static errno_t
sysdb_update_ssh_host(struct sss_domain_info *domain,
                      const char *name,
                      struct sysdb_attrs *attrs)
{
    errno_t ret;

    ret = sysdb_store_custom(domain, name, SSH_HOSTS_SUBDIR,
                             attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error storing host %s [%d]: %s\n", name, ret, strerror(ret));
        return ret;
    }

    return EOK;
}

errno_t
sysdb_store_ssh_host(struct sss_domain_info *domain,
                     const char *name,
                     const char *alias,
                     int cache_timeout,
                     time_t now,
                     struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret, sret;
    bool in_transaction = false;
    const char *search_attrs[] = { SYSDB_NAME_ALIAS, NULL };
    bool new_alias;
    struct ldb_message *host = NULL;
    struct ldb_message_element *el;
    unsigned int i;

    DEBUG(SSSDBG_TRACE_FUNC, "Storing host %s\n", name);

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

    ret = sysdb_get_ssh_host(tmp_ctx, domain, name, search_attrs, &host);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_OBJECTCLASS, SYSDB_SSH_HOST_OC);
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

    if (alias) {
        new_alias = true;

        /* copy aliases from the existing entry */
        if (host) {
            el = ldb_msg_find_element(host, SYSDB_NAME_ALIAS);

            if (el) {
                for (i = 0; i < el->num_values; i++) {
                    if (strcmp((char *)el->values[i].data, alias) == 0) {
                        new_alias = false;
                    }

                    ret = sysdb_attrs_add_val(attrs,
                                              SYSDB_NAME_ALIAS, &el->values[i]);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "Could not add name alias %s [%d]: %s\n",
                               el->values[i].data, ret, strerror(ret));
                        goto done;
                    }
                }
            }
        }

        /* add alias only if it is not already present */
        if (new_alias) {
            ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, alias);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Could not add name alias %s [%d]: %s\n",
                       alias, ret, strerror(ret));
                goto done;
            }
        }
    }

    /* make sure sshPublicKey is present when modifying an existing host */
    if (host) {
        ret = sysdb_attrs_get_el(attrs, SYSDB_SSH_PUBKEY, &el);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not get sysdb sshPublicKey [%d]: %s\n",
                   ret, strerror(ret));
            goto done;
        }
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_LAST_UPDATE, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set sysdb lastUpdate [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_CACHE_EXPIRE,
                                 cache_timeout ? (now + cache_timeout) : 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set sysdb cache expire [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = sysdb_update_ssh_host(domain, name, attrs);
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

errno_t
sysdb_set_ssh_host_attr(struct sss_domain_info *domain,
                        const char *name,
                        struct sysdb_attrs *attrs,
                        int mod_op)
{
    errno_t ret;
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    dn = sysdb_ssh_host_dn(tmp_ctx, domain, name);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_set_entry_attr(domain->sysdb, dn, attrs, mod_op);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sysdb_update_ssh_known_host_expire(struct sss_domain_info *domain,
                                   const char *name,
                                   time_t now,
                                   int known_hosts_timeout)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct sysdb_attrs *attrs;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Updating known_hosts expire time of host %s\n", name);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_SSH_KNOWN_HOSTS_EXPIRE,
                                 now + known_hosts_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set known_hosts expire time [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }

    ret = sysdb_update_ssh_host(domain, name, attrs);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_delete_ssh_host(struct sss_domain_info *domain,
                      const char *name)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Deleting host %s\n", name);
    return sysdb_delete_custom(domain, name, SSH_HOSTS_SUBDIR);
}

errno_t
sysdb_search_ssh_hosts(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *filter,
                       const char **attrs,
                       size_t *num_hosts,
                       struct ldb_message ***hosts)
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
                              SSH_HOSTS_SUBDIR, attrs,
                              &num_results, &results);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error looking up host [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    } if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No such host\n");
        *hosts = NULL;
        *num_hosts = 0;
        goto done;
    }

    *hosts = talloc_steal(mem_ctx, results);
    *num_hosts = num_results;
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_get_ssh_host(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   const char **attrs,
                   struct ldb_message **host)
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

    filter = talloc_asprintf(tmp_ctx, "(|(%s=%s)(%s=%s))",
                             SYSDB_NAME, name, SYSDB_NAME_ALIAS, name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Searching sysdb with filter '%s'\n", filter);
    ret = sysdb_search_ssh_hosts(tmp_ctx, domain, filter, attrs,
                                 &num_hosts, &hosts);
    if (ret != EOK) {
        goto done;
    }

    if (num_hosts > 1) {
        ret = EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one host with name %s\n", name);
        goto done;
    }

    *host = talloc_steal(mem_ctx, hosts[0]);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sysdb_get_ssh_known_hosts(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          time_t now,
                          const char **attrs,
                          struct ldb_message ***hosts,
                          size_t *num_hosts)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *filter;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx,
                             "(&(|(!(%s=*))(%s=0)(%s>=%lld))(%s>=%lld))",
                             SYSDB_CACHE_EXPIRE,
                             SYSDB_CACHE_EXPIRE,
                             SYSDB_CACHE_EXPIRE, (long long)now + 1,
                             SYSDB_SSH_KNOWN_HOSTS_EXPIRE, (long long)now + 1);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_ssh_hosts(mem_ctx, domain, filter, attrs,
                                 num_hosts, hosts);

done:
    talloc_free(tmp_ctx);

    return ret;
}
