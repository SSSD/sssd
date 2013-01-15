/*
    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "util/util.h"

struct sss_domain_info *get_next_domain(struct sss_domain_info *domain,
                                        bool descend)
{
    struct sss_domain_info *dom;

    dom = domain;
    while (dom) {
        if (descend && dom->subdomain_count > 0) {
            dom = dom->subdomains[0];
        } else if (dom->next) {
            dom = dom->next;
        } else if (descend && dom->parent) {
            dom = dom->parent->next;
        } else {
            return NULL;
        }
        if (!dom->disabled) break;
    }

    return dom;
}

struct sss_domain_info *new_subdomain(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *parent,
                                      const char *name,
                                      const char *realm,
                                      const char *flat_name,
                                      const char *id)
{
    struct sss_domain_info *dom;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Creating [%s] as subdomain of [%s]!\n", name, parent->name));

    dom = talloc_zero(mem_ctx, struct sss_domain_info);
    if (dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
        return NULL;
    }

    dom->parent = parent;
    dom->name = talloc_strdup(dom, name);
    if (dom->name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to copy domain name.\n"));
        goto fail;
    }

    dom->provider = talloc_strdup(dom, parent->provider);
    if (dom->provider == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to copy provider name.\n"));
        goto fail;
    }

    dom->conn_name = talloc_strdup(dom, parent->conn_name);
    if (dom->conn_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to copy connection name.\n"));
        goto fail;
    }

    if (realm != NULL) {
        dom->realm = talloc_strdup(dom, realm);
        if (dom->realm == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to copy realm name.\n"));
            goto fail;
        }
    }

    if (flat_name != NULL) {
        dom->flat_name = talloc_strdup(dom, flat_name);
        if (dom->flat_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to copy flat name.\n"));
            goto fail;
        }
    }

    if (id != NULL) {
        dom->domain_id = talloc_strdup(dom, id);
        if (dom->domain_id == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to copy id.\n"));
            goto fail;
        }
    }

    dom->enumerate = false;
    dom->fqnames = true;
    dom->mpg = true;
    /* FIXME: get ranges from the server */
    dom->id_min = 0;
    dom->id_max = 0xffffffff;
    dom->pwd_expiration_warning = parent->pwd_expiration_warning;
    dom->cache_credentials = parent->cache_credentials;
    dom->case_sensitive = false;
    dom->user_timeout = parent->user_timeout;
    dom->group_timeout = parent->group_timeout;
    dom->netgroup_timeout = parent->netgroup_timeout;
    dom->service_timeout = parent->service_timeout;
    dom->override_homedir = parent->override_homedir;
    dom->names = parent->names;

    dom->subdomain_homedir = parent->subdomain_homedir;

    if (parent->sysdb == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Missing sysdb context in parent domain.\n"));
        goto fail;
    }
    dom->sysdb = parent->sysdb;

    return dom;

fail:
    talloc_free(dom);
    return NULL;
}

struct sss_domain_info *copy_subdomain(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *subdomain)
{
    return new_subdomain(mem_ctx, subdomain->parent,
                         subdomain->name, subdomain->realm,
                         subdomain->flat_name, subdomain->domain_id);
}

errno_t sssd_domain_init(TALLOC_CTX *mem_ctx,
                         struct confdb_ctx *cdb,
                         const char *domain_name,
                         const char *db_path,
                         struct sss_domain_info **_domain)
{
    int ret;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;

    ret = confdb_get_domain(cdb, domain_name, &dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Error retrieving domain configuration.\n"));
        return ret;
    }

    if (dom->sysdb != NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Sysdb context already initialized.\n"));
        return EEXIST;
    }

    ret = sysdb_domain_init(mem_ctx, dom, db_path, &sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Error opening cache database.\n"));
        return ret;
    }

    dom->sysdb = talloc_steal(dom, sysdb);

    *_domain = dom;

    return EOK;
}
