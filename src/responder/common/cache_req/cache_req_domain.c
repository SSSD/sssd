/*
    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include "responder/common/cache_req/cache_req_domain.h"

struct cache_req_domain *
cache_req_domain_get_domain_by_name(struct cache_req_domain *domains,
                                    const char *name)
{
    struct cache_req_domain *dom;
    struct cache_req_domain *ret = NULL;

    DLIST_FOR_EACH(dom, domains) {
        if (sss_domain_get_state(dom->domain) == DOM_DISABLED) {
            continue;
        }

        if (strcasecmp(dom->domain->name, name) == 0 ||
            (dom->domain->flat_name != NULL &&
             strcasecmp(dom->domain->flat_name, name) == 0)) {
            ret = dom;
            break;
        }
    }

    if (ret == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown domains [%s].\n", name);
    }

    return ret;
}

errno_t
cache_req_domain_copy_cr_domains(TALLOC_CTX *mem_ctx,
                                 struct cache_req_domain *src,
                                 char **requested_domains,
                                 struct cache_req_domain **_dest)
{
    struct cache_req_domain *cr_domains = NULL;
    struct cache_req_domain *cr_domain;
    struct cache_req_domain *iter;
    errno_t ret;

    if (src == NULL) {
        return EINVAL;
    }

    DLIST_FOR_EACH(iter, src) {
        if (requested_domains != NULL
                && !string_in_list(iter->domain->name, requested_domains,
                                   false)) {
            continue;
        }

        cr_domain = talloc_zero(mem_ctx, struct cache_req_domain);
        if (cr_domain == NULL) {
            ret = ENOMEM;
            goto done;
        }

        cr_domain->domain = iter->domain;
        cr_domain->fqnames = iter->fqnames;

        DLIST_ADD_END(cr_domains, cr_domain, struct cache_req_domain *);
    }

    if (cr_domains == NULL) {
        if (requested_domains != NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "No requested domains found, "
                  "please check configuration options for typos.\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy domains.\n");
        }
        ret = EINVAL;
        goto done;
    }

    *_dest = cr_domains;
    ret = EOK;

done:
    if (ret != EOK) {
        cache_req_domain_list_zfree(&cr_domains);
    }

    return ret;
}

void cache_req_domain_list_zfree(struct cache_req_domain **cr_domains)
{
    struct cache_req_domain *p, *q, *r;

    DLIST_FOR_EACH_SAFE(p, q, *cr_domains) {
        r = p;
        DLIST_REMOVE(*cr_domains, p);
        talloc_zfree(r);
    }

    *cr_domains = NULL;
}

static bool
cache_req_domain_use_fqnames(struct sss_domain_info *domain,
                             bool enforce_non_fqnames)
{
    struct sss_domain_info *head;

    head = get_domains_head(domain);

    /*
     * In order to decide whether fully_qualified_names must be used on the
     * lookups we have to take into consideration:
     * - use_fully_qualified_name value of the head of the domains;
     *   (head->fqnames)
     * - the presence of a domains' resolution order list;
     *   (non_fqnames_enforced)
     *
     * The relationship between those two can be described by:
     * - head->fqnames:
     *   - true: in this case doesn't matter whether it's enforced or not,
     *           fully-qualified-names will _always_ be used
     *   - false: in this case (which is also the default case), the usage
     *            depends on it being enforced;
     *
     *     - enforce_non_fqnames:
     *       - true: in this case, the usage of fully-qualified-names is not
     *               needed;
     *       - false: in this case, the usage of fully-qualified-names will be
     *                done accordingly to what's set for the domain itself.
     */
     if (head->fqnames) {
         return true;
     } else if (enforce_non_fqnames) {
         return false;
     } else {
         return domain->fqnames;
     }
}

static struct cache_req_domain *
cache_req_domain_new_list_from_string_list(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domains,
                                           char **resolution_order)
{
    struct cache_req_domain *cr_domains = NULL;
    struct cache_req_domain *cr_domain;
    struct sss_domain_info *dom;
    char *name;
    int flag = SSS_GND_ALL_DOMAINS;
    int i;
    bool enforce_non_fqnames = false;
    errno_t ret;

    /* Firstly, in case a domains' resolution order is passed ... iterate over
     * the list adding its domains to the flatten cache req domains' list */
    if (resolution_order != NULL) {
        enforce_non_fqnames = true;
        for (i = 0; resolution_order[i] != NULL; i++) {
            name = resolution_order[i];
            for (dom = domains; dom; dom = get_next_domain(dom, flag)) {
                if (strcasecmp(name, dom->name) != 0) {
                    continue;
                }

                cr_domain = talloc_zero(mem_ctx, struct cache_req_domain);
                if (cr_domain == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                cr_domain->domain = dom;
                cr_domain->fqnames =
                    cache_req_domain_use_fqnames(dom, enforce_non_fqnames);

                /* when using the domain resolution order, using shortnames as
                 * input is allowed by default. However, we really want to use
                 * the fully qualified name as output in order to avoid
                 * conflicts whith users who have the very same name. */
                sss_domain_info_set_output_fqnames(cr_domain->domain, true);

                DLIST_ADD_END(cr_domains, cr_domain,
                              struct cache_req_domain *);
                break;
            }
        }
    }

    /* Then iterate through all the other domains (and subdomains) and add them
     * to the flatten cache req domains' list */
    for (dom = domains; dom; dom = get_next_domain(dom, flag)) {
        if (string_in_list(dom->name, resolution_order, false)) {
            continue;
        }

        cr_domain = talloc_zero(mem_ctx, struct cache_req_domain);
        if (cr_domain == NULL) {
            ret = ENOMEM;
            goto done;
        }
        cr_domain->domain = dom;
        cr_domain->fqnames =
            cache_req_domain_use_fqnames(dom, enforce_non_fqnames);

        /* when using the domain resolution order, using shortnames as input
         * is allowed by default. However, we really want to use the fully
         * qualified name as output in order to avoid conflicts whith users
         * who have the very same name.
         */
        if (resolution_order != NULL) {
            sss_domain_info_set_output_fqnames(cr_domain->domain, true);
        }

        DLIST_ADD_END(cr_domains, cr_domain, struct cache_req_domain *);
    }

    ret = EOK;

done:
    if (ret != EOK) {
        cache_req_domain_list_zfree(&cr_domains);
    }

    return cr_domains;
}

errno_t
cache_req_domain_new_list_from_domain_resolution_order(
                                        TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domains,
                                        const char *domain_resolution_order,
                                        struct cache_req_domain **_cr_domains)
{
    TALLOC_CTX *tmp_ctx;
    struct cache_req_domain *cr_domains;
    char **list = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (domain_resolution_order != NULL) {
        if (strcmp(domain_resolution_order, ":") != 0) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Domain resolution order list (split by ':'): \"%s\"\n",
                  domain_resolution_order);

            ret = split_on_separator(tmp_ctx, domain_resolution_order, ':',
                                     true, true, &list, NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                        "split_on_separator() failed [%d]: [%s].\n",
                        ret, sss_strerror(ret));
                goto done;
            }
        } else {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Domain resolution order list: ':' "
                  "(do not use any specific order)\n");
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Domain resolution order list: not set\n");
    }

    cr_domains = cache_req_domain_new_list_from_string_list(mem_ctx, domains,
                                                            list);
    if (cr_domains == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_OP_FAILURE,
              "cache_req_domain_new_list_from_domain_resolution_order() "
              "failed [%d]: [%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    *_cr_domains = cr_domains;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
