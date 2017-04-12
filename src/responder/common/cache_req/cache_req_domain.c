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
    errno_t ret;

    if (resolution_order != NULL) {
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

                DLIST_ADD_END(cr_domains, cr_domain,
                              struct cache_req_domain *);
                break;
            }
        }
    }

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
            ret = split_on_separator(tmp_ctx, domain_resolution_order, ':',
                                     true, true, &list, NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                        "split_on_separator() failed [%d]: [%s].\n",
                        ret, sss_strerror(ret));
                goto done;
            }
        }
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
