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

#ifndef _CACHE_REQ_DOMAIN_H_
#define _CACHE_REQ_DOMAIN_H_

#include "responder/common/responder.h"

struct cache_req_domain {
    struct sss_domain_info *domain;
    bool fqnames;
    bool locate_domain;

    struct cache_req_domain *prev;
    struct cache_req_domain *next;
};

struct cache_req_domain *
cache_req_domain_get_domain_by_name(struct cache_req_domain *domains,
                                    const char *name);

/*
 * This function may have a side effect of setting the output_fqnames' domain
 * property when it's called.
 *
 * It happens as the output_fqnames' domain property must only be set depending
 * on whether a domain resolution order is set or not, and the saner place to
 * set it to all domains is when flattening those (thus, in this function).
 */
errno_t
cache_req_domain_new_list_from_domain_resolution_order(
                                        TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *domains,
                                        const char *domain_resolution_order,
                                        struct cache_req_domain **_cr_domains);

errno_t
cache_req_domain_copy_cr_domains(TALLOC_CTX *mem_ctx,
                                 struct cache_req_domain *src,
                                 char **requested_domains,
                                 struct cache_req_domain **_dest);

void cache_req_domain_list_zfree(struct cache_req_domain **cr_domains);


#endif /* _CACHE_REQ_DOMAIN_H_ */
