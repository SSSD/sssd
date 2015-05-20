/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#ifndef IFP_CACHE_H_
#define IFP_CACHE_H_

#include "responder/common/responder.h"
#include "responder/ifp/ifp_iface_generated.h"

enum ifp_cache_type {
    IFP_CACHE_USER,
    IFP_CACHE_GROUP
};

errno_t ifp_cache_list_domains(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domains,
                               enum ifp_cache_type type,
                               const char ***_paths,
                               int *_num_paths);

/* org.freedesktop-sssd-infopipe.Cache */

int ifp_cache_list(struct sbus_request *sbus_req,
                   void *data,
                   enum ifp_cache_type type);

int ifp_cache_list_by_domain(struct sbus_request *sbus_req,
                             void *data,
                             const char *domain,
                             enum ifp_cache_type type);

/* org.freedesktop-sssd-infopipe.Cache.Object */

int ifp_cache_object_store(struct sbus_request *sbus_req,
                           struct sss_domain_info *domain,
                           struct ldb_dn *dn);

int ifp_cache_object_remove(struct sbus_request *sbus_req,
                            struct sss_domain_info *domain,
                            struct ldb_dn *dn);

#endif /* IFP_CACHE_H_ */
