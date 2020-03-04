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

#ifndef SYSDB_IP_NETWORKS_H_
#define SYSDB_IP_NETWORKS_H_

#include "db/sysdb.h"

#define SYSDB_IP_NETWORK_CLASS          "network"
#define SYSDB_IP_NETWORK_CONTAINER      "cn=networks"

#define SYSDB_IP_NETWORK_CLASS_FILTER   "objectclass="SYSDB_IP_NETWORK_CLASS
#define SYSDB_IP_NETWORK_ATTR_NUMBER    "ipNetworkNumber"

#define SYSDB_TMPL_IP_NETWORK_BASE      SYSDB_IP_NETWORK_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_IP_NETWORK           SYSDB_NAME"=%s,"SYSDB_TMPL_IP_NETWORK_BASE

#define SYSDB_IP_NETWORK_BYNAME_SUBFILTER \
    "(|("SYSDB_NAME"=%s)("SYSDB_NAME_ALIAS"=%s))"
#define SYSDB_IP_NETWORK_BYADDR_SUBFILTER \
    "("SYSDB_IP_NETWORK_ATTR_NUMBER"=%s)"

errno_t sysdb_getipnetworkbyname(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *name,
                                 struct ldb_result **_res);

errno_t sysdb_getipnetworkbyaddr(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
				 const char *address,
                                 struct ldb_result **_res);

errno_t
sysdb_store_ipnetwork(struct sss_domain_info *domain,
                      const char *primary_name,
                      const char **aliases,
                      const char *address,
                      struct sysdb_attrs *extra_attrs,
                      char **remove_attrs,
                      uint64_t cache_timeout,
                      time_t now);

struct ldb_dn *sysdb_ipnetwork_dn(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *name);

errno_t sysdb_ipnetwork_add(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *primary_name,
                            const char **aliases,
			    const char *address,
                            struct ldb_dn **dn);

errno_t sysdb_ipnetwork_delete(struct sss_domain_info *domain,
                               const char *name,
			       const char *address);

errno_t sysdb_search_ipnetworks(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char *sub_filter,
                                const char **attrs,
                                size_t *msgs_count,
                                struct ldb_message ***msgs);

errno_t sysdb_enumnetent(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         struct ldb_result **_res);

#endif /* SYSDB_IP_NETWORKS_H_ */
