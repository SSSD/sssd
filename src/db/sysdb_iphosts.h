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

#ifndef SYSDB_IP_HOSTS_H_
#define SYSDB_IP_HOSTS_H_

#include "db/sysdb.h"

#define SYSDB_IP_HOST_CLASS         "host"
#define SYSDB_IP_HOST_CONTAINER     "cn=hosts"

#define SYSDB_IP_HOST_CLASS_FILTER  "objectclass="SYSDB_IP_HOST_CLASS
#define SYSDB_IP_HOST_ATTR_ADDRESS  "ipHostNumber"

#define SYSDB_TMPL_IP_HOST_BASE     SYSDB_IP_HOST_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_IP_HOST          SYSDB_NAME"=%s,"SYSDB_TMPL_IP_HOST_BASE

#define SYSDB_IP_HOST_BYNAME_SUBFILTER \
    "(|("SYSDB_NAME"=%s)("SYSDB_NAME_ALIAS"=%s))"
#define SYSDB_IP_HOST_BYADDR_SUBFILTER \
    "("SYSDB_IP_HOST_ATTR_ADDRESS"=%s)"

errno_t sysdb_gethostbyname(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *name,
                            struct ldb_result **_res);

errno_t sysdb_gethostbyaddr(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *address,
                            struct ldb_result **_res);

errno_t
sysdb_store_host(struct sss_domain_info *domain,
                 const char *primary_name,
                 const char **aliases,
                 const char **addresses,
                 struct sysdb_attrs *extra_attrs,
                 char **remove_attrs,
                 uint64_t cache_timeout,
                 time_t now);

struct ldb_dn *sysdb_host_dn(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             const char *name);

errno_t sysdb_host_add(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *primary_name,
                       const char **aliases,
                       const char **addresses,
                       struct ldb_dn **dn);

errno_t sysdb_host_delete(struct sss_domain_info *domain,
                          const char *name,
                          const char *address);

errno_t sysdb_search_hosts(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *sub_filter,
                           const char **attrs,
                           size_t *msgs_count,
                           struct ldb_message ***msgs);

errno_t sysdb_enumhostent(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          struct ldb_result **_res);

#endif /* SYSDB_IP_HOSTS_H_ */
