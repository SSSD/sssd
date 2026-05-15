/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#ifndef SYSDB_SERVICES_H_
#define SYSDB_SERVICES_H_

#include "db/sysdb.h"

#define SYSDB_SVC_CLASS "service"
#define SYSDB_SVC_CONTAINER "cn=services"
#define SYSDB_SC "objectclass="SYSDB_SVC_CLASS

#define SYSDB_SVC_PORT "servicePort"
#define SYSDB_SVC_PROTO "serviceProtocol"

#define SYSDB_TMPL_SVC_BASE SYSDB_SVC_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_SVC SYSDB_NAME"=%s,"SYSDB_TMPL_SVC_BASE

#define SYSDB_SVC_BYNAME_FILTER "(&("SYSDB_SVC_PROTO"=%s)(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_SVC_BYPORT_FILTER "(&("SYSDB_SVC_PROTO"=%s)("SYSDB_SVC_PORT"=%u))"


#define SYSDB_SVC_ATTRS { \
    SYSDB_NAME, \
    SYSDB_NAME_ALIAS, \
    SYSDB_SVC_PORT, \
    SYSDB_SVC_PROTO, \
    SYSDB_DEFAULT_ATTRS, \
    NULL }

errno_t
sysdb_getservbyname(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    const char *name,
                    const char *proto,
                    struct ldb_result **_res);

errno_t
sysdb_getservbyport(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    int port,
                    const char *proto,
                    struct ldb_result **_res);

errno_t
sysdb_enumservent(TALLOC_CTX *mem_ctx,
                  struct sss_domain_info *domain,
                  struct ldb_result **_res);

errno_t
sysdb_store_service(struct sss_domain_info *domain,
                    const char *primary_name,
                    int port,
                    const char **aliases,
                    const char **protocols,
                    struct sysdb_attrs *extra_attrs,
                    char **remove_attrs,
                    uint64_t cache_timeout,
                    time_t now);

struct ldb_dn *
sysdb_svc_dn(struct sysdb_ctx *sysdb, TALLOC_CTX *mem_ctx,
             const char *domain, const char *name);

errno_t
sysdb_svc_add(TALLOC_CTX *mem_ctx,
              struct sss_domain_info *domain,
              const char *primary_name,
              int port,
              const char **aliases,
              const char **protocols,
              struct ldb_dn **dn);

errno_t
sysdb_svc_delete(struct sss_domain_info *domain,
                 const char *name,
                 int port,
                 const char *proto);

errno_t
sysdb_set_service_attr(struct sss_domain_info *domain,
                       const char *name,
                       struct sysdb_attrs *attrs,
                       int mod_op);

errno_t sysdb_search_services(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              const char *sub_filter,
                              const char **attrs,
                              size_t *msgs_count,
                              struct ldb_message ***msgs);

#endif /* SYSDB_SERVICES_H_ */
