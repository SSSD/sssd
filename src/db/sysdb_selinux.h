/*
   SSSD

   System Database Header - SELinux support

   Copyright (C) Jan Zeleny <jzeleny@redhat.com>	2012

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

#ifndef __SYS_DB_SELINUX_H__
#define __SYS_DB_SELINUX_H__

#include "db/sysdb.h"

#define SYSDB_SELINUX_CONTAINER "cn=selinux"
#define SYSDB_TMPL_SELINUX_BASE SYSDB_SELINUX_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_SEUSERMAP SYSDB_NAME"=%s,"SYSDB_TMPL_SELINUX_BASE

#define SYSDB_SELINUX_NAME "config"
#define SYSDB_SELINUX_SEEALSO "seeAlso"
#define SYSDB_SELINUX_USER "selinuxUser"
#define SYSDB_SELINUX_ENABLED "enabled"
#define SYSDB_SELINUX_DEFAULT_USER "user"
#define SYSDB_SELINUX_DEFAULT_ORDER "order"
#define SYSDB_SELINUX_HOST_PRIORITY "hostPriority"

errno_t sysdb_store_selinux_usermap(struct sss_domain_info *domain,
                                    struct sysdb_attrs *attrs);

errno_t sysdb_store_selinux_config(struct sss_domain_info *domain,
                                   const char *default_map,
                                   const char *order);

errno_t sysdb_get_selinux_usermaps(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   const char **attrs,
                                   size_t *count,
                                   struct ldb_message ***messages);

errno_t sysdb_search_selinux_config(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char **attrs,
                                    struct ldb_message **_config);

errno_t sysdb_delete_usermaps(struct sss_domain_info *domain);

#endif
