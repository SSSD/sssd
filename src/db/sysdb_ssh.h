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

#ifndef _SYSDB_SSH_H_
#define _SYSDB_SSH_H_

#include "db/sysdb.h"

#define SSH_HOSTS_SUBDIR "ssh_hosts"

#define SYSDB_SSH_HOST_OC "sshHost"

#define SYSDB_SSH_KNOWN_HOSTS_EXPIRE "sshKnownHostsExpire"

errno_t
sysdb_store_ssh_host(struct sss_domain_info *domain,
                     const char *name,
                     const char *alias,
                     int cache_timeout,
                     time_t now,
                     struct sysdb_attrs *attrs);

errno_t
sysdb_update_ssh_known_host_expire(struct sss_domain_info *domain,
                                   const char *name,
                                   time_t now,
                                   int known_hosts_timeout);

int
sysdb_set_ssh_host_attr(struct sss_domain_info *domain,
                        const char *name,
                        struct sysdb_attrs *attrs,
                        int mod_op);

errno_t
sysdb_delete_ssh_host(struct sss_domain_info *domain,
                      const char *name);

errno_t
sysdb_search_ssh_hosts(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *filter,
                       const char **attrs,
                       size_t *num_hosts,
                       struct ldb_message ***hosts);

errno_t
sysdb_get_ssh_host(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   const char **attrs,
                   struct ldb_message **host);

errno_t
sysdb_get_ssh_known_hosts(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          time_t now,
                          const char **attrs,
                          struct ldb_message ***hosts,
                          size_t *num_hosts);

#endif /* _SYSDB_SSH_H_ */
