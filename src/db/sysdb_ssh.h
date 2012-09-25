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
sysdb_store_ssh_host(struct sysdb_ctx *sysdb,
                     const char *name,
                     const char *alias,
                     time_t now,
                     struct sysdb_attrs *attrs);

errno_t
sysdb_update_ssh_known_host_expire(struct sysdb_ctx *sysdb,
                                   const char *name,
                                   time_t now,
                                   int known_hosts_timeout);

errno_t
sysdb_delete_ssh_host(struct sysdb_ctx *sysdb,
                      const char *name);

errno_t
sysdb_get_ssh_host(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *sysdb,
                   const char *name,
                   const char **attrs,
                   struct ldb_message **host);

errno_t
sysdb_get_ssh_known_hosts(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *sysdb,
                          time_t now,
                          const char **attrs,
                          struct ldb_message ***hosts,
                          size_t *num_hosts);

#endif /* _SYSDB_SSH_H_ */
