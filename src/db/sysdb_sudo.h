/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2011 Red Hat

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

#ifndef _SYSDB_SUDO_H_
#define _SYSDB_SUDO_H_

#include "db/sysdb.h"

/* subdirs in cn=custom in sysdb. We don't store sudo stuff in sysdb directly
 * b/c it's not name-service-switch data */
#define SUDORULE_SUBDIR "sudorules"

/* sysdb attributes */
#define SYSDB_SUDO_CACHE_AT_OC         "sudoRule"
#define SYSDB_SUDO_CACHE_AT_CN         "cn"
#define SYSDB_SUDO_CACHE_AT_USER       "sudoUser"
#define SYSDB_SUDO_CACHE_AT_HOST       "sudoHost"
#define SYSDB_SUDO_CACHE_AT_COMMAND    "sudoCommand"
#define SYSDB_SUDO_CACHE_AT_OPTION     "sudoOption"
#define SYSDB_SUDO_CACHE_AT_RUNASUSER  "sudoRunAsUser"
#define SYSDB_SUDO_CACHE_AT_RUNASGROUP "sudoRunAsGroup"
#define SYSDB_SUDO_CACHE_AT_NOTBEFORE  "sudoNotBefore"
#define SYSDB_SUDO_CACHE_AT_NOTAFTER   "sudoNotAfter"
#define SYSDB_SUDO_CACHE_AT_ORDER      "sudoOrder"

/* When constructing a sysdb filter, OR these values to include..   */
#define SYSDB_SUDO_FILTER_NONE           0x00       /* no additional filter */
#define SYSDB_SUDO_FILTER_NGRS           0x01       /* netgroups            */
#define SYSDB_SUDO_FILTER_TIMED          0x02       /* timed rules          */
#define SYSDB_SUDO_FILTER_INCLUDE_ALL    0x04       /* ALL                  */
#define SYSDB_SUDO_FILTER_INCLUDE_DFL    0x08       /* include cn=default   */

errno_t
sysdb_get_sudo_filter(TALLOC_CTX *mem_ctx, const char *username,
                      uid_t uid, char **groupnames, unsigned int flags,
                      char **_filter);

errno_t
sysdb_get_sudo_user_info(TALLOC_CTX *mem_ctx, const char *username,
                         struct sysdb_ctx *sysdb, uid_t *_uid,
                         char ***groupnames);

errno_t
sysdb_save_sudorule(struct sysdb_ctx *sysdb_ctx,
                   const char *rule_name,
                   struct sysdb_attrs *attrs);

errno_t sysdb_purge_sudorule_subtree(struct sysdb_ctx *sysdb,
                                     struct sss_domain_info *domain,
                                     const char *filter);

#endif /* _SYSDB_SUDO_H_ */
