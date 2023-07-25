/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#ifndef _SYSDB_AUTOFS_H_
#define _SYSDB_AUTOFS_H_

#include "db/sysdb.h"

/* subdirs in cn=custom in sysdb. We don't store autofs stuff in sysdb directly
 * b/c it's not name-service-switch data */
#define AUTOFS_MAP_SUBDIR   "autofsmaps"
#define AUTOFS_ENTRY_SUBDIR "autofsentries"

#define SYSDB_AUTOFS_MAP_OC            "automountMap"
#define SYSDB_AUTOFS_MAP_NAME          "automountMapName"

#define SYSDB_AUTOFS_ENTRY_OC     "automount"
#define SYSDB_AUTOFS_ENTRY_KEY    "automountKey"
#define SYSDB_AUTOFS_ENTRY_VALUE  "automountInformation"

errno_t
sysdb_save_autofsmap(struct sss_domain_info *domain,
                     const char *name,
                     const char *autofsmapname,
                     const char *origdn,
                     struct sysdb_attrs *attrs,
                     int cache_timeout,
                     time_t now,
                     bool enumerated);

errno_t
sysdb_get_map_byname(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
                     const char *map_name,
                     struct ldb_message **map);

errno_t
sysdb_delete_autofsmap(struct sss_domain_info *domain,
                       const char *name);

errno_t
sysdb_save_autofsentry(struct sss_domain_info *domain,
                       const char *map,
                       const char *key,
                       const char *value,
                       struct sysdb_attrs *attrs,
                       int cache_timeout,
                       time_t now);

errno_t
sysdb_get_autofsentry(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *map_name,
                      const char *entry_name,
                      struct ldb_message **_entry);

errno_t
sysdb_del_autofsentry(struct sss_domain_info *domain,
                      const char *entry_dn);

errno_t
sysdb_del_autofsentry_by_key(struct sss_domain_info *domain,
                             const char *map_name,
                             const char *entry_key);

errno_t
sysdb_autofs_entries_by_map(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *mapname,
                            size_t *_count,
                            struct ldb_message ***_entries);

errno_t
sysdb_set_autofsmap_attr(struct sss_domain_info *domain,
                         const char *name,
                         struct sysdb_attrs *attrs,
                         int mod_op);

errno_t
sysdb_invalidate_autofs_entries(struct sss_domain_info *domain,
                                const char *mapname);

errno_t
sysdb_invalidate_autofs_maps(struct sss_domain_info *domain);

char *
sysdb_autofsentry_strdn(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *map_name,
                        const char *entry_name,
                        const char *entry_value);

#endif /* _SYSDB_AUTOFS_H_ */
