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

#ifndef _SDAP_SUDO_CACHE_H_
#define _SDAP_SUDO_CACHE_H_

#include "src/providers/ldap/sdap.h"

/* Cache functions specific for the native sudo LDAP schema */
errno_t
sdap_save_native_sudorule_list(TALLOC_CTX *mem_ctx,
                               struct sysdb_ctx *sysdb_ctx,
                               struct sdap_attr_map *map,
                               struct sysdb_attrs **replies,
                               size_t replies_count,
                               int cache_timeout,
                               time_t now,
                               char **_usn);

#endif /* _SDAP_SUDO_CACHE_H_ */
