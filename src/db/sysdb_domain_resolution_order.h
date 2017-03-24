/*
    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef _SYSDB_DOMAIN_RESOLUTION_ORDER_H_
#define _SYSDB_DOMAIN_RESOLUTION_ORDER_H_

#include "db/sysdb.h"

errno_t
sysdb_get_domain_resolution_order(TALLOC_CTX *mem_ctx,
                                  struct sysdb_ctx *sysdb,
                                  struct ldb_dn *dn,
                                  const char **_domain_resolution_order);

errno_t
sysdb_update_domain_resolution_order(struct sysdb_ctx *sysdb,
                                     struct ldb_dn *dn,
                                     const char *domain_resolution_order);

#endif /* _SYSDB_DOMAIN_RESOLUTION_ORDER_H_ */
