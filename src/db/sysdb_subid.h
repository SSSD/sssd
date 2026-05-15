/*
    Copyright (C) 2021 Red Hat

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

#ifndef _SYSDB_SUBID_H_
#define _SYSDB_SUBID_H_

#include "db/sysdb.h"

#define SYSDB_SUBID_RANGE_OC "subordinateid"

errno_t sysdb_store_subid_range(struct sss_domain_info *domain,
                                const char *name,
                                int expiration_period,
                                struct sysdb_attrs *attrs);

errno_t sysdb_get_subid_ranges(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               const char *name,
                               const char **attrs,
                               struct ldb_message **range);

errno_t sysdb_delete_subid_range(struct sss_domain_info *domain,
                                 const char *name);

#endif /* _SYSDB_SSH_H_ */
