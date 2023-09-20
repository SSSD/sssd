/*
   SSSD

   Configuration Database

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#ifndef CONFDB_SETUP_H_
#define CONFDB_SETUP_H_

#include <stdbool.h>
#include <talloc.h>

#include "util/util_errors.h"

#define CONFDB_BASE_LDIF \
     "dn: @ATTRIBUTES\n" \
     "cn: CASE_INSENSITIVE\n" \
     "dc: CASE_INSENSITIVE\n" \
     "dn: CASE_INSENSITIVE\n" \
     "name: CASE_INSENSITIVE\n" \
     "objectclass: CASE_INSENSITIVE\n" \
     "\n" \
     "dn: @INDEXLIST\n" \
     "@IDXATTR: cn\n" \
     "\n" \
     "dn: @MODULES\n" \
     "@LIST: server_sort\n" \
     "\n"

struct confdb_ctx;

errno_t confdb_setup(TALLOC_CTX *mem_ctx,
                     const char *cdb_file,
                     const char *config_file,
                     const char *config_dir,
                     const char *only_section,
                     bool allow_missing_file,
                     struct confdb_ctx **_cdb);

#endif /* CONFDB_SETUP_H_ */
