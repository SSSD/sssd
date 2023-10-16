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
#include "util/sss_ini.h"

struct confdb_ctx;

errno_t confdb_setup(TALLOC_CTX *mem_ctx,
                     const char *cdb_file,
                     const char *config_file,
                     const char *config_dir,
                     const char *only_section,
                     bool allow_missing_file,
                     struct confdb_ctx **_cdb);

errno_t confdb_read_ini(TALLOC_CTX *mem_ctx,
                     const char *config_file,
                     const char *config_dir,
                     bool allow_missing_config,
                     struct sss_ini **_ini);

errno_t confdb_write_ini(TALLOC_CTX *mem_ctx,
                         const struct sss_ini *ini,
                         const char *cdb_file,
                         const char *only_section,
                         bool allow_missing_content,
                         struct confdb_ctx **_cdb);

#endif /* CONFDB_SETUP_H_ */
