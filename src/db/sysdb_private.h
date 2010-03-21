
/*
   SSSD

   Private System Database Header

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#ifndef __INT_SYS_DB_H__
#define __INT_SYS_DB_H__

#define SYSDB_VERSION_0_5 "0.5"
#define SYSDB_VERSION_0_4 "0.4"
#define SYSDB_VERSION_0_3 "0.3"
#define SYSDB_VERSION_0_2 "0.2"
#define SYSDB_VERSION_0_1 "0.1"

#define SYSDB_VERSION SYSDB_VERSION_0_5

#define SYSDB_BASE_LDIF \
     "dn: @ATTRIBUTES\n" \
     "userPrincipalName: CASE_INSENSITIVE\n" \
     "cn: CASE_INSENSITIVE\n" \
     "dc: CASE_INSENSITIVE\n" \
     "dn: CASE_INSENSITIVE\n" \
     "objectclass: CASE_INSENSITIVE\n" \
     "\n" \
     "dn: @INDEXLIST\n" \
     "@IDXATTR: cn\n" \
     "@IDXATTR: objectclass\n" \
     "@IDXATTR: member\n" \
     "@IDXATTR: memberof\n" \
     "@IDXATTR: name\n" \
     "@IDXATTR: uidNumber\n" \
     "@IDXATTR: gidNumber\n" \
     "@IDXATTR: lastUpdate\n" \
     "@IDXATTR: originalDN\n" \
     "\n" \
     "dn: @MODULES\n" \
     "@LIST: asq,memberof\n" \
     "\n" \
     "dn: cn=sysdb\n" \
     "cn: sysdb\n" \
     "version: " SYSDB_VERSION "\n" \
     "description: base object\n" \
     "\n"

#include "db/sysdb.h"

struct sysdb_ctx {
    struct sss_domain_info *domain;
    bool mpg;

    struct ldb_context *ldb;
    char *ldb_file;
};

struct sysdb_ctx_list {
    struct sysdb_ctx **dbs;
    size_t num_dbs;

    char *db_path;
};

#endif /* __INT_SYS_DB_H__ */
