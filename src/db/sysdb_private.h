
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

#define SYSDB_VERSION_0_13 "0.13"
#define SYSDB_VERSION_0_12 "0.12"
#define SYSDB_VERSION_0_11 "0.11"
#define SYSDB_VERSION_0_10 "0.10"
#define SYSDB_VERSION_0_9 "0.9"
#define SYSDB_VERSION_0_8 "0.8"
#define SYSDB_VERSION_0_7 "0.7"
#define SYSDB_VERSION_0_6 "0.6"
#define SYSDB_VERSION_0_5 "0.5"
#define SYSDB_VERSION_0_4 "0.4"
#define SYSDB_VERSION_0_3 "0.3"
#define SYSDB_VERSION_0_2 "0.2"
#define SYSDB_VERSION_0_1 "0.1"

#define SYSDB_VERSION SYSDB_VERSION_0_13

#define SYSDB_BASE_LDIF \
     "dn: @ATTRIBUTES\n" \
     "userPrincipalName: CASE_INSENSITIVE\n" \
     "cn: CASE_INSENSITIVE\n" \
     "dc: CASE_INSENSITIVE\n" \
     "dn: CASE_INSENSITIVE\n" \
     "originalDN: CASE_INSENSITIVE\n" \
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
     "@IDXATTR: dataExpireTimestamp\n" \
     "@IDXATTR: originalDN\n" \
     "@IDXATTR: nameAlias\n" \
     "@IDXATTR: servicePort\n" \
     "@IDXATTR: serviceProtocol\n" \
     "@IDXATTR: sudoUser\n" \
     "@IDXATTR: sshKnownHostsExpire\n" \
     "@IDXONE: 1\n" \
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

/* Internal utility functions */
int sysdb_get_db_file(TALLOC_CTX *mem_ctx,
                      const char *provider, const char *name,
                      const char *base_path, char **_ldb_file);
errno_t sysdb_ldb_connect(TALLOC_CTX *mem_ctx, const char *filename,
                          struct ldb_context **_ldb);
int sysdb_domain_init_internal(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               const char *db_path,
                               bool allow_upgrade,
                               struct sysdb_ctx **_ctx);

/* Upgrade routines */
int sysdb_upgrade_01(struct ldb_context *ldb, const char **ver);
int sysdb_check_upgrade_02(struct sss_domain_info *domains,
                           const char *db_path);
int sysdb_upgrade_03(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_04(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_05(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_06(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_07(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_08(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_09(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_10(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_11(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_12(struct sysdb_ctx *sysdb, const char **ver);

int add_string(struct ldb_message *msg, int flags,
               const char *attr, const char *value);
int add_ulong(struct ldb_message *msg, int flags,
              const char *attr, unsigned long value);
#endif /* __INT_SYS_DB_H__ */
