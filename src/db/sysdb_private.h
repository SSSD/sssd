
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

#define SYSDB_VERSION_0_17 "0.17"
#define SYSDB_VERSION_0_16 "0.16"
#define SYSDB_VERSION_0_15 "0.15"
#define SYSDB_VERSION_0_14 "0.14"
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

#define SYSDB_VERSION SYSDB_VERSION_0_17

#define SYSDB_BASE_LDIF \
     "dn: @ATTRIBUTES\n" \
     "userPrincipalName: CASE_INSENSITIVE\n" \
     "canonicalUserPrincipalName: CASE_INSENSITIVE\n" \
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
     "@IDXATTR: objectSIDString\n" \
     "@IDXONE: 1\n" \
     "\n" \
     "dn: @MODULES\n" \
     "@LIST: asq,memberof\n" \
     "\n" \
     "dn: cn=sysdb\n" \
     "cn: sysdb\n" \
     "version: " SYSDB_VERSION "\n" \
     "description: base object\n" \
     "\n" \
     "dn: cn=ranges,cn=sysdb\n" \
     "cn: ranges\n" \
     "\n"

/* The timestamp cache has its own versioning */
#define SYSDB_TS_VERSION_0_1 "0.1"

#define SYSDB_TS_VERSION SYSDB_TS_VERSION_0_1

#define SYSDB_TS_BASE_LDIF \
     "dn: @ATTRIBUTES\n" \
     "dn: CASE_INSENSITIVE\n" \
     "\n" \
     "dn: @INDEXLIST\n" \
     "@IDXATTR: lastUpdate\n" \
     "@IDXATTR: dataExpireTimestamp\n" \
     "@IDXONE: 1\n" \
     "\n" \
     "dn: cn=sysdb\n" \
     "cn: sysdb\n" \
     "version: " SYSDB_TS_VERSION "\n" \
     "description: base object\n" \
     "\n" \

#include "db/sysdb.h"

struct sysdb_ctx {
    struct ldb_context *ldb;
    char *ldb_file;

    struct ldb_context *ldb_ts;
    char *ldb_ts_file;

    int transaction_nesting;
};

/* Internal utility functions */
int sysdb_get_db_file(TALLOC_CTX *mem_ctx,
                      const char *provider,
                      const char *name,
                      const char *base_path,
                      char **_ldb_file,
                      char **_ts_file);
errno_t sysdb_ldb_connect(TALLOC_CTX *mem_ctx,
                          const char *filename,
                          int flags,
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
int sysdb_upgrade_10(struct sysdb_ctx *sysdb, struct sss_domain_info *domain,
                     const char **ver);
int sysdb_upgrade_11(struct sysdb_ctx *sysdb, struct sss_domain_info *domain,
                     const char **ver);
int sysdb_upgrade_12(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_13(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_14(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_15(struct sysdb_ctx *sysdb, const char **ver);
int sysdb_upgrade_16(struct sysdb_ctx *sysdb, const char **ver);

int sysdb_add_string(struct ldb_message *msg,
                     const char *attr, const char *value);
int sysdb_replace_string(struct ldb_message *msg,
                         const char *attr, const char *value);
int sysdb_delete_string(struct ldb_message *msg,
                        const char *attr, const char *value);
int sysdb_add_ulong(struct ldb_message *msg,
                    const char *attr, unsigned long value);
int sysdb_replace_ulong(struct ldb_message *msg,
                        const char *attr, unsigned long value);
int sysdb_delete_ulong(struct ldb_message *msg,
                       const char *attr, unsigned long value);

/* The utility function to create a subdomain sss_domain_info object is handy
 * for unit tests, so it should be available in a header, but not a public util
 * one, because the only interface for the deamon itself should be adding
 * the sysdb domain object and calling sysdb_update_subdomains()
 */
struct sss_domain_info *new_subdomain(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *parent,
                                      const char *name,
                                      const char *realm,
                                      const char *flat_name,
                                      const char *id,
                                      bool mpg,
                                      bool enumerate,
                                      const char *forest,
                                      uint32_t trust_direction);

/* Helper functions to deal with the timestamp cache should not be used
 * outside the sysdb itself. The timestamp cache should be completely
 * opaque to the sysdb consumers
 */

/* Returns true if the 'dn' parameter is a user or a group DN, because
 * at the moment, the timestamps cache only handles users and groups.
 * Returns false otherwise.
 */
bool is_ts_ldb_dn(struct ldb_dn *dn);

/* Given a ldb_result found in the timestamp cache, merge in the
 * corresponding full attributes from the sysdb cache. The new
 * attributes are allocated on the messages in the ldb_result.
 */
errno_t sysdb_merge_res_ts_attrs(struct sysdb_ctx *ctx,
                                 struct ldb_result *res,
                                 const char *attrs[]);

/* Given an array of ldb_message structures found in the timestamp cache,
 * merge in the corresponding full attributes from the sysdb cache. The
 * new attributes are allocated atop the ldb messages.
 */
errno_t sysdb_merge_msg_list_ts_attrs(struct sysdb_ctx *ctx,
                                      size_t msgs_count,
                                      struct ldb_message **msgs,
                                      const char *attrs[]);

/* Merge two sets of ldb_result structures. */
struct ldb_result *sss_merge_ldb_results(struct ldb_result *res,
                                         struct ldb_result *subres);

/* Search Entry in the timestamp cache */
int sysdb_search_ts_entry(TALLOC_CTX *mem_ctx,
                          struct sysdb_ctx *sysdb,
                          struct ldb_dn *base_dn,
                          enum ldb_scope scope,
                          const char *filter,
                          const char **attrs,
                          size_t *_msgs_count,
                          struct ldb_message ***_msgs);

int sysdb_search_ts_users(TALLOC_CTX *mem_ctx,
                          struct sss_domain_info *domain,
                          const char *sub_filter,
                          const char **attrs,
                          size_t *msgs_count,
                          struct ldb_message ***msgs);

int sysdb_search_ts_groups(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *sub_filter,
                           const char **attrs,
                           size_t *msgs_count,
                           struct ldb_message ***msgs);

#endif /* __INT_SYS_DB_H__ */
