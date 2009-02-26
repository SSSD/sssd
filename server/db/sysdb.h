/*
   SSSD

   System Database Header

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

#ifndef __SYS_DB_H__
#define __SYS_DB_H__

#include "ldb.h"

#define SYSDB_CONF_SECTION "config/sysdb"
#define SYSDB_FILE "sssd.ldb"

#define SYSDB_BASE "cn=sysdb"
#define SYSDB_DOM_BASE "cn=%s,cn=sysdb"
#define SYSDB_TMPL_USER_BASE "cn=users,cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_GROUP_BASE "cn=groups,cn=%s,"SYSDB_BASE

#define SYSDB_PWNAM_FILTER "(&(objectclass=user)(uid=%s))"
#define SYSDB_PWUID_FILTER "(&(objectclass=user)(uidNumber=%lu))"
#define SYSDB_PWENT_FILTER "(objectclass=user)"

#define SYSDB_GRNAM_FILTER "(&(objectclass=group)(gid=%s))"
#define SYSDB_GRNA2_FILTER "(&(objectclass=user)(memberof=%s))"
#define SYSDB_GRGID_FILTER "(&(objectclass=group)(gidNumber=%lu))"
#define SYSDB_GRENT_FILTER "(objectclass=group)"

#define SYSDB_INITGR_FILTER "(&(objectclass=group)(gidNumber=*))"

#define SYSDB_INITGR_LEGACY_FILTER "(&(objectclass=group)(memberUid=%s))"

#define SYSDB_PW_NAME "uid"
#define SYSDB_PW_PWD "userPassword"
#define SYSDB_PW_UIDNUM "uidNumber"
#define SYSDB_PW_GIDNUM "gidNumber"
#define SYSDB_PW_FULLNAME "fullName"
#define SYSDB_PW_HOMEDIR "homeDirectory"
#define SYSDB_PW_SHELL "loginShell"
#define SYSDB_PW_MEMBEROF "memberOf"

#define SYSDB_GR_NAME "gid"
#define SYSDB_GR_GIDNUM "gidNumber"
#define SYSDB_GR_MEMBER "member"
#define SYSDB_LEGACY_MEMBER "memberUid"

#define SYSDB_LAST_UPDATE "lastUpdate"

#define SYSDB_PW_ATTRS {SYSDB_PW_NAME, SYSDB_PW_UIDNUM, \
                        SYSDB_PW_GIDNUM, SYSDB_PW_FULLNAME, \
                        SYSDB_PW_HOMEDIR, SYSDB_PW_SHELL, \
                        SYSDB_LAST_UPDATE, \
                        NULL}
#define SYSDB_GRNAM_ATTRS {SYSDB_GR_NAME, SYSDB_GR_GIDNUM, \
                           SYSDB_LAST_UPDATE, SYSDB_LEGACY_MEMBER, \
                           NULL}
#define SYSDB_GRPW_ATTRS {SYSDB_PW_NAME, SYSDB_LAST_UPDATE, \
                          NULL}

#define SYSDB_INITGR_ATTR "memberof"
#define SYSDB_INITGR_ATTRS {SYSDB_GR_GIDNUM, SYSDB_LAST_UPDATE, \
                            NULL}

struct confdb_ctx;
struct sysdb_ctx;

typedef void (*sysdb_callback_t)(void *, int, struct ldb_result *);

int sysdb_init(TALLOC_CTX *mem_ctx,
               struct tevent_context *ev,
               struct confdb_ctx *cdb,
               const char *alt_db_path,
               struct sysdb_ctx **dbctx);

int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   const char *name,
                   bool legacy,
                   sysdb_callback_t fn, void *ptr);

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   uid_t uid,
                   bool legacy,
                   sysdb_callback_t fn, void *ptr);

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    const char *domain,
                    bool legacy,
                    sysdb_callback_t fn, void *ptr);

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   const char *name,
                   bool legacy,
                   sysdb_callback_t fn, void *ptr);

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   gid_t gid,
                   bool legacy,
                   sysdb_callback_t fn, void *ptr);

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    const char *domain,
                    bool legacy,
                    sysdb_callback_t fn, void *ptr);

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *ctx,
                     const char *domain,
                     const char *name,
                     bool legacy,
                     sysdb_callback_t fn, void *ptr);


/* the following are all SYNCHRONOUS calls
 * TODO: make these asynchronous */

int sysdb_add_group_member(TALLOC_CTX *mem_ctx,
                           struct sysdb_ctx *sysdb,
                           struct ldb_dn *member_dn,
                           struct ldb_dn *group_dn);

int sysdb_remove_group_member(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              struct ldb_dn *member_dn,
                              struct ldb_dn *group_dn);

int sysdb_delete_user(TALLOC_CTX *memctx,
                      struct sysdb_ctx *sysdb,
                      const char *domain, const char *name);

int sysdb_delete_user_by_uid(TALLOC_CTX *memctx,
                             struct sysdb_ctx *sysdb,
                             const char *domain, uid_t uid);

int sysdb_add_user_to_group(TALLOC_CTX *mem_ctx,
                            struct sysdb_ctx *sysdb,
                            const char *domain,
                            const char *group,
                            const char *username);

int sysdb_remove_user_from_group(TALLOC_CTX *mem_ctx,
                                 struct sysdb_ctx *sysdb,
                                 const char *domain,
                                 const char *group,
                                 const char *username);

int sysdb_delete_group(TALLOC_CTX *memctx,
                       struct sysdb_ctx *sysdb,
                       const char *domain, const char *name);

int sysdb_delete_group_by_gid(TALLOC_CTX *memctx,
                              struct sysdb_ctx *sysdb,
                              const char *domain, gid_t gid);

/* legacy synchronous functions for proxy providers */

int sysdb_legacy_store_user(TALLOC_CTX *memctx,
                            struct sysdb_ctx *sysdb,
                            const char *domain,
                            const char *name, const char *pwd,
                            uid_t uid, gid_t gid, const char *gecos,
                            const char *homedir, const char *shell);

int sysdb_legacy_store_group(TALLOC_CTX *memctx,
                             struct sysdb_ctx *sysdb,
                             const char *domain,
                             const char *name, gid_t gid,
                             char **members);

#endif /* __SYS_DB_H__ */
