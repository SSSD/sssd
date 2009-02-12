/*
   SSSD

   System Databse Header

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
#include "ldb_errors.h"

#define SYSDB_CONF_SECTION "config/sysdb"
#define SYSDB_FILE "sssd.ldb"

#define SYSDB_BASE "cn=sysdb"
#define SYSDB_TMPL_USER_BASE "cn=users,cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_GROUP_BASE "cn=groups,cn=%s,"SYSDB_BASE

#define SYSDB_PWNAM_FILTER "(&(objectclass=user)(uid=%s))"
#define SYSDB_PWUID_FILTER "(&(objectclass=user)(uidNumber=%lu))"
#define SYSDB_PWENT_FILTER "(objectclass=user)"

#define SYSDB_GRNAM_FILTER "(&(objectclass=group)(cn=%s))"
#define SYSDB_GRNA2_FILTER "(&(objectclass=user)(memberof=%s))"
#define SYSDB_GRGID_FILTER "(&(objectclass=group)(gidNumber=%lu))"
#define SYSDB_GRENT_FILTER "(objectclass=group)"

#define SYSDB_INITGR_FILTER "(&(objectclass=group)(gidNumber=*))"

#define SYSDB_PW_NAME "uid"
#define SYSDB_PW_PWD "userPassword"
#define SYSDB_PW_UIDNUM "uidNumber"
#define SYSDB_PW_GIDNUM "gidNumber"
#define SYSDB_PW_FULLNAME "fullName"
#define SYSDB_PW_HOMEDIR "homeDirectory"
#define SYSDB_PW_SHELL "loginShell"
#define SYSDB_PW_MEMBEROF "memberOf"

#define SYSDB_GR_NAME "cn"
#define SYSDB_GR_GIDNUM "gidNumber"
#define SYSDB_GR_MEMBER "member"

#define SYSDB_LAST_UPDATE "lastUpdate"

#define SYSDB_PW_ATTRS {SYSDB_PW_NAME, SYSDB_PW_UIDNUM, \
                        SYSDB_PW_GIDNUM, SYSDB_PW_FULLNAME, \
                        SYSDB_PW_HOMEDIR, SYSDB_PW_SHELL, \
                        SYSDB_LAST_UPDATE, \
                        NULL}
#define SYSDB_GRNAM_ATTRS {SYSDB_GR_NAME, SYSDB_GR_GIDNUM, \
                           SYSDB_LAST_UPDATE, \
                           NULL}
#define SYSDB_GRPW_ATTRS {SYSDB_PW_NAME, SYSDB_LAST_UPDATE, \
                          NULL}

#define SYSDB_INITGR_ATTR "memberof"
#define SYSDB_INITGR_ATTRS {SYSDB_GR_GIDNUM, SYSDB_LAST_UPDATE, \
                            NULL}

struct sysdb_ctx {
    struct ldb_context *ldb;
    const char *ldb_file;
};

struct confdb_ctx;

typedef void (*sysdb_callback_t)(void *, int, struct ldb_result *);

enum sysdb_flags {
    SYSDB_FLAG_MOD_NONE = 0,
    SYSDB_FLAG_MOD_ADD,
    SYSDB_FLAG_MOD_DELETE,
    SYSDB_FLAG_MOD_MODIFY
};

int sysdb_init(TALLOC_CTX *mem_ctx,
               struct event_context *ev,
               struct confdb_ctx *cdb,
               struct sysdb_ctx **nlctx);

int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct event_context *ev,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr);

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct event_context *ev,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   uid_t uid,
                   sysdb_callback_t fn, void *ptr);

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct event_context *ev,
                    struct sysdb_ctx *ctx,
                    sysdb_callback_t fn, void *ptr);

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct event_context *ev,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr);

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct event_context *ev,
                   struct sysdb_ctx *ctx,
                   const char *domain,
                   gid_t gid,
                   sysdb_callback_t fn, void *ptr);

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct event_context *ev,
                    struct sysdb_ctx *ctx,
                    sysdb_callback_t fn, void *ptr);

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct sysdb_ctx *ctx,
                     const char *domain,
                     const char *name,
                     sysdb_callback_t fn, void *ptr);

int sysdb_store_account_posix(TALLOC_CTX *memctx,
                              struct sysdb_ctx *sysdb,
                              const char *domain,
                              const char *name,
                              const char *pwd,
                              uid_t uid, gid_t gid,
                              const char *gecos,
                              const char *homedir,
                              const char *shell);

int sysdb_remove_account_posix(TALLOC_CTX *memctx,
                               struct sysdb_ctx *sysdb,
                               const char *domain, const char *name);

int sysdb_remove_account_posix_by_uid(TALLOC_CTX *memctx,
                                      struct sysdb_ctx *sysdb,
                                      const char *domain, uid_t uid);

int sysdb_store_group_posix(TALLOC_CTX *memctx,
                            struct sysdb_ctx *sysdb,
                            const char *domain,
                            const char *name, gid_t gid);

int sysdb_add_remove_posix_group_acct(TALLOC_CTX *mem_ctx,
                                     struct sysdb_ctx *sysdb,
                                     int flag,
                                     const char *domain,
                                     const char *group,
                                     const char *username);

/* Wrapper around adding a POSIX group to a POSIX group */
int sysdb_add_remove_posix_group_group(TALLOC_CTX *mem_ctx,
                                      struct sysdb_ctx *sysdb,
                                      int flag,
                                      const char *domain,
                                      const char *group,
                                      const char *member_group);

int sysdb_add_remove_posix_group_member(TALLOC_CTX *mem_ctx,
                                        struct sysdb_ctx *sysdb,
                                        int flag,
                                        struct ldb_dn *member_dn,
                                        struct ldb_dn *group_dn);

int sysdb_remove_group_posix(TALLOC_CTX *memctx,
                             struct sysdb_ctx *sysdb,
                             const char *domain, const char *name);

int sysdb_remove_group_posix_by_gid(TALLOC_CTX *memctx,
                                    struct sysdb_ctx *sysdb,
                                    const char *domain, gid_t gid);
#endif /* __SYS_DB_H__ */
