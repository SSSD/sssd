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

#include "confdb/confdb.h"
#include <tevent.h>

#define SYSDB_CONF_SECTION "config/sysdb"
#define SYSDB_FILE "sssd.ldb"

#define SYSDB_BASE "cn=sysdb"
#define SYSDB_DOM_BASE "cn=%s,cn=sysdb"
#define SYSDB_TMPL_USER_BASE "cn=users,cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_GROUP_BASE "cn=groups,cn=%s,"SYSDB_BASE

#define SYSDB_USER_CLASS "user"
#define SYSDB_GROUP_CLASS "group"

#define SYSDB_NAME "name"

#define SYSDB_NEXTID "nextID"
#define SYSDB_UIDNUM "uidNumber"
#define SYSDB_GIDNUM "gidNumber"
#define SYSDB_CREATE_TIME "createTimestamp"

#define SYSDB_PWD "userPassword"
#define SYSDB_FULLNAME "fullName"
#define SYSDB_HOMEDIR "homeDirectory"
#define SYSDB_SHELL "loginShell"
#define SYSDB_MEMBEROF "memberOf"
#define SYSDB_DISABLED "disabled"

#define SYSDB_MEMBER "member"
#define SYSDB_LEGACY_MEMBER "memberUid"

#define SYSDB_DEFAULTGROUP "defaultGroup"
#define SYSDB_GECOS "gecos"
#define SYSDB_LOCALE "locale"
#define SYSDB_KEYBOARD "keyboard"
#define SYSDB_SESSION "session"
#define SYSDB_LAST_LOGIN "lastLogin"
#define SYSDB_USERPIC "userPicture"

#define SYSDB_LAST_UPDATE "lastUpdate"

#define SYSDB_CACHEDPWD "cachedPassword"

#define SYSDB_ORIG_DN "originalDN"
#define SYSDB_UUID "uniqueID"
#define SYSDB_UPN "UserPrincipalName"

#define SYSDB_NEXTID_FILTER "("SYSDB_NEXTID"=*)"

#define SYSDB_UC "objectclass="SYSDB_USER_CLASS
#define SYSDB_GC "objectclass="SYSDB_GROUP_CLASS
#define SYSDB_MPGC "|("SYSDB_UC")("SYSDB_GC")"

#define SYSDB_PWNAM_FILTER "(&("SYSDB_UC")("SYSDB_NAME"=%s))"
#define SYSDB_PWUID_FILTER "(&("SYSDB_UC")("SYSDB_UIDNUM"=%lu))"
#define SYSDB_PWENT_FILTER "("SYSDB_UC")"

#define SYSDB_GRNAM_FILTER "(&("SYSDB_GC")("SYSDB_NAME"=%s))"
#define SYSDB_GRNA2_FILTER "(&("SYSDB_UC")("SYSDB_MEMBEROF"=%s))"
#define SYSDB_GRGID_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRENT_FILTER "("SYSDB_GC")"
#define SYSDB_GRNAM_MPG_FILTER "(&("SYSDB_MPGC")("SYSDB_NAME"=%s))"
#define SYSDB_GRGID_MPG_FILTER "(&("SYSDB_MPGC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRENT_MPG_FILTER "("SYSDB_MPGC")"

#define SYSDB_INITGR_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=*))"

#define SYSDB_INITGR_LEGACY_FILTER "(&("SYSDB_GC")("SYSDB_LEGACY_MEMBER"=%s))"

#define SYSDB_GETCACHED_FILTER "(&"SYSDB_UC")("SYSDB_LAST_LOGIN">=%lu))"

#define SYSDB_PW_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, \
                        SYSDB_GIDNUM, SYSDB_GECOS, \
                        SYSDB_HOMEDIR, SYSDB_SHELL, \
                        SYSDB_LAST_UPDATE, \
                        "objectClass", \
                        NULL}
#define SYSDB_USER_ATTRS {SYSDB_DEFAULTGROUP, \
                          SYSDB_GECOS, \
                          SYSDB_HOMEDIR, \
                          SYSDB_SHELL, \
                          SYSDB_FULLNAME, \
                          SYSDB_LOCALE, \
                          SYSDB_KEYBOARD, \
                          SYSDB_SESSION, \
                          SYSDB_LAST_LOGIN, \
                          SYSDB_USERPIC, \
                          SYSDB_LAST_UPDATE, \
                          NULL}
#define SYSDB_GRSRC_ATTRS {SYSDB_NAME, SYSDB_GIDNUM, \
                           SYSDB_LAST_UPDATE, SYSDB_LEGACY_MEMBER, \
                           "objectClass", \
                           NULL}
#define SYSDB_GRPW_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, \
                          SYSDB_LAST_UPDATE, \
                          "objectClass", \
                          NULL}

#define SYSDB_INITGR_ATTR "memberof"
#define SYSDB_INITGR_ATTRS {SYSDB_GIDNUM, SYSDB_LAST_UPDATE, \
                            "objectClass", \
                            NULL}

#define SYSDB_TMPL_USER SYSDB_NAME"=%s,"SYSDB_TMPL_USER_BASE
#define SYSDB_TMPL_GROUP SYSDB_NAME"=%s,"SYSDB_TMPL_GROUP_BASE

#define SYSDB_MOD_ADD LDB_FLAG_MOD_ADD
#define SYSDB_MOD_DEL LDB_FLAG_MOD_DELETE
#define SYSDB_MOD_REP LDB_FLAG_MOD_REPLACE

struct confdb_ctx;
struct sysdb_ctx;
struct sysdb_handle;

struct sysdb_attrs {
    int num;
    struct ldb_message_element *a;
};

/* sysdb_attrs helper functions */
struct sysdb_attrs *sysdb_new_attrs(TALLOC_CTX *memctx);

/* values are copied in the structure, allocated on "attrs" */
int sysdb_attrs_add_val(struct sysdb_attrs *attrs,
                        const char *name, const struct ldb_val *val);
int sysdb_attrs_add_string(struct sysdb_attrs *attrs,
                           const char *name, const char *str);
int sysdb_attrs_add_long(struct sysdb_attrs *attrs,
                         const char *name, long value);
int sysdb_attrs_add_uint32(struct sysdb_attrs *attrs,
                           const char *name, uint32_t value);
int sysdb_attrs_add_time_t(struct sysdb_attrs *attrs,
                           const char *name, time_t value);
int sysdb_attrs_get_el(struct sysdb_attrs *attrs, const char *name,
                       struct ldb_message_element **el);

/* convert an ldb error into an errno error */
int sysdb_error_to_errno(int ldberr);

/* DNs related helper functions */
struct ldb_dn *sysdb_user_dn(struct sysdb_ctx *ctx, void *memctx,
                             const char *domain, const char *name);
struct ldb_dn *sysdb_group_dn(struct sysdb_ctx *ctx, void *memctx,
                              const char *domain, const char *name);
struct ldb_dn *sysdb_domain_dn(struct sysdb_ctx *ctx, void *memctx,
                               const char *domain);

/* function to start and finish a transaction
 * sysdb_transaction_send() will queue a request for a transaction
 * when it is done it will call the tevent_req callback, which must
 * retrieve the transaction handle using sysdb_transaction_recv()
 *
 * A transaction must be completed either by sending a commit:
 * sysdb_transaction_commit_send()/sysdb_transaction_commit_recv()
 * or by freeing the transaction handle (this will implicitly cause
 * a transaction cancelation).
 *
 * Transactions are serialized, no other transaction or operation can be
 * performed while a transaction is active. Multiple transaction request
 * are queued internally and served in order.
 */

struct tevent_req *sysdb_transaction_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_ctx *ctx);
int sysdb_transaction_recv(struct tevent_req *req, TALLOC_CTX *memctx,
                           struct sysdb_handle **handle);

struct tevent_req *sysdb_transaction_commit_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_handle *handle);
int sysdb_transaction_commit_recv(struct tevent_req *req);


/* default transaction commit receive function.
 * This function does not use the request state so it is safe to use
 * from any caller */
void sysdb_transaction_complete(struct tevent_req *subreq);


/* Sysdb initialization.
 * call this function *only* once to initialize the database and get
 * the sysdb ctx */
int sysdb_init(TALLOC_CTX *mem_ctx,
               struct tevent_context *ev,
               struct confdb_ctx *cdb,
               const char *alt_db_path,
               struct sysdb_ctx **dbctx);

/* FIXME: REMOVE */
typedef void (*sysdb_callback_t)(void *, int, struct ldb_result *);

/* functions to retrieve information from sysdb
 * These functions automatically starts an operation
 * therefore they cannot be called within a transaction */
int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr);

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   uid_t uid,
                   sysdb_callback_t fn, void *ptr);

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    const char *expression,
                    sysdb_callback_t fn, void *ptr);

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   sysdb_callback_t fn, void *ptr);

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sysdb_ctx *ctx,
                   struct sss_domain_info *domain,
                   gid_t gid,
                   sysdb_callback_t fn, void *ptr);

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sysdb_ctx *ctx,
                    struct sss_domain_info *domain,
                    sysdb_callback_t fn, void *ptr);

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sysdb_ctx *ctx,
                     struct sss_domain_info *domain,
                     const char *name,
                     sysdb_callback_t fn, void *ptr);

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *ctx,
                        struct sss_domain_info *domain,
                        const char *name,
                        const char **attributes,
                        sysdb_callback_t fn, void *ptr);


/* functions that modify the databse
 * they have to be called within a transaction
 * See sysdb_transaction_send()/_recv() */

/* Delete Entry */
struct tevent_req *sysdb_delete_entry_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_handle *handle,
                                           struct ldb_dn *dn,
                                           bool ignore_not_found);
int sysdb_delete_entry_recv(struct tevent_req *req);

/* Search Entry */
struct tevent_req *sysdb_search_entry_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sysdb_handle *handle,
                                           struct ldb_dn *base_dn,
                                           int scope,
                                           const char *filter,
                                           const char **attrs);
int sysdb_search_entry_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct ldb_message **msg);

/* Search User (by uid or name) */
struct tevent_req *sysdb_search_user_by_name_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_ctx *sysdb,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  const char *name,
                                                  const char **attrs);
struct tevent_req *sysdb_search_user_by_uid_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_ctx *sysdb,
                                                 struct sysdb_handle *handle,
                                                 struct sss_domain_info *domain,
                                                 uid_t uid,
                                                 const char **attrs);
int sysdb_search_user_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           struct ldb_message **msg);

/* Delete User by uid */
struct tevent_req *sysdb_delete_user_by_uid_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct sysdb_handle *handle,
                                                 struct sss_domain_info *domain,
                                                 uid_t uid,
                                                 bool ignore_not_found);
int sysdb_delete_user_by_uid_recv(struct tevent_req *req);

/* Search Group (gy gid or name) */
struct tevent_req *sysdb_search_group_by_name_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct sysdb_ctx *sysdb,
                                                   struct sysdb_handle *handle,
                                                   struct sss_domain_info *domain,
                                                   const char *name,
                                                   const char **attrs);
struct tevent_req *sysdb_search_group_by_gid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_ctx *sysdb,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  gid_t gid,
                                                  const char **attrs);
int sysdb_search_group_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct ldb_message **msg);

/* Delete group by gid */
struct tevent_req *sysdb_delete_group_by_gid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  gid_t gid,
                                                  bool ignore_not_found);
int sysdb_delete_group_by_gid_recv(struct tevent_req *req);

/* Replace entry attrs */
struct tevent_req *sysdb_set_entry_attr_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct ldb_dn *entry_dn,
                                             struct sysdb_attrs *attrs,
                                             int mod_op);
int sysdb_set_entry_attr_recv(struct tevent_req *req);

/* Replace user attrs */
struct tevent_req *sysdb_set_user_attr_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sysdb_handle *handle,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            struct sysdb_attrs *attrs,
                                            int mod_op);
int sysdb_set_user_attr_recv(struct tevent_req *req);

/* Replace group attrs */
struct tevent_req *sysdb_set_group_attr_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             struct sysdb_attrs *attrs,
                                             int mod_op);
int sysdb_set_group_attr_recv(struct tevent_req *req);

/* Allocate a new id */
struct tevent_req *sysdb_get_new_id_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain);
int sysdb_get_new_id_recv(struct tevent_req *req, uint32_t *id);

/* Add user (only basic attrs and w/o checks) */
struct tevent_req *sysdb_add_basic_user_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             uid_t uid, gid_t gid,
                                             const char *gecos,
                                             const char *homedir,
                                             const char *shell);
int sysdb_add_basic_user_recv(struct tevent_req *req);

/* Add user (all checks) */
struct tevent_req *sysdb_add_user_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sysdb_handle *handle,
                                       struct sss_domain_info *domain,
                                       const char *name,
                                       uid_t uid, gid_t gid,
                                       const char *gecos,
                                       const char *homedir,
                                       const char *shell,
                                       struct sysdb_attrs *attrs);
int sysdb_add_user_recv(struct tevent_req *req);

/* Add group (only basic attrs and w/o checks) */
struct tevent_req *sysdb_add_basic_group_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct sysdb_handle *handle,
                                              struct sss_domain_info *domain,
                                              const char *name, gid_t gid);
int sysdb_add_basic_group_recv(struct tevent_req *req);

/* Add group (all checks) */
struct tevent_req *sysdb_add_group_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sysdb_handle *handle,
                                        struct sss_domain_info *domain,
                                        const char *name, gid_t gid,
                                        struct sysdb_attrs *attrs);
int sysdb_add_group_recv(struct tevent_req *req);

/* mod_op must be either LDB_FLAG_MOD_ADD or LDB_FLAG_MOD_DELETE */
struct tevent_req *sysdb_mod_group_member_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct ldb_dn *member_dn,
                                               struct ldb_dn *group_dn,
                                               int mod_op);
int sysdb_mod_group_member_recv(struct tevent_req *req);

int sysdb_set_group_gid(struct sysdb_handle *handle,
                        struct sss_domain_info *domain,
                        const char *name, gid_t gid,
                        sysdb_callback_t fn, void *pvt);

struct tevent_req *sysdb_store_user_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sysdb_handle *handle,
                                         struct sss_domain_info *domain,
                                         const char *name,
                                         const char *pwd,
                                         uid_t uid, gid_t gid,
                                         const char *gecos,
                                         const char *homedir,
                                         const char *shell);
int sysdb_store_user_recv(struct tevent_req *req);

struct tevent_req *sysdb_store_group_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sysdb_handle *handle,
                                          struct sss_domain_info *domain,
                                          const char *name,
                                          gid_t gid,
                                          const char **members);
int sysdb_store_group_recv(struct tevent_req *req);

struct tevent_req *sysdb_add_group_member_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct sysdb_handle *handle,
                                               struct sss_domain_info *domain,
                                               const char *group,
                                               const char *member);
int sysdb_add_group_member_recv(struct tevent_req *req);

struct tevent_req *sysdb_remove_group_member_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct sysdb_handle *handle,
                                                  struct sss_domain_info *domain,
                                                  const char *group,
                                                  const char *member);
int sysdb_remove_group_member_recv(struct tevent_req *req);

/* Password caching function.
 * If you are in a transaction ignore sysdb and pass in the handle.
 * If you are not in a transaction pass NULL in handle and provide sysdb,
 * in this case a transaction will be automatically started and the
 * function will be completely wrapped in it's own sysdb transaction */
struct tevent_req *sysdb_cache_password_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sysdb_ctx *sysdb,
                                             struct sysdb_handle *handle,
                                             struct sss_domain_info *domain,
                                             const char *username,
                                             const char *password);
int sysdb_cache_password_recv(struct tevent_req *req);

#endif /* __SYS_DB_H__ */
