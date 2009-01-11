/*
   SSSD

   NSS LDB Header

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


#include "nss/nss_ldb.h"

struct nss_ldb_ctx {
    struct ldb_context *ldb;
    const char *ldb_file;
};

struct confdb_ctx;

typedef void (*nss_ldb_callback_t)(void *, int, struct ldb_result *);

int nss_ldb_init(TALLOC_CTX *mem_ctx,
                 struct event_context *ev,
                 struct confdb_ctx *cdb,
                 struct nss_ldb_ctx **nlctx);

int nss_ldb_getpwnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     const char *domain,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_getpwuid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     const char *domain,
                     uint64_t uid,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_enumpwent(TALLOC_CTX *mem_ctx,
                      struct event_context *ev,
                      struct nss_ldb_ctx *ctx,
                      nss_ldb_callback_t fn, void *ptr);

int nss_ldb_getgrnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     const char *domain,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_getgrgid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     const char *domain,
                     uint64_t gid,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_enumgrent(TALLOC_CTX *mem_ctx,
                      struct event_context *ev,
                      struct nss_ldb_ctx *ctx,
                      nss_ldb_callback_t fn, void *ptr);

int nss_ldb_initgroups(TALLOC_CTX *mem_ctx,
                       struct event_context *ev,
                       struct nss_ldb_ctx *ctx,
                       const char *domain,
                       const char *name,
                       nss_ldb_callback_t fn, void *ptr);

