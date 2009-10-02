/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2009 Red Hat

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

#ifndef __SSS_OPS_H__
#define __SSS_OPS_H__

#include "tools/tools_util.h"
#include <stdbool.h>

#define DO_LOCK     1
#define DO_UNLOCK   2

struct ops_ctx {
    struct sss_domain_info *domain;

    char *name;
    uid_t uid;
    gid_t gid;
    char *gecos;
    char *home;
    char *shell;
    int   lock;

    char **addgroups;
    char **rmgroups;
};

/* default values for add operations */
int useradd_defaults(TALLOC_CTX *mem_ctx,
                     struct confdb_ctx *confdb,
                     struct ops_ctx *data,
                     const char *gecos,
                     const char *homedir,
                     const char *shell);

/* synchronous operations */
int useradd(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data);
int userdel(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data);
int usermod(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data);

int groupadd(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data);
int groupdel(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data);
int groupmod(TALLOC_CTX *mem_ctx,
            struct tevent_context *ev,
            struct sysdb_ctx *sysdb,
            struct sysdb_handle *handle,
            struct ops_ctx *data);

void start_transaction(struct tools_ctx *tctx);
void end_transaction(struct tools_ctx *tctx);

int sysdb_getpwnam_sync(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sysdb_ctx *sysdb,
                        const char *name,
                        struct sss_domain_info *domain,
                        struct ops_ctx **out);

int sysdb_getgrnam_sync(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sysdb_ctx *sysdb,
                        const char *name,
                        struct sss_domain_info *domain,
                        struct ops_ctx **out);

#endif /* __SSS_OPS_H__ */

