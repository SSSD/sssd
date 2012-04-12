/*
    SSSD

    Proxy provider, private header file

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#ifndef __PROXY_H__
#define __PROXY_H__

#include <nss.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "db/sysdb.h"
#include "proxy.h"
#include "sss_client/nss_compat.h"
#include <dhash.h>

struct proxy_nss_ops {
    enum nss_status (*getpwnam_r)(const char *name, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getpwuid_r)(uid_t uid, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setpwent)(void);
    enum nss_status (*getpwent_r)(struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endpwent)(void);

    enum nss_status (*getgrnam_r)(const char *name, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getgrgid_r)(gid_t gid, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*setgrent)(void);
    enum nss_status (*getgrent_r)(struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*endgrent)(void);
    enum nss_status (*initgroups_dyn)(const char *user, gid_t group,
                                      long int *start, long int *size,
                                      gid_t **groups, long int limit,
                                      int *errnop);
    enum nss_status (*setnetgrent)(const char *netgroup,
                                   struct __netgrent *result);
    enum nss_status (*getnetgrent_r)(struct __netgrent *result, char *buffer,
                                     size_t buflen, int *errnop);
    enum nss_status (*endnetgrent)(struct __netgrent *result);

    /* Services */
    enum nss_status (*getservbyname_r)(const char *name,
                                        const char *protocol,
                                        struct servent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop);
    enum nss_status (*getservbyport_r)(int port, const char *protocol,
                                        struct servent *result,
                                        char *buffer, size_t buflen,
                                        int *errnop);
    enum nss_status (*setservent)(void);
    enum nss_status (*getservent_r)(struct servent *result,
                                    char *buffer, size_t buflen,
                                    int *errnop);
    enum nss_status (*endservent)(void);
};

struct authtok_conv {
    uint32_t authtok_size;
    uint8_t *authtok;

    uint32_t newauthtok_size;
    uint8_t *newauthtok;

    bool sent_old;
};

struct proxy_id_ctx {
    struct be_ctx *be;
    bool fast_alias;
    struct proxy_nss_ops ops;
    void *handle;
};

struct proxy_auth_ctx {
    struct be_ctx *be;
    char *pam_target;

    uint32_t max_children;
    uint32_t running;
    uint32_t next_id;
    hash_table_t *request_table;
    struct sbus_connection *sbus_srv;
    int timeout_ms;
};

struct proxy_child_ctx {
    struct proxy_auth_ctx *auth_ctx;
    struct be_req *be_req;
    struct pam_data *pd;

    uint32_t id;
    pid_t pid;
    bool running;

    struct sbus_connection *conn;
    struct tevent_timer *timer;

    struct tevent_req *init_req;
};

struct pc_init_ctx {
    char *command;
    pid_t pid;
    struct tevent_timer *timeout;
    struct tevent_signal *sige;
    struct proxy_child_ctx *child_ctx;
    struct sbus_connection *conn;
};

#define PROXY_CHILD_PIPE "private/proxy_child"
#define DEFAULT_BUFSIZE 4096
#define MAX_BUF_SIZE 1024*1024 /* max 1MiB */

/* From proxy_common.c */
void proxy_reply(struct be_req *req, int dp_err,
                 int error, const char *errstr);

/* From proxy_id.c */
void proxy_get_account_info(struct be_req *breq);

/* From proxy_auth.c */
void proxy_pam_handler(struct be_req *req);

/* From proxy_netgroup.c */
errno_t get_netgroup(struct proxy_id_ctx *ctx,
                     struct sysdb_ctx *sysdb,
                     struct sss_domain_info *dom,
                     const char *name);

errno_t get_serv_byname(struct proxy_id_ctx *ctx,
                        struct sysdb_ctx *sysdb,
                        struct sss_domain_info *dom,
                        const char *name,
                        const char *protocol);

errno_t
get_serv_byport(struct proxy_id_ctx *ctx,
                struct sysdb_ctx *sysdb,
                struct sss_domain_info *dom,
                const char *be_filter,
                const char *protocol);

errno_t enum_services(struct proxy_id_ctx *ctx,
                      struct sysdb_ctx *sysdb,
                      struct sss_domain_info *dom);

#endif /* __PROXY_H__ */
