/*
   SSSD

   Async resolver header

   Authors:
        Martin Nagy <mnagy@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2009

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

#ifndef __ASYNC_RESOLV_H__
#define __ASYNC_RESOLV_H__

#include <netdb.h>
#include <ares.h>

#include "config.h"
#include "confdb/confdb.h"

#ifndef RESOLV_DEFAULT_TTL
#define RESOLV_DEFAULT_TTL 7200
#endif  /* RESOLV_DEFAULT_TTL */

#ifndef RESOLV_DEFAULT_SRV_TTL
#define RESOLV_DEFAULT_SRV_TTL 14400
#endif  /* RESOLV_DEFAULT_SRV_TTL */

#include "util/util.h"

/*
 * An opaque structure which holds context for a module using the async
 * resolver. Is should be used as a "local-global" variable - in sssd,
 * every backend should have its own.

 * Do NOT free the context until there are any pending resolv_ calls
 */
struct resolv_ctx;

int resolv_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev_ctx,
                int timeout, int ares_timeout, bool use_search_list,
                struct resolv_ctx **ctxp);

void resolv_reread_configuration(struct resolv_ctx *ctx);

const char *resolv_strerror(int ares_code);

struct resolv_hostent *
resolv_copy_hostent(TALLOC_CTX *mem_ctx, struct hostent *src);

struct resolv_hostent *
resolv_copy_hostent_ares(TALLOC_CTX *mem_ctx, struct hostent *src,
                         int family, void *ares_ttl_data,
                         int num_ares_ttl_data);

/** Get host by name **/
enum host_database {
    DB_FILES,
    DB_DNS,

    DB_SENTINEL
};

enum restrict_family {
    IPV4_ONLY,
    IPV4_FIRST,
    IPV6_ONLY,
    IPV6_FIRST
};

/* If resolv_hostent->family is AF_INET, then ipaddr points to
 * struct in_addr, else if family is AF_INET6, ipaddr points to
 * struct in6_addr
 */
struct resolv_addr {
    uint8_t *ipaddr;
    int ttl;
};

struct resolv_hostent {
    char  *name;            /* official name of host */
    char **aliases;         /* alias list */
    int    family;          /* host address type */

    struct resolv_addr **addr_list; /* list of addresses */
};

/* The default database order */
extern enum host_database default_host_dbs[];

struct tevent_req *resolv_gethostbyname_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct resolv_ctx *ctx,
                                            const char *name,
                                            enum restrict_family family_order,
                                            enum host_database *db);

int resolv_gethostbyname_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                              int *status, int *timeouts,
                              struct resolv_hostent **rhostent);

struct resolv_hostport {
    const char *host;
    int port;
};

struct resolv_hostport_addr {
    struct resolv_hostport origin;
    struct resolv_hostent *reply;
};

/* Resolves a list of resolv_hostport tuples into a list of
 * resolv_hostport_addr. Any unresolvable addresses are skipped.
 *
 * Optionally takes a limit argument and stops after the request
 * had resolved addresses up to the limit.
 */
struct tevent_req *resolv_hostport_list_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct resolv_ctx *ctx,
                                             struct resolv_hostport *hostport_list,
                                             size_t list_size,
                                             size_t limit,
                                             enum restrict_family family_order,
                                             enum host_database *db);

int resolv_hostport_list_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              size_t *_rhp_len,
                              struct resolv_hostport_addr ***_rhp_addrs);

char *
resolv_get_string_address_index(TALLOC_CTX *mem_ctx,
                                struct resolv_hostent *hostent,
                                unsigned int addrindex);

char *
resolv_get_string_ptr_address(TALLOC_CTX *mem_ctx,
                              int family, uint8_t *address);

#define resolv_get_string_address(mem_ctx, hostent) \
        resolv_get_string_address_index(mem_ctx, hostent, 0)

struct sockaddr *
resolv_get_sockaddr_address_index(TALLOC_CTX *mem_ctx,
                                  struct resolv_hostent *hostent,
                                  int port, int addrindex,
                                  socklen_t *sockaddr_len);

#define resolv_get_sockaddr_address(mem_ctx, rhostent, port, sockaddr_len) \
        resolv_get_sockaddr_address_index(mem_ctx, rhostent, port, 0, sockaddr_len)

/** Get SRV record **/
struct tevent_req *resolv_getsrv_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct resolv_ctx *ctx,
                                      const char *query);

int resolv_getsrv_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       int *status,
                       int *timeouts,
                       struct ares_srv_reply **reply_list,
                       uint32_t *ttl);

/* This is an implementation of section "Usage rules" of RFC 2782 */
int
resolv_sort_srv_reply(struct ares_srv_reply **reply);

/** Get TXT record **/
struct tevent_req *resolv_gettxt_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct resolv_ctx *ctx,
                                      const char *query);

int resolv_gettxt_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       int *status,
                       int *timeouts,
                       struct ares_txt_reply **reply_list);

/** Utils **/

struct tevent_req *
resolv_get_domain_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct resolv_ctx *resolv_ctx,
                        const char *hostname,
                        enum host_database *host_dbs,
                        enum restrict_family family_order);

errno_t resolv_get_domain_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               char **_dns_domain);

struct tevent_req *
resolv_discover_srv_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct resolv_ctx *resolv_ctx,
                         const char *service,
                         const char *protocol,
                         const char **discovery_domains);

errno_t resolv_discover_srv_recv(TALLOC_CTX *mem_ctx,
                                 struct tevent_req *req,
                                 struct ares_srv_reply **_reply_list,
                                 uint32_t *_ttl,
                                 char **_dns_domain);

bool
resolv_is_address(const char *name);

bool
resolv_is_unix(const char *name);

#endif /* __ASYNC_RESOLV_H__ */
