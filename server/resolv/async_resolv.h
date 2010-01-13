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

#ifndef HAVE_ARES_DATA
#include "resolv/ares/ares_parse_srv_reply.h"
#include "resolv/ares/ares_parse_txt_reply.h"
#include "resolv/ares/ares_data.h"
#endif /* HAVE_ARES_DATA */

/*
 * An opaque structure which holds context for a module using the async
 * resolver. Is should be used as a "local-global" variable - in sssd,
 * every backend should have its own.

 * Do NOT free the context until there are any pending resolv_ calls
 */
struct resolv_ctx;

int resolv_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev_ctx,
                int timeout, struct resolv_ctx **ctxp);

void resolv_reread_configuration(void);

const char *resolv_strerror(int ares_code);

struct hostent *resolv_copy_hostent(TALLOC_CTX *mem_ctx,
                                    struct hostent *src);

/** Get host by name **/
struct tevent_req *resolv_gethostbyname_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct resolv_ctx *ctx,
                                            const char *name,
                                            int family);

int resolv_gethostbyname_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              int *status,
                              int *timeouts,
                              struct hostent **hostent);

/** Get SRV record **/
struct tevent_req *resolv_getsrv_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct resolv_ctx *ctx,
                                      const char *query);

int resolv_getsrv_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       int *status,
                       int *timeouts,
                       struct ares_srv_reply **reply_list);

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

#endif /* __ASYNC_RESOLV_H__ */
