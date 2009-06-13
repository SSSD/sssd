/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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

#include <talloc.h>
#include <tevent.h>
#include "providers/dp_backend.h"
#include "providers/ldap/sdap.h"

/* TODO: remove later
 * These functions are available in the latest tevent and are the ones that
 * should be used as tevent_req is rightfully opaque there */
#ifndef tevent_req_data
#define tevent_req_data(req, type) ((type *)req->private_state)
#endif

#ifndef tevent_req_set_callback
#define tevent_req_set_callback(req, func, data) \
    do { req->async.fn = func; req->async.private_data = data; } while(0)
#endif

#ifndef tevent_req_callback_data
#define tevent_req_callback_data(req, type) ((type *)req->async.private_data)
#endif


struct tevent_req *sdap_connect_send(TALLOC_CTX *memctx,
                                     struct tevent_context *ev,
                                     struct sdap_options *opts,
                                     bool use_start_tls);

int sdap_connect_recv(struct tevent_req *req,
                      TALLOC_CTX *memctx,
                      struct sdap_handle **sh);

struct tevent_req *sdap_get_users_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *wildcard);

int sdap_get_users_recv(struct tevent_req *req);

struct tevent_req *sdap_get_groups_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *wildcard);

int sdap_get_groups_recv(struct tevent_req *req);

struct tevent_req *sdap_auth_send(TALLOC_CTX *memctx,
                                  struct tevent_context *ev,
                                  struct sdap_handle *sh,
                                  const char *user_dn,
                                  const char *password);

int sdap_auth_recv(struct tevent_req *req, enum sdap_result *result);

struct tevent_req *sdap_cache_pw_send(TALLOC_CTX *memctx,
                                      struct tevent_context *ev,
                                      struct sysdb_ctx *sysdb,
                                      struct sss_domain_info *domain,
                                      const char *username,
                                      const char *password);

int sdap_cache_pw_recv(struct tevent_req *req);
