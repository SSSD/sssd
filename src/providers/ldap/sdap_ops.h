/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#ifndef _SDAP_OPS_H_
#define _SDAP_OPS_H_

#include <talloc.h>
#include <tevent.h>
#include "providers/ldap/ldap_common.h"

struct tevent_req *sdap_search_bases_send(TALLOC_CTX *mem_ctx,
                                          struct tevent_context *ev,
                                          struct sdap_options *opts,
                                          struct sdap_handle *sh,
                                          struct sdap_search_base **bases,
                                          struct sdap_attr_map *map,
                                          bool allow_paging,
                                          int timeout,
                                          const char *filter,
                                          const char **attrs,
                                          const char *base_dn);

int sdap_search_bases_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *reply_count,
                           struct sysdb_attrs ***reply);

struct tevent_req *
sdap_search_bases_return_first_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sdap_options *opts,
                                    struct sdap_handle *sh,
                                    struct sdap_search_base **bases,
                                    struct sdap_attr_map *map,
                                    bool allow_paging,
                                    int timeout,
                                    const char *filter,
                                    const char **attrs,
                                    const char *base_dn);

int sdap_search_bases_return_first_recv(struct tevent_req *req,
                                        TALLOC_CTX *mem_ctx,
                                        size_t *_reply_count,
                                        struct sysdb_attrs ***_reply);

struct tevent_req *
sdap_deref_bases_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct sdap_options *opts,
                      struct sdap_handle *sh,
                      struct sdap_search_base **bases,
                      struct sdap_attr_map_info *maps,
                      const char *filter,
                      const char **attrs,
                      const char *deref_attr,
                      unsigned int flags,
                      int timeout);

int sdap_deref_bases_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          size_t *_reply_count,
                          struct sdap_deref_attrs ***_reply);

struct tevent_req *
sdap_deref_bases_return_first_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct sdap_options *opts,
                                   struct sdap_handle *sh,
                                   struct sdap_search_base **bases,
                                   struct sdap_attr_map_info *maps,
                                   const char *filter,
                                   const char **attrs,
                                   const char *deref_attr,
                                   unsigned int flags,
                                   int timeout);

int sdap_deref_bases_return_first_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       size_t *_reply_count,
                                       struct sdap_deref_attrs ***_reply);

#endif /* _SDAP_OPS_H_ */
