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

#ifndef IFP_GROUPS_H_
#define IFP_GROUPS_H_

#include "responder/ifp/ifp_private.h"

/* Utility functions */

char * ifp_groups_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      struct ldb_message *msg);

/* org.freedesktop.sssd.infopipe.Groups */

struct tevent_req *
ifp_groups_find_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             const char *name);

errno_t
ifp_groups_find_by_name_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             const char **_path);

struct tevent_req *
ifp_groups_find_by_id_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           uint32_t id);

errno_t
ifp_groups_find_by_id_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           const char **_path);

struct tevent_req *
ifp_groups_list_by_name_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             const char *filter,
                             uint32_t limit);

errno_t
ifp_groups_list_by_name_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             const char ***_paths);

struct tevent_req *
ifp_groups_list_by_domain_and_name_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sbus_request *sbus_req,
                                        struct ifp_ctx *ctx,
                                        const char *domain,
                                        const char *filter,
                                        uint32_t limit);

errno_t
ifp_groups_list_by_domain_and_name_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        const char ***_paths);

/* org.freedesktop.sssd.infopipe.Groups.Group */

struct tevent_req *
ifp_groups_group_update_member_list_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sbus_request *sbus_req,
                                         struct ifp_ctx *ctx);

errno_t
ifp_groups_group_update_member_list_recv(TALLOC_CTX *mem_ctx,
                                         struct tevent_req *req);

errno_t
ifp_groups_group_get_name(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          const char **_out);

errno_t
ifp_groups_group_get_gid_number(TALLOC_CTX *mem_ctx,
                                struct sbus_request *sbus_req,
                                struct ifp_ctx *ctx,
                                uint32_t *_out);

errno_t
ifp_groups_group_get_unique_id(TALLOC_CTX *mem_ctx,
                                struct sbus_request *sbus_req,
                                struct ifp_ctx *ctx,
                                const char **_out);

errno_t
ifp_groups_group_get_users(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           const char ***_out);

errno_t
ifp_groups_group_get_groups(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           const char ***_out);

/* org.freedesktop.sssd.infopipe.Cache */

errno_t
ifp_cache_list_group(TALLOC_CTX *mem_ctx,
                     struct sbus_request *sbus_req,
                     struct ifp_ctx *ctx,
                     const char ***_out);

errno_t
ifp_cache_list_by_domain_group(TALLOC_CTX *mem_ctx,
                               struct sbus_request *sbus_req,
                               struct ifp_ctx *ctx,
                               const char *domain,
                               const char ***_out);

/* org.freedesktop.sssd.infopipe.Cache.Object */

errno_t
ifp_cache_object_store_group(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             bool *_result);

errno_t
ifp_cache_object_remove_group(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              bool *_result);

#endif /* IFP_GROUPS_H_ */
