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

#ifndef IFP_USERS_H_
#define IFP_USERS_H_

#include "responder/ifp/ifp_private.h"

/* Utility functions */

char * ifp_users_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     struct ldb_message *msg);

/* org.freedesktop.sssd.infopipe.Users */

struct tevent_req *
ifp_users_find_by_name_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *name);

errno_t
ifp_users_find_by_name_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char **_path);

struct tevent_req *
ifp_users_find_by_id_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          uint32_t id);

errno_t
ifp_users_find_by_id_recv(TALLOC_CTX *mem_ctx,
                          struct tevent_req *req,
                          const char **_path);

struct tevent_req *
ifp_users_find_by_cert_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *pem_cert);

errno_t
ifp_users_find_by_cert_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char **_path);

struct tevent_req *
ifp_users_list_by_cert_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *pem_cert,
                            uint32_t limit);

errno_t
ifp_users_list_by_cert_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char ***_paths);

struct tevent_req *
ifp_users_find_by_name_and_cert_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sbus_request *sbus_req,
                                     struct ifp_ctx *ctx,
                                     const char *name,
                                     const char *pem_cert);

errno_t
ifp_users_find_by_name_and_cert_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     const char **_path);

struct tevent_req *
ifp_users_list_by_name_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *filter,
                            uint32_t limit);

errno_t
ifp_users_list_by_attr_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char ***_paths);

struct tevent_req *
ifp_users_list_by_domain_and_name_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sbus_request *sbus_req,
                                       struct ifp_ctx *ctx,
                                       const char *domain,
                                       const char *filter,
                                       uint32_t limit);

errno_t
ifp_users_list_by_domain_and_name_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req,
                                       const char ***_paths);

struct tevent_req *
ifp_users_find_by_valid_cert_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct sbus_request *sbus_req,
                                  struct ifp_ctx *ctx,
                                  const char *pem_cert);

errno_t
ifp_users_find_by_valid_cert_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  const char **_path);

/* org.freedesktop.sssd.infopipe.Users.User */

struct tevent_req *
ifp_users_user_update_groups_list_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sbus_request *sbus_req,
                                       struct ifp_ctx *ctx);

errno_t
ifp_users_user_update_groups_list_recv(struct tevent_req *req);

errno_t
ifp_users_user_get_name(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct ifp_ctx *ctx,
                        const char **_out);

errno_t
ifp_users_user_get_uid_number(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              uint32_t *_out);

errno_t
ifp_users_user_get_gid_number(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              uint32_t *_out);

errno_t
ifp_users_user_get_gecos(TALLOC_CTX *mem_ctx,
                        struct sbus_request *sbus_req,
                        struct ifp_ctx *ctx,
                        const char **_out);

errno_t
ifp_users_user_get_home_directory(TALLOC_CTX *mem_ctx,
                                  struct sbus_request *sbus_req,
                                  struct ifp_ctx *ctx,
                                  const char **_out);

errno_t
ifp_users_user_get_login_shell(TALLOC_CTX *mem_ctx,
                               struct sbus_request *sbus_req,
                               struct ifp_ctx *ctx,
                               const char **_out);

errno_t
ifp_users_user_get_unique_id(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             const char **_out);

errno_t
ifp_users_user_get_groups(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ifp_ctx,
                          const char ***_out);

errno_t
ifp_users_user_get_domain(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          const char **_out);

errno_t
ifp_users_user_get_domainname(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ifp_ctx,
                              const char **_out);

errno_t
ifp_users_user_get_extra_attributes(TALLOC_CTX *mem_ctx,
                                    struct sbus_request *sbus_req,
                                    struct ifp_ctx *ifp_ctx,
                                    hash_table_t **_out);

/* org.freedesktop.sssd.infopipe.Cache */

errno_t
ifp_cache_list_user(TALLOC_CTX *mem_ctx,
                    struct sbus_request *sbus_req,
                    struct ifp_ctx *ctx,
                    const char ***_out);

errno_t
ifp_cache_list_by_domain_user(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              const char *domain,
                              const char ***_out);

/* org.freedesktop.sssd.infopipe.Cache.Object */

errno_t
ifp_cache_object_store_user(TALLOC_CTX *mem_ctx,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            bool *_result);

errno_t
ifp_cache_object_remove_user(TALLOC_CTX *mem_ctx,
                             struct sbus_request *sbus_req,
                             struct ifp_ctx *ctx,
                             bool *_result);

struct tevent_req *
ifp_users_list_by_attr_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct ifp_ctx *ctx,
                            const char *attr,
                            const char *filter,
                            uint32_t limit);

errno_t
ifp_users_list_by_attr_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req,
                            const char ***_paths);
#endif /* IFP_USERS_H_ */
