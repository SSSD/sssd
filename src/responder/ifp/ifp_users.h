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

#include "responder/ifp/ifp_iface.h"
#include "responder/ifp/ifp_private.h"

/* Utility functions */

char * ifp_users_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     struct ldb_message *msg);

/* org.freedesktop.sssd.infopipe.Users */

int ifp_users_find_by_name(struct sbus_request *sbus_req,
                           void *data,
                           const char *name);

int ifp_users_find_by_id(struct sbus_request *sbus_req,
                         void *data,
                         uint32_t id);

int ifp_users_find_by_cert(struct sbus_request *sbus_req,
                           void *data,
                           const char *pem_cert);

int ifp_users_list_by_cert(struct sbus_request *sbus_req,
                           void *data,
                           const char *pem_cert,
                           uint32_t limit);

int ifp_users_find_by_name_and_cert(struct sbus_request *sbus_req,
                                    void *data,
                                    const char *name,
                                    const char *pem_cert);

int ifp_users_list_by_name(struct sbus_request *sbus_req,
                           void *data,
                           const char *filter,
                           uint32_t limit);

int ifp_users_list_by_domain_and_name(struct sbus_request *sbus_req,
                                      void *data,
                                      const char *domain,
                                      const char *filter,
                                      uint32_t limit);

/* org.freedesktop.sssd.infopipe.Users.User */

int ifp_users_user_update_groups_list(struct sbus_request *req,
                                      void *data);

void ifp_users_user_get_name(struct sbus_request *sbus_req,
                             void *data,
                             const char **_out);

void ifp_users_user_get_uid_number(struct sbus_request *sbus_req,
                                   void *data,
                                   uint32_t *_out);

void ifp_users_user_get_gid_number(struct sbus_request *sbus_req,
                                   void *data,
                                   uint32_t *_out);

void ifp_users_user_get_gecos(struct sbus_request *sbus_req,
                              void *data,
                              const char **_out);

void ifp_users_user_get_home_directory(struct sbus_request *sbus_req,
                                       void *data,
                                       const char **_out);

void ifp_users_user_get_login_shell(struct sbus_request *sbus_req,
                                    void *data,
                                    const char **_out);

void ifp_users_user_get_unique_id(struct sbus_request *sbus_req,
                                  void *data,
                                  const char **_out);

void ifp_users_user_get_groups(struct sbus_request *sbus_req,
                               void *data,
                               const char ***_out,
                               int *_size);

void ifp_users_user_get_domain(struct sbus_request *sbus_req,
                               void *data,
                               const char **_out);

void ifp_users_user_get_domainname(struct sbus_request *sbus_req,
                                   void *data,
                                   const char **_out);

void ifp_users_user_get_extra_attributes(struct sbus_request *sbus_req,
                                         void *data,
                                         hash_table_t **_out);

/* org.freedesktop.sssd.infopipe.Cache */

int ifp_cache_list_user(struct sbus_request *sbus_req,
                        void *data);

int ifp_cache_list_by_domain_user(struct sbus_request *sbus_req,
                                  void *data,
                                  const char *domain);

/* org.freedesktop.sssd.infopipe.Cache.Object */

int ifp_cache_object_store_user(struct sbus_request *sbus_req,
                                void *data);

int ifp_cache_object_remove_user(struct sbus_request *sbus_req,
                                 void *data);

#endif /* IFP_USERS_H_ */
