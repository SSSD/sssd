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

#include "responder/ifp/ifp_iface.h"
#include "responder/ifp/ifp_private.h"

/* Utility functions */

char * ifp_groups_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      struct ldb_message *msg);

/* org.freedesktop.sssd.infopipe.Groups */

int ifp_groups_find_by_name(struct sbus_request *sbus_req,
                            void *data,
                            const char *name);

int ifp_groups_find_by_id(struct sbus_request *sbus_req,
                          void *data,
                          uint32_t id);

int ifp_groups_list_by_name(struct sbus_request *sbus_req,
                            void *data,
                            const char *filter,
                            uint32_t limit);

int ifp_groups_list_by_domain_and_name(struct sbus_request *sbus_req,
                                       void *data,
                                       const char *domain,
                                       const char *filter,
                                       uint32_t limit);

/* org.freedesktop.sssd.infopipe.Groups.Group */

int ifp_groups_group_update_member_list(struct sbus_request *sbus_req,
                                        void *data);

void ifp_groups_group_get_name(struct sbus_request *sbus_req,
                               void *data,
                               const char **_out);

void ifp_groups_group_get_gid_number(struct sbus_request *sbus_req,
                                     void *data,
                                     uint32_t *_out);

void ifp_groups_group_get_unique_id(struct sbus_request *sbus_req,
                                    void *data,
                                    const char **_out);

void ifp_groups_group_get_users(struct sbus_request *sbus_req,
                                void *data,
                                const char ***_out,
                                int *_size);

void ifp_groups_group_get_groups(struct sbus_request *sbus_req,
                                void *data,
                                const char ***_out,
                                int *_size);

/* org.freedesktop.sssd.infopipe.Cache */

int ifp_cache_list_group(struct sbus_request *sbus_req,
                         void *data);

int ifp_cache_list_by_domain_group(struct sbus_request *sbus_req,
                                   void *data,
                                   const char *domain);

/* org.freedesktop.sssd.infopipe.Cache.Object */

int ifp_cache_object_store_group(struct sbus_request *sbus_req,
                                 void *data);

int ifp_cache_object_remove_group(struct sbus_request *sbus_req,
                                  void *data);

#endif /* IFP_GROUPS_H_ */
