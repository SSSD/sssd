/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: A private header

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

#ifndef _IFPSRV_PRIVATE_H_
#define _IFPSRV_PRIVATE_H_

#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "providers/data_provider.h"
#include "responder/ifp/ifp_iface.h"

struct sysbus_ctx {
    struct sbus_connection *conn;
    char *introspect_xml;
};

struct ifp_ctx {
    struct resp_ctx *rctx;
    struct sss_names_ctx *snctx;

    struct sysbus_ctx *sysbus;
    const char **user_whitelist;
    uint32_t wildcard_limit;
};

errno_t ifp_register_sbus_interface(struct sbus_connection *conn,
                                    void *handler_data);

void ifp_register_nodes(struct ifp_ctx *ctx, struct sbus_connection *conn);

int ifp_ping(struct sbus_request *dbus_req, void *data, const char *ping);

int ifp_user_get_attr(struct sbus_request *dbus_req, void *data);

int ifp_user_get_groups(struct sbus_request *req,
                        void *data, const char *arg_user);

/* == Utility functions == */
struct ifp_req {
    struct sbus_request *dbus_req;
    struct ifp_ctx *ifp_ctx;
};

errno_t ifp_req_create(struct sbus_request *dbus_req,
                       struct ifp_ctx *ifp_ctx,
                       struct ifp_req **_ifp_req);

/* Returns an appropriate DBus error for specific ifp_req_create failures */
int ifp_req_create_handle_failure(struct sbus_request *dbus_req, errno_t err);

errno_t ifp_add_value_to_dict(DBusMessageIter *iter_dict,
                              const char *key,
                              const char *value);

errno_t ifp_add_ldb_el_to_dict(DBusMessageIter *iter_dict,
                               struct ldb_message_element *el);
const char **
ifp_parse_user_attr_list(TALLOC_CTX *mem_ctx, const char *conf_str);

const char **
ifp_get_user_extra_attributes(TALLOC_CTX *mem_ctx, struct ifp_ctx *ifp_ctx);

bool ifp_attr_allowed(const char *whitelist[], const char *attr);
bool ifp_is_user_attr_allowed(struct ifp_ctx *ifp_ctx, const char *attr);

/* Used for list calls */
struct ifp_list_ctx {
    struct sbus_request *sbus_req;
    const char *filter;
    uint32_t limit;

    struct sss_domain_info *dom;
    struct ifp_ctx *ctx;

    const char **paths;
    size_t path_count;
};

struct ifp_list_ctx *ifp_list_ctx_new(struct sbus_request *sbus_req,
                                      struct ifp_ctx *ctx,
                                      const char *filter,
                                      uint32_t limit);

errno_t ifp_list_ctx_remaining_capacity(struct ifp_list_ctx *list_ctx,
                                        size_t entries,
                                        size_t *_capacity);

errno_t ifp_ldb_el_output_name(struct resp_ctx *rctx,
                               struct ldb_message *msg,
                               const char *el_name,
                               struct sss_domain_info *dom);

char *ifp_format_name_attr(TALLOC_CTX *mem_ctx, struct ifp_ctx *ifp_ctx,
                           const char *in_name, struct sss_domain_info *dom);

#endif /* _IFPSRV_PRIVATE_H_ */
