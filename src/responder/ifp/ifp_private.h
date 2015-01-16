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
#include "responder/ifp/ifp_iface_generated.h"

#define IFP_PATH "/org/freedesktop/sssd/infopipe"

struct sysbus_ctx {
    struct sbus_connection *conn;
    char *introspect_xml;
};

struct ifp_ctx {
    struct resp_ctx *rctx;
    struct sss_names_ctx *snctx;
    struct sss_nc_ctx *ncache;
    int neg_timeout;

    struct sysbus_ctx *sysbus;
    const char **user_whitelist;
};

errno_t ifp_register_sbus_interface(struct sbus_connection *conn,
                                    void *handler_data);

/* This is a throwaway method to ease the review of the patch.
 * It will be removed later */
int ifp_ping(struct sbus_request *dbus_req, void *data);

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

errno_t ifp_add_ldb_el_to_dict(DBusMessageIter *iter_dict,
                               struct ldb_message_element *el);
const char **ifp_parse_attr_list(TALLOC_CTX *mem_ctx, const char *conf_str);
const char **
ifp_parse_attr_list_ex(TALLOC_CTX *mem_ctx, const char *conf_str,
                       const char **defaults);
bool ifp_attr_allowed(const char *whitelist[], const char *attr);
#endif /* _IFPSRV_PRIVATE_H_ */
