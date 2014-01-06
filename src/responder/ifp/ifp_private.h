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
#include "providers/data_provider.h"
#include "responder/ifp/ifp_iface_generated.h"

#define INFOPIPE_PATH "/org/freedesktop/sssd/infopipe"

struct sysbus_ctx {
    struct sbus_connection *conn;
    char *introspect_xml;
};

struct ifp_ctx {
    struct resp_ctx *rctx;
    struct sss_names_ctx *snctx;

    struct sysbus_ctx *sysbus;
};

/* This is a throwaway method to ease the review of the patch.
 * It will be removed later */
int ifp_ping(struct sbus_request *dbus_req, void *data);

#endif /* _IFPSRV_PRIVATE_H_ */
