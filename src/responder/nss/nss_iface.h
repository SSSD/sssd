/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#ifndef _NSS_IFACE_H_
#define _NSS_IFACE_H_

#include "sss_iface/sss_iface_async.h"
#include "responder/nss/nss_private.h"

errno_t
sss_nss_register_backend_iface(struct sbus_connection *conn,
                               struct sss_nss_ctx *nss_ctx);

#endif /* _NSS_IFACE_H_ */
