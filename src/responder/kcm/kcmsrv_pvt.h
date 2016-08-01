/*
   SSSD

   KCM Server - private header file

   Copyright (C) Red Hat, 2016

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

#ifndef __KCMSRV_PVT_H__
#define __KCMSRV_PVT_H__

#include "config.h"

#include <sys/types.h>
#include "responder/common/responder.h"

/* KCM IO structure */
struct kcm_data {
    uint8_t *data;
    size_t length;
};

/* To avoid leaking the sssd-specific responder data to other
 * modules, the ccache databases and other KCM specific data
 * are kept separately
 */
struct kcm_resp_ctx {
    krb5_context k5c;
};

/* responder context that contains both the responder data,
 * like the ccaches and the sssd-specific stuff like the
 * generic responder ctx
 */
struct kcm_ctx {
    struct resp_ctx *rctx;
    int fd_limit;
    char *socket_path;

    struct kcm_resp_ctx *kcm_data;
};

int kcm_connection_setup(struct cli_ctx *cctx);

#endif /* __KCMSRV_PVT_H__ */
