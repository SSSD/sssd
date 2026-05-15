/*
   SSSD

   KCM Server - the KCM ccache operations - private structures

   Should be accessed only from the ccache layer.

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
#ifndef _KCMSRV_CCACHE_PVT_H
#define _KCMSRV_CCACHE_PVT_H

#include "responder/kcm/kcmsrv_ccache.h"
#include "responder/kcm/kcmsrv_ccache_be.h"

struct kcm_ccache_owner {
    uid_t uid;
    gid_t gid;
};

struct kcm_cred {
    struct sss_iobuf *cred_blob;
    /* Randomly generated 16 bytes */
    uuid_t uuid;

    struct kcm_cred *next;
    struct kcm_cred *prev;
};

struct kcm_ccdb {
    struct tevent_context *ev;

    void *db_handle;
    const struct kcm_ccdb_ops *ops;
};

struct kcm_ccache {
    const char *name;
    struct kcm_ccache_owner owner;
    uuid_t uuid;

    krb5_principal client;
    int32_t kdc_offset;

    struct kcm_cred *creds;
};

#endif /* _KCMSRV_CCACHE_PVT_H */
