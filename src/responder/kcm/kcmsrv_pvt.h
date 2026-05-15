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
#include <krb5/krb5.h>
#include "responder/common/responder.h"

#define KCM_PROTOCOL_VERSION_MAJOR 2
#define KCM_PROTOCOL_VERSION_MINOR 0

/* This should ideally be in RUNSTATEDIR, but Heimdal uses a hardcoded
 * /var/run, and we need to use the same default path. */
#define DEFAULT_KCM_SOCKET_PATH "/var/run/.heim_org.h5l.kcm-socket"

/*
 * KCM IO structure
 *
 * In theory we cold use sss_iobuf there, but since iobuf was
 * made opaque, this allows it to allocate the structures on
 * the stack in one go.
 * */
struct kcm_data {
    uint8_t *data;
    size_t length;
};

/*
 * To avoid leaking the sssd-specific responder data to other
 * modules, the ccache databases and other KCM specific data
 * are kept separately
 */
struct kcm_resp_ctx {
    krb5_context k5c;
    struct kcm_ccdb *db;
};

/* Supported ccache back ends */
enum kcm_ccdb_be {
    CCDB_BE_MEMORY,
    CCDB_BE_SECDB,
};

/*
 * responder context that contains both the responder data,
 * like the ccaches and the sssd-specific stuff like the
 * generic responder ctx
 */
struct kcm_ctx {
    struct resp_ctx *rctx;
    int fd_limit;
    char *socket_path;
    enum kcm_ccdb_be cc_be;
    struct kcm_ops_queue_ctx *qctx;

    struct kcm_resp_ctx *kcm_data;
};

int kcm_connection_setup(struct cli_ctx *cctx);

/*
 * Internally in SSSD-KCM we use SSSD-internal error codes so that we
 * can always the same sss_strerror() functions to format the errors
 * nicely, but the client expects libkrb5 error codes.
 */
krb5_error_code sss2krb5_error(errno_t err);

/* We enqueue all requests by the same UID to avoid concurrency issues.
 */
struct kcm_ops_queue_entry;

struct kcm_ops_queue_ctx *kcm_ops_queue_create(TALLOC_CTX *mem_ctx,
                                               struct kcm_ctx *kctx);

struct tevent_req *kcm_op_queue_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct kcm_ops_queue_ctx *qctx,
                                     struct cli_creds *client);

errno_t kcm_op_queue_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          struct kcm_ops_queue_entry **_entry);

#endif /* __KCMSRV_PVT_H__ */
