/*
   SSSD

   KCM Server - the KCM ccache database interface

   This file should only be included from the ccache.c module.

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

#ifndef _KCMSRV_CCACHE_BE_
#define _KCMSRV_CCACHE_BE_

#include "config.h"

#include <talloc.h>
#include "responder/kcm/kcmsrv_ccache.h"

typedef errno_t
(*ccdb_init_fn)(struct kcm_ccdb *db,
                struct confdb_ctx *cdb,
                const char *confdb_service_path);

typedef struct tevent_req *
(*ccdb_nextid_send_fn)(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct kcm_ccdb *db,
                       struct cli_creds *client);
typedef errno_t
(*ccdb_nextid_recv_fn)(struct tevent_req *req,
                       unsigned int *_nextid);

typedef struct tevent_req *
(*ccdb_set_default_send_fn)(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct kcm_ccdb *db,
                            struct cli_creds *client,
                            uuid_t uuid);
typedef errno_t
(*ccdb_set_default_recv_fn)(struct tevent_req *req);

typedef struct tevent_req *
(*ccdb_get_default_send_fn)(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct kcm_ccdb *db,
                            struct cli_creds *client);
typedef errno_t
(*ccdb_get_default_recv_fn)(struct tevent_req *req,
                            uuid_t dfl);


typedef errno_t
(*ccdb_list_all_cc_fn)(TALLOC_CTX *mem_ctx,
                       struct krb5_ctx *kctx,
                       struct tevent_context *ev,
                       struct kcm_ccdb *cdb,
                       struct kcm_ccache ***_cc_list);

typedef struct tevent_req *
(*ccdb_list_send_fn)(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct kcm_ccdb *db,
                     struct cli_creds *client);
typedef errno_t
(*ccdb_list_recv_fn)(struct tevent_req *req,
                     TALLOC_CTX *mem_ctx,
                     uuid_t **_uuid_list);

typedef struct tevent_req *
(*ccdb_getbyname_send_fn)(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct kcm_ccdb *db,
                          struct cli_creds *client,
                          const char *name);
typedef errno_t
(*ccdb_getbyname_recv_fn)(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          struct kcm_ccache **_cc);

typedef struct tevent_req *
(*ccdb_getbyuuid_send_fn)(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct kcm_ccdb *db,
                          struct cli_creds *client,
                          uuid_t uuid);
typedef errno_t
(*ccdb_getbyuuid_recv_fn)(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          struct kcm_ccache **_cc);

typedef struct tevent_req *
(*ccdb_name_by_uuid_send_fn)(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct kcm_ccdb *db,
                             struct cli_creds *client,
                             uuid_t uuid);
typedef errno_t
(*ccdb_name_by_uuid_recv_fn)(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             const char **_name);

typedef struct tevent_req *
(*ccdb_uuid_by_name_send_fn)(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct kcm_ccdb *db,
                             struct cli_creds *client,
                             const char *name);
typedef errno_t
(*ccdb_uuid_by_name_recv_fn)(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             uuid_t _uuid);

typedef struct tevent_req *
(*ccdb_create_send_fn)(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct kcm_ccdb *db,
                       struct cli_creds *client,
                       struct kcm_ccache *cc);
typedef errno_t
(*ccdb_create_recv_fn)(struct tevent_req *req);

typedef struct tevent_req *
(*ccdb_mod_send_fn)(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct kcm_ccdb *db,
                    struct cli_creds *client,
                    uuid_t uuid,
                    struct kcm_mod_ctx *mod_cc);
typedef errno_t
(*ccdb_mod_recv_fn)(struct tevent_req *req);

typedef struct tevent_req *
(*kcm_ccdb_store_cred_blob_send_fn)(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct kcm_ccdb *db,
                                    struct cli_creds *client,
                                    uuid_t uuid,
                                    struct sss_iobuf *cred_blob);
typedef errno_t
(*kcm_ccdb_store_cred_blob_recv_fn)(struct tevent_req *req);

typedef struct tevent_req *
(*ccdb_delete_send_fn)(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct kcm_ccdb *db,
                      struct cli_creds *client,
                      uuid_t uuid);
typedef errno_t
(*ccdb_delete_recv_fn)(struct tevent_req *req);

/*
 * Each ccache back end (for example memory or secdb) must implement
 * all these functions. The functions are wrapped by the kcm_ccdb
 * interface that performs additional sanity checks or contains shared
 * logic such as access checks but in general doesn't assume anything
 * about how the operations work.
 */
struct kcm_ccdb_ops {
    ccdb_init_fn init;

    ccdb_nextid_send_fn nextid_send;
    ccdb_nextid_recv_fn nextid_recv;

    ccdb_set_default_send_fn set_default_send;
    ccdb_set_default_recv_fn set_default_recv;

    ccdb_get_default_send_fn get_default_send;
    ccdb_get_default_recv_fn get_default_recv;

    ccdb_list_all_cc_fn list_all_cc;

    ccdb_list_send_fn list_send;
    ccdb_list_recv_fn list_recv;

    ccdb_getbyname_send_fn getbyname_send;
    ccdb_getbyname_recv_fn getbyname_recv;

    ccdb_getbyuuid_send_fn getbyuuid_send;
    ccdb_getbyuuid_recv_fn getbyuuid_recv;

    ccdb_name_by_uuid_send_fn name_by_uuid_send;
    ccdb_name_by_uuid_recv_fn name_by_uuid_recv;

    ccdb_uuid_by_name_send_fn uuid_by_name_send;
    ccdb_uuid_by_name_recv_fn uuid_by_name_recv;

    ccdb_create_send_fn create_send;
    ccdb_create_recv_fn create_recv;

    ccdb_mod_send_fn mod_send;
    ccdb_mod_recv_fn mod_recv;

    kcm_ccdb_store_cred_blob_send_fn store_cred_send;
    kcm_ccdb_store_cred_blob_recv_fn store_cred_recv;

    ccdb_delete_send_fn delete_send;
    ccdb_delete_recv_fn delete_recv;
};

extern const struct kcm_ccdb_ops ccdb_mem_ops;
extern const struct kcm_ccdb_ops ccdb_secdb_ops;

#endif /* _KCMSRV_CCACHE_BE_ */
