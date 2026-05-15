/*
   SSSD

   KCM Server - the KCM ccache operations

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
#ifndef _KCMSRV_CCACHE_H_
#define _KCMSRV_CCACHE_H_

#include "config.h"

#include <krb5/krb5.h>
#include <uuid/uuid.h>

#include "util/util.h"
#include "util/sss_iobuf.h"
#include "util/util_creds.h"
#include "providers/krb5/krb5_common.h"
#include "responder/kcm/kcmsrv_pvt.h"

#define UUID_BYTES    16
#define UUID_STR_SIZE 37

/* Just to keep the name of the ccache readable */
#define MAX_CC_NUM          99999

/*
 * Credentials are opaque to the KCM server
 *
 * Each ccache has a unique UUID.
 */
struct kcm_cred;

/*
 * An opaque ccache type and its operations
 *
 * Contains zero or some KCM credentials. One credential in the cache
 * is marked as the default one. The client can set and get the default
 * cache (e.g. with kswitch) but one cache is always the default -- we
 * fall back to the one created first.
 *
 * Each cache has a name and a UUID. Heimdal allows the name to be changed,
 * we don't (yet, because the MIT client doesn't allow that either)
 *
 * Each ccache also stores a client principal.
 */
struct kcm_ccache;

/*
 * Create a new KCM ccache owned by mem_ctx on the
 * memory level.
 *
 * When created, the ccache contains no credentials
 */
errno_t kcm_cc_new(TALLOC_CTX *mem_ctx,
                   krb5_context k5c,
                   struct cli_creds *owner,
                   const char *name,
                   krb5_principal princ,
                   struct kcm_ccache **_cc);

/*
 * Duplicate the ccache. Only ccache and credentials are duplicated,
 * but their data are a shallow copy.
 */
struct kcm_ccache *kcm_cc_dup(TALLOC_CTX *mem_ctx,
                              const struct kcm_ccache *cc);

/* Returns true if a client can access a ccache. */
bool kcm_cc_access(struct kcm_ccache *cc,
                   struct cli_creds *client);

/*
 * Since the kcm_ccache structure is opaque, the kcmsrv_ccache
 * layer contains a number of getsetters to read and write
 * properties of the kcm_ccache structure
 */
const char *kcm_cc_get_name(struct kcm_ccache *cc);
errno_t kcm_cc_get_uuid(struct kcm_ccache *cc, uuid_t _uuid);
krb5_principal kcm_cc_get_client_principal(struct kcm_ccache *cc);
int32_t kcm_cc_get_offset(struct kcm_ccache *cc);

/* Mainly useful for creating a cred structure from a persistent
 * storage
 */
struct kcm_cred *kcm_cred_new(TALLOC_CTX *mem_ctx,
                              uuid_t uuid,
                              struct sss_iobuf *cred_blob);

/* Add a cred to ccache */
errno_t kcm_cc_store_creds(struct kcm_ccache *cc,
                           struct kcm_cred *crd);

/* Set cc header information from sec key and client */
errno_t kcm_cc_set_header(struct kcm_ccache *cc,
                          const char *sec_key,
                          struct cli_creds *client);

krb5_creds **kcm_cc_unmarshal(TALLOC_CTX *mem_ctx,
                              krb5_context krb_context,
                              struct kcm_ccache *cc);

errno_t kcm_cred_get_uuid(struct kcm_cred *crd, uuid_t uuid);

/*
 * At the moment, the credentials are stored without unmarshalling
 * them, just as the clients sends the credentials.
 */
struct sss_iobuf *kcm_cred_get_creds(struct kcm_cred *crd);
errno_t kcm_cc_store_cred_blob(struct kcm_ccache *cc,
                               struct sss_iobuf *cred_blob);
 /*
 * The KCM server can call kcm_cred_get_creds to fetch the first
 * credential, then iterate over the credentials with
 * kcm_cc_next_cred until it returns NULL
 */
struct kcm_cred *kcm_cc_get_cred(struct kcm_ccache *cc);
struct kcm_cred *kcm_cc_next_cred(struct kcm_cred *crd);

/* An opaque database that contains all the ccaches */
struct kcm_ccdb;

/*
 * Initialize a ccache database of type cc_be
 */
struct kcm_ccdb *kcm_ccdb_init(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct confdb_ctx *cdb,
                               const char *confdb_service_path,
                               enum kcm_ccdb_be cc_be);
/*
 * Prepare KCM ccache list for renewals
 */
errno_t kcm_ccdb_renew_tgts(TALLOC_CTX *mem_ctx,
                            struct krb5_ctx *kctx,
                            struct tevent_context *ev,
                            struct kcm_ccdb *cdb,
                            struct kcm_ccache ***_cc_list);

/*
 * In KCM, each ccache name is usually in the form of "UID:<num>
 *
 * The <num> is generated by the KCM ccache database. Use this function
 * to retrieve the next number
 */
struct tevent_req *kcm_ccdb_nextid_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct kcm_ccdb *db,
                                        struct cli_creds *client);
errno_t kcm_ccdb_nextid_recv(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             char **_nextid);

/*
 * List all ccaches that belong to a given client
 *
 * The cc_list the recv function returns is NULL-terminated.
 *
 * NOTE: Contrary to how Heimdal behaves, root CAN NOT list all ccaches
 * of all users. This is a deliberate decision to treat root as any other
 * user.
 *
 * If a client has no ccaches, the function returns OK, but an empty list
 * containing just the NULL sentinel.
 */
struct tevent_req *kcm_ccdb_list_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct kcm_ccdb *db,
                                      struct cli_creds *client);
errno_t kcm_ccdb_list_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           uuid_t **_uuid_list);

/*
 * Retrieve a ccache by name.
 *
 * If there is no such ccache, return EOK, but a NULL _cc pointer
 */
struct tevent_req *kcm_ccdb_getbyname_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct kcm_ccdb *db,
                                           struct cli_creds *client,
                                           const char *name);
errno_t kcm_ccdb_getbyname_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx,
                                struct kcm_ccache **_cc);

/*
 * Retrieve a ccache by UUID
 *
 * If there is no such ccache, return EOK, but a NULL _cc pointer
 */
struct tevent_req *kcm_ccdb_getbyuuid_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct kcm_ccdb *db,
                                           struct cli_creds *client,
                                           uuid_t uuid);
errno_t kcm_ccdb_getbyuuid_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx,
                                struct kcm_ccache **_cc);

/*
 * Retrieve the default ccache. If there is no default cache,
 * return EOK, but a NULL UUID.
 */
struct tevent_req *kcm_ccdb_get_default_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client);
errno_t kcm_ccdb_get_default_recv(struct tevent_req *req,
                                  uuid_t *uuid);

/*
 * Translating name to UUID is often considerably faster than doing a full
 * CC retrieval, hence this function and the converse. If the UUID cannot
 * be found in the database, return ERR_KCM_CC_END
 */
struct tevent_req *kcm_ccdb_name_by_uuid_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              uuid_t uuid);
errno_t kcm_ccdb_name_by_uuid_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   const char **_name);

/*
 * Translating UUID to name is often considerably faster than doing a full
 * CC retrieval, hence this function and the converse. If the UUID cannot
 * be found in the database, return ERR_KCM_CC_END
 */
struct tevent_req *kcm_ccdb_uuid_by_name_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              const char *name);
errno_t kcm_ccdb_uuid_by_name_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   uuid_t _uuid);

/*
 * Set the default ccache. Passing a NULL UUID is a legal operation
 * that 'unsets' the default ccache.
 */
struct tevent_req *kcm_ccdb_set_default_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client,
                                             uuid_t uuid);
errno_t kcm_ccdb_set_default_recv(struct tevent_req *req);

/*
 * Add a ccache to the database.
 */
struct tevent_req *kcm_ccdb_create_cc_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct kcm_ccdb *db,
                                           struct cli_creds *client,
                                           struct kcm_ccache *cc);
errno_t kcm_ccdb_create_cc_recv(struct tevent_req *req);

/*
 * Modify cache properties in a db
 */
struct kcm_mod_ctx {
    int32_t kdc_offset;
    krb5_principal client;
    /* More settable properties (like name, when we support renames
     * will be added later
     */
};

struct kcm_mod_ctx *kcm_mod_ctx_new(TALLOC_CTX *mem_ctx);
errno_t kcm_mod_cc(struct kcm_ccache *cc, struct kcm_mod_ctx *mod_ctx);

struct tevent_req *kcm_ccdb_mod_cc_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct kcm_ccdb *db,
                                        struct cli_creds *client,
                                        uuid_t uuid,
                                        struct kcm_mod_ctx *mod_cc);
errno_t kcm_ccdb_mod_cc_recv(struct tevent_req *req);

/*
 * Store a credential in a cache
 */
struct tevent_req *kcm_ccdb_store_cred_blob_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct kcm_ccdb *db,
                                                 struct cli_creds *client,
                                                 uuid_t uuid,
                                                 struct sss_iobuf *cred_blob);
errno_t kcm_ccdb_store_cred_blob_recv(struct tevent_req *req);

/*
 * Delete a ccache from the database
 */
struct tevent_req *kcm_ccdb_delete_cc_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct kcm_ccdb *db,
                                           struct cli_creds *client,
                                           uuid_t uuid);
errno_t kcm_ccdb_delete_cc_recv(struct tevent_req *req);

void kcm_debug_uuid(uuid_t uuid);

/*
 * The KCM clients are not allowed (except root) to create ccaches
 * with arbitrary names. Instead, we assert that the ccache name
 * begins with UID where UID is the stringified representation of
 * the client's UID number
 */
errno_t kcm_check_name(const char *name, struct cli_creds *client);

/*
 * ccahe marshalling to and from JSON. This is used when the ccaches
 * are stored in the secrets store
 */

/*
 * The secrets store is a key-value store at heart. We store the UUID
 * and the name in the key to allow easy lookups be either key
 */
bool sec_key_match_name(const char *sec_key,
                        const char *name);

bool sec_key_match_uuid(const char *sec_key,
                        uuid_t uuid);

errno_t sec_key_parse(TALLOC_CTX *mem_ctx,
                      const char *sec_key,
                      const char **_name,
                      uuid_t uuid);

const char *sec_key_get_name(const char *sec_key);

errno_t sec_key_get_uuid(const char *sec_key,
                         uuid_t uuid);

const char *sec_key_create(TALLOC_CTX *mem_ctx,
                           const char *name,
                           uuid_t uuid);

/*
 * sec_key is a concatenation of the ccache's UUID and name
 * sec_value is the binary representation of ccache.
 */
errno_t sec_kv_to_ccache_binary(TALLOC_CTX *mem_ctx,
                                const char *sec_key,
                                struct sss_iobuf *sec_value,
                                struct cli_creds *client,
                                struct kcm_ccache **_cc);

/* Convert a kcm_ccache to its binary representation. */
errno_t kcm_ccache_to_sec_input_binary(TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache *cc,
                                       struct sss_iobuf **_payload);

errno_t bin_to_krb_data(TALLOC_CTX *mem_ctx,
                        struct sss_iobuf *buf,
                        krb5_data *out);
#endif /* _KCMSRV_CCACHE_H_ */
