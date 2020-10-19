/*
   SSSD

   KCM Server - ccache in-memory storage

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

#include "config.h"

#include <talloc.h>
#include <stdio.h>

#include "util/util.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"
#include "responder/kcm/kcmsrv_ccache_be.h"

struct ccdb_mem;

/*
 * The KCM memory database is just a double-linked list of kcm_ccache structures
 */
struct ccache_mem_wrap {
    struct kcm_ccache *cc;
    bool is_default;

    struct ccache_mem_wrap *next;
    struct ccache_mem_wrap *prev;

    struct ccdb_mem *mem_be;
};

struct ccdb_mem {
    /* Both ccaches and the next-id are kept in memory */
    struct ccache_mem_wrap *head;
    unsigned int nextid;
};

static struct ccache_mem_wrap *memdb_get_by_uuid(struct ccdb_mem *memdb,
                                                 struct cli_creds *client,
                                                 uuid_t uuid)
{
    uid_t uid;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccache_mem_wrap *out = NULL;

    uid = cli_creds_get_uid(client);

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (ccwrap->cc->owner.uid == uid) {
            if (uuid_compare(uuid, ccwrap->cc->uuid) == 0) {
                out = ccwrap;
                break;
            }
        }
    }

    return out;
}

static struct ccache_mem_wrap *memdb_get_by_name(struct ccdb_mem *memdb,
                                                 struct cli_creds *client,
                                                 const char *name)
{
    uid_t uid;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccache_mem_wrap *out = NULL;

    uid = cli_creds_get_uid(client);

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (ccwrap->cc->owner.uid == uid) {
            if (strcmp(ccwrap->cc->name, name) == 0) {
                out = ccwrap;
                break;
            }
        }
    }

    return out;
}

/* Since with the in-memory database, the database operations are just
 * fake-async wrappers around otherwise sync operations, we don't often
 * need any state, so we use this empty structure instead
 */
struct ccdb_mem_dummy_state {
};

static int ccwrap_destructor(void *ptr)
{
    struct ccache_mem_wrap *ccwrap = talloc_get_type(ptr, struct ccache_mem_wrap);

    if (ccwrap == NULL) {
        return 0;
    }

    if (ccwrap->cc != NULL) {
        if (ccwrap->cc->creds) {
            sss_erase_mem_securely(
                     sss_iobuf_get_data(ccwrap->cc->creds->cred_blob),
                     sss_iobuf_get_size(ccwrap->cc->creds->cred_blob));
        }
    }


    DLIST_REMOVE(ccwrap->mem_be->head, ccwrap);

    return 0;
}

static errno_t ccdb_mem_init(struct kcm_ccdb *db,
                             struct confdb_ctx *cdb,
                             const char *confdb_service_path)
{
    struct ccdb_mem *memdb = NULL;

    memdb = talloc_zero(db, struct ccdb_mem);
    if (memdb == NULL) {
        return ENOMEM;
    }
    db->db_handle = memdb;

    return EOK;
}

struct ccdb_mem_nextid_state {
    unsigned int nextid;
};

static struct tevent_req *ccdb_mem_nextid_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_nextid_state *state = NULL;
    struct ccdb_mem *memdb = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_nextid_state);
    if (req == NULL) {
        return NULL;
    }

    memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    if (memdb == NULL) {
        ret = EIO;
        goto immediate;
    }

    state->nextid = memdb->nextid++;

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_nextid_recv(struct tevent_req *req,
                                    unsigned int *_nextid)
{
    struct ccdb_mem_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_mem_nextid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_nextid = state->nextid;
    return EOK;
}

struct ccdb_mem_list_state {
    uuid_t *uuid_list;
};

static struct tevent_req *ccdb_mem_list_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem_list_state *state = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    size_t num_ccaches = 0;
    size_t cc_index = 0;
    errno_t ret;
    uid_t uid;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_list_state);
    if (req == NULL) {
        return NULL;
    }

    uid = cli_creds_get_uid(client);

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc->owner.uid == uid) {
            num_ccaches++;
        }
    }

    state->uuid_list = talloc_zero_array(state, uuid_t, num_ccaches+1);
    if (state->uuid_list == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    cc_index = 0;
    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc->owner.uid == uid) {
            uuid_copy(state->uuid_list[cc_index], ccwrap->cc->uuid);
            cc_index++;
        }
    }
    uuid_clear(state->uuid_list[num_ccaches]);

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_list_recv(struct tevent_req *req,
                                  TALLOC_CTX *mem_ctx,
                                  uuid_t **_uuid_list)
{
    struct ccdb_mem_list_state *state = tevent_req_data(req,
                                                struct ccdb_mem_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_uuid_list = talloc_steal(mem_ctx, state->uuid_list);
    return EOK;
}

static struct tevent_req *ccdb_mem_set_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client,
                                                    uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    struct ccache_mem_wrap *ccwrap = NULL;
    uid_t uid = cli_creds_get_uid(client);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    /* Reset all ccache defaults first */
    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (ccwrap->cc->owner.uid == uid) {
            ccwrap->is_default = false;
        }
    }

    /* Then set the default for the right ccache. This also allows to
     * pass a null uuid to just reset the old ccache (for example after
     * deleting the default
     */
    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap != NULL) {
        ccwrap->is_default = true;
    }

    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_set_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ccdb_mem_get_default_state {
    uuid_t dfl_uuid;
};

static struct tevent_req *ccdb_mem_get_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_get_default_state *state = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    uid_t uid = cli_creds_get_uid(client);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_get_default_state);
    if (req == NULL) {
        return NULL;
    }


    /* Reset all ccache defaults first */
    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (ccwrap->cc->owner.uid == uid && ccwrap->is_default == true) {
            break;
        }
    }

    if (ccwrap == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
               "No ccache marked as default, returning null ccache\n");
        uuid_clear(state->dfl_uuid);
    } else {
        uuid_copy(state->dfl_uuid, ccwrap->cc->uuid);
    }

    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_get_default_recv(struct tevent_req *req,
                                         uuid_t dfl)
{
    struct ccdb_mem_get_default_state *state = tevent_req_data(req,
                                                struct ccdb_mem_get_default_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    uuid_copy(dfl, state->dfl_uuid);
    return EOK;
}

struct ccdb_mem_getbyuuid_state {
    struct kcm_ccache *cc;
};

static struct tevent_req *ccdb_mem_getbyuuid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_getbyuuid_state *state = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    struct ccache_mem_wrap *ccwrap = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_getbyuuid_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap != NULL) {
        /* In order to provide a consistent interface, we need to let the caller
         * of getbyXXX own the ccache, therefore the memory back end returns a shallow
         * copy of the ccache
         */
        state->cc = kcm_cc_dup(state, ccwrap->cc);
        if (state->cc == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_getbyuuid_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_mem_getbyuuid_state *state = tevent_req_data(req,
                                                struct ccdb_mem_getbyuuid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct ccdb_mem_getbyname_state {
    struct kcm_ccache *cc;
};

static struct tevent_req *ccdb_mem_getbyname_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  const char *name)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_getbyname_state *state = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_getbyname_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_name(memdb, client, name);
    if (ccwrap != NULL) {
        /* In order to provide a consistent interface, we need to let the caller
         * of getbyXXX own the ccache, therefore the memory back end returns a shallow
         * copy of the ccache
         */
        state->cc = kcm_cc_dup(state, ccwrap->cc);
        if (state->cc == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_getbyname_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_mem_getbyname_state *state = tevent_req_data(req,
                                                struct ccdb_mem_getbyname_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct ccdb_mem_name_by_uuid_state {
    const char *name;
};

struct tevent_req *ccdb_mem_name_by_uuid_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_name_by_uuid_state *state = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    struct ccache_mem_wrap *ccwrap = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_name_by_uuid_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap == NULL) {
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    state->name = talloc_strdup(state, ccwrap->cc->name);
    if (state->name == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

errno_t ccdb_mem_name_by_uuid_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   const char **_name)
{
    struct ccdb_mem_name_by_uuid_state *state = tevent_req_data(req,
                                                struct ccdb_mem_name_by_uuid_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_name = talloc_steal(mem_ctx, state->name);
    return EOK;
}

struct ccdb_mem_uuid_by_name_state {
    uuid_t uuid;
};

struct tevent_req *ccdb_mem_uuid_by_name_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              const char *name)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_uuid_by_name_state *state = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    struct ccache_mem_wrap *ccwrap = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_uuid_by_name_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_name(memdb, client, name);
    if (ccwrap == NULL) {
        ret = ERR_NO_CREDS;
        goto immediate;
    }

    uuid_copy(state->uuid, ccwrap->cc->uuid);

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

errno_t ccdb_mem_uuid_by_name_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   uuid_t _uuid)
{
    struct ccdb_mem_uuid_by_name_state *state = tevent_req_data(req,
                                                struct ccdb_mem_uuid_by_name_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    uuid_copy(_uuid, state->uuid);
    return EOK;
}

static struct tevent_req *ccdb_mem_create_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client,
                                               struct kcm_ccache *cc)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccache_mem_wrap *ccwrap;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = talloc_zero(memdb, struct ccache_mem_wrap);
    if (ccwrap == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    ccwrap->cc = cc;
    ccwrap->mem_be = memdb;
    talloc_steal(ccwrap, cc);

    DLIST_ADD(memdb->head, ccwrap);
    talloc_set_destructor((TALLOC_CTX *) ccwrap, ccwrap_destructor);

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_create_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_mem_mod_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct kcm_ccdb *db,
                                            struct cli_creds *client,
                                            uuid_t uuid,
                                            struct kcm_mod_ctx *mod_cc)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    /* UUID is immutable, so search by that */
    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap == NULL) {
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    ret = kcm_mod_cc(ccwrap->cc, mod_cc);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot modify ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_mod_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_mem_store_cred_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct kcm_ccdb *db,
                                                   struct cli_creds *client,
                                                   uuid_t uuid,
                                                   struct sss_iobuf *cred_blob)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    struct ccache_mem_wrap *ccwrap = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap == NULL) {
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    ret = kcm_cc_store_cred_blob(ccwrap->cc, cred_blob);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store credentials to ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_store_cred_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_mem_delete_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client,
                                               uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccache_mem_wrap *ccwrap;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "BUG: Attempting to free unknown ccache\n");
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    ret = EOK;
    /* Destructor takes care of everything */
    talloc_free(ccwrap);
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_delete_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

const struct kcm_ccdb_ops ccdb_mem_ops = {
    .init = ccdb_mem_init,

    .nextid_send = ccdb_mem_nextid_send,
    .nextid_recv = ccdb_mem_nextid_recv,

    .set_default_send = ccdb_mem_set_default_send,
    .set_default_recv = ccdb_mem_set_default_recv,

    .get_default_send = ccdb_mem_get_default_send,
    .get_default_recv = ccdb_mem_get_default_recv,

    .list_send = ccdb_mem_list_send,
    .list_recv = ccdb_mem_list_recv,

    .getbyname_send = ccdb_mem_getbyname_send,
    .getbyname_recv = ccdb_mem_getbyname_recv,

    .getbyuuid_send = ccdb_mem_getbyuuid_send,
    .getbyuuid_recv = ccdb_mem_getbyuuid_recv,

    .name_by_uuid_send = ccdb_mem_name_by_uuid_send,
    .name_by_uuid_recv = ccdb_mem_name_by_uuid_recv,

    .uuid_by_name_send = ccdb_mem_uuid_by_name_send,
    .uuid_by_name_recv = ccdb_mem_uuid_by_name_recv,

    .create_send = ccdb_mem_create_send,
    .create_recv = ccdb_mem_create_recv,

    .mod_send = ccdb_mem_mod_send,
    .mod_recv = ccdb_mem_mod_recv,

    .store_cred_send = ccdb_mem_store_cred_send,
    .store_cred_recv = ccdb_mem_store_cred_recv,

    .delete_send = ccdb_mem_delete_send,
    .delete_recv = ccdb_mem_delete_recv,
};
