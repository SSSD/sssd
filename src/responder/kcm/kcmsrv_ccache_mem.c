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

    struct ccache_mem_wrap *next;
    struct ccache_mem_wrap *prev;

    struct ccdb_mem *mem_be;
};

struct ccdb_mem {
    /* Both ccaches and the next-id are kept in memory */
    struct ccache_mem_wrap *head;
    unsigned int nextid;
};

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
        krb5_free_principal(NULL, ccwrap->cc->client);

        if (ccwrap->cc->creds) {
            safezero(sss_iobuf_get_data(ccwrap->cc->creds->cred_blob),
                     sss_iobuf_get_size(ccwrap->cc->creds->cred_blob));
        }
    }


    DLIST_REMOVE(ccwrap->mem_be->head, ccwrap);

    return 0;
}

static errno_t ccdb_mem_init(struct kcm_ccdb *db)
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
                                               struct kcm_ccdb *db)
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

static struct kcm_ccache **ccdb_mem_list_int(TALLOC_CTX *mem_ctx,
                                                 struct kcm_ccdb *db,
                                                 uid_t uid,
                                                 bool only_dfl)
{
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);
    struct ccache_mem_wrap *ccwrap = NULL;
    size_t num_ccaches = 0;
    struct kcm_ccache **out;

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc->owner.uid == uid) {
            if (only_dfl && ccwrap->cc->is_default == false) {
                continue;
            }

            num_ccaches++;
        }
    }

    out = talloc_zero_array(mem_ctx, struct kcm_ccache *, num_ccaches + 1);
    if (out == NULL) {
        return NULL;
    }

    num_ccaches = 0;
    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc->owner.uid == uid) {
            if (only_dfl && ccwrap->cc->is_default == false) {
                continue;
            }

            out[num_ccaches] = ccwrap->cc;
            num_ccaches++;
        }
    }

    return out;
}

struct ccdb_mem_list_state {
    struct kcm_ccache **cc_list;
};

static struct tevent_req *ccdb_mem_list_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_list_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_list_state);
    if (req == NULL) {
        return NULL;
    }

    state->cc_list = ccdb_mem_list_int(state, db, cli_creds_get_uid(client), false);
    if (state->cc_list == NULL) {
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

static errno_t ccdb_mem_list_recv(struct tevent_req *req,
                                  TALLOC_CTX *mem_ctx,
                                  struct kcm_ccache ***_cc_list)
{
    struct ccdb_mem_list_state *state = tevent_req_data(req,
                                                struct ccdb_mem_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc_list = talloc_steal(mem_ctx, state->cc_list);
    return EOK;
}

static struct tevent_req *ccdb_mem_set_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client,
                                                    struct kcm_ccache *dfl)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct kcm_ccache **ccaches;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    ccaches = ccdb_mem_list_int(state,
                                db,
                                cli_creds_get_uid(client),
                                false);
    if (ccaches == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    for (int i = 0; ccaches[i] != NULL; i++) {
        if (dfl == ccaches[i]) {
            ccaches[i]->is_default = true;
        } else {
            ccaches[i]->is_default = false;
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

static errno_t ccdb_mem_set_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ccdb_mem_get_default_state {
    struct kcm_ccache *dfl;
};

static struct tevent_req *ccdb_mem_get_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_get_default_state *state = NULL;
    struct kcm_ccache **cc_list;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_get_default_state);
    if (req == NULL) {
        return NULL;
    }

    cc_list = ccdb_mem_list_int(state, db, cli_creds_get_uid(client), true);
    if (cc_list == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    state->dfl = cc_list[0];
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

static errno_t ccdb_mem_get_default_recv(struct tevent_req *req,
                                         struct kcm_ccache **_dfl)
{
    struct ccdb_mem_get_default_state *state = tevent_req_data(req,
                                                struct ccdb_mem_get_default_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_dfl = state->dfl;
    return EOK;
}

struct ccdb_mem_getbyuuid_state {
    struct kcm_ccache *cc;
};

static struct tevent_req *ccdb_mem_getbyuuid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  uint8_t *uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_getbyuuid_state *state = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem *memdb = talloc_get_type(db->db_handle, struct ccdb_mem);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_getbyuuid_state);
    if (req == NULL) {
        return NULL;
    }

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (memcmp(uuid, ccwrap->cc->uuid, UUID_BYTES) == 0) {
            break;
        }
    }

    if (ccwrap != NULL) {
        state->cc = ccwrap->cc;
    }

    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_getbyuuid_recv(struct tevent_req *req,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_mem_getbyuuid_state *state = tevent_req_data(req,
                                                struct ccdb_mem_getbyuuid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = state->cc;
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

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_getbyname_state);
    if (req == NULL) {
        return NULL;
    }

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (strcmp(ccwrap->cc->name, name) == 0) {
            break;
        }
    }

    if (ccwrap != NULL) {
        state->cc = ccwrap->cc;
    }

    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_getbyname_recv(struct tevent_req *req,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_mem_getbyname_state *state = tevent_req_data(req,
                                                struct ccdb_mem_getbyname_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = state->cc;
    return EOK;
}

static struct tevent_req *ccdb_mem_store_send(TALLOC_CTX *mem_ctx,
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

static errno_t ccdb_mem_store_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_mem_delete_send(TALLOC_CTX *mem_ctx,
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

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == cc) {
            break;
        }
    }

    if (ccwrap == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "BUG: Attempting to free unknown ccache\n");
        ret = ENOENT;
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

    .store_send = ccdb_mem_store_send,
    .store_recv = ccdb_mem_store_recv,

    .delete_send = ccdb_mem_delete_send,
    .delete_recv = ccdb_mem_delete_recv,
};
