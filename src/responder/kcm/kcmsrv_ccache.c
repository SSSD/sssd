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

#include "config.h"

#include "util/crypto/sss_crypto.h"
#include "util/util.h"
#include "util/sss_krb5.h"
#include "responder/kcm/kcmsrv_ccache.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"
#include "responder/kcm/kcmsrv_ccache_be.h"

static int kcm_cc_destructor(struct kcm_ccache *cc)
{
    if (cc == NULL) {
        return 0;
    }

    krb5_free_principal(NULL, cc->client);
    return 0;
}

errno_t kcm_cc_new(TALLOC_CTX *mem_ctx,
                   krb5_context k5c,
                   struct cli_creds *owner,
                   const char *name,
                   krb5_principal princ,
                   struct kcm_ccache **_cc)
{
    struct kcm_ccache *cc;
    krb5_error_code kret;
    errno_t ret;

    cc = talloc_zero(mem_ctx, struct kcm_ccache);
    if (cc == NULL) {
        return ENOMEM;
    }

    ret = kcm_check_name(name, owner);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Name %s is malformed\n", name);
        return ret;
    }

    cc->name = talloc_strdup(cc, name);
    if (cc->name == NULL) {
        talloc_free(cc);
        return ENOMEM;
    }

    uuid_generate(cc->uuid);

    kret = krb5_copy_principal(k5c, princ, &cc->client);
    if (kret != 0) {
        const char *err_msg = sss_krb5_get_error_message(k5c, kret);
        DEBUG(SSSDBG_OP_FAILURE,
              "krb5_copy_principal failed: [%d][%s]\n", kret, err_msg);
        sss_krb5_free_error_message(k5c, err_msg);
        talloc_free(cc);
        return ERR_INTERNAL;
    }

    cc->owner.uid = cli_creds_get_uid(owner);
    cc->owner.gid = cli_creds_get_gid(owner);
    cc->kdc_offset = INT32_MAX;

    talloc_set_destructor(cc, kcm_cc_destructor);
    *_cc = cc;
    return EOK;
}

const char *kcm_cc_get_name(struct kcm_ccache *cc)
{
    return cc ? cc->name : NULL;
}

errno_t kcm_cc_get_uuid(struct kcm_ccache *cc, uuid_t _uuid)
{
    if (cc == NULL) {
        return EINVAL;
    }
    uuid_copy(_uuid, cc->uuid);
    return EOK;
}

krb5_principal kcm_cc_get_client_principal(struct kcm_ccache *cc)
{
    return cc ? cc->client : NULL;
}

bool kcm_cc_access(struct kcm_ccache *cc,
                   struct cli_creds *client)
{
    bool ok;
    uid_t uid = cli_creds_get_uid(client);
    gid_t gid = cli_creds_get_gid(client);

    if (cc == NULL) {
        return false;
    }

    if (uid == 0 && gid == 0) {
        /* root can access any ccache */
        return true;
    }

    ok = ((cc->owner.uid == uid) && (cc->owner.gid == gid));
    if (!ok) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Client %"SPRIuid":%"SPRIgid" has no access to ccache %s\n",
              cli_creds_get_uid(client),
              cli_creds_get_gid(client),
              cc->name);
    }
    return ok;
}

int32_t kcm_cc_get_offset(struct kcm_ccache *cc)
{
    return cc ? cc->kdc_offset : INT32_MAX;
}

errno_t kcm_cc_store_cred_blob(struct kcm_ccache *cc,
                               struct sss_iobuf *cred_blob)
{
    struct kcm_cred *kcreds;
    uuid_t uuid;
    errno_t ret;

    if (cc == NULL || cred_blob == NULL) {
        return EINVAL;
    }

    uuid_generate(uuid);
    kcreds = kcm_cred_new(cc, uuid, cred_blob);
    if (kcreds == NULL) {
        return ENOMEM;
    }

    ret = kcm_cc_store_creds(cc, kcreds);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

struct kcm_cred *kcm_cc_get_cred(struct kcm_ccache *cc)
{
    if (cc == NULL) {
        return NULL;
    }

    return cc->creds;
}

struct kcm_cred *kcm_cc_next_cred(struct kcm_cred *crd)
{
    if (crd == NULL) {
        return NULL;
    }

    return crd->next;
}

struct kcm_cred *kcm_cred_new(TALLOC_CTX *mem_ctx,
                              uuid_t uuid,
                              struct sss_iobuf *cred_blob)
{
    struct kcm_cred *kcreds;

    kcreds = talloc_zero(mem_ctx, struct kcm_cred);
    if (kcreds == NULL) {
        return NULL;
    }

    uuid_copy(kcreds->uuid, uuid);
    kcreds->cred_blob = talloc_steal(kcreds, cred_blob);
    return kcreds;
}

/* Add a cred to ccache */
errno_t kcm_cc_store_creds(struct kcm_ccache *cc,
                           struct kcm_cred *crd)
{
    DLIST_ADD(cc->creds, crd);
    talloc_steal(cc, crd);
    return EOK;
}

errno_t kcm_cred_get_uuid(struct kcm_cred *crd, uuid_t _uuid)
{
    if (crd == NULL) {
        return EINVAL;
    }
    uuid_copy(_uuid, crd->uuid);
    return EOK;
}

struct sss_iobuf *kcm_cred_get_creds(struct kcm_cred *crd)
{
    return crd ? crd->cred_blob : NULL;
}

struct kcm_ccdb *kcm_ccdb_init(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               enum kcm_ccdb_be cc_be)
{
    errno_t ret;
    struct kcm_ccdb *ccdb = NULL;

    if (ev == NULL) {
        return NULL;
    }

    ccdb = talloc_zero(mem_ctx, struct kcm_ccdb);
    if (ccdb == NULL) {
        return NULL;
    }
    ccdb->ev = ev;

    switch (cc_be) {
    case CCDB_BE_MEMORY:
        DEBUG(SSSDBG_FUNC_DATA, "KCM back end: memory\n");
        ccdb->ops = &ccdb_mem_ops;
        break;
    case CCDB_BE_SECRETS:
        DEBUG(SSSDBG_FUNC_DATA, "KCM back end: sssd-secrets\n");
        ccdb->ops = &ccdb_sec_ops;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown ccache database\n");
        break;
    }

    if (ccdb->ops == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Ccache database not initialized\n");
        talloc_free(ccdb);
        return NULL;
    }

    ret = ccdb->ops->init(ccdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot initialize ccache database\n");
        talloc_free(ccdb);
        return NULL;
    }

    return ccdb;
}

struct kcm_ccdb_nextid_state {
    char *next_cc;
    struct kcm_ccdb *db;
    struct cli_creds *client;
};

static void kcm_ccdb_nextid_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_nextid_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct kcm_ccdb *db,
                                        struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_nextid_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_nextid_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;
    state->client = client;

    if (ev == NULL || db == NULL || client == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = state->db->ops->nextid_send(mem_ctx, ev, state->db, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_nextid_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_nextid_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_nextid_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_nextid_state);
    errno_t ret;
    unsigned int nextid;

    ret = state->db->ops->nextid_recv(subreq, &nextid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to generate next UID [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->next_cc = talloc_asprintf(state, "%"SPRIuid":%u",
                                     cli_creds_get_uid(state->client),
                                     nextid);
    if (state->next_cc == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "generated %s\n", state->next_cc);
    tevent_req_done(req);
}

errno_t kcm_ccdb_nextid_recv(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             char **_next_cc)
{
    struct kcm_ccdb_nextid_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_nextid_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_next_cc = talloc_steal(mem_ctx, state->next_cc);
    return EOK;
}

struct kcm_ccdb_list_state {
    struct kcm_ccdb *db;
    struct cli_creds *client;

    uuid_t *uuid_list;
};

static void kcm_ccdb_list_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_list_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct kcm_ccdb *db,
                                      struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_list_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_list_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;
    state->client = client;

    if (ev == NULL || db == NULL || client == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = state->db->ops->list_send(mem_ctx,
                                       ev,
                                       state->db,
                                       client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_list_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_list_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_list_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_list_state);
    errno_t ret;

    ret = state->db->ops->list_recv(subreq, state, &state->uuid_list);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to list all ccaches [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_list_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           uuid_t **_uuid_list)
{
    struct kcm_ccdb_list_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_list_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_uuid_list = talloc_steal(mem_ctx, state->uuid_list);
    return EOK;
}

struct kcm_ccdb_get_default_state {
    struct kcm_ccdb *db;
    uuid_t uuid;
};

static void kcm_ccdb_get_default_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_get_default_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_get_default_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_get_default_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;

    if (ev == NULL || db == NULL || client == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = db->ops->get_default_send(mem_ctx, ev, db, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_get_default_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_get_default_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_get_default_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_get_default_state);
    errno_t ret;

    ret = state->db->ops->get_default_recv(subreq, state->uuid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get the default ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_get_default_recv(struct tevent_req *req,
                                  uuid_t *uuid)
{
    struct kcm_ccdb_get_default_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_get_default_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (uuid != NULL) {
        /* The caller might supply a NULL dfl to just check if there is
         * some default ccache
         */
        uuid_copy(*uuid, state->uuid);
    }

    return EOK;
}

struct kcm_ccdb_set_default_state {
    struct tevent_context *ev;
    struct kcm_ccdb *db;
    struct cli_creds *client;
    uuid_t uuid;
};

static void kcm_ccdb_set_default_uuid_resolved(struct tevent_req *subreq);
static void kcm_ccdb_set_default_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_set_default_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client,
                                             uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_set_default_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_set_default_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;
    state->ev = ev;
    state->client = client;
    uuid_copy(state->uuid, uuid);

    if (ev == NULL || db == NULL || client == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    if (uuid_is_null(uuid)) {
        /* NULL UUID means to just reset the default to 'no default' */
        subreq = state->db->ops->set_default_send(state,
                                                state->ev,
                                                state->db,
                                                state->client,
                                                state->uuid);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
        tevent_req_set_callback(subreq, kcm_ccdb_set_default_done, req);
    } else {
        /* Otherwise we need to check if the client can access the UUID
         * about to be set as default
         */
        subreq = db->ops->getbyuuid_send(state, ev, db, client, uuid);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
        tevent_req_set_callback(subreq, kcm_ccdb_set_default_uuid_resolved, req);
    }

    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_set_default_uuid_resolved(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_set_default_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_set_default_state);
    errno_t ret;
    bool ok;
    struct kcm_ccache *cc;

    ret = state->db->ops->getbyuuid_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get cache by UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (cc == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "No cache found by UUID\n");
        tevent_req_error(req, ERR_KCM_CC_END);
        return;
    }

    ok = kcm_cc_access(cc, state->client);
    if (!ok) {
        tevent_req_error(req, EACCES);
        return;
    }

    subreq = state->db->ops->set_default_send(state,
                                              state->ev,
                                              state->db,
                                              state->client,
                                              state->uuid);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_set_default_done, req);
}

static void kcm_ccdb_set_default_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_set_default_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_set_default_state);
    errno_t ret;

    ret = state->db->ops->set_default_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set the default ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_set_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct kcm_ccdb_getbyname_state {
    struct kcm_ccdb *db;
    struct cli_creds *client;

    struct kcm_ccache *cc;
};

static void kcm_ccdb_getbyname_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_getbyname_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct kcm_ccdb *db,
                                           struct cli_creds *client,
                                           const char *name)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_getbyname_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_getbyname_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;
    state->client = client;

    if (ev == NULL || db == NULL || client == NULL || name == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = db->ops->getbyname_send(state, ev, db, client, name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_getbyname_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_getbyname_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_getbyname_state);
    errno_t ret;
    bool ok;

    ret = state->db->ops->getbyname_recv(subreq, state, &state->cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get cache by name [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->cc == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "No cache found by name\n");
        tevent_req_done(req);
        return;
    }

    ok = kcm_cc_access(state->cc, state->client);
    if (!ok) {
        tevent_req_error(req, EACCES);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_getbyname_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx,
                                struct kcm_ccache **_cc)
{
    struct kcm_ccdb_getbyname_state *state = tevent_req_data(req,
                                            struct kcm_ccdb_getbyname_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct kcm_ccdb_getbyuuid_state {
    struct kcm_ccdb *db;
    struct cli_creds *client;

    struct kcm_ccache *cc;
};

static void kcm_ccdb_getbyuuid_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_getbyuuid_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct kcm_ccdb *db,
                                           struct cli_creds *client,
                                           uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_getbyuuid_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_getbyuuid_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;
    state->client = client;

    if (ev == NULL || db == NULL || client == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = db->ops->getbyuuid_send(state, ev, db, client, uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_getbyuuid_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_getbyuuid_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_getbyuuid_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_getbyuuid_state);
    errno_t ret;
    bool ok;

    ret = state->db->ops->getbyuuid_recv(subreq, state, &state->cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get cache by UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->cc == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "No cache found by UUID\n");
        tevent_req_done(req);
        return;
    }

    ok = kcm_cc_access(state->cc, state->client);
    if (!ok) {
        tevent_req_error(req, EACCES);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_getbyuuid_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx,
                                struct kcm_ccache **_cc)
{
    struct kcm_ccdb_getbyuuid_state *state = tevent_req_data(req,
                                            struct kcm_ccdb_getbyuuid_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct kcm_ccdb_name_by_uuid_state {
    struct kcm_ccdb *db;
    struct cli_creds *client;

    const char *name;
};

static void kcm_ccdb_name_by_uuid_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_name_by_uuid_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_name_by_uuid_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx,
                            &state,
                            struct kcm_ccdb_name_by_uuid_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;
    state->client = client;

    if (ev == NULL || db == NULL || client == NULL || uuid_is_null(uuid)) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = db->ops->name_by_uuid_send(state, ev, db, client, uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_name_by_uuid_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_name_by_uuid_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_name_by_uuid_state *state = tevent_req_data(req,
                                        struct kcm_ccdb_name_by_uuid_state);
    errno_t ret;

    ret = state->db->ops->name_by_uuid_recv(subreq, state, &state->name);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to resolve cache by UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_name_by_uuid_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   const char **_name)
{
    struct kcm_ccdb_name_by_uuid_state *state = tevent_req_data(req,
                                        struct kcm_ccdb_name_by_uuid_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_name = talloc_steal(mem_ctx, state->name);
    return EOK;
}

struct kcm_ccdb_uuid_by_name_state {
    struct kcm_ccdb *db;
    struct cli_creds *client;

    uuid_t uuid;
};

static void kcm_ccdb_uuid_by_name_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_uuid_by_name_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              const char *name)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_uuid_by_name_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx,
                            &state,
                            struct kcm_ccdb_uuid_by_name_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;
    state->client = client;

    if (ev == NULL || db == NULL || client == NULL || name == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = db->ops->uuid_by_name_send(state, ev, db, client, name);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_uuid_by_name_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_uuid_by_name_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_uuid_by_name_state *state = tevent_req_data(req,
                                        struct kcm_ccdb_uuid_by_name_state);
    errno_t ret;

    ret = state->db->ops->uuid_by_name_recv(subreq, state, state->uuid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to resolve cache by UUID [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_uuid_by_name_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   uuid_t _uuid)
{
    struct kcm_ccdb_uuid_by_name_state *state = tevent_req_data(req,
                                        struct kcm_ccdb_uuid_by_name_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    uuid_copy(_uuid, state->uuid);
    return EOK;
}

struct kcm_ccdb_create_cc_state {
    struct kcm_ccdb *db;
};

static void kcm_ccdb_create_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_create_cc_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct kcm_ccdb *db,
                                           struct cli_creds *client,
                                           struct kcm_ccache *cc)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_create_cc_state *state = NULL;
    errno_t ret;
    bool ok;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_create_cc_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;

    if (ev == NULL || db == NULL || client == NULL || cc == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    ok = kcm_cc_access(cc, client);
    if (!ok) {
        ret = EACCES;
        goto immediate;
    }

    subreq = state->db->ops->create_send(mem_ctx,
                                         ev,
                                         state->db,
                                         client,
                                         cc);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_create_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_create_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_create_cc_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_create_cc_state);
    errno_t ret;

    ret = state->db->ops->create_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_create_cc_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

void kcm_mod_ctx_clear(struct kcm_mod_ctx *mod_ctx)
{
    if (mod_ctx == NULL) {
        return;
    }

    mod_ctx->kdc_offset = INT32_MAX;
}

void kcm_mod_cc(struct kcm_ccache *cc, struct kcm_mod_ctx *mod_ctx)
{
    if (cc == NULL || mod_ctx == NULL) {
        return;
    }

    if (mod_ctx->kdc_offset != INT32_MAX) {
        cc->kdc_offset = mod_ctx->kdc_offset;
    }

}

struct kcm_ccdb_mod_cc_state {
    struct kcm_ccdb *db;
};

static void kcm_ccdb_mod_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_mod_cc_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct kcm_ccdb *db,
                                        struct cli_creds *client,
                                        uuid_t uuid,
                                        struct kcm_mod_ctx *mod_cc)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_mod_cc_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_mod_cc_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;

    if (ev == NULL || db == NULL || client == NULL || mod_cc == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = state->db->ops->mod_send(mem_ctx,
                                      ev,
                                      state->db,
                                      client,
                                      uuid,
                                      mod_cc);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_mod_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_mod_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_mod_cc_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_mod_cc_state);
    errno_t ret;

    ret = state->db->ops->mod_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_mod_cc_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct kcm_ccdb_store_cred_blob_state {
    struct kcm_ccdb *db;
};

static void kcm_ccdb_store_cred_blob_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_store_cred_blob_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct kcm_ccdb *db,
                                                 struct cli_creds *client,
                                                 uuid_t uuid,
                                                 struct sss_iobuf *cred_blob)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_store_cred_blob_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_store_cred_blob_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;

    if (ev == NULL || db == NULL || client == NULL || cred_blob == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = state->db->ops->store_cred_send(mem_ctx,
                                             ev,
                                             state->db,
                                             client,
                                             uuid,
                                             cred_blob);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_store_cred_blob_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_store_cred_blob_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_store_cred_blob_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_store_cred_blob_state);
    errno_t ret;

    ret = state->db->ops->store_cred_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_store_cred_blob_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct kcm_ccdb_delete_cc_state {
    struct tevent_context *ev;
    struct kcm_ccdb *db;
    struct cli_creds *client;
    uuid_t uuid;
};

static void kcm_ccdb_delete_done(struct tevent_req *subreq);
static void kcm_ccdb_delete_get_default_done(struct tevent_req *subreq);
static void kcm_ccdb_delete_default_reset_done(struct tevent_req *subreq);

struct tevent_req *kcm_ccdb_delete_cc_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct kcm_ccdb *db,
                                           struct cli_creds *client,
                                           uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct kcm_ccdb_delete_cc_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct kcm_ccdb_delete_cc_state);
    if (req == NULL) {
        return NULL;
    }
    state->db = db;
    state->ev = ev;
    state->client = client;
    uuid_copy(state->uuid, uuid);

    if (ev == NULL || db == NULL || client == NULL) {
        ret = EINVAL;
        goto immediate;
    }

    subreq = state->db->ops->delete_send(state,
                                         state->ev,
                                         state->db,
                                         state->client,
                                         state->uuid);
    tevent_req_set_callback(subreq, kcm_ccdb_delete_done, req);

    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_ccdb_delete_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_delete_cc_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_delete_cc_state);
    errno_t ret;

    ret = state->db->ops->delete_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to delete ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* The delete operation must also check if the deleted ccache was
     * the default and reset the default if it was
     */
    subreq = state->db->ops->get_default_send(state,
                                              state->ev,
                                              state->db,
                                              state->client);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_delete_get_default_done, req);
}

static void kcm_ccdb_delete_get_default_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_delete_cc_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_delete_cc_state);
    errno_t ret;
    uuid_t dfl_uuid;
    uuid_t null_uuid;

    ret = state->db->ops->get_default_recv(subreq, dfl_uuid);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get the default ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (uuid_compare(dfl_uuid, state->uuid) != 0) {
        /* The ccache about to be deleted was not the default, quit */
        tevent_req_done(req);
        return;
    }

    /* If we deleted the default ccache, reset the default ccache to 'none' */
    uuid_clear(null_uuid);

    subreq = state->db->ops->set_default_send(state,
                                              state->ev,
                                              state->db,
                                              state->client,
                                              null_uuid);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, kcm_ccdb_delete_default_reset_done, req);
}

static void kcm_ccdb_delete_default_reset_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct kcm_ccdb_delete_cc_state *state = tevent_req_data(req,
                                                struct kcm_ccdb_delete_cc_state);
    errno_t ret;

    ret = state->db->ops->set_default_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to NULL the default ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t kcm_ccdb_delete_cc_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

void kcm_debug_uuid(uuid_t uuid)
{
    char dbgbuf[UUID_STR_SIZE];

    if (!(debug_level & SSSDBG_TRACE_ALL) || uuid == NULL) {
        return;
    }

    uuid_unparse(uuid, dbgbuf);
    DEBUG(SSSDBG_TRACE_ALL, "UUID: %s\n", dbgbuf);
}

errno_t kcm_check_name(const char *name, struct cli_creds *client)
{
    char prefix[64];
    size_t prefix_len;

    prefix_len = snprintf(prefix, sizeof(prefix),
                          "%"SPRIuid, cli_creds_get_uid(client));

    if (strncmp(name, prefix, prefix_len) != 0) {
        return ERR_KCM_WRONG_CCNAME_FORMAT;
    }
    return EOK;
}
