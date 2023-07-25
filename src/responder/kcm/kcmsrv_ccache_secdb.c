/*
   SSSD

   KCM Server - ccache storage using libsss_secrets

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
#include "util/secrets/secrets.h"
#include "util/crypto/sss_crypto.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"
#include "responder/kcm/kcmsrv_ccache_be.h"

#define KCM_SECDB_URL        "/kcm/persistent"
#define KCM_SECDB_BASE_FMT    KCM_SECDB_URL"/%"SPRIuid"/"
#define KCM_SECDB_CCACHE_FMT  KCM_SECDB_BASE_FMT"ccache/"
#define KCM_SECDB_DFL_FMT     KCM_SECDB_BASE_FMT"default"

static errno_t sec_get(TALLOC_CTX *mem_ctx,
                       struct sss_sec_req *req,
                       struct sss_iobuf **_buf,
                       char **_datatype)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *datatype;
    uint8_t *data;
    size_t len;
    struct sss_iobuf *buf;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_sec_get(tmp_ctx, req, &data, &len, &datatype);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot retrieve the secret [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    if (strcmp(datatype, "simple") == 0) {
        /* The secret is stored in b64 encoding, we need to decode it first. */
        data = sss_base64_decode(tmp_ctx, (const char*)data, &len);
        if (data == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot decode secret from base64\n");
            ret = EIO;
            goto done;
        }
    }

    buf = sss_iobuf_init_steal(tmp_ctx, data, len);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot init the iobuf\n");
        ret = EIO;
        goto done;
    }

    *_buf = talloc_steal(mem_ctx, buf);
    if (_datatype != NULL) {
        *_datatype = talloc_steal(mem_ctx, datatype);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sec_put(TALLOC_CTX *mem_ctx,
                       struct sss_sec_req *req,
                       struct sss_iobuf *buf)
{
    errno_t ret;

    ret = sss_sec_put(req, sss_iobuf_get_data(buf), sss_iobuf_get_size(buf),
                      SSS_SEC_PLAINTEXT, "binary");
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot write the secret [%d]: %s\n", ret, sss_strerror(ret));
    }

    return ret;
}

static errno_t sec_update(TALLOC_CTX *mem_ctx,
                          struct sss_sec_req *req,
                          struct sss_iobuf *buf)
{
    errno_t ret;

    ret = sss_sec_update(req, sss_iobuf_get_data(buf), sss_iobuf_get_size(buf),
                         SSS_SEC_PLAINTEXT, "binary");
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot write the secret [%d]: %s\n", ret, sss_strerror(ret));
    }

    return ret;
}

static const char *secdb_container_url_create(TALLOC_CTX *mem_ctx,
                                              struct cli_creds *client)
{
    return talloc_asprintf(mem_ctx,
                           KCM_SECDB_CCACHE_FMT,
                           cli_creds_get_uid(client));
}

static const char *secdb_cc_url_create(TALLOC_CTX *mem_ctx,
                                       struct cli_creds *client,
                                       const char *secdb_key)
{
    return talloc_asprintf(mem_ctx,
                           KCM_SECDB_CCACHE_FMT"%s",
                           cli_creds_get_uid(client),
                           secdb_key);
}

static const char *secdb_dfl_url_create(TALLOC_CTX *mem_ctx,
                                        struct cli_creds *client)
{
    return talloc_asprintf(mem_ctx,
                           KCM_SECDB_DFL_FMT,
                           cli_creds_get_uid(client));
}

static errno_t kcm_ccache_to_secdb_kv(TALLOC_CTX *mem_ctx,
                                      struct kcm_ccache *cc,
                                      struct cli_creds *client,
                                      const char **_url,
                                      struct sss_iobuf **_payload)
{
    errno_t ret;
    const char *url;
    const char *key;
    TALLOC_CTX *tmp_ctx;
    struct sss_iobuf *payload;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    key = sec_key_create(tmp_ctx, cc->name, cc->uuid);
    if (key == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create key for %s\n", cc->name);
        ret = ENOMEM;
        goto done;
    }

    url = secdb_cc_url_create(tmp_ctx, client, key);
    if (url == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create URL from %s\n", key);
        ret = ENOMEM;
        goto done;
    }

    ret = kcm_ccache_to_sec_input_binary(mem_ctx, cc, &payload);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert ccache to a secret [%d][%s]\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Created URL %s\n", url);
    *_url = talloc_steal(mem_ctx, url);
    *_payload = talloc_steal(mem_ctx, payload);
done:
    talloc_free(tmp_ctx);
    return ret;
}

struct ccdb_secdb {
    struct sss_sec_ctx *sctx;
};

/* Since with the synchronous database, the database operations are just
 * fake-async wrappers around otherwise sync operations, we don't often
 * need any state structure, unless the _recv() function returns anything,
 * so we use this empty structure instead
 */
struct ccdb_secdb_state {
};

static errno_t secdb_container_url_req(TALLOC_CTX *mem_ctx,
                                       struct sss_sec_ctx *sctx,
                                       struct cli_creds *client,
                                       struct sss_sec_req **_sreq)
{
    const char *url;
    struct sss_sec_req *sreq;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    url = secdb_container_url_create(tmp_ctx, client);
    if (url == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_sec_new_req(tmp_ctx, sctx, url, geteuid(), &sreq);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Created request for URL %s\n", url);
    *_sreq = talloc_steal(mem_ctx, sreq);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t secdb_cc_url_req(TALLOC_CTX *mem_ctx,
                                struct sss_sec_ctx *sctx,
                                struct cli_creds *client,
                                const char *secdb_url,
                                struct sss_sec_req **_sreq)
{
    struct sss_sec_req *sreq;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_sec_new_req(tmp_ctx, sctx, secdb_url, geteuid(), &sreq);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Created request for URL %s\n", secdb_url);
    *_sreq = talloc_steal(mem_ctx, sreq);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t secdb_cc_key_req(TALLOC_CTX *mem_ctx,
                                struct sss_sec_ctx *sctx,
                                struct cli_creds *client,
                                const char *secdb_key,
                                struct sss_sec_req **_sreq)
{
    const char *url;
    struct sss_sec_req *sreq;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    url = secdb_cc_url_create(tmp_ctx, client, secdb_key);
    if (url == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = secdb_cc_url_req(tmp_ctx, sctx, client, url, &sreq);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Created request for URL %s\n", url);
    *_sreq = talloc_steal(mem_ctx, sreq);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t secdb_dfl_url_req(TALLOC_CTX *mem_ctx,
                                 struct sss_sec_ctx *sctx,
                                 struct cli_creds *client,
                                 struct sss_sec_req **_sreq)
{
    const char *url;
    struct sss_sec_req *sreq;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    url = secdb_dfl_url_create(tmp_ctx, client);
    if (url == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_sec_new_req(tmp_ctx, sctx, url, geteuid(), &sreq);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Created request for URL %s\n", url);
    *_sreq = talloc_steal(mem_ctx, sreq);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t key_by_uuid(TALLOC_CTX *mem_ctx,
                           struct sss_sec_ctx *sctx,
                           struct cli_creds *client,
                           uuid_t uuid,
                           char **_key)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char *key_match = NULL;
    char **keys = NULL;
    size_t nkeys;
    struct sss_sec_req *sreq = NULL;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = secdb_container_url_req(tmp_ctx, sctx, client, &sreq);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_sec_list(tmp_ctx, sreq, &keys, &nkeys);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "The container was not found\n");
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    for (size_t i = 0; i < nkeys; i++) {
        if (sec_key_match_uuid(keys[i], uuid)) {
            key_match = keys[i];
            break;
        }
    }

    if (key_match == NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No key matched\n");
        ret = ENOENT;
        goto done;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found key %s\n", key_match);
    *_key = talloc_steal(mem_ctx, key_match);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t key_by_name(TALLOC_CTX *mem_ctx,
                           struct sss_sec_ctx *sctx,
                           struct cli_creds *client,
                           const char *name,
                           char **_key)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char *key_match = NULL;
    char **keys = NULL;
    size_t nkeys;
    struct sss_sec_req *sreq = NULL;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = secdb_container_url_req(tmp_ctx, sctx, client, &sreq);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_sec_list(tmp_ctx, sreq, &keys, &nkeys);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "The container was not found\n");
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    for (size_t i = 0; i < nkeys; i++) {
        if (sec_key_match_name(keys[i], name)) {
            key_match = keys[i];
            break;
        }
    }

    if (key_match == NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No key matched\n");
        ret = ENOENT;
        goto done;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found key %s\n", key_match);
    *_key = talloc_steal(mem_ctx, key_match);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t secdb_get_cc(TALLOC_CTX *mem_ctx,
                            struct sss_sec_ctx *sctx,
                            const char *secdb_key,
                            struct cli_creds *client,
                            struct kcm_ccache **_cc)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct kcm_ccache *cc = NULL;
    struct sss_sec_req *sreq = NULL;
    struct sss_iobuf *ccbuf;
    char *datatype;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = secdb_cc_key_req(tmp_ctx, sctx, client, secdb_key, &sreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot create secdb request [%d][%s]\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sec_get(tmp_ctx, sreq, &ccbuf, &datatype);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot get the secret [%d][%s]\n", ret, sss_strerror(ret));
        goto done;
    }

    if (strcmp(datatype, "binary") == 0) {
        ret = sec_kv_to_ccache_binary(tmp_ctx, secdb_key, ccbuf, client, &cc);
    } else {
        ret = sec_kv_to_ccache_json(tmp_ctx, secdb_key,
                                    (const char *)sss_iobuf_get_data(ccbuf),
                                    client, &cc);
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot convert %s data to ccache "
              "[%d]: %s\n", datatype, ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Fetched the ccache\n");
    *_cc = talloc_steal(mem_ctx, cc);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t ccdb_secdb_init(struct kcm_ccdb *db,
                               struct confdb_ctx *cdb,
                               const char *confdb_service_path)
{
    struct ccdb_secdb *secdb = NULL;
    errno_t ret;
    struct sss_sec_hive_config **kcm_section_quota;
    struct sss_sec_quota_opt dfl_kcm_nest_level = {
        .opt_name = CONFDB_SEC_CONTAINERS_NEST_LEVEL,
        .default_value = DEFAULT_SEC_CONTAINERS_NEST_LEVEL,
    };
    struct sss_sec_quota_opt dfl_kcm_max_secrets = {
        .opt_name = CONFDB_KCM_MAX_CCACHES,
        .default_value = DEFAULT_SEC_KCM_MAX_SECRETS,
    };
    struct sss_sec_quota_opt dfl_kcm_max_uid_secrets = {
        .opt_name = CONFDB_KCM_MAX_UID_CCACHES,
        .default_value = DEFAULT_SEC_KCM_MAX_UID_SECRETS,
    };
    struct sss_sec_quota_opt dfl_kcm_max_payload_size = {
        .opt_name = CONFDB_KCM_MAX_CCACHE_SIZE,
        .default_value = DEFAULT_SEC_KCM_MAX_PAYLOAD_SIZE,
    };


    secdb = talloc_zero(db, struct ccdb_secdb);
    if (secdb == NULL) {
        return ENOMEM;
    }

    kcm_section_quota = talloc_zero_array(secdb,
                                          struct sss_sec_hive_config *,
                                          2);
    if (kcm_section_quota == NULL) {
        talloc_free(secdb);
        return ENOMEM;
    }

    kcm_section_quota[0] = talloc_zero(kcm_section_quota,
                                       struct sss_sec_hive_config);
    if (kcm_section_quota[0] == NULL) {
        talloc_free(secdb);
        return ENOMEM;
    }
    kcm_section_quota[0]->hive_name = "kcm";

    ret = sss_sec_get_quota(cdb,
                            confdb_service_path,
                            &dfl_kcm_nest_level,
                            &dfl_kcm_max_secrets,
                            &dfl_kcm_max_uid_secrets,
                            &dfl_kcm_max_payload_size,
                            &kcm_section_quota[0]->quota);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get KCM global quotas [%d]: %s\n",
              ret, sss_strerror(ret));
        talloc_free(secdb);
        return ret;
    }

    if (kcm_section_quota[0]->quota.max_uid_secrets > 0) {
        /* Even cn=default is considered a secret that adds up to
         * the quota. To avoid off-by-one-confusion, increase
         * the quota by two to 1) account for the cn=default object
         * and 2) always allow writing to cn=defaults even if we
         * are exactly at the quota limit
         */
        kcm_section_quota[0]->quota.max_uid_secrets += 2;
    }

    ret = sss_sec_init(db, kcm_section_quota, &secdb->sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot initialize the security database\n");
        talloc_free(secdb);
        return ret;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "secdb initialized\n");
    db->db_handle = secdb;
    return EOK;
}

struct ccdb_secdb_nextid_state {
    unsigned int nextid;
};

static bool is_in_use(char **keys, size_t nkeys, const char *nextid_name)
{
    for (size_t i = 0; i < nkeys; i++) {
        if (sec_key_match_name(keys[i], nextid_name) == true) {
            return true;
        }
    }

    return false;
}

static struct tevent_req *ccdb_secdb_nextid_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_secdb_nextid_state *state = NULL;
    struct ccdb_secdb *secdb = NULL;
    const int maxtries = 3;
    int numtry;
    errno_t ret;
    struct sss_sec_req *sreq = NULL;
    char **keys = NULL;
    size_t nkeys;
    char *nextid_name = NULL;

    DEBUG(SSSDBG_TRACE_LIBS, "Generating a new ID\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_nextid_state);
    if (req == NULL) {
        return NULL;
    }

    secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    if (secdb == NULL) {
        ret = EIO;
        goto immediate;
    }

    ret = secdb_container_url_req(state, secdb->sctx, client, &sreq);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sss_sec_list(state, sreq, &keys, &nkeys);
    if (ret == ENOENT) {
        keys = NULL;
        nkeys = 0;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot list keys [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    for (numtry = 0; numtry  < maxtries; numtry++) {
        state->nextid = sss_rand() % MAX_CC_NUM;
        nextid_name = talloc_asprintf(state, "%"SPRIuid":%u",
                                      cli_creds_get_uid(client),
                                      state->nextid);
        if (nextid_name == NULL) {
            ret = ENOMEM;
            goto immediate;
        }

        if (!is_in_use(keys, nkeys, nextid_name)) {
            break;
        }
    }

    if (numtry >= maxtries) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to find a random ccache in %d tries\n", numtry);
        ret = EBUSY;
        goto immediate;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_LIBS, "Generated next ID %d\n", state->nextid);
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_secdb_nextid_recv(struct tevent_req *req,
                                    unsigned int *_nextid)
{
    struct ccdb_secdb_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_secdb_nextid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_nextid = state->nextid;
    return EOK;
}

static struct tevent_req *ccdb_secdb_set_default_send(TALLOC_CTX *mem_ctx,
                                                      struct tevent_context *ev,
                                                      struct kcm_ccdb *db,
                                                      struct cli_creds *client,
                                                      uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_secdb_state *state = NULL;
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    errno_t ret;
    char uuid_str[UUID_STR_SIZE];
    struct sss_sec_req *sreq = NULL;
    struct sss_iobuf *iobuf;
    char *cur_default;

    uuid_unparse(uuid, uuid_str);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Setting the default ccache to %s\n", uuid_str);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_state);
    if (req == NULL) {
        return NULL;
    }

    ret = secdb_dfl_url_req(state, secdb->sctx, client, &sreq);
    if (ret != EOK) {
        goto immediate;
    }

    iobuf = sss_iobuf_init_readonly(state,
                                    (const uint8_t *) uuid_str,
                                    UUID_STR_SIZE);
    if (iobuf == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    ret = sss_sec_get(state, sreq, (uint8_t**)&cur_default, NULL, NULL);
    if (ret == ENOENT) {
        ret = sec_put(state, sreq, iobuf);
    } else if (ret == EOK) {
        ret = sec_update(state, sreq, iobuf);
    }

    if (ret != EOK) {
        goto immediate;
    }

    ret = EOK;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Set the default ccache\n");
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_secdb_set_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ccdb_secdb_get_default_state {
    uuid_t uuid;
};

static struct tevent_req *ccdb_secdb_get_default_send(TALLOC_CTX *mem_ctx,
                                                      struct tevent_context *ev,
                                                      struct kcm_ccdb *db,
                                                      struct cli_creds *client)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_get_default_state *state = NULL;
    errno_t ret;
    struct sss_sec_req *sreq = NULL;
    struct sss_iobuf *dfl_iobuf = NULL;
    size_t uuid_size;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Getting the default ccache\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_get_default_state);
    if (req == NULL) {
        return NULL;
    }

    ret = secdb_dfl_url_req(state, secdb->sctx, client, &sreq);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sec_get(state, sreq, &dfl_iobuf, NULL);
    if (ret == ENOENT) {
        uuid_clear(state->uuid);
        ret = EOK;
        goto immediate;
    } else if (ret != EOK) {
        goto immediate;
    }

    uuid_size = sss_iobuf_get_size(dfl_iobuf);
    if (uuid_size != UUID_STR_SIZE) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected UUID size %zu\n", uuid_size);
        ret = EIO;
        goto immediate;
    }

    uuid_parse((const char *) sss_iobuf_get_data(dfl_iobuf), state->uuid);
    DEBUG(SSSDBG_TRACE_INTERNAL, "Got the default ccache\n");
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

static errno_t ccdb_secdb_get_default_recv(struct tevent_req *req,
                                           uuid_t uuid)
{
    struct ccdb_secdb_get_default_state *state = tevent_req_data(req,
                                                struct ccdb_secdb_get_default_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    uuid_copy(uuid, state->uuid);
    return EOK;
}

struct ccdb_secdb_list_state {
    uuid_t *uuid_list;
};

static struct tevent_req *ccdb_secdb_list_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_list_state *state = NULL;
    errno_t ret;
    char **keys = NULL;
    size_t nkeys;
    struct sss_sec_req *sreq = NULL;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Listing all ccaches\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_list_state);
    if (req == NULL) {
        return NULL;
    }

    ret = secdb_container_url_req(state, secdb->sctx, client, &sreq);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sss_sec_list(state, sreq, &keys, &nkeys);
    if (ret == ENOENT) {
        nkeys = 0;
        /* Fall through and return an empty list */
    } else if (ret != EOK) {
        goto immediate;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found %zu ccaches\n", nkeys);

    state->uuid_list = talloc_array(state, uuid_t, nkeys + 1);
    if (state->uuid_list == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    for (size_t i = 0; i < nkeys; i++) {
        ret = sec_key_get_uuid(keys[i],
                               state->uuid_list[i]);
        if (ret != EOK) {
            goto immediate;
        }
    }
    /* Sentinel */
    uuid_clear(state->uuid_list[nkeys]);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Listing all caches done\n");
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

static errno_t ccdb_secdb_list_recv(struct tevent_req *req,
                                  TALLOC_CTX *mem_ctx,
                                  uuid_t **_uuid_list)
{
    struct ccdb_secdb_list_state *state = tevent_req_data(req,
                                                struct ccdb_secdb_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_uuid_list = talloc_steal(mem_ctx, state->uuid_list);
    return EOK;
}

struct ccdb_secdb_getbyuuid_state {
    struct kcm_ccache *cc;
};

static struct tevent_req *ccdb_secdb_getbyuuid_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client,
                                                    uuid_t uuid)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_getbyuuid_state *state = NULL;
    errno_t ret;
    char *secdb_key = NULL;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Getting ccache by UUID\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_getbyuuid_state);
    if (req == NULL) {
        return NULL;
    }

    ret = key_by_uuid(state, secdb->sctx, client, uuid, &secdb_key);
    if (ret == ENOENT) {
        state->cc = NULL;
        ret = EOK;
        goto immediate;
    } else if (ret != EOK) {
        goto immediate;
    }

    ret = secdb_get_cc(state, secdb->sctx, secdb_key, client, &state->cc);
    if (ret != EOK) {
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Got ccache by UUID\n");
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

static errno_t ccdb_secdb_getbyuuid_recv(struct tevent_req *req,
                                         TALLOC_CTX *mem_ctx,
                                         struct kcm_ccache **_cc)
{
    struct ccdb_secdb_getbyuuid_state *state = tevent_req_data(req,
                                            struct ccdb_secdb_getbyuuid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct ccdb_secdb_getbyname_state {
    struct kcm_ccache *cc;
};

static struct tevent_req *ccdb_secdb_getbyname_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client,
                                                    const char *name)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_getbyname_state *state = NULL;
    errno_t ret;
    char *secdb_key = NULL;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Getting ccache by name\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_getbyname_state);
    if (req == NULL) {
        return NULL;
    }

    ret = key_by_name(state, secdb->sctx, client, name, &secdb_key);
    if (ret == ENOENT) {
        state->cc = NULL;
        ret = EOK;
        goto immediate;
    } else if (ret != EOK) {
        goto immediate;
    }

    ret = secdb_get_cc(state, secdb->sctx, secdb_key, client, &state->cc);
    if (ret != EOK) {
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Got ccache by name\n");
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

static errno_t ccdb_secdb_getbyname_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_secdb_getbyname_state *state = tevent_req_data(req,
                                                struct ccdb_secdb_getbyname_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}


struct ccdb_secdb_name_by_uuid_state {
    const char *name;
};

struct tevent_req *ccdb_secdb_name_by_uuid_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct kcm_ccdb *db,
                                                struct cli_creds *client,
                                                uuid_t uuid)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_name_by_uuid_state *state = NULL;
    errno_t ret;
    char *key;
    const char *name;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Translating UUID to name\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_name_by_uuid_state);
    if (req == NULL) {
        return NULL;
    }

    ret = key_by_uuid(state, secdb->sctx, client, uuid, &key);
    if (ret == ENOENT) {
        ret = ERR_NO_CREDS;
        goto immediate;
    } else if (ret != EOK) {
        goto immediate;
    }

    name = sec_key_get_name(key);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Malformed key, cannot get name\n");
        goto immediate;
    }

    state->name = talloc_strdup(state, name);
    if (state->name == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Got ccache by UUID\n");
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

errno_t ccdb_secdb_name_by_uuid_recv(struct tevent_req *req,
                                     TALLOC_CTX *sec_ctx,
                                     const char **_name)
{
    struct ccdb_secdb_name_by_uuid_state *state = tevent_req_data(req,
                                                struct ccdb_secdb_name_by_uuid_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_name = talloc_steal(sec_ctx, state->name);
    return EOK;
}

struct ccdb_secdb_uuid_by_name_state {
    uuid_t uuid;
};

struct tevent_req *ccdb_secdb_uuid_by_name_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct kcm_ccdb *db,
                                                struct cli_creds *client,
                                                const char *name)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_uuid_by_name_state *state = NULL;
    errno_t ret;
    char *key;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Translating name to UUID\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_uuid_by_name_state);
    if (req == NULL) {
        return NULL;
    }

    ret = key_by_name(state, secdb->sctx, client, name, &key);
    if (ret == ENOENT) {
        ret = ERR_NO_CREDS;
        goto immediate;
    } else if (ret != EOK) {
        goto immediate;
    }

    ret = sec_key_get_uuid(key, state->uuid);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "Malformed key, cannot get UUID\n");
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Got ccache by UUID\n");
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

static errno_t ccdb_secdb_uuid_by_name_recv(struct tevent_req *req,
                                            TALLOC_CTX *sec_ctx,
                                            uuid_t _uuid)
{
    struct ccdb_secdb_uuid_by_name_state *state = tevent_req_data(req,
                                                struct ccdb_secdb_uuid_by_name_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    uuid_copy(_uuid, state->uuid);
    return EOK;
}


static struct tevent_req *ccdb_secdb_create_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct kcm_ccdb *db,
                                                 struct cli_creds *client,
                                                 struct kcm_ccache *cc)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_state *state = NULL;
    errno_t ret;
    struct sss_sec_req *container_req = NULL;
    struct sss_sec_req *ccache_req = NULL;
    const char *url;
    struct sss_iobuf *ccache_payload;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Creating ccache storage for %s\n", cc->name);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_state);
    if (req == NULL) {
        return NULL;
    }

    /* Do the encoding asap so that if we fail, we don't even attempt any
     * writes */
    ret = kcm_ccache_to_secdb_kv(state, cc, client, &url, &ccache_payload);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert cache %s to JSON [%d]: %s\n",
              cc->name, ret, sss_strerror(ret));
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Creating the ccache container\n");
    ret = secdb_container_url_req(state, secdb->sctx, client, &container_req);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sss_sec_create_container(container_req);
    if (ret == EEXIST) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Container already exists, ignoring\n");
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create the ccache container\n");
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "ccache container created\n");
    DEBUG(SSSDBG_TRACE_INTERNAL, "creating empty ccache payload\n");

    ret = secdb_cc_url_req(state, secdb->sctx, client, url, &ccache_req);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sec_put(state, ccache_req, ccache_payload);
    if (ret != EOK) {
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "payload created\n");
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

static errno_t ccdb_secdb_create_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_secdb_mod_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              uuid_t uuid,
                                              struct kcm_mod_ctx *mod_cc)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_state *state = NULL;
    errno_t ret;
    char *secdb_key = NULL;
    struct kcm_ccache *cc = NULL;
    struct sss_iobuf *payload = NULL;
    struct sss_sec_req *sreq = NULL;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Modifying ccache\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_state);
    if (req == NULL) {
        return NULL;
    }

    ret = key_by_uuid(state, secdb->sctx, client, uuid, &secdb_key);
    if (ret == ENOENT) {
        ret = ERR_NO_CREDS;
        goto immediate;
    } else if (ret != EOK) {
        goto immediate;
    }

    ret = secdb_get_cc(state, secdb->sctx, secdb_key, client, &cc);
    if (ret != EOK) {
        goto immediate;
    }

    ret = kcm_mod_cc(cc, mod_cc);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot modify ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    ret = kcm_ccache_to_sec_input_binary(state, cc, &payload);
    if (ret != EOK) {
        goto immediate;
    }

    ret = secdb_cc_key_req(state, secdb->sctx, client, secdb_key, &sreq);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sec_update(state, sreq, payload);
    if (ret != EOK) {
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

static errno_t ccdb_secdb_mod_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_secdb_store_cred_send(TALLOC_CTX *mem_ctx,
                                                     struct tevent_context *ev,
                                                     struct kcm_ccdb *db,
                                                     struct cli_creds *client,
                                                     uuid_t uuid,
                                                     struct sss_iobuf *cred_blob)
{
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct tevent_req *req = NULL;
    struct ccdb_secdb_state *state = NULL;
    char *secdb_key = NULL;
    struct kcm_ccache *cc = NULL;
    struct sss_iobuf *payload = NULL;
    struct sss_sec_req *sreq = NULL;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Storing creds in ccache\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_state);
    if (req == NULL) {
        return NULL;
    }

    ret = key_by_uuid(state, secdb->sctx, client, uuid, &secdb_key);
    if (ret == ENOENT) {
        ret = ERR_NO_CREDS;
        goto immediate;
    } else if (ret != EOK) {
        goto immediate;
    }

    ret = secdb_get_cc(state, secdb->sctx, secdb_key, client, &cc);
    if (ret != EOK) {
        goto immediate;
    }

    ret = kcm_cc_store_cred_blob(cc, cred_blob);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store credentials to ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    ret = kcm_ccache_to_sec_input_binary(state, cc, &payload);
    if (ret != EOK) {
        goto immediate;
    }

    ret = secdb_cc_key_req(state, secdb->sctx, client, secdb_key, &sreq);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sec_update(state, sreq, payload);
    if (ret != EOK) {
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

static errno_t ccdb_secdb_store_cred_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_secdb_delete_send(TALLOC_CTX *mem_ctx,
                                                 struct tevent_context *ev,
                                                 struct kcm_ccdb *db,
                                                 struct cli_creds *client,
                                                 uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_secdb_state *state = NULL;
    struct ccdb_secdb *secdb = talloc_get_type(db->db_handle, struct ccdb_secdb);
    struct sss_sec_req *container_req = NULL;
    struct sss_sec_req *sreq = NULL;
    char *secdb_key = NULL;
    char **keys = NULL;
    size_t nkeys;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Deleting ccache\n");

    req = tevent_req_create(mem_ctx, &state, struct ccdb_secdb_state);
    if (req == NULL) {
        return NULL;
    }

    ret = secdb_container_url_req(state, secdb->sctx, client, &container_req);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sss_sec_list(state, container_req, &keys, &nkeys);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No ccaches to delete\n");
        goto immediate;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Found %zu ccaches\n", nkeys);

    if (nkeys == 0) {
        ret = EOK;
        goto immediate;
    }

    ret = key_by_uuid(state, secdb->sctx, client, uuid, &secdb_key);
    if (ret == ENOENT) {
        ret = ERR_NO_CREDS;
        goto immediate;
    } else if (ret != EOK) {
        goto immediate;
    }

    ret = secdb_cc_key_req(state, secdb->sctx, client, secdb_key, &sreq);
    if (ret != EOK) {
        goto immediate;
    }

    ret = sss_sec_delete(sreq);
    if (ret != EOK) {
        goto immediate;
    }

    if (nkeys > 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "There are other ccaches, done\n");
        ret = EOK;
        goto immediate;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "Removing ccache container\n");

    ret = sss_sec_delete(container_req);
    if (ret != EOK) {
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

static errno_t ccdb_secdb_delete_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

const struct kcm_ccdb_ops ccdb_secdb_ops = {
    .init = ccdb_secdb_init,

    .nextid_send = ccdb_secdb_nextid_send,
    .nextid_recv = ccdb_secdb_nextid_recv,

    .set_default_send = ccdb_secdb_set_default_send,
    .set_default_recv = ccdb_secdb_set_default_recv,

    .get_default_send = ccdb_secdb_get_default_send,
    .get_default_recv = ccdb_secdb_get_default_recv,

    .list_send = ccdb_secdb_list_send,
    .list_recv = ccdb_secdb_list_recv,

    .getbyname_send = ccdb_secdb_getbyname_send,
    .getbyname_recv = ccdb_secdb_getbyname_recv,

    .getbyuuid_send = ccdb_secdb_getbyuuid_send,
    .getbyuuid_recv = ccdb_secdb_getbyuuid_recv,

    .name_by_uuid_send = ccdb_secdb_name_by_uuid_send,
    .name_by_uuid_recv = ccdb_secdb_name_by_uuid_recv,

    .uuid_by_name_send = ccdb_secdb_uuid_by_name_send,
    .uuid_by_name_recv = ccdb_secdb_uuid_by_name_recv,

    .create_send = ccdb_secdb_create_send,
    .create_recv = ccdb_secdb_create_recv,

    .mod_send = ccdb_secdb_mod_send,
    .mod_recv = ccdb_secdb_mod_recv,

    .store_cred_send = ccdb_secdb_store_cred_send,
    .store_cred_recv = ccdb_secdb_store_cred_recv,

    .delete_send = ccdb_secdb_delete_send,
    .delete_recv = ccdb_secdb_delete_recv,
};
