/*
   SSSD

   KCM Server - ccache storage in sssd-secrets

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

#include <stdio.h>
#include <talloc.h>
#include <jansson.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/tev_curl.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"
#include "responder/kcm/kcmsrv_ccache_be.h"

#ifndef SSSD_SECRETS_SOCKET
#define SSSD_SECRETS_SOCKET VARDIR"/run/secrets.socket"
#endif  /* SSSD_SECRETS_SOCKET */

#ifndef SEC_TIMEOUT
#define SEC_TIMEOUT         5
#endif /* SEC_TIMEOUT */

/* Just to keep the name of the ccache readable */
#define MAX_CC_NUM          99999

/* Compat definition of json_array_foreach for older systems */
#ifndef json_array_foreach
#define json_array_foreach(array, idx, value) \
    for(idx = 0; \
            idx < json_array_size(array) && (value = json_array_get(array, idx)); \
            idx++)
#endif

static const char *find_by_name(const char **sec_key_list,
                                const char *name)
{
    const char *sec_name = NULL;

    if (sec_key_list == NULL) {
        return NULL;
    }

    for (int i = 0; sec_key_list[i]; i++) {
        if (sec_key_match_name(sec_key_list[i], name)) {
            sec_name = sec_key_list[i];
            break;
        }
    }

    return sec_name;
}

static const char *find_by_uuid(const char **sec_key_list,
                                uuid_t uuid)
{
    const char *sec_name = NULL;

    if (sec_key_list == NULL) {
        return NULL;
    }

    for (int i = 0; sec_key_list[i]; i++) {
        if (sec_key_match_uuid(sec_key_list[i], uuid)) {
            sec_name = sec_key_list[i];
            break;
        }
    }

    return sec_name;
}

static const char *sec_headers[] = {
    "Content-type: application/octet-stream",
    NULL,
};

struct ccdb_sec {
    struct tcurl_ctx *tctx;
};

static errno_t http2errno(int http_code)
{
    if (http_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "HTTP request returned %d\n", http_code);
    }

    switch (http_code) {
    case 200:
        return EOK;
    case 404:
        return ERR_NO_CREDS;
    case 400:
        return ERR_INPUT_PARSE;
    case 403:
        return EACCES;
    case 409:
        return EEXIST;
    case 413:
        return E2BIG;
    case 507:
        return ENOSPC;
    }

    return EIO;
}

/*
 * Helper request to list all UUID+name pairs
 */
struct sec_list_state {
    const char **sec_key_list;
    size_t sec_key_list_len;
};

static void sec_list_done(struct tevent_req *subreq);
static errno_t sec_list_parse(struct sss_iobuf *outbuf,
                              TALLOC_CTX *mem_ctx,
                              const char ***_list,
                              size_t *_list_len);

static struct tevent_req *sec_list_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct ccdb_sec *secdb,
                                        struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sec_list_state *state = NULL;
    errno_t ret;
    const char *container_url;

    req = tevent_req_create(mem_ctx, &state, struct sec_list_state);
    if (req == NULL) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Listing all ccaches in the secrets store\n");
    container_url = sec_container_url_create(state, client);
    if (container_url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = tcurl_http_send(state, ev, secdb->tctx,
                             TCURL_HTTP_GET,
                             SSSD_SECRETS_SOCKET,
                             container_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, sec_list_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sec_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sec_list_state *state = tevent_req_data(req,
                                                struct sec_list_state);
    struct sss_iobuf *outbuf;
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, &outbuf);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "list HTTP request failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code == 404) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Nothing to list\n");
        /* If no ccaches are found, return an empty list */
        state->sec_key_list = talloc_zero_array(state, const char *, 1);
        if (state->sec_key_list == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
    } else if (http_code == 200) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Found %zu items\n", state->sec_key_list_len);
        ret = sec_list_parse(outbuf, state,
                             &state->sec_key_list,
                             &state->sec_key_list_len);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
    } else {
        tevent_req_error(req, http2errno(http_code));
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "list done\n");
    tevent_req_done(req);
}

static errno_t sec_list_parse(struct sss_iobuf *outbuf,
                              TALLOC_CTX *mem_ctx,
                              const char ***_list,
                              size_t *_list_len)
{
    json_t *root;
    uint8_t *sec_http_list;
    json_error_t error;
    json_t *element;
    errno_t ret;
    int ok;
    size_t idx;
    const char **list = NULL;
    size_t list_len;

    sec_http_list = sss_iobuf_get_data(outbuf);
    if (sec_http_list == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No data in output buffer?\n");
        return EINVAL;
    }

    root = json_loads((const char *) sec_http_list, 0, &error);
    if (root == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "Failed to parse JSON payload on line %d: %s\n",
                error.line, error.text);
        return ERR_JSON_DECODING;
    }

    ok = json_is_array(root);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "list reply is not an object.\n");
        ret = ERR_JSON_DECODING;
        goto done;
    }

    list_len = json_array_size(root);
    list = talloc_zero_array(mem_ctx, const char *, list_len + 1);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    json_array_foreach(root, idx, element) {
        list[idx] = talloc_strdup(list, json_string_value(element));
        if (list[idx] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
    *_list = list;
    *_list_len = list_len;
done:
    if (ret != EOK) {
        talloc_free(list);
    }
    json_decref(root);
    return ret;
}

static errno_t sec_list_recv(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             const char ***_sec_key_list,
                             size_t *_sec_key_list_len)

{
    struct sec_list_state *state = tevent_req_data(req,
                                                struct sec_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_sec_key_list != NULL) {
        *_sec_key_list = talloc_steal(mem_ctx, state->sec_key_list);
    }
    if (_sec_key_list_len != NULL) {
        *_sec_key_list_len = state->sec_key_list_len;
    }
    return EOK;
}

/*
 * Helper request to get a ccache by key
 */
struct sec_get_state {
    const char *sec_key;
    struct cli_creds *client;

    struct kcm_ccache *cc;
};

static void sec_get_done(struct tevent_req *subreq);

static struct tevent_req *sec_get_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct ccdb_sec *secdb,
                                       struct cli_creds *client,
                                       const char *sec_key)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sec_get_state *state = NULL;
    errno_t ret;
    const char *cc_url;

    req = tevent_req_create(mem_ctx, &state, struct sec_get_state);
    if (req == NULL) {
        return NULL;
    }
    state->sec_key = sec_key;
    state->client = client;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Retrieving ccache %s\n", sec_key);

    cc_url = sec_cc_url_create(state, state->client, state->sec_key);
    if (cc_url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = tcurl_http_send(state,
                             ev,
                             secdb->tctx,
                             TCURL_HTTP_GET,
                             SSSD_SECRETS_SOCKET,
                             cc_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, sec_get_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sec_get_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sec_get_state *state = tevent_req_data(req,
                                                struct sec_get_state);
    struct sss_iobuf *outbuf;
    const char *sec_value;
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, &outbuf);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "GET HTTP request failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE,
              "GET operation returned HTTP error %d\n", http_code);
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    sec_value = (const char *) sss_iobuf_get_data(outbuf);
    if (sec_value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No data in output buffer\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    ret = sec_kv_to_ccache(state,
                           state->sec_key,
                           sec_value,
                           state->client,
                           &state->cc);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot convert JSON keyval to ccache blob [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "GET done\n");
    tevent_req_done(req);
}

static errno_t sec_get_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct kcm_ccache **_cc)
{
    struct sec_get_state *state = tevent_req_data(req, struct sec_get_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

/*
 * Helper request to get a ccache name or ID
 */
struct sec_get_ccache_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;
    const char *name;
    uuid_t uuid;

    const char *sec_key;

    struct kcm_ccache *cc;
};

static void sec_get_ccache_list_done(struct tevent_req *subreq);
static void sec_get_ccache_done(struct tevent_req *subreq);

static struct tevent_req *sec_get_ccache_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct ccdb_sec *secdb,
                                              struct cli_creds *client,
                                              const char *name,
                                              uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sec_get_ccache_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sec_get_ccache_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    state->name = name;
    uuid_copy(state->uuid, uuid);

    if ((name == NULL && uuid_is_null(uuid))
            || (name != NULL && !uuid_is_null(uuid))) {
        DEBUG(SSSDBG_OP_FAILURE, "Expected one of name, uuid to be set\n");
        ret = EINVAL;
        goto immediate;
    }

    subreq = sec_list_send(state, ev, secdb, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, sec_get_ccache_list_done, req);
    return req;


immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sec_get_ccache_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sec_get_ccache_state *state = tevent_req_data(req,
                                                struct sec_get_ccache_state);
    const char **sec_key_list;

    ret = sec_list_recv(subreq, state, &sec_key_list, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot list keys [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->name != NULL) {
        state->sec_key = find_by_name(sec_key_list, state->name);
    } else {
        state->sec_key = find_by_uuid(sec_key_list, state->uuid);
    }

    if (state->sec_key == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot find item in the ccache list\n");
        /* Don't error out, just return an empty list */
        tevent_req_done(req);
        return;
    }

    subreq = sec_get_send(state,
                          state->ev,
                          state->secdb,
                          state->client,
                          state->sec_key);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sec_get_ccache_done, req);
}

static void sec_get_ccache_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct sec_get_ccache_state *state = tevent_req_data(req,
                                                struct sec_get_ccache_state);

    ret = sec_get_recv(subreq, state, &state->cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot resolve key to ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sec_get_ccache_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   struct kcm_ccache **_cc)
{
    struct sec_get_ccache_state *state = tevent_req_data(req,
                                                struct sec_get_ccache_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

/*
 * The actual sssd-secrets back end
 */
static errno_t ccdb_sec_init(struct kcm_ccdb *db)
{
    struct ccdb_sec *secdb = NULL;

    secdb = talloc_zero(db, struct ccdb_sec);
    if (secdb == NULL) {
        return ENOMEM;
    }

    secdb->tctx = tcurl_init(secdb, db->ev);
    if (secdb->tctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot initialize tcurl\n");
        talloc_zfree(secdb);
        return ENOMEM;
   }

    /* We just need the random numbers to generate pseudo-random ccache names
     * and avoid conflicts */
    srand(time(NULL));

    db->db_handle = secdb;
    return EOK;
}

/*
 * Helper request to get a ccache by key
 */
struct sec_patch_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;

    const char *sec_key_url;
    struct sss_iobuf *sec_value;
};

static void sec_patch_del_done(struct tevent_req *subreq);
static void sec_patch_put_done(struct tevent_req *subreq);

static struct tevent_req *sec_patch_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct ccdb_sec *secdb,
                                         struct cli_creds *client,
                                         const char *sec_key_url,
                                         struct sss_iobuf *sec_value)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sec_patch_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sec_patch_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    state->sec_key_url = sec_key_url;
    state->sec_value = sec_value;

    subreq = tcurl_http_send(state, state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_DELETE,
                             SSSD_SECRETS_SOCKET,
                             state->sec_key_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, sec_patch_del_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sec_patch_del_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sec_patch_state *state = tevent_req_data(req,
                                                struct sec_patch_state);
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot delete key [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code == 404) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Key %s does not exist, moving on\n", state->sec_key_url);
    } else if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Adding new payload\n");

    subreq = tcurl_http_send(state,
                             state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_PUT,
                             SSSD_SECRETS_SOCKET,
                             state->sec_key_url,
                             sec_headers,
                             state->sec_value,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sec_patch_put_done, req);
}

static void sec_patch_put_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sec_patch_state *state = tevent_req_data(req,
                                                struct sec_patch_state);
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot put new value [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add the payload\n");
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "payload created\n");
    tevent_req_done(req);
}


static errno_t sec_patch_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* The operations between the KCM and sssd-secrets */

struct ccdb_sec_nextid_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;

    unsigned int nextid;
    char *nextid_name;

    int maxtries;
    int numtry;
};

static errno_t ccdb_sec_nextid_generate(struct tevent_req *req);
static void ccdb_sec_nextid_list_done(struct tevent_req *subreq);

/* Generate a unique ID */
/* GET the name from secrets, if doesn't exist, OK, if exists, try again */
static struct tevent_req *ccdb_sec_nextid_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_sec_nextid_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_nextid_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;

    state->maxtries = 3;
    state->numtry = 0;

    ret = ccdb_sec_nextid_generate(req);
    if (ret != EOK) {
        goto immediate;
    }

    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_sec_nextid_generate(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_nextid_state);

    if (state->numtry >= state->maxtries) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to find a random ccache in %d tries\n", state->numtry);
        return EBUSY;
    }

    state->nextid = rand() % MAX_CC_NUM;
    state->nextid_name = talloc_asprintf(state, "%"SPRIuid":%u",
                                         cli_creds_get_uid(state->client),
                                         state->nextid);
    if (state->nextid_name == NULL) {
        return ENOMEM;
    }

    subreq = sec_list_send(state, state->ev, state->secdb, state->client);
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ccdb_sec_nextid_list_done, req);

    state->numtry++;
    return EOK;
}

static void ccdb_sec_nextid_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_nextid_state);
    const char **sec_key_list;
    size_t sec_key_list_len;
    size_t i;

    ret = sec_list_recv(subreq, state, &sec_key_list, &sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot list keys [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    for (i = 0; i < sec_key_list_len; i++) {
        if (sec_key_match_name(sec_key_list[i], state->nextid_name) == true) {
            break;
        }
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          "Failed to find a random key, trying again..\n");
    if (i < sec_key_list_len) {
        /* Try again */
        ret = ccdb_sec_nextid_generate(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Generated new ccache name %u\n", state->nextid);
    tevent_req_done(req);
}

static errno_t ccdb_sec_nextid_recv(struct tevent_req *req,
                                    unsigned int *_nextid)
{
    struct ccdb_sec_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_nextid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_nextid = state->nextid;
    return EOK;
}

/* IN:  HTTP PUT $base/default -d 'uuid' */
/* We chose only UUID here to avoid issues later with renaming */
struct ccdb_sec_set_default_state {
};

static void ccdb_sec_set_default_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_set_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client,
                                                    uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_set_default_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    struct sss_iobuf *uuid_iobuf;
    errno_t ret;
    const char *url;
    char uuid_str[UUID_STR_SIZE];

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_set_default_state);
    if (req == NULL) {
        return NULL;
    }

    uuid_unparse(uuid, uuid_str);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Setting the default ccache to %s\n", uuid_str);

    url = sec_dfl_url_create(state, client);
    if (url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    uuid_iobuf = sss_iobuf_init_readonly(state,
                                         (uint8_t *) uuid_str,
                                         UUID_STR_SIZE);
    if (uuid_iobuf == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = sec_patch_send(state, ev, secdb, client, url, uuid_iobuf);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_set_default_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_set_default_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sec_patch_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sec_patch request failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Set the default ccache\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_set_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* IN:  HTTP GET $base/default  */
/* OUT: uuid */
struct ccdb_sec_get_default_state {
    uuid_t uuid;
};

static void ccdb_sec_get_default_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_get_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_get_default_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    const char *url;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_get_default_state);
    if (req == NULL) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Getting the default ccache\n");
    url = sec_dfl_url_create(state, client);
    if (url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = tcurl_http_send(state, ev, secdb->tctx,
                             TCURL_HTTP_GET,
                             SSSD_SECRETS_SOCKET,
                             url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_get_default_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_get_default_done(struct tevent_req *subreq)
{
    errno_t ret;
    int http_code;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ccdb_sec_get_default_state *state = tevent_req_data(req,
                                                struct ccdb_sec_get_default_state);
    struct sss_iobuf *outbuf;
    size_t uuid_size;

    ret = tcurl_http_recv(state, subreq, &http_code, &outbuf);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Communication with the secrets responder failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code == 404) {
        /* Return a NULL uuid */
        uuid_clear(state->uuid);
        tevent_req_done(req);
        return;
    } else if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    uuid_size = sss_iobuf_get_len(outbuf);
    if (uuid_size != UUID_STR_SIZE) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected UUID size %zu\n", uuid_size);
        tevent_req_error(req, EIO);
        return;
    }

    uuid_parse((const char *) sss_iobuf_get_data(outbuf), state->uuid);
    DEBUG(SSSDBG_TRACE_INTERNAL, "Got the default ccache\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_get_default_recv(struct tevent_req *req,
                                         uuid_t uuid)
{
    struct ccdb_sec_get_default_state *state = tevent_req_data(req,
                                                struct ccdb_sec_get_default_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    uuid_copy(uuid, state->uuid);
    return EOK;
}

/* HTTP GET $base/ccache/  */
/* OUT: a list of <uuid:name, uuid:name> */
struct ccdb_sec_list_state {
    uuid_t *uuid_list;
};

static void ccdb_sec_list_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_list_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_list_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_list_state);
    if (req == NULL) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Listing all ccaches\n");

    subreq = sec_list_send(state, ev, secdb, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_list_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_list_state *state = tevent_req_data(req,
                                                struct ccdb_sec_list_state);
    const char **sec_key_list;
    size_t sec_key_list_len;

    ret = sec_list_recv(subreq, state, &sec_key_list, &sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Communication with the secrets responder failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Found %zu ccaches\n", sec_key_list_len);

    state->uuid_list = talloc_array(state, uuid_t, sec_key_list_len + 1);
    if (state->uuid_list == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    for (size_t i = 0; i < sec_key_list_len; i++) {
        ret = sec_key_get_uuid(sec_key_list[i],
                               state->uuid_list[i]);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
    }
    /* Sentinel */
    uuid_clear(state->uuid_list[sec_key_list_len]);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Listing all caches done\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_list_recv(struct tevent_req *req,
                                  TALLOC_CTX *mem_ctx,
                                  uuid_t **_uuid_list)
{
    struct ccdb_sec_list_state *state = tevent_req_data(req,
                                                struct ccdb_sec_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_uuid_list = talloc_steal(mem_ctx, state->uuid_list);
    return EOK;
}

struct ccdb_sec_getbyuuid_state {
    struct kcm_ccache *cc;
};


/* HTTP GET $base/ccache/  */
/* OUT: a list of <uuid:name, uuid:name> */
/* for each item in list, compare with the uuid: portion */
/* HTTP GET $base/ccache/uuid:name  */
/* return result */
static void ccdb_sec_getbyuuid_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_getbyuuid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  uuid_t uuid)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_getbyuuid_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_getbyuuid_state);
    if (req == NULL) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Getting ccache by UUID\n");

    subreq = sec_get_ccache_send(state, ev, secdb, client, NULL, uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_getbyuuid_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_getbyuuid_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_getbyuuid_state *state = tevent_req_data(req,
                                            struct ccdb_sec_getbyuuid_state);

    ret = sec_get_ccache_recv(subreq, state, &state->cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot retrieve the ccache [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Got ccache by UUID\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_getbyuuid_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_sec_getbyuuid_state *state = tevent_req_data(req,
                                            struct ccdb_sec_getbyuuid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

/* HTTP GET $base/ccache/  */
/* OUT: a list of <uuid:name, uuid:name> */
/* for each item in list, compare with the :name portion */
/* HTTP GET $base/ccache/uuid:name  */
/* return result */
struct ccdb_sec_getbyname_state {
    struct kcm_ccache *cc;
};

static void ccdb_sec_getbyname_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_getbyname_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  const char *name)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_getbyname_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    uuid_t null_uuid;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_getbyname_state);
    if (req == NULL) {
        return NULL;
    }
    uuid_clear(null_uuid);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Getting ccache by name\n");

    subreq = sec_get_ccache_send(state, ev, secdb, client, name, null_uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_getbyname_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_getbyname_state *state = tevent_req_data(req,
                                            struct ccdb_sec_getbyname_state);

    ret = sec_get_ccache_recv(subreq, state, &state->cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot retrieve the ccache [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Got ccache by UUID\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_getbyname_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_sec_getbyname_state *state = tevent_req_data(req,
                                                struct ccdb_sec_getbyname_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct ccdb_sec_name_by_uuid_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;

    uuid_t uuid;

    const char *name;
};

static void ccdb_sec_name_by_uuid_done(struct tevent_req *subreq);

struct tevent_req *ccdb_sec_name_by_uuid_send(TALLOC_CTX *sec_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_name_by_uuid_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;

    req = tevent_req_create(sec_ctx, &state, struct ccdb_sec_name_by_uuid_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    uuid_copy(state->uuid, uuid);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Translating UUID to name\n");

    subreq = sec_list_send(state, state->ev, state->secdb, state->client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_name_by_uuid_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_name_by_uuid_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_name_by_uuid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_name_by_uuid_state);
    const char **sec_key_list;
    const char *name;
    size_t sec_key_list_len;
    size_t i;

    ret = sec_list_recv(subreq, state, &sec_key_list, &sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    for (i = 0; i < sec_key_list_len; i++) {
        if (sec_key_match_uuid(sec_key_list[i], state->uuid) == true) {
            /* Match, copy name */
            name = sec_key_get_name(sec_key_list[i]);
            if (name == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                       "Malformed key, cannot get name\n");
                tevent_req_error(req, EINVAL);
                return;
            }

            state->name = talloc_strdup(state, name);
            if (state->name == NULL) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            DEBUG(SSSDBG_TRACE_INTERNAL, "Got ccache by UUID\n");
            tevent_req_done(req);
            return;
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "No such UUID\n");
    tevent_req_error(req, ERR_NO_CREDS);
    return;
}

errno_t ccdb_sec_name_by_uuid_recv(struct tevent_req *req,
                                   TALLOC_CTX *sec_ctx,
                                   const char **_name)
{
    struct ccdb_sec_name_by_uuid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_name_by_uuid_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_name = talloc_steal(sec_ctx, state->name);
    return EOK;
}

struct ccdb_sec_uuid_by_name_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;

    const char *name;

    uuid_t uuid;
};

static void ccdb_sec_uuid_by_name_done(struct tevent_req *subreq);

struct tevent_req *ccdb_sec_uuid_by_name_send(TALLOC_CTX *sec_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              const char *name)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_uuid_by_name_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;

    req = tevent_req_create(sec_ctx, &state, struct ccdb_sec_uuid_by_name_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    state->name = name;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Translating name to UUID\n");

    subreq = sec_list_send(state, state->ev, state->secdb, state->client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_uuid_by_name_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_uuid_by_name_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_uuid_by_name_state *state = tevent_req_data(req,
                                                struct ccdb_sec_uuid_by_name_state);
    const char **sec_key_list;
    size_t sec_key_list_len;
    size_t i;

    ret = sec_list_recv(subreq, state, &sec_key_list, &sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    for (i = 0; i < sec_key_list_len; i++) {
        if (sec_key_match_name(sec_key_list[i], state->name) == true) {
            /* Match, copy UUID */
            ret = sec_key_get_uuid(sec_key_list[i], state->uuid);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                       "Malformed key, cannot get UUID\n");
                tevent_req_error(req, ret);
                return;
            }

            DEBUG(SSSDBG_TRACE_INTERNAL, "Got ccache by name\n");
            tevent_req_done(req);
            return;
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "No such name\n");
    tevent_req_error(req, ERR_NO_CREDS);
    return;
}

errno_t ccdb_sec_uuid_by_name_recv(struct tevent_req *req,
                                   TALLOC_CTX *sec_ctx,
                                   uuid_t _uuid)
{
    struct ccdb_sec_uuid_by_name_state *state = tevent_req_data(req,
                                                struct ccdb_sec_uuid_by_name_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    uuid_copy(_uuid, state->uuid);
    return EOK;
}

/* HTTP POST $base to create the container */
/* HTTP PUT $base to create the container. Since PUT errors out on duplicates, at least
 * we fail consistently here and don't overwrite the ccache on concurrent requests
 */
struct ccdb_sec_create_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;

    const char *key_url;
    struct sss_iobuf *ccache_payload;
};

static void ccdb_sec_container_done(struct tevent_req *subreq);
static void ccdb_sec_ccache_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_create_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client,
                                               struct kcm_ccache *cc)
{
    struct tevent_req *subreq = NULL;
    struct tevent_req *req = NULL;
    struct ccdb_sec_create_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;
    const char *container_url;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_create_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Creating ccache storage for %s\n", cc->name);

    /* Do the encoding asap so that if we fail, we don't even attempt any
     * writes */
    ret = kcm_ccache_to_sec_input(state, cc, client, &state->key_url, &state->ccache_payload);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert cache %s to JSON [%d]: %s\n",
              cc->name, ret, sss_strerror(ret));
        goto immediate;
    }

    container_url = sec_container_url_create(state, client);
    if (container_url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Creating the ccache container\n");
    subreq = tcurl_http_send(state, ev, secdb->tctx,
                             TCURL_HTTP_POST,
                             SSSD_SECRETS_SOCKET,
                             container_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_container_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_container_done(struct tevent_req *subreq)
{
    errno_t ret;
    int http_code;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ccdb_sec_create_state *state = tevent_req_data(req,
                                                struct ccdb_sec_create_state);

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Communication with the secrets responder failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* Conflict is not an error as multiple ccaches are under the same
     * container */
    if (http_code == 409) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Container already exists, ignoring\n");
    } else if (http_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create the ccache container\n");
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "ccache container created\n");
    DEBUG(SSSDBG_TRACE_INTERNAL, "creating empty ccache payload\n");

    subreq = tcurl_http_send(state,
                             state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_PUT,
                             SSSD_SECRETS_SOCKET,
                             state->key_url,
                             sec_headers,
                             state->ccache_payload,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_ccache_done, req);
}

static void ccdb_sec_ccache_done(struct tevent_req *subreq)
{
    errno_t ret;
    int http_code;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ccdb_sec_create_state *state = tevent_req_data(req,
                                                struct ccdb_sec_create_state);

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Communication with the secrets responder failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add the payload\n");
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "payload created\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_create_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ccdb_sec_mod_cred_state {
    struct tevent_context *ev;
    struct kcm_ccdb *db;
    struct cli_creds *client;
    struct kcm_mod_ctx *mod_cc;

    struct ccdb_sec *secdb;
};

static void ccdb_sec_mod_cred_get_done(struct tevent_req *subreq);
static void ccdb_sec_mod_cred_patch_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_mod_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct kcm_ccdb *db,
                                            struct cli_creds *client,
                                            uuid_t uuid,
                                            struct kcm_mod_ctx *mod_cc)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_mod_cred_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_mod_cred_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->db =db;
    state->client = client;
    state->secdb = secdb;
    state->mod_cc = mod_cc;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Modifying ccache\n");

    subreq = sec_get_ccache_send(state, ev, secdb, client, NULL, uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, *ccdb_sec_mod_cred_get_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_mod_cred_get_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_mod_cred_state *state = tevent_req_data(req,
                                            struct ccdb_sec_mod_cred_state);
    struct kcm_ccache *cc;
    const char *url;
    struct sss_iobuf *payload;

    ret = sec_get_ccache_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot retrieve the ccache [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (cc == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No such ccache\n");
        tevent_req_error(req, ERR_NO_CREDS);
        return;
    }

    kcm_mod_cc(cc, state->mod_cc);

    ret = kcm_ccache_to_sec_input(state, cc, state->client, &url, &payload);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to marshall modified ccache to payload [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sec_patch_send(state,
                            state->ev,
                            state->secdb,
                            state->client,
                            url,
                            payload);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_mod_cred_patch_done, req);
}

static void ccdb_sec_mod_cred_patch_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    ret = sec_patch_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sec_patch request failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "ccache modified\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_mod_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ccdb_sec_store_cred_state {
    struct tevent_context *ev;
    struct kcm_ccdb *db;
    struct cli_creds *client;
    struct sss_iobuf *cred_blob;

    struct ccdb_sec *secdb;
};

static void ccdb_sec_store_cred_get_done(struct tevent_req *subreq);
static void ccdb_sec_store_cred_patch_done(struct tevent_req *subreq);

/* HTTP DEL/PUT $base/ccache/uuid:name */
static struct tevent_req *ccdb_sec_store_cred_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct kcm_ccdb *db,
                                                   struct cli_creds *client,
                                                   uuid_t uuid,
                                                   struct sss_iobuf *cred_blob)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_store_cred_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_store_cred_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->db =db;
    state->client = client;
    state->cred_blob = cred_blob;
    state->secdb = secdb;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Storing creds in ccache\n");

    subreq = sec_get_ccache_send(state, ev, secdb, client, NULL, uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, *ccdb_sec_store_cred_get_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_store_cred_get_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_store_cred_state *state = tevent_req_data(req,
                                            struct ccdb_sec_store_cred_state);
    struct kcm_ccache *cc;
    const char *url;
    struct sss_iobuf *payload;

    ret = sec_get_ccache_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = kcm_cc_store_cred_blob(cc, state->cred_blob);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store credentials to ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = kcm_ccache_to_sec_input(state, cc, state->client, &url, &payload);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to marshall modified ccache to payload [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sec_patch_send(state,
                            state->ev,
                            state->secdb,
                            state->client,
                            url,
                            payload);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_store_cred_patch_done, req);
}

static void ccdb_sec_store_cred_patch_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);

    ret = sec_patch_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sec_patch request failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "ccache creds stored\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_store_cred_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* HTTP DELETE $base/ccache/uuid:name */
struct ccdb_sec_delete_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;
    uuid_t uuid;

    size_t sec_key_list_len;
};

static void ccdb_sec_delete_list_done(struct tevent_req *subreq);
static void ccdb_sec_delete_cc_done(struct tevent_req *subreq);
static void ccdb_sec_delete_container_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_delete_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client,
                                               uuid_t uuid)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_delete_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_delete_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    uuid_copy(state->uuid, uuid);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Deleting ccache\n");

    subreq = sec_list_send(state, ev, secdb, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_delete_list_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_delete_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_delete_state *state = tevent_req_data(req,
                                                struct ccdb_sec_delete_state);
    const char **sec_key_list;
    const char *sec_key;
    const char *cc_url;

    ret = sec_list_recv(subreq,
                        state,
                        &sec_key_list,
                        &state->sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (sec_key_list == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No ccaches to delete\n");
        tevent_req_done(req);
        return;
    }

    sec_key = find_by_uuid(sec_key_list, state->uuid);
    if (sec_key == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot find ccache by UUID\n");
        tevent_req_done(req);
        return;
    }

    cc_url = sec_cc_url_create(state, state->client, sec_key);
    if (cc_url == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = tcurl_http_send(state, state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_DELETE,
                             SSSD_SECRETS_SOCKET,
                             cc_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_delete_cc_done, req);
}

static void ccdb_sec_delete_cc_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_delete_state *state = tevent_req_data(req,
                                                struct ccdb_sec_delete_state);
    int http_code;
    const char *container_url;

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot delete ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    if (state->sec_key_list_len != 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "There are other ccaches, done\n");
        tevent_req_done(req);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Removing ccache container\n");

    container_url = sec_container_url_create(state, state->client);
    if (container_url == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = tcurl_http_send(state, state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_DELETE,
                             SSSD_SECRETS_SOCKET,
                             container_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_delete_container_done, req);
}

static void ccdb_sec_delete_container_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_delete_state *state = tevent_req_data(req,
                                                struct ccdb_sec_delete_state);
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot delete ccache container [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Removed ccache container\n");
    tevent_req_done(req);
}

static errno_t ccdb_sec_delete_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

const struct kcm_ccdb_ops ccdb_sec_ops = {
    .init = ccdb_sec_init,

    .nextid_send = ccdb_sec_nextid_send,
    .nextid_recv = ccdb_sec_nextid_recv,

    .set_default_send = ccdb_sec_set_default_send,
    .set_default_recv = ccdb_sec_set_default_recv,

    .get_default_send = ccdb_sec_get_default_send,
    .get_default_recv = ccdb_sec_get_default_recv,

    .list_send = ccdb_sec_list_send,
    .list_recv = ccdb_sec_list_recv,

    .getbyname_send = ccdb_sec_getbyname_send,
    .getbyname_recv = ccdb_sec_getbyname_recv,

    .getbyuuid_send = ccdb_sec_getbyuuid_send,
    .getbyuuid_recv = ccdb_sec_getbyuuid_recv,

    .name_by_uuid_send = ccdb_sec_name_by_uuid_send,
    .name_by_uuid_recv = ccdb_sec_name_by_uuid_recv,

    .uuid_by_name_send = ccdb_sec_uuid_by_name_send,
    .uuid_by_name_recv = ccdb_sec_uuid_by_name_recv,

    .create_send = ccdb_sec_create_send,
    .create_recv = ccdb_sec_create_recv,

    .mod_send = ccdb_sec_mod_send,
    .mod_recv = ccdb_sec_mod_recv,

    .store_cred_send = ccdb_sec_store_cred_send,
    .store_cred_recv = ccdb_sec_store_cred_recv,

    .delete_send = ccdb_sec_delete_send,
    .delete_recv = ccdb_sec_delete_recv,
};
