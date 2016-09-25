/*
   SSSD

   Secrets Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016

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

#include "responder/secrets/secsrv_private.h"
#include "util/crypto/sss_crypto.h"
#include <time.h>
#include <ldb.h>

#define MKEY_SIZE (256 / 8)

struct local_context {
    struct ldb_context *ldb;
    struct sec_data master_key;
};

static int local_decrypt(struct local_context *lctx, TALLOC_CTX *mem_ctx,
                         const char *secret, const char *enctype,
                         char **plain_secret)
{
    char *output;

    if (enctype && strcmp(enctype, "masterkey") == 0) {
        struct sec_data _secret;
        size_t outlen;
        int ret;

        _secret.data = (char *)sss_base64_decode(mem_ctx, secret,
                                                 &_secret.length);
        if (!_secret.data) return EINVAL;

        ret = sss_decrypt(mem_ctx, AES256CBC_HMAC_SHA256,
                          (uint8_t *)lctx->master_key.data,
                          lctx->master_key.length,
                          (uint8_t *)_secret.data, _secret.length,
                          (uint8_t **)&output, &outlen);
        if (ret) return ret;

        if (((strnlen(output, outlen) + 1) != outlen) ||
            output[outlen - 1] != '\0') {
            return EIO;
        }
    } else {
        output = talloc_strdup(mem_ctx, secret);
        if (!output) return ENOMEM;
    }

    *plain_secret = output;
    return EOK;
}

static int local_encrypt(struct local_context *lctx, TALLOC_CTX *mem_ctx,
                         const char *secret, const char *enctype,
                         char **ciphertext)
{
    struct sec_data _secret;
    char *output;
    int ret;

    if (!enctype || strcmp(enctype, "masterkey") != 0) return EINVAL;

    ret = sss_encrypt(mem_ctx, AES256CBC_HMAC_SHA256,
                      (uint8_t *)lctx->master_key.data,
                      lctx->master_key.length,
                      (const uint8_t *)secret, strlen(secret) + 1,
                      (uint8_t **)&_secret.data, &_secret.length);
    if (ret) return ret;

    output = sss_base64_encode(mem_ctx,
                               (uint8_t *)_secret.data, _secret.length);
    if (!output) return ENOMEM;

    *ciphertext = output;
    return EOK;
}

static int local_db_dn(TALLOC_CTX *mem_ctx,
                       struct ldb_context *ldb,
                       const char *req_path,
                       struct ldb_dn **req_dn)
{
    struct ldb_dn *dn;
    const char *s, *e;
    int ret;

    dn = ldb_dn_new(mem_ctx, ldb, "cn=secrets");
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    s = req_path;

    while (s && *s) {
        e = strchr(s, '/');
        if (e) {
            if (e == s) {
                s++;
                continue;
            }
            if (!ldb_dn_add_child_fmt(dn, "cn=%.*s", (int)(e - s), s)) {
                ret = ENOMEM;
                goto done;
            }
            s = e + 1;
        } else {
            if (!ldb_dn_add_child_fmt(dn, "cn=%s", s)) {
                ret = ENOMEM;
                goto done;
            }
            s = NULL;
        }
    }

    *req_dn = dn;
    ret = EOK;

done:
    return ret;
}

static char *local_dn_to_path(TALLOC_CTX *mem_ctx,
                              struct ldb_dn *basedn,
                              struct ldb_dn *dn)
{
    int basecomps;
    int dncomps;
    char *path = NULL;

    basecomps = ldb_dn_get_comp_num(basedn);
    dncomps = ldb_dn_get_comp_num(dn);

    for (int i = dncomps - basecomps; i > 0; i--) {
        const struct ldb_val *val;

        val = ldb_dn_get_component_val(dn, i - 1);
        if (!val) return NULL;

        if (path) {
            path = talloc_strdup_append_buffer(path, "/");
            if (!path) return NULL;
            path = talloc_strndup_append_buffer(path, (char *)val->data,
                                                val->length);
        } else {
            path = talloc_strndup(mem_ctx, (char *)val->data, val->length);
        }
        if (!path) return NULL;
    }

    return path;
}

#define LOCAL_SIMPLE_FILTER "(type=simple)"
#define LOCAL_CONTAINER_FILTER "(type=container)"

static int local_db_get_simple(TALLOC_CTX *mem_ctx,
                               struct local_context *lctx,
                               const char *req_path,
                               char **secret)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { "secret", "enctype", NULL };
    struct ldb_result *res;
    struct ldb_dn *dn;
    const char *attr_secret;
    const char *attr_enctype;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    ret = local_db_dn(tmp_ctx, lctx->ldb, req_path, &dn);
    if (ret != EOK) goto done;

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                     attrs, "%s", LOCAL_SIMPLE_FILTER);
    if (ret != EOK) {
        ret = ENOENT;
        goto done;
    }

    switch (res->count) {
    case 0:
        ret = ENOENT;
        goto done;
    case 1:
        break;
    default:
        ret = E2BIG;
        goto done;
    }

    attr_secret = ldb_msg_find_attr_as_string(res->msgs[0], "secret", NULL);
    if (!attr_secret) {
        ret = ENOENT;
        goto done;
    }

    attr_enctype = ldb_msg_find_attr_as_string(res->msgs[0], "enctype", NULL);

    if (attr_enctype) {
        ret = local_decrypt(lctx, mem_ctx, attr_secret, attr_enctype, secret);
        if (ret) goto done;
    } else {
        *secret = talloc_strdup(mem_ctx, attr_secret);
    }
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_db_list_keys(TALLOC_CTX *mem_ctx,
                              struct local_context *lctx,
                              const char *req_path,
                              char ***_keys,
                              int *num_keys)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { "secret", NULL };
    struct ldb_result *res;
    struct ldb_dn *dn;
    char **keys;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    ret = local_db_dn(tmp_ctx, lctx->ldb, req_path, &dn);
    if (ret != EOK) goto done;

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
                     attrs, "%s", LOCAL_SIMPLE_FILTER);
    if (ret != EOK) {
        ret = ENOENT;
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    keys = talloc_array(mem_ctx, char *, res->count);
    if (!keys) {
        ret = ENOMEM;
        goto done;
    }

    for (unsigned i = 0; i < res->count; i++) {
        keys[i] = local_dn_to_path(keys, dn, res->msgs[i]->dn);
        if (!keys[i]) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_keys = keys;
    *num_keys = res->count;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_db_check_containers(TALLOC_CTX *mem_ctx,
                                     struct local_context *lctx,
                                     struct ldb_dn *leaf_dn)
{
    static const char *attrs[] = { NULL};
    struct ldb_result *res = NULL;
    struct ldb_dn *dn;
    int num;
    int ret;

    dn = ldb_dn_copy(mem_ctx, leaf_dn);
    if (!dn) return ENOMEM;

    /* We need to exclude the leaf as that will be the new child entry,
     * We also do not care for the synthetic containers that constitute the
     * base path (cn=<uidnumber>,cn=users,cn=secrets), so in total we remove
     * 4 components */
    num = ldb_dn_get_comp_num(dn) - 4;

    for (int i = 0; i < num; i++) {
        /* remove the child first (we do not want to check the leaf) */
        if (!ldb_dn_remove_child_components(dn, 1)) return EFAULT;

        /* and check the parent container exists */
        ret = ldb_search(lctx->ldb, mem_ctx, &res, dn, LDB_SCOPE_BASE,
                         attrs, LOCAL_CONTAINER_FILTER);
        if (ret != LDB_SUCCESS) return ENOENT;
        if (res->count != 1) return ENOENT;
        talloc_free(res);
    }

    return EOK;
}

static int local_db_put_simple(TALLOC_CTX *mem_ctx,
                               struct local_context *lctx,
                               const char *req_path,
                               const char *secret)
{
    struct ldb_message *msg;
    const char *enctype = "masterkey";
    char *enc_secret;
    int ret;

    msg = ldb_msg_new(mem_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    ret = local_db_dn(msg, lctx->ldb, req_path, &msg->dn);
    if (ret != EOK) goto done;

    /* make sure containers exist */
    ret = local_db_check_containers(msg, lctx, msg->dn);
    if (ret != EOK) goto done;

    ret = local_encrypt(lctx, msg, secret, enctype, &enc_secret);
    if (ret != EOK) goto done;

    ret = ldb_msg_add_string(msg, "type", "simple");
    if (ret != EOK) goto done;

    ret = ldb_msg_add_string(msg, "enctype", enctype);
    if (ret != EOK) goto done;

    ret = ldb_msg_add_string(msg, "secret", enc_secret);
    if (ret != EOK) goto done;

    ret = ldb_msg_add_fmt(msg, "creationTime", "%lu", time(NULL));
    if (ret != EOK) goto done;

    ret = ldb_add(lctx->ldb, msg);
    if (ret != EOK) {
        if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) ret = EEXIST;
        else ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);
    return ret;
}

static int local_db_delete(TALLOC_CTX *mem_ctx,
                           struct local_context *lctx,
                           const char *req_path)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    static const char *attrs[] = { NULL };
    struct ldb_result *res;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    ret = local_db_dn(mem_ctx, lctx->ldb, req_path, &dn);
    if (ret != EOK) goto done;

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                    attrs, LOCAL_CONTAINER_FILTER);
    if (ret != EOK) goto done;

    if (res->count == 1) {
        ret = ldb_search(lctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_ONELEVEL,
                         attrs, NULL);
        if (ret != EOK) goto done;

        if (res->count > 0) {
            ret = EEXIST;
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to remove '%s': Container is not empty\n",
                  ldb_dn_get_linearized(dn));

            goto done;
        }
    }

    ret = ldb_delete(lctx->ldb, dn);
    ret = sysdb_error_to_errno(ret);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_db_create(TALLOC_CTX *mem_ctx,
                           struct local_context *lctx,
                           const char *req_path)
{
    struct ldb_message *msg;
    int ret;

    msg = ldb_msg_new(mem_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    ret = local_db_dn(msg, lctx->ldb, req_path, &msg->dn);
    if (ret != EOK) goto done;

    /* make sure containers exist */
    ret = local_db_check_containers(msg, lctx, msg->dn);
    if (ret != EOK) goto done;

    ret = ldb_msg_add_string(msg, "type", "container");
    if (ret != EOK) goto done;

    ret = ldb_msg_add_fmt(msg, "creationTime", "%lu", time(NULL));
    if (ret != EOK) goto done;

    ret = ldb_add(lctx->ldb, msg);
    if (ret != EOK) {
        if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) ret = EEXIST;
        else ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);
    return ret;
}

static int local_secrets_map_path(TALLOC_CTX *mem_ctx,
                                  struct sec_req_ctx *secreq,
                                  char **local_db_path)
{
    int ret;

    /* be strict for now */
    if (secreq->parsed_url.fragment != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unrecognized URI fragments: [%s]\n",
              secreq->parsed_url.fragment);
        return EINVAL;
    }

    if (secreq->parsed_url.userinfo != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unrecognized URI userinfo: [%s]\n",
              secreq->parsed_url.userinfo);
        return EINVAL;
    }

    /* only type simple for now */
    if (secreq->parsed_url.query != NULL) {
        ret = strcmp(secreq->parsed_url.query, "type=simple");
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid URI query: [%s]\n",
                  secreq->parsed_url.query);
            return EINVAL;
        }
    }

    /* drop SEC_BASEPATH prefix */
    *local_db_path =
        talloc_strdup(mem_ctx, &secreq->mapped_path[sizeof(SEC_BASEPATH) - 1]);
    if (!*local_db_path) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to local db path\n");
        return ENOMEM;
    }

    return EOK;
}


struct local_secret_state {
    struct tevent_context *ev;
    struct sec_req_ctx *secreq;
};

static struct tevent_req *local_secret_req(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           void *provider_ctx,
                                           struct sec_req_ctx *secreq)
{
    struct tevent_req *req;
    struct local_secret_state *state;
    struct local_context *lctx;
    struct sec_data body = { 0 };
    const char *content_type;
    bool body_is_json;
    char *req_path;
    char *secret;
    char **keys;
    int nkeys;
    int plen;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct local_secret_state);
    if (!req) return NULL;

    state->ev = ev;
    state->secreq = secreq;

    lctx = talloc_get_type(provider_ctx, struct local_context);
    if (!lctx) {
        ret = EIO;
        goto done;
    }

    if (sec_req_has_header(secreq, "Content-Type",
                                  "application/json")) {
        body_is_json = true;
        content_type = "application/json";
    } else if (sec_req_has_header(secreq, "Content-Type",
                           "application/octet-stream")) {
        body_is_json = false;
        content_type = "application/octet-stream";
    } else {
        ret = EINVAL;
        goto done;
    }

    ret = local_secrets_map_path(state, secreq, &req_path);
    if (ret) goto done;

    switch (secreq->method) {
    case HTTP_GET:
        if (req_path[strlen(req_path) - 1] == '/') {
            ret = local_db_list_keys(state, lctx, req_path, &keys, &nkeys);
            if (ret) goto done;

            ret = sec_array_to_json(state, keys, nkeys, &body.data);
            if (ret) goto done;

            body.length = strlen(body.data);
            break;
        }

        ret = local_db_get_simple(state, lctx, req_path, &secret);
        if (ret) goto done;

        if (body_is_json) {
            ret = sec_simple_secret_to_json(state, secret, &body.data);
            if (ret) goto done;

            body.length = strlen(body.data);
        } else {
            body.data = (void *)sss_base64_decode(state, secret, &body.length);
            ret = body.data ? EOK : ENOMEM;
        }
        if (ret) goto done;

        break;

    case HTTP_PUT:
        if (body_is_json) {
            ret = sec_json_to_simple_secret(state, secreq->body.data,
                                            &secret);
        } else {
            secret = sss_base64_encode(state, (uint8_t *)secreq->body.data,
                                       secreq->body.length);
            ret = secret ? EOK : ENOMEM;
        }
        if (ret) goto done;

        ret = local_db_put_simple(state, lctx, req_path, secret);
        if (ret) goto done;
        break;

    case HTTP_DELETE:
        ret = local_db_delete(state, lctx, req_path);
        if (ret) goto done;
        break;

    case HTTP_POST:
        plen = strlen(req_path);

        if (req_path[plen - 1] != '/') {
            ret = EINVAL;
            goto done;
        }

        req_path[plen - 1] = '\0';

        ret = local_db_create(state, lctx, req_path);
        if (ret) goto done;
        break;

    default:
        ret = EINVAL;
        goto done;
    }

    if (body.data) {
        ret = sec_http_reply_with_body(secreq, &secreq->reply, STATUS_200,
                                       content_type, &body);
    } else {
        ret = sec_http_status_reply(secreq, &secreq->reply, STATUS_200);
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        /* shortcircuit the request here as all called functions are
         * synchronous and final and no further subrequests are made */
        tevent_req_done(req);
    }
    return tevent_req_post(req, state->ev);
}

static int generate_master_key(const char *filename, size_t size)
{
    uint8_t buf[size];
    ssize_t rsize;
    int ret;
    int fd;

    ret = generate_csprng_buffer(buf, size);
    if (ret) return ret;

    fd = open(filename, O_CREAT|O_EXCL|O_WRONLY, 0600);
    if (fd == -1) return errno;

    rsize = sss_atomic_write_s(fd, buf, size);
    close(fd);
    if (rsize != size) {
        ret = unlink(filename);
        /* non-fatal failure */
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to remove file: %s - %d [%s]!\n",
                  filename, ret, sss_strerror(ret));
        }
        return EFAULT;
    }

    return EOK;
}

int local_secrets_provider_handle(struct sec_ctx *sctx,
                                  struct provider_handle **out_handle)
{
    const char *mkey = SECRETS_DB_PATH"/.secrets.mkey";
    const char *dbpath = SECRETS_DB_PATH"/secrets.ldb";
    struct provider_handle *handle;
    struct local_context *lctx;
    ssize_t size;
    int mfd;
    int ret;

    handle = talloc_zero(sctx, struct provider_handle);
    if (!handle) return ENOMEM;

    handle->name = "LOCAL";
    handle->fn = local_secret_req;

    lctx = talloc_zero(handle, struct local_context);
    if (!lctx) return ENOMEM;

    lctx->ldb = ldb_init(lctx, NULL);
    if (!lctx->ldb) return ENOMEM;

    ret = ldb_connect(lctx->ldb, dbpath, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(lctx->ldb);
        return EIO;
    }

    lctx->master_key.data = talloc_size(lctx, MKEY_SIZE);
    if (!lctx->master_key.data) return ENOMEM;
    lctx->master_key.length = MKEY_SIZE;

    ret = check_and_open_readonly(mkey, &mfd, 0, 0,
                                  S_IFREG|S_IRUSR|S_IWUSR, 0);
    if (ret == ENOENT) {
        ret = generate_master_key(mkey, MKEY_SIZE);
        if (ret) return EFAULT;
        ret = check_and_open_readonly(mkey, &mfd, 0, 0,
                                      S_IFREG|S_IRUSR|S_IWUSR, 0);
    }
    if (ret) return EFAULT;

    size = sss_atomic_read_s(mfd, lctx->master_key.data,
                             lctx->master_key.length);
    close(mfd);
    if (size < 0 || size != lctx->master_key.length) return EIO;

    handle->context = lctx;

    *out_handle = handle;
    return EOK;
}
