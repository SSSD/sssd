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
#include <sys/stat.h>
#include <fcntl.h>
#include <ldb.h>

#define MKEY_SIZE (256 / 8)

#define SECRETS_BASEDN  "cn=secrets"
#define KCM_BASEDN      "cn=kcm"

struct local_context {
    struct ldb_context *ldb;
    struct sec_data master_key;

    struct sec_quota *quota_secrets;
    struct sec_quota *quota_kcm;
};

static int local_decrypt(struct local_context *lctx, TALLOC_CTX *mem_ctx,
                         const char *secret, const char *enctype,
                         char **plain_secret)
{
    char *output;

    if (enctype && strcmp(enctype, "masterkey") == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Decrypting with masterkey\n");

        struct sec_data _secret;
        size_t outlen;
        int ret;

        _secret.data = (char *)sss_base64_decode(mem_ctx, secret,
                                                 &_secret.length);
        if (!_secret.data) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed\n");
            return EINVAL;
        }

        ret = sss_decrypt(mem_ctx, AES256CBC_HMAC_SHA256,
                          (uint8_t *)lctx->master_key.data,
                          lctx->master_key.length,
                          (uint8_t *)_secret.data, _secret.length,
                          (uint8_t **)&output, &outlen);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_decrypt failed [%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }

        if (((strnlen(output, outlen) + 1) != outlen) ||
            output[outlen - 1] != '\0') {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Output length mismatch or output not NULL-terminated\n");
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

    if (enctype == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No encryption type\n");
        return EINVAL;
    }

    if (strcmp(enctype, "masterkey") != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown encryption type '%s'\n", enctype);
        return EINVAL;
    }

    ret = sss_encrypt(mem_ctx, AES256CBC_HMAC_SHA256,
                      (uint8_t *)lctx->master_key.data,
                      lctx->master_key.length,
                      (const uint8_t *)secret, strlen(secret) + 1,
                      (uint8_t **)&_secret.data, &_secret.length);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_encrypt failed [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    output = sss_base64_encode(mem_ctx,
                               (uint8_t *)_secret.data, _secret.length);
    if (!output) return ENOMEM;

    *ciphertext = output;
    return EOK;
}

static int local_db_dn(TALLOC_CTX *mem_ctx,
                       struct ldb_context *ldb,
                       const char *basedn,
                       const char *req_path,
                       struct ldb_dn **req_dn)
{
    struct ldb_dn *dn;
    const char *s, *e;
    int ret;

    dn = ldb_dn_new(mem_ctx, ldb, basedn);
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

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Local path for [%s] is [%s]\n",
          req_path, ldb_dn_get_linearized(dn));
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

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Secrets path for [%s] is [%s]\n",
          ldb_dn_get_linearized(dn), path);
    return path;
}

struct local_db_req {
    char *path;
    const char *basedn;
    struct ldb_dn *req_dn;
    struct sec_quota *quota;
};

#define LOCAL_SIMPLE_FILTER "(type=simple)"
#define LOCAL_CONTAINER_FILTER "(type=container)"

static int local_db_get_simple(TALLOC_CTX *mem_ctx,
                               struct local_context *lctx,
                               struct local_db_req *lc_req,
                               char **secret)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { "secret", "enctype", NULL };
    struct ldb_result *res;
    const char *attr_secret;
    const char *attr_enctype;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Retrieving a secret from [%s]\n", lc_req->path);

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Searching for [%s] at [%s] with scope=base\n",
          LOCAL_SIMPLE_FILTER, ldb_dn_get_linearized(lc_req->req_dn));

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, lc_req->req_dn, LDB_SCOPE_BASE,
                     attrs, "%s", LOCAL_SIMPLE_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned [%d]: %s\n", ret, ldb_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    switch (res->count) {
    case 0:
        DEBUG(SSSDBG_TRACE_LIBS, "No secret found\n");
        ret = ENOENT;
        goto done;
    case 1:
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE,
              "Too many secrets returned with BASE search\n");
        ret = E2BIG;
        goto done;
    }

    attr_secret = ldb_msg_find_attr_as_string(res->msgs[0], "secret", NULL);
    if (!attr_secret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "The 'secret' attribute is missing\n");
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
                              struct local_db_req *lc_req,
                              char ***_keys,
                              int *num_keys)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { "secret", NULL };
    struct ldb_result *res;
    char **keys;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_FUNC, "Listing keys at [%s]\n", lc_req->path);

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Searching for [%s] at [%s] with scope=subtree\n",
          LOCAL_SIMPLE_FILTER, ldb_dn_get_linearized(lc_req->req_dn));

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, lc_req->req_dn, LDB_SCOPE_SUBTREE,
                     attrs, "%s", LOCAL_SIMPLE_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned [%d]: %s\n", ret, ldb_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "No secrets found\n");
        ret = ENOENT;
        goto done;
    }

    keys = talloc_array(mem_ctx, char *, res->count);
    if (!keys) {
        ret = ENOMEM;
        goto done;
    }

    for (unsigned i = 0; i < res->count; i++) {
        keys[i] = local_dn_to_path(keys, lc_req->req_dn, res->msgs[i]->dn);
        if (!keys[i]) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_keys = keys;
    DEBUG(SSSDBG_TRACE_LIBS, "Returning %d secrets\n", res->count);
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
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { NULL};
    struct ldb_result *res = NULL;
    struct ldb_dn *dn;
    int num;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    dn = ldb_dn_copy(tmp_ctx, leaf_dn);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    /* We need to exclude the leaf as that will be the new child entry,
     * We also do not care for the synthetic containers that constitute the
     * base path (cn=<uidnumber>,cn=users,cn=secrets), so in total we remove
     * 4 components */
    num = ldb_dn_get_comp_num(dn) - 4;

    for (int i = 0; i < num; i++) {
        /* remove the child first (we do not want to check the leaf) */
        if (!ldb_dn_remove_child_components(dn, 1)) return EFAULT;

        /* and check the parent container exists */
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Searching for [%s] at [%s] with scope=base\n",
              LOCAL_CONTAINER_FILTER, ldb_dn_get_linearized(dn));

        ret = ldb_search(lctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                         attrs, LOCAL_CONTAINER_FILTER);
        if (ret != LDB_SUCCESS || res->count != 1) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "DN [%s] does not exist\n", ldb_dn_get_linearized(dn));
            return ENOENT;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_db_check_containers_nest_level(struct local_db_req *lc_req,
                                                struct ldb_dn *leaf_dn)
{
    int nest_level;

    if (lc_req->quota->containers_nest_level == 0) {
        return EOK;
    }

    /* We need do not care for the synthetic containers that constitute the
     * base path (cn=<uidnumber>,cn=user,cn=secrets). */
    nest_level = ldb_dn_get_comp_num(leaf_dn) - 3;
    if (nest_level > lc_req->quota->containers_nest_level) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot create a nested container of depth %d as the maximum"
              "allowed number of nested containers is %d.\n",
              nest_level, lc_req->quota->containers_nest_level);

        return ERR_SEC_INVALID_CONTAINERS_NEST_LEVEL;
    }

    return EOK;
}

static struct ldb_dn *per_uid_container(TALLOC_CTX *mem_ctx,
                                        struct ldb_dn *req_dn)
{
    int user_comp;
    int num_comp;
    struct ldb_dn *uid_base_dn;

    uid_base_dn = ldb_dn_copy(mem_ctx, req_dn);
    if (uid_base_dn == NULL) {
        return NULL;
    }

    /* Remove all the components up to the per-user base path which consists
     * of three components:
     *  cn=<uidnumber>,cn=users,cn=secrets
     */
    user_comp = ldb_dn_get_comp_num(uid_base_dn) - 3;

    if (!ldb_dn_remove_child_components(uid_base_dn, user_comp)) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot remove child components\n");
        talloc_free(uid_base_dn);
        return NULL;
    }

    num_comp = ldb_dn_get_comp_num(uid_base_dn);
    if (num_comp != 3) {
        DEBUG(SSSDBG_OP_FAILURE, "Expected 3 components got %d\n", num_comp);
        talloc_free(uid_base_dn);
        return NULL;
    }

    return uid_base_dn;
}

static int local_db_check_peruid_number_of_secrets(TALLOC_CTX *mem_ctx,
                                                   struct local_context *lctx,
                                                   struct local_db_req *lc_req)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { NULL };
    struct ldb_result *res = NULL;
    struct ldb_dn *cli_basedn = NULL;
    int ret;

    if (lc_req->quota->max_uid_secrets == 0) {
        return EOK;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    cli_basedn = per_uid_container(tmp_ctx, lc_req->req_dn);
    if (cli_basedn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, cli_basedn, LDB_SCOPE_SUBTREE,
                     attrs, LOCAL_SIMPLE_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned %d: %s\n", ret, ldb_strerror(ret));
        goto done;
    }

    if (res->count >= lc_req->quota->max_uid_secrets) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store any more secrets for this client (basedn %s) "
              "as the maximum allowed limit (%d) has been reached\n",
              ldb_dn_get_linearized(cli_basedn),
              lc_req->quota->max_uid_secrets);
        ret = ERR_SEC_INVALID_TOO_MANY_SECRETS;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_db_check_number_of_secrets(TALLOC_CTX *mem_ctx,
                                            struct local_context *lctx,
                                            struct local_db_req *lc_req)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { NULL };
    struct ldb_result *res = NULL;
    struct ldb_dn *dn;
    int ret;

    if (lc_req->quota->max_secrets == 0) {
        return EOK;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    dn = ldb_dn_new(tmp_ctx, lctx->ldb, lc_req->basedn);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
                     attrs, LOCAL_SIMPLE_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned %d: %s\n", ret, ldb_strerror(ret));
        goto done;
    }

    if (res->count >= lc_req->quota->max_secrets) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store any more secrets as the maximum allowed limit (%d) "
              "has been reached\n", lc_req->quota->max_secrets);
        ret = ERR_SEC_INVALID_TOO_MANY_SECRETS;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_check_max_payload_size(struct local_db_req *lc_req,
                                        int payload_size)
{
    int max_payload_size;

    if (lc_req->quota->max_payload_size == 0) {
        return EOK;
    }

    max_payload_size = lc_req->quota->max_payload_size * 1024; /* kb */
    if (payload_size > max_payload_size) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Secrets' payload size [%d kb (%d)] exceeds the maximum allowed "
              "payload size [%d kb (%d)]\n",
              payload_size * 1024, /* kb */
              payload_size,
              lc_req->quota->max_payload_size, /* kb */
              max_payload_size);

        return ERR_SEC_PAYLOAD_SIZE_IS_TOO_LARGE;
    }

    return EOK;
}

static int local_db_put_simple(TALLOC_CTX *mem_ctx,
                               struct local_context *lctx,
                               struct local_db_req *lc_req,
                               const char *secret)
{
    struct ldb_message *msg;
    const char *enctype = "masterkey";
    char *enc_secret;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Adding a secret to [%s]\n", lc_req->path);

    msg = ldb_msg_new(mem_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = lc_req->req_dn;

    /* make sure containers exist */
    ret = local_db_check_containers(msg, lctx, msg->dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_containers failed for [%s]: [%d]: %s\n",
              ldb_dn_get_linearized(msg->dn), ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_number_of_secrets(msg, lctx, lc_req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_peruid_number_of_secrets(msg, lctx, lc_req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_check_max_payload_size(lc_req, strlen(secret));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_check_max_payload_size failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_encrypt(lctx, msg, secret, enctype, &enc_secret);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_encrypt failed [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_msg_add_string(msg, "type", "simple");
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding type:simple [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_msg_add_string(msg, "enctype", enctype);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding enctype [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_msg_add_string(msg, "secret", enc_secret);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding secret [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }


    ret = ldb_msg_add_fmt(msg, "creationTime", "%lu", time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding creationTime [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_add(lctx->ldb, msg);
    if (ret != EOK) {
        if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Secret %s already exists\n", ldb_dn_get_linearized(msg->dn));
            ret = EEXIST;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add secret [%s]: [%d]: %s\n",
                  ldb_dn_get_linearized(msg->dn), ret, ldb_strerror(ret));
            ret = EIO;
        }
        goto done;
    }

    ret = EOK;
done:
    talloc_free(msg);
    return ret;
}

static int local_db_delete(TALLOC_CTX *mem_ctx,
                           struct local_context *lctx,
                           struct local_db_req *lc_req)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { NULL };
    struct ldb_result *res;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Removing a secret from [%s]\n", lc_req->path);

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Searching for [%s] at [%s] with scope=base\n",
          LOCAL_CONTAINER_FILTER, ldb_dn_get_linearized(lc_req->req_dn));

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, lc_req->req_dn, LDB_SCOPE_BASE,
                     attrs, LOCAL_CONTAINER_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned %d: %s\n", ret, ldb_strerror(ret));
        goto done;
    }

    if (res->count == 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Searching for children of [%s]\n", ldb_dn_get_linearized(lc_req->req_dn));
        ret = ldb_search(lctx->ldb, tmp_ctx, &res, lc_req->req_dn, LDB_SCOPE_ONELEVEL,
                         attrs, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "ldb_search returned %d: %s\n", ret, ldb_strerror(ret));
            goto done;
        }

        if (res->count > 0) {
            ret = EEXIST;
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to remove '%s': Container is not empty\n",
                  ldb_dn_get_linearized(lc_req->req_dn));

            goto done;
        }
    }

    ret = ldb_delete(lctx->ldb, lc_req->req_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_delete returned %d: %s\n", ret, ldb_strerror(ret));
        /* fall through */
    }
    ret = sysdb_error_to_errno(ret);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_db_create(TALLOC_CTX *mem_ctx,
                           struct local_context *lctx,
                           struct local_db_req *lc_req)
{
    struct ldb_message *msg;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Creating a container at [%s]\n", lc_req->path);

    msg = ldb_msg_new(mem_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = lc_req->req_dn;

    /* make sure containers exist */
    ret = local_db_check_containers(msg, lctx, msg->dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_containers failed for [%s]: [%d]: %s\n",
              ldb_dn_get_linearized(msg->dn), ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_containers_nest_level(lc_req, msg->dn);
    if (ret != EOK) goto done;

    ret = ldb_msg_add_string(msg, "type", "container");
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding type:container [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_msg_add_fmt(msg, "creationTime", "%lu", time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding creationTime [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_add(lctx->ldb, msg);
    if (ret != EOK) {
        if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Secret %s already exists\n", ldb_dn_get_linearized(msg->dn));
            ret = EEXIST;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add secret [%s]: [%d]: %s\n",
                  ldb_dn_get_linearized(msg->dn), ret, ldb_strerror(ret));
            ret = EIO;
        }
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);
    return ret;
}

static int local_secrets_map_path(TALLOC_CTX *mem_ctx,
                                  struct local_context *lctx,
                                  struct sec_req_ctx *secreq,
                                  struct local_db_req **_lc_req)
{
    int ret;
    struct local_db_req *lc_req;
    struct ldb_context *ldb = lctx->ldb;

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

    lc_req = talloc(mem_ctx, struct local_db_req);
    if (lc_req == NULL) {
        return ENOMEM;
    }

    /* drop the prefix and select a basedn instead */
    if (strncmp(secreq->mapped_path,
                SEC_BASEPATH, sizeof(SEC_BASEPATH) - 1) == 0) {
        lc_req->path = talloc_strdup(lc_req,
                                     secreq->mapped_path + (sizeof(SEC_BASEPATH) - 1));
        lc_req->basedn = SECRETS_BASEDN;
        lc_req->quota = lctx->quota_secrets;
    } else if (strncmp(secreq->mapped_path,
               SEC_KCM_BASEPATH, sizeof(SEC_KCM_BASEPATH) - 1) == 0) {
        lc_req->path = talloc_strdup(lc_req,
                                     secreq->mapped_path + (sizeof(SEC_KCM_BASEPATH) - 1));
        lc_req->basedn = KCM_BASEDN;
        lc_req->quota = lctx->quota_kcm;
    } else {
        ret = EINVAL;
        goto done;
    }

    if (lc_req->path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to local db path\n");
        ret = ENOMEM;
        goto done;
    }

    ret = local_db_dn(mem_ctx, ldb, lc_req->basedn, lc_req->path, &lc_req->req_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to local db DN\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Local DB path is %s\n", lc_req->path);
    ret = EOK;
    *_lc_req = lc_req;
done:
    if (ret != EOK) {
        talloc_free(lc_req);
    }
    return ret;
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
    struct local_db_req *lc_req;
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

    DEBUG(SSSDBG_TRACE_INTERNAL, "Received a local secrets request\n");

    if (sec_req_has_header(secreq, "Content-Type",
                                  "application/json")) {
        body_is_json = true;
        content_type = "application/json";
    } else if (sec_req_has_header(secreq, "Content-Type",
                           "application/octet-stream")) {
        body_is_json = false;
        content_type = "application/octet-stream";
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "No or unknown Content-Type\n");
        ret = EINVAL;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Content-Type: %s\n", content_type);

    ret = local_secrets_map_path(state, lctx, secreq, &lc_req);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot map request path to local path\n");
        goto done;
    }

    switch (secreq->method) {
    case HTTP_GET:
        DEBUG(SSSDBG_TRACE_LIBS, "Processing HTTP GET at [%s]\n", lc_req->path);
        if (lc_req->path[strlen(lc_req->path) - 1] == '/') {
            ret = local_db_list_keys(state, lctx, lc_req, &keys, &nkeys);
            if (ret) goto done;

            ret = sec_array_to_json(state, keys, nkeys, &body.data);
            if (ret) goto done;

            body.length = strlen(body.data);
            break;
        }

        ret = local_db_get_simple(state, lctx, lc_req, &secret);
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
        if (secreq->body.length == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "PUT with no data\n");
            ret = EINVAL;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Processing HTTP PUT at [%s]\n", lc_req->path);
        if (body_is_json) {
            ret = sec_json_to_simple_secret(state, secreq->body.data,
                                            &secret);
        } else {
            secret = sss_base64_encode(state, (uint8_t *)secreq->body.data,
                                       secreq->body.length);
            ret = secret ? EOK : ENOMEM;
        }
        if (ret) goto done;

        ret = local_db_put_simple(state, lctx, lc_req, secret);
        if (ret) goto done;
        break;

    case HTTP_DELETE:
        ret = local_db_delete(state, lctx, lc_req);
        if (ret) goto done;
        break;

    case HTTP_POST:
        DEBUG(SSSDBG_TRACE_LIBS, "Processing HTTP POST at [%s]\n", lc_req->path);
        plen = strlen(lc_req->path);

        if (lc_req->path[plen - 1] != '/') {
            ret = EINVAL;
            goto done;
        }

        lc_req->path[plen - 1] = '\0';

        ret = local_db_create(state, lctx, lc_req);
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
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_LIBS, "Did not find the requested data\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Local secrets request error [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
        tevent_req_error(req, ret);
    } else {
        /* shortcircuit the request here as all called functions are
         * synchronous and final and no further subrequests are made */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Local secrets request done\n");
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
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "generate_csprng_buffer failed [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    fd = open(filename, O_CREAT|O_EXCL|O_WRONLY, 0600);
    if (fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "open(%s) failed [%d]: %s\n",
              filename, ret, strerror(ret));
        return ret;
    }

    rsize = sss_atomic_write_s(fd, buf, size);
    close(fd);
    if (rsize != size) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_atomic_write_s failed [%d]: %s\n",
              ret, strerror(ret));

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

    DEBUG(SSSDBG_TRACE_INTERNAL, "Creating a local provider handle\n");

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
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_connect(%s) returned %d: %s\n",
              dbpath, ret, ldb_strerror(ret));
        talloc_free(lctx->ldb);
        return EIO;
    }

    lctx->quota_secrets = &sctx->sec_config.quota;
    lctx->quota_kcm = &sctx->kcm_config.quota;

    lctx->master_key.data = talloc_size(lctx, MKEY_SIZE);
    if (!lctx->master_key.data) return ENOMEM;
    lctx->master_key.length = MKEY_SIZE;

    ret = check_and_open_readonly(mkey, &mfd, 0, 0,
                                  S_IFREG|S_IRUSR|S_IWUSR, 0);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No master key, generating a new one..\n");

        ret = generate_master_key(mkey, MKEY_SIZE);
        if (ret) return EFAULT;
        ret = check_and_open_readonly(mkey, &mfd, 0, 0,
                                      S_IFREG|S_IRUSR|S_IWUSR, 0);
    }
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot generate a master key: %d\n", ret);
        return EFAULT;
    }

    size = sss_atomic_read_s(mfd, lctx->master_key.data,
                             lctx->master_key.length);
    close(mfd);
    if (size < 0 || size != lctx->master_key.length) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read a master key: %d\n", ret);
        return EIO;
    }

    handle->context = lctx;

    *out_handle = handle;
    DEBUG(SSSDBG_TRACE_INTERNAL, "Local provider handle created\n");
    return EOK;
}
