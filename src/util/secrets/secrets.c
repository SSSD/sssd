/*
   SSSD

   Local secrets database

   Copyright (C) Red Hat 2018

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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/secrets/sec_pvt.h"
#include "util/secrets/secrets.h"

#define KCM_PEER_UID            0
#define MKEY_SIZE               (256 / 8)

#define SECRETS_BASEDN  "cn=secrets"
#define KCM_BASEDN      "cn=kcm"

#define LOCAL_SIMPLE_FILTER "(type=simple)"
#define LOCAL_CONTAINER_FILTER "(type=container)"

typedef int (*url_mapper_fn)(TALLOC_CTX *mem_ctx,
                             const char *url,
                             uid_t client,
                             char **mapped_path);

struct url_pfx_router {
    const char *prefix;
    url_mapper_fn mapper_fn;
};

static struct sss_sec_quota default_sec_quota = {
    .max_secrets = DEFAULT_SEC_MAX_SECRETS,
    .max_uid_secrets = DEFAULT_SEC_MAX_UID_SECRETS,
    .max_payload_size = DEFAULT_SEC_MAX_PAYLOAD_SIZE,
    .containers_nest_level = DEFAULT_SEC_CONTAINERS_NEST_LEVEL,
};

static struct sss_sec_quota default_kcm_quota = {
    .max_secrets = DEFAULT_SEC_KCM_MAX_SECRETS,
    .max_uid_secrets = DEFAULT_SEC_KCM_MAX_UID_SECRETS,
    .max_payload_size = DEFAULT_SEC_KCM_MAX_PAYLOAD_SIZE,
    .containers_nest_level = DEFAULT_SEC_CONTAINERS_NEST_LEVEL,
};

static int local_decrypt(struct sss_sec_ctx *sctx, TALLOC_CTX *mem_ctx,
                         const char *secret, const char *enctype,
                         char **plain_secret)
{
    char *output;

    if (enctype && strcmp(enctype, "masterkey") == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Decrypting with masterkey\n");

        struct sss_sec_data _secret;
        size_t outlen;
        int ret;

        _secret.data = (char *)sss_base64_decode(mem_ctx, secret,
                                                 &_secret.length);
        if (!_secret.data) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed\n");
            return EINVAL;
        }

        ret = sss_decrypt(mem_ctx, AES256CBC_HMAC_SHA256,
                          (uint8_t *)sctx->master_key.data,
                          sctx->master_key.length,
                          (uint8_t *)_secret.data, _secret.length,
                          (uint8_t **)&output, &outlen);
        talloc_free(_secret.data);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_decrypt failed [%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }

        if (((strnlen(output, outlen) + 1) != outlen) ||
            output[outlen - 1] != '\0') {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Output length mismatch or output not NULL-terminated\n");
            talloc_free(output);
            return EIO;
        }
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Unexpected enctype (not 'masterkey')\n");
        output = talloc_strdup(mem_ctx, secret);
        if (!output) return ENOMEM;
    }

    *plain_secret = output;
    return EOK;
}

static int local_encrypt(struct sss_sec_ctx *sec_ctx, TALLOC_CTX *mem_ctx,
                         const char *secret, const char *enctype,
                         char **ciphertext)
{
    struct sss_sec_data _secret;
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
                      (uint8_t *)sec_ctx->master_key.data,
                      sec_ctx->master_key.length,
                      (const uint8_t *)secret, strlen(secret) + 1,
                      (uint8_t **)&_secret.data, &_secret.length);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_encrypt failed [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    output = sss_base64_encode(mem_ctx,
                               (uint8_t *)_secret.data, _secret.length);
    talloc_free(_secret.data);
    if (!output) return ENOMEM;

    *ciphertext = output;
    return EOK;
}

static int local_db_check_containers(TALLOC_CTX *mem_ctx,
                                     struct sss_sec_ctx *sec_ctx,
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

        ret = ldb_search(sec_ctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                         attrs, LOCAL_CONTAINER_FILTER);
        if (ret != LDB_SUCCESS || res->count != 1) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "DN [%s] does not exist\n", ldb_dn_get_linearized(dn));
            ret = ENOENT;
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_db_check_number_of_secrets(TALLOC_CTX *mem_ctx,
                                            struct sss_sec_req *req)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { NULL };
    struct ldb_result *res = NULL;
    struct ldb_dn *dn;
    int ret;

    if (req->quota->max_secrets == 0) {
        return EOK;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    dn = ldb_dn_new(tmp_ctx, req->sctx->ldb, req->basedn);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(req->sctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
                     attrs, LOCAL_SIMPLE_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned %d: %s\n", ret, ldb_strerror(ret));
        goto done;
    }

    if (res->count >= req->quota->max_secrets) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store any more secrets as the maximum allowed limit (%d) "
              "has been reached\n", req->quota->max_secrets);
        ret = ERR_SEC_INVALID_TOO_MANY_SECRETS;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
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
                                                   struct sss_sec_req *req)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { NULL };
    struct ldb_result *res = NULL;
    struct ldb_dn *cli_basedn = NULL;
    int ret;

    if (req->quota->max_uid_secrets == 0) {
        return EOK;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    cli_basedn = per_uid_container(tmp_ctx, req->req_dn);
    if (cli_basedn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(req->sctx->ldb, tmp_ctx, &res, cli_basedn, LDB_SCOPE_SUBTREE,
                     attrs, LOCAL_SIMPLE_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned %d: %s\n", ret, ldb_strerror(ret));
        goto done;
    }

    if (res->count >= req->quota->max_uid_secrets) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store any more secrets for this client (basedn %s) "
              "as the maximum allowed limit (%d) has been reached\n",
              ldb_dn_get_linearized(cli_basedn),
              req->quota->max_uid_secrets);
        ret = ERR_SEC_INVALID_TOO_MANY_SECRETS;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int local_check_max_payload_size(struct sss_sec_req *req,
                                        int payload_size)
{
    int max_payload_size;

    if (req->quota->max_payload_size == 0) {
        return EOK;
    }

    max_payload_size = req->quota->max_payload_size * 1024; /* kb */
    if (payload_size > max_payload_size) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Secrets' payload size [%d kb (%d)] exceeds the maximum allowed "
              "payload size [%d kb (%d)]\n",
              payload_size * 1024, /* kb */
              payload_size,
              req->quota->max_payload_size, /* kb */
              max_payload_size);

        return ERR_SEC_PAYLOAD_SIZE_IS_TOO_LARGE;
    }

    return EOK;
}

static int local_db_check_containers_nest_level(struct sss_sec_req *req,
                                                struct ldb_dn *leaf_dn)
{
    int nest_level;

    if (req->quota->containers_nest_level == 0) {
        return EOK;
    }

    /* We need do not care for the synthetic containers that constitute the
     * base path (cn=<uidnumber>,cn=user,cn=secrets). */
    nest_level = ldb_dn_get_comp_num(leaf_dn) - 3;
    if (nest_level > req->quota->containers_nest_level) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot create a nested container of depth %d as the maximum"
              "allowed number of nested containers is %d.\n",
              nest_level, req->quota->containers_nest_level);

        return ERR_SEC_INVALID_CONTAINERS_NEST_LEVEL;
    }

    return EOK;
}

static int local_db_create(struct sss_sec_req *req)
{
    struct ldb_message *msg;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Creating a container at [%s]\n", req->path);

    msg = ldb_msg_new(req);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = req->req_dn;

    /* make sure containers exist */
    ret = local_db_check_containers(msg, req->sctx, msg->dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_containers failed for [%s]: [%d]: %s\n",
              ldb_dn_get_linearized(msg->dn), ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_containers_nest_level(req, msg->dn);
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

    ret = ldb_add(req->sctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Secret %s already exists\n", ldb_dn_get_linearized(msg->dn));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add secret [%s]: [%d]: %s\n",
                  ldb_dn_get_linearized(msg->dn), ret, ldb_strerror(ret));
        }
        ret = sss_ldb_error_to_errno (ret);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);
    return ret;
}

static int sec_map_url_to_user_path(TALLOC_CTX *mem_ctx,
                                    const char *url,
                                    uid_t client,
                                    char **mapped_path)
{
    /* change path to be user specific */
    *mapped_path =
        talloc_asprintf(mem_ctx, SSS_SEC_BASEPATH"users/%"SPRIuid"/%s",
                        client,
                        &url[sizeof(SSS_SEC_BASEPATH) - 1]);
    if (!*mapped_path) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to user specific url\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "User-specific secrets path is [%s]\n", *mapped_path);
    return EOK;
}

static int kcm_map_url_to_path(TALLOC_CTX *mem_ctx,
                               const char *url,
                               uid_t client,
                               char **mapped_path)
{
    if (client != KCM_PEER_UID) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "UID %"SPRIuid" is not allowed to access "
              "the "SSS_SEC_KCM_BASEPATH" hive\n",
              client);
        return EPERM;
    }

    *mapped_path = talloc_strdup(mem_ctx, url);
    if (!*mapped_path) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to user specific url\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "User-specific KCM path is [%s]\n", *mapped_path);
    return EOK;
}

static struct url_pfx_router secrets_url_mapping[] = {
    { SSS_SEC_BASEPATH, sec_map_url_to_user_path },
    { SSS_SEC_KCM_BASEPATH, kcm_map_url_to_path },
    { NULL, NULL },
};

errno_t sss_sec_map_path(TALLOC_CTX *mem_ctx,
                         const char *url,
                         uid_t client,
                         char **_mapped_path)
{
    url_mapper_fn mapper_fn = NULL;
    errno_t ret;

    if (url == NULL || _mapped_path == NULL) {
        return EINVAL;
    }

    for (int i = 0; secrets_url_mapping[i].prefix != NULL; i++) {
        if (strncasecmp(url,
                        secrets_url_mapping[i].prefix,
                        strlen(secrets_url_mapping[i].prefix)) == 0) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Mapping prefix %s\n", secrets_url_mapping[i].prefix);
            mapper_fn = secrets_url_mapping[i].mapper_fn;
            break;
        }
    }

    if (mapper_fn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Path [%s] does not start with any allowed prefix\n",
              url);
        return EPERM;
    }

    ret = mapper_fn(mem_ctx, url, client, _mapped_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map the user path [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return ret;
}

static int generate_master_key(const char *filename, size_t size)
{
    uint8_t buf[size];
    ssize_t rsize;
    int ret;
    int fd;

    ret = sss_generate_csprng_buffer(buf, size);
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

static errno_t lcl_read_mkey(TALLOC_CTX *mem_ctx,
                             struct sss_sec_data *master_key)
{
    int mfd;
    ssize_t size;
    errno_t ret;
    const char *mkey = SECRETS_DB_PATH"/.secrets.mkey";

    master_key->data = talloc_size(mem_ctx, MKEY_SIZE);
    if (master_key->data == NULL) {
        return ENOMEM;
    }

    master_key->length = MKEY_SIZE;

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

    size = sss_atomic_read_s(mfd, master_key->data,
                             master_key->length);
    close(mfd);
    if (size < 0 || size != master_key->length) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read a master key: %d\n", ret);
        return EIO;
    }

    return EOK;
}

static int set_quotas(struct sss_sec_ctx *sec_ctx,
                      struct sss_sec_hive_config **config_list)
{
    sec_ctx->quota_secrets = &default_sec_quota;
    sec_ctx->quota_kcm = &default_kcm_quota;

    if (config_list == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "No custom quota set, using defaults\n");
        return EOK;
    }

    for (int i = 0; config_list[i] != NULL; i++) {
        if (strcasecmp(config_list[i]->hive_name, "kcm") == 0) {
            sec_ctx->quota_kcm = &config_list[i]->quota;
        } else if (strcasecmp(config_list[i]->hive_name, "secrets") == 0) {
            sec_ctx->quota_secrets = &config_list[i]->quota;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Uknown hive %s, skipping\n", config_list[i]->hive_name);
        }
    }

    return EOK;
}

errno_t sss_sec_init(TALLOC_CTX *mem_ctx,
                     struct sss_sec_hive_config **config_list,
                     struct sss_sec_ctx **_sec_ctx)
{
    const char *dbpath = SECRETS_DB_PATH"/secrets.ldb";
    struct sss_sec_ctx *sec_ctx;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    if (_sec_ctx == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    sec_ctx = talloc_zero(tmp_ctx, struct sss_sec_ctx);
    if (sec_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = set_quotas(sec_ctx, config_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to set quotas\n");
        /* Not fatal */
    }

    sec_ctx->ldb = ldb_init(sec_ctx, NULL);
    if (sec_ctx->ldb == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_connect(sec_ctx->ldb, dbpath, 0, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_connect(%s) returned %d: %s\n",
              dbpath, ret, ldb_strerror(ret));
        talloc_free(sec_ctx->ldb);
        ret = EIO;
        goto done;
    }

    ret = lcl_read_mkey(sec_ctx, &sec_ctx->master_key);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get the master key\n");
        goto done;
    }

    ret = EOK;
    *_sec_ctx = talloc_steal(mem_ctx, sec_ctx);
done:
    talloc_free(tmp_ctx);
    return ret;
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

errno_t sss_sec_new_req(TALLOC_CTX *mem_ctx,
                        struct sss_sec_ctx *sec_ctx,
                        const char *url,
                        uid_t client,
                        struct sss_sec_req **_req)
{
    struct sss_sec_req *req;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    if (sec_ctx == NULL || url == NULL || _req == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    req = talloc_zero(tmp_ctx, struct sss_sec_req);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }
    req->sctx = sec_ctx;

    ret = sss_sec_map_path(req, url, client, &req->mapped_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Mapping URL to path failed\n");
        goto done;
    }

    if (req->mapped_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "The path was not mapped properly!\n");
        ret = EINVAL;
        goto done;
    }

    /* drop the prefix and select a basedn instead */
    if (strncmp(req->mapped_path,
                SSS_SEC_BASEPATH,
                sizeof(SSS_SEC_BASEPATH) - 1) == 0) {

        if (geteuid() != 0 && client != geteuid()) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Only root can impersonate other users\n");
            ret = EPERM;
            goto done;
        }

        req->path = talloc_strdup(req,
                                     req->mapped_path + (sizeof(SSS_SEC_BASEPATH) - 1));
        req->basedn = SECRETS_BASEDN;
        req->quota = sec_ctx->quota_secrets;
    } else if (strncmp(req->mapped_path,
                       SSS_SEC_KCM_BASEPATH,
                       sizeof(SSS_SEC_KCM_BASEPATH) - 1) == 0) {

        if (geteuid() != KCM_PEER_UID && client != KCM_PEER_UID) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "UID %"SPRIuid" is not allowed to access "
                  "the "SSS_SEC_KCM_BASEPATH" hive\n",
                  client);
            ret = EPERM;
            goto done;
        }

        req->path = talloc_strdup(req,
                                  req->mapped_path + (sizeof(SSS_SEC_KCM_BASEPATH) - 1));
        req->basedn = KCM_BASEDN;
        req->quota = sec_ctx->quota_kcm;
    } else {
        ret = EINVAL;
        goto done;
    }

    if (req->path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to local db path\n");
        ret = ENOMEM;
        goto done;
    }

    ret = local_db_dn(req, sec_ctx->ldb, req->basedn, req->path, &req->req_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to local db DN\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Local DB path is %s\n", req->path);

    ret = EOK;
    *_req = talloc_steal(mem_ctx, req);
done:
    talloc_free(tmp_ctx);
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

errno_t sss_sec_list(TALLOC_CTX *mem_ctx,
                     struct sss_sec_req *req,
                     char ***_keys,
                     size_t *_num_keys)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { "secret", NULL };
    struct ldb_result *res;
    char **keys;
    int ret;

    if (req == NULL || _keys == NULL || _num_keys == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_FUNC, "Listing keys at [%s]\n", req->path);

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Searching for [%s] at [%s] with scope=subtree\n",
          LOCAL_SIMPLE_FILTER, ldb_dn_get_linearized(req->req_dn));

    ret = ldb_search(req->sctx->ldb, tmp_ctx, &res, req->req_dn, LDB_SCOPE_SUBTREE,
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
        keys[i] = local_dn_to_path(keys, req->req_dn, res->msgs[i]->dn);
        if (!keys[i]) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_keys = keys;
    DEBUG(SSSDBG_TRACE_LIBS, "Returning %d secrets\n", res->count);
    *_num_keys = res->count;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_sec_get(TALLOC_CTX *mem_ctx,
                    struct sss_sec_req *req,
                    char **_secret)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { "secret", "enctype", NULL };
    struct ldb_result *res;
    const char *attr_secret;
    const char *attr_enctype;
    int ret;

    if (req == NULL || _secret == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Retrieving a secret from [%s]\n", req->path);

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Searching for [%s] at [%s] with scope=base\n",
          LOCAL_SIMPLE_FILTER, ldb_dn_get_linearized(req->req_dn));

    ret = ldb_search(req->sctx->ldb, tmp_ctx, &res, req->req_dn, LDB_SCOPE_BASE,
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
        ret = local_decrypt(req->sctx, mem_ctx, attr_secret, attr_enctype, _secret);
        if (ret) goto done;
    } else {
        *_secret = talloc_strdup(mem_ctx, attr_secret);
    }
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_sec_put(struct sss_sec_req *req,
                    const char *secret)
{
    struct ldb_message *msg;
    const char *enctype = "masterkey";
    char *enc_secret;
    int ret;

    if (req == NULL || secret == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Adding a secret to [%s]\n", req->path);

    msg = ldb_msg_new(req);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = req->req_dn;

    /* make sure containers exist */
    ret = local_db_check_containers(msg, req->sctx, msg->dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_containers failed for [%s]: [%d]: %s\n",
              ldb_dn_get_linearized(msg->dn), ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_number_of_secrets(msg, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_peruid_number_of_secrets(msg, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_check_max_payload_size(req, strlen(secret));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_check_max_payload_size failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_encrypt(req->sctx, msg, secret, enctype, &enc_secret);
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

    ret = ldb_add(req->sctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Secret %s already exists\n", ldb_dn_get_linearized(msg->dn));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add secret [%s]: [%d]: %s\n",
                  ldb_dn_get_linearized(msg->dn), ret, ldb_strerror(ret));
        }
        ret = sss_ldb_error_to_errno (ret);
        goto done;
    }

    ret = EOK;
done:
    talloc_free(msg);
    return ret;
}

errno_t sss_sec_update(struct sss_sec_req *req,
                       const char *secret)
{
    struct ldb_message *msg;
    const char *enctype = "masterkey";
    char *enc_secret;
    int ret;

    if (req == NULL || secret == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Adding a secret to [%s]\n", req->path);

    msg = ldb_msg_new(req);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = req->req_dn;

    /* make sure containers exist */
    ret = local_db_check_containers(msg, req->sctx, msg->dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_containers failed for [%s]: [%d]: %s\n",
              ldb_dn_get_linearized(msg->dn), ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_number_of_secrets(msg, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_peruid_number_of_secrets(msg, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_check_max_payload_size(req, strlen(secret));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_check_max_payload_size failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_encrypt(req->sctx, msg, secret, enctype, &enc_secret);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_encrypt failed [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* FIXME - should we have a lastUpdate timestamp? */
    ret = ldb_msg_add_empty(msg, "secret", LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_msg_add_empty failed: [%s]\n", ldb_strerror(ret));
        ret = EIO;
        goto done;
    }

    ret = ldb_msg_add_string(msg, "secret", enc_secret);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_msg_add_string failed: [%s]\n", ldb_strerror(ret));
        ret = EIO;
        goto done;
    }

    ret = ldb_modify(req->sctx->ldb, msg);
    if (ret == LDB_ERR_NO_SUCH_OBJECT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No such object to modify\n");
        ret = sss_ldb_error_to_errno (ret);
        goto done;
    } else if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_modify failed: [%s](%d)[%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(req->sctx->ldb));
        ret = sss_ldb_error_to_errno (ret);
        goto done;
    }

    ret = EOK;
done:
    talloc_free(msg);
    return ret;
}

errno_t sss_sec_delete(struct sss_sec_req *req)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { NULL };
    struct ldb_result *res;
    int ret;

    if (req == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Removing a secret from [%s]\n", req->path);

    tmp_ctx = talloc_new(req);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Searching for [%s] at [%s] with scope=base\n",
          LOCAL_CONTAINER_FILTER, ldb_dn_get_linearized(req->req_dn));

    ret = ldb_search(req->sctx->ldb, tmp_ctx, &res, req->req_dn, LDB_SCOPE_BASE,
                     attrs, LOCAL_CONTAINER_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned %d: %s\n", ret, ldb_strerror(ret));
        goto done;
    }

    if (res->count == 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Searching for children of [%s]\n", ldb_dn_get_linearized(req->req_dn));
        ret = ldb_search(req->sctx->ldb, tmp_ctx, &res, req->req_dn, LDB_SCOPE_ONELEVEL,
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
                  ldb_dn_get_linearized(req->req_dn));

            goto done;
        }
    }

    ret = ldb_delete(req->sctx->ldb, req->req_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_delete returned %d: %s\n", ret, ldb_strerror(ret));
        /* fall through */
    }

    if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_OBJECT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "LDB returned unexpected error: [%s]\n",
               ldb_strerror(ret));
    }
    ret = sss_ldb_error_to_errno (ret);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_sec_create_container(struct sss_sec_req *req)
{
    int plen;

    if (req == NULL) {
        return EINVAL;
    }

    plen = strlen(req->path);

    if (req->path[plen - 1] != '/') {
        return EINVAL;
    }

    req->path[plen - 1] = '\0';
    return local_db_create(req);
}

bool sss_sec_req_is_list(struct sss_sec_req *req)
{
    if (req == NULL || req->mapped_path == NULL) {
        return false;
    }

    if (req->mapped_path[strlen(req->mapped_path) - 1] == '/') {
        return true;
    }

    return false;
}
