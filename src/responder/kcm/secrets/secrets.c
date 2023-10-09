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
#include "config.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <uuid/uuid.h>

#include "responder/kcm/kcmsrv_ccache.h"
#include "util/util.h"
#include "util/util_creds.h"
#include "util/sss_iobuf.h"
#include "util/strtonum.h"
#include "util/crypto/sss_crypto.h"
#include "sec_pvt.h"
#include "secrets.h"

#define KCM_PEER_UID            0

#define KCM_BASEDN      "cn=kcm"

#define LOCAL_CONTAINER_FILTER     "(type=container)"
#define LOCAL_NON_CONTAINER_FILTER "(!"LOCAL_CONTAINER_FILTER")"

#define SEC_ATTR_SECRET  "secret"
#define SEC_ATTR_TYPE    "type"
#define SEC_ATTR_CTIME   "creationTime"

static struct sss_sec_quota default_kcm_quota = {
    .max_secrets = DEFAULT_SEC_KCM_MAX_SECRETS,
    .max_uid_secrets = DEFAULT_SEC_KCM_MAX_UID_SECRETS,
    .max_payload_size = DEFAULT_SEC_KCM_MAX_PAYLOAD_SIZE,
    .containers_nest_level = DEFAULT_SEC_CONTAINERS_NEST_LEVEL,
};

static char *local_dn_to_path(TALLOC_CTX *mem_ctx,
                              struct ldb_dn *basedn,
                              struct ldb_dn *dn);

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
                     attrs, LOCAL_NON_CONTAINER_FILTER);
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

static errno_t get_secret_expiration_time(uint8_t *key, size_t key_length,
                                          uint8_t *sec, size_t sec_length,
                                          time_t *_expiration)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    time_t expiration = 0;
    struct cli_creds client = {};
    struct kcm_ccache *cc;
    struct sss_iobuf *iobuf;
    krb5_creds **cred_list, **cred;
    const char *key_str;

    if (_expiration == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    key_str = talloc_strndup(tmp_ctx, (const char *) key, key_length);
    if (key_str == NULL) {
        ret = ENOMEM;
        goto done;
    }

    iobuf = sss_iobuf_init_readonly(tmp_ctx, sec, sec_length);
    if (iobuf == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sec_kv_to_ccache_binary(tmp_ctx, key_str, iobuf, &client, &cc);
    if (ret != EOK) {
        goto done;
    }

    cred_list = kcm_cc_unmarshal(tmp_ctx, NULL, cc);
    if (cred_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (cred = cred_list; *cred != NULL; cred++) {
        if ((*cred)->times.endtime != 0) {
            expiration = (time_t) (*cred)->times.endtime;
            break;
        }
    }

    *_expiration = expiration;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t local_db_remove_oldest_expired_secret(struct ldb_result *res,
                                                     struct sss_sec_req *req)
{
    struct sss_sec_req *new_req = NULL;
    const struct ldb_val *val;
    const struct ldb_val *rdn;
    struct ldb_message *msg;
    struct ldb_message_element *elem;
    struct ldb_dn *basedn;
    struct ldb_dn *oldest_dn = NULL;
    time_t oldest_time = time(NULL);
    time_t expiration;
    unsigned int i;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Removing the oldest expired credential\n");
    /* Between all the messages in result, there is also the key we are
     * currently treating, but because yet it doesn't have an expiration time,
     * it will be skipped.
     */
    for (i = 0; i < res->count; i++) {
        msg = res->msgs[i];

        /* Skip cn=default,... or any non cn=... */
        rdn = ldb_dn_get_rdn_val(msg->dn);
        if (strcmp(ldb_dn_get_rdn_name(msg->dn), "cn") != 0
            || strncmp("default", (char *) rdn->data, rdn->length) == 0) {
            continue;
        }

        elem = ldb_msg_find_element(msg, SEC_ATTR_SECRET);
        if (elem != NULL) {
            if (elem->num_values != 1) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Element %s has %u values. Ignoring it.\n",
                      SEC_ATTR_SECRET, elem->num_values);
                ret = ERR_MALFORMED_ENTRY;
                goto done;
            }

            val = &elem->values[0];
            ret = get_secret_expiration_time(rdn->data, rdn->length,
                                             val->data, val->length,
                                             &expiration);
            if (ret != EOK) {
                goto done;
            }
            if (expiration > 0 && expiration < oldest_time) {
                oldest_dn = msg->dn;
                oldest_time = expiration;
            }
        }
    }

    if (oldest_dn == NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Found no expired credential to remove\n");
        ret = ERR_NO_MATCHING_CREDS;
        goto done;
    }

    new_req = talloc_zero(NULL, struct sss_sec_req);
    if (new_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate the new request\n");
        ret = ENOMEM;
        goto done;
    }

    basedn = ldb_dn_new(new_req, req->sctx->ldb, req->basedn);
    if (basedn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create a dn: %s\n", req->basedn);
        ret = EINVAL;
        goto done;
    }

    new_req->basedn = req->basedn;
    new_req->quota = req->quota;
    new_req->req_dn = oldest_dn;
    new_req->sctx = req->sctx;
    new_req->path = local_dn_to_path(new_req, basedn, oldest_dn);
    if (new_req->path == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create the path\n");
        ret = EINVAL;
        goto done;
    }

    ret = sss_sec_delete(new_req);

done:
    if (new_req != NULL)
        talloc_free(new_req);

    return ret;
}


static int local_db_check_peruid_number_of_secrets(TALLOC_CTX *mem_ctx,
                                                   struct sss_sec_req *req)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { SEC_ATTR_SECRET, NULL };
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
                     attrs, LOCAL_NON_CONTAINER_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned %d: %s\n", ret, ldb_strerror(ret));
        goto done;
    }

    if (res->count >= req->quota->max_uid_secrets) {
        /* We reached the limit. Let's try to removed the
         * oldest expired credential to free some space. */
        ret = local_db_remove_oldest_expired_secret(res, req);
        if (ret != EOK) {
            if (ret == ERR_NO_MATCHING_CREDS) {
                /* max_uid_secrets is incremented by 2 for internal entries. */
                DEBUG(SSSDBG_OP_FAILURE,
                      "Cannot store any more secrets for this client (basedn %s) "
                      "as the maximum allowed limit (%d) has been reached\n",
                      ldb_dn_get_linearized(cli_basedn),
                      req->quota->max_uid_secrets - 2);
                ret = ERR_SEC_INVALID_TOO_MANY_SECRETS;
            }
            goto done;
        }
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

    max_payload_size = req->quota->max_payload_size * 1024; /* KiB */
    if (payload_size > max_payload_size) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Secrets' payload size [%d KiB (%d B)] exceeds the maximum "
              "allowed payload size [%d KiB (%d B)]\n",
              payload_size / 1024, /* KiB */
              payload_size,
              req->quota->max_payload_size, /* KiB */
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

    ret = ldb_msg_add_string(msg, SEC_ATTR_TYPE, "container");
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding type:container [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_msg_add_fmt(msg, SEC_ATTR_CTIME, "%lu", time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding creationTime [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_add(req->sctx->ldb, msg);
    if (ret != LDB_SUCCESS) {
        if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
            DEBUG(SSSDBG_FUNC_DATA,
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

/* non static since it is used in test_kcm_renewals.c */
errno_t sss_sec_init_with_path(TALLOC_CTX *mem_ctx,
                               struct sss_sec_quota *quota,
                               const char *dbpath,
                               struct sss_sec_ctx **_sec_ctx)
{
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

    if (quota) {
        sec_ctx->quota_kcm = quota;
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "No custom quota set, using defaults\n");
        sec_ctx->quota_kcm = &default_kcm_quota;
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

    ret = EOK;
    *_sec_ctx = talloc_steal(mem_ctx, sec_ctx);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_sec_init(TALLOC_CTX *mem_ctx,
                     struct sss_sec_quota *quota,
                     struct sss_sec_ctx **_sec_ctx)
{
    const char *dbpath = SECRETS_DB_PATH"/secrets.ldb";
    errno_t ret;

    ret = sss_sec_init_with_path(mem_ctx, quota, dbpath, _sec_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize secdb [%d]: %s\n",
                                   ret, sss_strerror(ret));
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
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

    /* drop the prefix and select a basedn instead */
    if (geteuid() != KCM_PEER_UID && client != KCM_PEER_UID) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "UID %"SPRIuid" is not allowed to access the KCM hive\n",
              client);
        ret = EPERM;
        goto done;
    }

    req->basedn = KCM_BASEDN;
    req->quota = sec_ctx->quota_kcm;
    req->path = talloc_strdup(req, url);
    if (req->path == NULL) {
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

/* Complete list of ccache names(UUID:name) */
errno_t sss_sec_list_cc_uuids(TALLOC_CTX *mem_ctx,
                              struct sss_sec_ctx *sec,
                              const char ***_uuid_list,
                              const char ***_uid_list,
                              size_t *_uuid_list_count)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *dn;
    const struct ldb_val *name_val;
    const struct ldb_val *uid_val;
    static const char *attrs[] = { "distinguishedName", NULL };
    const char **uuid_list;
    const char **uid_list;
    size_t real_count = 0;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new(tmp_ctx, sec->ldb, "cn=persistent,cn=kcm");

    ret = ldb_search(sec->ldb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
           attrs, LOCAL_NON_CONTAINER_FILTER);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "ldb_search returned [%d]: %s\n", ret, ldb_strerror(ret));
        ret = EIO;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_LIBS, "No ccaches found\n");
        ret = ENOENT;
        goto done;
    }

    uuid_list = talloc_zero_array(tmp_ctx, const char *, res->count);
    if (uuid_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    uid_list = talloc_zero_array(tmp_ctx, const char *, res->count);
    if (uid_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; i < res->count; i++) {
        name_val = ldb_dn_get_component_val(res->msgs[i]->dn, 0);
        uid_val = ldb_dn_get_component_val(res->msgs[i]->dn, 2);
        if (strcmp((const char *)name_val->data, "default") == 0) {
            continue;
        }

        uuid_list[real_count] = talloc_strdup(uuid_list, (const char *)name_val->data);
        if (uuid_list[real_count] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate UUID\n");
            ret = ENOMEM;
            goto done;
        }

        uid_list[real_count] = talloc_strdup(uid_list, (const char *)uid_val->data);
        if (uid_list[real_count] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate uid\n");
            ret = ENOMEM;
            goto done;
        }

        real_count++;
    }

    *_uid_list = talloc_steal(mem_ctx, uid_list);
    *_uuid_list = talloc_steal(mem_ctx, uuid_list);
    *_uuid_list_count = real_count;

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_sec_list(TALLOC_CTX *mem_ctx,
                     struct sss_sec_req *req,
                     char ***_keys,
                     size_t *_num_keys)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { SEC_ATTR_SECRET, NULL };
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
          "Searching at [%s] with scope=subtree\n",
          ldb_dn_get_linearized(req->req_dn));

    ret = ldb_search(req->sctx->ldb, tmp_ctx, &res, req->req_dn, LDB_SCOPE_SUBTREE,
                     attrs, LOCAL_NON_CONTAINER_FILTER);
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
                    uint8_t **_secret,
                    size_t *_secret_len)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { SEC_ATTR_SECRET, NULL };
    struct ldb_result *res;
    const struct ldb_val *attr_secret;
    int ret;

    if (req == NULL || _secret == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Retrieving a secret from [%s]\n", req->path);

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Searching at [%s] with scope=base\n",
          ldb_dn_get_linearized(req->req_dn));

    ret = ldb_search(req->sctx->ldb, tmp_ctx, &res, req->req_dn, LDB_SCOPE_BASE,
                     attrs, LOCAL_NON_CONTAINER_FILTER);
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

    attr_secret = ldb_msg_find_ldb_val(res->msgs[0], SEC_ATTR_SECRET);
    if ((!attr_secret) || (attr_secret->length == 0)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "The 'secret' attribute is missing\n");
        ret = ENOENT;
        goto done;
    }

    *_secret = talloc_memdup(mem_ctx, attr_secret->data, attr_secret->length);
    if (*_secret == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (_secret_len) {
        *_secret_len = attr_secret->length;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_sec_put(struct sss_sec_req *req,
                    uint8_t *secret,
                    size_t secret_len)
{
    struct ldb_message *msg;
    struct ldb_val secret_val;
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

    ret = local_db_check_peruid_number_of_secrets(msg, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_peruid_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_number_of_secrets(msg, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_check_max_payload_size(req, secret_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_check_max_payload_size failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    secret_val.length = secret_len;
    secret_val.data = talloc_memdup(req->sctx, secret, secret_len);
    if (!secret_val.data) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_value(msg, SEC_ATTR_SECRET, &secret_val, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_add_string failed adding secret [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_msg_add_fmt(msg, SEC_ATTR_CTIME, "%lu", time(NULL));
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
                       uint8_t *secret,
                       size_t secret_len)
{
    struct ldb_message *msg;
    struct ldb_val secret_val;
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

    ret = local_db_check_peruid_number_of_secrets(msg, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_peruid_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_db_check_number_of_secrets(msg, req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_db_check_number_of_secrets failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = local_check_max_payload_size(req, secret_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "local_check_max_payload_size failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    secret_val.length = secret_len;
    secret_val.data = talloc_memdup(req->sctx, secret, secret_len);
    if (!secret_val.data) {
        ret = ENOMEM;
        goto done;
    }

    /* FIXME - should we have a lastUpdate timestamp? */
    ret = ldb_msg_add_empty(msg, SEC_ATTR_SECRET, LDB_FLAG_MOD_REPLACE, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_msg_add_empty failed: [%s]\n", ldb_strerror(ret));
        ret = EIO;
        goto done;
    }

    ret = ldb_msg_add_value(msg, SEC_ATTR_SECRET, &secret_val, NULL);
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
