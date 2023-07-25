/*
    SSSD

    Kerberos 5 Backend Module -- Request a TGT when the system gets online

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <security/pam_modules.h>
#ifdef USE_KEYRING
#include <sys/types.h>
#include <keyutils.h>
#endif
#include <dhash.h>

#include "providers/krb5/krb5_auth.h"
#include "util/util.h"
#include "util/find_uid.h"

struct deferred_auth_ctx {
    hash_table_t *user_table;
    struct be_ctx *be_ctx;
    struct tevent_context *ev;
    struct krb5_ctx *krb5_ctx;
};

struct auth_data {
    struct be_ctx *be_ctx;
    struct krb5_ctx *krb5_ctx;
    struct pam_data *pd;
};

static void *hash_talloc(const size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void hash_talloc_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

static void authenticate_user_done(struct tevent_req *req);
static void authenticate_user(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval current_time,
                              void *private_data)
{
    struct auth_data *auth_data = talloc_get_type(private_data,
                                                  struct auth_data);
    struct pam_data *pd = auth_data->pd;
    struct tevent_req *req;

    DEBUG_PAM_DATA(SSSDBG_TRACE_ALL, pd);

#ifdef USE_KEYRING
    char *password;
    long keysize;
    long keyrevoke;
    errno_t ret;

    keysize = keyctl_read_alloc(pd->key_serial, (void **)&password);
    if (keysize == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "keyctl_read failed [%d][%s].\n", ret, strerror(ret));
        return;
    }

    ret = sss_authtok_set_password(pd->authtok, password, keysize);
    sss_erase_mem_securely(password, keysize);
    free(password);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "failed to set password in auth token [%d][%s].\n",
                  ret, strerror(ret));
        return;
    }

    keyrevoke = keyctl_revoke(pd->key_serial);
    if (keyrevoke == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "keyctl_revoke failed [%d][%s].\n", ret, strerror(ret));
    }
#endif

    req = krb5_auth_queue_send(auth_data, ev, auth_data->be_ctx,
                               auth_data->pd, auth_data->krb5_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_auth_send failed.\n");
        talloc_free(auth_data);
        return;
    }

    tevent_req_set_callback(req, authenticate_user_done, auth_data);
}

static void authenticate_user_done(struct tevent_req *req)
{
    struct auth_data *auth_data = tevent_req_callback_data(req,
                                                           struct auth_data);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err = DP_ERR_OK;

    ret = krb5_auth_queue_recv(req, &pam_status, &dp_err);
    talloc_free(req);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_auth request failed.\n");
    } else {
        if (pam_status == PAM_SUCCESS) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Successfully authenticated user [%s].\n",
                      auth_data->pd->user);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to authenticate user [%s].\n",
                      auth_data->pd->user);
        }
    }

    talloc_free(auth_data);
}

static errno_t authenticate_stored_users(
            struct deferred_auth_ctx *deferred_auth_ctx)
{
    int ret;
    hash_table_t *uid_table;
    struct hash_iter_context_t *iter;
    hash_entry_t *entry;
    hash_key_t key;
    hash_value_t value;
    struct pam_data *pd;
    struct auth_data *auth_data;
    struct tevent_timer *te;

    ret = get_uid_table(deferred_auth_ctx, &uid_table);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "get_uid_table failed.\n");
        return ret;
    }

    iter = new_hash_iter_context(deferred_auth_ctx->user_table);
    if (iter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "new_hash_iter_context failed.\n");
        return EINVAL;
    }

    while ((entry = iter->next(iter)) != NULL) {
        key.type = HASH_KEY_ULONG;
        key.ul = entry->key.ul;
        pd = talloc_get_type(entry->value.ptr, struct pam_data);

        ret = hash_lookup(uid_table, &key, &value);

        if (ret == HASH_SUCCESS) {
            DEBUG(SSSDBG_FUNC_DATA, "User [%s] is still logged in, "
                      "trying online authentication.\n", pd->user);

            auth_data = talloc_zero(deferred_auth_ctx->be_ctx,
                                    struct auth_data);
            if (auth_data == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
            } else {
                auth_data->pd = talloc_steal(auth_data, pd);
                auth_data->krb5_ctx = deferred_auth_ctx->krb5_ctx;
                auth_data->be_ctx = deferred_auth_ctx->be_ctx;

                te = tevent_add_timer(deferred_auth_ctx->ev,
                                      auth_data, tevent_timeval_current(),
                                      authenticate_user, auth_data);
                if (te == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
                }
            }
        } else {
            DEBUG(SSSDBG_FUNC_DATA, "User [%s] is not logged in anymore, "
                      "discarding online authentication.\n", pd->user);
            talloc_free(pd);
        }

        ret = hash_delete(deferred_auth_ctx->user_table,
                          &entry->key);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "hash_delete failed [%s].\n",
                      hash_error_string(ret));
        }
    }

    talloc_free(iter);

    return EOK;
}

static void delayed_online_authentication_callback(void *private_data)
{
    struct deferred_auth_ctx *deferred_auth_ctx =
            talloc_get_type(private_data, struct deferred_auth_ctx);
    int ret;

    if (deferred_auth_ctx->user_table == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Delayed online authentication activated, "
                  "but user table does not exists.\n");
        return;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Backend is online, starting delayed online authentication.\n");
    ret = authenticate_stored_users(deferred_auth_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "authenticate_stored_users failed.\n");
    }

    return;
}

errno_t add_user_to_delayed_online_authentication(struct krb5_ctx *krb5_ctx,
                                                  struct sss_domain_info *domain,
                                                  struct pam_data *pd,
                                                  uid_t uid)
{
    int ret;
    hash_key_t key;
    hash_value_t value;
    struct pam_data *new_pd;

    if (domain->type != DOM_TYPE_POSIX) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Domain type does not support delayed authentication\n");
        return ENOTSUP;
    }

    if (krb5_ctx->deferred_auth_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing context for delayed online authentication.\n");
        return EINVAL;
    }

    if (krb5_ctx->deferred_auth_ctx->user_table == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "user_table not available.\n");
        return EINVAL;
    }

    if (sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_PASSWORD) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Invalid authtok for user [%s].\n", pd->user);
        return EINVAL;
    }

    ret = copy_pam_data(krb5_ctx->deferred_auth_ctx, pd, &new_pd);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "copy_pam_data failed\n");
        return ENOMEM;
    }


#ifdef USE_KEYRING
    const char *password;
    size_t len;

    ret = sss_authtok_get_password(new_pd->authtok, &password, &len);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get password [%d][%s].\n", ret, strerror(ret));
        sss_authtok_set_empty(new_pd->authtok);
        talloc_free(new_pd);
        return ret;
    }

    new_pd->key_serial = add_key("user", new_pd->user, password, len,
                                 KEY_SPEC_SESSION_KEYRING);
    if (new_pd->key_serial == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "add_key failed [%d][%s].\n", ret, strerror(ret));
        sss_authtok_set_empty(new_pd->authtok);
        talloc_free(new_pd);
        return ret;
    }
    DEBUG(SSSDBG_TRACE_ALL,
          "Saved authtok of user [%s] with serial [%"SPRIkey_ser"].\n",
              new_pd->user, new_pd->key_serial);
    sss_authtok_set_empty(new_pd->authtok);
#endif

    key.type = HASH_KEY_ULONG;
    key.ul = uid;
    value.type = HASH_VALUE_PTR;
    value.ptr = new_pd;

    ret = hash_enter(krb5_ctx->deferred_auth_ctx->user_table,
                     &key, &value);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot add user [%s] to table [%s], "
                  "delayed online authentication not possible.\n",
                  pd->user, hash_error_string(ret));
        talloc_free(new_pd);
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Added user [%s] successfully to "
              "delayed online authentication.\n", pd->user);

    return EOK;
}

errno_t init_delayed_online_authentication(struct krb5_ctx *krb5_ctx,
                                           struct be_ctx *be_ctx,
                                           struct tevent_context *ev)
{
    int ret;
    hash_table_t *tmp_table;

    ret = get_uid_table(krb5_ctx, &tmp_table);
    if (ret != EOK) {
        if (ret == ENOSYS) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Delayed online auth was requested "
                      "on an unsupported system.\n");
        } else {
            DEBUG(SSSDBG_FATAL_FAILURE, "Delayed online auth was requested "
                      "but initialisation failed.\n");
        }
        return ret;
    }
    ret = hash_destroy(tmp_table);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "hash_destroy failed [%s].\n", hash_error_string(ret));
        return EFAULT;
    }

    krb5_ctx->deferred_auth_ctx = talloc_zero(krb5_ctx,
                                          struct deferred_auth_ctx);
    if (krb5_ctx->deferred_auth_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ret = hash_create_ex(0,
                         &krb5_ctx->deferred_auth_ctx->user_table,
                         0, 0, 0, 0, hash_talloc, hash_talloc_free,
                         krb5_ctx->deferred_auth_ctx,
                         NULL, NULL);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "hash_create_ex failed [%s]\n", hash_error_string(ret));
        ret = ENOMEM;
        goto fail;
    }

    krb5_ctx->deferred_auth_ctx->be_ctx = be_ctx;
    krb5_ctx->deferred_auth_ctx->krb5_ctx = krb5_ctx;
    krb5_ctx->deferred_auth_ctx->ev = ev;

    ret = be_add_online_cb(krb5_ctx, be_ctx,
                           delayed_online_authentication_callback,
                           krb5_ctx->deferred_auth_ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_add_online_cb failed.\n");
        goto fail;
    }

    /* TODO: add destructor */

    return EOK;
fail:
    talloc_zfree(krb5_ctx->deferred_auth_ctx);
    return ret;
}
