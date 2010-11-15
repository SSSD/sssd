/*
    SSSD

    Kerberos 5 Backend Module -- Renew a TGT automatically

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

#include "util/util.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_auth.h"

#define INITIAL_TGT_TABLE_SIZE 10

struct renew_tgt_ctx {
    hash_table_t *tgt_table;
    struct be_ctx *be_ctx;
    struct tevent_context *ev;
    struct krb5_ctx *krb5_ctx;
    time_t timer_interval;
    struct tevent_timer *te;
    bool added_to_online_callbacks;
};

struct renew_data {
    time_t start_time;
    time_t lifetime;
    time_t start_renew_at;
    struct pam_data *pd;
};

struct auth_data {
    struct be_ctx *be_ctx;
    struct krb5_ctx *krb5_ctx;
    struct pam_data *pd;
    hash_table_t *table;
    hash_key_t key;
};


static void renew_tgt_done(struct tevent_req *req);
static void renew_tgt(struct tevent_context *ev, struct tevent_timer *te,
                      struct timeval current_time, void *private_data)
{
    struct auth_data *auth_data = talloc_get_type(private_data,
                                                  struct auth_data);
    struct tevent_req *req;

    req = krb5_auth_send(auth_data, ev, auth_data->be_ctx, auth_data->pd,
                         auth_data->krb5_ctx);
    if (req == NULL) {
        DEBUG(1, ("krb5_auth_send failed.\n"));
        talloc_free(auth_data);
        return;
    }

    tevent_req_set_callback(req, renew_tgt_done, auth_data);
}

static void renew_tgt_done(struct tevent_req *req)
{
    struct auth_data *auth_data = tevent_req_callback_data(req,
                                                           struct auth_data);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err;

    ret = krb5_auth_recv(req, &pam_status, &dp_err);
    talloc_free(req);
    if (ret) {
        DEBUG(1, ("krb5_auth request failed.\n"));
    } else {
        switch (pam_status) {
            case PAM_SUCCESS:
                DEBUG(4, ("Successfully renewed TGT for user [%s].\n",
                          auth_data->pd->user));
                break;
            case PAM_AUTHINFO_UNAVAIL:
            case PAM_AUTHTOK_LOCK_BUSY:
                DEBUG(4, ("Cannot renewed TGT for user [%s] while offline, "
                          "will retry later.\n",
                          auth_data->pd->user));
                break;
            default:
                DEBUG(1, ("Failed to renew TGT for user [%s].\n",
                          auth_data->pd->user));
                ret = hash_delete(auth_data->table, &auth_data->key);
                if (ret != HASH_SUCCESS) {
                    DEBUG(1, ("hash_delete failed.\n"));
                }
        }
    }

    talloc_zfree(auth_data);
}

static errno_t renew_all_tgts(struct renew_tgt_ctx *renew_tgt_ctx)
{
    int ret;
    hash_entry_t *entries;
    unsigned long count;
    size_t c;
    time_t now;
    struct auth_data *auth_data;
    struct renew_data *renew_data;
    struct tevent_timer *te;

    ret = hash_entries(renew_tgt_ctx->tgt_table, &count, &entries);
    if (ret != HASH_SUCCESS) {
        DEBUG(1, ("hash_entries failed.\n"));
        return ENOMEM;
    }

    now = time(NULL);

    for (c = 0; c < count; c++) {
        renew_data = talloc_get_type(entries[c].value.ptr, struct renew_data);
        DEBUG(9, ("Checking [%s] for renewal at [%.24s].\n", entries[c].key.str,
                  ctime(&renew_data->start_renew_at)));
        if (renew_data->start_renew_at < now) {
            auth_data = talloc_zero(renew_tgt_ctx, struct auth_data);
            if (auth_data == NULL) {
                DEBUG(1, ("talloc_zero failed.\n"));
            } else {
                auth_data->pd = renew_data->pd;
                auth_data->krb5_ctx = renew_tgt_ctx->krb5_ctx;
                auth_data->be_ctx = renew_tgt_ctx->be_ctx;
                auth_data->table = renew_tgt_ctx->tgt_table;
                auth_data->key.type = entries[c].key.type;
                auth_data->key.str = talloc_strdup(auth_data,
                                                   entries[c].key.str);
                if (auth_data->key.str == NULL) {
                    DEBUG(1, ("talloc_strdup failed.\n"));
                    te = NULL;
                } else {
                    te = tevent_add_timer(renew_tgt_ctx->ev,
                                          auth_data, tevent_timeval_current(),
                                          renew_tgt, auth_data);
                    if (te == NULL) {
                        DEBUG(1, ("tevent_add_timer failed.\n"));
                    }
                }
            }

            if (auth_data == NULL || te == NULL) {
                DEBUG(1, ("Failed to renew TGT in [%s].\n", entries[c].key.str));
                ret = hash_delete(renew_tgt_ctx->tgt_table, &entries[c].key);
                if (ret != HASH_SUCCESS) {
                    DEBUG(1, ("hash_delete failed.\n"));
                }
            }
        }
    }

    talloc_free(entries);

    return EOK;
}

static void renew_handler(struct renew_tgt_ctx *renew_tgt_ctx);

static void renew_tgt_online_callback(void *private_data)
{
    struct renew_tgt_ctx *renew_tgt_ctx = talloc_get_type(private_data,
                                                          struct renew_tgt_ctx);

    renew_tgt_ctx->added_to_online_callbacks = false;
    renew_handler(renew_tgt_ctx);
}

static void renew_tgt_timer_handler(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval current_time, void *data)
{
    struct renew_tgt_ctx *renew_tgt_ctx = talloc_get_type(data,
                                                          struct renew_tgt_ctx);

    renew_handler(renew_tgt_ctx);
}

static void renew_handler(struct renew_tgt_ctx *renew_tgt_ctx)
{
    struct timeval next;
    int ret;

    if (be_is_offline(renew_tgt_ctx->be_ctx)) {
        if (renew_tgt_ctx->added_to_online_callbacks) {
            DEBUG(3, ("Renewal task was already added to online callbacks.\n"));
            return;
        }
        DEBUG(7, ("Offline, adding renewal task to online callbacks.\n"));
        ret = be_add_online_cb(renew_tgt_ctx->krb5_ctx, renew_tgt_ctx->be_ctx,
                               renew_tgt_online_callback, renew_tgt_ctx, NULL);
        if (ret == EOK) {
            renew_tgt_ctx->added_to_online_callbacks = true;
            return;
        }

        DEBUG(1, ("Failed to add the renewal task to online callbacks, "
                  "continue normal operation.\n"));
    } else {
        ret = renew_all_tgts(renew_tgt_ctx);
        if (ret != EOK) {
            DEBUG(1, ("renew_all_tgts failed. "
                      "Disabling automatic TGT renewal\n"));
            sss_log(SSS_LOG_ERR, "Disabling automatic TGT renewal.");
            talloc_zfree(renew_tgt_ctx);
            return;
        }
    }

    DEBUG(7, ("Adding new renew timer.\n"));

    next = tevent_timeval_current_ofs(renew_tgt_ctx->timer_interval,
                                      0);
    renew_tgt_ctx->te = tevent_add_timer(renew_tgt_ctx->ev, renew_tgt_ctx,
                                         next, renew_tgt_timer_handler,
                                         renew_tgt_ctx);
    if (renew_tgt_ctx->te == NULL) {
        DEBUG(1, ("tevent_add_timer failed.\n"));
        sss_log(SSS_LOG_ERR, "Disabling automatic TGT renewal.");
        talloc_zfree(renew_tgt_ctx);
    }

    return;
}

errno_t init_renew_tgt(struct krb5_ctx *krb5_ctx, struct be_ctx *be_ctx,
                       struct tevent_context *ev, time_t renew_intv)
{
    int ret;
    struct timeval next;

    krb5_ctx->renew_tgt_ctx = talloc_zero(krb5_ctx, struct renew_tgt_ctx);
    if (krb5_ctx->renew_tgt_ctx == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ret = sss_hash_create(krb5_ctx->renew_tgt_ctx, INITIAL_TGT_TABLE_SIZE,
                          &krb5_ctx->renew_tgt_ctx->tgt_table);
    if (ret != EOK) {
        DEBUG(1, ("sss_hash_create failed.\n"));
        goto fail;
    }

    krb5_ctx->renew_tgt_ctx->be_ctx = be_ctx;
    krb5_ctx->renew_tgt_ctx->krb5_ctx = krb5_ctx;
    krb5_ctx->renew_tgt_ctx->ev = ev;
    krb5_ctx->renew_tgt_ctx->timer_interval = renew_intv;
    krb5_ctx->renew_tgt_ctx->added_to_online_callbacks = false;


    next = tevent_timeval_current_ofs(krb5_ctx->renew_tgt_ctx->timer_interval,
                                      0);
    krb5_ctx->renew_tgt_ctx->te = tevent_add_timer(ev, krb5_ctx->renew_tgt_ctx,
                                                   next, renew_tgt_timer_handler,
                                                   krb5_ctx->renew_tgt_ctx);
    if (krb5_ctx->renew_tgt_ctx->te == NULL) {
        DEBUG(1, ("tevent_add_timer failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    return EOK;

fail:
    talloc_zfree(krb5_ctx->renew_tgt_ctx);
    return ret;
}

errno_t add_tgt_to_renew_table(struct krb5_ctx *krb5_ctx, const char *ccfile,
                               struct tgt_times *tgtt, struct pam_data *pd)
{
    char *key_str = NULL;
    int ret;
    hash_key_t key;
    hash_value_t value;
    struct renew_data *renew_data = NULL;

    if (krb5_ctx->renew_tgt_ctx == NULL) {
        DEBUG(7 ,("Renew context not initialized, "
                  "automatic renewal not available.\n"));
        return EOK;
    }

    if (pd->cmd != SSS_PAM_AUTHENTICATE && pd->cmd != SSS_CMD_RENEW &&
        pd->cmd != SSS_PAM_CHAUTHTOK) {
        DEBUG(1, ("Unexpected pam task [%d].\n", pd->cmd));
        return EINVAL;
    }

    key.type = HASH_KEY_STRING;
    if (ccfile[0] == '/') {
        key_str = talloc_asprintf(NULL, "FILE:%s", ccfile);
        if (key_str == NULL) {
            DEBUG(1, ("talloc_asprintf doneed.\n"));
            ret = ENOMEM;
            goto done;
        }
    } else {
        key_str = talloc_strdup(NULL, ccfile);
    }
    key.str = key_str;

    renew_data = talloc_zero(krb5_ctx->renew_tgt_ctx, struct renew_data);
    if (renew_data == NULL) {
        DEBUG(1, ("talloc_zero doneed.\n"));
        ret = ENOMEM;
        goto done;
    }

    renew_data->start_time = tgtt->starttime;
    renew_data->lifetime = tgtt->endtime;
    renew_data->start_renew_at = (time_t) (tgtt->starttime +
                                        0.5 *(tgtt->endtime - tgtt->starttime));

    ret = copy_pam_data(renew_data, pd, &renew_data->pd);
    if (ret != EOK) {
        DEBUG(1, ("copy_pam_data doneed.\n"));
        goto done;
    }

    if (renew_data->pd->newauthtok_type != SSS_AUTHTOK_TYPE_EMPTY) {
        talloc_zfree(renew_data->pd->newauthtok);
        renew_data->pd->newauthtok_size = 0;
        renew_data->pd->newauthtok_type = SSS_AUTHTOK_TYPE_EMPTY;
    }

    talloc_zfree(renew_data->pd->authtok);
    renew_data->pd->authtok = (uint8_t *) talloc_strdup(renew_data->pd, key.str);
    if (renew_data->pd->authtok == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }
    renew_data->pd->authtok_size = strlen((char *) renew_data->pd->authtok) + 1;
    renew_data->pd->authtok_type = SSS_AUTHTOK_TYPE_CCFILE;

    renew_data->pd->cmd = SSS_CMD_RENEW;

    value.type = HASH_VALUE_PTR;
    value.ptr = renew_data;

    ret = hash_enter(krb5_ctx->renew_tgt_ctx->tgt_table, &key, &value);
    if (ret != HASH_SUCCESS) {
        DEBUG(1, ("hash_enter failed.\n"));
        ret = EFAULT;
        goto done;
    }

    DEBUG(7, ("Added [%s] for renewal at [%.24s].\n", key_str,
                                           ctime(&renew_data->start_renew_at)));

    ret = EOK;

done:
    talloc_free(key_str);
    if (ret != EOK) {
        talloc_free(renew_data);
    }
    return ret;
}
