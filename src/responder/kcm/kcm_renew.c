/*
    SSSD

    KCM Kerberos renewals -- Renew a TGT automatically

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2020 Red Hat

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
#include "util/util.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_ccache.h"
#include "responder/kcm/kcmsrv_ccache.h"
#include "responder/kcm/kcmsrv_pvt.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"
#include "responder/kcm/kcm_renew.h"

extern struct dp_option default_krb5_opts[];

struct kcm_renew_auth_ctx {
    struct tevent_context *ev;
    struct krb5child_req *kr;

    struct krb5_ctx *krb5_ctx;
    struct kcm_auth_data *auth_data;

    uint8_t *buf;
    ssize_t len;
};

struct kcm_auth_data {
    struct kcm_renew_auth_ctx *auth_ctx;
    struct krb5_ctx *krb5_ctx;
    uid_t uid;
    gid_t gid;
    const char *ccname;
    const char *upn;
};

static void kcm_renew_tgt_done(struct tevent_req *req);

static errno_t kcm_set_options(struct krb5_ctx *krb5_ctx,
                               char *lifetime,
                               char *rtime,
                               bool validate,
                               bool canonicalize,
                               int timeout,
                               char *renew_intv,
                               time_t *_renew_intv_tm)
{
    errno_t ret;
    krb5_error_code kerr;
    krb5_deltat renew_interval_delta;

    if (renew_intv != NULL) {
        kerr = krb5_string_to_deltat(renew_intv, &renew_interval_delta);
        if (kerr != 0) {
            DEBUG(SSSDBG_FATAL_FAILURE, "krb5_string_to_deltat failed\n");
            ret = ENOMEM;
            goto done;
        }

        *_renew_intv_tm = renew_interval_delta;
    } else {
        *_renew_intv_tm = 0;
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Option [%s] set to [%s]\n",
                             CONFDB_KCM_KRB5_RENEW_INTERVAL,
                             renew_intv == NULL ? "none" : renew_intv);

    if (lifetime != NULL) {
        ret = krb5_string_to_deltat(lifetime, &krb5_ctx->lifetime);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to convert lifetime string [%d]: %s\n",
                                     ret, sss_strerror(ret));
            goto done;
        }
        krb5_ctx->lifetime_str = lifetime;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Option [%s] set to [%s]\n",
                             CONFDB_KCM_KRB5_LIFETIME,
                             krb5_ctx->lifetime_str == NULL ? "none" : krb5_ctx->lifetime_str);

    if (rtime != 0) {
        ret = krb5_string_to_deltat(rtime, &krb5_ctx->rlife);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to convert renewable lifetime "
                                     "string [%d]: %s.\n", ret, sss_strerror(ret));
            goto done;
        }
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Option [%s] set to [%s]\n",
                             CONFDB_KCM_KRB5_RENEWABLE_LIFETIME,
                             rtime == NULL ? "none" : rtime);

    ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_VALIDATE, validate);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set krb5 child timeout [%d]: %s\n",
                                 ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Option [%s] set to [%s]\n",
                             CONFDB_KCM_KRB5_VALIDATE,
                             validate ? "true" : "false");

    krb5_ctx->canonicalize = canonicalize;
    DEBUG(SSSDBG_TRACE_FUNC, "Option [%s] set to [%s]\n",
                             CONFDB_KCM_KRB5_CANONICALIZE,
                             canonicalize ? "true" : "false");

    if (timeout > 0) {
        ret = dp_opt_set_int(krb5_ctx->opts, KRB5_AUTH_TIMEOUT, timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set krb5 child timeout [%d]: %s\n",
                                     ret, sss_strerror(ret));
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Option [%s] set to [%d]\n",
                             CONFDB_KCM_KRB5_AUTH_TIMEOUT,
                             timeout);

    ret = EOK;
done:
    return ret;
}

static errno_t kcm_read_options(TALLOC_CTX *mem_ctx,
                                struct confdb_ctx *cdb,
                                const char *cpath,
                                char **_lifetime,
                                char **_rtime,
                                bool *_validate,
                                bool *_canonicalize,
                                int *_timeout,
                                char **_renew_intv)
{
    TALLOC_CTX *tmp_ctx;
    char *lifetime;
    char *rtime;
    bool validate;
    bool canonicalize;
    int timeout;
    char *renew_intv;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = confdb_get_string(cdb, tmp_ctx, cpath,
                            CONFDB_KCM_KRB5_LIFETIME, NULL,
                            &lifetime);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read %s/%s [%d]: %s\n", cpath,
              CONFDB_KCM_KRB5_LIFETIME, ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_string(cdb, tmp_ctx, cpath,
                            CONFDB_KCM_KRB5_RENEWABLE_LIFETIME, NULL,
                            &rtime);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read %s/%s [%d]: %s\n", cpath,
              CONFDB_KCM_KRB5_RENEWABLE_LIFETIME, ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_bool(cdb, cpath,
                          CONFDB_KCM_KRB5_VALIDATE, false,
                          &validate);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read %s/%s [%d]: %s\n", cpath,
              CONFDB_KCM_KRB5_VALIDATE, ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_bool(cdb, cpath,
                          CONFDB_KCM_KRB5_CANONICALIZE, false,
                          &canonicalize);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read %s/%s [%d]: %s\n", cpath,
              CONFDB_KCM_KRB5_CANONICALIZE, ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_int(cdb, cpath,
                         CONFDB_KCM_KRB5_AUTH_TIMEOUT, 0,
                         &timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read %s/%s [%d]: %s\n", cpath,
              CONFDB_KCM_KRB5_AUTH_TIMEOUT, ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_string(cdb, tmp_ctx, cpath,
                            CONFDB_KCM_KRB5_RENEW_INTERVAL, NULL,
                            &renew_intv);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot read %s/%s [%d]: %s\n", cpath,
              CONFDB_KCM_KRB5_AUTH_TIMEOUT, ret, sss_strerror(ret));
        goto done;
    }


    *_lifetime = talloc_steal(mem_ctx, lifetime);
    *_rtime = talloc_steal(mem_ctx, rtime);
    *_validate = validate;
    *_canonicalize = canonicalize;
    *_timeout = timeout;
    *_renew_intv = renew_intv;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int kcm_get_renewal_config(struct kcm_ctx *kctx,
                           struct krb5_ctx **_krb5_ctx,
                           time_t *_renew_intv)
{
    int ret;
    struct krb5_ctx *krb5_ctx;
    char *lifetime;
    char *rtime;
    bool validate;
    bool canonicalize;
    int timeout;
    char *renew_intv;
    time_t renew_intv_tm;
    bool tgt_renewal;
    char *tgt_renewal_inherit;
    const char *conf_path;
    int i;

    krb5_ctx = talloc_zero(kctx->rctx, struct krb5_ctx);
    if (krb5_ctx == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error allocating krb5_ctx\n");
        goto done;
    }

    /* Set default Kerberos options */
    krb5_ctx->opts = talloc_zero_array(krb5_ctx, struct dp_option, KRB5_OPTS);
    if (krb5_ctx->opts == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error allocating krb5_ctx opts\n");
        goto done;
    }

    for (i = 0; i < KRB5_OPTS; i++) {
        krb5_ctx->opts[i].opt_name = default_krb5_opts[i].opt_name;
        krb5_ctx->opts[i].type = default_krb5_opts[i].type;
        krb5_ctx->opts[i].def_val = default_krb5_opts[i].def_val;
        switch (krb5_ctx->opts[i].type) {
            case DP_OPT_STRING:
                ret = dp_opt_set_string(krb5_ctx->opts, i,
                                        default_krb5_opts[i].def_val.string);
                break;
            case DP_OPT_BLOB:
                ret = dp_opt_set_blob(krb5_ctx->opts, i,
                                      default_krb5_opts[i].def_val.blob);
                break;
            case DP_OPT_NUMBER:
                ret = dp_opt_set_int(krb5_ctx->opts, i,
                                     default_krb5_opts[i].def_val.number);
                break;
            case DP_OPT_BOOL:
                ret = dp_opt_set_bool(krb5_ctx->opts, i,
                                      default_krb5_opts[i].def_val.boolean);
                break;
            default:
                ret = EINVAL;
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed setting default renewal kerberos "
                                     "options [%d]: %s\n", ret, sss_strerror(ret));
            talloc_free(krb5_ctx->opts);
            goto done;
        }
    }

    ret = confdb_get_bool(kctx->rctx->cdb,
                          kctx->rctx->confdb_service_path,
                          CONFDB_KCM_TGT_RENEWAL, false,
                          &tgt_renewal);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve TGT Renewal confdb value "
                                 "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Option [%s] set to [%s]\n",
                             CONFDB_KCM_TGT_RENEWAL,
                             tgt_renewal ? "true" : "false");
    if (tgt_renewal == false) {
        ret = ENOTSUP;
        goto done;
    }

    ret = confdb_get_string(kctx->rctx->cdb,
                            kctx->rctx,
                            kctx->rctx->confdb_service_path,
                            CONFDB_KCM_TGT_RENEWAL_INHERIT,
                            NULL,
                            &tgt_renewal_inherit);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve TGT Renewal inherit confdb "
                                 "valule [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Option [%s] set to [%s]\n",
                             CONFDB_KCM_TGT_RENEWAL_INHERIT,
                             tgt_renewal_inherit == NULL ? "none" : tgt_renewal_inherit);

    /* Override with config options */
    if (tgt_renewal_inherit == NULL) {
        ret = kcm_read_options(kctx, kctx->rctx->cdb, kctx->rctx->confdb_service_path,
                               &lifetime, &rtime, &validate, &canonicalize,
                               &timeout, &renew_intv);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to read krb5 options from "
                                     "[kcm] section [%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }
    } else {
        conf_path = talloc_asprintf(kctx->rctx, CONFDB_DOMAIN_PATH_TMPL,
                                    tgt_renewal_inherit);
        if (conf_path == NULL) {
            ret = ENOMEM;
            DEBUG(SSSDBG_FATAL_FAILURE, "fatal error allocating conf_path\n");
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Inherit krb5 options for domain [%s] for renewals\n",
                                 conf_path);
        ret = kcm_read_options(kctx, kctx->rctx->cdb, conf_path,
                               &lifetime, &rtime, &validate, &canonicalize,
                               &timeout, &renew_intv);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed reading domain [%s] inherit krb5 options "
                                     "[%d]: %s\n", conf_path, ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = kcm_set_options(krb5_ctx, lifetime, rtime, validate, canonicalize,
                          timeout, renew_intv, &renew_intv_tm);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed setting krb5 options for renewal "
                                 "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_renew_intv = renew_intv_tm;
    *_krb5_ctx = krb5_ctx;
    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(krb5_ctx);
    }
    return ret;
}

static errno_t kcm_child_req_setup(TALLOC_CTX *mem_ctx,
                                   struct kcm_auth_data *auth_data,
                                   struct krb5_ctx *krb5_ctx,
                                   struct krb5child_req **_req)
{
    struct krb5child_req *krreq;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Setup for renewal of [%s] " \
                                 "for principal name [%s]\n",
                                 auth_data->upn,
                                 auth_data->ccname);

    krreq = talloc_zero(mem_ctx, struct krb5child_req);
    if (krreq == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to alloc krreq [%d]: %s\n",
                                    ret, strerror(ret));
        goto fail;
    }

    krreq->krb5_ctx = krb5_ctx;

    /* Set uid and gid */
    krreq->uid = auth_data->uid;
    krreq->gid = auth_data->gid;

    krreq->upn = talloc_strdup(krreq, auth_data->upn);
    if (krreq->upn == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to strdup krreq->upn [%d]: %s\n",
                                    ret, strerror(ret));
        goto fail;
    }

    krreq->ccname = talloc_asprintf(krreq, "KCM:%s", auth_data->ccname);
    if (krreq->ccname == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to strdup krreq->ccname [%d]: %s\n",
              ret, strerror(ret));
        goto fail;
    }

   /* Set PAM Data */
    krreq->pd = create_pam_data(krreq);
    if (krreq->pd == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed creating pam data on krreq->pd "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto fail;
    }

    krreq->pd->cmd = SSS_CMD_RENEW;
    krreq->pd->user = talloc_strdup(krreq->pd, auth_data->upn);
    if (krreq->pd->user == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to strdup krreq->pd->user "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto fail;
    }

    /* Set authtok values */
    sss_authtok_set_empty(krreq->pd->newauthtok);

    ret = sss_authtok_set_ccfile(krreq->pd->authtok, krreq->ccname, 0);
    if (ret != EOK) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed setting authtok krreq->ccname"
                                    "[%d]: %s\n", ret, strerror(ret));
        goto fail;
    }

    krreq->old_ccname = krreq->ccname;

    *_req = krreq;

    return EOK;
fail:
    talloc_zfree(krreq);
    return ret;
}

static void kcm_renew_tgt(struct tevent_context *ev,
                          struct tevent_immediate *imm,
                          void *private_data)
{
    struct kcm_auth_data *auth_data;
    struct tevent_req *req;
    struct kcm_renew_auth_ctx *ctx;
    errno_t ret;

    auth_data = talloc_get_type(private_data, struct kcm_auth_data);

    ctx = talloc_zero(auth_data, struct kcm_renew_auth_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to allocate renew auth ctx\n");
        return;
    }
    auth_data->auth_ctx = ctx;

    ret = kcm_child_req_setup(ctx, auth_data, auth_data->krb5_ctx, &ctx->kr);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to setup krb5 child for renewal [%d]: %s\n",
                                    ret, sss_strerror(ret));
        talloc_free(auth_data);
        return;
    }

    req = handle_child_send(ctx, ev, ctx->kr);
    if (req == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to trigger krb5 child process request"
                                    "[%d]: %s\n", ret, sss_strerror(ret));
        talloc_free(auth_data);
        return;
    }

    tevent_req_set_callback(req, kcm_renew_tgt_done, auth_data);

    return;
}

static void kcm_renew_tgt_done(struct tevent_req *req)
{
    struct kcm_auth_data *auth_data;
    struct kcm_renew_auth_ctx *ctx;
    int ret;
    struct krb5_child_response *res;

    auth_data = tevent_req_callback_data(req, struct kcm_auth_data);
    ctx = auth_data->auth_ctx;

    ret = handle_child_recv(req, ctx, &ctx->buf, &ctx->len);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to receive krb5 child process request"
                                    "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }
    ret = parse_krb5_child_response(ctx, ctx->buf, ctx->len, ctx->kr->pd,
                                    0, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Krb5 child returned error! Please " \
                                 "inspect the krb5_child.log file. "
                                 " Error [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }
    if (res->msg_status != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Renewal failed - krb5_child [%d]\n",
                                 res->msg_status);
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Successfully renewed [%s]\n", res->ccname);
done:
    talloc_zfree(ctx);
    talloc_zfree(auth_data);
    return;
}

static errno_t kcm_creds_check_times(TALLOC_CTX *mem_ctx,
                                     struct kcm_renew_tgt_ctx *renew_tgt_ctx,
                                     krb5_creds *creds,
                                     struct kcm_ccache *cc,
                                     const char *client_name)
{
    struct tgt_times tgtt;
    time_t now;
    time_t start_renew;
    struct kcm_auth_data *auth_data;
    struct tevent_immediate *imm;
    int ret;

    memset(&tgtt, 0, sizeof(tgtt));
    tgtt.authtime = creds->times.authtime;
    tgtt.starttime = creds->times.starttime;
    tgtt.endtime = creds->times.endtime;
    tgtt.renew_till = creds->times.renew_till;

    now = time(NULL);
    /* Attempt renewal only after half of the ticket lifetime has exceeded */
    start_renew = (time_t) (tgtt.starttime + 0.5 * (tgtt.endtime - tgtt.starttime));
    if (tgtt.renew_till >= tgtt.endtime && tgtt.renew_till >= now
        && tgtt.endtime >= now && start_renew <= now) {
            DEBUG(SSSDBG_TRACE_INTERNAL, "Renewal cred ready!\n");
            auth_data = talloc_zero(renew_tgt_ctx, struct kcm_auth_data);
            if (auth_data == NULL) {
                ret = ENOMEM;
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to allocate auth_data for renewals\n");
                goto done;
            }

            auth_data->krb5_ctx = renew_tgt_ctx->krb5_ctx;
            auth_data->upn = talloc_strdup(auth_data, client_name);
            auth_data->uid = cc->owner.uid;
            auth_data->gid = cc->owner.gid;
            auth_data->ccname = cc->name;
            if (auth_data->upn == NULL) {
                ret = ENOMEM;
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to allocate auth_data->upn for renewals\n");
                goto done;
            }

            imm = tevent_create_immediate(auth_data);
            if (imm == NULL) {
                ret = ENOMEM;
                DEBUG(SSSDBG_CRIT_FAILURE, "tevent_create_immediate failed\n");
                goto done;
            }

            tevent_schedule_immediate(imm, renew_tgt_ctx->ev, kcm_renew_tgt,
                                      auth_data);
        } else {
            DEBUG(SSSDBG_TRACE_INTERNAL, "Time not applicable\n");
        }

    ret = EOK;
done:
    return ret;
}

errno_t kcm_renew_all_tgts(TALLOC_CTX *mem_ctx,
                           struct kcm_renew_tgt_ctx *renew_tgt_ctx,
                           struct kcm_ccache **cc_list)
{
    TALLOC_CTX *tmp_ctx;
    size_t count = 0;
    int ret;
    struct kcm_ccache *cc;
    char *client_name;
    krb5_context krb_context;
    krb5_creds **extracted_creds;
    krb5_error_code kerr;

    if (cc_list == NULL) {
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create tmp talloc_ctx\n");
        return ENOMEM;
    }

    kerr = krb5_init_context(&krb_context);
    if (kerr != 0) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to init krb5 context\n");
        goto done;
    }

    count = talloc_array_length(cc_list);
    if (count <= 1) {
        DEBUG(SSSDBG_TRACE_FUNC, "No renewal entries found.\n");
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Found [%zu] renewal entries.\n", count - 1);
    for (int i = 0; i < count - 1; i++) {
        cc = cc_list[i];
        DEBUG(SSSDBG_TRACE_FUNC,
          "Checking ccache [%s] for creds to renew\n", cc->name);

        extracted_creds = kcm_cc_unmarshal(tmp_ctx, krb_context, cc);
        if (extracted_creds == NULL) {
            ret = ENOMEM;
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed unmarshaling creds\n");
            goto done;
        }

        for (int j = 0; extracted_creds[j] != NULL; j++) {
            kerr = krb5_unparse_name(tmp_ctx, extracted_creds[j]->client,
                                     &client_name);
            if (kerr != 0) {
                ret = EIO;
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed unparsing name\n");
                goto done;
            }

            kcm_creds_check_times(tmp_ctx, renew_tgt_ctx, extracted_creds[j],
                                  cc, client_name);
        }
    }

    ret = EOK;
done:
    if (tmp_ctx != NULL) {
        talloc_free(tmp_ctx);
    }
    krb5_free_context(krb_context);
    return ret;
}

static void kcm_renew_tgt_timer_handler(struct tevent_context *ev,
                                        struct tevent_timer *te,
                                        struct timeval current_time,
										void *data)
{
    struct kcm_renew_tgt_ctx *renew_tgt_ctx;
    errno_t ret;
    struct timeval next;
    struct kcm_ccache **cc_list;
    TALLOC_CTX *tmp_ctx;

    renew_tgt_ctx = talloc_get_type(data, struct kcm_renew_tgt_ctx);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failure in tmp_ctx talloc_new\n");
        return;
    }

    /* forget the timer event, it will be freed by the tevent timer loop */
    renew_tgt_ctx->te = NULL;

	/* Prepare KCM ccache list for renewals */
	ret = kcm_ccdb_renew_tgts(tmp_ctx, renew_tgt_ctx->krb5_ctx,
                              ev, renew_tgt_ctx->db, &cc_list);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No ccache renewal entries to prepare.\n");
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve list of TGTs for renewal "
                                   "preparation [%d]: %s\n", ret, sss_strerror(ret));
    }

    if (ret == EOK) {
        ret = kcm_renew_all_tgts(tmp_ctx, renew_tgt_ctx, cc_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to successfully execute renewal of TGT list"
                                       "[%d]: %s\n", ret, sss_strerror(ret));
        }
    }

    /* Reschedule timer */
    next = sss_tevent_timeval_current_ofs_time_t(renew_tgt_ctx->timer_interval);
    renew_tgt_ctx->te = tevent_add_timer(ev, renew_tgt_ctx,
                                         next, kcm_renew_tgt_timer_handler,
                                         renew_tgt_ctx);
    if (renew_tgt_ctx->te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup timer, renewals will be "
                                   "disabled until the next interval triggers\n");
        talloc_zfree(renew_tgt_ctx);
    }

    talloc_free(tmp_ctx);
    return;
}

errno_t kcm_renewal_setup(struct resp_ctx *rctx,
                          struct krb5_ctx *krb5_ctx,
                          struct tevent_context *ev,
                          struct kcm_ccdb *db,
                          time_t renew_intv)
{
    int ret;
    struct timeval next;

    krb5_ctx->kcm_renew_tgt_ctx = talloc_zero(krb5_ctx, struct kcm_renew_tgt_ctx);
    if (krb5_ctx->kcm_renew_tgt_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    krb5_ctx->kcm_renew_tgt_ctx->rctx = rctx;
    krb5_ctx->kcm_renew_tgt_ctx->krb5_ctx = krb5_ctx;
    krb5_ctx->kcm_renew_tgt_ctx->db = db,
    krb5_ctx->kcm_renew_tgt_ctx->ev = ev;
    krb5_ctx->kcm_renew_tgt_ctx->timer_interval = renew_intv;

    /* Check KCM for tickets to renew */
    next = sss_tevent_timeval_current_ofs_time_t(
                                   krb5_ctx->kcm_renew_tgt_ctx->timer_interval);
    krb5_ctx->kcm_renew_tgt_ctx->te = tevent_add_timer(ev, krb5_ctx->kcm_renew_tgt_ctx,
                                                   next,
                                                   kcm_renew_tgt_timer_handler,
                                                   krb5_ctx->kcm_renew_tgt_ctx);
    if (krb5_ctx->kcm_renew_tgt_ctx->te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup renewal timer\n");
        ret = ENOMEM;
        goto fail;
    }

    return EOK;

fail:
    talloc_zfree(krb5_ctx->renew_tgt_ctx);
    return ret;
}
