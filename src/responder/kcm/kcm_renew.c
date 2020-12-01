extern struct dp_option default_krb5_opts[];

struct kcm_renew_tgt_ctx {
    struct tevent_context *ev;
    struct krb5child_req *kr;

    struct krb5_ctx *krb5_ctx;
    struct auth_data *auth_data;

    uint8_t *buf;
    ssize_t len;
};

struct auth_data {
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
                             renew_intv);

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
                             krb5_ctx->lifetime_str);

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
                             rtime);

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
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error allocating krb5_ctx [%d]: %s\n",
                                    ret, sss_strerror(ret));
        goto done;
    }

    /* Set default Kerberos options */
    krb5_ctx->opts = talloc_zero_array(krb5_ctx, struct dp_option, KRB5_OPTS);
    if (krb5_ctx->opts == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error allocating krb5_ctx opts [%d]: %s\n",
                                    ret, sss_strerror(ret));
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
            DEBUG(SSSDBG_FATAL_FAILURE, "fatal error allocating conf_path [%d]: %s\n",
                                        ret, sss_strerror(ret));
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Inherit krb5 options for domain [%s] for renewals\n",
                                 conf_path);
        ret = kcm_read_options(kctx, kctx->rctx->cdb, conf_path,
                               &lifetime, &rtime, &validate, &canonicalize,
                               &timeout, &renew_intv);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed reading domain [%s] inherit krb5 options ");
                                     "[%d]: %s\n", conf_path, ret, sss_strerror(ret);
            goto done;
        }
    }

    ret = kcm_set_options(krb5_ctx, lifetime, rtime, validate, canonicalize,
                          timeout, renew_intv, &renew_intv_tm);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed setting krb5 options for renewal ");
                                 "[%d]: %s\n", ret, sss_strerror(ret);
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
