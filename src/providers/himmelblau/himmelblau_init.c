/*
    SSSD

    Himmelblau Provider - Initialization

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#include "providers/himmelblau/himmelblau_common.h"
#include "providers/himmelblau/himmelblau_opts.h"
#include "confdb/confdb.h"
#include "lib/idmap/sss_idmap.h"
#include "util/util_sss_idmap.h"

static errno_t himmelblau_init_broker(struct himmelblau_init_ctx *init_ctx)
{
    MSAL_ERROR *error = NULL;
    errno_t ret;

    if (init_ctx->broker_initialized) {
        return EOK;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing himmelblau broker\n");

    /* Set global logging level for libhimmelblau */
    error = set_global_tracing_level(INFO);
    if (error) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to set tracing level, continuing anyway\n");
        error_free(error);
        error = NULL;
    }

    /* Initialize TPM (required) */
    DEBUG(SSSDBG_TRACE_FUNC, "Initializing TPM\n");
    error = tpm_init(NULL, &init_ctx->tpm);
    if (error) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize TPM: %s\n", error->msg);
        error_free(error);
        return EIO;
    }
    init_ctx->tpm_initialized = true;

    /* Try to load existing device enrollment (includes auth value) */
    DEBUG(SSSDBG_TRACE_FUNC, "Loading device enrollment from sysdb\n");
    char *device_id_tmp = NULL;
    ret = himmelblau_sysdb_load_device_enrollment(
        init_ctx,
        init_ctx->be_ctx->domain,
        &device_id_tmp,
        &init_ctx->auth_value,
        &init_ctx->transport_key_obj,
        &init_ctx->cert_key_obj);

    if (ret == ENOENT) {
        /* Device not enrolled yet, generate new auth value */
        DEBUG(SSSDBG_TRACE_FUNC, "Device not enrolled, generating new auth value\n");
        error = auth_value_generate(&init_ctx->auth_value);
        if (error) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to generate auth value: %s\n", error->msg);
            error_free(error);
            return EIO;
        }
        init_ctx->enrollment_keys_loaded = false;
        init_ctx->transport_key_obj = NULL;
        init_ctx->cert_key_obj = NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to load device enrollment from sysdb: %d\n", ret);
        return ret;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Loaded device enrollment from sysdb\n");
        init_ctx->enrollment_keys_loaded = true;
        talloc_free(device_id_tmp);
    }

    /* Create machine key */
    DEBUG(SSSDBG_TRACE_FUNC, "Creating TPM machine key\n");
    error = tpm_machine_key_create(init_ctx->tpm,
                                   init_ctx->auth_value,
                                   &init_ctx->loadable_machine_key);
    if (error) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to create machine key: %s\n", error->msg);
        error_free(error);
        return EIO;
    }

    /* Load machine key */
    DEBUG(SSSDBG_TRACE_FUNC, "Loading TPM machine key\n");
    error = tpm_machine_key_load(init_ctx->tpm,
                                 init_ctx->auth_value,
                                 init_ctx->loadable_machine_key,
                                 &init_ctx->machine_key);
    if (error) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to load machine key: %s\n", error->msg);
        error_free(error);
        return EIO;
    }
    init_ctx->machine_key_initialized = true;

    /* Initialize broker (pass enrollment keys if available) */
    DEBUG(SSSDBG_TRACE_FUNC, "Initializing broker\n");
    error = broker_init(NULL, NULL,
                       init_ctx->transport_key_obj,
                       init_ctx->cert_key_obj,
                       &init_ctx->broker);
    if (error) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize broker: %s\n", error->msg);
        error_free(error);
        return EIO;
    }

    init_ctx->broker_initialized = true;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Himmelblau broker, TPM, and machine key initialized successfully\n");
    return EOK;
}

static int himmelblau_init_ctx_destructor(struct himmelblau_init_ctx *ctx)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Cleaning up himmelblau init context\n");

    if (ctx->broker) {
        DEBUG(SSSDBG_TRACE_FUNC, "Freeing himmelblau broker\n");
        broker_free(ctx->broker);
        ctx->broker = NULL;
    }

    if (ctx->cert_key_obj) {
        DEBUG(SSSDBG_TRACE_FUNC, "Freeing certificate key\n");
        loadable_ms_device_enrollment_key_free(ctx->cert_key_obj);
        ctx->cert_key_obj = NULL;
    }

    if (ctx->transport_key_obj) {
        DEBUG(SSSDBG_TRACE_FUNC, "Freeing transport key\n");
        loadable_ms_oapxbc_rsa_key_free(ctx->transport_key_obj);
        ctx->transport_key_obj = NULL;
    }

    if (ctx->machine_key) {
        DEBUG(SSSDBG_TRACE_FUNC, "Freeing machine key\n");
        machine_key_free(ctx->machine_key);
        ctx->machine_key = NULL;
    }

    if (ctx->loadable_machine_key) {
        DEBUG(SSSDBG_TRACE_FUNC, "Freeing loadable machine key\n");
        loadable_machine_key_free(ctx->loadable_machine_key);
        ctx->loadable_machine_key = NULL;
    }

    if (ctx->auth_value) {
        DEBUG(SSSDBG_TRACE_FUNC, "Freeing auth value\n");
        string_free(ctx->auth_value);
        ctx->auth_value = NULL;
    }

    if (ctx->tpm) {
        DEBUG(SSSDBG_TRACE_FUNC, "Freeing himmelblau TPM\n");
        tpm_free(ctx->tpm);
        ctx->tpm = NULL;
    }

    return 0;
}

errno_t sssm_himmelblau_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             struct data_provider *provider,
                             const char *module_name,
                             void **_module_data)
{
    struct himmelblau_init_ctx *init_ctx;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing himmelblau provider\n");

    init_ctx = talloc_zero(mem_ctx, struct himmelblau_init_ctx);
    if (init_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    init_ctx->be_ctx = be_ctx;

    /* Get options from confdb */
    ret = dp_get_options(init_ctx, be_ctx->cdb, be_ctx->conf_path,
                         default_himmelblau_opts, HIMMELBLAU_OPTS,
                         &init_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_get_options() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Get domain from options */
    init_ctx->domain = dp_opt_get_string(init_ctx->opts, HIMMELBLAU_DOMAIN);
    if (init_ctx->domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Option " CONFDB_HIMMELBLAU_DOMAIN " is required\n");
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Himmelblau domain: %s\n", init_ctx->domain);

    /* Initialize broker, TPM, and machine key fields */
    init_ctx->broker = NULL;
    init_ctx->broker_initialized = false;
    init_ctx->tpm = NULL;
    init_ctx->tpm_initialized = false;
    init_ctx->auth_value = NULL;
    init_ctx->loadable_machine_key = NULL;
    init_ctx->machine_key = NULL;
    init_ctx->machine_key_initialized = false;
    init_ctx->transport_key_obj = NULL;
    init_ctx->cert_key_obj = NULL;
    init_ctx->enrollment_keys_loaded = false;

    /* Set destructor for cleanup */
    talloc_set_destructor(init_ctx, himmelblau_init_ctx_destructor);

    /* Initialize broker, TPM, and machine key */
    ret = himmelblau_init_broker(init_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize broker, TPM, and machine key: %d\n", ret);
        goto done;
    }

    *_module_data = init_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(init_ctx);
    }

    return ret;
}

errno_t sssm_himmelblau_auth_init(TALLOC_CTX *mem_ctx,
                                  struct be_ctx *be_ctx,
                                  void *module_data,
                                  struct dp_method *dp_methods)
{
    struct himmelblau_init_ctx *init_ctx;
    struct himmelblau_auth_ctx *auth_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing himmelblau auth target\n");

    init_ctx = talloc_get_type(module_data, struct himmelblau_init_ctx);

    auth_ctx = talloc_zero(init_ctx, struct himmelblau_auth_ctx);
    if (auth_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    auth_ctx->be_ctx = be_ctx;
    auth_ctx->init_ctx = init_ctx;
    auth_ctx->domain = init_ctx->domain;

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  himmelblau_pam_handler_send, himmelblau_pam_handler_recv,
                  auth_ctx,
                  struct himmelblau_auth_ctx, struct pam_data, struct pam_data *);

    init_ctx->auth_ctx = auth_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Himmelblau auth target initialized\n");

    return EOK;
}

static errno_t himmelblau_set_idmap_options(struct sss_idmap_ctx *idmap_ctx,
                                             struct dp_option *opts)
{
    enum idmap_error_code err;
    id_t idmap_lower;
    id_t idmap_upper;
    id_t rangesize;

    idmap_lower = dp_opt_get_int(opts, HIMMELBLAU_IDMAP_LOWER);
    idmap_upper = dp_opt_get_int(opts, HIMMELBLAU_IDMAP_UPPER);
    rangesize = dp_opt_get_int(opts, HIMMELBLAU_IDMAP_RANGESIZE);

    /* Validate configuration */
    if (rangesize <= 0 || idmap_upper <= idmap_lower ||
        (idmap_upper - idmap_lower) < rangesize) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid idmap range settings: [%"SPRIid"][%"SPRIid"][%"SPRIid"]\n",
              idmap_lower, idmap_upper, rangesize);
        return EINVAL;
    }

    if (((idmap_upper - idmap_lower) % rangesize) != 0) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Range size does not divide evenly. "
              "Uppermost range will not be used\n");
    }

    err = sss_idmap_ctx_set_lower(idmap_ctx, idmap_lower);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set lower boundary: %s\n", idmap_error_string(err));
        return EIO;
    }

    err = sss_idmap_ctx_set_upper(idmap_ctx, idmap_upper);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set upper boundary: %s\n", idmap_error_string(err));
        return EIO;
    }

    err = sss_idmap_ctx_set_rangesize(idmap_ctx, rangesize);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set range size: %s\n", idmap_error_string(err));
        return EIO;
    }

    return EOK;
}

errno_t sssm_himmelblau_id_init(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                void *module_data,
                                struct dp_method *dp_methods)
{
    struct himmelblau_init_ctx *init_ctx;
    struct himmelblau_id_ctx *id_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range id_range;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing himmelblau id target\n");

    init_ctx = talloc_get_type(module_data, struct himmelblau_init_ctx);

    id_ctx = talloc_zero(init_ctx, struct himmelblau_id_ctx);
    if (id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    id_ctx->be_ctx = be_ctx;
    id_ctx->init_ctx = init_ctx;
    id_ctx->domain = init_ctx->domain;

    /* Initialize idmap context */
    err = sss_idmap_init(sss_idmap_talloc, init_ctx, sss_idmap_talloc_free,
                         &id_ctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize idmap: %s\n",
              idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }

    /* Set idmap options */
    ret = himmelblau_set_idmap_options(id_ctx->idmap_ctx, init_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set idmap options: %d\n", ret);
        goto done;
    }

    /* Calculate ID range using domain name as identifier */
    err = sss_idmap_calculate_range(id_ctx->idmap_ctx, init_ctx->domain,
                                    NULL, &id_range);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to calculate id range for [%s]: %s\n",
              init_ctx->domain, idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }

    /* Add domain to idmap context */
    err = sss_idmap_add_gen_domain_ex(id_ctx->idmap_ctx, be_ctx->domain->name,
                                      init_ctx->domain, &id_range,
                                      NULL, NULL, NULL, NULL, 0, false);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add idmap domain [%s]: %s\n",
              be_ctx->domain->name, idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  himmelblau_account_info_handler_send,
                  himmelblau_account_info_handler_recv,
                  id_ctx,
                  struct himmelblau_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    init_ctx->id_ctx = id_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(id_ctx);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Himmelblau id target initialized\n");

    return ret;
}
