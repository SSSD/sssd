/*
    SSSD

    files_init.c - Initialization of the files provider

    Copyright (C) 2016 Red Hat

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

#include "providers/data_provider/dp.h"
#include "providers/files/files_private.h"
#include "util/util.h"

#define DEFAULT_PASSWD_FILE "/etc/passwd"
#define DEFAULT_GROUP_FILE "/etc/group"

static errno_t files_init_file_sources(TALLOC_CTX *mem_ctx,
                                       struct be_ctx *be_ctx,
                                       const char ***_passwd_files,
                                       const char ***_group_files)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *conf_passwd_files;
    char *conf_group_files;
    char **passwd_list = NULL;
    char **group_list = NULL;
    int num_passwd_files = 0;
    int num_group_files = 0;
    const char **passwd_files = NULL;
    const char **group_files = NULL;
    char *dfl_passwd_files = NULL;
    char *env_group_files = NULL;
    int i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_getenv(tmp_ctx, "SSS_FILES_PASSWD", DEFAULT_PASSWD_FILE,
                     &dfl_passwd_files);
    if (ret == EOK) {
        sss_log(SSS_LOG_ALERT,
                "Defaulting to %s for the passwd file, "
                "this should only be used for testing!\n",
                dfl_passwd_files);
    } else if (ret != ENOENT) {
        sss_log(SSS_LOG_ALERT, "sss_getenv() failed");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_FUNC,
          "Using passwd file: [%s].\n",
          dfl_passwd_files);

    ret = sss_getenv(tmp_ctx, "SSS_FILES_GROUP", DEFAULT_GROUP_FILE,
                     &env_group_files);
    if (ret == EOK) {
        sss_log(SSS_LOG_ALERT,
                "Defaulting to %s for the group file, "
                "this should only be used for testing!\n",
                env_group_files);
    } else if (ret != ENOENT) {
        sss_log(SSS_LOG_ALERT, "sss_getenv() failed");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_FUNC,
          "Using group file: [%s].\n",
          env_group_files);

    ret = confdb_get_string(be_ctx->cdb, tmp_ctx, be_ctx->conf_path,
                            CONFDB_FILES_PASSWD, dfl_passwd_files,
                            &conf_passwd_files);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to retrieve confdb passwd files!\n");
        goto done;
    }

    ret = confdb_get_string(be_ctx->cdb, tmp_ctx, be_ctx->conf_path,
                            CONFDB_FILES_GROUP, env_group_files,
                            &conf_group_files);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to retrieve confdb group files!\n");
        goto done;
    }

    ret = split_on_separator(tmp_ctx, conf_passwd_files, ',', true, true,
                             &passwd_list, &num_passwd_files);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "Failed to parse passwd list!\n");
        goto done;
    }

    passwd_files = talloc_zero_array(tmp_ctx, const char *,
                                     num_passwd_files + 1);
    if (passwd_files == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_passwd_files; i++) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Using passwd file: [%s].\n", passwd_list[i]);

        passwd_files[i] = talloc_strdup(passwd_files, passwd_list[i]);
        if (passwd_files[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* Retrieve list of group files */
    ret = split_on_separator(tmp_ctx, conf_group_files, ',', true, true,
                             &group_list, &num_group_files);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "Failed to parse group files!\n");
        goto done;
    }

    group_files = talloc_zero_array(tmp_ctx, const char *,
                                    num_group_files + 1);
    if (group_files == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_group_files; i++) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Using group file: [%s].\n", group_list[i]);
        group_files[i] = talloc_strdup(group_files, group_list[i]);
        if (group_files[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_passwd_files = talloc_steal(mem_ctx, passwd_files);
    *_group_files = talloc_steal(mem_ctx, group_files);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sssm_files_init(TALLOC_CTX *mem_ctx,
                    struct be_ctx *be_ctx,
                    struct data_provider *provider,
                    const char *module_name,
                    void **_module_data)
{
    struct files_id_ctx *ctx;
    errno_t ret;

    ctx = talloc_zero(mem_ctx, struct files_id_ctx);
    if (ctx == NULL) {
        return ENOMEM;
    }

    ctx->be = be_ctx;
    ctx->domain = be_ctx->domain;

    ret = files_init_file_sources(ctx, be_ctx,
                                  &ctx->passwd_files,
                                  &ctx->group_files);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot initialize the passwd/group source files\n");
        goto done;
    }

    ctx->fctx = sf_init(ctx, be_ctx->ev,
                        ctx->passwd_files,
                        ctx->group_files,
                        ctx);
    if (ctx->fctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_certmap_to_sysdb(be_ctx->cdb, be_ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to initialize certificate mapping rules. "
              "Authentication with certificates/Smartcards might not work "
              "as expected.\n");
        /* not fatal, ignored */
    } else {
        ret = files_init_certmap(ctx, ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "files_init_certmap failed. "
                  "Authentication with certificates/Smartcards might not work "
                  "as expected.\n");
            /* not fatal, ignored */
        }
    }

    *_module_data = ctx;
    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_files_id_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       void *module_data,
                       struct dp_method *dp_methods)
{
    struct files_id_ctx *ctx;

    ctx = talloc_get_type(module_data, struct files_id_ctx);
    if (ctx == NULL) {
        return EINVAL;
    }

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  files_account_info_handler_send,
                  files_account_info_handler_recv,
                  ctx, struct files_id_ctx,
                  struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send,
                  default_account_domain_recv,
                  NULL, void,
                  struct dp_get_acct_domain_data, struct dp_reply_std);

    return EOK;
}

int sssm_files_auth_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         void *module_data,
                         struct dp_method *dp_methods)
{
    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  files_auth_handler_send, files_auth_handler_recv, NULL, void,
                  struct pam_data, struct pam_data *);

    return EOK;
}
