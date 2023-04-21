/*
   SSSD

   PAM Responder - helpers for PAM prompting configuration

   Copyright (C) Sumit Bose <sbose@redhat.com> 2019

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
#include "util/sss_pam_data.h"
#include "confdb/confdb.h"
#include "sss_client/sss_cli.h"
#include "responder/pam/pamsrv.h"

#define DEFAULT_PASSKEY_PROMPT_INTERACTIVE _("Insert your Passkey device, then press ENTER.")
#define DEFAULT_PASSKEY_PROMPT_TOUCH _("Please touch the device.")

typedef errno_t (pam_set_prompting_fn_t)(TALLOC_CTX *, struct confdb_ctx *,
                                         const char *,
                                         struct prompt_config ***);


static errno_t pam_set_password_prompting_options(TALLOC_CTX *tmp_ctx,
                                                struct confdb_ctx *cdb,
                                                const char *section,
                                                struct prompt_config ***pc_list)
{
    int ret;
    char *value = NULL;

    ret = confdb_get_string(cdb, tmp_ctx, section, CONFDB_PC_PASSWORD_PROMPT,
                            NULL, &value);
    if (ret == EOK && value != NULL) {
        ret = pc_list_add_password(pc_list, value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "pc_list_add_password failed.\n");
        }
        return ret;
    }

    return ENOENT;
}

static errno_t pam_set_2fa_prompting_options(TALLOC_CTX *tmp_ctx,
                                             struct confdb_ctx *cdb,
                                             const char *section,
                                             struct prompt_config ***pc_list)
{
    bool single_2fa_prompt = false;
    char *first_prompt = NULL;
    char *second_prompt = NULL;
    int ret;


    ret = confdb_get_bool(cdb, section, CONFDB_PC_2FA_SINGLE_PROMPT, false,
                          &single_2fa_prompt);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "confdb_get_bool failed, using defaults");
    }
    ret = confdb_get_string(cdb, tmp_ctx, section, CONFDB_PC_2FA_1ST_PROMPT,
                            NULL, &first_prompt);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "confdb_get_string failed, using defaults");
    }

    if (single_2fa_prompt) {
        ret = pc_list_add_2fa_single(pc_list, first_prompt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "pc_list_add_2fa_single failed.\n");
        }
        return ret;
    } else {
        ret = confdb_get_string(cdb, tmp_ctx, section, CONFDB_PC_2FA_2ND_PROMPT,
                                NULL, &second_prompt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "confdb_get_string failed, using defaults");
        }

        ret = pc_list_add_2fa(pc_list, first_prompt, second_prompt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "pc_list_add_2fa failed.\n");
        }
        return ret;
    }

    return ENOENT;
}

static errno_t pam_set_passkey_prompting_options(TALLOC_CTX *tmp_ctx,
                                             struct confdb_ctx *cdb,
                                             const char *section,
                                             struct prompt_config ***pc_list)
{
    bool passkey_interactive = false;
    char *passkey_interactive_prompt = NULL;
    bool passkey_touch = false;
    char *passkey_touch_prompt = NULL;
    int ret;


    ret = confdb_get_bool(cdb, section, CONFDB_PC_PASSKEY_INTERACTIVE, false,
                          &passkey_interactive);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "confdb_get_bool failed, using defaults");
    }

    if (passkey_interactive) {
        ret = confdb_get_string(cdb, tmp_ctx, section, CONFDB_PC_PASSKEY_INTERACTIVE_PROMPT,
                                DEFAULT_PASSKEY_PROMPT_INTERACTIVE, &passkey_interactive_prompt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "confdb_get_string failed, using defaults");
        }
    }

    ret = confdb_get_bool(cdb, section, CONFDB_PC_PASSKEY_TOUCH, false,
                          &passkey_touch);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "confdb_get_bool failed, using defaults");
    }

    if (passkey_touch) {
	    ret = confdb_get_string(cdb, tmp_ctx, section, CONFDB_PC_PASSKEY_TOUCH_PROMPT,
			                    DEFAULT_PASSKEY_PROMPT_TOUCH, &passkey_touch_prompt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "confdb_get_string failed, using defaults");
        }
    }

    ret = pc_list_add_passkey(pc_list, passkey_interactive_prompt, passkey_touch_prompt);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "pc_list_add_passkey_touch failed.\n");
    }

    return ret;
}
static errno_t pam_set_prompting_options(struct confdb_ctx *cdb,
                                         const char *service_name,
                                         char **sections,
                                         int num_sections,
                                         const char *section_path,
                                         pam_set_prompting_fn_t *setter,
                                         struct prompt_config ***pc_list)
{
    char *dummy;
    size_t c;
    bool global = false;
    bool specific = false;
    char *section = NULL;
    int ret;
    char *last;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }


    dummy = talloc_asprintf(tmp_ctx, "%s/%s", section_path,
                                              service_name);
    for (c = 0; c < num_sections; c++) {
        if (strcmp(sections[c], section_path) == 0) {
            global = true;
        }
        if (dummy != NULL && strcmp(sections[c], dummy) == 0) {
            specific = true;
        }
    }

    section = talloc_asprintf(tmp_ctx, "%s/%s", CONFDB_PC_CONF_ENTRY, dummy);
    if (section == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ENOENT;
    if (specific) {
        ret = setter(tmp_ctx, cdb, section, pc_list);
    }
    if (global && ret == ENOENT) {
        last = strrchr(section, '/');
        if (last != NULL) {
            *last = '\0';
            ret = setter(tmp_ctx, cdb, section, pc_list);
        }
    }
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "setter failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t pam_eval_prompting_config(struct pam_ctx *pctx, struct pam_data *pd)
{
    int ret;
    struct prompt_config **pc_list = NULL;
    int resp_len;
    uint8_t *resp_data = NULL;
    struct pam_resp_auth_type types;

    if (pctx->num_prompting_config_sections == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "No prompting configuration found.\n");
        return EOK;
    }

    ret = pam_get_auth_types(pd, &types);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get authentication types\n");
        goto done;
    }

    if (types.passkey_auth) {
        ret = pam_set_prompting_options(pctx->rctx->cdb, pd->service,
                                        pctx->prompting_config_sections,
                                        pctx->num_prompting_config_sections,
                                        CONFDB_PC_TYPE_PASSKEY,
                                        pam_set_passkey_prompting_options,
                                        &pc_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "pam_set_prompting_options failed.\n");
            goto done;
        }
    }

    if (types.cert_auth) {
        /* If certificate based authentication is possilbe, i.e. a Smartcard
         * or similar with the mapped certificate is available we currently
         * prefer this authentication type unconditionally. If other types
         * should be used the Smartcard can be removed during authentication.
         * Since there currently are no specific options for cert_auth we are
         * done. */
        ret = EOK;
        goto done;
    }

    /* If OTP and password auth are possible we currently prefer OTP. */
    if (types.otp_auth) {
        ret = pam_set_prompting_options(pctx->rctx->cdb, pd->service,
                                        pctx->prompting_config_sections,
                                        pctx->num_prompting_config_sections,
                                        CONFDB_PC_TYPE_2FA,
                                        pam_set_2fa_prompting_options,
                                        &pc_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "pam_set_prompting_options failed.\n");
            goto done;
        }
    }

    if (types.password_auth) {
        ret = pam_set_prompting_options(pctx->rctx->cdb, pd->service,
                                        pctx->prompting_config_sections,
                                        pctx->num_prompting_config_sections,
                                        CONFDB_PC_TYPE_PASSWORD,
                                        pam_set_password_prompting_options,
                                        &pc_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "pam_set_prompting_options failed.\n");
            goto done;
        }
    }

    if (pc_list != NULL) {
        ret = pam_get_response_prompt_config(pc_list, &resp_len, &resp_data);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "pam_get_response_prompt_config failed.\n");
            goto done;
        }

        ret = pam_add_response(pd, SSS_PAM_PROMPT_CONFIG, resp_len, resp_data);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "pam_add_response failed.\n");
            goto done;
        }
    }

    ret = EOK;
done:
    free(resp_data);
    pc_list_free(pc_list);

    return ret;
}
