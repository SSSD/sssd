/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2021 Red Hat

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <krb5/clpreauth_plugin.h>

#include "krb5_plugin/common/radius_clpreauth.h"
#include "idp.h"

static krb5_pa_data **
sss_idpcl_encode_padata(void)
{
    krb5_pa_data **padata;

    padata = calloc(2, sizeof(krb5_pa_data *));
    if (padata == NULL) {
        return NULL;
    }

    padata[0] = malloc(sizeof(krb5_pa_data));
    if (padata[0] == NULL) {
        free(padata);
        return NULL;
    }

    padata[0]->pa_type = SSSD_IDP_OAUTH2_PADATA;
    padata[0]->contents = NULL;
    padata[0]->length = 0;

    padata[1] = NULL;

    return padata;
}

static krb5_error_code
sss_idpcl_prompt(krb5_context context,
                 krb5_prompter_fct prompter,
                 void *prompter_data,
                 struct sss_idp_oauth2 *data,
                 krb5_data *_reply)
{
    krb5_error_code ret;
    krb5_prompt prompt;
    char *prompt_str;
    int aret;

    if (data->verification_uri_complete != NULL) {
        aret = asprintf(&prompt_str,
                        "Authenticate at %1$s and press ENTER.",
                        data->verification_uri_complete);
    } else {
        aret = asprintf(&prompt_str,
                        "Authenticate with PIN %1$s at %2$s and press ENTER.",
                        data->user_code, data->verification_uri);
    }

    if (aret < 0) {
        return ENOMEM;
    }

    prompt.reply = _reply;
    prompt.prompt = prompt_str;
    prompt.hidden = 1;

    ret = (*prompter)(context, prompter_data, NULL, NULL, 1, &prompt);
    free(prompt_str);

    return ret;
}

static krb5_error_code
sss_idpcl_prep_questions(krb5_context context,
                         krb5_clpreauth_moddata moddata,
                         krb5_clpreauth_modreq modreq,
                         krb5_get_init_creds_opt *opt,
                         krb5_clpreauth_callbacks cb,
                         krb5_clpreauth_rock rock,
                         krb5_kdc_req *request,
                         krb5_data *encoded_request_body,
                         krb5_data *encoded_previous_request,
                         krb5_pa_data *pa_data)
{
    struct sss_idp_oauth2 *data;
    char *challenge = NULL;
    krb5_error_code ret;

    data = sss_idp_oauth2_decode_padata(pa_data);
    if (data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    challenge = sss_idp_oauth2_encode_challenge(data);
    if (challenge == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = cb->ask_responder_question(context, rock, SSSD_IDP_OAUTH2_QUESTION,
                                     challenge);

done:
    sss_idp_oauth2_free(data);
    free(challenge);

    return ret;
}

static krb5_error_code
sss_idpcl_process(krb5_context context,
                  krb5_clpreauth_moddata moddata,
                  krb5_clpreauth_modreq modreq,
                  krb5_get_init_creds_opt *opt,
                  krb5_clpreauth_callbacks cb,
                  krb5_clpreauth_rock rock,
                  krb5_kdc_req *request,
                  krb5_data *encoded_request_body,
                  krb5_data *encoded_previous_request,
                  krb5_pa_data *pa_data,
                  krb5_prompter_fct prompter,
                  void *prompter_data,
                  krb5_pa_data ***_pa_data_out)
{
    krb5_keyblock *as_key;
    krb5_pa_data **padata;
    krb5_error_code ret;
    krb5_data reply;
    struct sss_idp_oauth2 *data = NULL;
    char prompt_answer[255] = {0};
    const char *answer;

    data = sss_idp_oauth2_decode_padata(pa_data);
    if (data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Get FAST armor key. */
    as_key = cb->fast_armor(context, rock);
    if (as_key == NULL) {
        ret = ENOENT;
        goto done;
    }

    answer = cb->get_responder_answer(context, rock, SSSD_IDP_OAUTH2_QUESTION);
    /* Call prompter if we have no answer. We don't really require any answer,
     * but we need to present a prompt to the user and wait until the user has
     * finished authentication via an idp provider. */
    if (answer == NULL) {
        reply.magic = 0;
        reply.length = sizeof(prompt_answer) / sizeof(char);
        reply.data = prompt_answer;

        ret = sss_idpcl_prompt(context, prompter, prompter_data, data, &reply);
        if (ret != 0) {
            goto done;
        }
    }

    /* Use FAST armor key as response key. */
    ret = cb->set_as_key(context, rock, as_key);
    if (ret != 0) {
        goto done;
    }

    /* Encode the request into the pa_data output. */
    padata = sss_idpcl_encode_padata();
    if (padata == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cb->disable_fallback(context, rock);
    *_pa_data_out = padata;

    ret = 0;

done:
    sss_idp_oauth2_free(data);
    return ret;
}

krb5_error_code
clpreauth_idp_initvt(krb5_context context,
                     int maj_ver,
                     int min_ver,
                     krb5_plugin_vtable vtable)
{
    static krb5_preauthtype pa_type_list[] = { SSSD_IDP_OAUTH2_PADATA, 0 };
    krb5_clpreauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }

    vt = (krb5_clpreauth_vtable)vtable;
    vt->name = discard_const(SSSD_IDP_PLUGIN);
    vt->pa_type_list = pa_type_list;
    vt->request_init = sss_radiuscl_init;
    vt->prep_questions = sss_idpcl_prep_questions;
    vt->process = sss_idpcl_process;
    vt->request_fini = sss_radiuscl_fini;
    vt->gic_opts = NULL;

    return 0;
}
