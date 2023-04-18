/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2023 Red Hat

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
#include <stdlib.h>
#include <string.h>
#include <krb5/clpreauth_plugin.h>

#include "krb5_plugin/common/radius_clpreauth.h"
#include "passkey.h"

static krb5_error_code
sss_passkeycl_prompt(krb5_context context,
                     krb5_prompter_fct prompter,
                     void *prompter_data,
                     struct sss_passkey_message *message,
                     krb5_data *_reply)
{
    return ENOTSUP;
}

static krb5_error_code
sss_passkeycl_prep_questions(krb5_context context,
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
    struct sss_passkey_message *message;
    char *question = NULL;
    char **realms = NULL;
    krb5_error_code ret;
    size_t r = 0;

    message = sss_passkey_message_decode_padata(pa_data);
    if (message == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (message->data.challenge->domain == NULL) {
        ret = KRB5KDC_ERR_PREAUTH_FAILED;
        goto done;
    }

    /* Find a realm that matches the domain from the challenge */
    ret = krb5_get_host_realm(context,
                              message->data.challenge->domain,
                              &realms);
    if (ret || ((realms == NULL) || (realms[0] == NULL))) {
        ret = KRB5KDC_ERR_PREAUTH_FAILED;
        goto done;
    }

    /* Do explicit check for the challenge domain in case
     * we've got back a referral (empty) realm */
    if (strlen(realms[0]) == strlen(KRB5_REFERRAL_REALM)) {
        ret = strncasecmp(message->data.challenge->domain,
                          request->server->realm.data,
                          request->server->realm.length);
        if (ret != 0) {
            ret = KRB5KDC_ERR_PREAUTH_FAILED;
            goto done;
        }

    } else {
        for(r = 0; realms[r] != NULL; r++) {
            ret = strncasecmp(realms[r],
                              request->server->realm.data,
                              request->server->realm.length);
            if (ret == 0) {
                break;
            }
        }

        /* doesn't know the domain, reject the challenge */
        if (realms[r] == NULL) {
            ret = KRB5KDC_ERR_PREAUTH_FAILED;
            goto done;
        }
    }

    question = sss_passkey_message_encode(message);
    if (question == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = cb->ask_responder_question(context, rock, SSSD_PASSKEY_QUESTION,
                                     question);

done:
    if (realms) {
        krb5_free_host_realm(context, realms);
    }
    sss_passkey_message_free(message);
    free(question);

    return ret;
}

static krb5_error_code
sss_passkeycl_process(krb5_context context,
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
    krb5_data user_reply;
    struct sss_passkey_message *input_message = NULL;
    struct sss_passkey_message *reply_message = NULL;
    char prompt_answer[255] = {0};
    const char *answer;

    input_message = sss_passkey_message_decode_padata(pa_data);
    if (input_message == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Get FAST armor key. */
    as_key = cb->fast_armor(context, rock);
    if (as_key == NULL) {
        ret = ENOENT;
        goto done;
    }

    answer = cb->get_responder_answer(context, rock, SSSD_PASSKEY_QUESTION);
    /* Call prompter if we have no answer to present a prompt. */
    if (answer == NULL) {
        user_reply.magic = 0;
        user_reply.length = sizeof(prompt_answer) / sizeof(char);
        user_reply.data = prompt_answer;

        ret = sss_passkeycl_prompt(context, prompter, prompter_data,
                                   input_message, &user_reply);
        if (ret != 0) {
            goto done;
        }
    }

    /* Use FAST armor key as response key. */
    ret = cb->set_as_key(context, rock, as_key);
    if (ret != 0) {
        goto done;
    }

    /* Encode the answer into the pa_data output. */
    reply_message = sss_passkey_message_decode(answer);
    if (reply_message == NULL) {
        ret = ENOMEM;
        goto done;
    }

    padata = sss_passkey_message_encode_padata_array(reply_message);
    if (padata == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cb->disable_fallback(context, rock);
    *_pa_data_out = padata;

    ret = 0;

done:
    sss_passkey_message_free(reply_message);
    sss_passkey_message_free(input_message);
    return ret;
}

krb5_error_code
clpreauth_passkey_initvt(krb5_context context,
                         int maj_ver,
                         int min_ver,
                         krb5_plugin_vtable vtable)
{
    static krb5_preauthtype pa_type_list[] = { SSSD_PASSKEY_PADATA, 0 };
    krb5_clpreauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }

    vt = (krb5_clpreauth_vtable)vtable;
    vt->name = discard_const(SSSD_PASSKEY_PLUGIN);
    vt->pa_type_list = pa_type_list;
    vt->request_init = sss_radiuscl_init;
    vt->prep_questions = sss_passkeycl_prep_questions;
    vt->process = sss_passkeycl_process;
    vt->request_fini = sss_radiuscl_fini;
    vt->gic_opts = NULL;

    return 0;
}
