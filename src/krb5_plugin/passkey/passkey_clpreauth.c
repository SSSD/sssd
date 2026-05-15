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
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <krb5/clpreauth_plugin.h>

#include "krb5_plugin/common/radius_clpreauth.h"
#include "passkey.h"

#include "util/child_common.h"

static krb5_error_code
sss_passkeycl_prompt(krb5_context context,
                     krb5_prompter_fct prompter,
                     void *prompter_data,
                     struct sss_passkey_message *message,
                     const char *prompt_txt,
                     char *prompt_answer,
                     int answer_len,
                     krb5_data *_reply)
{
    krb5_error_code ret;
    krb5_prompt prompt;
    char *prompt_str;
    int aret;

    _reply->magic = 0;
    _reply->length = answer_len;
    _reply->data = prompt_answer;

    aret = asprintf(&prompt_str, "%s", prompt_txt);
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
sss_passkeycl_exec_child(struct sss_passkey_challenge *data,
                         char *pin,
                         uint8_t **_reply)
{
    int pipe_to_child[2];
    int pipe_to_parent[2];
    pid_t cpid;
    char *args[10] = {NULL};
    int arg_c = 0;
    int size;
    uint8_t *buf;
    int ret = 0;
    char *result_creds;

    buf = calloc(1, CHILD_MSG_CHUNK);
    if (buf == NULL) {
        ret = ENOMEM;
        return ret;
    }

    ret = sss_passkey_concat_credentials(data->credential_id_list,
                                         &result_creds);
    if (ret != 0) {
        ret = ENOMEM;
        goto done;
    }

    args[arg_c++] = discard_const(SSSD_PASSKEY_CHILD);
    args[arg_c++] = discard_const("--get-assert");
    args[arg_c++] = discard_const("--domain");
    args[arg_c++] = data->domain;
    args[arg_c++] = discard_const("--key-handle");
    args[arg_c++] = discard_const(result_creds);
    args[arg_c++] = discard_const("--cryptographic-challenge");
    args[arg_c++] = data->cryptographic_challenge;
    args[arg_c++] = NULL;

    ret = pipe(pipe_to_child);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    ret = pipe(pipe_to_parent);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    cpid = fork();
    /* Child */
    if (cpid == 0) {
        close(pipe_to_child[1]);
        dup2(pipe_to_child[0], STDIN_FILENO);

        close(pipe_to_parent[0]);
        dup2(pipe_to_parent[1], STDOUT_FILENO);

        execv(SSSD_PASSKEY_CHILD, args);
        exit(EXIT_FAILURE);
    /* Parent - write PIN to child and read output
     * back from child */
    } else {
        close(pipe_to_child[0]);
        close(pipe_to_parent[1]);

        write(pipe_to_child[1], pin, strlen(pin));
        close(pipe_to_child[1]);

        size = read(pipe_to_parent[0], buf, CHILD_MSG_CHUNK);
        if (size == -1) {
            ret = ENOMEM;
            goto done;
        }

        close(pipe_to_parent[0]);
        wait(NULL);
    }

    *_reply = buf;

done:
    if (ret != 0) {
        free(buf);
    }

    free(result_creds);
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
    struct sss_passkey_message *reply_msg = NULL;
    enum sss_passkey_phase phase;
    const char *state;
    char prompt_answer[255] = {0};
    int answer_len;
    char *prompt_reply = NULL;
    uint8_t *reply = NULL;
    const char *answer;

    input_message = sss_passkey_message_decode_padata(pa_data);
    if (input_message == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (prompter == NULL) {
        ret = EINVAL;
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
        /* Interactive prompt */
        answer_len = sizeof(prompt_answer) / sizeof(char);

        ret = sss_passkeycl_prompt(context, prompter, prompter_data,
                                   input_message, SSSD_PASSKEY_PROMPT,
                                   prompt_answer, answer_len,
                                   &user_reply);
        if (ret != 0) {
            goto done;
        }

        /* Prompt for PIN */
        if (input_message->data.challenge->user_verification == 1) {
            ret = sss_passkeycl_prompt(context, prompter, prompter_data,
                                       input_message, SSSD_PASSKEY_PIN_PROMPT,
                                       prompt_answer, answer_len,
                                       &user_reply);
            if (ret != 0) {
                goto done;
            }
        }

        ret = sss_passkeycl_exec_child(input_message->data.challenge, prompt_answer, &reply);
        if (ret != 0) {
            goto done;
        }

        phase = SSS_PASSKEY_PHASE_REPLY;
        state = SSSD_PASSKEY_REPLY_STATE;
        reply_msg = sss_passkey_message_from_reply_json(phase, state, (char *)reply);
        if (reply_msg == NULL) {
            ret = ENOMEM;
            goto done;
        }

        prompt_reply = sss_passkey_message_encode(reply_msg);
        if (prompt_reply == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* Use FAST armor key as response key. */
    ret = cb->set_as_key(context, rock, as_key);
    if (ret != 0) {
        goto done;
    }

    /* Encode the answer into the pa_data output. */
    if (prompt_reply != NULL) {
        reply_message = sss_passkey_message_decode(prompt_reply);
    } else {
        reply_message = sss_passkey_message_decode(answer);
    }
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
    sss_passkey_message_free(reply_msg);
    sss_passkey_message_free(input_message);
    free(reply);
    free(prompt_reply);

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
