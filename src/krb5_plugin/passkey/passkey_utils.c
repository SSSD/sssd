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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <arpa/inet.h>
#include <krb5/preauth_plugin.h>

#include "krb5_plugin/common/utils.h"
#include "krb5_plugin/passkey/passkey.h"

void
sss_passkey_config_free(struct sss_passkey_config *passkey)
{
    if (passkey == NULL) {
        return;
    }

    sss_string_array_free(passkey->indicators);
    free(passkey);
}

/**
 * {
 *   "indicators": ["..."] (optional)
 * }
 */
krb5_error_code
sss_passkey_config_init(const char *config,
                        struct sss_passkey_config **_passkey)
{
    struct sss_passkey_config *passkey;
    json_t *jindicators = NULL;
    json_error_t jret;
    json_t *jroot;
    krb5_error_code ret;

    passkey = malloc(sizeof(struct sss_passkey_config));
    if (passkey == NULL) {
        return ENOMEM;
    }
    memset(passkey, 0, sizeof(struct sss_passkey_config));

    jroot = json_loads(config, 0, &jret);
    if (jroot == NULL) {
        ret = EINVAL;
        goto done;
    }

    ret = json_unpack(jroot, "[{s?:o}]", "indicators", &jindicators);
    if (ret != 0) {
        ret = EINVAL;
        goto done;
    }

    /* Are indicators set? */
    if (jindicators != NULL) {
        passkey->indicators = sss_json_array_to_strings(jindicators);
        if (passkey->indicators == NULL) {
            ret = EINVAL;
            goto done;
        }
    }

    *_passkey = passkey;

    ret = 0;

done:
    if (ret != 0) {
        sss_passkey_config_free(passkey);
    }

    if (jroot != NULL) {
        json_decref(jroot);
    }

    return ret;
}

void
sss_passkey_challenge_free(struct sss_passkey_challenge *data)
{
    if (data == NULL) {
        return;
    }

    free(data->domain);
    free(data->cryptographic_challenge);
    sss_string_array_free(data->credential_id_list);

    free(data);
}

static struct sss_passkey_challenge *
sss_passkey_challenge_init(char *domain,
                           char **credential_id_list,
                           int user_verification,
                           char *cryptographic_challenge)
{
    struct sss_passkey_challenge *data;
    krb5_error_code ret;

    /* These are required fields. */
    if (is_empty(domain)
        || is_empty(cryptographic_challenge)
        || credential_id_list == NULL || is_empty(credential_id_list[0])) {
        return NULL;
    }

    data = malloc(sizeof(struct sss_passkey_challenge));
    if (data == NULL) {
        return NULL;
    }
    memset(data, 0, sizeof(struct sss_passkey_challenge));

    data->user_verification = user_verification;
    data->domain = strdup(domain);
    data->cryptographic_challenge = strdup(cryptographic_challenge);
    if (data->domain == NULL || data->cryptographic_challenge == NULL) {
        ret = ENOMEM;
        goto done;
    }

    data->credential_id_list = sss_string_array_copy(credential_id_list);
    if (data->credential_id_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;

done:
    if (ret != 0) {
        sss_passkey_challenge_free(data);
        return NULL;
    }

    return data;
}

static struct sss_passkey_challenge *
sss_passkey_challenge_from_json_object(json_t *jobject)
{
    struct sss_passkey_challenge jdata = {0};
    struct sss_passkey_challenge *data = NULL;
    json_t *jcredential_id_list = NULL;
    char **credential_id_list = NULL;
    int ret;

    if (jobject == NULL) {
        return NULL;
    }

    ret = json_unpack(jobject, "{s:s, s:o, s:i, s:s}",
                "domain", &jdata.domain,
                "credential_id_list", &jcredential_id_list,
                "user_verification", &jdata.user_verification,
                "cryptographic_challenge", &jdata.cryptographic_challenge);
    if (ret != 0) {
        return NULL;
    }

    if (jcredential_id_list != NULL) {
        credential_id_list = sss_json_array_to_strings(jcredential_id_list);
        if (credential_id_list == NULL) {
            return NULL;
        }
    }

    data = sss_passkey_challenge_init(jdata.domain, credential_id_list,
                                      jdata.user_verification,
                                      jdata.cryptographic_challenge);

    sss_string_array_free(credential_id_list);
    return data;
}

static json_t *
sss_passkey_challenge_to_json_object(const struct sss_passkey_challenge *data)
{
    json_t *jroot;
    json_t *jcredential_id_list;

    if (data == NULL) {
        return NULL;
    }

    /* These are required fields. */
    if (data->domain == NULL || data->credential_id_list == NULL
        || data->cryptographic_challenge == NULL) {
        return NULL;
    }

    jcredential_id_list = sss_strings_to_json_array(data->credential_id_list);
    if (jcredential_id_list == NULL) {
        return NULL;
    }

    jroot = json_pack("{s:s, s:o, s:i, s:s}", "domain", data->domain,
                        "credential_id_list", jcredential_id_list,
                        "user_verification", data->user_verification,
                        "cryptographic_challenge",
                        data->cryptographic_challenge);
    if (jroot == NULL) {
        json_decref(jcredential_id_list);
        return NULL;
    }

    return jroot;
}

void
sss_passkey_reply_free(struct sss_passkey_reply *data)
{
    if (data == NULL) {
        return;
    }

    free(data->credential_id);
    free(data->cryptographic_challenge);
    free(data->authenticator_data);
    free(data->assertion_signature);
    free(data->user_id);
    free(data);
}

static struct sss_passkey_reply *
sss_passkey_reply_init(char *credential_id,
                       char *cryptographic_challenge,
                       char *authenticator_data,
                       char *assertion_signature,
                       char *user_id)
{
    struct sss_passkey_reply *data;
    krb5_error_code ret;

    /* These are required fields. */
    if (is_empty(credential_id)
        || is_empty(cryptographic_challenge)
        || is_empty(authenticator_data)
        || is_empty(assertion_signature)) {
        return NULL;
    }

    data = malloc(sizeof(struct sss_passkey_reply));
    if (data == NULL) {
        return NULL;
    }
    memset(data, 0, sizeof(struct sss_passkey_reply));

    data->credential_id = strdup(credential_id);
    data->cryptographic_challenge = strdup(cryptographic_challenge);
    data->authenticator_data = strdup(authenticator_data);
    data->assertion_signature = strdup(assertion_signature);
    data->user_id = user_id == NULL ? NULL : strdup(user_id);
    if (data->credential_id == NULL
        || data->cryptographic_challenge == NULL
        || data->authenticator_data == NULL
        || data->assertion_signature == NULL
        || (user_id != NULL && data->user_id == NULL)) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;

done:
    if (ret != 0) {
        sss_passkey_reply_free(data);
        return NULL;
    }

    return data;
}

static struct sss_passkey_reply *
sss_passkey_reply_from_json_object(json_t *jobject)
{
    struct sss_passkey_reply jdata = {0};
    int ret;

    if (jobject == NULL) {
        return NULL;
    }

    ret = json_unpack(jobject, "{s:s, s:s, s:s, s:s, s?:s}",
                "credential_id", &jdata.credential_id,
                "cryptographic_challenge", &jdata.cryptographic_challenge,
                "authenticator_data", &jdata.authenticator_data,
                "assertion_signature", &jdata.assertion_signature,
                "user_id", &jdata.user_id);
    if (ret != 0) {
        return NULL;
    }

    return sss_passkey_reply_init(jdata.credential_id,
                                  jdata.cryptographic_challenge,
                                  jdata.authenticator_data,
                                  jdata.assertion_signature,
                                  jdata.user_id);
}

static json_t *
sss_passkey_reply_to_json_object(const struct sss_passkey_reply *data)
{
    if (data == NULL) {
        return NULL;
    }

    /* These are required fields. */
    if (data->credential_id == NULL
       || data->cryptographic_challenge == NULL
       || data->authenticator_data == NULL
       || data->assertion_signature == NULL) {
        return NULL;
    }

    return json_pack("{s:s, s:s, s:s, s:s, s:s*}",
                     "credential_id", data->credential_id,
                     "cryptographic_challenge", data->cryptographic_challenge,
                     "authenticator_data", data->authenticator_data,
                     "assertion_signature", data->assertion_signature,
                     "user_id", data->user_id);
}

void
sss_passkey_message_free(struct sss_passkey_message *message)
{
    if (message == NULL) {
        return;
    }

    switch (message->phase) {
    case SSS_PASSKEY_PHASE_INIT:
        break;
    case SSS_PASSKEY_PHASE_CHALLENGE:
        sss_passkey_challenge_free(message->data.challenge);
        break;
    case SSS_PASSKEY_PHASE_REPLY:
        sss_passkey_reply_free(message->data.reply);
        break;
    default:
        /* nothing to do */
        break;
    }

    free(message->state);
    free(message);
}

static struct sss_passkey_message *
sss_passkey_message_init(enum sss_passkey_phase phase,
                         const char *state,
                         void *data)
{
    struct sss_passkey_message *message;

    switch (phase) {
    case SSS_PASSKEY_PHASE_INIT:
        if (state != NULL || data != NULL) {
            return NULL;
        }
        break;
    case SSS_PASSKEY_PHASE_CHALLENGE:
    case SSS_PASSKEY_PHASE_REPLY:
        if (state == NULL || data == NULL) {
            return NULL;
        }
        break;
    default:
        return NULL;
    }

    message = malloc(sizeof(struct sss_passkey_message));
    if (message == NULL) {
        return NULL;
    }
    memset(message, 0, sizeof(struct sss_passkey_message));

    message->phase = phase;
    message->state = state == NULL ? NULL : strdup(state);
    message->data.ptr = data;

    if (state != NULL && message->state == NULL) {
        sss_passkey_message_free(message);
        return NULL;
    }

    return message;
}

static struct sss_passkey_message *
sss_passkey_message_from_json(const char *json_str)
{
    struct sss_passkey_message *message = NULL;
    enum sss_passkey_phase phase = 0;
    const char *state = NULL;
    void *data = NULL;
    json_error_t jret;
    json_t *jdata = NULL;
    json_t *jroot;
    int ret;

    jroot = json_loads(json_str, 0, &jret);
    if (jroot == NULL) {
        return NULL;
    }

    ret = json_unpack(jroot, "{s:i, s?:s, s?:o}",
                     "phase", &phase,
                     "state", &state,
                     "data", &jdata);
    if (ret != 0) {
        goto done;
    }

    switch (phase) {
    case SSS_PASSKEY_PHASE_INIT:
        data = NULL;
        break;
    case SSS_PASSKEY_PHASE_CHALLENGE:
        data = sss_passkey_challenge_from_json_object(jdata);
        if (data == NULL) {
            goto done;
        }
        break;
    case SSS_PASSKEY_PHASE_REPLY:
        data = sss_passkey_reply_from_json_object(jdata);
        if (data == NULL) {
            goto done;
        }
        break;
    default:
        goto done;
    }

    message = sss_passkey_message_init(phase, state, data);
    if (message == NULL && phase == SSS_PASSKEY_PHASE_CHALLENGE) {
        sss_passkey_challenge_free(data);
    } else if (message == NULL && phase == SSS_PASSKEY_PHASE_REPLY) {
        sss_passkey_reply_free(data);
    }

done:
    json_decref(jroot);
    return message;
}

static char *
sss_passkey_message_to_json(const struct sss_passkey_message *message)
{
    json_t *jroot;
    json_t *jdata;
    char *str;

    if (message == NULL) {
        return NULL;
    }

    switch (message->phase) {
    case SSS_PASSKEY_PHASE_INIT:
        if (message->state != NULL || message->data.ptr != NULL) {
            return NULL;
        }
        jdata = NULL;
        break;
    case SSS_PASSKEY_PHASE_CHALLENGE:
        if (message->state == NULL || message->data.challenge == NULL) {
            return NULL;
        }

        jdata = sss_passkey_challenge_to_json_object(message->data.challenge);
        if (jdata == NULL) {
            return NULL;
        }
        break;
    case SSS_PASSKEY_PHASE_REPLY:
        if (message->state == NULL || message->data.reply == NULL) {
            return NULL;
        }

        jdata = sss_passkey_reply_to_json_object(message->data.reply);
        if (jdata == NULL) {
            return NULL;
        }
        break;
    default:
        return NULL;
    }

    jroot = json_pack("{s:i, s:s*, s:o*}",
                      "phase", message->phase,
                      "state", message->state,
                      "data", jdata);
    if (jroot == NULL) {
        json_decref(jdata);
        return NULL;
    }

    str = json_dumps(jroot, JSON_COMPACT);
    json_decref(jroot);

    return str;
}

struct sss_passkey_message *
sss_passkey_message_from_reply_json(enum sss_passkey_phase phase,
                                    const char *state,
                                    const char *json_str)
{
    json_error_t jret;
    json_t *jroot;
    struct sss_passkey_message *message;
    struct sss_passkey_reply *data;

    if (json_str == NULL) {
        return NULL;
    }

    jroot = json_loads(json_str, 0, &jret);
    if (jroot == NULL) {
        return NULL;
    }

    data = sss_passkey_reply_from_json_object(jroot);
    if (data == NULL) {
        json_decref(jroot);
        return NULL;
    }

    message = sss_passkey_message_init(phase, state, data);
    if (message == NULL) {
        sss_passkey_reply_free(data);
    }

    json_decref(jroot);
    return message;
}

char *
sss_passkey_message_encode(const struct sss_passkey_message *data)
{
    return sss_radius_message_encode(SSSD_PASSKEY_PREFIX,
        (sss_radius_message_encode_fn)sss_passkey_message_to_json, data);
}

struct sss_passkey_message *
sss_passkey_message_decode(const char *str)
{
    return sss_radius_message_decode(SSSD_PASSKEY_PREFIX,
        (sss_radius_message_decode_fn)sss_passkey_message_from_json, str);
}

krb5_pa_data *
sss_passkey_message_encode_padata(const struct sss_passkey_message *data)
{
    return sss_radius_encode_padata(SSSD_PASSKEY_PADATA,
        (sss_radius_message_encode_fn)sss_passkey_message_encode, data);
}

struct sss_passkey_message *
sss_passkey_message_decode_padata(krb5_pa_data *padata)
{
    return sss_radius_decode_padata(
        (sss_radius_message_decode_fn)sss_passkey_message_decode, padata);
}

krb5_pa_data **
sss_passkey_message_encode_padata_array(const struct sss_passkey_message *data)
{
    return sss_radius_encode_padata_array(SSSD_PASSKEY_PADATA,
        (sss_radius_message_encode_fn)sss_passkey_message_encode, data);
}

krb5_error_code
sss_passkey_concat_credentials(char **creds,
                               char **_creds_str)
{
    krb5_error_code ret;
    char *result_creds = NULL;
    size_t total_sz = 0;
    size_t len = 0;
    int rc = 0;

    for (int i = 0; creds[i] != NULL; i++) {
        total_sz += strlen(creds[i]);
        if (i > 0) {
            /* separating comma in resulting creds string */
            total_sz++;
        }
    }

    result_creds = malloc(total_sz + 1);
    if (result_creds == NULL) {
        ret = ENOMEM;
        goto done;
    }

    len = strlen(creds[0]);

    rc = snprintf(result_creds, len + 1, "%s", creds[0]);
    if (rc < 0 || rc > len) {
        ret = ENOMEM;
        free(result_creds);
        goto done;
    }

    for (int i = 1; creds[i] != NULL; i++) {
        rc = snprintf(result_creds + len, total_sz - len + 1, ",%s", creds[i]);
        if (rc < 0 || rc > total_sz - len) {
            ret = ENOMEM;
            free(result_creds);
            goto done;
        }

        len += rc;
    }

    *_creds_str = result_creds;

    ret = 0;
done:
    return ret;
}
