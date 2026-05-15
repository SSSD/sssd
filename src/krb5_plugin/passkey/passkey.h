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

#ifndef _PASSKEY_H_
#define _PASSKEY_H_

#include <stdlib.h>
#include <krb5/preauth_plugin.h>

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#define SSSD_PASSKEY_PLUGIN "passkey"
#define SSSD_PASSKEY_CONFIG "passkey"
#define SSSD_PASSKEY_PADATA 153 // PA-REDHAT-PASSKEY
#define SSSD_PASSKEY_QUESTION "passkey"
#define SSSD_PASSKEY_PREFIX "passkey "
#define SSSD_PASSKEY_REPLY_STATE "ipa_otpd state"
#define SSSD_PASSKEY_PROMPT "Insert your passkey device, then press ENTER"
#define SSSD_PASSKEY_PIN_PROMPT "Enter PIN"
#define SSSD_PASSKEY_CHILD SSSD_LIBEXEC_PATH"/passkey_child"

struct sss_passkey_config {
    char **indicators;
};

void
sss_passkey_config_free(struct sss_passkey_config *passkey);

krb5_error_code
sss_passkey_config_init(const char *config,
                        struct sss_passkey_config **_passkey);

enum sss_passkey_phase {
    SSS_PASSKEY_PHASE_INIT,
    SSS_PASSKEY_PHASE_CHALLENGE,
    SSS_PASSKEY_PHASE_REPLY
};

struct sss_passkey_challenge {
    char *domain;
    char **credential_id_list;
    int user_verification;
    char *cryptographic_challenge;
};

struct sss_passkey_reply {
    char *credential_id;
    char *cryptographic_challenge;
    char *authenticator_data;
    char *assertion_signature;
    char *user_id;
};

struct sss_passkey_message {
    enum sss_passkey_phase phase;
    char *state;
    union {
        struct sss_passkey_challenge *challenge;
        struct sss_passkey_reply *reply;
        void *ptr;
    } data;
};

void
sss_passkey_message_free(struct sss_passkey_message *message);

struct sss_passkey_message *
sss_passkey_message_from_reply_json(enum sss_passkey_phase phase,
                                    const char *state,
                                    const char *json_str);

char *
sss_passkey_message_encode(const struct sss_passkey_message *data);

struct sss_passkey_message *
sss_passkey_message_decode(const char *str);

krb5_pa_data *
sss_passkey_message_encode_padata(const struct sss_passkey_message *data);

struct sss_passkey_message *
sss_passkey_message_decode_padata(krb5_pa_data *padata);

krb5_pa_data **
sss_passkey_message_encode_padata_array(const struct sss_passkey_message *data);

krb5_error_code
sss_passkey_concat_credentials(char **creds,
                               char **_creds_str);

#endif /* _PASSKEY_H_ */
