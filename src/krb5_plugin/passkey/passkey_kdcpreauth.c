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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <krad.h>
#include <krb5/kdcpreauth_plugin.h>

#include "shared/safealign.h"
#include "krb5_plugin/common/radius_kdcpreauth.h"
#include "krb5_plugin/common/utils.h"
#include "krb5_plugin/passkey/passkey.h"
#include "util/util.h"

struct sss_passkeykdc_config {
    struct sss_radiuskdc_config *radius;
    struct sss_passkey_config *passkey;
};

static void
sss_passkeykdc_config_free(struct sss_passkeykdc_config *config)
{
    if (config == NULL) {
        return;
    }

    sss_radiuskdc_config_free(config->radius);
    sss_passkey_config_free(config->passkey);
    free(config);
}

static krb5_error_code
sss_passkeykdc_config_init(struct sss_radiuskdc_state *state,
                           krb5_context kctx,
                           krb5_const_principal princ,
                           const char *configstr,
                           struct sss_passkeykdc_config **_config)
{
    struct sss_passkeykdc_config *config;
    krb5_error_code ret;

    if (state == NULL) {
        return EINVAL;
    }

    config = malloc(sizeof(struct sss_passkeykdc_config));
    if (config == NULL) {
        ret = ENOMEM;
        goto done;
    }
    memset(config, 0, sizeof(struct sss_passkeykdc_config));

    ret = sss_radiuskdc_config_init(state, kctx, princ, configstr, &config->radius);
    if (ret != 0) {
        goto done;
    }

    ret = sss_passkey_config_init(configstr, &config->passkey);
    if (ret != 0) {
        goto done;
    }


    *_config = config;
    ret = 0;

done:
    if (ret != 0) {
        sss_passkeykdc_config_free(config);
    }

    return ret;
}

static void
sss_passkeykdc_challenge_done(krb5_error_code rret,
                              const krad_packet *rreq,
                              const krad_packet *rres,
                              void *data)
{
    struct sss_passkey_message *message = NULL;
    struct sss_radiuskdc_challenge *state;
    krb5_pa_data *padata = NULL;
    krb5_data cookie = {0};
    char *reply = NULL;
    krb5_error_code ret;

    state = (struct sss_radiuskdc_challenge *)data;

    if (rret != 0) {
        ret = rret;
        goto done;
    }

    if (krad_packet_get_code(rres) != krad_code_name2num("Access-Challenge")) {
        ret = ENOENT;
        goto done;
    }

    reply = sss_radiuskdc_get_attr_as_string(rres, "Proxy-State");
    if (reply == NULL) {
        ret = EINVAL;
        goto done;
    }

    message = sss_passkey_message_decode(reply);
    if (message == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (message->phase != SSS_PASSKEY_PHASE_CHALLENGE) {
        ret = EINVAL;
        goto done;
    }

    /* Remember the whole passkey challenge message in cookie so we can later
     * verify that the client response is really associated with this request.
     */
    cookie.data = reply;
    cookie.length = strlen(reply) + 1;
    ret = sss_radiuskdc_set_cookie(state->kctx, state->cb, state->rock,
                                   SSSD_PASSKEY_PADATA, &cookie);
    if (ret != 0) {
        goto done;
    }

    padata = sss_passkey_message_encode_padata(message);
    if (padata == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;

done:
    state->respond(state->arg, ret, padata);
    sss_radiuskdc_challenge_free(state);
    sss_passkey_message_free(message);
    free(reply);

    /* padata should not be freed */

    return;
}

/* Send a password-less Access-Request and expect Access-Challenge response. */
static krb5_error_code
sss_passkeykdc_challenge_send(krb5_context kctx,
                              krb5_kdcpreauth_callbacks cb,
                              krb5_kdcpreauth_rock rock,
                              krb5_kdcpreauth_edata_respond_fn respond,
                              void *arg,
                              struct sss_radiuskdc_config *config)
{
    struct sss_passkey_message message;
    struct sss_radiuskdc_challenge *state;
    char *encoded_message = NULL;
    krb5_error_code ret;

    state = sss_radiuskdc_challenge_init(kctx, cb, rock, respond, arg, config);
    if (state == NULL) {
        ret = ENOMEM;
        goto done;
    }

    message.phase = SSS_PASSKEY_PHASE_INIT;
    message.state = NULL;
    message.data.challenge = NULL;

    encoded_message = sss_passkey_message_encode(&message);
    if (encoded_message == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_radiuskdc_set_attr_as_string(state->client->attrs,
                                           "Proxy-State",
                                           encoded_message);
    if (ret != 0) {
        goto done;
    }

    ret = krad_client_send(state->client->client,
                           krad_code_name2num("Access-Request"),
                           state->client->attrs, config->server,
                           config->secret, config->timeout, config->retries,
                           sss_passkeykdc_challenge_done, state);

done:
    free(encoded_message);

    if (ret != 0) {
        sss_radiuskdc_challenge_free(state);
    }

    return ret;
}

/* Send Access-Request with password and state set to indicate that the user has
 * finished authentication against passkey provider. We expect Access-Accept. */
static krb5_error_code
sss_passkeykdc_verify_send(krb5_context kctx,
                           krb5_kdcpreauth_rock rock,
                           krb5_kdcpreauth_callbacks cb,
                           krb5_enc_tkt_part *enc_tkt_reply,
                           krb5_kdcpreauth_verify_respond_fn respond,
                           void *arg,
                           const struct sss_passkey_message *message,
                           char **indicators,
                           struct sss_radiuskdc_config *config)
{
    struct sss_radiuskdc_verify *state;
    char *encoded_message = NULL;
    krb5_error_code ret;

    state = sss_radiuskdc_verify_init(kctx, rock, cb, enc_tkt_reply, respond,
                                      arg, indicators, config);
    if (state == NULL) {
        return ENOMEM;
    }

    encoded_message = sss_passkey_message_encode(message);
    if (encoded_message == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_radiuskdc_set_attr_as_string(state->client->attrs,
                                           "Proxy-State",
                                           encoded_message);
    if (ret != 0) {
        goto done;
    }

    ret = krad_client_send(state->client->client,
                           krad_code_name2num("Access-Request"),
                           state->client->attrs, config->server,
                           config->secret, config->timeout, config->retries,
                           sss_radiuskdc_verify_done, state);

done:
    free(encoded_message);

    if (ret != 0) {
        sss_radiuskdc_verify_free(state);
    }

    return ret;
}

static krb5_error_code
sss_passkeykdc_init(krb5_context kctx,
                    krb5_kdcpreauth_moddata *_moddata,
                    const char **_realmnames)
{
    return sss_radiuskdc_init(SSSD_PASSKEY_PLUGIN, kctx, _moddata, _realmnames);
}

static void
sss_passkeykdc_edata(krb5_context kctx,
                     krb5_kdc_req *request,
                     krb5_kdcpreauth_callbacks cb,
                     krb5_kdcpreauth_rock rock,
                     krb5_kdcpreauth_moddata moddata,
                     krb5_preauthtype pa_type,
                     krb5_kdcpreauth_edata_respond_fn respond,
                     void *arg)
{
    struct sss_passkeykdc_config *config = NULL;
    struct sss_radiuskdc_state *state;
    krb5_keyblock *armor_key;
    char *configstr = NULL;
    krb5_error_code ret;

    state = (struct sss_radiuskdc_state *)moddata;

    ret = sss_radiuskdc_enabled(SSSD_PASSKEY_CONFIG, kctx, cb, rock, &configstr);
    if (ret != 0) {
        goto done;
    }

    armor_key = cb->fast_armor(kctx, rock);
    if (armor_key == NULL) {
        ret = ENOENT;
        goto done;
    }

    ret = sss_passkeykdc_config_init(state, kctx, cb->client_name(kctx, rock),
                                     configstr, &config);
    if (ret != 0) {
        goto done;
    }

    ret = sss_passkeykdc_challenge_send(kctx, cb, rock, respond, arg,
                                        config->radius);

done:
    if (ret != 0) {
        respond(arg, ret, NULL);
    }

    cb->free_string(kctx, rock, configstr);
    sss_passkeykdc_config_free(config);
}

static void
sss_passkeykdc_verify(krb5_context kctx,
                      krb5_data *req_pkt,
                      krb5_kdc_req *request,
                      krb5_enc_tkt_part *enc_tkt_reply,
                      krb5_pa_data *pa,
                      krb5_kdcpreauth_callbacks cb,
                      krb5_kdcpreauth_rock rock,
                      krb5_kdcpreauth_moddata moddata,
                      krb5_kdcpreauth_verify_respond_fn respond,
                      void *arg)
{
    struct sss_radiuskdc_state *state;
    struct sss_passkeykdc_config *config = NULL;
    struct sss_passkey_message *message = NULL;
    struct sss_passkey_message *challenge = NULL;
    char *configstr = NULL;
    krb5_error_code ret;
    krb5_data cookie;

    state = (struct sss_radiuskdc_state *)moddata;

    ret = sss_radiuskdc_enabled(SSSD_PASSKEY_CONFIG, kctx, cb, rock, &configstr);
    if (ret != 0) {
        goto done;
    }

    ret = sss_passkeykdc_config_init(state, kctx, cb->client_name(kctx, rock),
                                     configstr, &config);
    if (ret != 0) {
        goto done;
    }

    ret = sss_radiuskdc_get_cookie(kctx, cb, rock, SSSD_PASSKEY_PADATA,
                                   &cookie);
    if (ret != 0) {
        goto done;
    }

    challenge = sss_passkey_message_decode(cookie.data);
    if (challenge == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (pa->pa_type != SSSD_PASSKEY_PADATA || pa->length == 0) {
        ret = KRB5_PREAUTH_BAD_TYPE;
        goto done;
    }

    message = sss_passkey_message_decode_padata(pa);
    if (message == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (message->phase != SSS_PASSKEY_PHASE_REPLY
        || strcmp(message->state, challenge->state) != 0
        || strcmp(message->data.reply->cryptographic_challenge,
                  challenge->data.challenge->cryptographic_challenge) != 0) {
        ret = EINVAL;
        goto done;
    }

    ret = sss_passkeykdc_verify_send(kctx, rock, cb, enc_tkt_reply, respond,
            arg, message, config->passkey->indicators, config->radius);
    if (ret != 0) {
        goto done;
    }

    ret = 0;

done:
    if (ret != 0) {
        respond(arg, ret, NULL, NULL, NULL);
    }

    cb->free_string(kctx, rock, configstr);
    sss_passkeykdc_config_free(config);
    sss_passkey_message_free(message);
    sss_passkey_message_free(challenge);
}

krb5_error_code
kdcpreauth_passkey_initvt(krb5_context kctx,
                          int maj_ver,
                          int min_ver,
                          krb5_plugin_vtable vtable)
{
    static krb5_preauthtype pa_type_list[] = { SSSD_PASSKEY_PADATA, 0 };
    krb5_kdcpreauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }

    vt = (krb5_kdcpreauth_vtable)vtable;
    vt->name = discard_const(SSSD_PASSKEY_PLUGIN);
    vt->pa_type_list = pa_type_list;
    vt->init = sss_passkeykdc_init;
    vt->fini = sss_radiuskdc_fini;
    vt->flags = sss_radiuskdc_flags;
    vt->edata = sss_passkeykdc_edata;
    vt->verify = sss_passkeykdc_verify;
    vt->return_padata = sss_radiuskdc_return_padata;

    com_err(SSSD_PASSKEY_PLUGIN, 0, "SSSD passkey plugin loaded");

    return 0;
}
