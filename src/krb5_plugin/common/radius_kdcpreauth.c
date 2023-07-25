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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <krad.h>
#include <krb5/kdcpreauth_plugin.h>

#include "krb5_plugin/common/radius_kdcpreauth.h"
#include "krb5_plugin/common/utils.h"
#include "util/util.h"

krb5_error_code
sss_radiuskdc_init(const char *plugin_name,
                   krb5_context kctx,
                   krb5_kdcpreauth_moddata *_moddata,
                   const char **_realmnames)
{
    struct sss_radiuskdc_state *state;

    state = malloc(sizeof(struct sss_radiuskdc_state));
    if (state == NULL) {
        return ENOMEM;
    }

    state->plugin_name = plugin_name;

    /* IPA is the only consumer so far so it is fine to hardcode the values. */
    state->server = KRB5_KDC_RUNDIR "/DEFAULT.socket";
    state->secret = "";
    state->timeout = 5 * 1000;
    state->retries = 3;

    *_moddata = (krb5_kdcpreauth_moddata)state;

    return 0;
}

void
sss_radiuskdc_fini(krb5_context kctx,
                   krb5_kdcpreauth_moddata moddata)
{
    struct sss_radiuskdc_state *state;

    state = (struct sss_radiuskdc_state *)moddata;

    if (state == NULL) {
        return;
    }

    free(state);
}

int
sss_radiuskdc_flags(krb5_context kctx,
                    krb5_preauthtype pa_type)
{
    return PA_REPLACES_KEY;
}

krb5_error_code
sss_radiuskdc_return_padata(krb5_context kctx,
                            krb5_pa_data *padata,
                            krb5_data *req_pkt,
                            krb5_kdc_req *request,
                            krb5_kdc_rep *reply,
                            krb5_keyblock *encrypting_key,
                            krb5_pa_data **send_pa_out,
                            krb5_kdcpreauth_callbacks cb,
                            krb5_kdcpreauth_rock rock,
                            krb5_kdcpreauth_moddata moddata,
                            krb5_kdcpreauth_modreq modreq)
{
    struct sss_radiuskdc_state *state;
    krb5_keyblock *armor_key;
    bool *result;

    state = (struct sss_radiuskdc_state *)moddata;
    result = (bool *)modreq;

    /* This should not happen. */
    if (state == NULL) {
        return EINVAL;
    }

    /* Verification was not successful. Do not replace the key. */
    if (result == NULL || *result == false) {
        return 0;
    }

    /* Get the armor key. */
    armor_key = cb->fast_armor(kctx, rock);
    if (armor_key == NULL) {
        com_err(state->plugin_name, ENOENT,
                "No armor key found when returning padata");
        return ENOENT;
    }

    /* Replace the reply key with the FAST armor key. */
    krb5_free_keyblock_contents(kctx, encrypting_key);
    return krb5_copy_keyblock_contents(kctx, armor_key, encrypting_key);
}

krb5_error_code
sss_radiuskdc_enabled(const char *config_name,
                      krb5_context kctx,
                      krb5_kdcpreauth_callbacks cb,
                      krb5_kdcpreauth_rock rock,
                      char **_config)
{
    krb5_error_code ret;
    char *config;

    ret = cb->get_string(kctx, rock, config_name, &config);
    if (ret != 0) {
        return ret;
    }

    /* Disabled. */
    if (config == NULL) {
        return ENOENT;
    }

    /* Enabled. Return the config string. */
    *_config = config;

    return 0;
}

void
sss_radiuskdc_config_free(struct sss_radiuskdc_config *config)
{
    if (config == NULL) {
        return;
    }

    free(config->username);
    free(config->server);
    free(config->secret);
    free(config);
}

krb5_error_code
sss_radiuskdc_config_init(struct sss_radiuskdc_state *state,
                          krb5_context kctx,
                          krb5_const_principal princ,
                          const char *configstr,
                          struct sss_radiuskdc_config **_config)
{
    struct sss_radiuskdc_config *config;
    krb5_error_code ret;
    char *username;

    if (state == NULL) {
        return EINVAL;
    }

    config = malloc(sizeof(struct sss_radiuskdc_config));
    if (config == NULL) {
        ret = ENOMEM;
        goto done;
    }
    memset(config, 0, sizeof(struct sss_radiuskdc_config));

    config->server = strdup(state->server);
    config->secret = strdup(state->secret);
    config->retries = state->retries;
    config->timeout = state->timeout;

    if (config->server == NULL || config->secret == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = krb5_unparse_name_flags(kctx, princ, 0, &username);
    if (ret != 0) {
        goto done;
    }

    config->username = strdup(username);
    krb5_free_unparsed_name(kctx, username);
    if (config->username == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_config = config;
    ret = 0;

done:
    if (ret != 0) {
        sss_radiuskdc_config_free(config);
    }

    return ret;
}

krb5_error_code
sss_radiuskdc_set_cookie(krb5_context context,
                         krb5_kdcpreauth_callbacks cb,
                         krb5_kdcpreauth_rock rock,
                         krb5_preauthtype pa_type,
                         const krb5_data *state)
{
    krb5_data cookie;
    unsigned int len;
    uint8_t *blob;
    size_t pctr;

    len = sizeof(uint16_t) + state->length;
    blob = malloc(len);
    if (blob == NULL) {
        return ENOMEM;
    }

    pctr = 0;
    SAFEALIGN_SET_UINT16(&blob[pctr], 1, &pctr);
    SAFEALIGN_SET_STRING(&blob[pctr], state->data, state->length, &pctr);

    cookie.magic = 0;
    cookie.data = (char *)blob;
    cookie.length = len;

    return cb->set_cookie(context, rock, pa_type, &cookie);
}

krb5_error_code
sss_radiuskdc_get_cookie(krb5_context context,
                         krb5_kdcpreauth_callbacks cb,
                         krb5_kdcpreauth_rock rock,
                         krb5_preauthtype pa_type,
                         krb5_data *_state)
{
    uint16_t version;
    krb5_data cookie;
    krb5_data state;
    size_t pctr;

    if (!cb->get_cookie(context, rock, pa_type, &cookie)) {
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    if (cookie.length < sizeof(uint16_t)) {
        return EINVAL;
    }

    pctr = 0;
    SAFEALIGN_COPY_UINT16(&version, cookie.data, &pctr);
    state.magic = 0;
    state.data = &cookie.data[pctr];
    state.length = cookie.length - sizeof(uint16_t);

    *_state = state;

    return 0;
}


/* Some attributes have limited length. In order to accept longer values,
 * we will concatenate all attribute values to single krb5_data. */
krb5_error_code
sss_radiuskdc_get_complete_attr(const krad_packet *rres,
                                const char *attr_name,
                                krb5_data *_data)
{
    krad_attr attr = krad_attr_name2num(attr_name);
    const krb5_data *rmsg;
    krb5_data data = {0};
    unsigned int memindex;
    unsigned int i;

    i = 0;
    do {
        rmsg = krad_packet_get_attr(rres, attr, i);
        if (rmsg != NULL) {
            data.length += rmsg->length;
        }
        i++;
    } while (rmsg != NULL);

    if (data.length == 0) {
        return ENOENT;
    }

    data.data = malloc(data.length);
    if (data.data == NULL) {
        return ENOMEM;
    }

    i = 0;
    memindex = 0;
    do {
        rmsg = krad_packet_get_attr(rres, attr, i);
        if (rmsg != NULL) {
            memcpy(&data.data[memindex], rmsg->data, rmsg->length);
            memindex += rmsg->length;
        }
        i++;
    } while (rmsg != NULL);

    if (memindex != data.length) {
        free(data.data);
        return ERANGE;
    }

    *_data = data;

    return 0;
}

/* From krad internals, RFC 2865 */
#ifndef UCHAR_MAX
#define UCHAR_MAX 255
#endif
#define MAX_ATTRSIZE (UCHAR_MAX - 2)

krb5_error_code
sss_radiuskdc_put_complete_attr(krad_attrset *attrset,
                                krad_attr attr,
                                const krb5_data *datap)
{
    krb5_data state = {0};
    char *p = datap->data;
    unsigned int len = datap->length;
    krb5_error_code ret = 0;

    do {
        /* - 5 to make sure we fit into minimal value length */
        state.data = p;
        state.length = MIN(MAX_ATTRSIZE - 5, len);
        p += state.length;

        ret = krad_attrset_add(attrset, attr, &(state));
        if (ret != 0) {
            break;
        }
        len -= state.length;
    } while (len > 0);

    return ret;
}

char *
sss_radiuskdc_get_attr_as_string(const krad_packet *packet, const char *attr)
{
    krb5_data data = {0};
    krb5_error_code ret;
    char *str;

    ret = sss_radiuskdc_get_complete_attr(packet, attr, &data);
    if (ret != 0) {
        return NULL;
    }

    str = strndup(data.data, data.length);
    free(data.data);

    return str;
}

krb5_error_code
sss_radiuskdc_set_attr_as_string(krad_attrset *attrset,
                                 const char *attr,
                                 const char *value)
{
    krb5_data data = {0};
    krb5_error_code ret;

    data.data = discard_const(value);
    data.length = strlen(value) + 1;

    ret = sss_radiuskdc_put_complete_attr(attrset,
                                          krad_attr_name2num(attr),
                                          &data);

    return ret;
}

void
sss_radiuskdc_client_free(struct sss_radiuskdc_client *client)
{
    if (client == NULL) {
        return;
    }

    krad_client_free(client->client);
    krad_attrset_free(client->attrs);
    free(client);
}

struct sss_radiuskdc_client *
sss_radiuskdc_client_init(krb5_context kctx,
                          verto_ctx *vctx,
                          struct sss_radiuskdc_config *config)
{
    struct sss_radiuskdc_client *client;
    char hostname[HOST_NAME_MAX + 1];
    krb5_data data = {0};
    krb5_error_code ret;

    client = malloc(sizeof(struct sss_radiuskdc_client));
    if (client == NULL) {
        return NULL;
    }
    memset(client, 0, sizeof(struct sss_radiuskdc_client));

    ret = krad_client_new(kctx, vctx, &client->client);
    if (ret != 0) {
        goto fail;
    }

    ret = krad_attrset_new(kctx, &client->attrs);
    if (ret != 0) {
        goto fail;
    }

    ret = gethostname(hostname, sizeof(hostname) / sizeof(char));
    if (ret != 0) {
        goto fail;
    }

    data.data = hostname;
    data.length = strlen(hostname);
    ret = krad_attrset_add(client->attrs, krad_attr_name2num("NAS-Identifier"),
                           &data);
    if (ret != 0) {
        goto fail;
    }

    ret = krad_attrset_add_number(client->attrs, krad_attr_name2num("Service-Type"),
                                  KRAD_SERVICE_TYPE_AUTHENTICATE_ONLY);
    if (ret != 0) {
        goto fail;
    }

    data.data = config->username;
    data.length = strlen(config->username);
    ret = krad_attrset_add(client->attrs, krad_attr_name2num("User-Name"),
                           &data);
    if (ret != 0) {
        goto fail;
    }

    return client;

fail:
    sss_radiuskdc_client_free(client);
    return NULL;
}

void
sss_radiuskdc_challenge_free(struct sss_radiuskdc_challenge *state)
{
    if (state == NULL) {
        return;
    }

    sss_radiuskdc_client_free(state->client);
    free(state);
}

struct sss_radiuskdc_challenge *
sss_radiuskdc_challenge_init(krb5_context kctx,
                             krb5_kdcpreauth_callbacks cb,
                             krb5_kdcpreauth_rock rock,
                             krb5_kdcpreauth_edata_respond_fn respond,
                             void *arg,
                             struct sss_radiuskdc_config *config)
{
    struct sss_radiuskdc_challenge *state;

    state = malloc(sizeof(struct sss_radiuskdc_challenge));
    if (state == NULL) {
        return NULL;
    }
    memset(state, 0, sizeof(struct sss_radiuskdc_challenge));

    state->kctx = kctx;
    state->cb = cb;
    state->rock = rock;
    state->respond = respond;
    state->arg = arg;

    state->client = sss_radiuskdc_client_init(kctx,
                                              cb->event_context(kctx, rock),
                                              config);
    if (state->client == NULL) {
        sss_radiuskdc_challenge_free(state);
        return NULL;
    }

    return state;
}

void
sss_radiuskdc_verify_free(struct sss_radiuskdc_verify *state)
{
    if (state == NULL) {
        return;
    }

    sss_string_array_free(state->indicators);
    sss_radiuskdc_client_free(state->client);
    free(state);
}

struct sss_radiuskdc_verify *
sss_radiuskdc_verify_init(krb5_context kctx,
                          krb5_kdcpreauth_rock rock,
                          krb5_kdcpreauth_callbacks cb,
                          krb5_enc_tkt_part *enc_tkt_reply,
                          krb5_kdcpreauth_verify_respond_fn respond,
                          void *arg,
                          char **indicators,
                          struct sss_radiuskdc_config *config)
{
    struct sss_radiuskdc_verify *state;

    state = malloc(sizeof(struct sss_radiuskdc_verify));
    if (state == NULL) {
        return NULL;
    }
    memset(state, 0, sizeof(struct sss_radiuskdc_verify));

    state->kctx = kctx;
    state->rock = rock;
    state->cb = cb;
    state->enc_tkt_reply = enc_tkt_reply;
    state->respond = respond;
    state->arg = arg;

    state->indicators = sss_string_array_copy(indicators);
    if (state->indicators == NULL) {
        sss_radiuskdc_verify_free(state);
        return NULL;
    }

    state->client = sss_radiuskdc_client_init(kctx,
                                              cb->event_context(kctx, rock),
                                              config);
    if (state->client == NULL) {
        sss_radiuskdc_verify_free(state);
        return NULL;
    }

    return state;
}

void
sss_radiuskdc_verify_done(krb5_error_code rret,
                          const krad_packet *rreq,
                          const krad_packet *rres,
                          void *data)
{
    static bool verify_success = true;
    static bool verify_failure = false;
    struct sss_radiuskdc_verify *state;
    krb5_kdcpreauth_modreq modreq;
    krb5_error_code ret;
    int i;

    state = (struct sss_radiuskdc_verify *)data;
    modreq = (krb5_kdcpreauth_modreq)&verify_failure;

    if (rret != 0) {
        ret = rret;
        goto done;
    }

    if (krad_packet_get_code(rres) != krad_code_name2num("Access-Accept")) {
        ret = KRB5_PREAUTH_FAILED;
        goto done;
    }

    state->enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;

    for (i = 0; state->indicators[i] != NULL; i++) {
        ret = state->cb->add_auth_indicator(state->kctx, state->rock,
                                            state->indicators[i]);
        if (ret != 0) {
            goto done;
        }
    }

    modreq = (krb5_kdcpreauth_modreq)&verify_success;
    ret = 0;

done:
    state->respond(state->arg, ret, modreq, NULL, NULL);
    sss_radiuskdc_verify_free(state);
}
