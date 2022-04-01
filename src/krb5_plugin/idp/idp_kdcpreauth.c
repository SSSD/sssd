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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <krad.h>
#include <krb5/kdcpreauth_plugin.h>

#include "shared/safealign.h"
#include "idp.h"
#include "util/util.h"

struct sss_idpkdc_state {
    const char *server;
    const char *secret;
    size_t retries;
    int timeout;
};

struct sss_idpkdc_config {
    char *username;
    char *server;
    char *secret;
    size_t retries;
    int timeout;

    struct sss_idp_config *idpcfg;
};

static void
sss_idpkdc_config_free(struct sss_idpkdc_config *config)
{
    if (config == NULL) {
        return;
    }

    sss_idp_config_free(config->idpcfg);
    free(config->username);
    free(config->server);
    free(config->secret);
    free(config);
}

static krb5_error_code
sss_idpkdc_config_init(struct sss_idpkdc_state *state,
                       krb5_context kctx,
                       krb5_const_principal princ,
                       const char *configstr,
                       struct sss_idpkdc_config **_config)
{
    struct sss_idpkdc_config *config;
    krb5_error_code ret;
    char *username;

    if (state == NULL) {
        return EINVAL;
    }

    config = malloc(sizeof(struct sss_idpkdc_config));
    if (config == NULL) {
        ret = ENOMEM;
        goto done;
    }
    memset(config, 0, sizeof(struct sss_idpkdc_config));

    ret = sss_idp_config_init(configstr, &config->idpcfg);
    if (ret != 0) {
        goto done;
    }

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
        sss_idpkdc_config_free(config);
    }

    return ret;
}

static krb5_error_code
sss_idpkdc_set_cookie(krb5_context context,
                      krb5_kdcpreauth_callbacks cb,
                      krb5_kdcpreauth_rock rock,
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

    return cb->set_cookie(context, rock, SSSD_IDP_OAUTH2_PADATA, &cookie);
}

static krb5_error_code
sss_idpkdc_get_cookie(krb5_context context,
                      krb5_kdcpreauth_callbacks cb,
                      krb5_kdcpreauth_rock rock,
                      krb5_data *_state)
{
    uint16_t version;
    krb5_data cookie;
    krb5_data state;
    size_t pctr;

    if (!cb->get_cookie(context, rock, SSSD_IDP_OAUTH2_PADATA, &cookie)) {
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
static krb5_error_code
sss_idpkdc_get_complete_attr(const krad_packet *rres,
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

static krb5_error_code
sss_idpkdc_put_complete_attr(krad_attrset *attrset,
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

struct sss_idpkdc_radius {
    krad_client *client;
    krad_attrset *attrs;
};

static void
sss_idpkdc_radius_free(struct sss_idpkdc_radius *radius)
{
    if (radius == NULL) {
        return;
    }

    krad_client_free(radius->client);
    krad_attrset_free(radius->attrs);
    free(radius);
}

static struct sss_idpkdc_radius *
sss_idpkdc_radius_init(krb5_context kctx,
                       verto_ctx *vctx,
                       struct sss_idpkdc_config *config)
{
    struct sss_idpkdc_radius *radius;
    char hostname[HOST_NAME_MAX + 1];
    krb5_data data = {0};
    krb5_error_code ret;

    radius = malloc(sizeof(struct sss_idpkdc_radius));
    if (radius == NULL) {
        return NULL;
    }
    memset(radius, 0, sizeof(struct sss_idpkdc_radius));

    ret = krad_client_new(kctx, vctx, &radius->client);
    if (ret != 0) {
        goto fail;
    }

    ret = krad_attrset_new(kctx, &radius->attrs);
    if (ret != 0) {
        goto fail;
    }

    ret = gethostname(hostname, sizeof(hostname) / sizeof(char));
    if (ret != 0) {
        goto fail;
    }

    data.data = hostname;
    data.length = strlen(hostname);
    ret = krad_attrset_add(radius->attrs, krad_attr_name2num("NAS-Identifier"),
                           &data);
    if (ret != 0) {
        goto fail;
    }

    ret = krad_attrset_add_number(radius->attrs, krad_attr_name2num("Service-Type"),
                                  KRAD_SERVICE_TYPE_AUTHENTICATE_ONLY);
    if (ret != 0) {
        goto fail;
    }

    data.data = config->username;
    data.length = strlen(config->username);
    ret = krad_attrset_add(radius->attrs, krad_attr_name2num("User-Name"),
                           &data);
    if (ret != 0) {
        goto fail;
    }

    return radius;

fail:
    sss_idpkdc_radius_free(radius);
    return NULL;
}

struct sss_idpkdc_challenge {
    struct sss_idpkdc_radius *radius;

    krb5_context kctx;
    krb5_kdcpreauth_callbacks cb;
    krb5_kdcpreauth_rock rock;
    krb5_kdcpreauth_edata_respond_fn respond;
    void *arg;
};

static void
sss_idpkdc_challenge_free(struct sss_idpkdc_challenge *challenge)
{
    if (challenge == NULL) {
        return;
    }

    sss_idpkdc_radius_free(challenge->radius);
    free(challenge);
}

static void
sss_idpkdc_challenge_done(krb5_error_code rret,
                          const krad_packet *rreq,
                          const krad_packet *rres,
                          void *data)
{
    struct sss_idpkdc_challenge *state;
    struct sss_idp_oauth2 *idp_oauth2 = NULL;
    krb5_pa_data *padata = NULL;
    krb5_data rstate = {0};
    krb5_data rmsg = {0};
    krb5_error_code ret;

    state = (struct sss_idpkdc_challenge *)data;

    if (rret != 0) {
        ret = rret;
        goto done;
    }

    if (krad_packet_get_code(rres) != krad_code_name2num("Access-Challenge")) {
        ret = ENOENT;
        goto done;
    }

    ret = sss_idpkdc_get_complete_attr(rres, "Proxy-State", &rstate);
    if (ret != 0) {
        goto done;
    }

    ret = sss_idpkdc_get_complete_attr(rres, "Reply-Message", &rmsg);
    if (ret != 0) {
        goto done;
    }

    /* Remember the RADIUS state so it can be set in the Access-Request message
     * sent in sss_idpkdc_verify(), thus allowing the RADIUS server to
     * associate the message with its internal state. */
    ret = sss_idpkdc_set_cookie(state->kctx, state->cb, state->rock, &rstate);
    if (ret != 0) {
        goto done;
    }

    idp_oauth2 = sss_idp_oauth2_decode_reply_message(&rmsg);
    if (idp_oauth2 == NULL) {
        ret = ENOMEM;
        goto done;
    }

    padata = sss_idp_oauth2_encode_padata(idp_oauth2);
    if (padata == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = 0;

done:
    state->respond(state->arg, ret, padata);
    sss_idpkdc_challenge_free(state);
    sss_idp_oauth2_free(idp_oauth2);
    free(rstate.data);
    free(rmsg.data);

    /* padata should not be freed */

    return;
}

/* Send a password-less Access-Request and expect Access-Challenge response. */
static krb5_error_code
sss_idpkdc_challenge_send(krb5_context kctx,
                          verto_ctx *vctx,
                          krb5_kdcpreauth_callbacks cb,
                          krb5_kdcpreauth_rock rock,
                          krb5_kdcpreauth_edata_respond_fn respond,
                          void *arg,
                          struct sss_idpkdc_config *config)
{
    struct sss_idpkdc_challenge *state;
    krb5_error_code ret;

    state = malloc(sizeof(struct sss_idpkdc_challenge));
    if (state == NULL) {
        ret = ENOMEM;
        goto done;
    }
    memset(state, 0, sizeof(struct sss_idpkdc_challenge));

    state->kctx = kctx;
    state->cb = cb;
    state->rock = rock;
    state->respond = respond;
    state->arg = arg;

    state->radius = sss_idpkdc_radius_init(kctx, vctx, config);
    if (state->radius == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = krad_client_send(state->radius->client,
                           krad_code_name2num("Access-Request"),
                           state->radius->attrs, config->server,
                           config->secret, config->timeout, config->retries,
                           sss_idpkdc_challenge_done, state);

done:
    if (ret != 0) {
        sss_idpkdc_challenge_free(state);
    }

    return ret;
}

struct sss_idpkdc_verify {
    struct sss_idpkdc_radius *radius;
    struct sss_idpkdc_config *config;

    krb5_context kctx;
    krb5_kdcpreauth_rock rock;
    krb5_kdcpreauth_callbacks cb;
    krb5_enc_tkt_part *enc_tkt_reply;
    krb5_kdcpreauth_verify_respond_fn respond;
    void *arg;
};

static void
sss_idpkdc_verify_free(struct sss_idpkdc_verify *verify)
{
    if (verify == NULL) {
        return;
    }

    sss_idpkdc_radius_free(verify->radius);
    sss_idpkdc_config_free(verify->config);
    free(verify);
}

static void
sss_idpkdc_verify_done(krb5_error_code rret,
                       const krad_packet *rreq,
                       const krad_packet *rres,
                       void *data)
{
    static bool verify_success = true;
    static bool verify_failure = false;
    struct sss_idpkdc_verify *state;
    krb5_kdcpreauth_modreq modreq;
    krb5_error_code ret;
    int i;

    state = (struct sss_idpkdc_verify *)data;
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

    for (i = 0; state->config->idpcfg->indicators[i] != NULL; i++) {
        ret = state->cb->add_auth_indicator(state->kctx, state->rock,
                                            state->config->idpcfg->indicators[i]);
        if (ret != 0) {
            goto done;
        }
    }

    modreq = (krb5_kdcpreauth_modreq)&verify_success;
    ret = 0;

done:
    state->respond(state->arg, ret, modreq, NULL, NULL);
    sss_idpkdc_verify_free(state);
    return;
}

/* Send Access-Request with password and state set to indicate that the user has
 * finished authentication against idp provider. We expect Access-Accept. */
static krb5_error_code
sss_idpkdc_verify_send(krb5_context kctx,
                       verto_ctx *vctx,
                       krb5_kdcpreauth_rock rock,
                       krb5_kdcpreauth_callbacks cb,
                       krb5_enc_tkt_part *enc_tkt_reply,
                       krb5_kdcpreauth_verify_respond_fn respond,
                       void *arg,
                       const krb5_data *rstate,
                       struct sss_idpkdc_config *config)
{
    struct sss_idpkdc_verify *state;
    krb5_error_code ret;

    state = malloc(sizeof(struct sss_idpkdc_verify));
    if (state == NULL) {
        return ENOMEM;
    }
    memset(state, 0, sizeof(struct sss_idpkdc_verify));

    state->config = config;
    state->kctx = kctx;
    state->rock = rock;
    state->cb = cb;
    state->enc_tkt_reply = enc_tkt_reply;
    state->respond = respond;
    state->arg = arg;

    state->radius = sss_idpkdc_radius_init(kctx, vctx, config);
    if (state->radius == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_idpkdc_put_complete_attr(state->radius->attrs,
                                       krad_attr_name2num("Proxy-State"),
                                       rstate);
    if (ret != 0) {
        goto done;
    }

    ret = krad_client_send(state->radius->client,
                           krad_code_name2num("Access-Request"),
                           state->radius->attrs, config->server,
                           config->secret, config->timeout, config->retries,
                           sss_idpkdc_verify_done, state);

done:
    if (ret != 0) {
        /* It is the caller responsibility to free config in case of error. */
        state->config = NULL;
        sss_idpkdc_verify_free(state);
    }

    return ret;
}

static krb5_error_code
sss_idpkdc_enabled(krb5_context kctx,
                   krb5_kdcpreauth_callbacks cb,
                   krb5_kdcpreauth_rock rock,
                   char **_config)
{
    krb5_error_code ret;
    char *config;

    ret = cb->get_string(kctx, rock, SSSD_IDP_CONFIG, &config);
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

static krb5_error_code
sss_idpkdc_init(krb5_context kctx,
                krb5_kdcpreauth_moddata *_moddata,
                const char **_realmnames)
{
    struct sss_idpkdc_state *state;

    state = malloc(sizeof(struct sss_idpkdc_state));
    if (state == NULL) {
        return ENOMEM;
    }

    /* IPA is the only consumer so far so it is fine to hardcode the values. */
    state->server = KRB5_KDC_RUNDIR "/DEFAULT.socket";
    state->secret = "";
    state->timeout = 5 * 1000;
    state->retries = 3;

    *_moddata = (krb5_kdcpreauth_moddata)state;

    return 0;
}

static void
sss_idpkdc_fini(krb5_context kctx,
                krb5_kdcpreauth_moddata moddata)
{
    struct sss_idpkdc_state *state;

    state = (struct sss_idpkdc_state *)moddata;

    if (state == NULL) {
        return;
    }

    free(state);
}

static int
sss_idpkdc_flags(krb5_context kctx,
                 krb5_preauthtype pa_type)
{
    return PA_REPLACES_KEY;
}

static void
sss_idpkdc_edata(krb5_context kctx,
                 krb5_kdc_req *request,
                 krb5_kdcpreauth_callbacks cb,
                 krb5_kdcpreauth_rock rock,
                 krb5_kdcpreauth_moddata moddata,
                 krb5_preauthtype pa_type,
                 krb5_kdcpreauth_edata_respond_fn respond,
                 void *arg)
{
    struct sss_idpkdc_config *config = NULL;
    struct sss_idpkdc_state *state;
    char *configstr = NULL;
    krb5_error_code ret;

    state = (struct sss_idpkdc_state *)moddata;

    ret = sss_idpkdc_enabled(kctx, cb, rock, &configstr);
    if (ret != 0) {
        goto done;
    }

    ret = sss_idpkdc_config_init(state, kctx, cb->client_name(kctx, rock),
                                 configstr, &config);
    if (ret != 0) {
        goto done;
    }

    ret = sss_idpkdc_challenge_send(kctx, cb->event_context(kctx, rock), cb,
                                    rock, respond, arg, config);

done:
    if (ret != 0) {
        respond(arg, ret, NULL);
    }

    cb->free_string(kctx, rock, configstr);
    sss_idpkdc_config_free(config);
}

static void
sss_idpkdc_verify(krb5_context kctx,
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
    struct sss_idpkdc_state *state;
    struct sss_idpkdc_config *config = NULL;
    char *configstr = NULL;
    krb5_error_code ret;
    krb5_data rstate;

    state = (struct sss_idpkdc_state *)moddata;

    ret = sss_idpkdc_enabled(kctx, cb, rock, &configstr);
    if (ret != 0) {
        goto done;
    }

    ret = sss_idpkdc_config_init(state, kctx, cb->client_name(kctx, rock),
                                 configstr, &config);
    if (ret != 0) {
        goto done;
    }

    ret = sss_idpkdc_get_cookie(kctx, cb, rock, &rstate);
    if (ret != 0) {
        goto done;
    }

    if (pa->pa_type != SSSD_IDP_OAUTH2_PADATA || pa->length != 0) {
        ret = KRB5_PREAUTH_BAD_TYPE;
        goto done;
    }

    /* config is freed by verify_done if ret == 0 */
    ret = sss_idpkdc_verify_send(kctx, cb->event_context(kctx, rock), rock,
                                 cb, enc_tkt_reply, respond, arg,
                                 &rstate, config);
    if (ret != 0) {
        goto done;
    }

    ret = 0;

done:
    if (ret != 0) {
        sss_idpkdc_config_free(config);
        respond(arg, ret, NULL, NULL, NULL);
    }

    cb->free_string(kctx, rock, configstr);
}

static krb5_error_code
sss_idpkdc_return_padata(krb5_context kctx,
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
    krb5_keyblock *armor_key;
    bool *result;

    result = (bool *)modreq;

    /* Verification was not successful. Do not replace the key. */
    if (result == NULL || *result == false) {
        return 0;
    }

    /* Unexpected padata. Return error. */
    if (padata->length != 0) {
        return EINVAL;
    }

    /* Get the armor key. */
    armor_key = cb->fast_armor(kctx, rock);
    if (armor_key == NULL) {
        com_err(SSSD_IDP_PLUGIN, ENOENT,
                "No armor key found when returning padata");
        return ENOENT;
    }

    /* Replace the reply key with the FAST armor key. */
    krb5_free_keyblock_contents(kctx, encrypting_key);
    return krb5_copy_keyblock_contents(kctx, armor_key, encrypting_key);
}

krb5_error_code
kdcpreauth_idp_initvt(krb5_context kctx,
                      int maj_ver,
                      int min_ver,
                      krb5_plugin_vtable vtable)
{
    static krb5_preauthtype pa_type_list[] = { SSSD_IDP_OAUTH2_PADATA, 0 };
    krb5_kdcpreauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }

    vt = (krb5_kdcpreauth_vtable)vtable;
    vt->name = discard_const(SSSD_IDP_PLUGIN);
    vt->pa_type_list = pa_type_list;
    vt->init = sss_idpkdc_init;
    vt->fini = sss_idpkdc_fini;
    vt->flags = sss_idpkdc_flags;
    vt->edata = sss_idpkdc_edata;
    vt->verify = sss_idpkdc_verify;
    vt->return_padata = sss_idpkdc_return_padata;

    com_err(SSSD_IDP_PLUGIN, 0, "Loaded");

    return 0;
}
