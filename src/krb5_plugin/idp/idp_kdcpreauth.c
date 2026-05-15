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
#include "krb5_plugin/common/radius_kdcpreauth.h"
#include "krb5_plugin/common/utils.h"
#include "idp.h"
#include "util/util.h"

struct sss_idpkdc_config {
    struct sss_radiuskdc_config *radius;
    struct sss_idp_config *idpcfg;
};

static void
sss_idpkdc_config_free(struct sss_idpkdc_config *config)
{
    if (config == NULL) {
        return;
    }

    sss_radiuskdc_config_free(config->radius);
    sss_idp_config_free(config->idpcfg);
    free(config);
}

static krb5_error_code
sss_idpkdc_config_init(struct sss_radiuskdc_state *state,
                       krb5_context kctx,
                       krb5_const_principal princ,
                       const char *configstr,
                       struct sss_idpkdc_config **_config)
{
    struct sss_idpkdc_config *config;
    krb5_error_code ret;

    if (state == NULL) {
        return EINVAL;
    }

    config = malloc(sizeof(struct sss_idpkdc_config));
    if (config == NULL) {
        ret = ENOMEM;
        goto done;
    }
    memset(config, 0, sizeof(struct sss_idpkdc_config));

    ret = sss_radiuskdc_config_init(state, kctx, princ, configstr, &config->radius);
    if (ret != 0) {
        goto done;
    }

    ret = sss_idp_config_init(configstr, &config->idpcfg);
    if (ret != 0) {
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

static void
sss_idpkdc_challenge_done(krb5_error_code rret,
                          const krad_packet *rreq,
                          const krad_packet *rres,
                          void *data)
{
    struct sss_radiuskdc_challenge *state;
    struct sss_idp_oauth2 *idp_oauth2 = NULL;
    krb5_pa_data *padata = NULL;
    krb5_data rstate = {0};
    char *rmsg = NULL;
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

    ret = sss_radiuskdc_get_complete_attr(rres, "Proxy-State", &rstate);
    if (ret != 0) {
        goto done;
    }

    rmsg = sss_radiuskdc_get_attr_as_string(rres, "Reply-Message");
    if (rmsg == NULL) {
        ret = EINVAL;
        goto done;
    }

    /* Remember the RADIUS state so it can be set in the Access-Request message
     * sent in sss_idpkdc_verify(), thus allowing the RADIUS server to
     * associate the message with its internal state. */
    ret = sss_radiuskdc_set_cookie(state->kctx, state->cb, state->rock,
                                   SSSD_IDP_OAUTH2_PADATA, &rstate);
    if (ret != 0) {
        goto done;
    }

    idp_oauth2 = sss_idp_oauth2_decode_challenge(rmsg);
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
    sss_radiuskdc_challenge_free(state);
    sss_idp_oauth2_free(idp_oauth2);
    free(rstate.data);
    free(rmsg);

    /* padata should not be freed */

    return;
}

/* Send a password-less Access-Request and expect Access-Challenge response. */
static krb5_error_code
sss_idpkdc_challenge_send(krb5_context kctx,
                          krb5_kdcpreauth_callbacks cb,
                          krb5_kdcpreauth_rock rock,
                          krb5_kdcpreauth_edata_respond_fn respond,
                          void *arg,
                          struct sss_radiuskdc_config *config)
{
    struct sss_radiuskdc_challenge *state;
    krb5_error_code ret;

    state = sss_radiuskdc_challenge_init(kctx, cb, rock, respond, arg, config);
    if (state == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = krad_client_send(state->client->client,
                           krad_code_name2num("Access-Request"),
                           state->client->attrs, config->server,
                           config->secret, config->timeout, config->retries,
                           sss_idpkdc_challenge_done, state);

done:
    if (ret != 0) {
        sss_radiuskdc_challenge_free(state);
    }

    return ret;
}

/* Send Access-Request with password and state set to indicate that the user has
 * finished authentication against idp provider. We expect Access-Accept. */
static krb5_error_code
sss_idpkdc_verify_send(krb5_context kctx,
                       krb5_kdcpreauth_rock rock,
                       krb5_kdcpreauth_callbacks cb,
                       krb5_enc_tkt_part *enc_tkt_reply,
                       krb5_kdcpreauth_verify_respond_fn respond,
                       void *arg,
                       const krb5_data *rstate,
                       char **indicators,
                       struct sss_radiuskdc_config *config)
{
    struct sss_radiuskdc_verify *state;
    krb5_error_code ret;

    state = sss_radiuskdc_verify_init(kctx, rock, cb, enc_tkt_reply, respond,
                                      arg, indicators, config);
    if (state == NULL) {
        return ENOMEM;
    }

    ret = sss_radiuskdc_put_complete_attr(state->client->attrs,
                                          krad_attr_name2num("Proxy-State"),
                                          rstate);
    if (ret != 0) {
        goto done;
    }

    ret = krad_client_send(state->client->client,
                           krad_code_name2num("Access-Request"),
                           state->client->attrs, config->server,
                           config->secret, config->timeout, config->retries,
                           sss_radiuskdc_verify_done, state);

done:
    if (ret != 0) {
        sss_radiuskdc_verify_free(state);
    }

    return ret;
}

static krb5_error_code
sss_idpkdc_init(krb5_context kctx,
                krb5_kdcpreauth_moddata *_moddata,
                const char **_realmnames)
{
    return sss_radiuskdc_init(SSSD_IDP_PLUGIN, kctx, _moddata, _realmnames);
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
    struct sss_radiuskdc_state *state;
    krb5_keyblock *armor_key;
    char *configstr = NULL;
    krb5_error_code ret;

    state = (struct sss_radiuskdc_state *)moddata;

    ret = sss_radiuskdc_enabled(SSSD_IDP_CONFIG, kctx, cb, rock, &configstr);
    if (ret != 0) {
        goto done;
    }

    armor_key = cb->fast_armor(kctx, rock);
    if (armor_key == NULL) {
        ret = ENOENT;
        goto done;
    }

    ret = sss_idpkdc_config_init(state, kctx, cb->client_name(kctx, rock),
                                 configstr, &config);
    if (ret != 0) {
        goto done;
    }

    ret = sss_idpkdc_challenge_send(kctx, cb, rock, respond, arg,
                                    config->radius);

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
    struct sss_radiuskdc_state *state;
    struct sss_idpkdc_config *config = NULL;
    char *configstr = NULL;
    krb5_error_code ret;
    krb5_data rstate;

    state = (struct sss_radiuskdc_state *)moddata;

    ret = sss_radiuskdc_enabled(SSSD_IDP_CONFIG, kctx, cb, rock, &configstr);
    if (ret != 0) {
        goto done;
    }

    ret = sss_idpkdc_config_init(state, kctx, cb->client_name(kctx, rock),
                                 configstr, &config);
    if (ret != 0) {
        goto done;
    }

    ret = sss_radiuskdc_get_cookie(kctx, cb, rock, SSSD_IDP_OAUTH2_PADATA,
                                   &rstate);
    if (ret != 0) {
        goto done;
    }

    if (pa->pa_type != SSSD_IDP_OAUTH2_PADATA || pa->length != 0) {
        ret = KRB5_PREAUTH_BAD_TYPE;
        goto done;
    }

    /* config is freed by verify_done if ret == 0 */
    ret = sss_idpkdc_verify_send(kctx, rock, cb, enc_tkt_reply, respond, arg,
            &rstate, config->idpcfg->indicators, config->radius);
    if (ret != 0) {
        goto done;
    }

    ret = 0;

done:
    if (ret != 0) {
        respond(arg, ret, NULL, NULL, NULL);
    }

    cb->free_string(kctx, rock, configstr);
    sss_idpkdc_config_free(config);
}

krb5_error_code
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
    /* Unexpected padata. Return error. */
    if (padata->length != 0) {
        return EINVAL;
    }

    return sss_radiuskdc_return_padata(kctx, padata, req_pkt, request, reply,
                                       encrypting_key, send_pa_out, cb, rock,
                                       moddata, modreq);
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
    vt->fini = sss_radiuskdc_fini;
    vt->flags = sss_radiuskdc_flags;
    vt->edata = sss_idpkdc_edata;
    vt->verify = sss_idpkdc_verify;
    vt->return_padata = sss_idpkdc_return_padata;

    com_err(SSSD_IDP_PLUGIN, 0, "SSSD IdP plugin loaded");

    return 0;
}
