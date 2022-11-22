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

#ifndef _RADIUS_KDCPREAUTH_H_
#define _RADIUS_KDCPREAUTH_H_

#include <stdlib.h>
#include <krb5/preauth_plugin.h>

struct sss_radiuskdc_state {
    const char *plugin_name;
    const char *server;
    const char *secret;
    size_t retries;
    int timeout;
};

struct sss_radiuskdc_config {
    char *username;
    char *server;
    char *secret;
    size_t retries;
    int timeout;
};

struct sss_radiuskdc_client {
    krad_client *client;
    krad_attrset *attrs;
};

struct sss_radiuskdc_challenge {
    struct sss_radiuskdc_client *client;

    krb5_context kctx;
    krb5_kdcpreauth_callbacks cb;
    krb5_kdcpreauth_rock rock;
    krb5_kdcpreauth_edata_respond_fn respond;
    void *arg;
};

struct sss_radiuskdc_verify {
    struct sss_radiuskdc_client *client;
    char **indicators;

    krb5_context kctx;
    krb5_kdcpreauth_rock rock;
    krb5_kdcpreauth_callbacks cb;
    krb5_enc_tkt_part *enc_tkt_reply;
    krb5_kdcpreauth_verify_respond_fn respond;
    void *arg;
};

krb5_error_code
sss_radiuskdc_init(const char *plugin_name,
                   krb5_context kctx,
                   krb5_kdcpreauth_moddata *_moddata,
                   const char **_realmnames);

void
sss_radiuskdc_fini(krb5_context kctx,
                   krb5_kdcpreauth_moddata moddata);

int
sss_radiuskdc_flags(krb5_context kctx,
                    krb5_preauthtype pa_type);

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
                            krb5_kdcpreauth_modreq modreq);

krb5_error_code
sss_radiuskdc_enabled(const char *config_name,
                      krb5_context kctx,
                      krb5_kdcpreauth_callbacks cb,
                      krb5_kdcpreauth_rock rock,
                      char **_config);

void
sss_radiuskdc_config_free(struct sss_radiuskdc_config *config);

krb5_error_code
sss_radiuskdc_config_init(struct sss_radiuskdc_state *state,
                          krb5_context kctx,
                          krb5_const_principal princ,
                          const char *configstr,
                          struct sss_radiuskdc_config **_config);

krb5_error_code
sss_radiuskdc_set_cookie(krb5_context context,
                         krb5_kdcpreauth_callbacks cb,
                         krb5_kdcpreauth_rock rock,
                         krb5_preauthtype pa_type,
                         const krb5_data *state);

krb5_error_code
sss_radiuskdc_get_cookie(krb5_context context,
                         krb5_kdcpreauth_callbacks cb,
                         krb5_kdcpreauth_rock rock,
                         krb5_preauthtype pa_type,
                         krb5_data *_state);

krb5_error_code
sss_radiuskdc_get_complete_attr(const krad_packet *rres,
                                const char *attr_name,
                                krb5_data *_data);

krb5_error_code
sss_radiuskdc_put_complete_attr(krad_attrset *attrset,
                                krad_attr attr,
                                const krb5_data *datap);

char *
sss_radiuskdc_get_attr_as_string(const krad_packet *packet, const char *attr);


krb5_error_code
sss_radiuskdc_set_attr_as_string(krad_attrset *attrset,
                                 const char *attr,
                                 const char *value);

void
sss_radiuskdc_client_free(struct sss_radiuskdc_client *client);

struct sss_radiuskdc_client *
sss_radiuskdc_client_init(krb5_context kctx,
                          verto_ctx *vctx,
                          struct sss_radiuskdc_config *config);

void
sss_radiuskdc_challenge_free(struct sss_radiuskdc_challenge *state);

struct sss_radiuskdc_challenge *
sss_radiuskdc_challenge_init(krb5_context kctx,
                             krb5_kdcpreauth_callbacks cb,
                             krb5_kdcpreauth_rock rock,
                             krb5_kdcpreauth_edata_respond_fn respond,
                             void *arg,
                             struct sss_radiuskdc_config *config);

void
sss_radiuskdc_verify_free(struct sss_radiuskdc_verify *state);

struct sss_radiuskdc_verify *
sss_radiuskdc_verify_init(krb5_context kctx,
                          krb5_kdcpreauth_rock rock,
                          krb5_kdcpreauth_callbacks cb,
                          krb5_enc_tkt_part *enc_tkt_reply,
                          krb5_kdcpreauth_verify_respond_fn respond,
                          void *arg,
                          char **indicators,
                          struct sss_radiuskdc_config *config);

void
sss_radiuskdc_verify_done(krb5_error_code rret,
                          const krad_packet *rreq,
                          const krad_packet *rres,
                          void *data);

#endif /* _RADIUS_KDCPREAUTH_H_ */
