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

#ifndef _IDP_H_
#define _IDP_H_

#include <stdlib.h>
#include <krb5/preauth_plugin.h>

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#define SSSD_IDP_PLUGIN "idp"
#define SSSD_IDP_CONFIG "idp"
#define SSSD_IDP_OAUTH2_PADATA 152 // PA-REDHAT-IDP-OAUTH2
#define SSSD_IDP_OAUTH2_QUESTION "idp-oauth2"
#define SSSD_IDP_OAUTH2_PREFIX "oauth2 "
/* DARC: the second AS-REQ carries the confirmation code the user typed. */
#define SSSD_IDP_OAUTH2_CONFIRM_PREFIX "oauth2-confirm "
/* Longest confirmation code accepted from the user. */
#define SSSD_IDP_OAUTH2_CONFIRM_MAX 32
/* Only indicators with this prefix are taken from the RADIUS server. */
#define SSSD_IDP_INDICATOR_PREFIX "idp-"

struct sss_idp_config {
    char *type;
    char **indicators;
};

void
sss_idp_config_free(struct sss_idp_config *idpcfg);

krb5_error_code
sss_idp_config_init(const char *config,
                    struct sss_idp_config **_idpcfg);

struct sss_idp_oauth2 {
    char *verification_uri;
    char *verification_uri_complete;
    char *user_code;

    /* PA-152 payload version 2 (DARC, Device Authorization with Return
     * Confirmation). A version 1 payload leaves these zero/NULL. */
    int version;
    /* Where the user receives the confirmation code: "page" (the
     * verification page) or "authenticator" (the user's authenticator app,
     * no verification_uri/user_code). */
    char *delivery;
    /* Length and character set ("numeric", "alphanumeric") of the code the
     * user must type; length 0 when no confirmation is required. */
    int confirmation_length;
    char *confirmation_charset;
    int expires_in;
};

/* True when the user must type a confirmation code at the terminal. */
#define sss_idp_oauth2_needs_confirmation(data) \
    ((data) != NULL && (data)->version >= 2 && (data)->confirmation_length > 0)

void
sss_idp_oauth2_free(struct sss_idp_oauth2 *data);

krb5_pa_data *
sss_idp_oauth2_encode_padata(struct sss_idp_oauth2 *data);

struct sss_idp_oauth2 *
sss_idp_oauth2_decode_padata(krb5_pa_data *padata);

struct sss_idp_oauth2 *
sss_idp_oauth2_decode(const char *str);

char *
sss_idp_oauth2_encode_challenge(struct sss_idp_oauth2 *data);

struct sss_idp_oauth2 *
sss_idp_oauth2_decode_challenge(const char *str);

/* DARC: PA-152 of the second AS-REQ, "oauth2-confirm <code>". */
krb5_pa_data *
sss_idp_oauth2_encode_confirm_padata(const char *code);

/* Returns the confirmation code from a PA-152 of the second AS-REQ (a copy
 * the caller frees), or NULL when it is not a confirmation. */
char *
sss_idp_oauth2_decode_confirm_padata(const krb5_pa_data *padata);

/* Check a code typed by the user against the challenge: non-empty, not too
 * long, printable ASCII without spaces once separators are removed. Returns
 * a normalized copy (spaces and dashes removed) or NULL. */
char *
sss_idp_oauth2_normalize_confirmation(const char *code);

/* Indicators the RADIUS server returned in an Access-Accept Reply-Message
 * "oauth2 {\"v\":2,\"indicators\":[...]}". Only names starting with
 * SSSD_IDP_INDICATOR_PREFIX are kept. Returns NULL when there are none. */
char **
sss_idp_oauth2_decode_accept_indicators(const char *str);

#endif /* _IDP_H_ */
