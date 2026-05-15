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
};

void
sss_idp_oauth2_free(struct sss_idp_oauth2 *data);

krb5_pa_data *
sss_idp_oauth2_encode_padata(struct sss_idp_oauth2 *data);

struct sss_idp_oauth2 *
sss_idp_oauth2_decode_padata(krb5_pa_data *padata);

char *
sss_idp_oauth2_encode_challenge(struct sss_idp_oauth2 *data);

struct sss_idp_oauth2 *
sss_idp_oauth2_decode_challenge(const char *str);

#endif /* _IDP_H_ */
