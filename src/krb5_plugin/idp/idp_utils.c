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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <arpa/inet.h>
#include <krb5/preauth_plugin.h>

#include "krb5_plugin/common/utils.h"
#include "krb5_plugin/idp/idp.h"

void
sss_idp_config_free(struct sss_idp_config *idpcfg)
{
    if (idpcfg == NULL) {
        return;
    }

    if (idpcfg->type != NULL) {
        free(idpcfg->type);
    }

    sss_string_array_free(idpcfg->indicators);
    free(idpcfg);
}

/**
 * [{
 *   "type": "oauth2",
 *   "indicators": ["..."] (optional)
 * }]
 *
 * Note: array and type is used for future extensibility.
 */
krb5_error_code
sss_idp_config_init(const char *config,
                    struct sss_idp_config **_idpcfg)
{
    struct sss_idp_config *idpcfg;
    json_t *jindicators = NULL;
    json_error_t jret;
    json_t *jroot;
    krb5_error_code ret;

    idpcfg = malloc(sizeof(struct sss_idp_config));
    if (idpcfg == NULL) {
        return ENOMEM;
    }
    memset(idpcfg, 0, sizeof(struct sss_idp_config));

    jroot = json_loads(config, 0, &jret);
    if (jroot == NULL) {
        ret = EINVAL;
        goto done;
    }

    /* Only one item is supported at the moment. The rest is ignored. */
    ret = json_unpack(jroot, "[{s:s, s?:o}]",
                      "type", &idpcfg->type,
                      "indicators", &jindicators);
    if (ret != 0) {
        ret = EINVAL;
        goto done;
    }

    /* Only oauth2 type is supported at the moment. */
    if (strcmp(idpcfg->type, "oauth2") != 0) {
        ret = EINVAL;
        goto done;
    }

    idpcfg->type = strdup(idpcfg->type);
    if (idpcfg->type == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Are indicators set? */
    if (jindicators != NULL) {
        idpcfg->indicators = sss_json_array_to_strings(jindicators);
        if (idpcfg->indicators == NULL) {
            ret = EINVAL;
            goto done;
        }
    }

    *_idpcfg = idpcfg;

    ret = 0;

done:
    if (ret != 0) {
        sss_idp_config_free(idpcfg);
    }

    if (jroot != NULL) {
        json_decref(jroot);
    }

    return ret;
}

void
sss_idp_oauth2_free(struct sss_idp_oauth2 *data)
{
    if (data == NULL) {
        return;
    }

    free(data->verification_uri);
    free(data->verification_uri_complete);
    free(data->user_code);
    free(data);
}

static struct sss_idp_oauth2 *
sss_idp_oauth2_init(const char *verification_uri,
                    const char *verification_uri_complete,
                    const char *user_code)
{
    struct sss_idp_oauth2 *data;

    /* These are required fields. */
    if (is_empty(verification_uri) || is_empty(user_code)) {
        return NULL;
    }

    data = malloc(sizeof(struct sss_idp_oauth2));
    if (data == NULL) {
        return NULL;
    }
    memset(data, 0, sizeof(struct sss_idp_oauth2));

    data->verification_uri = strdup(verification_uri);
    data->user_code = strdup(user_code);
    if (data->verification_uri == NULL || data->user_code == NULL) {
        sss_idp_oauth2_free(data);
        return NULL;
    }

    if (!is_empty(verification_uri_complete)) {
        data->verification_uri_complete = strdup(verification_uri_complete);
        if (data->verification_uri_complete == NULL) {
            sss_idp_oauth2_free(data);
            return NULL;
        }
    }

    return data;
}

static struct sss_idp_oauth2 *
sss_idp_oauth2_from_json(const char *json_str)
{
    struct sss_idp_oauth2 jdata = {0};
    struct sss_idp_oauth2 *data;
    json_error_t jret;
    json_t *jroot;
    int ret;

    jroot = json_loads(json_str, 0, &jret);
    if (jroot == NULL) {
        return NULL;
    }

    ret = json_unpack(jroot, "{s:s, s?:s, s:s}",
                "verification_uri", &jdata.verification_uri,
                "verification_uri_complete", &jdata.verification_uri_complete,
                "user_code", &jdata.user_code);
    if (ret != 0) {
        json_decref(jroot);
        return NULL;
    }

    data = sss_idp_oauth2_init(jdata.verification_uri,
                               jdata.verification_uri_complete,
                               jdata.user_code);

    json_decref(jroot);
    return data;
}

static char *
sss_idp_oauth2_to_json(const struct sss_idp_oauth2 *data)
{
    json_t *jroot;
    char *str;

    if (data == NULL) {
        return NULL;
    }

    /* These are required fields. */
    if (data->verification_uri == NULL || data->user_code == NULL) {
        return NULL;
    }

    jroot = json_pack("{s:s?, s:s*, s:s?}",
                "verification_uri", data->verification_uri,
                "verification_uri_complete", data->verification_uri_complete,
                "user_code", data->user_code);
    if (jroot == NULL) {
        return NULL;
    }

    str = json_dumps(jroot, JSON_COMPACT);
    json_decref(jroot);

    return str;
}

struct sss_idp_oauth2 *
sss_idp_oauth2_decode(const char *str)
{
    return sss_radius_message_decode(SSSD_IDP_OAUTH2_PREFIX,
        (sss_radius_message_decode_fn)sss_idp_oauth2_from_json, str);
}

static char *
sss_idp_oauth2_encode(struct sss_idp_oauth2 *data)
{
    return sss_radius_message_encode(SSSD_IDP_OAUTH2_PREFIX,
        (sss_radius_message_encode_fn)sss_idp_oauth2_to_json, data);
}

krb5_pa_data *
sss_idp_oauth2_encode_padata(struct sss_idp_oauth2 *data)
{
    return sss_radius_encode_padata(SSSD_IDP_OAUTH2_PADATA,
        (sss_radius_message_encode_fn)sss_idp_oauth2_encode, data);
}

struct sss_idp_oauth2 *
sss_idp_oauth2_decode_padata(krb5_pa_data *padata)
{
    return sss_radius_decode_padata(
        (sss_radius_message_decode_fn)sss_idp_oauth2_decode, padata);
}

char *
sss_idp_oauth2_encode_challenge(struct sss_idp_oauth2 *data)
{
    return sss_idp_oauth2_encode(data);
}

struct sss_idp_oauth2 *
sss_idp_oauth2_decode_challenge(const char *str)
{
    return sss_idp_oauth2_decode(str);
}
