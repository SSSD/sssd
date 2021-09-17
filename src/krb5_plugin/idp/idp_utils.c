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

#include "krb5_plugin/idp/idp.h"

#define is_empty(var) ((var) == NULL || (var)[0] == '\0')

static krb5_error_code
sss_idp_json_array_to_strings(json_t *jarray, char ***_array)
{
    krb5_error_code ret;
    const char *strval;
    char **array;
    json_t *jval;
    size_t i;

    if (!json_is_array(jarray)) {
        return EINVAL;
    }

    array = calloc(json_array_size(jarray) + 1, sizeof(char *));
    if (array == NULL) {
        return ENOMEM;
    }

    json_array_foreach(jarray, i, jval) {
        strval = json_string_value(jval);
        if (strval == NULL) {
            ret = EINVAL;
            goto fail;
        }

        array[i] = strdup(strval);
        if (array[i] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
    }

    *_array = array;

    return 0;

fail:
    for (i = 0; array[i] != NULL; i++) {
        free(array[i]);
    }
    free(array);

    return ret;
}

void
sss_idp_config_free(struct sss_idp_config *idpcfg)
{
    int i;

    if (idpcfg == NULL) {
        return;
    }

    if (idpcfg->type != NULL) {
        free(idpcfg->type);
    }

    if (idpcfg->indicators != NULL) {
        for (i = 0; idpcfg->indicators[i] != NULL; i++) {
            free(idpcfg->indicators[i]);
        }
        free(idpcfg->indicators);
    }

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
        ret = sss_idp_json_array_to_strings(jindicators, &idpcfg->indicators);
        if (ret != 0) {
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

static struct sss_idp_oauth2 *
sss_idp_oauth2_decode(const char *str)
{
    size_t prefix_len;

    prefix_len = strlen(SSSD_IDP_OAUTH2_PREFIX);
    if (strncmp(str, SSSD_IDP_OAUTH2_PREFIX, prefix_len) != 0) {
        return NULL;
    }

    return sss_idp_oauth2_from_json(str + prefix_len);
}

static char *
sss_idp_oauth2_encode(struct sss_idp_oauth2 *data)
{
    char *json_str;
    char *str;
    int aret;

    json_str = sss_idp_oauth2_to_json(data);
    if (json_str == NULL) {
        return NULL;
    }

    aret = asprintf(&str, "%s%s", SSSD_IDP_OAUTH2_PREFIX, json_str);
    free(json_str);
    if (aret < 0) {
        return NULL;
    }

    return str;
}

struct sss_idp_oauth2 *
sss_idp_oauth2_decode_reply_message(const krb5_data *msg)
{
    struct sss_idp_oauth2 *data;
    char *str;

    str = strndup(msg->data, msg->length);
    if (str == NULL) {
        return NULL;
    }

    data = sss_idp_oauth2_decode(str);
    free(str);

    return data;
}

krb5_pa_data *
sss_idp_oauth2_encode_padata(struct sss_idp_oauth2 *data)
{
    krb5_pa_data *padata;
    char *str;

    str = sss_idp_oauth2_encode(data);
    if (str == NULL) {
        return NULL;
    }

    padata = malloc(sizeof(krb5_pa_data));
    if (padata == NULL) {
        free(str);
        return NULL;
    }

    padata->pa_type = SSSD_IDP_OAUTH2_PADATA;
    padata->contents = (krb5_octet*)str;
    padata->length = strlen(str) + 1;

    return padata;
}

struct sss_idp_oauth2 *
sss_idp_oauth2_decode_padata(krb5_pa_data *padata)
{
    if (padata->length == 0 || padata->contents == NULL) {
        return NULL;
    }

    /* contents is NULL terminated string */
    if (padata->contents[padata->length - 1] != '\0') {
        return NULL;
    }

    return sss_idp_oauth2_decode((const char*)padata->contents);
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
