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
    free(data->delivery);
    free(data->confirmation_charset);
    free(data);
}

static int
sss_idp_oauth2_strdup(char **dest, const char *src)
{
    if (is_empty(src)) {
        *dest = NULL;
        return 0;
    }

    *dest = strdup(src);
    return *dest == NULL ? ENOMEM : 0;
}

static struct sss_idp_oauth2 *
sss_idp_oauth2_init(const struct sss_idp_oauth2 *in)
{
    struct sss_idp_oauth2 *data;
    bool authenticator;

    authenticator = in->version >= 2 && in->delivery != NULL
                    && strcmp(in->delivery, "authenticator") == 0;

    /* Required fields: where to go and what to enter, unless the code is
     * delivered to the user's authenticator app (DARC mode M4). */
    if (!authenticator
            && (is_empty(in->verification_uri) || is_empty(in->user_code))) {
        return NULL;
    }

    /* The authenticator mode only makes sense with a code to type. */
    if (authenticator && in->confirmation_length <= 0) {
        return NULL;
    }

    if (in->confirmation_length < 0
            || in->confirmation_length > SSSD_IDP_OAUTH2_CONFIRM_MAX) {
        return NULL;
    }

    data = malloc(sizeof(struct sss_idp_oauth2));
    if (data == NULL) {
        return NULL;
    }
    memset(data, 0, sizeof(struct sss_idp_oauth2));

    data->version = in->version < 1 ? 1 : in->version;
    data->confirmation_length = in->confirmation_length;
    data->expires_in = in->expires_in;

    if (sss_idp_oauth2_strdup(&data->verification_uri,
                              in->verification_uri) != 0
        || sss_idp_oauth2_strdup(&data->verification_uri_complete,
                                 in->verification_uri_complete) != 0
        || sss_idp_oauth2_strdup(&data->user_code, in->user_code) != 0
        || sss_idp_oauth2_strdup(&data->delivery, in->delivery) != 0
        || sss_idp_oauth2_strdup(&data->confirmation_charset,
                                 in->confirmation_charset) != 0) {
        sss_idp_oauth2_free(data);
        return NULL;
    }

    return data;
}

/**
 * Version 1:
 * {"verification_uri": "...", "verification_uri_complete": "..." (optional),
 *  "user_code": "..."}
 *
 * Version 2 (DARC) adds:
 * {"v": 2, "delivery": "page" | "authenticator",
 *  "confirmation": {"length": 6, "charset": "numeric"} (optional),
 *  "expires_in": 600 (optional)}
 */
static struct sss_idp_oauth2 *
sss_idp_oauth2_from_json(const char *json_str)
{
    struct sss_idp_oauth2 jdata = {0};
    struct sss_idp_oauth2 *data;
    json_t *jconfirmation = NULL;
    json_error_t jret;
    json_t *jroot;
    int ret;

    jroot = json_loads(json_str, 0, &jret);
    if (jroot == NULL) {
        return NULL;
    }

    ret = json_unpack(jroot, "{s?:s, s?:s, s?:s, s?:i, s?:s, s?:o, s?:i}",
                "verification_uri", &jdata.verification_uri,
                "verification_uri_complete", &jdata.verification_uri_complete,
                "user_code", &jdata.user_code,
                "v", &jdata.version,
                "delivery", &jdata.delivery,
                "confirmation", &jconfirmation,
                "expires_in", &jdata.expires_in);
    if (ret != 0) {
        json_decref(jroot);
        return NULL;
    }

    if (jdata.version >= 2 && jconfirmation != NULL) {
        ret = json_unpack(jconfirmation, "{s:i, s?:s}",
                          "length", &jdata.confirmation_length,
                          "charset", &jdata.confirmation_charset);
        if (ret != 0) {
            json_decref(jroot);
            return NULL;
        }
    }

    data = sss_idp_oauth2_init(&jdata);

    json_decref(jroot);
    return data;
}

static char *
sss_idp_oauth2_to_json(const struct sss_idp_oauth2 *data)
{
    json_t *jroot;
    json_t *jconfirmation;
    char *str;
    int jret;

    if (data == NULL) {
        return NULL;
    }

    if (data->version < 2) {
        /* These are required fields. */
        if (data->verification_uri == NULL || data->user_code == NULL) {
            return NULL;
        }

        jroot = json_pack("{s:s?, s:s*, s:s?}",
                    "verification_uri", data->verification_uri,
                    "verification_uri_complete", data->verification_uri_complete,
                    "user_code", data->user_code);
    } else {
        jroot = json_pack("{s:i, s:s*, s:s*, s:s*, s:s*}",
                    "v", data->version,
                    "delivery", data->delivery,
                    "verification_uri", data->verification_uri,
                    "verification_uri_complete", data->verification_uri_complete,
                    "user_code", data->user_code);
    }
    if (jroot == NULL) {
        return NULL;
    }

    if (data->version >= 2 && data->confirmation_length > 0) {
        jconfirmation = json_pack("{s:i, s:s*}",
                                  "length", data->confirmation_length,
                                  "charset", data->confirmation_charset);
        jret = json_object_set_new(jroot, "confirmation", jconfirmation);
        if (jconfirmation == NULL || jret != 0) {
            json_decref(jroot);
            return NULL;
        }
    }

    if (data->version >= 2 && data->expires_in > 0) {
        jret = json_object_set_new(jroot, "expires_in",
                                   json_integer(data->expires_in));
        if (jret != 0) {
            json_decref(jroot);
            return NULL;
        }
    }

    str = json_dumps(jroot, JSON_COMPACT | JSON_PRESERVE_ORDER);
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

char *
sss_idp_oauth2_normalize_confirmation(const char *code)
{
    char *out;
    size_t i;
    size_t j;

    if (is_empty(code)) {
        return NULL;
    }

    out = malloc(strlen(code) + 1);
    if (out == NULL) {
        return NULL;
    }

    for (i = 0, j = 0; code[i] != '\0'; i++) {
        if (code[i] == ' ' || code[i] == '-' || code[i] == '\t') {
            continue;
        }

        /* Printable ASCII only: the code is typed from a web page. */
        if (code[i] < 0x21 || code[i] > 0x7e || j >= SSSD_IDP_OAUTH2_CONFIRM_MAX) {
            free(out);
            return NULL;
        }

        out[j++] = code[i];
    }
    out[j] = '\0';

    if (j == 0) {
        free(out);
        return NULL;
    }

    return out;
}

krb5_pa_data *
sss_idp_oauth2_encode_confirm_padata(const char *code)
{
    krb5_pa_data *padata;
    char *normalized;
    char *str;
    int aret;

    normalized = sss_idp_oauth2_normalize_confirmation(code);
    if (normalized == NULL) {
        return NULL;
    }

    aret = asprintf(&str, "%s%s", SSSD_IDP_OAUTH2_CONFIRM_PREFIX, normalized);
    free(normalized);
    if (aret < 0) {
        return NULL;
    }

    padata = malloc(sizeof(krb5_pa_data));
    if (padata == NULL) {
        free(str);
        return NULL;
    }

    padata->magic = 0;
    padata->pa_type = SSSD_IDP_OAUTH2_PADATA;
    padata->contents = (krb5_octet *)str;
    padata->length = strlen(str) + 1;

    return padata;
}

char *
sss_idp_oauth2_decode_confirm_padata(const krb5_pa_data *padata)
{
    const char *str;
    size_t prefix_len;

    if (padata == NULL || padata->pa_type != SSSD_IDP_OAUTH2_PADATA
            || padata->length == 0 || padata->contents == NULL) {
        return NULL;
    }

    /* contents is a NULL terminated string */
    if (padata->contents[padata->length - 1] != '\0'
            || strlen((const char *)padata->contents) != padata->length - 1) {
        return NULL;
    }

    str = (const char *)padata->contents;
    prefix_len = strlen(SSSD_IDP_OAUTH2_CONFIRM_PREFIX);
    if (strncmp(str, SSSD_IDP_OAUTH2_CONFIRM_PREFIX, prefix_len) != 0) {
        return NULL;
    }

    return sss_idp_oauth2_normalize_confirmation(str + prefix_len);
}

static void *
sss_idp_oauth2_indicators_from_json(const char *json_str)
{
    json_t *jindicators = NULL;
    json_error_t jret;
    json_t *jroot;
    json_t *jval;
    char **out = NULL;
    size_t i;
    size_t n = 0;

    jroot = json_loads(json_str, 0, &jret);
    if (jroot == NULL) {
        return NULL;
    }

    if (json_unpack(jroot, "{s:o}", "indicators", &jindicators) != 0
            || !json_is_array(jindicators)) {
        goto done;
    }

    out = calloc(json_array_size(jindicators) + 1, sizeof(char *));
    if (out == NULL) {
        goto done;
    }

    json_array_foreach(jindicators, i, jval) {
        const char *name = json_string_value(jval);

        /* The RADIUS server may only add IdP-specific indicators. */
        if (name == NULL
                || strncmp(name, SSSD_IDP_INDICATOR_PREFIX,
                           strlen(SSSD_IDP_INDICATOR_PREFIX)) != 0
                || strlen(name) > 64) {
            continue;
        }

        out[n] = strdup(name);
        if (out[n] == NULL) {
            sss_string_array_free(out);
            out = NULL;
            goto done;
        }
        n++;
    }

    if (n == 0) {
        sss_string_array_free(out);
        out = NULL;
    }

done:
    json_decref(jroot);
    return out;
}

char **
sss_idp_oauth2_decode_accept_indicators(const char *str)
{
    return sss_radius_message_decode(SSSD_IDP_OAUTH2_PREFIX,
        (sss_radius_message_decode_fn)sss_idp_oauth2_indicators_from_json,
        str);
}
