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
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <krb5/preauth_plugin.h>

#include "krb5_plugin/common/utils.h"

void
sss_string_array_free(char **array)
{
    size_t i;

    if (array == NULL) {
        return;
    }

    for (i = 0; array[i] != NULL; i++) {
        free(array[i]);
    }

    free(array);
}

char **
sss_string_array_copy(char **array)
{
    char **copy;
    size_t i;

    for (i = 0; array[i] != NULL; i++) {
        /* Just count. */
    }

    copy = calloc(i + 1, sizeof(char *));
    if (copy == NULL) {
        return NULL;
    }

    for (i = 0; array[i] != NULL; i++) {
        copy[i] = strdup(array[i]);
        if (copy[i] == NULL) {
            sss_string_array_free(copy);
            return NULL;
        }
    }

    copy[i] = NULL;

    return copy;
}

char **
sss_json_array_to_strings(json_t *jarray)
{
    const char *strval;
    char **array;
    json_t *jval;
    size_t i;

    if (!json_is_array(jarray)) {
        return NULL;
    }

    array = calloc(json_array_size(jarray) + 1, sizeof(char *));
    if (array == NULL) {
        return NULL;
    }

    json_array_foreach(jarray, i, jval) {
        strval = json_string_value(jval);
        if (strval == NULL) {
            goto fail;
        }

        array[i] = strdup(strval);
        if (array[i] == NULL) {
            goto fail;
        }
    }

    return array;

fail:
    sss_string_array_free(array);

    return NULL;
}

json_t *
sss_strings_to_json_array(char **array)
{
    json_t *jarray;
    json_t *jstr;
    size_t i;
    int jret;

    jarray = json_array();
    if (jarray == NULL) {
        return NULL;
    }

    if (array == NULL) {
        return jarray;
    }

    for (i = 0; array[i] != NULL; i++) {
        jstr = json_string(array[i]);
        if (jstr == NULL) {
            goto fail;
        }

        jret = json_array_append_new(jarray, jstr);
        if (jret != 0) {
            goto fail;
        }
    }

    return jarray;

fail:
    json_decref(jarray);

    return NULL;
}

void *
sss_radius_message_decode(const char *prefix,
                          sss_radius_message_decode_fn fn,
                          const char *str)
{
    size_t prefix_len;

    if (str == NULL) {
        return NULL;
    }

    prefix_len = strlen(prefix);
    if (strncmp(str, prefix, prefix_len) != 0) {
        return NULL;
    }

    return fn(str + prefix_len);
}

char *
sss_radius_message_encode(const char *prefix,
                          sss_radius_message_encode_fn fn,
                          const void *data)
{
    char *json_str;
    char *str;
    int aret;

    json_str = fn(data);
    if (json_str == NULL) {
        return NULL;
    }

    aret = asprintf(&str, "%s%s", prefix, json_str);
    free(json_str);
    if (aret < 0) {
        return NULL;
    }

    return str;
}

krb5_pa_data *
sss_radius_encode_padata(krb5_preauthtype patype,
                         sss_radius_message_encode_fn fn,
                         const void *data)
{
    krb5_pa_data *padata;
    char *str;

    str = fn(data);
    if (str == NULL) {
        return NULL;
    }

    padata = malloc(sizeof(krb5_pa_data));
    if (padata == NULL) {
        free(str);
        return NULL;
    }

    padata->pa_type = patype;
    padata->contents = (krb5_octet*)str;
    padata->length = strlen(str) + 1;

    return padata;
}

void *
sss_radius_decode_padata(sss_radius_message_decode_fn fn,
                         krb5_pa_data *padata)
{
    if (padata->length == 0 || padata->contents == NULL) {
        return NULL;
    }

    /* contents is NULL terminated string */
    if (padata->contents[padata->length - 1] != '\0') {
        return NULL;
    }

    return fn((const char*)padata->contents);
}

krb5_pa_data **
sss_radius_encode_padata_array(krb5_preauthtype patype,
                               sss_radius_message_encode_fn fn,
                               const void *data)
{
    krb5_pa_data **array;

    array = calloc(2, sizeof(krb5_pa_data *));
    if (array == NULL) {
        return NULL;
    }

    array[0] = sss_radius_encode_padata(patype, fn, data);
    array[1] = NULL;

    if (array[0] == NULL) {
        free(array);
        return NULL;
    }

    return array;
}
