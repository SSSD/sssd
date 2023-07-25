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

#ifndef _KRB5_PLUGIN_UTILS_H_
#define _KRB5_PLUGIN_UTILS_H_

#include <jansson.h>
#include <krb5/preauth_plugin.h>

#define is_empty(var) ((var) == NULL || (var)[0] == '\0')

void
sss_string_array_free(char **array);

char **
sss_string_array_copy(char **array);

char **
sss_json_array_to_strings(json_t *jarray);

json_t *
sss_strings_to_json_array(char **array);

typedef void * (*sss_radius_message_decode_fn)(const char *);
typedef char * (*sss_radius_message_encode_fn)(const void *);

void *
sss_radius_message_decode(const char *prefix,
                          sss_radius_message_decode_fn fn,
                          const char *str);

char *
sss_radius_message_encode(const char *prefix,
                          sss_radius_message_encode_fn fn,
                          const void *data);

krb5_pa_data *
sss_radius_encode_padata(krb5_preauthtype patype,
                         sss_radius_message_encode_fn fn,
                         const void *data);

void *
sss_radius_decode_padata(sss_radius_message_decode_fn fn,
                         krb5_pa_data *padata);

krb5_pa_data **
sss_radius_encode_padata_array(krb5_preauthtype patype,
                               sss_radius_message_encode_fn fn,
                               const void *data);

#endif /* _KRB5_PLUGIN_UTILS_H_ */
