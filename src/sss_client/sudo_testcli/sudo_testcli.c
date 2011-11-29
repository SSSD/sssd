/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <talloc.h>

#include "sss_client/sss_cli.h"
#include "sss_client/sudo/sss_sudo.h"
#include "sss_client/sudo/sss_sudo_private.h"

#ifndef EOK
#define EOK 0
#endif

int create_query(const char *username, char **_query, int *_query_len);
void print_sss_result(struct sss_result *result);

int main(int argc, char **argv)
{
    struct sss_cli_req_data request;
    const char *username = NULL;
    char *query = NULL;
    int query_len = 0;
    int errnop = 0;
    int ret = 0;
    uint8_t *reply_buf = NULL;
    char *reply_buf_char = NULL;
    size_t reply_len;
    int i = 0;
    struct sss_result *result = NULL;
    uint32_t error = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: sss_sudo_cli username\n");
        goto fail;
    }

    username = argv[1];

    /* create query */

    ret = create_query(username, &query, &query_len);
    if (ret != EOK) {
        fprintf(stderr, "Unable to create query: %s\n", strerror(ret));
        goto fail;
    }

    request.len = query_len;
    request.data = (const void*)query;

    /* send query and recieve response */

    errnop = 0;
    ret = sss_sudo_make_request(SSS_SUDO_GET_SUDORULES, &request, &reply_buf,
                                &reply_len, &errnop);
    if (errnop != EOK) {
        fprintf(stderr, "Unable to contact SSSD responder: %s\n", strerror(errnop));
        goto fail;
    }

    reply_buf_char = (char*)reply_buf;
    if (reply_len > 0) {
        printf("Reply length: %d\n", (int)reply_len);
        printf("Reply data:\n");
        for (i = 0; i < reply_len; i++) {
            if (reply_buf_char[i] == '\0') {
                printf("\\0");
            } else {
                printf("%c", reply_buf_char[i]);
            }
        }
        printf("\n");
    } else {
        printf("No reply received!\n");
    }

    /* get sss_result - it will send new query to responder */

    ret = sss_sudo_get_result(username, &error, &result);
    if (ret != EOK) {
        fprintf(stderr, "Usss_sudo_get_result() failed: %s\n", strerror(ret));
        goto fail;
    }

    printf("\n=== Printing response data ===\n");
    printf("Response code: %d\n\n", error);
    if (error == SSS_SUDO_ERROR_OK) {
        print_sss_result(result);
    }


    sss_sudo_free_result(result);
    free(query);
    return 0;

fail:
    sss_sudo_free_result(result);
    free(query);
    return 1;
}

int create_query(const char *username, char **_query, int *_query_len)
{
    char *data = NULL;
    int data_len = strlen(username) + 1;

    if (data_len <= 0) {
        return EINVAL;
    }

    data = (char*)malloc(data_len * sizeof(char));
    if (data == NULL) {
        return ENOMEM;
    }

    memcpy(data, username, data_len);

    *_query = data;
    *_query_len = data_len;

    return EOK;
}

void print_sss_result(struct sss_result *result)
{
    struct sss_rule *rule = NULL;
    struct sss_attr *attr = NULL;
    int i = 0;
    int j = 0;
    int k = 0;

    printf("Number of rules: %d\n", result->num_rules);

    for (i = 0; i < result->num_rules; i++) {
        rule = &result->rules[i];
        printf("=== Rule %d has %d attributes\n", i, rule->num_attrs);
        for (j = 0; j < rule->num_attrs; j++) {
            attr = &rule->attrs[j];
            printf("   === Attribute named %s has %d values:\n", attr->name,
                   attr->num_values);

            for (k = 0; k < attr->num_values; k++) {
                printf("       %s\n", attr->values[k]);
            }
        }
    }
}
