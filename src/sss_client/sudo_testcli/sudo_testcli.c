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

void print_sss_result(struct sss_sudo_result *result);

int main(int argc, char **argv)
{
    int ret = 0;
    struct sss_sudo_result *result = NULL;
    uint32_t error = 0;

    if (argc > 2) {
        fprintf(stderr, "Usage: sss_sudo_cli username\n");
        goto fail;
    }

    /* get sss_result - it will send new query to responder */

    if (argc == 1) {
        ret = sss_sudo_send_recv_defaults(&error, &result);
        if (ret != EOK) {
            fprintf(stderr, "sss_sudo_send_recv_defaults() failed: %s\n", strerror(ret));
            goto fail;
        }
    } else {
        ret = sss_sudo_send_recv(argv[1], &error, &result);
        if (ret != EOK) {
            fprintf(stderr, "sss_sudo_send_recv() failed: %s\n", strerror(ret));
            goto fail;
        }
    }

    printf("=== Printing response data ===\n");
    printf("Response code: %d\n\n", error);
    if (error == SSS_SUDO_ERROR_OK) {
        print_sss_result(result);
    }


    sss_sudo_free_result(result);
    return 0;

fail:
    sss_sudo_free_result(result);
    return 1;
}

void print_sss_result(struct sss_sudo_result *result)
{
    struct sss_sudo_rule *rule = NULL;
    struct sss_sudo_attr *attr = NULL;
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
