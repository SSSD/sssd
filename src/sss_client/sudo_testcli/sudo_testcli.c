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
#include <sys/types.h>
#include <pwd.h>

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
    struct passwd *passwd = NULL;
    const char *username = NULL;
    char *domainname = NULL;
    uid_t uid = 0;
    uint32_t error = 0;

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: sss_sudo_cli username [uid]\n");
        goto fail;
    }

    username = argv[1];
    if (argc == 3) {
        uid = atoi(argv[2]);
    } else {
        passwd = getpwnam(username);
        if (passwd == NULL) {
            fprintf(stderr, "Unknown user\n");
            goto fail;
        }
        uid = passwd->pw_uid;
    }

    /* get sss_result - it will send new query to responder */

    /* get default options */

    ret = sss_sudo_send_recv_defaults(uid, username, &error,
                                      &domainname, &result);
    if (ret != EOK) {
        fprintf(stderr, "sss_sudo_send_recv_defaults() failed: %s\n",
                strerror(ret));
        goto fail;
    }

    printf("[\n");
    printf("\t{\n");
    printf("\t\t\"type\": \"default\",\n");
    printf("\t\t\"retval\": %u,\n", error);
    if (error == SSS_SUDO_ERROR_OK) {
        print_sss_result(result);
    }
    printf("\t},\n");

    sss_sudo_free_result(result);
    result = NULL;

    /* get rules */

    ret = sss_sudo_send_recv(uid, username, domainname, &error, &result);
    if (ret != EOK) {
        fprintf(stderr, "sss_sudo_send_recv() failed: %s\n", strerror(ret));
        goto fail;
    }

    printf("\t{\n");
    printf("\t\t\"type\": \"rules\",\n");
    printf("\t\t\"retval\": %u,\n", error);
    if (error == SSS_SUDO_ERROR_OK) {
        print_sss_result(result);
    }
    printf("\t}\n");
    printf("]\n");


    free(domainname);
    sss_sudo_free_result(result);
    return 0;

fail:
    free(domainname);
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

    printf("\t\t\"result\": {\n");
    printf("\t\t\t\"num_rules\": %d,\n", result->num_rules);
    printf("\t\t\t\"rules\": [\n");
    for (i = 0; i < result->num_rules; i++) {
        rule = &result->rules[i];
        printf("\t\t\t\t{\n");
        for (j = 0; j < rule->num_attrs; j++) {
            attr = &rule->attrs[j];
            printf("\t\t\t\t\t\"%s\": ", attr->name);
            if (attr->num_values > 1) {
                printf("[ ");
                printf("\"%s\"", attr->values[0]);
                for (k = 1; k < attr->num_values; k++) {
                    printf(", \"%s\"", attr->values[k]);
                }
                printf(" ]");
            } else {
                printf("\"%s\"", attr->values[0]);
            }

            if (j < rule->num_attrs - 1) {
                printf(",");
            }
            printf("\n");
        }
        printf("\t\t\t\t}");
        if (i < result->num_rules - 1) {
            printf(",");
        }
        printf("\n");
    }
    printf("\t\t\t]\n");
    printf("\t\t}\n");
}
