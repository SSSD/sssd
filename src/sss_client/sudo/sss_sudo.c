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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "util/util.h"
#include "sss_client/sss_cli.h"
#include "sss_client/sudo/sss_sudo.h"
#include "sss_client/sudo/sss_sudo_private.h"

static int sss_sudo_make_request(enum sss_cli_command cmd,
                          struct sss_cli_req_data *rd,
                          uint8_t **repbuf, size_t *replen,
                          int *errnop)
{
    return sss_cli_make_request_with_checks(cmd, rd, SSS_CLI_SOCKET_TIMEOUT,
                                            repbuf, replen, errnop,
                                            SSS_SUDO_SOCKET_NAME, true, false);
}

static int sss_sudo_create_query(uid_t uid,
                                 const char *username,
                                 uint8_t **_query,
                                 size_t *_query_len);

static void sss_sudo_free_rules(unsigned int num_rules,
                                struct sss_sudo_rule *rules);

static void sss_sudo_free_attrs(unsigned int num_attrs,
                                struct sss_sudo_attr *attrs);

static int sss_sudo_send_recv_generic(enum sss_cli_command command,
                                      uid_t uid,
                                      const char *username,
                                      uint32_t *_error,
                                      char **_domainname,
                                      struct sss_sudo_result **_result)
{
    struct sss_cli_req_data request;
    uint8_t *query_buf = NULL;
    size_t query_len = 0;
    uint8_t *reply_buf = NULL;
    size_t reply_len = 0;
    int errnop = 0;
    int ret = 0;

    /* create query */

    ret = sss_sudo_create_query(uid, username, &query_buf, &query_len);
    if (ret != EOK) {
        goto done;
    }

    request.len = query_len;
    request.data = (const void*)query_buf;

    /* send query and receive response */

    errnop = 0;
    ret = sss_sudo_make_request(command, &request,
                                &reply_buf, &reply_len, &errnop);
    if (ret != SSS_STATUS_SUCCESS) {
        if (_error != NULL) {
            *_error = (uint32_t)errnop;
        }
        goto done;
    }

    /* parse structure */

    ret = sss_sudo_parse_response((const char*)reply_buf, reply_len,
                                  _domainname, _result, _error);

done:
    free(query_buf);
    free(reply_buf);
    return ret;
}

int sss_sudo_send_recv(uid_t uid,
                       const char *username,
                       const char *domainname,
                       uint32_t *_error,
                       struct sss_sudo_result **_result)
{
    int ret;

    if (username == NULL || strlen(username) == 0) {
        return EINVAL;
    }

    /* send query and receive response */

    ret = sss_sudo_send_recv_generic(SSS_SUDO_GET_SUDORULES, uid, username,
                                     _error, NULL, _result);
    return ret;
}

int sss_sudo_send_recv_defaults(uid_t uid,
                                const char *username,
                                uint32_t *_error,
                                char **_domainname,
                                struct sss_sudo_result **_result)
{
    if (username == NULL || strlen(username) == 0) {
        return EINVAL;
    }

    return sss_sudo_send_recv_generic(SSS_SUDO_GET_DEFAULTS, uid, username,
                                      _error, _domainname, _result);
}

static int sss_sudo_create_query(uid_t uid, const char *username,
                                 uint8_t **_query, size_t *_query_len)
{
    uint8_t *data = NULL;
    size_t username_len = strlen(username) * sizeof(char) + 1;
    size_t data_len = sizeof(uid_t) + username_len;
    size_t offset = 0;

    data = (uint8_t*)malloc(data_len * sizeof(uint8_t));
    if (data == NULL) {
        return ENOMEM;
    }

    SAFEALIGN_SET_VALUE(data, uid, uid_t, &offset);
    memcpy(data + offset, username, username_len);

    *_query = data;
    *_query_len = data_len;

    return EOK;
}

int sss_sudo_get_values(struct sss_sudo_rule *e,
                        const char *attrname, char ***_values)
{
    struct sss_sudo_attr *attr = NULL;
    char **values = NULL;
    int i, j;

    for (i = 0; i < e->num_attrs; i++) {
        attr = e->attrs + i;
        if (strcasecmp(attr->name, attrname) == 0) {
            values = calloc(attr->num_values + 1, sizeof(char*));
            if (values == NULL) {
                return ENOMEM;
            }

            for (j = 0; j < attr->num_values; j++) {
                values[j] = strdup(attr->values[j]);
                if (values[j] == NULL) {
                    sss_sudo_free_values(values);
                    return ENOMEM;
                }
            }

            values[attr->num_values] = NULL;

            break;
        }
    }

    if (values == NULL) {
        return ENOENT;
    }

    *_values = values;

    return EOK;
}

void sss_sudo_free_values(char **values)
{
    char **value = NULL;

    if (values == NULL) {
        return;
    }

    for (value = values; *value != NULL; value++) {
        free(*value);
    }

    free(values);
}

void sss_sudo_free_result(struct sss_sudo_result *result)
{
    if (result == NULL) {
        return;
    }

    sss_sudo_free_rules(result->num_rules, result->rules);
    free(result);
}

void sss_sudo_free_rules(unsigned int num_rules, struct sss_sudo_rule *rules)
{
    struct sss_sudo_rule *rule = NULL;
    int i;

    if (rules == NULL) {
        return;
    }

    for (i = 0; i < num_rules; i++) {
        rule = rules + i;

        sss_sudo_free_attrs(rule->num_attrs, rule->attrs);
        rule->attrs = NULL;
    }

    free(rules);
}

void sss_sudo_free_attrs(unsigned int num_attrs, struct sss_sudo_attr *attrs)
{
    struct sss_sudo_attr *attr = NULL;
    int i, j;

    if (attrs == NULL) {
        return;
    }

    for (i = 0; i < num_attrs; i++) {
        attr = attrs + i;

        free(attr->name);
        attr->name = NULL;

        for (j = 0; j < attr->num_values; j++) {
            free(attr->values[j]);
            attr->values[j] = NULL;
        }

        free(attr->values);
    }

    free(attrs);
}
