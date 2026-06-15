/*
    SSSD

    Client environment variable parsing and serialization

    Copyright (C) Red Hat, 2026

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

#include <ctype.h>
#include <string.h>

#include "util/util.h"
#include "util/client_envs.h"
#include "util/sss_client_envs.h"

static bool is_session_id_valid(const char *id)
{
    if (id == NULL || *id == '\0') return false;

    for (const char *p = id; *p != '\0'; p++) {
        if (!isalnum((unsigned char)*p)) {
            return false;
        }
    }

    return true;
}

static bool is_client_env_valid(const char *env)
{
    char **parts = NULL;
    bool valid = false;
    int num_parts;
    int ret;

    if (env == NULL) return false;

    ret = split_on_separator(NULL, env, '=', false, false, &parts, &num_parts);
    if (ret != EOK || num_parts != 2) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Invalid env format: %s\n", env);
        goto done;
    }

    if (!is_client_env_allowed(parts[0])) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Environment variable '%s' is not allowed\n", parts[0]);
        goto done;
    }

    /* Special validation for GDM_AUTH_SESSION_ID */
    if (strcmp(parts[0], "GDM_AUTH_SESSION_ID") == 0) {
        if (!is_session_id_valid(parts[1])) {
            goto done;
        }
    }

    valid = true;

done:
    talloc_free(parts);
    return valid;
}

static size_t count_null_terminated_strings(const uint8_t *data, size_t size)
{
    size_t count = 0;

    for (size_t i = 0; i < size; i++) {
        if (data[i] == '\0') {
            count++;
        }
    }

    return count;
}

int parse_client_env_list(TALLOC_CTX *mem_ctx, const uint8_t *data,
                          size_t size, const char ***_envs, size_t *_count)
{
    const char **envs;
    const char *p;
    const char *end;
    size_t count;
    size_t idx;

    if (size == 0) {
        *_envs = NULL;
        *_count = 0;
        return EOK;
    }

    if (data[size - 1] != '\0') {
        DEBUG(SSSDBG_OP_FAILURE,
              "Client env list is not null-terminated\n");
        return EINVAL;
    }

    count = count_null_terminated_strings(data, size);
    if (count == 0) {
        *_envs = NULL;
        *_count = 0;
        return EOK;
    }

    const char *valid_envs[count + 1];

    idx = 0;
    p = (const char *)data;
    end = (const char *)data + size;
    while (p < end && idx < count) {
        size_t len = strlen(p);
        if (len == 0) return EINVAL;

        if (is_client_env_valid(p)) {
            valid_envs[idx++] = p;
        }

        p += len + 1;
    }
    valid_envs[idx] = NULL;

    if (idx == 0) {
        *_envs = NULL;
        *_count = 0;
        return EOK;
    }

    envs = dup_string_list(mem_ctx, valid_envs);
    if (envs == NULL) return ENOMEM;

    *_envs = envs;
    *_count = idx;

    return EOK;
}

int serialize_client_env_list(TALLOC_CTX *mem_ctx, const char **envs,
                              uint8_t **_buf, size_t *_len)
{
    uint8_t *buf;
    uint8_t *p;
    size_t total = 0;

    if (envs == NULL) {
        *_buf = NULL;
        *_len = 0;
        return EOK;
    }

    for (size_t i = 0; envs[i] != NULL; i++) {
        total += strlen(envs[i]) + 1;
    }

    if (total == 0) {
        *_buf = NULL;
        *_len = 0;
        return EOK;
    }

    buf = talloc_array(mem_ctx, uint8_t, total);
    if (buf == NULL) return ENOMEM;

    p = buf;
    for (size_t i = 0; envs[i] != NULL; i++) {
        size_t len = strlen(envs[i]) + 1;
        memcpy(p, envs[i], len);
        p += len;
    }

    *_buf = buf;
    *_len = total;

    return EOK;
}
