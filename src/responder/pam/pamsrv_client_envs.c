/*
    SSSD

    PAM Responder - Client environment variable handling

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

#include "util/util.h"
#include "util/client_envs.h"

#include "pamsrv_client_envs.h"

static bool is_env_allowed(const char *env)
{
    size_t n_envs;

    if (env == NULL)
        return false;

    n_envs = get_allowed_client_envs_count();
    for (size_t i = 0; i < n_envs; i++) {
        if (strcmp(env, allowed_client_envs[i]) == 0)
            return true;
    }

    return false;
}

static bool is_session_id_valid(const char *id)
{
    if (id == NULL || *id == '\0')
        return false;

    for (const char *p = id; *p != '\0'; p++) {
        if (!isalnum((unsigned char)*p))
            return false;
    }

    return true;
}

static bool is_client_env_valid(const char *env)
{
    char **parts = NULL;
    bool valid = false;
    int num_parts;
    int ret;

    if (env == NULL)
        return false;

    ret = split_on_separator(NULL, env, '=', false, false, &parts, &num_parts);
    if (ret != EOK || num_parts != 2) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Invalid env format: %s\n", env);
        goto done;
    }

    if (!is_env_allowed(parts[0])) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Environment variable '%s' is not allowed\n", parts[0]);
        goto done;
    }

    /* Special validation for GRD_PCSCD_SESSION_ID */
    if (strcmp(parts[0], "GRD_PCSCD_SESSION_ID") == 0) {
        if (!is_session_id_valid(parts[1]))
            goto done;
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
        if (data[i] == '\0')
            count++;
    }

    return count;
}

int parse_client_env_list(TALLOC_CTX *mem_ctx, const uint8_t *data,
                          size_t size, const char ***_envs, size_t *_count)
{
    const char **envs;
    const char *p;
    size_t count;
    size_t idx;

    count = count_null_terminated_strings(data, size);
    if (count == 0)
        return EOK;

    envs = talloc_zero_array(mem_ctx, const char *, count + 1);
    if (envs == NULL)
        return ENOMEM;

    idx = 0;
    p = (const char *)data;
    while (*p != '\0') {
        size_t len = strlen(p);
        if (len == 0) break;
        envs[idx] = talloc_strdup(envs, p);
        if (envs[idx] == NULL) {
            talloc_free(envs);
            return ENOMEM;
        }
        p += len + 1;
        idx++;
    }
    envs[idx] = NULL;

    *_envs = envs;
    *_count = count;

    return EOK;
}

int filter_client_envs(TALLOC_CTX *mem_ctx, const char **client_envs,
                       size_t count, const char ***_filtered_envs,
                       size_t *_count)
{
    const char *valid_envs[count + 1];
    const char **filtered_envs;
    size_t n;

    if (client_envs == NULL || count == 0) {
        *_count = 0;
        *_filtered_envs = NULL;
        return EOK;
    }

    n = 0;
    for (size_t i = 0; i < count; i++) {
        if (is_client_env_valid(client_envs[i]))
            valid_envs[n++] = client_envs[i];
    }
    valid_envs[n] = NULL;

    if (n == 0) {
        *_count = 0;
        *_filtered_envs = NULL;
        return EOK;
    }

    filtered_envs = dup_string_list(mem_ctx, valid_envs);
    if (filtered_envs == NULL)
        return ENOMEM;

    *_filtered_envs = filtered_envs;
    *_count = n;

    return EOK;
}
