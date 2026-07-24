/*
    SSSD

    Client environment variable allowlist

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

#include <string.h>
#include <stdbool.h>
#include "util/client_envs.h"

const char *allowed_client_envs[] = {
    "GDM_AUTH_SESSION_ID",
};

size_t get_allowed_client_envs_count(void)
{
    return (sizeof(allowed_client_envs) / sizeof(allowed_client_envs[0]));
}

bool is_client_env_allowed(const char *env_name)
{
    size_t n_envs;

    if (env_name == NULL) return false;

    n_envs = get_allowed_client_envs_count();
    for (size_t i = 0; i < n_envs; i++) {
        if (strcmp(env_name, allowed_client_envs[i]) == 0) {
            return true;
        }
    }

    return false;
}
