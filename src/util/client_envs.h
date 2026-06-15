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

#ifndef _SSS_CLIENT_ENVS_H_
#define _SSS_CLIENT_ENVS_H_

#include <stddef.h>
#include <stdbool.h>

/* Allowed environment variables to forward to child processes */
extern const char *allowed_client_envs[];

size_t get_allowed_client_envs_count(void);

/* Check if an environment variable name is in the allowlist */
bool is_client_env_allowed(const char *env_name);

#endif /* _SSS_CLIENT_ENVS_H_ */
