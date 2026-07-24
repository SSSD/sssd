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

#ifndef SSS_CLIENT_ENVS_H_
#define SSS_CLIENT_ENVS_H_

#include <talloc.h>
#include <stdint.h>

/* Parse a buffer of null-terminated strings ("KEY=val\0KEY=val\0") into
 * a NULL-terminated array of strings, keeping only those that are in the
 * allowed list and pass validation. Returns EOK on success. */
int parse_client_env_list(TALLOC_CTX *mem_ctx, const uint8_t *data,
                          size_t size, const char ***_envs, size_t *_count);

/* Serialize a NULL-terminated array of strings into a buffer of
 * null-terminated strings ("KEY=val\0KEY=val\0"). Returns EOK on success. */
int serialize_client_env_list(TALLOC_CTX *mem_ctx, const char **envs,
                              uint8_t **_buf, size_t *_len);

#endif /* SSS_CLIENT_ENVS_H_ */
