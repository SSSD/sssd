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

#ifndef _PAMSRV_CLIENT_ENVS_H_
#define _PAMSRV_CLIENT_ENVS_H_

#include <talloc.h>
#include <stdint.h>

struct pam_ctx;

/* Parse a buffer of null-terminated strings ("KEY=val\0KEY=val\0") into
 * a NULL-terminated array of strings. Returns EOK on success. */
int parse_client_env_list(TALLOC_CTX *mem_ctx, const uint8_t *data,
                          size_t size, const char ***_strings, size_t *_count);

/* Filter client environment variables, keeping only those that are in the
 * allowed list and pass validation. Returns a NULL-terminated array.
 * Returns EOK on success. */
int filter_client_envs(TALLOC_CTX *mem_ctx, const char **client_envs,
                       size_t count, const char ***_filtered_envs,
                       size_t *_count);

/* Copy client_envs and append any derived environment variables.
 * Returns a NULL-terminated array. Returns EOK on success. */
int append_derived_client_envs(TALLOC_CTX *mem_ctx, struct pam_ctx *pctx,
                               const char **client_envs, size_t count,
                               const char ***_result_envs, size_t *_count);

#endif /* _PAMSRV_CLIENT_ENVS_H_ */
