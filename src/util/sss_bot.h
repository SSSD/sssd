/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2026 Red Hat

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

#ifndef __SSS_BOT_H__
#define __SSS_BOT_H__

#include <stdint.h>
#include <sys/types.h>
#include "util/util_errors.h"

/* Shell override */
#define SSS_BOT_SHELL "/usr/bin/sss-confined-shell"

struct sss_bot {
    char *input; /* Original input name, may contain potential realm or domain */
    char *name; /* Bot account name, short name, without realm or domain */
    char *random; /* Random part of the name, extracted from the name */
    uint32_t uid; /* UID number of the original user, extracted from the name */
};

#ifdef TALLOC_VERSION_MAJOR

/**
 * Parse bot name.
 *
 * For talloc-aware code. talloc.h must be included before this header.
 *
 * Return EINVAL if the @input does not validate as a bot account.
 */
errno_t
sss_bot_parse(TALLOC_CTX *mem_ctx, const char *input, struct sss_bot **_bot);

/**
 * Deep copy sss_bot.
 */
struct sss_bot *
sss_bot_copy(TALLOC_CTX *mem_ctx, struct sss_bot *bot);

#else

/**
 * Parse bot name.
 *
 * This is talloc-free version that can be used in client libraries.
 *
 * Free it with @sss_bot_cli_free.
 *
 * Return EINVAL if the @input does not validate as a bot account.
 */
int
sss_bot_cli_parse(const char *input, struct sss_bot **_bot);

void
sss_bot_cli_free(struct sss_bot *bot);

#endif /* TALLOC_VERSION_MAJOR */

#endif /* __SSS_BOT_H__ */
