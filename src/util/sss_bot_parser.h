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

#ifndef __SSS_BOT_PARSER_H__
#define __SSS_BOT_PARSER_H__

#include <stdint.h>
#include <sys/types.h>

/* Bot name format: BOT~$UID~$RND[@REALM|@DOMAIN] */
#define SSS_BOT_PREFIX "BOT~"
#define SSS_BOT_PREFIX_LEN (sizeof(SSS_BOT_PREFIX) - 1)

/**
 * Parsed bot name data, all pointers reference the original input string.
 */
struct sss_bot_parser_data {
    const char *input;
    size_t input_len;

    const char *name;
    size_t name_len;

    const char *random;
    size_t random_len;

    uint32_t uid;
};

/**
 * Parse bot name into @_data without any memory allocation.
 *
 * Return EINVAL if the @input does not validate as a bot account.
 */
int
sss_bot_parse_const(const char *input, struct sss_bot_parser_data *_data);

#endif /* __SSS_BOT_PARSER_H__ */
