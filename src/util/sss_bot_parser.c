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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util/sss_bot_parser.h"

int
sss_bot_parse_const(const char *input, struct sss_bot_parser_data *_data)
{
    const char *uid_start;
    const char *at_pos;
    unsigned long uid;
    char *uid_end;
    size_t len;

    if (input == NULL) {
        return EINVAL;
    }

    if (strncmp(input, SSS_BOT_PREFIX, SSS_BOT_PREFIX_LEN) != 0) {
        return EINVAL;
    }

    uid_start = input + SSS_BOT_PREFIX_LEN;
    if (*uid_start < '0' || *uid_start > '9') {
        return EINVAL;
    }

    errno = 0;
    uid = strtoul(uid_start, &uid_end, 10);
    if (errno != 0 || uid == 0 || *uid_end != '~' || uid > UINT32_MAX) {
        return EINVAL;
    }

    /* Random part must not be empty */
    if (uid_end[1] == '\0' || uid_end[1] == '@') {
        return EINVAL;
    }

    at_pos = strchr(input, '@');
    len = (at_pos != NULL) ? (size_t)(at_pos - input) : strlen(input);

    _data->input = input;
    _data->input_len = strlen(input);
    _data->name = input;
    _data->name_len = len;
    _data->random = uid_end + 1;
    _data->random_len = len - (size_t)(uid_end + 1 - input);
    _data->uid = (uint32_t)uid;

    return 0;
}
