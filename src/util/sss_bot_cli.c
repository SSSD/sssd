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
#include "util/sss_bot.h"
#include "util/util_errors.h"

int
sss_bot_cli_parse(const char *input, struct sss_bot **_bot)
{
    struct sss_bot *bot;
    struct sss_bot_parser_data data;
    int ret;

    ret = sss_bot_parse_const(input, &data);
    if (ret != 0) {
        return ret;
    }

    bot = malloc(sizeof(struct sss_bot));
    if (bot == NULL) {
        return ENOMEM;
    }

    bot->input = strndup(data.input, data.input_len);
    bot->name = strndup(data.name, data.name_len);
    bot->random = strndup(data.random, data.random_len);
    bot->uid = data.uid;

    if (bot->input == NULL || bot->name == NULL || bot->random == NULL) {
        sss_bot_cli_free(bot);
        return ENOMEM;
    }

    *_bot = bot;

    return 0;
}

void
sss_bot_cli_free(struct sss_bot *bot)
{
    if (bot == NULL) {
        return;
    }

    free(bot->input);
    free(bot->name);
    free(bot->random);
    free(bot);
}
