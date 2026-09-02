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
#include <talloc.h>

#include "util/sss_bot_parser.h"
#include "util/sss_bot.h"
#include "util/util_errors.h"

errno_t
sss_bot_parse(TALLOC_CTX *mem_ctx, const char *input, struct sss_bot **_bot)
{
    struct sss_bot_parser_data data;
    struct sss_bot *bot;
    errno_t ret;

    ret = sss_bot_parse_const(input, &data);
    if (ret != EOK) {
        return ret;
    }

    bot = talloc_zero(mem_ctx, struct sss_bot);
    if (bot == NULL) {
        return ENOMEM;
    }

    bot->input = talloc_strdup(bot, data.input);
    bot->name = talloc_strndup(bot, data.name, data.name_len);
    bot->random = talloc_strndup(bot, data.random, data.random_len);
    bot->uid = data.uid;

    if (bot->input == NULL || bot->name == NULL || bot->random == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_bot = bot;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(bot);
    }

    return ret;
}

struct sss_bot *
sss_bot_copy(TALLOC_CTX *mem_ctx, struct sss_bot *bot)
{
    struct sss_bot *copy;

    if (bot == NULL) {
        return NULL;
    }

    copy = talloc_zero(mem_ctx, struct sss_bot);
    if (copy == NULL) {
        return NULL;
    }

    copy->input = talloc_strdup(copy, bot->input);
    copy->name = talloc_strdup(copy, bot->name);
    copy->random = talloc_strdup(copy, bot->random);
    if (copy->input == NULL || copy->name == NULL || copy->random == NULL) {
        talloc_free(copy);
        return NULL;
    }

    copy->uid = bot->uid;

    return copy;
}
