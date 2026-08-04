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
#include <string.h>
#include <stdlib.h>
#include <talloc.h>

#include "util/sss_bot.h"
#include "util/util_errors.h"

errno_t
sss_bot_parse(TALLOC_CTX *mem_ctx, const char *input, struct sss_bot **_bot)
{
    struct sss_bot *bot;
    const char *at_pos;
    const char *uid_start_pos;
    char *uid_end_pos;
    unsigned long uid;
    errno_t ret;

    if (input == NULL) {
        return EINVAL;
    }

    if (strncmp(input, SSS_BOT_PREFIX, SSS_BOT_PREFIX_LEN) != 0) {
        return EINVAL;
    }

    bot = talloc_zero(mem_ctx, struct sss_bot);
    if (bot == NULL) {
        return ENOMEM;
    }

    bot->input = talloc_strdup(bot, input);
    if (bot->input == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* strip realm or domain */
    at_pos = strchr(input, '@');
    if (at_pos != NULL) {
        bot->name = talloc_strndup(bot, input, at_pos - input);
    } else {
        bot->name = talloc_strdup(bot, bot->input);
    }
    if (bot->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* parse uid */
    uid_start_pos = bot->name + SSS_BOT_PREFIX_LEN;
    if (*uid_start_pos < '0' || *uid_start_pos > '9') {
        ret = EINVAL;
        goto done;
    }

    errno = 0;
    uid = strtoul(uid_start_pos, &uid_end_pos, 10);
    if (errno != 0 || uid == 0 || *uid_end_pos != '~' || uid > UINT32_MAX) {
        ret = EINVAL;
        goto done;
    }
    bot->uid = (uint32_t)uid;

    /* parse random part */
    bot->random = talloc_strdup(bot, uid_end_pos + 1);
    if (bot->random == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (bot->random[0] == '\0') {
        ret = EINVAL;
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
