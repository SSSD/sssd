/*
   SSSD

   Copyright (C) Red Hat, 2020

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

#include "config.h"

#include <stdio.h>
#include <talloc.h>

#include "util/util.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"

/*
 * The secrets store is a key-value store at heart. We store the UUID
 * and the name in the key to allow easy lookups by either part.
 */
#define SEC_KEY_SEPARATOR   '-'

const char *sec_key_create(TALLOC_CTX *mem_ctx,
                           const char *name,
                           uuid_t uuid)
{
    char uuid_str[UUID_STR_SIZE];

    uuid_unparse(uuid, uuid_str);
    return talloc_asprintf(mem_ctx,
                           "%s%c%s", uuid_str, SEC_KEY_SEPARATOR, name);
}

static bool sec_key_valid(const char *sec_key)
{
    if (sec_key == NULL) {
        return false;
    }

    if (strlen(sec_key) < UUID_STR_SIZE + 1) {
        /* One char for separator (at UUID_STR_SIZE, because strlen doesn't
         * include the '\0', but UUID_STR_SIZE does) and at least one for
         * the name */
        DEBUG(SSSDBG_CRIT_FAILURE, "Key %s is too short\n", sec_key);
        return false;
    }

    if (sec_key[UUID_STR_SIZE - 1] != SEC_KEY_SEPARATOR) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Key doesn't contain the separator\n");
        return false;
    }

    return true;
}

errno_t sec_key_parse(TALLOC_CTX *mem_ctx,
                      const char *sec_key,
                      const char **_name,
                      uuid_t uuid)
{
    char uuid_str[UUID_STR_SIZE];

    if (!sec_key_valid(sec_key)) {
        return EINVAL;
    }

    strncpy(uuid_str, sec_key, sizeof(uuid_str) - 1);
    if (sec_key[UUID_STR_SIZE - 1] != SEC_KEY_SEPARATOR) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Key doesn't contain the separator\n");
        return EINVAL;
    }
    uuid_str[UUID_STR_SIZE - 1] = '\0';

    *_name = talloc_strdup(mem_ctx, sec_key + UUID_STR_SIZE);
    if (*_name == NULL) {
        return ENOMEM;
    }
    uuid_parse(uuid_str, uuid);

    return EOK;
}

errno_t sec_key_get_uuid(const char *sec_key,
                         uuid_t uuid)
{
    char uuid_str[UUID_STR_SIZE];

    if (!sec_key_valid(sec_key)) {
        return EINVAL;
    }

    strncpy(uuid_str, sec_key, UUID_STR_SIZE - 1);
    uuid_str[UUID_STR_SIZE - 1] = '\0';
    uuid_parse(uuid_str, uuid);
    return EOK;
}

const char *sec_key_get_name(const char *sec_key)
{
    if (!sec_key_valid(sec_key)) {
        return NULL;
    }

    return sec_key + UUID_STR_SIZE;
}

bool sec_key_match_name(const char *sec_key,
                        const char *name)
{
    if (!sec_key_valid(sec_key) || name == NULL) {
        return false;
    }

    return strcmp(sec_key + UUID_STR_SIZE, name) == 0;
}

bool sec_key_match_uuid(const char *sec_key,
                        uuid_t uuid)
{
    errno_t ret;
    uuid_t key_uuid;

    /* Clear uuid value to avoid cppcheck warning. */
    uuid_clear(key_uuid);

    ret = sec_key_get_uuid(sec_key, key_uuid);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot convert key to UUID\n");
        return false;
    }

    return uuid_compare(key_uuid, uuid) == 0;
}
