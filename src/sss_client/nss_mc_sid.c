/*
 * System Security Services Daemon. NSS client interface
 *
 * Copyright (C) 2022 Red Hat
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* SID database NSS interface using mmap cache */

#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "nss_mc.h"
#include "util/mmap_cache.h"
#include "idmap/sss_nss_idmap.h"

#if HAVE_PTHREAD
static pthread_mutex_t sid_mc_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sss_cli_mc_ctx sid_mc_ctx = SSS_CLI_MC_CTX_INITIALIZER(&sid_mc_ctx_mutex);
#else
static struct sss_cli_mc_ctx sid_mc_ctx = SSS_CLI_MC_CTX_INITIALIZER;
#endif

static errno_t mc_get_sid_by_typed_id(uint32_t id, enum sss_id_type object_type,
                                      char **sid, uint32_t *type,
                                      uint32_t *populated_by)
{
    int ret;
    char key[16];
    int key_len;
    uint32_t hash;
    uint32_t slot;
    struct sss_mc_rec *rec = NULL;
    const struct sss_mc_sid_data *data = NULL;

    key_len = snprintf(key, sizeof(key), "%d-%ld", object_type, (long)id);
    if (key_len > (sizeof(key) - 1)) {
        return EINVAL;
    }

    ret = sss_nss_mc_get_ctx("sid", &sid_mc_ctx);
    if (ret) {
        return ret;
    }

    hash = sss_nss_mc_hash(&sid_mc_ctx, key, key_len + 1);
    slot = sid_mc_ctx.hash_table[hash];

    while (MC_SLOT_WITHIN_BOUNDS(slot, sid_mc_ctx.dt_size)) {
        free(rec); /* free record from previous iteration */
        rec = NULL;

        ret = sss_nss_mc_get_record(&sid_mc_ctx, slot, &rec);
        if (ret) {
            goto done;
        }
        if (hash != rec->hash2) {
            ret = EINVAL;
            goto done;
        }

        data = (struct sss_mc_sid_data *)rec->data;
        if (id == data->id) {
            if (rec->expire < time(NULL)) {
                ret = EINVAL;
                goto done;
            }
            *type = data->type;
            if (populated_by) {
                *populated_by = data->populated_by;
            }
            *sid = strdup(data->sid);
            if (!*sid) {
                ret = ENOMEM;
            }
            goto done;
        }

        slot = sss_nss_mc_next_slot_with_hash(rec, hash);
    }

    ret = ENOENT;

done:
    free(rec);
    __sync_sub_and_fetch(&sid_mc_ctx.active_threads, 1);
    return ret;
}

errno_t sss_nss_mc_get_sid_by_uid(uint32_t id, char **sid, uint32_t *type)
{
    return mc_get_sid_by_typed_id(id, SSS_ID_TYPE_UID, sid, type, NULL);
}

errno_t sss_nss_mc_get_sid_by_gid(uint32_t id, char **sid, uint32_t *type)
{
    return mc_get_sid_by_typed_id(id, SSS_ID_TYPE_GID, sid, type, NULL);
}

errno_t sss_nss_mc_get_sid_by_id(uint32_t id, char **sid, uint32_t *type)
{
    errno_t ret;
    uint32_t populated_by;

    /* MC should behave the same way sssd_nss does.
     * If user object exists sssd_nss would always return this user object.
     */
    ret = sss_nss_mc_get_sid_by_uid(id, sid, type);
    if (ret != ENOENT) {
        return ret; /* found or fatal error */
    }

    /* This is where things get tricky.
     * Consider a case of manually created user private group:
     * since MC could be primed via explicit by-gid() lookup,
     * missing user object doesn't mean sssd_nss wouldn't return
     * it, hence only return group object if cache was primed via
     * by-id() lookup.
     */
    ret = mc_get_sid_by_typed_id(id, SSS_ID_TYPE_GID, sid, type, &populated_by);
    if ((ret == 0) && (populated_by == 1)) {
        /* Cache was primed via explicit by-gid() lookup - request should go to sssd_nss */
        free(*sid);
        ret = ENOENT;
    }

    return ret;
}

errno_t sss_nss_mc_get_id_by_sid(const char *sid, uint32_t *id, uint32_t *type)
{
    int ret;
    int key_len;
    uint32_t hash;
    uint32_t slot;
    struct sss_mc_rec *rec = NULL;
    const struct sss_mc_sid_data *data = NULL;

    key_len = strlen(sid) + 1;

    ret = sss_nss_mc_get_ctx("sid", &sid_mc_ctx);
    if (ret) {
        return ret;
    }

    hash = sss_nss_mc_hash(&sid_mc_ctx, sid, key_len);
    slot = sid_mc_ctx.hash_table[hash];

    while (MC_SLOT_WITHIN_BOUNDS(slot, sid_mc_ctx.dt_size)) {
        free(rec); /* free record from previous iteration */
        rec = NULL;

        ret = sss_nss_mc_get_record(&sid_mc_ctx, slot, &rec);
        if (ret) {
            goto done;
        }
        if (hash != rec->hash1) {
            ret = EINVAL;
            goto done;
        }

        data = (struct sss_mc_sid_data *)rec->data;
        if (strcmp(sid, data->sid) == 0) {
            if (rec->expire < time(NULL)) {
                ret = EINVAL;
                goto done;
            }
            *type = data->type;
            *id = data->id;
            goto done; /* ret == 0 */
        }

        slot = sss_nss_mc_next_slot_with_hash(rec, hash);
    }

    ret = ENOENT;

done:
    free(rec);
    __sync_sub_and_fetch(&sid_mc_ctx.active_threads, 1);
    return ret;
}
