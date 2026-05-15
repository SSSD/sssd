/*
 * System Security Services Daemon. NSS client interface
 *
 * Authors:
 *     Lukas Slebodnik <lslebodn@redhat.com>
 *
 * Copyright (C) 2015 Red Hat
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

/* INITGROUPs database NSS interface using mmap cache */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/mman.h>
#include <time.h>
#include "nss_mc.h"
#include "shared/safealign.h"

#if HAVE_PTHREAD
static pthread_mutex_t initgr_mc_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sss_cli_mc_ctx initgr_mc_ctx = SSS_CLI_MC_CTX_INITIALIZER(&initgr_mc_ctx_mutex);
#else
static struct sss_cli_mc_ctx initgr_mc_ctx = SSS_CLI_MC_CTX_INITIALIZER;
#endif

static errno_t sss_nss_mc_parse_result(struct sss_mc_rec *rec,
                                       long int *start, long int *size,
                                       gid_t **groups, long int limit)
{
    struct sss_mc_initgr_data *data;
    time_t expire;
    long int i;
    uint32_t num_groups;
    long int max_ret;

    /* additional checks before filling result*/
    expire = rec->expire;
    if (expire < time(NULL)) {
        /* entry is now invalid */
        return EINVAL;
    }

    data = (struct sss_mc_initgr_data *)rec->data;
    num_groups = data->num_groups;
    max_ret = num_groups;

    /* check we have enough space in the buffer */
    if ((*size - *start) < num_groups) {
        long int newsize;
        gid_t *newgroups;

        newsize = *size + num_groups;
        if ((limit > 0) && (newsize > limit)) {
            newsize = limit;
            max_ret = newsize - *start;
        }

        newgroups = (gid_t *)realloc((*groups), newsize * sizeof(**groups));
        if (!newgroups) {
            return ENOMEM;
        }
        *groups = newgroups;
        *size = newsize;
    }

    for (i = 0; i < max_ret; i++) {
        SAFEALIGN_COPY_UINT32(&(*groups)[*start], data->gids + i, NULL);
        *start += 1;
    }

    return 0;
}

errno_t sss_nss_mc_initgroups_dyn(const char *name, size_t name_len,
                                  gid_t group, long int *start, long int *size,
                                  gid_t **groups, long int limit)
{
    struct sss_mc_rec *rec = NULL;
    struct sss_mc_initgr_data *data;
    char *rec_name;
    uint32_t hash;
    uint32_t slot;
    int ret;
    const size_t data_offset = offsetof(struct sss_mc_initgr_data, gids);
    size_t data_size;

    ret = sss_nss_mc_get_ctx("initgroups", &initgr_mc_ctx);
    if (ret) {
        return ret;
    }

    /* Get max size of data table. */
    data_size = initgr_mc_ctx.dt_size;

    /* hashes are calculated including the NULL terminator */
    hash = sss_nss_mc_hash(&initgr_mc_ctx, name, name_len + 1);
    slot = initgr_mc_ctx.hash_table[hash];

    /* If slot is not within the bounds of mmapped region and
     * it's value is not MC_INVALID_VAL, then the cache is
     * probably corrupted. */
    while (MC_SLOT_WITHIN_BOUNDS(slot, data_size)) {
        /* free record from previous iteration */
        free(rec);
        rec = NULL;

        ret = sss_nss_mc_get_record(&initgr_mc_ctx, slot, &rec);
        if (ret) {
            goto done;
        }

        /* check record matches what we are searching for */
        if (hash != rec->hash1) {
            /* if name hash does not match we can skip this immediately */
            slot = sss_nss_mc_next_slot_with_hash(rec, hash);
            continue;
        }

        data = (struct sss_mc_initgr_data *)rec->data;
        rec_name = (char *)data + data->name;
        /* Integrity check
         * - data->name cannot point outside all strings or data
         * - all data must be within copy of record
         * - data->strs cannot point outside strings
         * - rec_name is a zero-terminated string */
        if (data->name < data_offset
            || data->name >= data_offset + data->data_len
            || data->strs_len > data->data_len
            || data->data_len > rec->len) {
            ret = ENOENT;
            goto done;
        }

        if (strcmp(name, rec_name) == 0) {
            break;
        }

        slot = sss_nss_mc_next_slot_with_hash(rec, hash);
    }

    if (!MC_SLOT_WITHIN_BOUNDS(slot, data_size)) {
        ret = ENOENT;
        goto done;
    }

    ret = sss_nss_mc_parse_result(rec, start, size, groups, limit);

done:
    free(rec);
    __sync_sub_and_fetch(&initgr_mc_ctx.active_threads, 1);
    return ret;
}
