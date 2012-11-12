/*
 * System Security Services Daemon. NSS client interface
 *
 * Copyright (C) Simo Sorce 2011
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

/* GROUP database NSS interface using mmap cache */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include "nss_mc.h"

struct sss_cli_mc_ctx gr_mc_ctx = { false, -1, 0, NULL, 0, NULL, 0, NULL, 0 };

static errno_t sss_nss_mc_parse_result(struct sss_mc_rec *rec,
                                       struct group *result,
                                       char *buffer, size_t buflen)
{
    struct sss_mc_grp_data *data;
    time_t expire;
    void *cookie;
    char *membuf;
    size_t memsize;
    int ret;
    int i;

    /* additional checks before filling result*/
    expire = rec->expire;
    if (expire < time(NULL)) {
        /* entry is now invalid */
        return EINVAL;
    }

    data = (struct sss_mc_grp_data *)rec->data;

    memsize = (data->members + 1) * sizeof(char *);
    if (data->strs_len + memsize > buflen) {
        return ERANGE;
    }

    /* fill in glibc provided structs */

    /* copy in buffer */
    membuf = buffer + memsize;
    memcpy(membuf, data->strs, data->strs_len);

    /* fill in group */
    result->gr_gid = data->gid;
    result->gr_mem = (char **)buffer;
    result->gr_mem[data->members] = NULL;

    cookie = NULL;
    ret = sss_nss_str_ptr_from_buffer(&result->gr_name, &cookie,
                                      membuf, data->strs_len);
    if (ret) {
        return ret;
    }
    ret = sss_nss_str_ptr_from_buffer(&result->gr_passwd, &cookie,
                                      membuf, data->strs_len);
    if (ret) {
        return ret;
    }

    for (i = 0; i < data->members; i++) {
        ret = sss_nss_str_ptr_from_buffer(&result->gr_mem[i], &cookie,
                                          membuf, data->strs_len);
        if (ret) {
            return ret;
        }
    }
    if (cookie != NULL) {
        return EINVAL;
    }

    return 0;
}

errno_t sss_nss_mc_getgrnam(const char *name, size_t name_len,
                            struct group *result,
                            char *buffer, size_t buflen)
{
    struct sss_mc_rec *rec = NULL;
    struct sss_mc_grp_data *data;
    char *rec_name;
    uint32_t hash;
    uint32_t slot;
    int ret;

    ret = sss_nss_mc_get_ctx("group", &gr_mc_ctx);
    if (ret) {
        return ret;
    }

    /* hashes are calculated including the NULL terminator */
    hash = sss_nss_mc_hash(&gr_mc_ctx, name, name_len + 1);
    slot = gr_mc_ctx.hash_table[hash];
    if (slot > MC_SIZE_TO_SLOTS(gr_mc_ctx.dt_size)) {
        return ENOENT;
    }

    while (slot != MC_INVALID_VAL) {

        ret = sss_nss_mc_get_record(&gr_mc_ctx, slot, &rec);
        if (ret) {
            goto done;
        }

        /* check record matches what we are searching for */
        if (hash != rec->hash1) {
            /* if name hash does not match we can skip this immediately */
            slot = rec->next;
            continue;
        }

        data = (struct sss_mc_grp_data *)rec->data;
        rec_name = (char *)data + data->name;
        if (strcmp(name, rec_name) == 0) {
            break;
        }

        slot = rec->next;
    }

    if (slot == MC_INVALID_VAL) {
        ret = ENOENT;
        goto done;
    }

    ret = sss_nss_mc_parse_result(rec, result, buffer, buflen);

done:
    free(rec);
    return ret;
}

errno_t sss_nss_mc_getgrgid(gid_t gid,
                            struct group *result,
                            char *buffer, size_t buflen)
{
    struct sss_mc_rec *rec = NULL;
    struct sss_mc_grp_data *data;
    char gidstr[11];
    uint32_t hash;
    uint32_t slot;
    int len;
    int ret;

    ret = sss_nss_mc_get_ctx("group", &gr_mc_ctx);
    if (ret) {
        return ret;
    }

    len = snprintf(gidstr, 11, "%ld", (long)gid);
    if (len > 10) {
        return EINVAL;
    }

    /* hashes are calculated including the NULL terminator */
    hash = sss_nss_mc_hash(&gr_mc_ctx, gidstr, len+1);
    slot = gr_mc_ctx.hash_table[hash];
    if (slot > MC_SIZE_TO_SLOTS(gr_mc_ctx.dt_size)) {
        return ENOENT;
    }

    while (slot != MC_INVALID_VAL) {

        ret = sss_nss_mc_get_record(&gr_mc_ctx, slot, &rec);
        if (ret) {
            goto done;
        }

        /* check record matches what we are searching for */
        if (hash != rec->hash2) {
            /* if uid hash does not match we can skip this immediately */
            slot = rec->next;
            continue;
        }

        data = (struct sss_mc_grp_data *)rec->data;
        if (gid == data->gid) {
            break;
        }

        slot = rec->next;
    }

    if (slot == MC_INVALID_VAL) {
        ret = ENOENT;
        goto done;
    }

    ret = sss_nss_mc_parse_result(rec, result, buffer, buflen);

done:
    free(rec);
    return ret;
}

