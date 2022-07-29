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

/* PASSWD database NSS interface using mmap cache */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/mman.h>
#include <time.h>
#include "nss_mc.h"

#if HAVE_PTHREAD
static pthread_mutex_t pw_mc_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sss_cli_mc_ctx pw_mc_ctx = SSS_CLI_MC_CTX_INITIALIZER(&pw_mc_ctx_mutex);
#else
static struct sss_cli_mc_ctx pw_mc_ctx = SSS_CLI_MC_CTX_INITIALIZER;
#endif

static errno_t sss_nss_mc_parse_result(struct sss_mc_rec *rec,
                                       struct passwd *result,
                                       char *buffer, size_t buflen)
{
    struct sss_mc_pwd_data *data;
    time_t expire;
    void *cookie;
    int ret;

    /* additional checks before filling result*/
    expire = rec->expire;
    if (expire < time(NULL)) {
        /* entry is now invalid */
        return EINVAL;
    }

    data = (struct sss_mc_pwd_data *)rec->data;

    if (data->strs_len > buflen) {
        return ERANGE;
    }

    /* fill in glibc provided structs */

    /* copy in buffer */
    memcpy(buffer, data->strs, data->strs_len);

    /* fill in passwd */
    result->pw_uid = data->uid;
    result->pw_gid = data->gid;

    cookie = NULL;
    ret = sss_nss_str_ptr_from_buffer(&result->pw_name, &cookie,
                                      buffer, data->strs_len);
    if (ret) {
        return ret;
    }
    ret = sss_nss_str_ptr_from_buffer(&result->pw_passwd, &cookie,
                                      buffer, data->strs_len);
    if (ret) {
        return ret;
    }
    ret = sss_nss_str_ptr_from_buffer(&result->pw_gecos, &cookie,
                                      buffer, data->strs_len);
    if (ret) {
        return ret;
    }
    ret = sss_nss_str_ptr_from_buffer(&result->pw_dir, &cookie,
                                      buffer, data->strs_len);
    if (ret) {
        return ret;
    }
    ret = sss_nss_str_ptr_from_buffer(&result->pw_shell, &cookie,
                                      buffer, data->strs_len);
    if (ret) {
        return ret;
    }
    if (cookie != NULL) {
        return EINVAL;
    }

    return 0;
}

errno_t sss_nss_mc_getpwnam(const char *name, size_t name_len,
                            struct passwd *result,
                            char *buffer, size_t buflen)
{
    struct sss_mc_rec *rec = NULL;
    struct sss_mc_pwd_data *data;
    char *rec_name;
    uint32_t hash;
    uint32_t slot;
    int ret;
    const size_t strs_offset = offsetof(struct sss_mc_pwd_data, strs);
    size_t data_size;

    ret = sss_nss_mc_get_ctx("passwd", &pw_mc_ctx);
    if (ret) {
        return ret;
    }

    /* Get max size of data table. */
    data_size = pw_mc_ctx.dt_size;

    /* hashes are calculated including the NULL terminator */
    hash = sss_nss_mc_hash(&pw_mc_ctx, name, name_len + 1);
    slot = pw_mc_ctx.hash_table[hash];

    /* If slot is not within the bounds of mmapped region and
     * it's value is not MC_INVALID_VAL, then the cache is
     * probably corrupted. */
    while (MC_SLOT_WITHIN_BOUNDS(slot, data_size)) {
        /* free record from previous iteration */
        free(rec);
        rec = NULL;

        ret = sss_nss_mc_get_record(&pw_mc_ctx, slot, &rec);
        if (ret) {
            goto done;
        }

        /* check record matches what we are searching for */
        if (hash != rec->hash1) {
            /* if name hash does not match we can skip this immediately */
            slot = sss_nss_mc_next_slot_with_hash(rec, hash);
            continue;
        }

        data = (struct sss_mc_pwd_data *)rec->data;
        rec_name = (char *)data + data->name;
        /* Integrity check
         * - data->name cannot point outside strings
         * - all strings must be within copy of record
         * - rec_name is a zero-terminated string */
        if (data->name < strs_offset
            || data->name >= strs_offset + data->strs_len
            || data->strs_len > rec->len) {
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

    ret = sss_nss_mc_parse_result(rec, result, buffer, buflen);

done:
    free(rec);
    __sync_sub_and_fetch(&pw_mc_ctx.active_threads, 1);
    return ret;
}

errno_t sss_nss_mc_getpwuid(uid_t uid,
                            struct passwd *result,
                            char *buffer, size_t buflen)
{
    struct sss_mc_rec *rec = NULL;
    struct sss_mc_pwd_data *data;
    char uidstr[11];
    uint32_t hash;
    uint32_t slot;
    int len;
    int ret;

    ret = sss_nss_mc_get_ctx("passwd", &pw_mc_ctx);
    if (ret) {
        return ret;
    }

    len = snprintf(uidstr, 11, "%ld", (long)uid);
    if (len > 10) {
        ret = EINVAL;
        goto done;
    }

    /* hashes are calculated including the NULL terminator */
    hash = sss_nss_mc_hash(&pw_mc_ctx, uidstr, len+1);
    slot = pw_mc_ctx.hash_table[hash];

    /* If slot is not within the bounds of mmapped region and
     * it's value is not MC_INVALID_VAL, then the cache is
     * probably corrupted. */
    while (MC_SLOT_WITHIN_BOUNDS(slot, pw_mc_ctx.dt_size)) {
        /* free record from previous iteration */
        free(rec);
        rec = NULL;

        ret = sss_nss_mc_get_record(&pw_mc_ctx, slot, &rec);
        if (ret) {
            goto done;
        }

        /* check record matches what we are searching for */
        if (hash != rec->hash2) {
            /* if uid hash does not match we can skip this immediately */
            slot = sss_nss_mc_next_slot_with_hash(rec, hash);
            continue;
        }

        data = (struct sss_mc_pwd_data *)rec->data;
        if (uid == data->uid) {
            break;
        }

        slot = sss_nss_mc_next_slot_with_hash(rec, hash);
    }

    if (!MC_SLOT_WITHIN_BOUNDS(slot, pw_mc_ctx.dt_size)) {
        ret = ENOENT;
        goto done;
    }

    ret = sss_nss_mc_parse_result(rec, result, buffer, buflen);

done:
    free(rec);
    __sync_sub_and_fetch(&pw_mc_ctx.active_threads, 1);
    return ret;
}

