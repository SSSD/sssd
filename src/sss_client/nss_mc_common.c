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

/* NSS interfaces to mmap cache */

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include "nss_mc.h"
#include "sss_cli.h"
#include "shared/io.h"

/* FIXME: hook up to library destructor to avoid leaks */
/* FIXME: temporarily open passwd file on our own, later we will probably
 * use socket passing from the main process */
/* FIXME: handle name upper/lower casing? Maybe a flag passed down by
 * SSSD or a flag in sss_mc_header? per domain? */

#define MEMCPY_WITH_BARRIERS(res, dest, src, len) \
do { \
    uint32_t _b1; \
    res = false; \
    _b1 = (src)->b1; \
    if (MC_VALID_BARRIER(_b1)) { \
        __sync_synchronize(); \
        memcpy(dest, src, len); \
        __sync_synchronize(); \
        if ((src)->b2 == _b1) { \
            res = true; \
        } \
    } \
} while(0)

static void sss_mt_lock(struct sss_cli_mc_ctx *ctx)
{
#if HAVE_PTHREAD
    pthread_mutex_lock(ctx->mutex);
#endif
}

static void sss_mt_unlock(struct sss_cli_mc_ctx *ctx)
{
#if HAVE_PTHREAD
    pthread_mutex_unlock(ctx->mutex);
#endif
}

static errno_t sss_nss_mc_validate(struct sss_cli_mc_ctx *ctx)
{
    struct stat fdstat;

    /* No mc ctx initialized?*/
    if (ctx == NULL || ctx->fd < 0) {
        return EINVAL;
    }

    if (fstat(ctx->fd, &fdstat) == -1) {
        return EINVAL;
    }

    /* Memcache was removed. */
    if (fdstat.st_nlink == 0) {
        return EINVAL;
    }

    /* FD was hijacked */
    if ((fdstat.st_dev != ctx->fd_device) || (fdstat.st_ino != ctx->fd_inode)) {
        ctx->fd = -1; /* don't ruin app even if it's misbehaving */
        return EINVAL;
    }

    /* Invalid size. */
    if (fdstat.st_size != ctx->mmap_size) {
        return EINVAL;
    }

    return EOK;
}

errno_t sss_nss_check_header(struct sss_cli_mc_ctx *ctx)
{
    struct sss_mc_header h;
    bool copy_ok;
    int count;
    int ret;

    ret = sss_nss_mc_validate(ctx);
    if (ret != EOK) {
        return ret;
    }

    /* retry barrier protected reading max 5 times then give up */
    for (count = 5; count > 0; count--) {
        MEMCPY_WITH_BARRIERS(copy_ok, &h,
                             (struct sss_mc_header *)ctx->mmap_base,
                             sizeof(struct sss_mc_header));
        if (copy_ok) {
            /* record is consistent so we can proceed */
            break;
        }
    }
    if (count == 0) {
        /* couldn't successfully read header we have to give up */
        return EIO;
    }

    if (h.major_vno != SSS_MC_MAJOR_VNO ||
        h.minor_vno != SSS_MC_MINOR_VNO ||
        h.status == SSS_MC_HEADER_RECYCLED) {
        return EINVAL;
    }

    /* first time we check the header, let's fill our own struct */
    if (ctx->data_table == NULL) {
        ctx->seed = h.seed;
        ctx->data_table = MC_PTR_ADD(ctx->mmap_base, h.data_table);
        ctx->hash_table = MC_PTR_ADD(ctx->mmap_base, h.hash_table);
        ctx->dt_size = h.dt_size;
        ctx->ht_size = h.ht_size;
    } else {
        if (ctx->seed != h.seed ||
            ctx->data_table != MC_PTR_ADD(ctx->mmap_base, h.data_table) ||
            ctx->hash_table != MC_PTR_ADD(ctx->mmap_base, h.hash_table) ||
            ctx->dt_size != h.dt_size ||
            ctx->ht_size != h.ht_size) {
            return EINVAL;
        }
    }

    return 0;
}

static void sss_nss_mc_destroy_ctx(struct sss_cli_mc_ctx *ctx)
{

    if ((ctx->mmap_base != NULL) && (ctx->mmap_size != 0)) {
        munmap(ctx->mmap_base, ctx->mmap_size);
    }
    ctx->mmap_base = NULL;
    ctx->mmap_size = 0;

    if (ctx->fd != -1) {
        close(ctx->fd);
    }
    ctx->fd = -1;
    ctx->fd_inode = 0;
    ctx->fd_device = 0;

    ctx->seed = 0;
    ctx->data_table = NULL;
    ctx->dt_size = 0;
    ctx->hash_table = NULL;
    ctx->ht_size = 0;
    ctx->initialized = UNINITIALIZED;
    /* `mutex` and `active_threads` should be left intact */
}

static errno_t sss_nss_mc_init_ctx(const char *name,
                                   struct sss_cli_mc_ctx *ctx)
{
    struct stat fdstat;
    char *file = NULL;
    int ret;

    sss_mt_lock(ctx);
    /* check if ctx is initialised by previous thread. */
    if (ctx->initialized != UNINITIALIZED) {
        ret = sss_nss_check_header(ctx);
        goto done;
    }

    ret = asprintf(&file, "%s/%s", SSS_NSS_MCACHE_DIR, name);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    ctx->fd = sss_open_cloexec(file, O_RDONLY, &ret);
    if (ctx->fd == -1) {
        ret = EIO;
        goto done;
    }

    ret = fstat(ctx->fd, &fdstat);
    if (ret == -1) {
        ret = EIO;
        goto done;
    }
    ctx->fd_inode = fdstat.st_ino;
    ctx->fd_device = fdstat.st_dev;

    if (fdstat.st_size < MC_HEADER_SIZE) {
        ret = ENOMEM;
        goto done;
    }
    ctx->mmap_size = fdstat.st_size;

    ctx->mmap_base = mmap(NULL, ctx->mmap_size,
                          PROT_READ, MAP_SHARED, ctx->fd, 0);
    if (ctx->mmap_base == MAP_FAILED) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_nss_check_header(ctx);
    if (ret != 0) {
        goto done;
    }

    ctx->initialized = INITIALIZED;

    ret = 0;

done:
    if (ret) {
        sss_nss_mc_destroy_ctx(ctx);
    }
    free(file);
    sss_mt_unlock(ctx);

    return ret;
}

errno_t sss_nss_mc_get_ctx(const char *name, struct sss_cli_mc_ctx *ctx)
{
    char *envval;
    int ret;

    envval = getenv("SSS_NSS_USE_MEMCACHE");
    if (envval && strcasecmp(envval, "NO") == 0) {
        return EPERM;
    }

    __sync_add_and_fetch(&ctx->active_threads, 1);

    switch (ctx->initialized) {
    case UNINITIALIZED:
        ret = sss_nss_mc_init_ctx(name, ctx);
        break;
    case INITIALIZED:
        ret = sss_nss_check_header(ctx);
        break;
    case RECYCLED:
        /* we need to safely destroy memory cache */
        ret = EAGAIN;
        break;
    default:
        ret = EFAULT;
    }

    if (ret) {
        if (ctx->initialized == INITIALIZED) {
            ctx->initialized = RECYCLED;
        }
        if (ctx->initialized == RECYCLED &&
            (__sync_fetch_and_add(&ctx->active_threads, 0) == 1)) {
            /* just one thread should call munmap */
            sss_mt_lock(ctx);
            if (ctx->initialized == RECYCLED) {
                sss_nss_mc_destroy_ctx(ctx);
            }
            sss_mt_unlock(ctx);
        }
        /* In case of error, we will not touch mmapped area => decrement */
        __sync_sub_and_fetch(&ctx->active_threads, 1);
    }
    return ret;
}

uint32_t sss_nss_mc_hash(struct sss_cli_mc_ctx *ctx,
                         const char *key, size_t len)
{
    return murmurhash3(key, len, ctx->seed) % MC_HT_ELEMS(ctx->ht_size);
}

errno_t sss_nss_mc_get_record(struct sss_cli_mc_ctx *ctx,
                              uint32_t slot, struct sss_mc_rec **_rec)
{
    struct sss_mc_rec *rec;
    struct sss_mc_rec *copy_rec = NULL;
    size_t buf_size = 0;
    size_t rec_len;
    uint32_t b1;
    uint32_t b2;
    bool copy_ok;
    int count;
    int ret;

    /* try max 5 times */
    for (count = 5; count > 0; count--) {
        rec = MC_SLOT_TO_PTR(ctx->data_table, slot, struct sss_mc_rec);

        /* fetch record length */
        b1 = rec->b1;
        __sync_synchronize();
        rec_len = rec->len;
        __sync_synchronize();
        b2 = rec->b2;
        if (!MC_VALID_BARRIER(b1) || b1 != b2) {
            /* record is inconsistent, retry */
            continue;
        }

        if (!MC_CHECK_RECORD_LENGTH(ctx, rec)) {
            /* record has invalid length */
            free(copy_rec);
            return EINVAL;
        }

        if (rec_len > buf_size) {
            free(copy_rec);
            copy_rec = malloc(rec_len);
            if (!copy_rec) {
                ret = ENOMEM;
                goto done;
            }
            buf_size = rec_len;
        }
        /* we cannot access data directly, we must copy data and then
         * access the copy */
        MEMCPY_WITH_BARRIERS(copy_ok, copy_rec, rec, rec_len);

        /* we must check data is consistent again after the copy */
        if (copy_ok && b1 == copy_rec->b2) {
            /* record is consistent, use it */
            break;
        }
    }
    if (count == 0) {
        /* couldn't successfully read header we have to give up */
        ret = EIO;
        goto done;
    }

    *_rec = copy_rec;
    ret = 0;

done:
    if (ret) {
        free(copy_rec);
        *_rec = NULL;
    }
    return ret;
}

/*
 * returns strings from a buffer.
 *
 * Call first time with *cookie set to null, then call again
 * with the returned cookie.
 * On the last string the cookie will be reset to null and
 * all strings will have been returned.
 * In case the last string is not zero terminated EINVAL is returned.
 */
errno_t sss_nss_str_ptr_from_buffer(char **str, void **cookie,
                                    char *buf, size_t len)
{
    char *max = buf + len;
    char *ret;
    char *p;

    if (*cookie == NULL) {
        p = buf;
    } else {
        p = *((char **)cookie);
    }

    ret = p;

    while (p < max) {
        if (*p == '\0') {
            break;
        }
        p++;
    }
    if (p >= max) {
        return EINVAL;
    }
    p++;
    if (p == max) {
        *cookie = NULL;
    } else {
        *cookie = p;
    }

    *str = ret;
    return 0;
}

uint32_t sss_nss_mc_next_slot_with_hash(struct sss_mc_rec *rec,
                                        uint32_t hash)
{
    if (rec->hash1 == hash) {
        return rec->next1;
    } else if (rec->hash2 == hash) {
        return rec->next2;
    } else {
        /* it should never happen. */
        return MC_INVALID_VAL;
    }

}
