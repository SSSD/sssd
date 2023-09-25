/*
   SSSD

   NSS Responder - Mmap Cache

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2011

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

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "confdb/confdb.h"
#include <sys/mman.h>
#include <fcntl.h>
#include "util/mmap_cache.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "responder/nss/nss_private.h"
#include "responder/nss/nsssrv_mmap_cache.h"

#define MC_NEXT_BARRIER(val) ((((val) + 1) & 0x00ffffff) | 0xf0000000)

#define MC_RAISE_BARRIER(m) do { \
    m->b2 = MC_NEXT_BARRIER(m->b1); \
    __sync_synchronize(); \
} while (0)

#define MC_LOWER_BARRIER(m) do { \
    __sync_synchronize(); \
    m->b1 = m->b2; \
} while (0)

#define MC_RAISE_INVALID_BARRIER(m) do { \
    m->b2 = MC_INVALID_VAL; \
    __sync_synchronize(); \
} while (0)

struct sss_mc_ctx {
    char *name;             /* mmap cache name */
    enum sss_mc_type type;  /* mmap cache type */
    char *file;             /* mmap cache file name */
    int fd;                 /* file descriptor */

    uid_t uid;              /* User ID of owner */
    gid_t gid;              /* Group ID of owner */

    uint32_t seed;          /* pseudo-random seed to avoid collision attacks */
    time_t valid_time_slot; /* maximum time the entry is valid in seconds */

    void *mmap_base;        /* base address of mmap */
    size_t mmap_size;       /* total size of mmap */

    uint32_t *hash_table;   /* hash table address (in mmap) */
    uint32_t ht_size;       /* size of hash table */

    uint8_t *free_table;    /* free list bitmaps */
    uint32_t ft_size;       /* size of free table */
    uint32_t next_slot;     /* the next slot after last allocation done via erasure */

    uint8_t *data_table;    /* data table address (in mmap) */
    uint32_t dt_size;       /* size of data table */
};

#define MC_FIND_BIT(base, num) \
    uint32_t n = (num); \
    uint8_t *b = (base) + n / 8; \
    uint8_t c = 0x80 >> (n % 8);

#define MC_SET_BIT(base, num) do { \
    MC_FIND_BIT(base, num) \
    *b |= c; \
} while (0)

#define MC_CLEAR_BIT(base, num) do { \
    MC_FIND_BIT(base, num) \
    *b &= ~c; \
} while (0)

#define MC_PROBE_BIT(base, num, used) do { \
    MC_FIND_BIT(base, num) \
    if (*b & c) used = true; \
    else used = false; \
} while (0)

static inline
uint32_t sss_mc_next_slot_with_hash(struct sss_mc_rec *rec,
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

static inline
void sss_mc_chain_slot_to_record_with_hash(struct sss_mc_rec *rec,
                                           uint32_t hash,
                                           uint32_t slot)
{
    /* changing a single uint32_t is atomic, so there is no
     * need to use barriers in this case */
    if (rec->hash1 == hash) {
        rec->next1 = slot;
    } else if (rec->hash2 == hash) {
        rec->next2 = slot;
    }
}

/* This function will store corrupted memcache to disk for later
 * analysis. */
static void  sss_mc_save_corrupted(struct sss_mc_ctx *mc_ctx)
{
    int err;
    int fd = -1;
    ssize_t written = -1;
    char *file = NULL;
    TALLOC_CTX *tmp_ctx;

    if (mc_ctx == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Cannot store uninitialized cache. Nothing to do.\n");
        return;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory.\n");
        return;
    }

    file = talloc_asprintf(tmp_ctx, "%s_%s",
                           mc_ctx->file, "corrupted");
    if (file == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory.\n");
        goto done;
    }

    /* We will always store only the last problematic cache state */
    fd = creat(file, 0600);
    if (fd == -1) {
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to open file '%s' [%d]: %s\n",
               file, err, strerror(err));
        goto done;
    }

    written = sss_atomic_write_s(fd, mc_ctx->mmap_base, mc_ctx->mmap_size);
    if (written != mc_ctx->mmap_size) {
        if (written == -1) {
            err = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "write() failed [%d]: %s\n", err, strerror(err));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "write() returned %zd (expected (%zd))\n",
                   written, mc_ctx->mmap_size);
        }
        goto done;
    }

    sss_log(SSS_LOG_NOTICE,
            "Stored copy of corrupted mmap cache in file '%s\n'", file);
done:
    if (fd != -1) {
        close(fd);
        if (written == -1) {
            err = unlink(file);
            if (err != 0) {
                err = errno;
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to remove file '%s': %s.\n", file,
                       strerror(err));
            }
        }
    }
    talloc_free(tmp_ctx);
}

static uint32_t sss_mc_hash(struct sss_mc_ctx *mcc,
                            const char *key, size_t len)
{
    return murmurhash3(key, len, mcc->seed) % MC_HT_ELEMS(mcc->ht_size);
}

static void sss_mc_add_rec_to_chain(struct sss_mc_ctx *mcc,
                                    struct sss_mc_rec *rec,
                                    uint32_t hash)
{
    struct sss_mc_rec *cur;
    uint32_t slot;

    if (hash > MC_HT_ELEMS(mcc->ht_size)) {
        /* Invalid hash. This should never happen, but better
         * return than trying to access out of bounds memory */
        return;
    }

    slot = mcc->hash_table[hash];
    if (slot == MC_INVALID_VAL) {
        /* no previous record/collision, just add to hash table */
        mcc->hash_table[hash] = MC_PTR_TO_SLOT(mcc->data_table, rec);
        return;
    }

    do {
        cur = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
        if (cur == rec) {
            /* rec already stored in hash chain */
            return;
        }
        slot = sss_mc_next_slot_with_hash(cur, hash);
    } while (slot != MC_INVALID_VAL);
    /* end of chain, append our record here */

    slot = MC_PTR_TO_SLOT(mcc->data_table, rec);
    sss_mc_chain_slot_to_record_with_hash(cur, hash, slot);
}

static void sss_mc_rm_rec_from_chain(struct sss_mc_ctx *mcc,
                                     struct sss_mc_rec *rec,
                                     uint32_t hash)
{
    struct sss_mc_rec *prev = NULL;
    struct sss_mc_rec *cur = NULL;
    uint32_t slot;

    if (hash > MC_HT_ELEMS(mcc->ht_size)) {
        /* It can happen if rec->hash1 and rec->hash2 was the same.
         * or it is invalid hash. It is better to return
         * than trying to access out of bounds memory
         */
        return;
    }

    slot = mcc->hash_table[hash];
    if (slot == MC_INVALID_VAL) {
        /* record has already been removed. It may happen if rec->hash1 and
         * rec->has2 are the same. (It is not very likely).
         */
        return;
    }
    cur = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
    if (cur == rec) {
        mcc->hash_table[hash] = sss_mc_next_slot_with_hash(rec, hash);
    } else {
        slot = sss_mc_next_slot_with_hash(cur, hash);
        while (slot != MC_INVALID_VAL) {
            prev = cur;
            cur = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
            if (cur == rec) {
                slot = sss_mc_next_slot_with_hash(cur, hash);

                sss_mc_chain_slot_to_record_with_hash(prev, hash, slot);
                slot = MC_INVALID_VAL;
            } else {
                slot = sss_mc_next_slot_with_hash(cur, hash);
            }
        }
    }
}

static void sss_mc_free_slots(struct sss_mc_ctx *mcc, struct sss_mc_rec *rec)
{
    uint32_t slot;
    uint32_t num;
    uint32_t i;

    slot = MC_PTR_TO_SLOT(mcc->data_table, rec);
    num = MC_SIZE_TO_SLOTS(rec->len);
    for (i = 0; i < num; i++) {
        MC_CLEAR_BIT(mcc->free_table, slot + i);
    }
}

static void sss_mc_invalidate_rec(struct sss_mc_ctx *mcc,
                                  struct sss_mc_rec *rec)
{
    if (rec->b1 == MC_INVALID_VAL) {
        /* record already invalid */
        return;
    }

    /* Remove from hash chains */
    /* hash chain 1 */
    sss_mc_rm_rec_from_chain(mcc, rec, rec->hash1);
    /* hash chain 2 */
    sss_mc_rm_rec_from_chain(mcc, rec, rec->hash2);

    /* Clear from free_table */
    sss_mc_free_slots(mcc, rec);

    /* Invalidate record fields */
    MC_RAISE_INVALID_BARRIER(rec);
    memset(rec->data, MC_INVALID_VAL8, ((MC_SLOT_SIZE * MC_SIZE_TO_SLOTS(rec->len))
                                        - sizeof(struct sss_mc_rec)));
    rec->len = MC_INVALID_VAL32;
    rec->expire = MC_INVALID_VAL64;
    rec->next1 = MC_INVALID_VAL32;
    rec->next2 = MC_INVALID_VAL32;
    rec->hash1 = MC_INVALID_VAL32;
    rec->hash2 = MC_INVALID_VAL32;
    MC_LOWER_BARRIER(rec);
}

static bool sss_mc_is_valid_rec(struct sss_mc_ctx *mcc, struct sss_mc_rec *rec)
{
    struct sss_mc_rec *self;
    uint32_t slot;

    if (((uint8_t *)rec < mcc->data_table) ||
        ((uint8_t *)rec > (mcc->data_table + mcc->dt_size - MC_SLOT_SIZE))) {
        return false;
    }

    if ((rec->b1 == MC_INVALID_VAL) ||
        (rec->b1 != rec->b2)) {
        return false;
    }

    if (!MC_CHECK_RECORD_LENGTH(mcc, rec)) {
        return false;
    }

    if (rec->expire == MC_INVALID_VAL64) {
        return false;
    }

    /* next record can be invalid if there are no next records */

    if (rec->hash1 == MC_INVALID_VAL32) {
        return false;
    } else {
        self = NULL;
        slot = mcc->hash_table[rec->hash1];
        while (slot != MC_INVALID_VAL32 && self != rec) {
            self = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
            slot = sss_mc_next_slot_with_hash(self, rec->hash1);
        }
        if (self != rec) {
            return false;
        }
    }
    if (rec->hash2 != MC_INVALID_VAL32) {
        self = NULL;
        slot = mcc->hash_table[rec->hash2];
        while (slot != MC_INVALID_VAL32 && self != rec) {
            self = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
            slot = sss_mc_next_slot_with_hash(self, rec->hash2);
        }
        if (self != rec) {
            return false;
        }
    }

    /* all tests passed */
    return true;
}

static const char *mc_type_to_str(enum sss_mc_type type)
{
    switch (type) {
    case SSS_MC_PASSWD:
        return "PASSWD";
    case SSS_MC_GROUP:
        return "GROUP";
    case SSS_MC_INITGROUPS:
        return "INITGROUPS";
    case SSS_MC_SID:
        return "SID";
    default:
        return "-UNKNOWN-";
    }
}

/* FIXME: This is a very simplistic, inefficient, memory allocator,
 * it will just free the oldest entries regardless of expiration if it
 * cycled the whole free bits map and found no empty slot */
static errno_t sss_mc_find_free_slots(struct sss_mc_ctx *mcc,
                                      int num_slots, uint32_t *free_slot)
{
    struct sss_mc_rec *rec;
    uint32_t tot_slots;
    uint32_t cur;
    uint32_t i;
    uint32_t t;
    bool used;

    tot_slots = mcc->ft_size * 8;

    /* Try to find a free slot w/o removing anything first */
    /* FIXME: Is it really worth it? Maybe it is easier to
     * just recycle the next set of slots? */
    if ((mcc->next_slot + num_slots) > tot_slots) {
        cur = 0;
    } else {
        cur = mcc->next_slot;
    }

    /* search for enough (num_slots) consecutive zero bits, indicating
     * consecutive empty slots */
    for (i = 0; i < mcc->ft_size; i++) {
        t = cur / 8;
        /* if all full in this byte skip directly to the next */
        if (mcc->free_table[t] == 0xff) {
            cur = ((cur + 8) & ~7);
            if (cur >= tot_slots) {
                cur = 0;
            }
            continue;
        }

        /* at least one bit in this byte is marked as empty */
        for (t = ((cur + 8) & ~7) ; cur < t; cur++) {
            MC_PROBE_BIT(mcc->free_table, cur, used);
            if (!used) break;
        }
        /* check if we have enough slots before hitting the table end */
        if ((cur + num_slots) > tot_slots) {
            cur = 0;
            continue;
        }

        /* check if we have at least num_slots empty starting from the first
         * we found in the previous steps */
        for (t = cur + num_slots; cur < t; cur++) {
            MC_PROBE_BIT(mcc->free_table, cur, used);
            if (used) break;
        }
        if (cur == t) {
            /* ok found num_slots consecutive free bits */
            *free_slot = cur - num_slots;
            /* `mcc->next_slot` is not updated here intentionally.
             * For details see discussion in https://github.com/SSSD/sssd/pull/999
             */
            return EOK;
        }
    }

    /* no free slots found, free occupied slots after next_slot */
    if ((mcc->next_slot + num_slots) > tot_slots) {
        cur = 0;
    } else {
        cur = mcc->next_slot;
    }
    if (cur == 0) {
        /* inform only once per full loop to avoid excessive spam */
        DEBUG(SSSDBG_IMPORTANT_INFO, "mmap cache of type '%s' is full\n",
              mc_type_to_str(mcc->type));
        sss_log(SSS_LOG_NOTICE, "mmap cache of type '%s' is full, if you see "
                "this message often then please consider increase of cache size",
                mc_type_to_str(mcc->type));
    }
    for (i = 0; i < num_slots; i++) {
        MC_PROBE_BIT(mcc->free_table, cur + i, used);
        if (used) {
            /* the first used slot should be a record header, however we
             * carefully check it is a valid header and hardfail if not */
            rec = MC_SLOT_TO_PTR(mcc->data_table, cur + i, struct sss_mc_rec);
            if (!sss_mc_is_valid_rec(mcc, rec)) {
                /* this is a fatal error, the caller should probably just
                 * invalidate the whole cache */
                return EFAULT;
            }
            /* next loop skip the whole record */
            i += MC_SIZE_TO_SLOTS(rec->len) - 1;

            /* finally invalidate record completely */
            sss_mc_invalidate_rec(mcc, rec);
        }
    }

    mcc->next_slot = cur + num_slots;
    *free_slot = cur;
    return EOK;
}

static errno_t sss_mc_get_strs_offset(struct sss_mc_ctx *mcc,
                                      size_t *_offset)
{
    switch (mcc->type) {
    case SSS_MC_PASSWD:
        *_offset = offsetof(struct sss_mc_pwd_data, strs);
        return EOK;
    case SSS_MC_GROUP:
        *_offset = offsetof(struct sss_mc_grp_data, strs);
        return EOK;
    case SSS_MC_INITGROUPS:
        *_offset = offsetof(struct sss_mc_initgr_data, gids);
        return EOK;
    case SSS_MC_SID:
        *_offset = offsetof(struct sss_mc_sid_data, sid);
        return EOK;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE, "Unknown memory cache type.\n");
        return EINVAL;
    }
}

static errno_t sss_mc_get_strs_len(struct sss_mc_ctx *mcc,
                                   struct sss_mc_rec *rec,
                                   size_t *_len)
{
    switch (mcc->type) {
    case SSS_MC_PASSWD:
        *_len = ((struct sss_mc_pwd_data *)&rec->data)->strs_len;
        return EOK;
    case SSS_MC_GROUP:
        *_len = ((struct sss_mc_grp_data *)&rec->data)->strs_len;
        return EOK;
    case SSS_MC_INITGROUPS:
        *_len = ((struct sss_mc_initgr_data *)&rec->data)->data_len;
        return EOK;
    case SSS_MC_SID:
        *_len = ((struct sss_mc_sid_data *)&rec->data)->sid_len;
        return EOK;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE, "Unknown memory cache type.\n");
        return EINVAL;
    }
}

static struct sss_mc_rec *sss_mc_find_record(struct sss_mc_ctx *mcc,
                                             const struct sized_string *key)
{
    struct sss_mc_rec *rec = NULL;
    uint32_t hash;
    uint32_t slot;
    rel_ptr_t name_ptr;
    char *t_key;
    size_t strs_offset;
    size_t strs_len;
    uint8_t *max_addr;
    errno_t ret;

    hash = sss_mc_hash(mcc, key->str, key->len);

    slot = mcc->hash_table[hash];
    if (!MC_SLOT_WITHIN_BOUNDS(slot, mcc->dt_size)) {
        return NULL;
    }

    /* Get max address of data table. */
    max_addr = mcc->data_table + mcc->dt_size;

    ret = sss_mc_get_strs_offset(mcc, &strs_offset);
    if (ret != EOK) {
        return NULL;
    }

    while (slot != MC_INVALID_VAL) {
        if (!MC_SLOT_WITHIN_BOUNDS(slot, mcc->dt_size)) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Corrupted memcache. Slot number too big.\n");
            sss_mc_save_corrupted(mcc);
            sss_mmap_cache_reset(mcc);
            return NULL;
        }

        rec = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
        ret = sss_mc_get_strs_len(mcc, rec, &strs_len);
        if (ret != EOK) {
            return NULL;
        }

        if (key->len > strs_len) {
            /* The string cannot be in current record */
            slot = sss_mc_next_slot_with_hash(rec, hash);
            continue;
        }

        safealign_memcpy(&name_ptr, rec->data, sizeof(rel_ptr_t), NULL);
        t_key = (char *)rec->data + name_ptr;
        /* name_ptr must point to some data in the strs/gids area of the data
         * payload. Since it is a pointer relative to rec->data it must be
         * larger/equal to strs_offset and must be smaller then strs_offset + strs_len.
         * Additionally the area must not end outside of the data table and
         * t_key must be a zero-terminated string. */
        if (name_ptr < strs_offset
                || name_ptr >= strs_offset + strs_len
                || (uint8_t *)rec->data > max_addr
                || strs_offset > max_addr - (uint8_t *)rec->data
                || strs_len > max_addr - (uint8_t *)rec->data - strs_offset) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Corrupted memcache entry at slot %u. "
                  "name_ptr value is %u.\n", slot, name_ptr);
            sss_mc_save_corrupted(mcc);
            sss_mmap_cache_reset(mcc);
            return NULL;
        }

        if (strcmp(key->str, t_key) == 0) {
            return rec;
        }

        slot = sss_mc_next_slot_with_hash(rec, hash);
    }

    return NULL;
}

static errno_t sss_mc_get_record(struct sss_mc_ctx **_mcc,
                                 size_t rec_len,
                                 const struct sized_string *key,
                                 struct sss_mc_rec **_rec)
{
    struct sss_mc_ctx *mcc = *_mcc;
    struct sss_mc_rec *old_rec = NULL;
    struct sss_mc_rec *rec;
    int old_slots;
    int num_slots;
    uint32_t base_slot;
    errno_t ret;
    int i;

    num_slots = MC_SIZE_TO_SLOTS(rec_len);

    old_rec = sss_mc_find_record(mcc, key);
    if (old_rec) {
        old_slots = MC_SIZE_TO_SLOTS(old_rec->len);

        if (old_slots == num_slots) {
            *_rec = old_rec;
            return EOK;
        }

        /* slot size changed, invalidate record and fall through to get a
        * fully new record */
        sss_mc_invalidate_rec(mcc, old_rec);
    }

    /* we are going to use more space, find enough free slots */
    ret = sss_mc_find_free_slots(mcc, num_slots, &base_slot);
    if (ret != EOK) {
        if (ret == EFAULT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Fatal internal mmap cache error, invalidating cache!\n");
            (void)sss_mmap_cache_reinit(talloc_parent(mcc),
                                        -1, -1, -1, -1,
                                        _mcc);
        }
        return ret;
    }

    rec = MC_SLOT_TO_PTR(mcc->data_table, base_slot, struct sss_mc_rec);

    /* mark as not valid yet */
    MC_RAISE_INVALID_BARRIER(rec);
    rec->len = rec_len;
    rec->next1 = MC_INVALID_VAL;
    rec->next2 = MC_INVALID_VAL;
    rec->padding = MC_INVALID_VAL;
    MC_LOWER_BARRIER(rec);

    /* and now mark slots as used */
    for (i = 0; i < num_slots; i++) {
        MC_SET_BIT(mcc->free_table, base_slot + i);
    }

    *_rec = rec;
    return EOK;
}

static inline void sss_mmap_set_rec_header(struct sss_mc_ctx *mcc,
                                           struct sss_mc_rec *rec,
                                           size_t len, time_t ttl,
                                           const char *key1, size_t key1_len,
                                           const char *key2, size_t key2_len)
{
    rec->len = len;
    rec->expire = time(NULL) + ttl;
    rec->hash1 = sss_mc_hash(mcc, key1, key1_len);
    rec->hash2 = sss_mc_hash(mcc, key2, key2_len);
}

static inline void sss_mmap_chain_in_rec(struct sss_mc_ctx *mcc,
                                         struct sss_mc_rec *rec)
{
    /* name first */
    sss_mc_add_rec_to_chain(mcc, rec, rec->hash1);
    /* then uid/gid */
    sss_mc_add_rec_to_chain(mcc, rec, rec->hash2);
}

/***************************************************************************
 * generic invalidation
 ***************************************************************************/

static errno_t sss_mmap_cache_validate_or_reinit(struct sss_mc_ctx **_mcc);

static errno_t sss_mmap_cache_invalidate(struct sss_mc_ctx **_mcc,
                                         const struct sized_string *key)
{
    struct sss_mc_ctx *mcc;
    struct sss_mc_rec *rec;
    int ret;

    ret = sss_mmap_cache_validate_or_reinit(_mcc);
    if (ret != EOK) {
        return ret;
    }

    mcc = *_mcc;

    rec = sss_mc_find_record(mcc, key);
    if (rec == NULL) {
        /* nothing to invalidate */
        return ENOENT;
    }

    sss_mc_invalidate_rec(mcc, rec);

    return EOK;
}

static errno_t sss_mmap_cache_validate_or_reinit(struct sss_mc_ctx **_mcc)
{
    struct sss_mc_ctx *mcc = *_mcc;
    struct stat fdstat;
    bool reinit = false;
    errno_t ret;

    /* No mcc initialized? Memory cache may be disabled. */
    if (mcc == NULL || mcc->fd < 0) {
        ret = EINVAL;
        reinit = false;
        goto done;
    }

    if (fstat(mcc->fd, &fdstat) == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
            "Unable to stat memory cache [file=%s, fd=%d] [%d]: %s\n",
            mcc->file, mcc->fd, ret, sss_strerror(ret));
        reinit = true;
        goto done;
    }

    if (fdstat.st_nlink == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Memory cache file was removed\n");
        ret = ENOENT;
        reinit = true;
        goto done;
    }

    if (fdstat.st_size != mcc->mmap_size) {
        DEBUG(SSSDBG_CRIT_FAILURE,
            "Memory cache is corrupted, invalid size [file=%s, fd=%d, "
            "expected_size=%zu, real_size=%zu]\n",
            mcc->file, mcc->fd, mcc->mmap_size, fdstat.st_size);
        ret = EINVAL;
        reinit = true;
        goto done;
    }

    ret = EOK;
    reinit = false;

done:
    if (reinit) {
        return sss_mmap_cache_reinit(talloc_parent(mcc), -1, -1, -1, -1, _mcc);
    }

    return ret;
}

/***************************************************************************
 * passwd map
 ***************************************************************************/

errno_t sss_mmap_cache_pw_store(struct sss_mc_ctx **_mcc,
                                const struct sized_string *name,
                                const struct sized_string *pw,
                                uid_t uid, gid_t gid,
                                const struct sized_string *gecos,
                                const struct sized_string *homedir,
                                const struct sized_string *shell)
{
    struct sss_mc_ctx *mcc;
    struct sss_mc_rec *rec;
    struct sss_mc_pwd_data *data;
    struct sized_string uidkey;
    char uidstr[11];
    size_t data_len;
    size_t rec_len;
    size_t pos;
    int ret;

    ret = sss_mmap_cache_validate_or_reinit(_mcc);
    if (ret != EOK) {
        return ret;
    }

    mcc = *_mcc;

    ret = snprintf(uidstr, 11, "%ld", (long)uid);
    if (ret > 10) {
        return EINVAL;
    }
    to_sized_string(&uidkey, uidstr);

    data_len = name->len + pw->len + gecos->len + homedir->len + shell->len;
    rec_len = sizeof(struct sss_mc_rec) +
              sizeof(struct sss_mc_pwd_data) +
              data_len;
    if (rec_len > mcc->dt_size) {
        return ENOMEM;
    }

    ret = sss_mc_get_record(_mcc, rec_len, name, &rec);
    if (ret != EOK) {
        return ret;
    }

    data = (struct sss_mc_pwd_data *)rec->data;
    pos = 0;

    MC_RAISE_BARRIER(rec);

    /* header */
    sss_mmap_set_rec_header(mcc, rec, rec_len, mcc->valid_time_slot,
                            name->str, name->len, uidkey.str, uidkey.len);

    /* passwd struct */
    data->name = MC_PTR_DIFF(data->strs, data);
    data->uid = uid;
    data->gid = gid;
    data->strs_len = data_len;
    memcpy(&data->strs[pos], name->str, name->len);
    pos += name->len;
    memcpy(&data->strs[pos], pw->str, pw->len);
    pos += pw->len;
    memcpy(&data->strs[pos], gecos->str, gecos->len);
    pos += gecos->len;
    memcpy(&data->strs[pos], homedir->str, homedir->len);
    pos += homedir->len;
    memcpy(&data->strs[pos], shell->str, shell->len);

    MC_LOWER_BARRIER(rec);

    /* finally chain the rec in the hash table */
    sss_mmap_chain_in_rec(mcc, rec);

    return EOK;
}

errno_t sss_mmap_cache_pw_invalidate(struct sss_mc_ctx **_mcc,
                                     const struct sized_string *name)
{
    return sss_mmap_cache_invalidate(_mcc, name);
}

errno_t sss_mmap_cache_pw_invalidate_uid(struct sss_mc_ctx **_mcc, uid_t uid)
{
    struct sss_mc_ctx *mcc;
    struct sss_mc_rec *rec = NULL;
    struct sss_mc_pwd_data *data;
    uint32_t hash;
    uint32_t slot;
    char *uidstr;
    errno_t ret;

    ret = sss_mmap_cache_validate_or_reinit(_mcc);
    if (ret != EOK) {
        return ret;
    }

    mcc = *_mcc;

    uidstr = talloc_asprintf(NULL, "%ld", (long)uid);
    if (!uidstr) {
        return ENOMEM;
    }

    hash = sss_mc_hash(mcc, uidstr, strlen(uidstr) + 1);

    slot = mcc->hash_table[hash];
    if (!MC_SLOT_WITHIN_BOUNDS(slot, mcc->dt_size)) {
        ret = ENOENT;
        goto done;
    }

    while (slot != MC_INVALID_VAL) {
        if (!MC_SLOT_WITHIN_BOUNDS(slot, mcc->dt_size)) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Corrupted memcache.\n");
            sss_mc_save_corrupted(mcc);
            sss_mmap_cache_reset(mcc);
            ret = ENOENT;
            goto done;
        }

        rec = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
        data = (struct sss_mc_pwd_data *)(&rec->data);

        if (uid == data->uid) {
            break;
        }

        slot = sss_mc_next_slot_with_hash(rec, hash);
    }

    if (slot == MC_INVALID_VAL) {
        ret = ENOENT;
        goto done;
    }

    sss_mc_invalidate_rec(mcc, rec);

    ret = EOK;

done:
    talloc_zfree(uidstr);
    return ret;
}

/***************************************************************************
 * group map
 ***************************************************************************/

int sss_mmap_cache_gr_store(struct sss_mc_ctx **_mcc,
                            const struct sized_string *name,
                            const struct sized_string *pw,
                            gid_t gid, size_t memnum,
                            const char *membuf, size_t memsize)
{
    struct sss_mc_ctx *mcc;
    struct sss_mc_rec *rec;
    struct sss_mc_grp_data *data;
    struct sized_string gidkey;
    char gidstr[11];
    size_t data_len;
    size_t rec_len;
    size_t pos;
    int ret;

    ret = sss_mmap_cache_validate_or_reinit(_mcc);
    if (ret != EOK) {
        return ret;
    }

    mcc = *_mcc;

    ret = snprintf(gidstr, 11, "%ld", (long)gid);
    if (ret > 10) {
        return EINVAL;
    }
    to_sized_string(&gidkey, gidstr);

    data_len = name->len + pw->len + memsize;
    rec_len = sizeof(struct sss_mc_rec) +
              sizeof(struct sss_mc_grp_data) +
              data_len;
    if (rec_len > mcc->dt_size) {
        return ENOMEM;
    }

    ret = sss_mc_get_record(_mcc, rec_len, name, &rec);
    if (ret != EOK) {
        return ret;
    }

    data = (struct sss_mc_grp_data *)rec->data;
    pos = 0;

    MC_RAISE_BARRIER(rec);

    /* header */
    sss_mmap_set_rec_header(mcc, rec, rec_len, mcc->valid_time_slot,
                            name->str, name->len, gidkey.str, gidkey.len);

    /* group struct */
    data->name = MC_PTR_DIFF(data->strs, data);
    data->gid = gid;
    data->members = memnum;
    data->strs_len = data_len;
    memcpy(&data->strs[pos], name->str, name->len);
    pos += name->len;
    memcpy(&data->strs[pos], pw->str, pw->len);
    pos += pw->len;
    memcpy(&data->strs[pos], membuf, memsize);

    MC_LOWER_BARRIER(rec);

    /* finally chain the rec in the hash table */
    sss_mmap_chain_in_rec(mcc, rec);

    return EOK;
}

errno_t sss_mmap_cache_gr_invalidate(struct sss_mc_ctx **_mcc,
                                     const struct sized_string *name)
{
    return sss_mmap_cache_invalidate(_mcc, name);
}

errno_t sss_mmap_cache_gr_invalidate_gid(struct sss_mc_ctx **_mcc, gid_t gid)
{
    struct sss_mc_ctx *mcc;
    struct sss_mc_rec *rec = NULL;
    struct sss_mc_grp_data *data;
    uint32_t hash;
    uint32_t slot;
    char *gidstr;
    errno_t ret;

    ret = sss_mmap_cache_validate_or_reinit(_mcc);
    if (ret != EOK) {
        return ret;
    }

    mcc = *_mcc;

    gidstr = talloc_asprintf(NULL, "%ld", (long)gid);
    if (!gidstr) {
        return ENOMEM;
    }

    hash = sss_mc_hash(mcc, gidstr, strlen(gidstr) + 1);

    slot = mcc->hash_table[hash];
    if (!MC_SLOT_WITHIN_BOUNDS(slot, mcc->dt_size)) {
        ret = ENOENT;
        goto done;
    }

    while (slot != MC_INVALID_VAL) {
        if (!MC_SLOT_WITHIN_BOUNDS(slot, mcc->dt_size)) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Corrupted memcache.\n");
            sss_mc_save_corrupted(mcc);
            sss_mmap_cache_reset(mcc);
            ret = ENOENT;
            goto done;
        }

        rec = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
        data = (struct sss_mc_grp_data *)(&rec->data);

        if (gid == data->gid) {
            break;
        }

        slot = sss_mc_next_slot_with_hash(rec, hash);
    }

    if (slot == MC_INVALID_VAL) {
        ret = ENOENT;
        goto done;
    }

    sss_mc_invalidate_rec(mcc, rec);

    ret = EOK;

done:
    talloc_zfree(gidstr);
    return ret;
}

errno_t sss_mmap_cache_initgr_store(struct sss_mc_ctx **_mcc,
                                    const struct sized_string *name,
                                    const struct sized_string *unique_name,
                                    uint32_t num_groups,
                                    const uint8_t *gids_buf)
{
    struct sss_mc_ctx *mcc;
    struct sss_mc_rec *rec;
    struct sss_mc_initgr_data *data;
    size_t data_len;
    size_t rec_len;
    size_t pos;
    int ret;

    ret = sss_mmap_cache_validate_or_reinit(_mcc);
    if (ret != EOK) {
        return ret;
    }

    mcc = *_mcc;

    /* array of gids + name + unique_name */
    data_len = num_groups * sizeof(uint32_t) + name->len + unique_name->len;
    rec_len = sizeof(struct sss_mc_rec) + sizeof(struct sss_mc_initgr_data)
              + data_len;
    if (rec_len > mcc->dt_size) {
        return ENOMEM;
    }

    /* use unique name for searching potential old records */
    ret = sss_mc_get_record(_mcc, rec_len, unique_name, &rec);
    if (ret != EOK) {
        return ret;
    }

    data = (struct sss_mc_initgr_data *)rec->data;
    pos = 0;

    MC_RAISE_BARRIER(rec);

    sss_mmap_set_rec_header(mcc, rec, rec_len, mcc->valid_time_slot,
                            name->str, name->len,
                            unique_name->str, unique_name->len);

    /* initgroups struct */
    data->strs_len = name->len + unique_name->len;
    data->data_len = data_len;
    data->num_groups = num_groups;
    memcpy((char *)data->gids + pos, gids_buf, num_groups * sizeof(uint32_t));
    pos += num_groups * sizeof(uint32_t);

    memcpy((char *)data->gids + pos, unique_name->str, unique_name->len);
    data->strs = data->unique_name = MC_PTR_DIFF((char *)data->gids + pos, data);
    pos += unique_name->len;

    memcpy((char *)data->gids + pos, name->str, name->len);
    data->name = MC_PTR_DIFF((char *)data->gids + pos, data);

    MC_LOWER_BARRIER(rec);

    /* finally chain the rec in the hash table */
    sss_mmap_chain_in_rec(mcc, rec);

    return EOK;
}

errno_t sss_mmap_cache_initgr_invalidate(struct sss_mc_ctx **_mcc,
                                         const struct sized_string *name)
{
    return sss_mmap_cache_invalidate(_mcc, name);
}

errno_t sss_mmap_cache_sid_store(struct sss_mc_ctx **_mcc,
                                 const struct sized_string *sid,
                                 uint32_t id,
                                 uint32_t type,
                                 bool explicit_lookup)
{
    struct sss_mc_ctx *mcc;
    struct sss_mc_rec *rec;
    struct sss_mc_sid_data *data;
    char idkey[16];
    size_t rec_len;
    int ret;

    ret = sss_mmap_cache_validate_or_reinit(_mcc);
    if (ret != EOK) {
        return ret;
    }

    mcc = *_mcc;

    ret = snprintf(idkey, sizeof(idkey), "%d-%ld",
                   (type == SSS_ID_TYPE_GID) ? SSS_ID_TYPE_GID : SSS_ID_TYPE_UID,
                   (long)id);
    if (ret > (sizeof(idkey) - 1)) {
        return EINVAL;
    }

    rec_len = sizeof(struct sss_mc_rec) +
              sizeof(struct sss_mc_sid_data) +
              sid->len;

    ret = sss_mc_get_record(_mcc, rec_len, sid, &rec);
    if (ret != EOK) {
        return ret;
    }

    data = (struct sss_mc_sid_data *)rec->data;
    MC_RAISE_BARRIER(rec);

    sss_mmap_set_rec_header(mcc, rec, rec_len, mcc->valid_time_slot,
                            sid->str, sid->len, idkey, strlen(idkey) + 1);

    data->name = MC_PTR_DIFF(data->sid, data);
    data->type = type;
    data->id = id;
    data->populated_by = (explicit_lookup ? 1 : 0);
    data->sid_len = sid->len;
    memcpy(data->sid, sid->str, sid->len);

    MC_LOWER_BARRIER(rec);
    sss_mmap_chain_in_rec(mcc, rec);

    return EOK;
}

/***************************************************************************
 * initialization
 ***************************************************************************/

/* Copy of sss_mc_set_recycled is present in the src/tools/tools_mc_util.c.
 * If you modify this function, you should modify the duplicated function
 * too. */
static errno_t sss_mc_set_recycled(int fd)
{
    uint32_t w = SSS_MC_HEADER_RECYCLED;
    off_t offset;
    off_t pos;
    ssize_t written;

    offset = offsetof(struct sss_mc_header, status);

    pos = lseek(fd, offset, SEEK_SET);
    if (pos == -1) {
        /* What do we do now? */
        return errno;
    }

    errno = 0;
    written = sss_atomic_write_s(fd, (uint8_t *)&w, sizeof(w));
    if (written == -1) {
        return errno;
    }

    if (written != sizeof(w)) {
        /* Write error */
        return EIO;
    }

    return EOK;
}

static void sss_mc_destroy_file(const char *filename)
{
    const useconds_t t = 50000;
    const int retries = 3;
    int ofd;
    int ret;

    ofd = open(filename, O_RDWR);
    if (ofd != -1) {
        ret = sss_br_lock_file(ofd, 0, 1, retries, t);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to lock file %s.\n", filename);
        }
        ret = sss_mc_set_recycled(ofd);
        if (ret) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to mark mmap file %s as"
                                         " recycled: %d (%s)\n",
                                         filename, ret, strerror(ret));
        }
        close(ofd);
    } else if (errno != ENOENT) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to open old memory cache file %s: %d (%s)\n",
               filename, ret, strerror(ret));
    }

    errno = 0;
    ret = unlink(filename);
    if (ret == -1 && errno != ENOENT) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "Failed to delete mmap file %s: %d (%s)\n",
                                  filename, ret, strerror(ret));
    }
}

static errno_t sss_mc_create_file(struct sss_mc_ctx *mc_ctx)
{
    const useconds_t t = 50000;
    const int retries = 3;
    mode_t old_mask;
    int ret, uret;

    /* temporarily relax umask as we need the file to be readable
     * by everyone and writeable by group */
    old_mask = umask(0002);

    errno = 0;
    mc_ctx->fd = open(mc_ctx->file, O_CREAT | O_EXCL | O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
    umask(old_mask);
    if (mc_ctx->fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to open mmap file %s: %d(%s)\n",
                                    mc_ctx->file, ret, strerror(ret));
        return ret;
    }

    /* Make sure that the memory cache files are chowned to sssd.sssd even
     * if the nss responder runs as root. This is because the specfile
     * has the ownership recorded as sssd.sssd
     */
    if ((getuid() == 0) || (geteuid() == 0)) {
        ret = fchown(mc_ctx->fd, mc_ctx->uid, mc_ctx->gid);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to chown mmap file %s: %d(%s)\n",
                                       mc_ctx->file, ret, strerror(ret));
            return ret;
        }
    }

    ret = sss_br_lock_file(mc_ctx->fd, 0, 1, retries, t);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to lock file %s.\n", mc_ctx->file);
        close(mc_ctx->fd);
        mc_ctx->fd = -1;

        /* Report on unlink failures but don't overwrite the errno
         * from sss_br_lock_file
         */
        errno = 0;
        uret = unlink(mc_ctx->file);
        if (uret == -1) {
            uret = errno;
            DEBUG(SSSDBG_TRACE_FUNC, "Failed to rm mmap file %s: %d(%s)\n",
                                    mc_ctx->file, uret, strerror(uret));
        }

        return ret;
    }

    return ret;
}

static void sss_mc_header_update(struct sss_mc_ctx *mc_ctx, int status)
{
    struct sss_mc_header *h;

    /* update header using barriers */
    h = (struct sss_mc_header *)mc_ctx->mmap_base;
    MC_RAISE_BARRIER(h);
    if (status == SSS_MC_HEADER_ALIVE) {
        /* no reason to update anything else if the file is recycled or
         * right before reset */
        h->hash_table = MC_PTR_DIFF(mc_ctx->hash_table, mc_ctx->mmap_base);
        h->free_table = MC_PTR_DIFF(mc_ctx->free_table, mc_ctx->mmap_base);
        h->data_table = MC_PTR_DIFF(mc_ctx->data_table, mc_ctx->mmap_base);
        h->ht_size = mc_ctx->ht_size;
        h->ft_size = mc_ctx->ft_size;
        h->dt_size = mc_ctx->dt_size;
        h->major_vno = SSS_MC_MAJOR_VNO;
        h->minor_vno = SSS_MC_MINOR_VNO;
        h->seed = mc_ctx->seed;
        h->reserved = 0;
    }
    h->status = status;
    MC_LOWER_BARRIER(h);
}

static int mc_ctx_destructor(struct sss_mc_ctx *mc_ctx)
{
    int ret;

    /* Print debug message to logs if munmap() or close()
     * fail but always return 0 */

    if (mc_ctx->mmap_base != NULL) {
        ret = munmap(mc_ctx->mmap_base, mc_ctx->mmap_size);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to unmap old memory cache file."
                   "[%d]: %s\n", ret, strerror(ret));
        }
    }

    if (mc_ctx->fd != -1) {
        ret = close(mc_ctx->fd);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to close old memory cache file."
                   "[%d]: %s\n", ret, strerror(ret));
        }
    }

    return 0;
}

#define POSIX_FALLOCATE_ATTEMPTS 3

errno_t sss_mmap_cache_init(TALLOC_CTX *mem_ctx, const char *name,
                            uid_t uid, gid_t gid,
                            enum sss_mc_type type, size_t n_elem,
                            time_t timeout, struct sss_mc_ctx **mcc)
{
    /* sss_mc_rec alone occupies whole slot,
     * so each entry takes 2 slots at the very least
     */
    static const int PAYLOAD_FACTOR = 2;

    struct sss_mc_ctx *mc_ctx = NULL;
    int ret, dret;
    char *filename;

    filename = talloc_asprintf(mem_ctx, "%s/%s", SSS_NSS_MCACHE_DIR, name);
    if (!filename) {
        return ENOMEM;
    }
    /*
     * First of all mark the current file as recycled
     * and unlink so active clients will abandon its use ASAP
     */
    sss_mc_destroy_file(filename);

    if ((timeout == 0) || (n_elem == 0)) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Fast '%s' mmap cache is explicitly DISABLED\n",
              mc_type_to_str(type));
        *mcc = NULL;
        return EOK;
    }
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Fast '%s' mmap cache: memcache_timeout = %"SPRItime", slots = %zu\n",
          mc_type_to_str(type), timeout, n_elem);

    mc_ctx = talloc_zero(mem_ctx, struct sss_mc_ctx);
    if (!mc_ctx) {
        talloc_free(filename);
        return ENOMEM;
    }
    mc_ctx->fd = -1;
    talloc_set_destructor(mc_ctx, mc_ctx_destructor);

    mc_ctx->name = talloc_strdup(mc_ctx, name);
    if (!mc_ctx->name) {
        ret = ENOMEM;
        goto done;
    }

    mc_ctx->uid = uid;
    mc_ctx->gid = gid;

    mc_ctx->type = type;

    mc_ctx->valid_time_slot = timeout;

    mc_ctx->file = talloc_steal(mc_ctx, filename);

    /* elements must always be multiple of 8 to make things easier to handle,
     * so we increase by the necessary amount if they are not a multiple */
    /* We can use MC_ALIGN64 for this */
    n_elem = MC_ALIGN64(n_elem);

    /* hash table is double the size because it will store both forward and
     * reverse keys (name/uid, name/gid, ..) */
    mc_ctx->ht_size = MC_HT_SIZE(2 * n_elem / PAYLOAD_FACTOR);
    mc_ctx->dt_size = n_elem * MC_SLOT_SIZE;
    mc_ctx->ft_size = n_elem / 8; /* 1 bit per slot */
    mc_ctx->mmap_size = MC_HEADER_SIZE +
                        MC_ALIGN64(mc_ctx->dt_size) +
                        MC_ALIGN64(mc_ctx->ft_size) +
                        MC_ALIGN64(mc_ctx->ht_size);


    ret = sss_mc_create_file(mc_ctx);
    if (ret) {
        goto done;
    }

    /* Attempt allocation several times, in case of EINTR */
    for (int i = 0; i < POSIX_FALLOCATE_ATTEMPTS; i++) {
        ret = posix_fallocate(mc_ctx->fd, 0, mc_ctx->mmap_size);
        if (ret != EINTR)
            break;
    }
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate file %s: %d(%s)\n",
                                    mc_ctx->file, ret, strerror(ret));
        goto done;
    }

    mc_ctx->mmap_base = mmap(NULL, mc_ctx->mmap_size,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED, mc_ctx->fd, 0);
    if (mc_ctx->mmap_base == MAP_FAILED) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to mmap file %s(%zu): %d(%s)\n",
                                    mc_ctx->file, mc_ctx->mmap_size,
                                    ret, strerror(ret));
        goto done;
    }

    mc_ctx->data_table = MC_PTR_ADD(mc_ctx->mmap_base, MC_HEADER_SIZE);
    mc_ctx->free_table = MC_PTR_ADD(mc_ctx->data_table,
                                    MC_ALIGN64(mc_ctx->dt_size));
    mc_ctx->hash_table = MC_PTR_ADD(mc_ctx->free_table,
                                    MC_ALIGN64(mc_ctx->ft_size));

    memset(mc_ctx->data_table, 0xff, mc_ctx->dt_size);
    memset(mc_ctx->free_table, 0x00, mc_ctx->ft_size);
    memset(mc_ctx->hash_table, 0xff, mc_ctx->ht_size);

    /* generate a pseudo-random seed.
     * Needed to fend off dictionary based collision attacks */
    ret = sss_generate_csprng_buffer((uint8_t *)&mc_ctx->seed, sizeof(mc_ctx->seed));
    if (ret != EOK) {
        goto done;
    }

    sss_mc_header_update(mc_ctx, SSS_MC_HEADER_ALIVE);

    ret = EOK;

done:
    if (ret) {
        /* Closing the file descriptor and unmapping the file
         * from memory is done in the mc_ctx_destructor. */
        if (mc_ctx && mc_ctx->file && mc_ctx->fd != -1) {
            dret = unlink(mc_ctx->file);
            if (dret == -1) {
                dret = errno;
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to rm mmap file %s: %d(%s)\n", mc_ctx->file,
                       dret, strerror(dret));
            }
        }

        talloc_free(mc_ctx);
    } else {
        *mcc = mc_ctx;
    }
    return ret;
}

errno_t sss_mmap_cache_reinit(TALLOC_CTX *mem_ctx,
                              uid_t uid, gid_t gid,
                              size_t n_elem,
                              time_t timeout, struct sss_mc_ctx **mc_ctx)
{
    errno_t ret;
    TALLOC_CTX* tmp_ctx = NULL;
    char *name;
    enum sss_mc_type type;

    if (mc_ctx == NULL || (*mc_ctx) == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to re-init uninitialized memory cache.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory.\n");
        return ENOMEM;
    }

    name = talloc_strdup(tmp_ctx, (*mc_ctx)->name);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory.\n");
        ret = ENOMEM;
        goto done;
    }

    type = (*mc_ctx)->type;

    if (n_elem == (size_t)-1) {
        n_elem = (*mc_ctx)->ft_size * 8;
    }

    if (timeout == (time_t)-1) {
        timeout = (*mc_ctx)->valid_time_slot;
    }

    if (uid == (uid_t)-1) {
        uid = (*mc_ctx)->uid;
    }

    if (gid == (gid_t)-1) {
        gid = (*mc_ctx)->gid;
    }

    talloc_free(*mc_ctx);

    /* make sure we do not leave a potentially freed pointer around */
    *mc_ctx = NULL;

    ret = sss_mmap_cache_init(mem_ctx,
                              name,
                              uid, gid,
                              type,
                              n_elem,
                              timeout,
                              mc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to re-initialize mmap cache.\n");
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* Erase all contents of the mmap cache. This will bring the cache
 * to the same state as if it was just initialized. */
void sss_mmap_cache_reset(struct sss_mc_ctx *mc_ctx)
{
    if (mc_ctx == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Fastcache not initialized. Nothing to do.\n");
        return;
    }

    sss_mc_header_update(mc_ctx, SSS_MC_HEADER_UNINIT);

    /* Reset the mmapped area */
    memset(mc_ctx->data_table, 0xff, mc_ctx->dt_size);
    memset(mc_ctx->free_table, 0x00, mc_ctx->ft_size);
    memset(mc_ctx->hash_table, 0xff, mc_ctx->ht_size);

    sss_mc_header_update(mc_ctx, SSS_MC_HEADER_ALIVE);
}
