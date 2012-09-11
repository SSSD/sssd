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
#include "confdb/confdb.h"
#include <sys/mman.h>
#include <fcntl.h>
#include "util/mmap_cache.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_mmap_cache.h"

/* arbitrary (avg of my /etc/passwd) */
#define SSS_AVG_PASSWD_PAYLOAD (MC_SLOT_SIZE * 4)
/* short group name and no gids (private user group */
#define SSS_AVG_GROUP_PAYLOAD (MC_SLOT_SIZE * 3)

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

    uint32_t seed;          /* pseudo-random seed to avoid collision attacks */
    time_t valid_time_slot; /* maximum time the entry is valid in seconds */

    void *mmap_base;        /* base address of mmap */
    size_t mmap_size;       /* total size of mmap */

    uint32_t *hash_table;   /* hash table address (in mmap) */
    uint32_t ht_size;       /* size of hash table */

    uint8_t *free_table;    /* free list bitmaps */
    uint32_t ft_size;       /* size of free table */
    uint32_t next_slot;     /* the next slot after last allocation */

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
        slot = cur->next;
    } while (slot != MC_INVALID_VAL);
    /* end of chain, append our record here */

    /* changing a single uint32_t is atomic, so there is no
     * need to use barriers in this case */
    cur->next = MC_PTR_TO_SLOT(mcc->data_table, rec);
}

static void sss_mc_rm_rec_from_chain(struct sss_mc_ctx *mcc,
                                     struct sss_mc_rec *rec,
                                     uint32_t hash)
{
    struct sss_mc_rec *prev = NULL;
    struct sss_mc_rec *cur = NULL;
    uint32_t slot;

    slot = mcc->hash_table[hash];
    cur = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
    if (cur == rec) {
        mcc->hash_table[hash] = rec->next;
    } else {
        slot = cur->next;
        while (slot != MC_INVALID_VAL) {
            prev = cur;
            cur = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
            if (cur == rec) {
                /* changing a single uint32_t is atomic, so there is no
                 * need to use barriers in this case */
                prev->next = cur->next;
                slot = MC_INVALID_VAL;
            } else {
                slot = cur->next;
            }
        }
    }
}

static void sss_mc_invalidate_rec(struct sss_mc_ctx *mcc,
                                  struct sss_mc_rec *rec)
{
    if (rec->b1 == MC_INVALID_VAL) {
        /* record already invalid */
        return;
    }

    /* hash chain 1 */
    sss_mc_rm_rec_from_chain(mcc, rec, rec->hash1);
    /* hash chain 2 */
    sss_mc_rm_rec_from_chain(mcc, rec, rec->hash2);

    MC_RAISE_INVALID_BARRIER(rec);
    memset(rec->data, 'X', rec->len - sizeof(struct sss_mc_rec));
    rec->len = MC_INVALID_VAL;
    rec->expire = (uint64_t)-1;
    rec->next = MC_INVALID_VAL;
    rec->hash1 = MC_INVALID_VAL;
    rec->hash2 = MC_INVALID_VAL;
    MC_LOWER_BARRIER(rec);
}

/* FIXME: This is a very simplistic, inefficient, memory allocator,
 * it will just free the oldest entries regardless of expiration if it
 * cycled the whole freebits map and found no empty slot */
static int sss_mc_find_free_slots(struct sss_mc_ctx *mcc, int num_slots)
{
    struct sss_mc_rec *rec;
    uint32_t tot_slots;
    uint32_t cur;
    uint32_t i;
    uint32_t t;
    bool used;

    tot_slots = mcc->ft_size * 8;

    /* Try to find a free slot w/o removing a nything first */
    /* FIXME: is it really worth it ? May be it is easier to
     * just recycle the next set of slots ? */
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
            return cur - num_slots;
        }
    }

    /* no free slots found, free occupied slots after next_slot */
    if ((mcc->next_slot + num_slots) > tot_slots) {
        cur = 0;
    } else {
        cur = mcc->next_slot;
    }
    for (i = 0; i < num_slots; i++) {
        MC_PROBE_BIT(mcc->free_table, cur + i, used);
        if (!used) continue;

        rec = MC_SLOT_TO_PTR(mcc->data_table, cur + i, struct sss_mc_rec);
        for (t = i + MC_SIZE_TO_SLOTS(rec->len); i < t; i++) {
            MC_CLEAR_BIT(mcc->free_table, cur + i);
        }
        sss_mc_invalidate_rec(mcc, rec);
    }

    mcc->next_slot = cur + num_slots;
    return cur;
}

static struct sss_mc_rec *sss_mc_find_record(struct sss_mc_ctx *mcc,
                                             struct sized_string *key)
{
    struct sss_mc_rec *rec;
    uint32_t hash;
    uint32_t slot;
    rel_ptr_t name_ptr;
    char *t_key;

    hash = sss_mc_hash(mcc, key->str, key->len);

    slot = mcc->hash_table[hash];
    if (slot > MC_SIZE_TO_SLOTS(mcc->dt_size)) {
        return NULL;
    }

    while (slot != MC_INVALID_VAL) {
        rec = MC_SLOT_TO_PTR(mcc->data_table, slot, struct sss_mc_rec);
        name_ptr = *((rel_ptr_t *)rec->data);

        t_key = (char *)rec->data + name_ptr;
        if (strcmp(key->str, t_key) == 0) {
            break;
        }

        slot = rec->next;
    }

    if (slot == MC_INVALID_VAL) {
        return NULL;
    }

    return rec;
}

static struct sss_mc_rec *sss_mc_get_record(struct sss_mc_ctx *mcc,
                                            size_t rec_len,
                                            struct sized_string *key)
{
    struct sss_mc_rec *old_rec = NULL;
    struct sss_mc_rec *rec;
    int old_slots;
    int num_slots;
    uint32_t base_slot;
    int i;

    num_slots = MC_SIZE_TO_SLOTS(rec_len);

    old_rec = sss_mc_find_record(mcc, key);
    if (old_rec) {
        old_slots = MC_SIZE_TO_SLOTS(old_rec->len);

        if (old_slots == num_slots) {
            return old_rec;
        }

        /* slot size changed, invalidate record and fall through to get a
        * fully new record */
        base_slot = MC_PTR_TO_SLOT(mcc->data_table, old_rec);
        sss_mc_invalidate_rec(mcc, old_rec);

        /* and now free slots */
        for (i = 0; i < old_slots; i++) {
            MC_CLEAR_BIT(mcc->free_table, base_slot + i);
        }
    }

    /* we are going to use more space, find enough free slots */
    base_slot = sss_mc_find_free_slots(mcc, num_slots);

    rec = MC_SLOT_TO_PTR(mcc->data_table, base_slot, struct sss_mc_rec);

    /* mark as not valid yet */
    MC_RAISE_INVALID_BARRIER(rec);
    rec->len = rec_len;
    rec->next = MC_INVALID_VAL;
    MC_LOWER_BARRIER(rec);

    /* and now mark slots as used */
    for (i = 0; i < num_slots; i++) {
        MC_SET_BIT(mcc->free_table, base_slot + i);
    }

    return rec;
}


/***************************************************************************
 * passwd map
 ***************************************************************************/

errno_t sss_mmap_cache_pw_store(struct sss_mc_ctx *mcc,
                                struct sized_string *name,
                                struct sized_string *pw,
                                uid_t uid, gid_t gid,
                                struct sized_string *gecos,
                                struct sized_string *homedir,
                                struct sized_string *shell)
{
    struct sss_mc_rec *rec;
    struct sss_mc_pwd_data *data;
    struct sized_string uidkey;
    char uidstr[11];
    size_t data_len;
    size_t rec_len;
    size_t pos;
    int ret;

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

    rec = sss_mc_get_record(mcc, rec_len, name);

    data = (struct sss_mc_pwd_data *)rec->data;
    pos = 0;

    MC_RAISE_BARRIER(rec);

    /* header */
    rec->len = rec_len;
    rec->expire = time(NULL) + mcc->valid_time_slot;
    rec->hash1 = sss_mc_hash(mcc, name->str, name->len);
    rec->hash2 = sss_mc_hash(mcc, uidkey.str, uidkey.len);

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
    pos += shell->len;

    MC_LOWER_BARRIER(rec);

    /* finally chain the rec in the hash table */
    /* name hash first */
    sss_mc_add_rec_to_chain(mcc, rec, rec->hash1);
    /* then uid */
    sss_mc_add_rec_to_chain(mcc, rec, rec->hash2);

    return EOK;
}


/***************************************************************************
 * group map
 ***************************************************************************/

int sss_mmap_cache_gr_store(struct sss_mc_ctx *mcc,
                            struct sized_string *name,
                            struct sized_string *pw,
                            gid_t gid, size_t memnum,
                            char *membuf, size_t memsize)
{
    struct sss_mc_rec *rec;
    struct sss_mc_grp_data *data;
    struct sized_string gidkey;
    char gidstr[11];
    size_t data_len;
    size_t rec_len;
    size_t pos;
    int ret;

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

    rec = sss_mc_get_record(mcc, rec_len, name);

    data = (struct sss_mc_grp_data *)rec->data;
    pos = 0;

    MC_RAISE_BARRIER(rec);

    /* header */
    rec->len = rec_len;
    rec->expire = time(NULL) + mcc->valid_time_slot;
    rec->hash1 = sss_mc_hash(mcc, name->str, name->len);
    rec->hash2 = sss_mc_hash(mcc, gidkey.str, gidkey.len);

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
    pos += memsize;

    MC_LOWER_BARRIER(rec);

    /* finally chain the rec in the hash table */
    /* name hash first */
    sss_mc_add_rec_to_chain(mcc, rec, rec->hash1);
    /* then gid */
    sss_mc_add_rec_to_chain(mcc, rec, rec->hash2);

    return EOK;
}


/***************************************************************************
 * initialization
 ***************************************************************************/

static errno_t sss_mc_set_recycled(int fd)
{
    uint32_t w = SSS_MC_HEADER_RECYCLED;
    struct sss_mc_header h;
    off_t offset;
    off_t pos;
    int ret;

    offset = MC_PTR_DIFF(&h.status, &h);

    pos = lseek(fd, offset, SEEK_SET);
    if (pos == -1) {
        /* What do we do now ? */
        return errno;
    }

    errno = 0;
    ret = sss_atomic_write_s(fd, (uint8_t *)&w, sizeof(h.status));
    if (ret == -1) {
        return errno;
    }

    if (ret != sizeof(h.status)) {
        /* Write error */
        return EIO;
    }

    return EOK;
}

/*
 * When we (re)create a new file we must mark the current file as recycled
 * so active clients will abandon its use asap.
 * We unlink the current file and make a new one
 */
static errno_t sss_mc_create_file(struct sss_mc_ctx *mc_ctx)
{
    mode_t old_mask;
    int ofd;
    int ret;

    ofd = open(mc_ctx->file, O_RDWR);
    if (ofd != -1) {
        ret = sss_mc_set_recycled(ofd);
        if (ret) {
            DEBUG(SSSDBG_TRACE_FUNC, ("Failed to mark mmap file %s as"
                                      " recycled: %d(%s)\n",
                                      mc_ctx->file, ret, strerror(ret)));
        }

        close(ofd);
    }

    errno = 0;
    ret = unlink(mc_ctx->file);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, ("Failed to rm mmap file %s: %d(%s)\n",
                                  mc_ctx->file, ret, strerror(ret)));
    }

    /* temporarily relax umask as we need the file to be readable
     * by everyone for now */
    old_mask = umask(0022);

    ret = 0;
    mc_ctx->fd = open(mc_ctx->file, O_CREAT | O_EXCL | O_RDWR, 0644);
    if (mc_ctx->fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to open mmap file %s: %d(%s)\n",
                                    mc_ctx->file, ret, strerror(ret)));
    }

    /* reset mask back */
    umask(old_mask);

    return ret;
}

static void sss_mc_header_update(struct sss_mc_ctx *mc_ctx, int status)
{
    struct sss_mc_header *h;

    /* update header using barriers */
    h = (struct sss_mc_header *)mc_ctx->mmap_base;
    MC_RAISE_BARRIER(h);
    if (status != SSS_MC_HEADER_RECYCLED) {
        /* no reason to update anything else if the file is recycled */
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

errno_t sss_mmap_cache_init(TALLOC_CTX *mem_ctx, const char *name,
                            enum sss_mc_type type, size_t n_elem,
                            time_t timeout, struct sss_mc_ctx **mcc)
{
    struct sss_mc_ctx *mc_ctx = NULL;
    unsigned int rseed;
    int payload;
    int ret;

    switch (type) {
    case SSS_MC_PASSWD:
        payload = SSS_AVG_PASSWD_PAYLOAD;
        break;
    case SSS_MC_GROUP:
        payload = SSS_AVG_GROUP_PAYLOAD;
        break;
    default:
        return EINVAL;
    }

    mc_ctx = talloc_zero(mem_ctx, struct sss_mc_ctx);
    if (!mc_ctx) {
        return ENOMEM;
    }
    mc_ctx->fd = -1;

    mc_ctx->name = talloc_strdup(mem_ctx, name);
    if (!mc_ctx->name) {
        ret = ENOMEM;
        goto done;
    }

    mc_ctx->type = type;

    mc_ctx->valid_time_slot = timeout;

    mc_ctx->file = talloc_asprintf(mc_ctx, "%s/%s",
                                   SSS_NSS_MCACHE_DIR, name);
    if (!mc_ctx->file) {
        ret = ENOMEM;
        goto done;
    }

    /* elements must always be multiple of 8 to make things easier to handle,
     * so we increase by the necessary amount if they are not a multiple */
    /* We can use MC_ALIGN64 for this */
    n_elem = MC_ALIGN64(n_elem);

    /* hash table is double the size because it will store both forward and
     * reverse keys (name/uid, name/gid, ..) */
    mc_ctx->ht_size = MC_HT_SIZE(n_elem * 2);
    mc_ctx->dt_size = MC_DT_SIZE(n_elem, payload);
    mc_ctx->ft_size = MC_FT_SIZE(n_elem);
    mc_ctx->mmap_size = MC_HEADER_SIZE +
                        MC_ALIGN64(mc_ctx->dt_size) +
                        MC_ALIGN64(mc_ctx->ft_size) +
                        MC_ALIGN64(mc_ctx->ht_size);


    /* for now ALWAYS create a new file on restart */

    ret = sss_mc_create_file(mc_ctx);
    if (ret) {
        goto done;
    }

    ret = ftruncate(mc_ctx->fd, mc_ctx->mmap_size);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to resize file %s: %d(%s)\n",
                                    mc_ctx->file, ret, strerror(ret)));
        goto done;
    }

    mc_ctx->mmap_base = mmap(NULL, mc_ctx->mmap_size,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED, mc_ctx->fd, 0);
    if (mc_ctx->mmap_base == MAP_FAILED) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to mmap file %s(%ld): %d(%s)\n",
                                    mc_ctx->file, mc_ctx->mmap_size,
                                    ret, strerror(ret)));
        goto done;
    }

    mc_ctx->data_table = MC_PTR_ADD(mc_ctx->mmap_base, MC_HEADER_SIZE);
    mc_ctx->free_table = MC_PTR_ADD(mc_ctx->data_table,
                                    MC_ALIGN64(mc_ctx->dt_size));
    mc_ctx->hash_table = MC_PTR_ADD(mc_ctx->free_table,
                                    MC_ALIGN64(mc_ctx->ft_size));

    memset(mc_ctx->data_table, 0x00, mc_ctx->dt_size);
    memset(mc_ctx->free_table, 0x00, mc_ctx->ft_size);
    memset(mc_ctx->hash_table, 0xff, mc_ctx->ht_size);

    /* generate a pseudo-random seed.
     * Needed to fend off dictionary based collision attacks */
    rseed = time(NULL) * getpid();
    mc_ctx->seed = rand_r(&rseed);

    sss_mc_header_update(mc_ctx, SSS_MC_HEADER_ALIVE);

    ret = EOK;

done:
    if (ret) {
        if (mc_ctx && mc_ctx->mmap_base) {
            munmap(mc_ctx->mmap_base, mc_ctx->mmap_size);
        }
        if (mc_ctx && mc_ctx->fd != -1) {
            close(mc_ctx->fd);
            ret = unlink(mc_ctx->file);
            if (ret == -1) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to rm mmap file %s: %d(%s)\n",
                                            mc_ctx->file, ret, strerror(ret)));
            }
        }

        talloc_free(mc_ctx);
    } else {
        *mcc = mc_ctx;
    }
    return ret;
}

errno_t sss_mmap_cache_reinit(TALLOC_CTX *mem_ctx, size_t n_elem,
                              time_t timeout, struct sss_mc_ctx **mc_ctx)
{
    errno_t ret;
    TALLOC_CTX* tmp_ctx = NULL;
    char *name;
    enum sss_mc_type type;

    if (mc_ctx == NULL || (*mc_ctx) == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to re-init unitialized memory cache.\n"));
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory.\n"));
        return ENOMEM;
    }

    name = talloc_strdup(tmp_ctx, (*mc_ctx)->name);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory.\n"));
        ret = ENOMEM;
        goto done;
    }

    type = (*mc_ctx)->type;
    ret = talloc_free(*mc_ctx);
    if (ret != 0) {
        /* This can happen only if destructor is associated with this
         * context */
        DEBUG(SSSDBG_MINOR_FAILURE, ("Destructor asociated with memory"
                                    " context failed.\n"));
    }

    ret = sss_mmap_cache_init(mem_ctx, name, type, n_elem, timeout, mc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to re-initialize mmap cache.\n"));
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}
