/*
   SSSD

   NSS Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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
#include <fcntl.h>
#include <time.h>
#include "tdb.h"

#define NC_ENTRY_PREFIX "NCE/"
#define NC_USER_PREFIX NC_ENTRY_PREFIX"USER"
#define NC_GROUP_PREFIX NC_ENTRY_PREFIX"GROUP"
#define NC_UID_PREFIX NC_ENTRY_PREFIX"UID"
#define NC_GID_PREFIX NC_ENTRY_PREFIX"GID"

struct nss_nc_ctx {
    struct tdb_context *tdb;
};

static int string_to_tdb_data(char *str, TDB_DATA *ret)
{
    if (!str || !ret) return EINVAL;

    ret->dptr = (uint8_t *)str;
    ret->dsize = strlen(str)+1;

    return EOK;
}

int nss_ncache_init(TALLOC_CTX *memctx, struct nss_nc_ctx **_ctx)
{
    struct nss_nc_ctx *ctx;

    ctx = talloc_zero(memctx, struct nss_nc_ctx);
    if (!ctx) return ENOMEM;

    errno = 0;
    /* open a memory only tdb with default hash size */
    ctx->tdb = tdb_open("memcache", 0, TDB_INTERNAL, O_RDWR|O_CREAT, 0);
    if (!ctx->tdb) return errno;

    *_ctx = ctx;
    return EOK;
};

static int nss_ncache_check_str(struct nss_nc_ctx *ctx, char *str, int ttl)
{
    TDB_DATA key;
    TDB_DATA data;
    unsigned long long int timestamp;
    bool expired = false;
    char *ep;
    int ret;

    ret = string_to_tdb_data(str, &key);
    if (ret != EOK) goto done;

    data = tdb_fetch(ctx->tdb, key);

    if (!data.dptr) {
        ret = ENOENT;
        goto done;
    }

    if (ttl == -1) {
        /* a negative ttl means: never expires */
        ret = EEXIST;
        goto done;
    }

    errno = 0;
    timestamp = strtoull((const char *)data.dptr, &ep, 0);
    if (errno != 0 || *ep != '\0') {
        /* Malformed entry, remove it and return no entry */
        expired = true;
        goto done;
    }

    if (timestamp == 0) {
        /* a 0 timestamp means this is a permanent entry */
        ret = EEXIST;
        goto done;
    }

    if (timestamp + ttl > time(NULL)) {
        /* still valid */
        ret = EEXIST;
        goto done;
    }

    expired = true;

done:
    if (expired) {
        /* expired, remove and return no entry */
        tdb_delete(ctx->tdb, key);
        ret = ENOENT;
    }

    return ret;
}

static int nss_ncache_set_str(struct nss_nc_ctx *ctx,
                              char *str, bool permanent)
{
    TDB_DATA key;
    TDB_DATA data;
    char *timest;
    int ret;

    ret = string_to_tdb_data(str, &key);
    if (ret != EOK) return ret;

    if (permanent) {
        timest = talloc_strdup(ctx, "0");
    } else {
        timest = talloc_asprintf(ctx, "%llu",
                                 (unsigned long long int)time(NULL));
    }
    if (!timest) return ENOMEM;

    ret = string_to_tdb_data(timest, &data);
    if (ret != EOK) goto done;

    ret = tdb_store(ctx->tdb, key, data, TDB_REPLACE);
    if (ret != 0) {
        DEBUG(1, ("Negative cache failed to set entry: [%s]\n",
                  tdb_errorstr(ctx->tdb)));
        ret = EFAULT;
    }

done:
    talloc_free(timest);
    return ret;
}

int nss_ncache_check_user(struct nss_nc_ctx *ctx, int ttl,
                          const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_USER_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = nss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

int nss_ncache_check_group(struct nss_nc_ctx *ctx, int ttl,
                           const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_GROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = nss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

int nss_ncache_check_uid(struct nss_nc_ctx *ctx, int ttl, uid_t uid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_UID_PREFIX, uid);
    if (!str) return ENOMEM;

    ret = nss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

int nss_ncache_check_gid(struct nss_nc_ctx *ctx, int ttl, gid_t gid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_GID_PREFIX, gid);
    if (!str) return ENOMEM;

    ret = nss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

int nss_ncache_set_user(struct nss_nc_ctx *ctx, bool permanent,
                        const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_USER_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = nss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

int nss_ncache_set_group(struct nss_nc_ctx *ctx, bool permanent,
                        const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_GROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = nss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

int nss_ncache_set_uid(struct nss_nc_ctx *ctx, bool permanent, uid_t uid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_UID_PREFIX, uid);
    if (!str) return ENOMEM;

    ret = nss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

int nss_ncache_set_gid(struct nss_nc_ctx *ctx, bool permanent, gid_t gid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_GID_PREFIX, gid);
    if (!str) return ENOMEM;

    ret = nss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

static int delete_permanent(struct tdb_context *tdb,
                            TDB_DATA key, TDB_DATA data, void *state)
{
    unsigned long long int timestamp;
    bool remove_key = false;
    char *ep;

    if (strncmp((char *)key.dptr,
                NC_ENTRY_PREFIX, sizeof(NC_ENTRY_PREFIX)) != 0) {
        /* not interested in this key */
        return 0;
    }

    errno = 0;
    timestamp = strtoull((const char *)data.dptr, &ep, 0);
    if (errno != 0 || *ep != '\0') {
        /* Malformed entry, remove it */
        remove_key = true;
        goto done;
    }

    if (timestamp == 0) {
        /* a 0 timestamp means this is a permanent entry */
        remove_key = true;
    }

done:
    if (remove_key) {
        return tdb_delete(tdb, key);
    }

    return 0;
}

int nss_ncache_reset_permament(struct nss_nc_ctx *ctx)
{
    int ret;

    ret = tdb_traverse(ctx->tdb, delete_permanent, NULL);
    if (ret < 0)
        return EIO;

    return EOK;
}
