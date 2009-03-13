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

#define NC_USER_PREFIX "NCUSER"
#define NC_GROUP_PREFIX "NCGROUP"
#define NC_UID_PREFIX "NCUID"
#define NC_GID_PREFIX "NCGID"

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

    errno = 0;
    timestamp = strtoull((const char *)data.dptr, &ep, 0);
    if (errno != 0 || *ep != '\0') {
        /* Malformed entry, remove it and return no entry */
        expired = true;
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

static int nss_ncache_set_str(struct nss_nc_ctx *ctx, char *str)
{
    TDB_DATA key;
    TDB_DATA data;
    char *timest;
    int ret;

    ret = string_to_tdb_data(str, &key);
    if (ret != EOK) return ret;

    timest = talloc_asprintf(ctx, "%llu", (unsigned long long int)time(NULL));
    if (!timest) return ENOMEM;

    ret = string_to_tdb_data(timest, &data);
    if (ret != EOK) goto done;

    ret = tdb_store(ctx->tdb, key, data, TDB_REPLACE);
    if (ret != 0) {
        DEBUG(1, ("Negative cache failed to set entry: [%s]",
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

int nss_ncache_set_user(struct nss_nc_ctx *ctx,
                        const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_USER_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = nss_ncache_set_str(ctx, str);

    talloc_free(str);
    return ret;
}

int nss_ncache_set_group(struct nss_nc_ctx *ctx,
                        const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_GROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = nss_ncache_set_str(ctx, str);

    talloc_free(str);
    return ret;
}

int nss_ncache_set_uid(struct nss_nc_ctx *ctx, uid_t uid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_UID_PREFIX, uid);
    if (!str) return ENOMEM;

    ret = nss_ncache_set_str(ctx, str);

    talloc_free(str);
    return ret;
}

int nss_ncache_set_gid(struct nss_nc_ctx *ctx, gid_t gid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_GID_PREFIX, gid);
    if (!str) return ENOMEM;

    ret = nss_ncache_set_str(ctx, str);

    talloc_free(str);
    return ret;
}

