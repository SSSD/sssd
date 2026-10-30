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

#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include "tdb.h"
#include "util/util.h"
#include "util/strtonum.h"
#include "util/nss_dl_load.h"
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"


#define NC_ENTRY_PREFIX "NCE/"
#define NC_USER_PREFIX NC_ENTRY_PREFIX"USER"
#define NC_GROUP_PREFIX NC_ENTRY_PREFIX"GROUP"
#define NC_NETGROUP_PREFIX NC_ENTRY_PREFIX"NETGR"
#define NC_SERVICE_PREFIX NC_ENTRY_PREFIX"SERVICE"
#define NC_UID_PREFIX NC_ENTRY_PREFIX"UID"
#define NC_GID_PREFIX NC_ENTRY_PREFIX"GID"
#define NC_SID_PREFIX NC_ENTRY_PREFIX"SID"
#define NC_CERT_PREFIX NC_ENTRY_PREFIX"CERT"
#define NC_DOMAIN_ACCT_LOCATE_PREFIX NC_ENTRY_PREFIX"DOM_LOCATE"
#define NC_DOMAIN_ACCT_LOCATE_TYPE_PREFIX NC_ENTRY_PREFIX"DOM_LOCATE_TYPE"

/* Permanently filtered out ID range, as configured by filter_uids and
 * filter_gids. Ranges are kept in a plain list instead of being expanded into
 * one tdb entry per ID, so that a range as wide as "1000-60000" costs a single
 * entry. A range holding a single ID is not kept here at all: it is stored as
 * a permanent tdb entry, exactly like a name coming from filter_users. */
struct sss_nc_id_range {
    struct sss_nc_id_range *prev;
    struct sss_nc_id_range *next;
    const char *dom_name; /* NULL for the domain independent entries */
    uint32_t min;
    uint32_t max;
};

struct sss_nc_ctx {
    struct tdb_context *tdb;
    uint32_t timeout;
    struct sss_nc_id_range *uid_ranges;
    struct sss_nc_id_range *gid_ranges;
};

typedef int (*ncache_set_byname_fn_t)(struct sss_nc_ctx *, bool,
                                      const char *, const char *);

static int sss_ncache_set_ent(struct sss_nc_ctx *ctx, bool permanent,
                              struct sss_domain_info *dom, const char *name,
                              ncache_set_byname_fn_t setter);

static int string_to_tdb_data(char *str, TDB_DATA *ret)
{
    if (!str || !ret) return EINVAL;

    ret->dptr = (uint8_t *)str;
    ret->dsize = strlen(str)+1;

    return EOK;
}

/* open a memory only tdb with default hash size */
static struct tdb_context *sss_ncache_open_tdb(void)
{
    errno = 0;
    return tdb_open("memcache", 0, TDB_INTERNAL, O_RDWR|O_CREAT, 0);
}

int sss_ncache_init(TALLOC_CTX *memctx, uint32_t timeout,
                    struct sss_nc_ctx **_ctx)
{
    struct sss_nc_ctx *ctx;

    ctx = talloc_zero(memctx, struct sss_nc_ctx);
    if (!ctx) return ENOMEM;

    ctx->tdb = sss_ncache_open_tdb();
    if (!ctx->tdb) return errno;

    ctx->timeout = timeout;

    *_ctx = ctx;
    return EOK;
};

static int sss_ncache_check_str(struct sss_nc_ctx *ctx, char *str)
{
    TDB_DATA key;
    TDB_DATA data;
    unsigned long long int timestamp;
    bool expired = false;
    char *ep;
    int ret;

    DEBUG_CONDITIONAL(SSSDBG_TRACE_INTERNAL, "Checking negative cache for [%s]\n", str);

    data.dptr = NULL;

    ret = string_to_tdb_data(str, &key);
    if (ret != EOK) goto done;

    data = tdb_fetch(ctx->tdb, key);

    if (!data.dptr) {
        ret = ENOENT;
        goto done;
    }

    errno = 0;
    timestamp = strtoull((const char *)data.dptr, &ep, 10);
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

    if (timestamp >= time(NULL)) {
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

    free(data.dptr);
    return ret;
}

static int sss_ncache_set_str(struct sss_nc_ctx *ctx, char *str, bool permanent)
{
    TDB_DATA key;
    TDB_DATA data;
    char *timest;
    unsigned long long int timell;
    int ret;

    ret = string_to_tdb_data(str, &key);
    if (ret != EOK) return ret;

    if (permanent) {
        timest = talloc_strdup(ctx, "0");
    } else {
        /* EOK is tested in cwrap based unit test */
        if (ctx->timeout == 0) {
            return EOK;
        }
        timell = ctx->timeout + (unsigned long long int)time(NULL);
        timest = talloc_asprintf(ctx, "%llu", timell);
    }
    if (!timest) return ENOMEM;

    ret = string_to_tdb_data(timest, &data);
    if (ret != EOK) goto done;

    DEBUG(SSSDBG_TRACE_FUNC, "Adding [%s] to negative cache%s\n",
              str, permanent?" permanently":"");

    ret = tdb_store(ctx->tdb, key, data, TDB_REPLACE);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Negative cache failed to set entry: [%s]\n",
                  tdb_errorstr(ctx->tdb));
        ret = EFAULT;
    }

done:
    talloc_free(timest);
    return ret;
}

static int sss_ncache_check_user_int(struct sss_nc_ctx *ctx, const char *domain,
                                     const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_USER_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}

static int sss_ncache_check_group_int(struct sss_nc_ctx *ctx,
                                      const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_GROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}

static int sss_ncache_check_netgr_int(struct sss_nc_ctx *ctx,
                                      const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_NETGROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}

static int sss_ncache_check_service_int(struct sss_nc_ctx *ctx,
                                        const char *domain,
                                        const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s",
                          NC_SERVICE_PREFIX,
                          domain,
                          name);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}

typedef int (*ncache_check_byname_fn_t)(struct sss_nc_ctx *, const char *,
                                        const char *);

static int sss_cache_check_ent(struct sss_nc_ctx *ctx,
                               struct sss_domain_info *dom, const char *name,
                               ncache_check_byname_fn_t checker)
{
    char *lower;
    errno_t ret;

    if (dom->case_sensitive == false) {
        lower = sss_tc_utf8_str_tolower(ctx, name);
        if (!lower) return ENOMEM;
        ret = checker(ctx, dom->name, lower);
        talloc_free(lower);
    } else {
        ret = checker(ctx, dom->name, name);
    }

    return ret;
}

int sss_ncache_check_user(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                          const char *name)
{
    return sss_cache_check_ent(ctx, dom, name, sss_ncache_check_user_int);
}

int sss_ncache_check_upn(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         const char *name)
{
    char *neg_cache_name = NULL;
    errno_t ret;

    neg_cache_name = talloc_asprintf(ctx, "@%s", name);
    if (neg_cache_name == NULL) {
        return ENOMEM;
    }

    ret = sss_cache_check_ent(ctx, dom, neg_cache_name,
                              sss_ncache_check_user_int);
    talloc_free(neg_cache_name);

    return ret;
}

int sss_ncache_check_group(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                           const char *name)
{
    return sss_cache_check_ent(ctx, dom, name, sss_ncache_check_group_int);
}

int sss_ncache_check_netgr(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                           const char *name)
{
    return sss_cache_check_ent(ctx, dom, name, sss_ncache_check_netgr_int);
}

static int sss_ncache_set_service_int(struct sss_nc_ctx *ctx, bool permanent,
                                      const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_SERVICE_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

int sss_ncache_set_service_name(struct sss_nc_ctx *ctx, bool permanent,
                                struct sss_domain_info *dom,
                                const char *name, const char *proto)
{
    int ret;
    char *service_and_protocol = talloc_asprintf(ctx, "%s:%s",
                                                 name,
                                                 proto ? proto : "<ANY>");
    if (!service_and_protocol) return ENOMEM;

    ret = sss_ncache_set_ent(ctx, permanent, dom,
                             service_and_protocol,
                             sss_ncache_set_service_int);
    talloc_free(service_and_protocol);
    return ret;
}

int sss_ncache_check_service(struct sss_nc_ctx *ctx,struct sss_domain_info *dom,
                             const char *name, const char *proto)
{
    int ret;
    char *service_and_protocol = talloc_asprintf(ctx, "%s:%s",
                                                 name,
                                                 proto ? proto : "<ANY>");
    if (!service_and_protocol) return ENOMEM;

    ret = sss_cache_check_ent(ctx, dom, service_and_protocol,
                              sss_ncache_check_service_int);
    talloc_free(service_and_protocol);
    return ret;
}

int sss_ncache_set_service_port(struct sss_nc_ctx *ctx, bool permanent,
                                struct sss_domain_info *dom,
                                uint16_t port, const char *proto)
{
    int ret;
    char *service_and_protocol = talloc_asprintf(ctx, "%ul:%s",
                                                 port,
                                                 proto ? proto : "<ANY>");
    if (!service_and_protocol) return ENOMEM;

    ret = sss_ncache_set_ent(ctx, permanent, dom,
                             service_and_protocol,
                             sss_ncache_set_service_int);
    talloc_free(service_and_protocol);
    return ret;
}

int sss_ncache_check_service_port(struct sss_nc_ctx *ctx,
                                  struct sss_domain_info *dom,
                                  uint16_t port,
                                  const char *proto)
{
    int ret;
    char *service_and_protocol = talloc_asprintf(ctx, "%ul:%s",
                                                 port,
                                                 proto ? proto : "<ANY>");
    if (!service_and_protocol) return ENOMEM;

    ret = sss_cache_check_ent(ctx, dom, service_and_protocol,
                              sss_ncache_check_service_int);
    talloc_free(service_and_protocol);
    return ret;
}



/* Check the permanently filtered out ranges. The domain scoping mirrors the
 * one of the tdb keys: a range set for a specific domain only matches a lookup
 * in that very domain, a domain independent range only matches a domain
 * independent lookup. Callers interested in both do the two calls, the same
 * way they already do for the single-ID entries. */
static bool sss_ncache_check_id_range(const struct sss_nc_id_range *ranges,
                                      const struct sss_domain_info *dom,
                                      uint32_t id)
{
    struct sss_nc_id_range *range;

    DLIST_FOR_EACH(range, discard_const(ranges)) {
        if ((dom == NULL) != (range->dom_name == NULL)) {
            continue;
        }

        if (id < range->min || id > range->max) {
            continue;
        }

        if (dom == NULL || strcmp(dom->name, range->dom_name) == 0) {
            return true;
        }
    }

    return false;
}

static int sss_ncache_set_id_range(TALLOC_CTX *memctx,
                                   struct sss_nc_id_range **ranges,
                                   struct sss_domain_info *dom,
                                   uint32_t min, uint32_t max)
{
    struct sss_nc_id_range *range;

    if (min > max) {
        return EINVAL;
    }

    range = talloc_zero(memctx, struct sss_nc_id_range);
    if (range == NULL) {
        return ENOMEM;
    }

    if (dom != NULL) {
        range->dom_name = talloc_strdup(range, dom->name);
        if (range->dom_name == NULL) {
            talloc_free(range);
            return ENOMEM;
        }
    }

    range->min = min;
    range->max = max;

    DLIST_ADD(*ranges, range);

    return EOK;
}

static void sss_ncache_free_id_ranges(struct sss_nc_id_range **ranges)
{
    struct sss_nc_id_range *range;

    while (*ranges != NULL) {
        range = *ranges;
        DLIST_REMOVE(*ranges, range);
        talloc_free(range);
    }
}

static int sss_ncache_set_uid_range(struct sss_nc_ctx *ctx,
                             struct sss_domain_info *dom,
                             uid_t min, uid_t max)
{
    if (min == max) {
        /* A single ID is stored as a plain permanent entry, the same way a
         * name coming from filter_users is. The hash lookup is cheaper than
         * walking the range list and a cache reset flushes the entry for
         * free. */
        return sss_ncache_set_uid(ctx, true, dom, min);
    }

    return sss_ncache_set_id_range(ctx, &ctx->uid_ranges, dom, min, max);
}

static int sss_ncache_set_gid_range(struct sss_nc_ctx *ctx,
                             struct sss_domain_info *dom,
                             gid_t min, gid_t max)
{
    if (min == max) {
        /* see sss_ncache_set_uid_range() */
        return sss_ncache_set_gid(ctx, true, dom, min);
    }

    return sss_ncache_set_id_range(ctx, &ctx->gid_ranges, dom, min, max);
}

int sss_ncache_check_uid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         uid_t uid)
{
    char *str;
    int ret;

    if (sss_ncache_check_id_range(ctx->uid_ranges, dom, uid)) {
        return EEXIST;
    }

    if (dom != NULL) {
        str = talloc_asprintf(ctx, "%s/%s/%"SPRIuid, NC_UID_PREFIX, dom->name,
                              uid);
    } else {
        str = talloc_asprintf(ctx, "%s/%"SPRIuid, NC_UID_PREFIX, uid);
    }
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}

int sss_ncache_check_gid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         gid_t gid)
{
    char *str;
    int ret;

    if (sss_ncache_check_id_range(ctx->gid_ranges, dom, gid)) {
        return EEXIST;
    }

    if (dom != NULL) {
        str = talloc_asprintf(ctx, "%s/%s/%"SPRIgid, NC_GID_PREFIX, dom->name,
                              gid);
    } else {
        str = talloc_asprintf(ctx, "%s/%"SPRIgid, NC_GID_PREFIX, gid);
    }
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}

int sss_ncache_check_sid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         const char *sid)
{
    char *str;
    int ret;

    if (dom != NULL) {
        str = talloc_asprintf(ctx, "%s/%s/%s", NC_SID_PREFIX, dom->name, sid);
    } else {
        str = talloc_asprintf(ctx, "%s/%s", NC_SID_PREFIX, sid);
    }
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}

int sss_ncache_check_cert(struct sss_nc_ctx *ctx, const char *cert)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%s", NC_CERT_PREFIX, cert);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}


static int sss_ncache_set_user_int(struct sss_nc_ctx *ctx, bool permanent,
                                   const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_USER_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

static int sss_ncache_set_group_int(struct sss_nc_ctx *ctx, bool permanent,
                                    const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_GROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

static int sss_ncache_set_netgr_int(struct sss_nc_ctx *ctx, bool permanent,
                                    const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_NETGROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

static int sss_ncache_set_ent(struct sss_nc_ctx *ctx, bool permanent,
                              struct sss_domain_info *dom, const char *name,
                              ncache_set_byname_fn_t setter)
{
    char *lower;
    errno_t ret;

    if (dom->case_sensitive == false) {
        lower = sss_tc_utf8_str_tolower(ctx, name);
        if (!lower) return ENOMEM;
        ret = setter(ctx, permanent, dom->name, lower);
        talloc_free(lower);
    } else {
        ret = setter(ctx, permanent, dom->name, name);
    }

    return ret;
}


int sss_ncache_set_user(struct sss_nc_ctx *ctx, bool permanent,
                        struct sss_domain_info *dom, const char *name)
{
    return sss_ncache_set_ent(ctx, permanent, dom, name, sss_ncache_set_user_int);
}

int sss_ncache_set_upn(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, const char *name)
{
    char *neg_cache_name = NULL;
    errno_t ret;

    neg_cache_name = talloc_asprintf(ctx, "@%s", name);
    if (neg_cache_name == NULL) {
        return ENOMEM;
    }

    ret = sss_ncache_set_ent(ctx, permanent, dom, neg_cache_name,
                             sss_ncache_set_user_int);
    talloc_free(neg_cache_name);

    return ret;
}

int sss_ncache_set_group(struct sss_nc_ctx *ctx, bool permanent,
                         struct sss_domain_info *dom, const char *name)
{
    return sss_ncache_set_ent(ctx, permanent, dom, name, sss_ncache_set_group_int);
}

int sss_ncache_set_netgr(struct sss_nc_ctx *ctx, bool permanent,
                         struct sss_domain_info *dom, const char *name)
{
    return sss_ncache_set_ent(ctx, permanent, dom, name, sss_ncache_set_netgr_int);
}

int sss_ncache_set_uid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, uid_t uid)
{
    char *str;
    int ret;

    if (dom != NULL) {
        str = talloc_asprintf(ctx, "%s/%s/%"SPRIuid, NC_UID_PREFIX, dom->name,
                              uid);
    } else {
        str = talloc_asprintf(ctx, "%s/%"SPRIuid, NC_UID_PREFIX, uid);
    }
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

int sss_ncache_set_gid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, gid_t gid)
{
    char *str;
    int ret;

    if (dom != NULL) {
        str = talloc_asprintf(ctx, "%s/%s/%"SPRIgid, NC_GID_PREFIX, dom->name,
                              gid);
    } else {
        str = talloc_asprintf(ctx, "%s/%"SPRIgid, NC_GID_PREFIX, gid);
    }
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

int sss_ncache_set_sid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, const char *sid)
{
    char *str;
    int ret;

    if (dom != NULL) {
        str = talloc_asprintf(ctx, "%s/%s/%s", NC_SID_PREFIX, dom->name, sid);
    } else {
        str = talloc_asprintf(ctx, "%s/%s", NC_SID_PREFIX, sid);
    }
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

int sss_ncache_set_cert(struct sss_nc_ctx *ctx, bool permanent,
                        const char *cert)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%s", NC_CERT_PREFIX, cert);
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

static char *domain_lookup_type_str(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *dom,
                                    const char *lookup_type)
{
    return talloc_asprintf(mem_ctx,
                           "%s/%s/%s",
                           NC_DOMAIN_ACCT_LOCATE_TYPE_PREFIX,
                           dom->name,
                           lookup_type);
}

int sss_ncache_set_domain_locate_type(struct sss_nc_ctx *ctx,
                                      struct sss_domain_info *dom,
                                      const char *lookup_type)
{
    char *str;
    int ret;

    str = domain_lookup_type_str(ctx, dom, lookup_type);
    if (!str) return ENOMEM;

    /* Permanent cache is always used here, because the lookup
     * type's (getgrgid, getpwuid, ..) support locating an entry's domain
     * doesn't change
     */
    ret = sss_ncache_set_str(ctx, str, true);
    talloc_free(str);
    return ret;
}

int sss_ncache_check_domain_locate_type(struct sss_nc_ctx *ctx,
                                        struct sss_domain_info *dom,
                                        const char *lookup_type)
{
    char *str;
    int ret;

    str = domain_lookup_type_str(ctx, dom, lookup_type);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str);
    talloc_free(str);
    return ret;
}

static char *locate_gid_str(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *dom,
                            gid_t gid)
{
    return talloc_asprintf(mem_ctx,
                           "%s/%s/%s/%"SPRIgid,
                           NC_DOMAIN_ACCT_LOCATE_PREFIX,
                           NC_GID_PREFIX,
                           dom->name,
                           gid);
}

int sss_ncache_set_locate_gid(struct sss_nc_ctx *ctx,
                              struct sss_domain_info *dom,
                              gid_t gid)
{
    char *str;
    int ret;

    if (dom == NULL) {
        return EINVAL;
    }

    str = locate_gid_str(ctx, dom, gid);
    if (str == NULL) {
        return ENOMEM;
    }

    ret = sss_ncache_set_str(ctx, str, false);
    talloc_free(str);
    return ret;
}

int sss_ncache_check_locate_gid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom,
                                gid_t gid)
{
    char *str;
    int ret;

    if (dom == NULL) {
        return EINVAL;
    }

    str = locate_gid_str(ctx, dom, gid);
    if (str == NULL) {
        return ENOMEM;
    }

    ret = sss_ncache_check_str(ctx, str);
    talloc_free(str);
    return ret;
}

static char *locate_uid_str(struct sss_nc_ctx *ctx,
                            struct sss_domain_info *dom,
                            uid_t uid)
{
    return talloc_asprintf(ctx,
                           "%s/%s/%s/%"SPRIuid,
                           NC_DOMAIN_ACCT_LOCATE_PREFIX,
                           NC_UID_PREFIX,
                           dom->name,
                           uid);
}

int sss_ncache_set_locate_uid(struct sss_nc_ctx *ctx,
                              struct sss_domain_info *dom,
                              uid_t uid)
{
    char *str;
    int ret;

    if (dom == NULL) {
        return EINVAL;
    }

    str = locate_uid_str(ctx, dom, uid);
    if (str == NULL) {
        return ENOMEM;
    }

    ret = sss_ncache_set_str(ctx, str, false);
    talloc_free(str);
    return ret;
}

int sss_ncache_check_locate_uid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom,
                                uid_t uid)
{
    char *str;
    int ret;

    if (dom == NULL) {
        return EINVAL;
    }

    str = locate_uid_str(ctx, dom, uid);
    if (str == NULL) {
        return ENOMEM;
    }

    ret = sss_ncache_check_str(ctx, str);
    talloc_free(str);
    return ret;
}

static char *locate_sid_str(struct sss_nc_ctx *ctx,
                            struct sss_domain_info *dom,
                            const char *sid)
{
    return talloc_asprintf(ctx,
                           "%s/%s/%s/%s",
                           NC_DOMAIN_ACCT_LOCATE_PREFIX,
                           NC_SID_PREFIX,
                           dom->name,
                           sid);
}

int sss_ncache_check_locate_sid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom,
                                const char *sid)
{
    char *str;
    int ret;

    if (dom == NULL) {
        return EINVAL;
    }

    str = locate_sid_str(ctx, dom, sid);
    if (str == NULL) {
        return ENOMEM;
    }

    ret = sss_ncache_check_str(ctx, str);
    talloc_free(str);
    return ret;
}

int sss_ncache_set_locate_sid(struct sss_nc_ctx *ctx,
                              struct sss_domain_info *dom,
                              const char *sid)
{
    char *str;
    int ret;

    if (dom == NULL) {
        return EINVAL;
    }

    str = locate_sid_str(ctx, dom, sid);
    if (str == NULL) {
        return ENOMEM;
    }

    ret = sss_ncache_set_str(ctx, str, false);
    talloc_free(str);
    return ret;
}

/* Parse a single filter_uids/filter_gids value, either a plain "ID" or an
 * inclusive "MIN-MAX" range. */
static errno_t sss_ncache_parse_id_filter(const char *value,
                                          uint32_t *_min, uint32_t *_max)
{
    uint32_t min;
    uint32_t max;
    char *endptr;

    /* strtouint32() would silently accept a sign, and a leading separator
     * would make an empty boundary look like a valid 0. */
    if (!isdigit((unsigned char)value[0])) {
        return EINVAL;
    }

    min = strtouint32(value, &endptr, 10);
    if (errno != 0) {
        return EINVAL;
    }

    if (*endptr == '\0') {
        max = min;
    } else if (*endptr == '-') {
        value = endptr + 1;
        if (!isdigit((unsigned char)value[0])) {
            return EINVAL;
        }

        max = strtouint32(value, &endptr, 10);
        if (errno != 0 || *endptr != '\0') {
            return EINVAL;
        }

        if (max < min) {
            return EINVAL;
        }
    } else {
        return EINVAL;
    }

    *_min = min;
    *_max = max;

    return EOK;
}

typedef int (*ncache_set_id_range_fn_t)(struct sss_nc_ctx *ctx,
                                        struct sss_domain_info *dom,
                                        uint32_t min, uint32_t max);

/* Read one filter_uids/filter_gids list and hand every entry to the setter.
 * A malformed entry is reported and skipped, the same way filter_users deals
 * with an unparsable name. */
static errno_t sss_ncache_prepopulate_id_list(struct sss_nc_ctx *ncache,
                                              struct confdb_ctx *cdb,
                                              const char *conf_path,
                                              const char *option,
                                              struct sss_domain_info *dom,
                                              ncache_set_id_range_fn_t setter)
{
    TALLOC_CTX *tmp_ctx;
    char **filter_list = NULL;
    uint32_t min;
    uint32_t max;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = confdb_get_string_as_list(cdb, tmp_ctx, conf_path, option,
                                    &filter_list);
    if (ret == ENOENT) {
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    for (i = 0; filter_list[i] != NULL; i++) {
        ret = sss_ncache_parse_id_filter(filter_list[i], &min, &max);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid value in %s list: [%s], expecting an ID or an "
                  "ID range such as [1-999], skipping\n",
                  option, filter_list[i]);
            continue;
        }

        ret = setter(ncache, dom, min, max);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to store permanent %s filter for [%s] (%d [%s])\n",
                  option, filter_list[i], ret, sss_strerror(ret));
            continue;
        }

        if (min != max) {
            /* If min == max, the entry was not created as a range and
             * is already logged. */
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Added %s range [%"PRIu32"-%"PRIu32"] to the negative cache "
                  "of [%s]\n", option, min, max,
                  dom == NULL ? "all domains" : dom->name);
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* Populate the negative cache from filter_uids/filter_gids, both from the
 * domain sections and from the domain independent [nss] one. */
static errno_t sss_ncache_prepopulate_ids(struct sss_nc_ctx *ncache,
                                          struct confdb_ctx *cdb,
                                          struct sss_domain_info *domain_list,
                                          const char *option,
                                          ncache_set_id_range_fn_t setter)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *dom;
    struct sss_domain_info *ddom;
    char *conf_path;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    for (dom = domain_list; dom != NULL; dom = get_next_domain(dom, 0)) {
        conf_path = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL,
                                    dom->name);
        if (conf_path == NULL) {
            ret = ENOMEM;
            goto done;
        }

        /* An ID filter set on a domain covers its sub-domains as well, just
         * like filter_users and filter_groups do. */
        for (ddom = dom; ddom != NULL;
                    ddom = get_next_domain(ddom, SSS_GND_ALL_SUBDOMAINS)) {
            ret = sss_ncache_prepopulate_id_list(ncache, cdb, conf_path,
                                                 option, ddom, setter);
            if (ret != EOK) {
                goto done;
            }
        }

        talloc_free(conf_path);
    }

    /* The domain independent list is registered both as a domain independent
     * entry and once per domain, the same way filter_users and filter_groups
     * fan their [nss] list out over every domain. A domain independent entry
     * on its own would not be enough: while the ID requests do fall back to a
     * lookup with a NULL domain, is_group_filtered(), which drops filtered
     * groups from the initgroups reply, only ever asks for a given domain. */
    ret = sss_ncache_prepopulate_id_list(ncache, cdb, CONFDB_NSS_CONF_ENTRY,
                                         option, NULL, setter);
    if (ret != EOK) {
        goto done;
    }

    for (dom = domain_list; dom != NULL;
                dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {
        ret = sss_ncache_prepopulate_id_list(ncache, cdb,
                                             CONFDB_NSS_CONF_ENTRY, option,
                                             dom, setter);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sss_ncache_prepopulate(struct sss_nc_ctx *ncache,
                               struct confdb_ctx *cdb,
                               struct resp_ctx *rctx)
{
    errno_t ret;
    char **filter_list = NULL;
    char **default_list = NULL;
    char *name = NULL;
    struct sss_domain_info *dom = NULL;
    struct sss_domain_info *domain_list = rctx->domains;
    struct sss_domain_info *ddom;
    char *domainname = NULL;
    char *conf_path = NULL;
    TALLOC_CTX *tmpctx = talloc_new(NULL);
    int i;
    char *fqname = NULL;

    if (tmpctx == NULL) {
        return ENOMEM;
    }

    /* Populate domain-specific negative cache user entries */
    for (dom = domain_list; dom; dom = get_next_domain(dom, 0)) {
        conf_path = talloc_asprintf(tmpctx, CONFDB_DOMAIN_PATH_TMPL,
                                    dom->name);
        if (!conf_path) {
            ret = ENOMEM;
            goto done;
        }

        talloc_zfree(filter_list);
        ret = confdb_get_string_as_list(cdb, tmpctx, conf_path,
                                        CONFDB_NSS_FILTER_USERS,
                                        &filter_list);
        if (ret == ENOENT) continue;
        if (ret != EOK) goto done;

        for (i = 0; (filter_list && filter_list[i]); i++) {
            ret = sss_parse_name_for_domains(tmpctx, domain_list,
                                             NULL,
                                             filter_list[i],
                                             &domainname, &name);
            if (ret == EAGAIN) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Can add [%s] only as UPN to negcache because the "
                      "required domain is not known yet\n", filter_list[i]);
            } else if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Invalid name in filterUsers list: [%s] (%d)\n",
                         filter_list[i], ret);
                continue;
            }

            /* Check domain and its sub-domains */
            for (ddom = dom; ddom != NULL;
                        ddom = get_next_domain(ddom, SSS_GND_ALL_SUBDOMAINS)) {

                if (domainname && strcmp(domainname, ddom->name)) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "Mismatch between domain name (%s) and name "
                              "set in FQN  (%s), assuming %s is UPN\n",
                              ddom->name, domainname, filter_list[i]);
                    ret = sss_ncache_set_upn(ncache, true, ddom, filter_list[i]);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "sss_ncache_set_upn failed (%d [%s]), ignored\n",
                              ret, sss_strerror(ret));
                    }
                    continue;
                }

                fqname = sss_create_internal_fqname(tmpctx, name, ddom->name);
                if (fqname == NULL) {
                    continue;
                }

                ret = sss_ncache_set_upn(ncache, true, ddom, fqname);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sss_ncache_set_upn failed (%d [%s]), ignored\n",
                          ret, sss_strerror(ret));
                }
                ret = sss_ncache_set_user(ncache, true, ddom, fqname);
                talloc_zfree(fqname);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed to store permanent user filter for [%s]"
                              " (%d [%s])\n", filter_list[i],
                              ret, sss_strerror(ret));
                    continue;
                }
            }
        }
    }

    talloc_zfree(filter_list);
    /* Populate non domain-specific negative cache user entries */
    ret = confdb_get_string_as_list(cdb, tmpctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_FILTER_USERS, &filter_list);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    for (i = 0; (filter_list && filter_list[i]); i++) {
        ret = sss_parse_name_for_domains(tmpctx, domain_list,
                                         NULL, filter_list[i],
                                         &domainname, &name);
        if (ret == EAGAIN) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Can add [%s] only as UPN to negcache because the "
                  "required domain is not known yet\n", filter_list[i]);
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid name in filterUsers list: [%s] (%d)\n",
                     filter_list[i], ret);
            continue;
        }
        if (domainname) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Adding [%s] to UPN negative cache of all domains.\n",
                  filter_list[i]);
            for (dom = domain_list;
                 dom != NULL;
                 dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {
                ret = sss_ncache_set_upn(ncache, true, dom, filter_list[i]);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sss_ncache_set_upn failed (%d [%s]), ignored\n",
                          ret, sss_strerror(ret));
                }
            }

            /* Add name to domain specific cache for known domain names */
            dom = responder_get_domain(rctx, domainname);
            if (dom != NULL) {
                fqname = sss_create_internal_fqname(tmpctx, name, dom->name);
                if (fqname == NULL) {
                    continue;
                }

                ret = sss_ncache_set_user(ncache, true, dom, fqname);
                talloc_zfree(fqname);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed to store permanent user filter for [%s]"
                              " (%d [%s])\n", filter_list[i],
                              ret, strerror(ret));
                    continue;
                }
            }
        } else {
            for (dom = domain_list;
                 dom != NULL;
                 dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {
                fqname = sss_create_internal_fqname(tmpctx, name, dom->name);
                if (fqname == NULL) {
                    continue;
                }

                ret = sss_ncache_set_upn(ncache, true, dom, fqname);
                if (ret != EOK) {
                   DEBUG(SSSDBG_CRIT_FAILURE,
                         "Failed to store permanent upn filter for"
                             " [%s:%s] (%d [%s])\n",
                             dom->name, filter_list[i],
                             ret, strerror(ret));
                }

                ret = sss_ncache_set_user(ncache, true, dom, fqname);
                talloc_zfree(fqname);
                if (ret != EOK) {
                   DEBUG(SSSDBG_CRIT_FAILURE,
                         "Failed to store permanent user filter for"
                             " [%s:%s] (%d [%s])\n",
                             dom->name, filter_list[i],
                             ret, strerror(ret));
                    continue;
                }
            }
        }
    }

    /* Populate domain-specific negative cache group entries */
    for (dom = domain_list; dom; dom = get_next_domain(dom, 0)) {
        conf_path = talloc_asprintf(tmpctx, CONFDB_DOMAIN_PATH_TMPL, dom->name);
        if (!conf_path) {
            ret = ENOMEM;
            goto done;
        }

        talloc_zfree(filter_list);
        ret = confdb_get_string_as_list(cdb, tmpctx, conf_path,
                                        CONFDB_NSS_FILTER_GROUPS, &filter_list);
        if (ret == ENOENT) continue;
        if (ret != EOK) goto done;

        for (i = 0; (filter_list && filter_list[i]); i++) {
            ret = sss_parse_name_for_domains(tmpctx, domain_list,
                                             NULL, filter_list[i],
                                             &domainname, &name);
            if (ret != EOK) {
                /* Groups do not have UPNs, so domain names, if present,
                 * must be known */
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Invalid name in filterGroups list: [%s] (%d)\n",
                         filter_list[i], ret);
                continue;
            }

            /* Check domain and its sub-domains */
            for (ddom = dom;
                        ddom != NULL && (ddom == dom || ddom->parent != NULL);
                        ddom = get_next_domain(ddom, SSS_GND_ALL_DOMAINS)) {
                if (domainname && strcmp(domainname, ddom->name)) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Mismatch between domain name (%s) and name "
                              "set in FQN  (%s), skipping group %s\n",
                              ddom->name, domainname, name);
                    continue;
                }

                fqname = sss_create_internal_fqname(tmpctx, name, ddom->name);
                if (fqname == NULL) {
                    continue;
                }

                ret = sss_ncache_set_group(ncache, true, ddom, fqname);
                talloc_zfree(fqname);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed to store permanent group filter for [%s]"
                              " (%d [%s])\n", filter_list[i],
                              ret, strerror(ret));
                    continue;
                }
            }
        }
    }

    talloc_zfree(filter_list);
    /* Populate non domain-specific negative cache group entries */
    ret = confdb_get_string_as_list(cdb, tmpctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_FILTER_GROUPS, &filter_list);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    for (i = 0; (filter_list && filter_list[i]); i++) {
        ret = sss_parse_name_for_domains(tmpctx, domain_list,
                                         NULL, filter_list[i],
                                         &domainname, &name);
        if (ret != EOK) {
            /* Groups do not have UPNs, so domain names, if present,
             * must be known */
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid name in filterGroups list: [%s] (%d)\n",
                     filter_list[i], ret);
            continue;
        }
        if (domainname) {
            dom = responder_get_domain(rctx, domainname);
            if (!dom) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Invalid domain name [%s]\n", domainname);
                continue;
            }

            fqname = sss_create_internal_fqname(tmpctx, name, dom->name);
            if (fqname == NULL) {
                continue;
            }

            ret = sss_ncache_set_group(ncache, true, dom, fqname);
            talloc_zfree(fqname);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to store permanent group filter for"
                          " [%s] (%d [%s])\n", filter_list[i],
                          ret, strerror(ret));
                continue;
            }
        } else {
            for (dom = domain_list;
                 dom != NULL;
                 dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {
                fqname = sss_create_internal_fqname(tmpctx, name, dom->name);
                if (fqname == NULL) {
                    continue;
                }

                ret = sss_ncache_set_group(ncache, true, dom, fqname);
                talloc_zfree(fqname);
                if (ret != EOK) {
                   DEBUG(SSSDBG_CRIT_FAILURE,
                         "Failed to store permanent group filter for"
                             " [%s:%s] (%d [%s])\n",
                             dom->name, filter_list[i],
                             ret, strerror(ret));
                    continue;
                }
            }
        }
    }

    /* Populate the negative cache UID and GID ranges */
    ret = sss_ncache_prepopulate_ids(ncache, cdb, domain_list,
                                     CONFDB_NSS_FILTER_UIDS,
                                     sss_ncache_set_uid_range);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_ncache_prepopulate_ids(ncache, cdb, domain_list,
                                     CONFDB_NSS_FILTER_GIDS,
                                     sss_ncache_set_gid_range);
    if (ret != EOK) {
        goto done;
    }

    /* SSSD doesn't handle "root", thus it'll be added to the negative cache
     * nonetheless what's already added there. */
    default_list = talloc_array(tmpctx, char *, 2);
    if (default_list == NULL) {
        ret= ENOMEM;
        goto done;
    }
    default_list[0] = talloc_strdup(tmpctx, "root");
    if (default_list[0] == NULL) {
        ret = ENOMEM;
        goto done;
    }
    default_list[1] = NULL;

    /* Populate negative cache users and groups entries for the
     * "default_list" */
    for (i = 0; (default_list != NULL && default_list[i] != NULL); i++) {
        for (dom = domain_list;
             dom != NULL;
             dom = get_next_domain(dom, SSS_GND_ALL_DOMAINS)) {
            fqname = sss_create_internal_fqname(tmpctx,
                                                default_list[i],
                                                dom->name);
            if (fqname == NULL) {
                continue;
            }

            ret = sss_ncache_set_user(ncache, true, dom, fqname);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to store permanent user filter for"
                      " [%s:%s] (%d [%s])\n",
                      dom->name, default_list[i],
                      ret, strerror(ret));
                continue;
            }

            ret = sss_ncache_set_group(ncache, true, dom, fqname);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to store permanent group filter for"
                      " [%s:%s] (%d [%s])\n",
                      dom->name, default_list[i],
                      ret, strerror(ret));
                continue;
            }
        }
    }

    /* Also add "root" uid and gid to the negative cache */
    ret = sss_ncache_set_uid(ncache, true, NULL, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to store permanent uid filter for root (0) "
              "(%d [%s])\n",
              ret, strerror(ret));
    }

    ret = sss_ncache_set_gid(ncache, true, NULL, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to store permanent gid filter for root (0) "
              "(%d [%s])\n",
              ret, strerror(ret));
    }

    ret = EOK;

done:
    talloc_free(tmpctx);
    return ret;
}

/* Recreate the negcache from scratch and repopulate permanent entries.
 * All non-permanent entries are dropped. */
errno_t sss_ncache_reset(struct resp_ctx *rctx,
                         struct sss_nc_ctx *ncache)
{
    struct tdb_context *tdb;

    /* Open the replacement before dropping the old one so a failure leaves
     * the existing cache usable. */
    tdb = sss_ncache_open_tdb();
    if (tdb == NULL) {
        return errno ? errno : EIO;
    }

    tdb_close(ncache->tdb);
    ncache->tdb = tdb;

    sss_ncache_free_id_ranges(&ncache->uid_ranges);
    sss_ncache_free_id_ranges(&ncache->gid_ranges);

    return sss_ncache_prepopulate(ncache, rctx->cdb, rctx);
}
