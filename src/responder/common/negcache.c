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

#include <fcntl.h>
#include <time.h>
#include "tdb.h"
#include "util/util.h"
#include "util/nss_dl_load.h"
#include "confdb/confdb.h"
#include "responder/common/negcache_files.h"
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

struct sss_nc_ctx {
    struct tdb_context *tdb;
    uint32_t timeout;
    uint32_t local_timeout;
    struct sss_nss_ops ops;
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

static errno_t ncache_load_nss_symbols(struct sss_nss_ops *ops)
{
    errno_t ret;
    struct sss_nss_symbols syms[] = {
        {(void*)&ops->getpwnam_r, true, "getpwnam_r" },
        {(void*)&ops->getpwuid_r, true, "getpwuid_r" },
        {(void*)&ops->getgrnam_r, true, "getgrnam_r" },
        {(void*)&ops->getgrgid_r, true, "getgrgid_r" }
    };
    size_t nsyms = sizeof(syms) / sizeof(struct sss_nss_symbols);

    ret = sss_load_nss_symbols(ops, "files", syms, nsyms);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

int sss_ncache_init(TALLOC_CTX *memctx, uint32_t timeout,
                    uint32_t local_timeout, struct sss_nc_ctx **_ctx)
{
    errno_t ret;
    struct sss_nc_ctx *ctx;

    ctx = talloc_zero(memctx, struct sss_nc_ctx);
    if (!ctx) return ENOMEM;

    ret = ncache_load_nss_symbols(&ctx->ops);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load NSS symbols [%d]: %s\n",
              ret, sss_strerror(ret));
        talloc_free(ctx);
        return ret;
    }

    errno = 0;
    /* open a memory only tdb with default hash size */
    ctx->tdb = tdb_open("memcache", 0, TDB_INTERNAL, O_RDWR|O_CREAT, 0);
    if (!ctx->tdb) return errno;

    ctx->timeout = timeout;
    ctx->local_timeout = local_timeout;

    *_ctx = ctx;
    return EOK;
};

uint32_t sss_ncache_get_timeout(struct sss_nc_ctx *ctx)
{
    return ctx->timeout;
}

static int sss_ncache_check_str(struct sss_nc_ctx *ctx, char *str)
{
    TDB_DATA key;
    TDB_DATA data;
    unsigned long long int timestamp;
    bool expired = false;
    char *ep;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Checking negative cache for [%s]\n", str);

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

static int sss_ncache_set_str(struct sss_nc_ctx *ctx, char *str,
                              bool permanent, bool use_local_negative)
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
        if (use_local_negative == true && ctx->local_timeout > ctx->timeout) {
            timell = ctx->local_timeout;
        } else {
            /* EOK is tested in cwrap based unit test */
            if (ctx->timeout == 0) {
                return EOK;
            }
            timell = ctx->timeout;
        }
        timell += (unsigned long long int)time(NULL);
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

    ret = sss_ncache_set_str(ctx, str, permanent, false);

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



int sss_ncache_check_uid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         uid_t uid)
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

    ret = sss_ncache_check_str(ctx, str);

    talloc_free(str);
    return ret;
}

int sss_ncache_check_gid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         gid_t gid)
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
    bool use_local_negative = false;
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_USER_PREFIX, domain, name);
    if (!str) return ENOMEM;

    if ((!permanent) && (ctx->local_timeout > 0)) {
        use_local_negative = is_user_local_by_name(&ctx->ops, name);
    }
    ret = sss_ncache_set_str(ctx, str, permanent, use_local_negative);

    talloc_free(str);
    return ret;
}

static int sss_ncache_set_group_int(struct sss_nc_ctx *ctx, bool permanent,
                                    const char *domain, const char *name)
{
    bool use_local_negative = false;
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_GROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    if ((!permanent) && (ctx->local_timeout > 0)) {
        use_local_negative = is_group_local_by_name(&ctx->ops, name);
    }
    ret = sss_ncache_set_str(ctx, str, permanent, use_local_negative);

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

    ret = sss_ncache_set_str(ctx, str, permanent, false);

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
    bool use_local_negative = false;
    char *str;
    int ret;

    if (dom != NULL) {
        str = talloc_asprintf(ctx, "%s/%s/%"SPRIuid, NC_UID_PREFIX, dom->name,
                              uid);
    } else {
        str = talloc_asprintf(ctx, "%s/%"SPRIuid, NC_UID_PREFIX, uid);
    }
    if (!str) return ENOMEM;

    if ((!permanent) && (ctx->local_timeout > 0)) {
        use_local_negative = is_user_local_by_uid(&ctx->ops, uid);
    }
    ret = sss_ncache_set_str(ctx, str, permanent, use_local_negative);

    talloc_free(str);
    return ret;
}

int sss_ncache_set_gid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, gid_t gid)
{
    bool use_local_negative = false;
    char *str;
    int ret;

    if (dom != NULL) {
        str = talloc_asprintf(ctx, "%s/%s/%"SPRIgid, NC_GID_PREFIX, dom->name,
                              gid);
    } else {
        str = talloc_asprintf(ctx, "%s/%"SPRIgid, NC_GID_PREFIX, gid);
    }
    if (!str) return ENOMEM;

    if ((!permanent) && (ctx->local_timeout > 0)) {
        use_local_negative = is_group_local_by_gid(&ctx->ops, gid);
    }
    ret = sss_ncache_set_str(ctx, str, permanent, use_local_negative);

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

    ret = sss_ncache_set_str(ctx, str, permanent, false);

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

    ret = sss_ncache_set_str(ctx, str, permanent, false);

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
    ret = sss_ncache_set_str(ctx, str, true, false);
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

    ret = sss_ncache_set_str(ctx, str, false, false);
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

    ret = sss_ncache_set_str(ctx, str, false, false);
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

    ret = sss_ncache_set_str(ctx, str, false, false);
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
                NC_ENTRY_PREFIX, sizeof(NC_ENTRY_PREFIX) - 1) != 0) {
        /* not interested in this key */
        return 0;
    }

    errno = 0;
    timestamp = strtoull((const char *)data.dptr, &ep, 10);
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

int sss_ncache_reset_permanent(struct sss_nc_ctx *ctx)
{
    int ret;

    ret = tdb_traverse(ctx->tdb, delete_permanent, NULL);
    if (ret < 0)
        return EIO;

    return EOK;
}

static int delete_prefix(struct tdb_context *tdb,
                         TDB_DATA key, TDB_DATA data, void *state)
{
    const char *prefix = (const char *) state;
    unsigned long long int timestamp;
    char *ep = NULL;

    if (strncmp((char *)key.dptr, prefix, strlen(prefix) - 1) != 0) {
        /* not interested in this key */
        return 0;
    }

    errno = 0;
    timestamp = strtoull((const char *)data.dptr, &ep, 10);
    if ((errno == 0) && (*ep == '\0') && (timestamp == 0)) {
        /* skip permanent entries */
        return 0;
    }

    return tdb_delete(tdb, key);
}

static int sss_ncache_reset_pfx(struct sss_nc_ctx *ctx,
                                const char **prefixes)
{
    int ret;

    if (prefixes == NULL) {
        return EOK;
    }

    for (int i = 0; prefixes[i] != NULL; i++) {
        ret = tdb_traverse(ctx->tdb,
                           delete_prefix,
                           discard_const(prefixes[i]));
        if (ret < 0) {
            return EIO;
        }
    }

    return EOK;
}

int sss_ncache_reset_users(struct sss_nc_ctx *ctx)
{
    const char *prefixes[] = {
        NC_USER_PREFIX,
        NC_UID_PREFIX,
        NULL,
    };

    return sss_ncache_reset_pfx(ctx, prefixes);
}

int sss_ncache_reset_groups(struct sss_nc_ctx *ctx)
{
    const char *prefixes[] = {
        NC_GROUP_PREFIX,
        NC_GID_PREFIX,
        NULL,
    };

    return sss_ncache_reset_pfx(ctx, prefixes);
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

/* Reset permanent negcache after checking the domains */
errno_t sss_ncache_reset_repopulate_permanent(struct resp_ctx *rctx,
                                              struct sss_nc_ctx *ncache)
{
    int ret;

    ret = sss_ncache_reset_permanent(ncache);
    if (ret == EOK) {
        ret = sss_ncache_prepopulate(ncache, rctx->cdb, rctx);
    }

    return ret;
}
