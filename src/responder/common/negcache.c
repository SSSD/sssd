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
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include <fcntl.h>
#include <time.h>
#include "tdb.h"

#define NC_ENTRY_PREFIX "NCE/"
#define NC_USER_PREFIX NC_ENTRY_PREFIX"USER"
#define NC_GROUP_PREFIX NC_ENTRY_PREFIX"GROUP"
#define NC_NETGROUP_PREFIX NC_ENTRY_PREFIX"NETGR"
#define NC_SERVICE_PREFIX NC_ENTRY_PREFIX"SERVICE"
#define NC_UID_PREFIX NC_ENTRY_PREFIX"UID"
#define NC_GID_PREFIX NC_ENTRY_PREFIX"GID"

struct sss_nc_ctx {
    struct tdb_context *tdb;
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

int sss_ncache_init(TALLOC_CTX *memctx, struct sss_nc_ctx **_ctx)
{
    struct sss_nc_ctx *ctx;

    ctx = talloc_zero(memctx, struct sss_nc_ctx);
    if (!ctx) return ENOMEM;

    errno = 0;
    /* open a memory only tdb with default hash size */
    ctx->tdb = tdb_open("memcache", 0, TDB_INTERNAL, O_RDWR|O_CREAT, 0);
    if (!ctx->tdb) return errno;

    *_ctx = ctx;
    return EOK;
};

static int sss_ncache_check_str(struct sss_nc_ctx *ctx, char *str, int ttl)
{
    TDB_DATA key;
    TDB_DATA data;
    unsigned long long int timestamp;
    bool expired = false;
    char *ep;
    int ret;

    DEBUG(8, ("Checking negative cache for [%s]\n", str));

    data.dptr = NULL;

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

    free(data.dptr);
    return ret;
}

static int sss_ncache_set_str(struct sss_nc_ctx *ctx,
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

    DEBUG(6, ("Adding [%s] to negative cache%s\n",
              str, permanent?" permanently":""));

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

static int sss_ncache_check_user_int(struct sss_nc_ctx *ctx, int ttl,
                                     const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_USER_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

static int sss_ncache_check_group_int(struct sss_nc_ctx *ctx, int ttl,
                                      const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_GROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

static int sss_ncache_check_netgr_int(struct sss_nc_ctx *ctx, int ttl,
                                      const char *domain, const char *name)
{
    char *str;
    int ret;

    if (!name || !*name) return EINVAL;

    str = talloc_asprintf(ctx, "%s/%s/%s", NC_NETGROUP_PREFIX, domain, name);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

static int sss_ncache_check_service_int(struct sss_nc_ctx *ctx,
                                        int ttl,
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

    ret = sss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

typedef int (*ncache_check_byname_fn_t)(struct sss_nc_ctx *, int,
                                        const char *, const char *);

static int sss_cache_check_ent(struct sss_nc_ctx *ctx, int ttl,
                               struct sss_domain_info *dom, const char *name,
                               ncache_check_byname_fn_t checker)
{
    char *lower;
    errno_t ret;

    if (dom->case_sensitive == false) {
        lower = sss_tc_utf8_str_tolower(ctx, name);
        if (!lower) return ENOMEM;
        ret = checker(ctx, ttl, dom->name, lower);
        talloc_free(lower);
    } else {
        ret = checker(ctx, ttl, dom->name, name);
    }

    return ret;
}

int sss_ncache_check_user(struct sss_nc_ctx *ctx, int ttl,
                          struct sss_domain_info *dom, const char *name)
{
    return sss_cache_check_ent(ctx, ttl, dom, name,
                               sss_ncache_check_user_int);
}

int sss_ncache_check_group(struct sss_nc_ctx *ctx, int ttl,
                           struct sss_domain_info *dom, const char *name)
{
    return sss_cache_check_ent(ctx, ttl, dom, name,
                               sss_ncache_check_group_int);
}

int sss_ncache_check_netgr(struct sss_nc_ctx *ctx, int ttl,
                           struct sss_domain_info *dom, const char *name)
{
    return sss_cache_check_ent(ctx, ttl, dom, name,
                               sss_ncache_check_netgr_int);
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

int sss_ncache_check_service(struct sss_nc_ctx *ctx, int ttl,
                             struct sss_domain_info *dom,
                             const char *name,
                             const char *proto)
{
    int ret;
    char *service_and_protocol = talloc_asprintf(ctx, "%s:%s",
                                                 name,
                                                 proto ? proto : "<ANY>");
    if (!service_and_protocol) return ENOMEM;

    ret = sss_cache_check_ent(ctx, ttl, dom, service_and_protocol,
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

int sss_ncache_check_service_port(struct sss_nc_ctx *ctx, int ttl,
                                  struct sss_domain_info *dom,
                                  uint16_t port,
                                  const char *proto)
{
    int ret;
    char *service_and_protocol = talloc_asprintf(ctx, "%ul:%s",
                                                 port,
                                                 proto ? proto : "<ANY>");
    if (!service_and_protocol) return ENOMEM;

    ret = sss_cache_check_ent(ctx, ttl, dom, service_and_protocol,
                              sss_ncache_check_service_int);
    talloc_free(service_and_protocol);
    return ret;
}



int sss_ncache_check_uid(struct sss_nc_ctx *ctx, int ttl, uid_t uid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_UID_PREFIX, uid);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str, ttl);

    talloc_free(str);
    return ret;
}

int sss_ncache_check_gid(struct sss_nc_ctx *ctx, int ttl, gid_t gid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_GID_PREFIX, gid);
    if (!str) return ENOMEM;

    ret = sss_ncache_check_str(ctx, str, ttl);

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

int sss_ncache_set_uid(struct sss_nc_ctx *ctx, bool permanent, uid_t uid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_UID_PREFIX, uid);
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

    talloc_free(str);
    return ret;
}

int sss_ncache_set_gid(struct sss_nc_ctx *ctx, bool permanent, gid_t gid)
{
    char *str;
    int ret;

    str = talloc_asprintf(ctx, "%s/%u", NC_GID_PREFIX, gid);
    if (!str) return ENOMEM;

    ret = sss_ncache_set_str(ctx, str, permanent);

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

int sss_ncache_reset_permament(struct sss_nc_ctx *ctx)
{
    int ret;

    ret = tdb_traverse(ctx->tdb, delete_permanent, NULL);
    if (ret < 0)
        return EIO;

    return EOK;
}

errno_t sss_ncache_prepopulate(struct sss_nc_ctx *ncache,
                               struct confdb_ctx *cdb,
                               struct sss_names_ctx *names_ctx,
                               struct sss_domain_info *domain_list)
{
    errno_t ret;
    bool filter_set = false;
    char **filter_list = NULL;
    char *name = NULL;
    struct sss_domain_info *dom = NULL;
    char *domainname = NULL;
    char *conf_path = NULL;
    TALLOC_CTX *tmpctx = talloc_new(NULL);
    int i;

    /* Populate domain-specific negative cache entries */
    for (dom = domain_list; dom; dom = dom->next) {
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
        filter_set = true;

        for (i = 0; (filter_list && filter_list[i]); i++) {
            ret = sss_parse_name(tmpctx, names_ctx, filter_list[i],
                                 &domainname, &name);
            if (ret != EOK) {
                DEBUG(1, ("Invalid name in filterUsers list: [%s] (%d)\n",
                         filter_list[i], ret));
                continue;
            }

            if (domainname && strcmp(domainname, dom->name)) {
                DEBUG(1, ("Mismatch between domain name (%s) and name "
                          "set in FQN  (%s), skipping user %s\n",
                          dom->name, domainname, name));
                continue;
            }

            ret = sss_ncache_set_user(ncache, true, dom, name);
            if (ret != EOK) {
                DEBUG(1, ("Failed to store permanent user filter for [%s]"
                          " (%d [%s])\n", filter_list[i],
                          ret, strerror(ret)));
                continue;
            }
        }
    }

    ret = confdb_get_string_as_list(cdb, tmpctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_FILTER_USERS, &filter_list);
    if (ret == ENOENT) {
        if (!filter_set) {
            filter_list = talloc_array(tmpctx, char *, 2);
            if (!filter_list) {
                ret = ENOMEM;
                goto done;
            }
            filter_list[0] = talloc_strdup(tmpctx, "root");
            if (!filter_list[0]) {
                ret = ENOMEM;
                goto done;
            }
            filter_list[1] = NULL;
        }
    }
    else if (ret != EOK) goto done;

    for (i = 0; (filter_list && filter_list[i]); i++) {
        ret = sss_parse_name(tmpctx, names_ctx, filter_list[i],
                             &domainname, &name);
        if (ret != EOK) {
            DEBUG(1, ("Invalid name in filterUsers list: [%s] (%d)\n",
                     filter_list[i], ret));
            continue;
        }
        if (domainname) {
            dom = responder_get_domain(domain_list, domainname);
            if (!dom) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      ("Invalid domain name [%s]\n", domainname));
                continue;
            }

            ret = sss_ncache_set_user(ncache, true, dom, name);
            if (ret != EOK) {
                DEBUG(1, ("Failed to store permanent user filter for [%s]"
                          " (%d [%s])\n", filter_list[i],
                          ret, strerror(ret)));
                continue;
            }
        } else {
            for (dom = domain_list; dom; dom = dom->next) {
                ret = sss_ncache_set_user(ncache, true, dom, name);
                if (ret != EOK) {
                   DEBUG(1, ("Failed to store permanent user filter for"
                             " [%s:%s] (%d [%s])\n",
                             dom->name, filter_list[i],
                             ret, strerror(ret)));
                    continue;
                }
            }
        }
    }

    filter_set = false;
    for (dom = domain_list; dom; dom = dom->next) {
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
        filter_set = true;

        for (i = 0; (filter_list && filter_list[i]); i++) {
            ret = sss_parse_name(tmpctx, names_ctx, filter_list[i],
                                 &domainname, &name);
            if (ret != EOK) {
                DEBUG(1, ("Invalid name in filterGroups list: [%s] (%d)\n",
                         filter_list[i], ret));
                continue;
            }

            if (domainname && strcmp(domainname, dom->name)) {
                DEBUG(1, ("Mismatch betwen domain name (%s) and name "
                          "set in FQN  (%s), skipping group %s\n",
                          dom->name, domainname, name));
                continue;
            }

            ret = sss_ncache_set_group(ncache, true, dom, name);
            if (ret != EOK) {
                DEBUG(1, ("Failed to store permanent group filter for [%s]"
                          " (%d [%s])\n", filter_list[i],
                          ret, strerror(ret)));
                continue;
            }
        }
    }

    ret = confdb_get_string_as_list(cdb, tmpctx, CONFDB_NSS_CONF_ENTRY,
                                    CONFDB_NSS_FILTER_GROUPS, &filter_list);
    if (ret == ENOENT) {
        if (!filter_set) {
            filter_list = talloc_array(tmpctx, char *, 2);
            if (!filter_list) {
                ret = ENOMEM;
                goto done;
            }
            filter_list[0] = talloc_strdup(tmpctx, "root");
            if (!filter_list[0]) {
                ret = ENOMEM;
                goto done;
            }
            filter_list[1] = NULL;
        }
    }
    else if (ret != EOK) goto done;

    for (i = 0; (filter_list && filter_list[i]); i++) {
        ret = sss_parse_name(tmpctx, names_ctx, filter_list[i],
                             &domainname, &name);
        if (ret != EOK) {
            DEBUG(1, ("Invalid name in filterGroups list: [%s] (%d)\n",
                     filter_list[i], ret));
            continue;
        }
        if (domainname) {
            dom = responder_get_domain(domain_list, domainname);
            if (!dom) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      ("Invalid domain name [%s]\n", domainname));
                continue;
            }

            ret = sss_ncache_set_group(ncache, true, dom, name);
            if (ret != EOK) {
                DEBUG(1, ("Failed to store permanent group filter for"
                          " [%s] (%d [%s])\n", filter_list[i],
                          ret, strerror(ret)));
                continue;
            }
        } else {
            for (dom = domain_list; dom; dom = dom->next) {
                ret = sss_ncache_set_group(ncache, true, dom, name);
                if (ret != EOK) {
                   DEBUG(1, ("Failed to store permanent group filter for"
                             " [%s:%s] (%d [%s])\n",
                             dom->name, filter_list[i],
                             ret, strerror(ret)));
                    continue;
                }
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmpctx);
    return ret;
}
