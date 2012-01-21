/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "providers/proxy/proxy.h"
#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb_services.h"

#define BUFLEN  1024

errno_t
proxy_save_service(struct sysdb_ctx *sysdb,
                   struct servent *svc,
                   bool lowercase,
                   uint64_t cache_timeout)
{
    errno_t ret;
    char *cased_name;
    const char **protocols;
    const char **cased_aliases;
    TALLOC_CTX *tmp_ctx;
    size_t num_aliases, i;
    time_t now = time(NULL);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    cased_name = sss_get_cased_name(tmp_ctx, svc->s_name, !lowercase);
    if (!cased_name) {
        ret = ENOMEM;
        goto done;
    }

    protocols = talloc_array(tmp_ctx, const char *, 2);
    if (!protocols) {
        ret = ENOMEM;
        goto done;
    }

    protocols[0] = sss_get_cased_name(protocols, svc->s_proto,
                                      !lowercase);
    if (!protocols[0]) {
        ret = ENOMEM;
        goto done;
    }
    protocols[1] = NULL;

    /* Count the aliases */
    for(num_aliases = 0; svc->s_aliases[num_aliases]; num_aliases++);

    if (num_aliases >= 1) {
        cased_aliases = talloc_array(tmp_ctx, const char *, num_aliases + 1);
        if (!cased_aliases) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < num_aliases; i++) {
            cased_aliases[i] = sss_get_cased_name(tmp_ctx, svc->s_aliases[i],
                                                  !lowercase);
            if (!cased_aliases[i]) {
                ret = ENOMEM;
                goto done;
            }
        }
        cased_aliases[num_aliases] = NULL;
    } else {
        cased_aliases = NULL;
    }

    ret = sysdb_store_service(sysdb,
                              cased_name,
                              ntohs(svc->s_port),
                              cased_aliases,
                              protocols,
                              cache_timeout,
                              now);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
get_serv_byname(struct proxy_id_ctx *ctx,
                struct sysdb_ctx *sysdb,
                struct sss_domain_info *dom,
                const char *name,
                const char *protocol)
{
    errno_t ret;
    enum nss_status status;
    struct servent *result;
    TALLOC_CTX *tmp_ctx;
    char buffer[BUFLEN];

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    result = talloc_zero(tmp_ctx, struct servent);
    if (!result) {
        ret = ENOMEM;
        goto done;
    }

    status = ctx->ops.getservbyname_r(name, protocol, result,
                                      buffer, BUFLEN, &ret);
    if (status != NSS_STATUS_SUCCESS && status != NSS_STATUS_NOTFOUND) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("getservbyname_r failed for service [%s].\n", name));
        return ret;
    }

    if (status == NSS_STATUS_NOTFOUND) {
        /* Make sure we remove it from the cache */
        ret = sysdb_svc_delete(sysdb, name, 0, protocol);
    } else {

        /* Results found. Save them into the cache */
        ret = proxy_save_service(sysdb, result,
                                 !dom->case_sensitive,
                                 ctx->entry_cache_timeout);
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
get_serv_byport(struct proxy_id_ctx *ctx,
                struct sysdb_ctx *sysdb,
                struct sss_domain_info *dom,
                const char *be_filter,
                const char *protocol)
{
    errno_t ret;
    enum nss_status status;
    struct servent *result;
    TALLOC_CTX *tmp_ctx;
    uint16_t port;
    char buffer[BUFLEN];

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    result = talloc_zero(tmp_ctx, struct servent);
    if (!result) {
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    port = htons(strtouint16(be_filter, NULL, 0));
    if (errno) {
        ret = errno;
        goto done;
    }

    status = ctx->ops.getservbyport_r(port, protocol, result,
                                      buffer, BUFLEN, &ret);
    if (status != NSS_STATUS_SUCCESS && status != NSS_STATUS_NOTFOUND) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("getservbyport_r failed for service [%s].\n", be_filter));
        return ret;
    }

    if (status == NSS_STATUS_NOTFOUND) {
        /* Make sure we remove it from the cache */
        ret = sysdb_svc_delete(sysdb, NULL, port, protocol);
    } else {
        /* Results found. Save them into the cache */
        ret = proxy_save_service(sysdb, result,
                                 !dom->case_sensitive,
                                 ctx->entry_cache_timeout);
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}
