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
proxy_save_service(struct sss_domain_info *domain,
                   struct servent *svc,
                   bool lowercase,
                   uint64_t cache_timeout)
{
    errno_t ret;
    char *cased_name;
    const char **protocols;
    const char **cased_aliases;
    TALLOC_CTX *tmp_ctx;
    char *lc_alias = NULL;
    time_t now = time(NULL);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    cased_name = sss_get_cased_name(tmp_ctx, svc->s_name,
                                    domain->case_preserve);
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
    ret = sss_get_cased_name_list(tmp_ctx,
                                  (const char * const *) svc->s_aliases,
                                  !lowercase, &cased_aliases);
    if (ret != EOK) {
        goto done;
    }

    if (domain->case_preserve) {
        /* Add lowercased alias to allow case-insensitive lookup */
        lc_alias = sss_tc_utf8_str_tolower(tmp_ctx, svc->s_name);
        if (lc_alias == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot convert name to lowercase.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = add_string_to_list(tmp_ctx, lc_alias,
                                 discard_const_p(char **, &cased_aliases));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add lowercased name alias.\n");
            goto done;
        }
    }

    ret = sysdb_store_service(domain,
                              cased_name,
                              ntohs(svc->s_port),
                              cased_aliases,
                              protocols,
                              NULL, NULL,
                              cache_timeout,
                              now);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
get_serv_byname(struct proxy_id_ctx *ctx,
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
              "getservbyname_r failed for service [%s].\n", name);
        goto done;
    }

    if (status == NSS_STATUS_NOTFOUND) {
        /* Make sure we remove it from the cache */
        ret = sysdb_svc_delete(dom, name, 0, protocol);
    } else {

        /* Results found. Save them into the cache */
        ret = proxy_save_service(dom, result,
                                 !dom->case_sensitive,
                                 dom->service_timeout);
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
get_serv_byport(struct proxy_id_ctx *ctx,
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

    port = htons(strtouint16(be_filter, NULL, 0));
    if (errno) {
        ret = errno;
        goto done;
    }

    status = ctx->ops.getservbyport_r(port, protocol, result,
                                      buffer, BUFLEN, &ret);
    if (status != NSS_STATUS_SUCCESS && status != NSS_STATUS_NOTFOUND) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "getservbyport_r failed for service [%s].\n", be_filter);
        goto done;
    }

    if (status == NSS_STATUS_NOTFOUND) {
        /* Make sure we remove it from the cache */
        ret = sysdb_svc_delete(dom, NULL, port, protocol);
    } else {
        /* Results found. Save them into the cache */
        ret = proxy_save_service(dom, result,
                                 !dom->case_sensitive,
                                 dom->service_timeout);
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
enum_services(struct proxy_id_ctx *ctx,
              struct sysdb_ctx *sysdb,
              struct sss_domain_info *dom)
{
    TALLOC_CTX *tmpctx;
    bool in_transaction = false;
    struct servent *svc;
    enum nss_status status;
    size_t buflen;
    char *buffer;
    char *newbuf;
    errno_t ret, sret;
    time_t now = time(NULL);
    const char **protocols;
    const char **cased_aliases;
    bool again;

    DEBUG(SSSDBG_TRACE_FUNC, "Enumerating services\n");

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    svc = talloc(tmpctx, struct servent);
    if (!svc) {
        ret = ENOMEM;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = talloc_size(tmpctx, buflen);
    if (!buffer) {
        ret = ENOMEM;
        goto done;
    }

    protocols = talloc_zero_array(tmpctx, const char *, 2);
    if (protocols == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.setservent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

    do {
        again = false;

        /* always zero out the svc structure */
        memset(svc, 0, sizeof(struct servent));

        /* get entry */
        status = ctx->ops.getservent_r(svc, buffer, buflen, &ret);

        switch (status) {
            case NSS_STATUS_TRYAGAIN:
                /* buffer too small? */
                if (buflen < MAX_BUF_SIZE) {
                    buflen *= 2;
                }
                if (buflen > MAX_BUF_SIZE) {
                    buflen = MAX_BUF_SIZE;
                }
                newbuf = talloc_realloc_size(tmpctx, buffer, buflen);
                if (!newbuf) {
                    ret = ENOMEM;
                    goto done;
                }
                buffer = newbuf;
                again = true;
                break;

            case NSS_STATUS_NOTFOUND:

                /* we are done here */
                DEBUG(SSSDBG_TRACE_FUNC, "Enumeration completed.\n");

                ret = sysdb_transaction_commit(sysdb);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
                    goto done;
                }

                in_transaction = false;
                break;

            case NSS_STATUS_SUCCESS:

                DEBUG(SSSDBG_TRACE_INTERNAL,
                        "Service found (%s, %d/%s)\n",
                         svc->s_name, svc->s_port, svc->s_proto);

                protocols[0] = sss_get_cased_name(protocols, svc->s_proto,
                        dom->case_sensitive);
                if (!protocols[0]) {
                    ret = ENOMEM;
                    goto done;
                }
                protocols[1] = NULL;

                ret = sss_get_cased_name_list(tmpctx,
                        (const char * const *) svc->s_aliases,
                        dom->case_sensitive, &cased_aliases);
                if (ret != EOK) {
                    /* Do not fail completely on errors.
                     * Just report the failure to save and go on */
                    DEBUG(SSSDBG_OP_FAILURE,
                            "Failed to store service [%s]. Ignoring.\n",
                             strerror(ret));
                    again = true;
                    break;
                }

                ret = sysdb_store_service(dom,
                                          svc->s_name,
                                          svc->s_port,
                                          cased_aliases,
                                          protocols,
                                          NULL, NULL,
                                          dom->service_timeout,
                                          now);
                if (ret) {
                    /* Do not fail completely on errors.
                     * Just report the failure to save and go on */
                    DEBUG(SSSDBG_OP_FAILURE,
                            "Failed to store service [%s]. Ignoring.\n",
                             strerror(ret));
                }
                again = true;
                break;

            case NSS_STATUS_UNAVAIL:
                /* "remote" backend unavailable. Enter offline mode */
                ret = ENXIO;
                break;

            default:
                ret = EIO;
                DEBUG(SSSDBG_CRIT_FAILURE,
                        "proxy -> getservent_r failed (%d)[%s]\n",
                         ret, strerror(ret));
                break;
        }
    } while (again);

done:
    talloc_zfree(tmpctx);
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not cancel transaction! [%s]\n",
                   strerror(sret));
        }
    }
    ctx->ops.endservent();
    return ret;
}
