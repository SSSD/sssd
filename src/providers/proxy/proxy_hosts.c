/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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
#include "db/sysdb_iphosts.h"
#include <resolv.h>
#include <arpa/inet.h>

static errno_t
nss_status_to_errno(enum nss_status status)
{
    switch (status) {
    case NSS_STATUS_SUCCESS:
        return EOK;
    case NSS_STATUS_TRYAGAIN:
        return EAGAIN;
    case NSS_STATUS_NOTFOUND:
        return ENOENT;
    case NSS_STATUS_UNAVAIL:
    default:
        break;
    }

    return EIO;
}

static errno_t
parse_hostent(TALLOC_CTX *mem_ctx,
              struct hostent *result,
              bool case_sensitive,
              char **out_name,
              char ***out_aliases,
              char ***out_addresses)
{
    char **addresses = *out_addresses;
    char **aliases = *out_aliases;
    int i;
    errno_t ret;

    /* Parse addresses */
    for (i = 0; result->h_addr_list[i] != NULL; i++) {
        size_t len = talloc_array_length(addresses);
        char buf[INET6_ADDRSTRLEN];
        const char *addr = NULL;
        bool found = false;
        int j;

        if (result->h_length == INADDRSZ) {
            addr = inet_ntop(AF_INET, result->h_addr_list[i],
                             buf, INET6_ADDRSTRLEN);
        } else if (result->h_length == IN6ADDRSZ) {
            addr = inet_ntop(AF_INET6, result->h_addr_list[i],
                             buf, INET6_ADDRSTRLEN);
        }

        if (addr == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                    "Failed to convert host network address of host "
                    "'%s' to a character string: %s\n", result->h_name,
                    strerror(errno));
            continue;
        }

        /* Skip duplicates */
        for (j = 0;
             j < len && addresses != NULL && addresses[j] != NULL;
             j++) {
            if (strcasecmp(addresses[j], addr) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            ret = add_string_to_list(mem_ctx, addr, &addresses);
            if (ret != EOK) {
                goto done;
            }

            DEBUG(SSSDBG_TRACE_INTERNAL, "Host [%s] has address [%s]\n",
                    result->h_name, addr);
        }
    }

    for (i = 0; result->h_aliases[i] != NULL; i++) {
        size_t len = talloc_array_length(aliases);
        const char *alias = result->h_aliases[i];
        bool found = false;
        int j;

        for (j = 0; j < len && aliases != NULL && aliases[j] != NULL; j++) {
            if (case_sensitive && strcmp(aliases[j], alias) == 0) {
                found = true;
                break;
            } else if (strcasecmp(aliases[j], alias) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            ret = add_string_to_list(mem_ctx, alias, &aliases);
            if (ret != EOK) {
                goto done;
            }

            DEBUG(SSSDBG_TRACE_INTERNAL, "Host [%s] has alias [%s]\n",
                    result->h_name, alias);
        }
    }

    *out_name = talloc_strdup(mem_ctx, result->h_name);
    *out_addresses = addresses;
    *out_aliases = aliases;

    ret = EOK;
done:
    return ret;
}

static errno_t
proxy_save_host(struct sss_domain_info *domain,
                bool lowercase,
                uint64_t cache_timeout,
                char *name,
                char **aliases,
                char **addresses)
{
    errno_t ret;
    char *cased_name = NULL;
    const char **cased_aliases = NULL;
    const char **cased_addresses = NULL;
    TALLOC_CTX *tmp_ctx;
    char *lc_alias = NULL;
    time_t now = time(NULL);

    DEBUG(SSSDBG_TRACE_FUNC, "Saving host [%s] into cache, domain [%s]\n",
          name, domain->name);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    cased_name = sss_get_cased_name(tmp_ctx, name,
                                    domain->case_preserve);
    if (cased_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get cased name.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Count the aliases */
    ret = sss_get_cased_name_list(tmp_ctx,
                                  (const char * const *) aliases,
                                  !lowercase, &cased_aliases);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get cased aliases.\n");
        goto done;
    }

    /* Count the addresses */
    ret = sss_get_cased_name_list(tmp_ctx,
                                  (const char * const *) addresses,
                                  !lowercase, &cased_addresses);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get cased addresses.\n");
        goto done;
    }

    if (domain->case_preserve) {
        /* Add lowercased alias to allow case-insensitive lookup */
        lc_alias = sss_tc_utf8_str_tolower(tmp_ctx, name);
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

    ret = sysdb_store_host(domain, cased_name, cased_aliases, cased_addresses,
                           NULL, NULL, cache_timeout, now);
done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
get_host_by_name_internal(struct proxy_resolver_ctx *ctx,
                          struct sss_domain_info *domain,
                          TALLOC_CTX *mem_ctx,
                          const char *search_name, int af,
                          char **out_name,
                          char ***out_addresses,
                          char ***out_aliases)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *buffer = NULL;
    size_t buflen = DEFAULT_BUFSIZE;
    struct hostent *result = NULL;
    enum nss_status status;
    int err;
    int h_err;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Resolving host [%s] [%s]\n", search_name,
          af == AF_INET ? "AF_INET" : "AF_INET6");

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    result = talloc_zero(tmp_ctx, struct hostent);
    if (result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Ask for IPv4 addresses */
    err = 0;
    h_err = 0;
    for (status = NSS_STATUS_TRYAGAIN,
         err = ERANGE, h_err = 0;
         status == NSS_STATUS_TRYAGAIN && err == ERANGE;
         buflen *= 2)
    {
        buffer = talloc_realloc_size(tmp_ctx, buffer, buflen);
        if (buffer == NULL) {
            ret = ENOMEM;
            goto done;
        }

        status = ctx->ops.gethostbyname2_r(search_name, af, result,
                                           buffer, buflen,
                                           &err, &h_err);
    }

    ret = nss_status_to_errno(status);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                "gethostbyname2_r (%s) failed for host [%s]: %d, %s, %s.\n",
                af == AF_INET ? "AF_INET" : "AF_INET6",
                search_name, status, strerror(err), hstrerror(h_err));
        }

        goto done;
    }

    ret = parse_hostent(mem_ctx, result, domain->case_sensitive,
                        out_name, out_aliases, out_addresses);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse hostent [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
get_host_byname(struct proxy_resolver_ctx *ctx,
                struct sss_domain_info *domain,
                const char *search_name)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret_v4;
    errno_t ret_v6;
    errno_t ret;
    char *name = NULL;
    char **addresses = NULL;
    char **aliases = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Processing request for host name [%s]\n",
          search_name);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret_v4 = get_host_by_name_internal(ctx, domain, tmp_ctx, search_name,
                                       AF_INET, &name, &addresses, &aliases);
    if (ret_v4 != EOK && ret_v4 != ENOENT) {
        ret = ret_v4;
        goto done;
    }

    ret_v6 = get_host_by_name_internal(ctx, domain, tmp_ctx, search_name,
                                       AF_INET6, &name, &addresses, &aliases);
    if (ret_v6 != EOK && ret_v6 != ENOENT) {
        ret = ret_v6;
        goto done;
    }

    if (ret_v4 == ENOENT && ret_v6 == ENOENT) {
        /* Make sure we remove it from the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Host [%s] not found, removing from "
              "cache\n", name);
        sysdb_host_delete(domain, search_name, NULL);
        ret = ENOENT;
        goto done;
    } else {
        /* Results found. Save them into the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Host [%s] found, saving into "
              "cache\n", name);
        ret = proxy_save_host(domain, !domain->case_sensitive,
                              domain->resolver_timeout,
                              name, aliases, addresses);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store host [%s] [%d]: %s\n",
                  name, ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
get_host_by_addr_internal(struct proxy_resolver_ctx *ctx,
                          struct sss_domain_info *domain,
                          TALLOC_CTX *mem_ctx,
                          const char *addrstr,
                          char **out_name,
                          char ***out_addresses,
                          char ***out_aliases)
{
    TALLOC_CTX *tmp_ctx;
    char *buffer = NULL;
    size_t buflen = DEFAULT_BUFSIZE;
    struct hostent *result = NULL;
    enum nss_status status;
    int err;
    int h_err;
    char addrbuf[IN6ADDRSZ];
    socklen_t addrlen = 0;
    int af = 0;
    errno_t ret;
    char *name = NULL;
    char **addresses = NULL;
    char **aliases = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Resolving host [%s]\n", addrstr);

    if (inet_pton(AF_INET, addrstr, addrbuf)) {
        af = AF_INET;
        addrlen = INADDRSZ;
    } else if (inet_pton(AF_INET6, addrstr, addrbuf)) {
        af = AF_INET6;
        addrlen = IN6ADDRSZ;
    } else {
        return EINVAL;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    result = talloc_zero(tmp_ctx, struct hostent);
    if (result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Ask for IPv4 addresses */
    err = 0;
    h_err = 0;
    for (status = NSS_STATUS_TRYAGAIN,
         err = ERANGE, h_err = 0;
         status == NSS_STATUS_TRYAGAIN && err == ERANGE;
         buflen *= 2)
    {
        buffer = talloc_realloc_size(tmp_ctx, buffer, buflen);
        if (buffer == NULL) {
            ret = ENOMEM;
            goto done;
        }

        status = ctx->ops.gethostbyaddr_r(addrbuf, addrlen, af, result,
                                          buffer, buflen,
                                          &err, &h_err);
    }

    ret = nss_status_to_errno(status);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
            "gethostbyaddr_r (%s) failed for host [%s]: %d, %s, %s.\n",
            af == AF_INET ? "AF_INET" : "AF_INET6",
            addrstr, status, strerror(err), hstrerror(h_err));
        goto done;
    }

    if (ret == EOK) {
        ret = parse_hostent(tmp_ctx, result, domain->case_sensitive,
                            &name, &aliases, &addresses);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to parse hostent [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    if (name != NULL) {
        *out_name = talloc_steal(mem_ctx, name);
    }
    if (addresses != NULL) {
        *out_addresses = talloc_steal(mem_ctx, addresses);
    }
    if (aliases != NULL) {
        *out_aliases = talloc_steal(mem_ctx, aliases);
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
get_host_byaddr(struct proxy_resolver_ctx *ctx,
                struct sss_domain_info *domain,
                const char *address)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char *name = NULL;
    char **addresses = NULL;
    char **aliases = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Processing request for host address [%s]\n",
          address);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = get_host_by_addr_internal(ctx, domain, tmp_ctx, address,
                                    &name, &addresses, &aliases);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    if (ret == ENOENT) {
        /* Make sure we remove it from the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Host [%s] not found, removing from "
              "cache\n", address);
        sysdb_host_delete(domain, NULL, address);
    } else {
        /* Results found. Save them into the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Host [%s] found, saving into "
              "cache\n", address);
        ret = proxy_save_host(domain, !domain->case_sensitive,
                              domain->resolver_timeout,
                              name, aliases, addresses);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store host [%s] [%d]: %s\n",
                  name, ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
gethostent_internal(struct proxy_resolver_ctx *ctx,
                    struct sss_domain_info *domain,
                    TALLOC_CTX *mem_ctx,
                    char **out_name,
                    char ***out_addresses,
                    char ***out_aliases)

{
    TALLOC_CTX *tmp_ctx = NULL;
    char *buffer = NULL;
    size_t buflen = DEFAULT_BUFSIZE;
    enum nss_status status;
    struct hostent *result = NULL;
    char *name = NULL;
    char **addresses = NULL;
    char **aliases = NULL;
    int err;
    int h_err;
    errno_t ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    result = talloc_zero(tmp_ctx, struct hostent);
    if (result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (status = NSS_STATUS_TRYAGAIN,
         err = ERANGE, h_err = 0;
         status == NSS_STATUS_TRYAGAIN && err == ERANGE;
         buflen *= 2)
    {
        buffer = talloc_realloc_size(tmp_ctx, buffer, buflen);
        if (buffer == NULL) {
            ret = ENOMEM;
            goto done;
        }

        status = ctx->ops.gethostent_r(result,
                                       buffer, buflen,
                                       &err, &h_err);
    }

    ret = nss_status_to_errno(status);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
            "gethostent_r failed: %d, %s, %s.\n",
            status, strerror(err), hstrerror(h_err));
        goto done;
    }

    if (ret == EOK) {
        ret = parse_hostent(tmp_ctx, result, domain->case_sensitive,
                            &name, &aliases, &addresses);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to parse hostent [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    if (name != NULL) {
        *out_name = talloc_steal(mem_ctx, name);
    }
    if (addresses != NULL) {
        *out_addresses = talloc_steal(mem_ctx, addresses);
    }
    if (aliases != NULL) {
        *out_aliases = talloc_steal(mem_ctx, aliases);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
enum_iphosts(struct proxy_resolver_ctx *ctx,
             struct sss_domain_info *domain)
{
    struct sysdb_ctx *sysdb = domain->sysdb;
    TALLOC_CTX *tmp_ctx = NULL;
    bool in_transaction = false;
    enum nss_status status;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Enumerating iphosts\n");

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    status = ctx->ops.sethostent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

    do {
        char *name = NULL;
        char **addresses = NULL;
        char **aliases = NULL;

        ret = gethostent_internal(ctx, domain, tmp_ctx, &name,
                                     &addresses, &aliases);
        if (ret == EOK) {
            /* Results found. Save them into the cache */
            DEBUG(SSSDBG_TRACE_INTERNAL, "Host [%s] found, saving into "
                  "cache\n", name);

            proxy_save_host(domain, !domain->case_sensitive,
                            domain->resolver_timeout,
                            name, aliases, addresses);
        }

        /* Free children to avoid using too much memory */
        talloc_free_children(tmp_ctx);
    } while (ret == EOK);

    if (ret == ENOENT) {
        /* We are done, commit transaction and stop loop */
        DEBUG(SSSDBG_TRACE_FUNC, "Enumeration completed.\n");
        ret = sysdb_transaction_commit(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
            goto done;
        }
        in_transaction = false;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "gethostent_r failed [%d]: %s\n",
                ret, strerror(ret));
    }

done:
    talloc_free(tmp_ctx);
    if (in_transaction) {
        errno_t sret;

        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not cancel transaction! [%s]\n",
                   strerror(sret));
        }
    }
    ctx->ops.endhostent();
    return ret;
}

static struct dp_reply_std
proxy_hosts_info(TALLOC_CTX *mem_ctx,
                 struct proxy_resolver_ctx *ctx,
                 struct dp_resolver_data *data,
                 struct be_ctx *be_ctx,
                 struct sss_domain_info *domain)
{
    struct dp_reply_std reply;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Processing host request, filter type [%d]\n",
          data->filter_type);

    switch (data->filter_type) {
    case BE_FILTER_NAME:
        ret = get_host_byname(ctx, domain, data->filter_value);
        break;

    case BE_FILTER_ADDR:
        ret = get_host_byaddr(ctx, domain, data->filter_value);
        break;

    case BE_FILTER_ENUM:
        ret = enum_iphosts(ctx, domain);
        break;

    default:
        dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL,
                         "Invalid filter type");
        return reply;
    }

    if (ret) {
        if (ret == ENXIO) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "proxy returned UNAVAIL error, going offline!\n");
            be_mark_offline(be_ctx);
        }

        dp_reply_std_set(&reply, DP_ERR_FATAL, ret, NULL);
        return reply;
    }

    dp_reply_std_set(&reply, DP_ERR_OK, EOK, NULL);
    return reply;
}

struct proxy_hosts_handler_state {
    int dummy;
    struct dp_reply_std reply;
};

struct tevent_req *
proxy_hosts_handler_send(TALLOC_CTX *mem_ctx,
                      struct proxy_resolver_ctx *resolver_ctx,
                      struct dp_resolver_data *resolver_data,
                      struct dp_req_params *params)
{
    struct proxy_hosts_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct proxy_hosts_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->reply = proxy_hosts_info(state, resolver_ctx, resolver_data,
                                    params->be_ctx, params->be_ctx->domain);

    tevent_req_done(req);
    return tevent_req_post(req, params->ev);
}

errno_t
proxy_hosts_handler_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct dp_reply_std *data)
{
    struct proxy_hosts_handler_state *state;

    state = tevent_req_data(req, struct proxy_hosts_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
