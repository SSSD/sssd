/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2020 SUSE LINUX GmbH, Nuernberg, Germany.

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
#include "db/sysdb_ipnetworks.h"
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
parse_netent(TALLOC_CTX *mem_ctx,
             struct netent *result,
             bool case_sensitive,
             char **out_name,
             char ***out_aliases,
             char **out_address)
{
    char **aliases = *out_aliases;
    char addrbuf[INET_ADDRSTRLEN];
    const char *addr = NULL;
    int i;
    errno_t ret;

    if (result->n_addrtype == AF_INET) {
        /* result->n_net is represented in host byte order, but the NSS
         * client, inet_ntop and inet_pton functions expect the address
         * in network byte order
         */
        uint32_t tmpaddr = htonl(result->n_net);
        addr = inet_ntop(AF_INET, &tmpaddr, addrbuf, INET_ADDRSTRLEN);
    }

    if (addr == NULL) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to convert address of network '%s' to a character "
              "string: %s\n", result->n_name, strerror(ret));
        return ret;
    }

    for (i = 0; result->n_aliases[i] != NULL; i++) {
        size_t len = talloc_array_length(aliases);
        const char *alias = result->n_aliases[i];
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

            DEBUG(SSSDBG_TRACE_INTERNAL, "Network [%s] has alias [%s]\n",
                    result->n_name, alias);
        }
    }

    *out_name = talloc_strdup(mem_ctx, result->n_name);
    *out_address = talloc_strdup(mem_ctx, addr);
    *out_aliases = aliases;

    ret = EOK;
done:
    return ret;
}

static errno_t
proxy_save_ipnetwork(struct sss_domain_info *domain,
                     bool lowercase,
                     uint64_t cache_timeout,
                     char *name,
                     char **aliases,
                     char *address)
{
    errno_t ret;
    char *cased_name = NULL;
    const char **cased_aliases = NULL;
    TALLOC_CTX *tmp_ctx;
    char *lc_alias = NULL;
    time_t now = time(NULL);

    DEBUG(SSSDBG_TRACE_FUNC, "Saving network [%s] into cache, domain [%s]\n",
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

    ret = sysdb_store_ipnetwork(domain, cased_name, cased_aliases, address,
                                NULL, NULL, cache_timeout, now);
done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
get_net_byname(struct proxy_resolver_ctx *ctx,
               struct sss_domain_info *domain,
               const char *search_name)
{
    TALLOC_CTX *tmp_ctx;
    struct netent *result = NULL;
    char *buffer = NULL;
    size_t buflen = DEFAULT_BUFSIZE;
    int err = 0;
    int h_err = 0;
    enum nss_status status;
    errno_t ret;
    char *name = NULL;
    char *address = NULL;
    char **aliases = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Resolving network [%s]\n", search_name);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    result = talloc_zero(tmp_ctx, struct netent);
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

        status = ctx->ops.getnetbyname_r(search_name, result,
                                         buffer, buflen,
                                         &err, &h_err);
    }

    ret = nss_status_to_errno(status);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
            "getnetbyname_r failed for network [%s]: %d, %s, %s.\n",
            search_name, status, strerror(err), hstrerror(h_err));
        goto done;
    }

    if (ret == ENOENT) {
        /* Not found, make sure we remove it from the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Network [%s] not found, removing from "
              "cache\n", search_name);
        sysdb_ipnetwork_delete(domain, search_name, NULL);
        ret = ENOENT;
        goto done;
    } else {
        /* Found, parse result */
        ret = parse_netent(tmp_ctx, result, domain->case_sensitive,
                           &name, &aliases, &address);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to parse netent [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        /* Save result into the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Network [%s] found as [%s], saving into "
              "cache\n", search_name, name);
        ret = proxy_save_ipnetwork(domain, !domain->case_sensitive,
                                   domain->resolver_timeout,
                                   name, aliases, address);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store network [%s] [%d]: %s\n",
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
get_net_byaddr(struct proxy_resolver_ctx *ctx,
               struct sss_domain_info *domain,
               const char *search_addrstr)
{
    TALLOC_CTX *tmp_ctx;
    struct netent *result = NULL;
    char *buffer = NULL;
    size_t buflen = DEFAULT_BUFSIZE;
    int err = 0;
    int h_err = 0;
    uint32_t addrbuf;
    enum nss_status status;
    errno_t ret;
    char *name = NULL;
    char *address = NULL;
    char **aliases = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Resolving network [%s]\n", search_addrstr);

    if (inet_pton(AF_INET, search_addrstr, &addrbuf) != 1) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    result = talloc_zero(tmp_ctx, struct netent);
    if (result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* getnetbyaddr_r expects address in host byte order */
    addrbuf = ntohl(addrbuf);

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

        status = ctx->ops.getnetbyaddr_r(addrbuf, AF_INET, result,
                                         buffer, buflen,
                                         &err, &h_err);
    }

    ret = nss_status_to_errno(status);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
            "getnetbyname_r failed for network [%s]: %d, %s, %s.\n",
            search_addrstr, status, strerror(err), hstrerror(h_err));
        goto done;
    }

    if (ret == ENOENT) {
        /* Not found, make sure we remove it from the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Network [%s] not found, removing from "
              "cache\n", search_addrstr);
        sysdb_ipnetwork_delete(domain, NULL, search_addrstr);
        ret = ENOENT;
        goto done;
    } else {
        /* Found, parse result */
        ret = parse_netent(tmp_ctx, result, domain->case_sensitive,
                           &name, &aliases, &address);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to parse netent [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        /* Save result into the cache */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Network [%s] found as [%s], saving into "
              "cache\n", search_addrstr, name);
        ret = proxy_save_ipnetwork(domain, !domain->case_sensitive,
                                   domain->resolver_timeout,
                                   name, aliases, address);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store network [%s] [%d]: %s\n",
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
getnetent_internal(struct proxy_resolver_ctx *ctx,
                   struct sss_domain_info *domain,
                   TALLOC_CTX *mem_ctx,
                   char **out_name,
                   char **out_address,
                   char ***out_aliases)

{
    TALLOC_CTX *tmp_ctx = NULL;
    char *buffer = NULL;
    size_t buflen = DEFAULT_BUFSIZE;
    enum nss_status status;
    struct netent *result = NULL;
    char *name = NULL;
    char *address = NULL;
    char **aliases = NULL;
    int err;
    int h_err;
    errno_t ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    result = talloc_zero(tmp_ctx, struct netent);
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

        status = ctx->ops.getnetent_r(result,
                                      buffer, buflen,
                                      &err, &h_err);
    }

    ret = nss_status_to_errno(status);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
            "getnetent_r failed: %d, %s, %s.\n",
            status, strerror(err), hstrerror(h_err));
        goto done;
    }

    if (ret == EOK) {
        ret = parse_netent(tmp_ctx, result, domain->case_sensitive,
                           &name, &aliases, &address);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to parse netent [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    if (name != NULL) {
        *out_name = talloc_steal(mem_ctx, name);
    }
    if (address != NULL) {
        *out_address = talloc_steal(mem_ctx, address);
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
enum_ipnetworks(struct proxy_resolver_ctx *ctx,
                struct sss_domain_info *domain)
{
    struct sysdb_ctx *sysdb = domain->sysdb;
    TALLOC_CTX *tmp_ctx = NULL;
    bool in_transaction = false;
    enum nss_status status;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Enumerating IP networks\n");

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

    status = ctx->ops.setnetent();
    if (status != NSS_STATUS_SUCCESS) {
        ret = EIO;
        goto done;
    }

    do {
        char *name = NULL;
        char *address = NULL;
        char **aliases = NULL;

        ret = getnetent_internal(ctx, domain, tmp_ctx, &name,
                                 &address, &aliases);
        if (ret == EOK) {
            /* Results found. Save them into the cache */
            DEBUG(SSSDBG_TRACE_INTERNAL, "IP network [%s] found, saving into "
                  "cache\n", name);

            proxy_save_ipnetwork(domain, !domain->case_sensitive,
                                 domain->resolver_timeout,
                                 name, aliases, address);
        }

        /* Free children to avoid using too much memory */
        talloc_free_children(tmp_ctx);
    } while (ret == EOK);

    if (ret == ENOENT) {
        /* We are done, commit transaction and stop loop */
        DEBUG(SSSDBG_TRACE_FUNC, "IP networks enumeration completed.\n");
        ret = sysdb_transaction_commit(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
            goto done;
        }
        in_transaction = false;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "getnetent_r failed [%d]: %s\n",
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
    ctx->ops.endnetent();
    return ret;
}

static struct dp_reply_std
proxy_nets_info(TALLOC_CTX *mem_ctx,
                struct proxy_resolver_ctx *ctx,
                struct dp_resolver_data *data,
                struct be_ctx *be_ctx,
                struct sss_domain_info *domain)
{
    struct dp_reply_std reply;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Processing networks request, filter type [%d]\n",
          data->filter_type);

    switch (data->filter_type) {
    case BE_FILTER_NAME:
        ret = get_net_byname(ctx, domain, data->filter_value);
        break;

    case BE_FILTER_ADDR:
        ret = get_net_byaddr(ctx, domain, data->filter_value);
        break;

    case BE_FILTER_ENUM:
        ret = enum_ipnetworks(ctx, domain);
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

struct proxy_nets_handler_state {
    struct dp_reply_std reply;
};

struct tevent_req *
proxy_nets_handler_send(TALLOC_CTX *mem_ctx,
                        struct proxy_resolver_ctx *resolver_ctx,
                        struct dp_resolver_data *resolver_data,
                        struct dp_req_params *params)
{
    struct proxy_nets_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct proxy_nets_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->reply = proxy_nets_info(state, resolver_ctx, resolver_data,
                                   params->be_ctx, params->be_ctx->domain);

    tevent_req_done(req);
    return tevent_req_post(req, params->ev);
}

errno_t
proxy_nets_handler_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        struct dp_reply_std *data)
{
    struct proxy_nets_handler_state *state;

    state = tevent_req_data(req, struct proxy_nets_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
