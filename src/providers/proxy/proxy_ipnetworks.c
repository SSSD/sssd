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
              "cache\n", name);
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
        DEBUG(SSSDBG_TRACE_INTERNAL, "Network [%s] found, saving into "
              "cache\n", name);
        /* TODO */
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
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
        /* TODO */
        /* FALLTHROUGH */

    case BE_FILTER_ENUM:
        /* TODO */
        /* FALLTHROUGH */

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
