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

#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"
#include "db/sysdb_iphosts.h"

struct sdap_get_iphost_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    const char **attrs;
    const char *base_filter;
    char *filter;
    int timeout;
    bool enumeration;

    char *higher_usn;
    struct sysdb_attrs **iphosts;
    size_t count;

    size_t base_iter;
    struct sdap_search_base **search_bases;
};

static errno_t
sdap_get_iphost_next_base(struct tevent_req *req);

struct tevent_req *
sdap_get_iphost_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct sss_domain_info *dom,
                     struct sysdb_ctx *sysdb,
                     struct sdap_options *opts,
                     struct sdap_search_base **search_bases,
                     struct sdap_handle *sh,
                     const char **attrs,
                     const char *filter,
                     int timeout,
                     bool enumeration)
{
    struct sdap_get_iphost_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_get_iphost_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->sysdb = sysdb;
    state->attrs = attrs;
    state->higher_usn = NULL;
    state->iphosts =  NULL;
    state->count = 0;
    state->timeout = timeout;
    state->base_filter = filter;
    state->base_iter = 0;
    state->search_bases = search_bases;
    state->enumeration = enumeration;

    if (state->search_bases == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "IP host lookup request without a search base\n");
        ret = EINVAL;
        goto done;
    }

    ret = sdap_get_iphost_next_base(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, state->ev);
    }

    return req;
}

static void
sdap_get_iphost_process(struct tevent_req *subreq);

static errno_t
sdap_get_iphost_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_get_iphost_state *state;

    state = tevent_req_data(req, struct sdap_get_iphost_state);

    talloc_zfree(state->filter);
    state->filter = sdap_combine_filters(state, state->base_filter,
            state->search_bases[state->base_iter]->filter);
    if (state->filter == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
            "Searching for IP host with base [%s]\n",
            state->search_bases[state->base_iter]->basedn);

    subreq = sdap_get_generic_send(
            state, state->ev, state->opts, state->sh,
            state->search_bases[state->base_iter]->basedn,
            state->search_bases[state->base_iter]->scope,
            state->filter, state->attrs,
            state->opts->iphost_map, SDAP_OPTS_IPHOST,
            state->timeout,
            state->enumeration); /* If we're enumerating, we need paging */
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, sdap_get_iphost_process, req);

    return EOK;
}

static errno_t
sdap_save_iphosts(TALLOC_CTX *mem_ctx,
                  struct sysdb_ctx *sysdb,
                  struct sss_domain_info *dom,
                  struct sdap_options *opts,
                  struct sysdb_attrs **iphosts,
                  size_t num_hosts,
                  char **_usn_value);
static void
sdap_get_iphost_process(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_get_iphost_state *state;
    int ret;
    size_t count, i;
    struct sysdb_attrs **hosts;
    bool next_base = false;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_get_iphost_state);

    ret = sdap_get_generic_recv(subreq, state, &count, &hosts);
    talloc_zfree(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Search for IP hosts returned %zu results.\n",
          count);

    if (state->enumeration || count == 0) {
        /* No hosts found in this search or enumerating */
        next_base = true;
    }

    /* Add this batch of sevices to the list */
    if (count > 0) {
        state->iphosts = talloc_realloc(state, state->iphosts,
                                        struct sysdb_attrs *,
                                        state->count + count + 1);
        if (state->iphosts == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        /* Steal the new hosts into the list */
        for (i = 0; i < count; i++) {
            state->iphosts[state->count + i] =
                talloc_steal(state->iphosts, hosts[i]);
        }

        state->count += count;
        state->iphosts[state->count] = NULL;
    }

    if (next_base) {
        state->base_iter++;
        if (state->search_bases[state->base_iter]) {
            /* There are more search bases to try */
            ret = sdap_get_iphost_next_base(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }
    }

    /* No more search bases
     * Return ENOENT if no hosts were found
     */
    if (state->count == 0) {
        tevent_req_error(req, ENOENT);
        return;
    }

    ret = sdap_save_iphosts(state, state->sysdb, state->dom, state->opts,
                            state->iphosts, state->count, &state->higher_usn);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to store IP hosts.\n");
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Saved %zu IP hosts\n", state->count);

    tevent_req_done(req);
}

static errno_t
sdap_save_iphost(TALLOC_CTX *mem_ctx,
                 struct sysdb_ctx *sysdb,
                 struct sdap_options *opts,
                 struct sss_domain_info *dom,
                 struct sysdb_attrs *attrs,
                 char **_usn_value,
                 time_t now);

static errno_t
sdap_save_iphosts(TALLOC_CTX *mem_ctx,
                  struct sysdb_ctx *sysdb,
                  struct sss_domain_info *dom,
                  struct sdap_options *opts,
                  struct sysdb_attrs **hosts,
                  size_t num_hosts,
                  char **_usn_value)
{
    errno_t ret, sret;
    time_t now;
    size_t i;
    bool in_transaction = false;
    char *higher_usn = NULL;
    char *usn_value;
    TALLOC_CTX *tmp_ctx;

    if (num_hosts == 0) {
        /* Nothing to do */
        return ENOENT;
    }

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

    now = time(NULL);
    for (i = 0; i < num_hosts; i++) {
        usn_value = NULL;

        ret = sdap_save_iphost(tmp_ctx, sysdb, opts, dom, hosts[i],
                               &usn_value, now);

        /* Do not fail completely on errors.
         * Just report the failure to save and go on */
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to store IP host %zu. Ignoring.\n", i);
        } else {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "IP host [%zu/%zu] saved\n", i, num_hosts);
        }

        if (usn_value != NULL) {
            if (higher_usn != NULL) {
                if ((strlen(usn_value) > strlen(higher_usn)) ||
                    (strcmp(usn_value, higher_usn) > 0)) {
                    talloc_zfree(higher_usn);
                    higher_usn = usn_value;
                } else {
                    talloc_zfree(usn_value);
                }
            } else {
                higher_usn = usn_value;
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction!\n");
        goto done;
    }
    in_transaction = false;

    if (_usn_value != NULL) {
        *_usn_value = talloc_steal(mem_ctx, higher_usn);
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to cancel transaction!\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sdap_save_iphost(TALLOC_CTX *mem_ctx,
                 struct sysdb_ctx *sysdb,
                 struct sdap_options *opts,
                 struct sss_domain_info *dom,
                 struct sysdb_attrs *attrs,
                 char **_usn_value,
                 time_t now)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct sysdb_attrs *host_attrs;
    struct ldb_message_element *el;
    char *usn_value = NULL;
    const char *name = NULL;
    const char **aliases = NULL;
    const char **addresses = NULL;
    const char **cased_aliases = NULL;
    const char **cased_addresses = NULL;
    const char **store_aliases = NULL;
    const char **store_addresses = NULL;
    char **missing;
    uint64_t cache_timeout;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    host_attrs = sysdb_new_attrs(tmp_ctx);
    if (host_attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Identify the primary name of this hosts */
    ret = sdap_get_primary_name(opts->iphost_map[SDAP_AT_IPHOST_NAME].name,
                                attrs, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not determine the primary name of the IP host\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "IP host primary name: [%s]\n", name);

    /* Handle any available aliases */
    ret = sysdb_attrs_get_aliases(tmp_ctx, attrs, name,
                                  !dom->case_sensitive,
                                  &aliases);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to identify IP host aliases: [%s]\n",
              strerror(ret));
        goto done;
    }

    /* Get the addresses */
    ret = sysdb_attrs_get_string_array(attrs, SYSDB_IP_HOST_ATTR_ADDRESS,
                                       tmp_ctx, &addresses);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to identify IP host addresses: [%s]\n",
               strerror(ret));
        goto done;
    }

    if (dom->case_sensitive == false) {
        /* Don't perform the extra mallocs if not necessary */
        ret = sss_get_cased_name_list(tmp_ctx, aliases,
                                      dom->case_sensitive, &cased_aliases);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                "Failed to get case_sensitive aliases: [%s]\n",
                strerror(ret));
            goto done;
        }

        ret = sss_get_cased_name_list(tmp_ctx, addresses,
                                      dom->case_sensitive, &cased_addresses);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                "Failed to get case_sensitive addresses: [%s]\n",
                strerror(ret));
            goto done;
        }
    }

    store_aliases = dom->case_sensitive ? aliases : cased_aliases;
    store_addresses = dom->case_sensitive ? addresses : cased_addresses;

    /* Get the USN value, if available */
    ret = sysdb_attrs_get_el(attrs,
                             opts->iphost_map[SDAP_AT_IPHOST_USN].sys_name,
                             &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to retrieve USN value: [%s]\n",
               strerror(ret));
        goto done;
    }

    if (ret == ENOENT || el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Original USN value is not available for [%s].\n",
               name);
    } else {
        ret = sysdb_attrs_add_string(host_attrs,
                          opts->iphost_map[SDAP_AT_IPHOST_USN].sys_name,
                          (const char*)el->values[0].data);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to add USN value: [%s]\n",
                   strerror(ret));
            goto done;
        }
        usn_value = talloc_strdup(tmp_ctx, (const char*)el->values[0].data);
        if (usn_value == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* Make sure to remove any extra attributes from the sysdb
     * that have been removed from LDAP
     */
    ret = list_missing_attrs(host_attrs, opts->iphost_map, SDAP_OPTS_IPHOST,
                             attrs, &missing);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to identify removed attributes: [%s]\n",
               strerror(ret));
        goto done;
    }

    cache_timeout = dom->resolver_timeout;

    ret = sysdb_store_host(dom, name, store_aliases, store_addresses,
                           host_attrs, missing, cache_timeout, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to store IP host in the sysdb: [%s]\n",
               strerror(ret));
        goto done;
    }

    *_usn_value = talloc_steal(mem_ctx, usn_value);

done:
    talloc_free(tmp_ctx);
    return ret;

}

errno_t
sdap_get_iphost_recv(TALLOC_CTX *mem_ctx,
                      struct tevent_req *req,
                      char **usn_value)
{
    struct sdap_get_iphost_state *state;

    state = tevent_req_data(req, struct sdap_get_iphost_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (usn_value != NULL) {
        *usn_value = talloc_steal(mem_ctx, state->higher_usn);
    }

    return EOK;
}

/* Enumeration routines */

struct enum_iphosts_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *id_ctx;
    struct sdap_id_op *op;
    struct sss_domain_info *domain;
    struct sysdb_ctx *sysdb;

    char *filter;
    const char **attrs;
};

static void
enum_iphosts_op_done(struct tevent_req *subreq);

struct tevent_req *
enum_iphosts_send(TALLOC_CTX *memctx,
                   struct tevent_context *ev,
                   struct sdap_id_ctx *id_ctx,
                   struct sdap_id_op *op,
                   bool purge)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct enum_iphosts_state *state;

    req = tevent_req_create(memctx, &state, struct enum_iphosts_state);
    if (!req) return NULL;

    state->ev = ev;
    state->id_ctx = id_ctx;
    state->domain = id_ctx->be->domain;
    state->sysdb = id_ctx->be->domain->sysdb;
    state->op = op;

    if (id_ctx->srv_opts && id_ctx->srv_opts->max_iphost_value && !purge) {
        state->filter = talloc_asprintf(
                state,
                "(&(objectclass=%s)(%s=*)(%s=*)(%s>=%s)(!(%s=%s)))",
                id_ctx->opts->iphost_map[SDAP_OC_IPHOST].name,
                id_ctx->opts->iphost_map[SDAP_AT_IPHOST_NAME].name,
                id_ctx->opts->iphost_map[SDAP_AT_IPHOST_NUMBER].name,
                id_ctx->opts->iphost_map[SDAP_AT_IPHOST_USN].name,
                id_ctx->srv_opts->max_iphost_value,
                id_ctx->opts->iphost_map[SDAP_AT_IPHOST_USN].name,
                id_ctx->srv_opts->max_iphost_value);
    } else {
        state->filter = talloc_asprintf(
                state,
                "(&(objectclass=%s)(%s=*)(%s=*))",
                id_ctx->opts->iphost_map[SDAP_OC_IPHOST].name,
                id_ctx->opts->iphost_map[SDAP_AT_IPHOST_NAME].name,
                id_ctx->opts->iphost_map[SDAP_AT_IPHOST_NUMBER].name);
    }
    if (!state->filter) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to build base filter\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = build_attrs_from_map(state, id_ctx->opts->iphost_map,
                               SDAP_OPTS_IPHOST, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) {
        goto fail;
    }

    subreq = sdap_get_iphost_send(state, state->ev,
                                  state->domain, state->sysdb,
                                  state->id_ctx->opts,
                                  state->id_ctx->opts->sdom->iphost_search_bases,
                                  sdap_id_op_handle(state->op),
                                  state->attrs, state->filter,
                                  dp_opt_get_int(state->id_ctx->opts->basic,
                                                 SDAP_SEARCH_TIMEOUT),
                                  true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, enum_iphosts_op_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
enum_iphosts_op_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct enum_iphosts_state *state =
            tevent_req_data(req, struct enum_iphosts_state);
    char *usn_value = NULL;
    char *endptr = NULL;
    unsigned usn_number;
    int ret;

    ret = sdap_get_iphost_recv(state, subreq, &usn_value);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (usn_value) {
        talloc_zfree(state->id_ctx->srv_opts->max_iphost_value);
        state->id_ctx->srv_opts->max_iphost_value =
                talloc_steal(state->id_ctx, usn_value);
        errno = 0;
        usn_number = strtoul(usn_value, &endptr, 10);
        if (!errno && endptr && (*endptr == '\0') && (endptr != usn_value)
            && (usn_number > state->id_ctx->srv_opts->last_usn)) {
            state->id_ctx->srv_opts->last_usn = usn_number;
        }
    }

    DEBUG(SSSDBG_FUNC_DATA, "IP host higher USN value: [%s]\n",
              state->id_ctx->srv_opts->max_iphost_value);

    tevent_req_done(req);
}

errno_t
enum_iphosts_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
