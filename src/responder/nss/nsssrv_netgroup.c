/*
    SSSD

    nsssrv_netgroup.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <collection.h>
#include "util/util.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_private.h"
#include "responder/nss/nsssrv_netgroup.h"
#include "responder/common/negcache.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"

static errno_t get_netgroup_entry(struct nss_ctx *nctx,
                                  char *name,
                                  struct getent_ctx **netgr)
{
    hash_key_t key;
    hash_value_t value;
    int hret;

    key.type = HASH_KEY_STRING;
    key.str = name;

    hret = hash_lookup(nctx->netgroups, &key, &value);
    if (hret == HASH_SUCCESS) {
        *netgr = talloc_get_type(value.ptr, struct getent_ctx);
        return EOK;
    } else if (hret == HASH_ERROR_KEY_NOT_FOUND) {
        return ENOENT;
    }

    DEBUG(1, ("Unexpected error reading from netgroup hash [%d][%s]\n",
              hret, hash_error_string(hret)));
    return EIO;
}

static int netgr_hash_remove (TALLOC_CTX *ctx);
static errno_t set_netgroup_entry(struct nss_ctx *nctx,
                                  struct getent_ctx *netgr)
{
    hash_key_t key;
    hash_value_t value;
    int hret;

    if (netgr->name == NULL) {
        DEBUG(1, ("Missing netgroup name.\n"));
        return EINVAL;
    }
    /* Add this entry to the hash table */
    key.type = HASH_KEY_STRING;
    key.str = netgr->name;
    value.type = HASH_VALUE_PTR;
    value.ptr = netgr;
    hret = hash_enter(nctx->netgroups, &key, &value);
    if (hret != EOK) {
        DEBUG(0, ("Unable to add hash table entry for [%s]", key.str));
        DEBUG(4, ("Hash error [%d][%s]", hret, hash_error_string(hret)));
        return EIO;
    }
    talloc_steal(nctx->netgroups, netgr);
    talloc_set_destructor((TALLOC_CTX *) netgr, netgr_hash_remove);

    return EOK;
}

static struct tevent_req *setnetgrent_send(TALLOC_CTX *mem_ctx,
                                           const char *rawname,
                                           struct nss_cmd_ctx *cmdctx);
static void nss_cmd_setnetgrent_done(struct tevent_req *req);
int nss_cmd_setnetgrent(struct cli_ctx *client)
{
    struct nss_cmd_ctx *cmdctx;
    struct tevent_req *req;
    const char *rawname;
    uint8_t *body;
    size_t blen;
    errno_t ret = EOK;

    /* Reset the result cursor to zero */
    client->netgrent_cur = 0;

    cmdctx = talloc_zero(client, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = client;

    /* get netgroup name to query */
    sss_packet_get_body(client->creq->in, &body, &blen);

    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        ret = EINVAL;
        goto done;
    }

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(body, blen -1)) {
        ret = EINVAL;
        goto done;
    }

    rawname = (const char *)body;

    req = setnetgrent_send(cmdctx, rawname, cmdctx);
    if (!req) {
        DEBUG(0, ("Fatal error calling setnetgrent_send\n"));
        ret = EIO;
        goto done;
    }
    tevent_req_set_callback(req, nss_cmd_setnetgrent_done, cmdctx);

done:
    return nss_cmd_done(cmdctx, ret);
}

static int netgr_hash_remove (TALLOC_CTX *ctx)
{
    int hret;
    hash_key_t key;
    struct getent_ctx *netgr =
            talloc_get_type(ctx, struct getent_ctx);

    key.type = HASH_KEY_STRING;
    key.str = netgr->name;

    /* Remove the netgroup result object from the lookup table */
    hret = hash_delete(netgr->lookup_table, &key);
    if (hret != HASH_SUCCESS) {
        DEBUG(0, ("Could not remove key [%s] from table! [%d][%s]\n",
                  netgr->name, hret, hash_error_string(hret)));
        return -1;
    }
    return 0;
}

struct setnetgrent_ctx {
    struct nss_ctx *nctx;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;
    char *netgr_shortname;
    struct getent_ctx *netgr;
    const char *rawname;
};
static errno_t setnetgrent_retry(struct tevent_req *req);
static errno_t lookup_netgr_step(struct setent_step_ctx *step_ctx);
static struct tevent_req *setnetgrent_send(TALLOC_CTX *mem_ctx,
                                           const char *rawname,
                                           struct nss_cmd_ctx *cmdctx)
{
    char *domname;
    errno_t ret;
    struct tevent_req *req;
    struct setnetgrent_ctx *state;
    struct nss_dom_ctx *dctx;

    struct cli_ctx *client = cmdctx->cctx;
    struct nss_ctx *nctx =
            talloc_get_type(client->rctx->pvt_ctx, struct nss_ctx);

    req = tevent_req_create(mem_ctx, &state, struct setnetgrent_ctx);
    if (!req) {
        DEBUG(0, ("Could not create tevent request for setnetgrent\n"));
        return NULL;
    }

    state->nctx = nctx;
    state->cmdctx = cmdctx;
    state->rawname = rawname;

    state->dctx = talloc_zero(state, struct nss_dom_ctx);
    if (!state->dctx) {
        ret = ENOMEM;
        goto error;
    }
    dctx = state->dctx;
    dctx->cmdctx = state->cmdctx;

    ret = sss_parse_name_for_domains(state, client->rctx->domains, rawname,
                                     &domname, &state->netgr_shortname);
    if (ret != EOK) {
        DEBUG(2, ("Invalid name received [%s]\n", rawname));
        goto error;
    }

    DEBUG(4, ("Requesting info for netgroup [%s] from [%s]\n",
              state->netgr_shortname, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(dctx, client->rctx, domname);
        if (!dctx->domain) {
            ret = EINVAL;
            goto error;
        }

        /* Save the netgroup name for getnetgrent */
        client->netgr_name = talloc_strdup(client, rawname);
        if (!client->netgr_name) {
            ret = ENOMEM;
            goto error;
        }
    } else {
        /* this is a multidomain search */
        dctx->domain = client->rctx->domains;
        cmdctx->check_next = true;

        /* Save the netgroup name for getnetgrent */
        client->netgr_name = talloc_strdup(client, state->netgr_shortname);
        if (!client->netgr_name) {
            ret = ENOMEM;
            goto error;
        }
    }

    ret = setnetgrent_retry(req);
    if (ret != EOK) {
        if (ret == EAGAIN) {
            /* We need to reenter the mainloop
             * We may be refreshing the cache
             */
            return req;
        }

        goto error;
    }

    return req;

error:
    tevent_req_error(req, ret);
    tevent_req_post(req, cmdctx->cctx->ev);
    return req;
}

static errno_t setnetgrent_retry(struct tevent_req *req)
{
    errno_t ret;
    struct setent_step_ctx *step_ctx;
    struct setnetgrent_ctx *state;
    struct cli_ctx *client;
    struct nss_ctx *nctx;
    struct nss_cmd_ctx *cmdctx;
    struct nss_dom_ctx *dctx;

    state = tevent_req_data(req, struct setnetgrent_ctx);
    dctx = state->dctx;
    cmdctx = state->cmdctx;
    client = cmdctx->cctx;
    nctx = talloc_get_type(client->rctx->pvt_ctx, struct nss_ctx);

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);

    /* Is the result context already available?
     * Check for existing lookups for this netgroup
     */
    ret = get_netgroup_entry(nctx, client->netgr_name, &state->netgr);
    if (ret == EOK) {
        /* Another process already requested this netgroup
         * Check whether it's ready for processing.
         */
        if (state->netgr->ready) {
            if (state->netgr->found) {
                /* Ready to process results */
                tevent_req_done(req);
            } else {
                tevent_req_error(req, ENOENT);
            }

            tevent_req_post(req, nctx->rctx->ev);
            /* Return EOK, otherwise this will be treated as
             * an error
             */
            return EOK;
        }

        /* Result object is still being constructed
         * Register for notification when it's ready
         */
        ret = nss_setent_add_ref(state, state->netgr, req);
        if (ret != EOK) {
            goto done;
        }
        /* Will return control below */
    } else if (ret == ENOENT) {
        /* This is the first attempt to request this netgroup
         */
        state->netgr = talloc_zero(nctx, struct getent_ctx);
        if (!state->netgr) {
            ret = ENOMEM;
            goto done;
        }
        dctx->netgr = state->netgr;

        /* Save the name used for the lookup table
         * so we can remove it in the destructor
         */
        state->netgr->name = talloc_strdup(state->netgr,
                                           client->netgr_name);
        if (!state->netgr->name) {
            talloc_free(state->netgr);
            ret = ENOMEM;
            goto done;
        }

        state->netgr->lookup_table = nctx->netgroups;

        /* Add a reference for ourselves */
        ret = nss_setent_add_ref(state, state->netgr, req);
        if (ret != EOK) {
            talloc_free(state->netgr);
            goto done;
        }

        ret = set_netgroup_entry(nctx, state->netgr);
        if (ret != EOK) {
            DEBUG(1, ("set_netgroup_entry failed.\n"));
            talloc_free(state->netgr);
            goto done;
        }

        /* Perform lookup */
        step_ctx = talloc_zero(state->netgr, struct setent_step_ctx);
        if (!step_ctx) {
            ret = ENOMEM;
            goto done;
        }

        /* Steal the dom_ctx onto the step_ctx so it doesn't go out of scope if
         * this request is canceled while other requests are in-progress.
         */
        step_ctx->dctx = talloc_steal(step_ctx, state->dctx);
        step_ctx->nctx = state->nctx;
        step_ctx->getent_ctx = state->netgr;
        step_ctx->rctx = client->rctx;
        step_ctx->check_next = cmdctx->check_next;
        step_ctx->name =
                talloc_strdup(step_ctx, state->netgr->name);
        if (!step_ctx->name) {
            ret = ENOMEM;
            goto done;
        }

        ret = lookup_netgr_step(step_ctx);
        if (ret != EOK) {
            goto done;
        }
        tevent_req_done(req);
        tevent_req_post(req, cmdctx->cctx->ev);
        /* Will return control below */
    } else {
        /* Unexpected error from hash_lookup */
        goto done;
    }

    ret = EOK;

done:
    return ret;
}

static void lookup_netgr_dp_callback(uint16_t err_maj, uint32_t err_min,
                                     const char *err_msg, void *ptr);

static void setnetgrent_result_timeout(struct tevent_context *ev,
                                       struct tevent_timer *te,
                                       struct timeval current_time,
                                       void *pvt);

/* Set up a lifetime timer for this result object
 * We don't want this result object to outlive the
 * entry cache refresh timeout
 */
static void set_netgr_lifetime(uint32_t lifetime,
                               struct setent_step_ctx *step_ctx,
                               struct getent_ctx *netgr)
{
    struct timeval tv;
    struct tevent_timer *te;

    tv = tevent_timeval_current_ofs(lifetime, 0);
    te = tevent_add_timer(step_ctx->nctx->rctx->ev,
                          step_ctx->nctx->gctx, tv,
                          setnetgrent_result_timeout,
                          netgr);
    if (!te) {
        DEBUG(0, ("Could not set up life timer for setnetgrent result object. "
                  "Entries may become stale.\n"));
    }
}

static errno_t lookup_netgr_step(struct setent_step_ctx *step_ctx)
{
    errno_t ret;
    struct sss_domain_info *dom = step_ctx->dctx->domain;
    struct getent_ctx *netgr;
    struct sysdb_ctx *sysdb;
    char *name = NULL;
    uint32_t lifetime;

    /* Check each domain for this netgroup name */
    while (dom) {
        /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && step_ctx->check_next && dom->fqnames) {
            dom = dom->next;
        }

        /* No domains left to search */
        if (!dom) break;

        if (dom != step_ctx->dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            step_ctx->dctx->check_provider =
                    NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        step_ctx->dctx->domain = dom;

        talloc_free(name);
        name = sss_get_cased_name(step_ctx, step_ctx->name,
                                  dom->case_sensitive);
        if (!name) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("sss_get_cased_name failed\n"));
            return ENOMEM;
        }

        DEBUG(4, ("Requesting info for [%s@%s]\n",
                  name, dom->name));
        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        /* Look up the netgroup in the cache */
        ret = sysdb_getnetgr(step_ctx->dctx, sysdb, name,
                             &step_ctx->dctx->res);
        if (ret == ENOENT) {
            /* This netgroup was not found in this domain */
            if (!step_ctx->dctx->check_provider) {
                if (step_ctx->check_next) {
                    dom = dom->next;
                    continue;
                }
                else break;
            }
            ret = EOK;
        }

        if (ret != EOK) {
            DEBUG(1, ("Failed to make request to our cache!\n"));
            return EIO;
        }

        ret = get_netgroup_entry(step_ctx->nctx, step_ctx->name,
                                 &netgr);
        if (ret != EOK) {
            /* Something really bad happened! */
            DEBUG(0, ("Netgroup entry was lost!\n"));
            return ret;
        }

        /* Convert the result to a list of entries */
        ret = sysdb_netgr_to_entries(netgr, step_ctx->dctx->res,
                                     &netgr->entries);
        if (ret == ENOENT) {
            /* This netgroup was not found in this domain */
            DEBUG(2, ("No results for netgroup %s (domain %s)\n",
                      name, dom->name));

            if (!step_ctx->dctx->check_provider) {
                if (step_ctx->check_next) {
                    dom = dom->next;
                    continue;
                }
                else break;
            }
            ret = EOK;
        }

        if (ret != EOK) {
            DEBUG(1, ("Failed to convert results into entries\n"));
            netgr->ready = true;
            netgr->found = false;
            set_netgr_lifetime(step_ctx->nctx->neg_timeout, step_ctx, netgr);
            return EIO;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (step_ctx->dctx->check_provider) {
            ret = check_cache(step_ctx->dctx,
                              step_ctx->nctx,
                              step_ctx->dctx->res,
                              SSS_DP_NETGR,
                              name, 0,
                              lookup_netgr_dp_callback,
                              step_ctx);
            if (ret != EOK) {
                /* May return EAGAIN legitimately to indicate that
                 * we need to reenter the mainloop
                 */
                return ret;
            }
        }

        /* Results found */
        DEBUG(6, ("Returning info for netgroup [%s@%s]\n",
                  name, dom->name));
        netgr->ready = true;
        netgr->found = true;
        if (step_ctx->nctx->cache_refresh_percent) {
            lifetime = dom->netgroup_timeout *
                (step_ctx->nctx->cache_refresh_percent / 100);
        } else {
            lifetime = dom->netgroup_timeout;
        }
        if (lifetime < 10) lifetime = 10;
        set_netgr_lifetime(lifetime, step_ctx, netgr);
        return EOK;
    }

    /* If we've gotten here, then no domain contained this netgroup */
    DEBUG(SSSDBG_MINOR_FAILURE,
          ("No matching domain found for [%s], fail!\n", step_ctx->name));

    netgr = talloc_zero(step_ctx->nctx, struct getent_ctx);
    if (netgr == NULL) {
        DEBUG(1, ("talloc_zero failed, ignored.\n"));
    } else {
        netgr->ready = true;
        netgr->found = false;
        netgr->entries = NULL;
        netgr->lookup_table = step_ctx->nctx->netgroups;
        netgr->name = talloc_strdup(netgr, step_ctx->name);
        if (netgr->name == NULL) {
            DEBUG(1, ("talloc_strdup failed.\n"));
            talloc_free(netgr);
            return ENOMEM;
        }

        ret = set_netgroup_entry(step_ctx->nctx, netgr);
        if (ret != EOK) {
            DEBUG(1, ("set_netgroup_entry failed, ignored.\n"));
        }
        set_netgr_lifetime(step_ctx->nctx->neg_timeout, step_ctx, netgr);
    }

    return ENOENT;
}

static void lookup_netgr_dp_callback(uint16_t err_maj, uint32_t err_min,
                                     const char *err_msg, void *ptr)
{
    struct setent_step_ctx *step_ctx =
            talloc_get_type(ptr, struct setent_step_ctx);
    struct nss_dom_ctx *dctx = step_ctx->dctx;
    struct nss_cmd_ctx *cmdctx = dctx->cmdctx;
    int ret;

    if (err_maj) {
        DEBUG(2, ("Unable to get information from Data Provider\n"
                  "Error: %u, %u, %s\n"
                  "Will try to return what we have in cache\n",
                  (unsigned int)err_maj, (unsigned int)err_min, err_msg));
        /* Loop to the next domain if possible */
        if (dctx->domain->next && cmdctx->check_next) {
            dctx->domain = dctx->domain->next;
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        }
    }

    /* ok the backend returned, search to see if we have updated results */
    ret = lookup_netgr_step(step_ctx);
    if (ret != EOK) {
        if (ret == EAGAIN) {
            return;
        }
    }

    /* We have results to return */
    nss_setent_notify_error(dctx->netgr, ret);
}

static void setnetgrent_result_timeout(struct tevent_context *ev,
                                       struct tevent_timer *te,
                                       struct timeval current_time,
                                       void *pvt)
{
    struct getent_ctx *netgr =
            talloc_get_type(pvt, struct getent_ctx);

    /* Free the netgroup result context
     * The destructor for the netgroup will remove itself
     * from the hash table
     *
     * If additional getnetgrent() requests come in, they
     * will invoke an implicit setnetgrent() call and
     * refresh the result object
     */
    talloc_free(netgr);
}

static errno_t setnetgrent_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static void nss_cmd_setnetgrent_done(struct tevent_req *req)
{
    errno_t reqret;
    errno_t ret;
    struct sss_packet *packet;
    uint8_t *body;
    size_t blen;

    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);

    reqret = setnetgrent_recv(req);
    talloc_zfree(req);
    if (reqret != EOK && reqret != ENOENT) {
        DEBUG(1, ("setnetgrent failed\n"));
        nss_cmd_done(cmdctx, reqret);
        return;
    }

    /* Either we succeeded or no domains were eligible */
    ret = sss_packet_new(cmdctx->cctx->creq, 0,
                         sss_packet_get_cmd(cmdctx->cctx->creq->in),
                         &cmdctx->cctx->creq->out);
    if (ret == EOK) {
        if (reqret == ENOENT) {
            /* Notify the caller that this entry wasn't found */
            sss_cmd_empty_packet(cmdctx->cctx->creq->out);
        } else {
            packet = cmdctx->cctx->creq->out;
            ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
            if (ret != EOK) {
                DEBUG(1, ("Couldn't grow the packet\n"));
                NSS_CMD_FATAL_ERROR(cmdctx);
            }

            sss_packet_get_body(packet, &body, &blen);
            ((uint32_t *)body)[0] = 1; /* Got some results */
            ((uint32_t *)body)[1] = 0; /* reserved */
        }

        sss_cmd_done(cmdctx->cctx, NULL);
        return;
    }

    DEBUG(1, ("Error creating packet\n"));
}

static void setnetgrent_implicit_done(struct tevent_req *req);
static errno_t nss_cmd_getnetgrent_process(struct nss_cmd_ctx *cmdctx,
                                           struct getent_ctx *netgr);
int nss_cmd_getnetgrent(struct cli_ctx *client)
{
    errno_t ret;
    struct nss_ctx *nctx;
    struct nss_cmd_ctx *cmdctx;
    struct getent_ctx *netgr;
    struct tevent_req *req;

    DEBUG(4, ("Requesting netgroup data\n"));

    cmdctx = talloc_zero(client, struct nss_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = client;

    nctx = talloc_get_type(client->rctx->pvt_ctx, struct nss_ctx);

    if (!client->netgr_name) {
        /* Tried to run getnetgrent without a preceding
         * setnetgrent. There is no way to determine which
         * netgroup is being requested.
         */
        return nss_cmd_done(cmdctx, EINVAL);
    }

    /* Look up the results from the hash */
    ret = get_netgroup_entry(nctx, client->netgr_name, &netgr);
    if (ret == ENOENT) {
        /* We need to invoke an implicit setnetgrent() to
         * wait for the result object to become available.
         */

        req = setnetgrent_send(cmdctx, client->netgr_name, cmdctx);
        if (!req) {
            return nss_cmd_done(cmdctx, EIO);
        }
        tevent_req_set_callback(req, setnetgrent_implicit_done, cmdctx);

        return EOK;
    } else if (ret != EOK) {
        DEBUG(1, ("An unexpected error occurred: [%d][%s]\n",
                  ret, strerror(ret)));

        return nss_cmd_done(cmdctx, ret);
    }

    /* Hash entry was found. Is it ready? */
    if (!netgr->ready) {
        /* We need to invoke an implicit setnetgrent() to
         * wait for the result object to become available.
         */
        req = setnetgrent_send(cmdctx, client->netgr_name, cmdctx);
        if (!req) {
            return nss_cmd_done(cmdctx, EIO);
        }
        tevent_req_set_callback(req, setnetgrent_implicit_done, cmdctx);

        return EOK;
    } else if (!netgr->found) {
        DEBUG(6, ("Results for [%s] not found.\n", client->netgr_name));
        return ENOENT;
    }

    DEBUG(6, ("Returning results for [%s]\n", client->netgr_name));

    /* Read the result strings */
    ret = nss_cmd_getnetgrent_process(cmdctx, netgr);
    if (ret != EOK) {
        DEBUG(1, ("Failed: [%d][%s]\n", ret, strerror(ret)));
    }
    return ret;
}

static void setnetgrent_implicit_done(struct tevent_req *req)
{
    errno_t ret;
    struct getent_ctx *netgr;
    struct nss_cmd_ctx *cmdctx =
            tevent_req_callback_data(req, struct nss_cmd_ctx);
    struct nss_ctx *nctx =
            talloc_get_type(cmdctx->cctx->rctx->pvt_ctx, struct nss_ctx);

    ret = setnetgrent_recv(req);
    talloc_zfree(req);

    /* ENOENT is acceptable, it just means there were no values
     * to be returned. This will be handled gracefully in
     * nss_cmd_retnetgrent later
     */
    if (ret != EOK && ret != ENOENT) {
        DEBUG(0, ("Implicit setnetgrent failed with unexpected error "
                  "[%d][%s]\n", ret, strerror(ret)));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }

    if (ret == ENOENT) {
        /* No entries found for this netgroup */
        nss_cmd_done(cmdctx, ret);
        return;
    }

    /* Look up the results from the hash */
    ret = get_netgroup_entry(nctx, cmdctx->cctx->netgr_name, &netgr);
    if (ret == ENOENT) {
        /* Critical error. This should never happen */
        DEBUG(0, ("Implicit setnetgrent returned success without creating "
                  "result object.\n"));
        NSS_CMD_FATAL_ERROR(cmdctx);
    } else if (ret != EOK) {
        DEBUG(1, ("An unexpected error occurred: [%d][%s]\n",
                  ret, strerror(ret)));

        NSS_CMD_FATAL_ERROR(cmdctx);
    }

    if (!netgr->ready) {
        /* Critical error. This should never happen */
        DEBUG(0, ("Implicit setnetgrent returned success without creating "
                  "result object.\n"));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }

    ret = nss_cmd_getnetgrent_process(cmdctx, netgr);
    if (ret != EOK) {
        DEBUG(0, ("Immediate retrieval failed with unexpected error "
                  "[%d][%s]\n", ret, strerror(ret)));
        NSS_CMD_FATAL_ERROR(cmdctx);
    }
}

static errno_t nss_cmd_retnetgrent(struct cli_ctx *client,
                                   struct sysdb_netgroup_ctx **entries,
                                   int num);
static errno_t nss_cmd_getnetgrent_process(struct nss_cmd_ctx *cmdctx,
                                           struct getent_ctx *netgr)
{
    struct cli_ctx *client = cmdctx->cctx;
    uint8_t *body;
    size_t blen;
    uint32_t num;
    errno_t ret;

    /* get max num of entries to return in one call */
    sss_packet_get_body(client->creq->in, &body, &blen);
    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }
    num = *((uint32_t *)body);

    /* create response packet */
    ret = sss_packet_new(client->creq, 0,
                         sss_packet_get_cmd(client->creq->in),
                         &client->creq->out);
    if (ret != EOK) {
        return ret;
    }

    if (!netgr->entries || netgr->entries[0] == NULL) {
        /* No entries */
        DEBUG(5, ("No entries found\n"));
        ret = sss_cmd_empty_packet(client->creq->out);
        if (ret != EOK) {
            return nss_cmd_done(cmdctx, ret);
        }
        goto done;
    }

    ret = nss_cmd_retnetgrent(client, netgr->entries, num);

done:
    sss_packet_set_error(client->creq->out, ret);
    sss_cmd_done(client, cmdctx);

    return EOK;
}

static errno_t nss_cmd_retnetgrent(struct cli_ctx *client,
                                   struct sysdb_netgroup_ctx **entries,
                                   int count)
{
    size_t len;
    size_t hostlen = 0;
    size_t userlen = 0;
    size_t domainlen = 0;
    size_t grouplen = 0;
    uint8_t *body;
    size_t blen, rp;
    errno_t ret;
    struct sss_packet *packet = client->creq->out;
    int num, start;

    /* first 2 fields (len and reserved), filled up later */
    rp = 2*sizeof(uint32_t);
    ret = sss_packet_grow(packet, rp);
    if (ret != EOK) return ret;

    start = client->netgrent_cur;
    num = 0;
    while (entries[client->netgrent_cur] &&
           (client->netgrent_cur - start) < count) {
        if (entries[client->netgrent_cur]->type == SYSDB_NETGROUP_TRIPLE_VAL) {
            hostlen = 1;
            if (entries[client->netgrent_cur]->value.triple.hostname) {
                hostlen += strlen(entries[client->netgrent_cur]->value.triple.hostname);
            }

            userlen = 1;
            if (entries[client->netgrent_cur]->value.triple.username) {
                userlen += strlen(entries[client->netgrent_cur]->value.triple.username);
            }

            domainlen = 1;
            if (entries[client->netgrent_cur]->value.triple.domainname) {
                domainlen += strlen(entries[client->netgrent_cur]->value.triple.domainname);
            }

            len = sizeof(uint32_t) + hostlen + userlen + domainlen;
            ret = sss_packet_grow(packet, len);
            if (ret != EOK) {
                return ret;
            }
            sss_packet_get_body(packet, &body, &blen);

            SAFEALIGN_SET_UINT32(&body[rp], SSS_NETGR_REP_TRIPLE, &rp);

            if (hostlen == 1) {
                body[rp] = '\0';
            } else {
                memcpy(&body[rp],
                       entries[client->netgrent_cur]->value.triple.hostname,
                       hostlen);
            }
            rp += hostlen;

            if (userlen == 1) {
                body[rp] = '\0';
            } else {
                memcpy(&body[rp],
                       entries[client->netgrent_cur]->value.triple.username,
                       userlen);
            }
            rp += userlen;

            if (domainlen == 1) {
                body[rp] = '\0';
            } else {
                memcpy(&body[rp],
                       entries[client->netgrent_cur]->value.triple.domainname,
                       domainlen);
            }
            rp += domainlen;
        } else if (entries[client->netgrent_cur]->type == SYSDB_NETGROUP_GROUP_VAL) {
            if (entries[client->netgrent_cur]->value.groupname == NULL ||
                entries[client->netgrent_cur]->value.groupname[0] == '\0') {
                DEBUG(1, ("Empty netgroup member. Please check your cache.\n"));
                continue;
            }

            grouplen = 1 + strlen(entries[client->netgrent_cur]->value.groupname);

            len = sizeof(uint32_t) + grouplen;

            ret = sss_packet_grow(packet, len);
            if (ret != EOK) {
                return ret;
            }

            sss_packet_get_body(packet, &body, &blen);

            SAFEALIGN_SET_UINT32(&body[rp], SSS_NETGR_REP_GROUP, &rp);

            memcpy(&body[rp],
                   entries[client->netgrent_cur]->value.groupname,
                   grouplen);
            rp += grouplen;
        } else {
            DEBUG(1, ("Unexpected value type for netgroup entry. "
                      "Please check your cache.\n"));
            continue;
        }

        num++;
        client->netgrent_cur++;
    }

    sss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = num; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

int nss_cmd_endnetgrent(struct cli_ctx *client)
{
    errno_t ret;

    /* create response packet */
    ret = sss_packet_new(client->creq, 0,
                         sss_packet_get_cmd(client->creq->in),
                         &client->creq->out);

    if (ret != EOK) {
        return ret;
    }

    /* Reset the indices so that subsequent requests start at zero */
    client->netgrent_cur = 0;
    talloc_zfree(client->netgr_name);

    sss_cmd_done(client, NULL);
    return EOK;
}
