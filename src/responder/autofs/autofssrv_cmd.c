/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

    Autofs responder: commands

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

#include <talloc.h>

#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/autofs/autofs_private.h"
#include "db/sysdb.h"
#include "db/sysdb_autofs.h"
#include "confdb/confdb.h"

static int autofs_cmd_send_error(struct autofs_cmd_ctx *cmdctx, int err)
{
    return sss_cmd_send_error(cmdctx->cctx, err);
}

static int
autofs_cmd_send_empty(struct autofs_cmd_ctx *cmdctx)
{
    return sss_cmd_send_empty(cmdctx->cctx, cmdctx);
}

static int
autofs_cmd_done(struct autofs_cmd_ctx *cmdctx, int ret)
{
    switch (ret) {
    case EOK:
        /* all fine, just return here */
        break;

    case ENOENT:
        ret = autofs_cmd_send_empty(cmdctx);
        if (ret) {
            return EFAULT;
        }
        break;

    case EAGAIN:
        /* async processing, just return here */
        break;

    case EFAULT:
        /* very bad error */
        return EFAULT;

    default:
        ret = autofs_cmd_send_error(cmdctx, ret);
        if (ret) {
            return EFAULT;
        }
        sss_cmd_done(cmdctx->cctx, cmdctx);
        break;
    }

    return EOK;
}

static errno_t
autofs_setent_add_ref(TALLOC_CTX *memctx,
                      struct autofs_map_ctx *map_ctx,
                      struct tevent_req *req)
{
    return setent_add_ref(memctx, map_ctx, &map_ctx->reqs, req);
}

static void
autofs_setent_notify(struct autofs_map_ctx *map_ctx, errno_t ret)
{
    setent_notify(&map_ctx->reqs, ret);
}

static errno_t
get_autofs_map(struct autofs_ctx *actx,
               char *mapname,
               struct autofs_map_ctx **map)
{
    hash_key_t key;
    hash_value_t value;
    int hret;

    key.type = HASH_KEY_STRING;
    key.str = mapname;

    hret = hash_lookup(actx->maps, &key, &value);
    if (hret == HASH_SUCCESS) {
        *map = talloc_get_type(value.ptr, struct autofs_map_ctx);
        return EOK;
    } else if (hret == HASH_ERROR_KEY_NOT_FOUND) {
        return ENOENT;
    }

    DEBUG(SSSDBG_CRIT_FAILURE,
          ("Unexpected error reading from autofs map hash [%d][%s]\n",
          hret, hash_error_string(hret)));
    return EIO;
}

static int autofs_map_hash_remove (TALLOC_CTX *ctx);

static errno_t
set_autofs_map(struct autofs_ctx *actx,
               struct autofs_map_ctx *map)
{
    hash_key_t key;
    hash_value_t value;
    int hret;

    if (map->mapname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Missing autofs map name.\n"));
        return EINVAL;
    }

    /* Add this entry to the hash table */
    key.type = HASH_KEY_STRING;
    key.str = map->mapname;
    value.type = HASH_VALUE_PTR;
    value.ptr = map;
    hret = hash_enter(actx->maps, &key, &value);
    if (hret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to add hash table entry for [%s]", key.str));
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Hash error [%d][%s]", hret, hash_error_string(hret)));
        return EIO;
    }
    talloc_steal(actx->maps, map);
    talloc_set_destructor((TALLOC_CTX *) map, autofs_map_hash_remove);

    return EOK;
}

static int
autofs_map_hash_remove(TALLOC_CTX *ctx)
{
    int hret;
    hash_key_t key;
    struct autofs_map_ctx *map =
            talloc_get_type(ctx, struct autofs_map_ctx);

    key.type = HASH_KEY_STRING;
    key.str = map->mapname;

    /* Remove the autofs map result object from the lookup table */
    hret = hash_delete(map->map_table, &key);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not remove key from table! [%d][%s]\n",
              hret, hash_error_string(hret)));
        return -1;
    }
    return 0;
}

static struct tevent_req *
setautomntent_send(TALLOC_CTX *mem_ctx,
                   const char *rawname,
                   struct autofs_cmd_ctx *cmdctx);
static errno_t setautomntent_recv(struct tevent_req *req);
static void sss_autofs_cmd_setautomntent_done(struct tevent_req *req);

/* FIXME - file a ticket to have per-responder private
 * data instead of growing the cli_ctx structure */
static int
sss_autofs_cmd_setautomntent(struct cli_ctx *client)
{
    struct autofs_cmd_ctx *cmdctx;
    uint8_t *body;
    size_t blen;
    errno_t ret = EOK;
    const char *rawname;
    struct tevent_req *req;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("sss_autofs_cmd_setautomntent\n"));

    cmdctx = talloc_zero(client, struct autofs_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = client;

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
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Got request for automount map named %s\n", rawname));

    req = setautomntent_send(cmdctx, rawname, cmdctx);
    if (!req) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Fatal error calling setautomntent_send\n"));
        ret = EIO;
        goto done;
    }
    tevent_req_set_callback(req, sss_autofs_cmd_setautomntent_done, cmdctx);

    ret = EOK;
done:
    return autofs_cmd_done(cmdctx, ret);
}

static void sss_autofs_cmd_setautomntent_done(struct tevent_req *req)
{
    struct autofs_cmd_ctx *cmdctx =
        tevent_req_callback_data(req, struct autofs_cmd_ctx);
    errno_t ret;
    errno_t reqret;
    struct sss_packet *packet;
    uint8_t *body;
    size_t blen;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("setautomntent done\n"));

    reqret = setautomntent_recv(req);
    talloc_zfree(req);
    if (reqret != EOK && reqret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("setautomntent_recv failed\n"));
        autofs_cmd_done(cmdctx, reqret);
        return;
    }

    /* Either we succeeded or no domains were eligible */
    ret = sss_packet_new(cmdctx->cctx->creq, 0,
                         sss_packet_get_cmd(cmdctx->cctx->creq->in),
                         &cmdctx->cctx->creq->out);
    if (ret == EOK) {
        if (reqret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC, ("setautomntent did not find requested map\n"));
            /* Notify the caller that this entry wasn't found */
            sss_cmd_empty_packet(cmdctx->cctx->creq->out);
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, ("setautomntent found data\n"));
            packet = cmdctx->cctx->creq->out;
            ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Couldn't grow the packet\n"));
                talloc_free(cmdctx);
                return;
            }

            sss_packet_get_body(packet, &body, &blen);
            ((uint32_t *)body)[0] = 1; /* Got some results */
            ((uint32_t *)body)[1] = 0; /* reserved */
        }

        sss_cmd_done(cmdctx->cctx, NULL);
        return;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, ("Error creating packet\n"));
    return;
}

struct setautomntent_state {
    struct autofs_cmd_ctx *cmdctx;
    struct autofs_dom_ctx *dctx;

    char *mapname;
    struct autofs_map_ctx *map;
};

struct setautomntent_lookup_ctx {
    struct autofs_ctx *actx;
    struct autofs_dom_ctx *dctx;
    struct resp_ctx *rctx;
    struct cli_ctx *cctx;

    bool returned_to_mainloop;

    char *mapname;
    struct autofs_map_ctx *map;
};

static errno_t
lookup_automntmap_step(struct setautomntent_lookup_ctx *lookup_ctx);

static void
autofs_map_result_timeout(struct tevent_context *ev,
                          struct tevent_timer *te,
                          struct timeval current_time,
                          void *pvt)
{
    struct autofs_map_ctx *map =
            talloc_get_type(pvt, struct autofs_map_ctx);

    /* Free the autofs map result context
     * The destructor for the autofs map will remove itself
     * from the hash table
     */
    talloc_free(map);
}

static void
set_autofs_map_lifetime(uint32_t lifetime,
                        struct setautomntent_lookup_ctx *lookup_ctx,
                        struct autofs_map_ctx *map)
{
    struct timeval tv;
    struct tevent_timer *te;

    tv = tevent_timeval_current_ofs(lifetime, 0);
    te = tevent_add_timer(lookup_ctx->rctx->ev,
                          lookup_ctx->rctx, tv,
                          autofs_map_result_timeout,
                          map);
    if (!te) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not set up life timer for autofs maps. "
               "Entries may become stale.\n"));
    }
}

static struct tevent_req *
setautomntent_send(TALLOC_CTX *mem_ctx,
                   const char *rawname,
                   struct autofs_cmd_ctx *cmdctx)
{
    char *domname;
    errno_t ret;
    struct tevent_req *req;
    struct setautomntent_state *state;
    struct cli_ctx *client = cmdctx->cctx;
    struct autofs_dom_ctx *dctx;
    struct autofs_ctx *actx =
            talloc_get_type(client->rctx->pvt_ctx, struct autofs_ctx);
    struct setautomntent_lookup_ctx *lookup_ctx;

    req = tevent_req_create(mem_ctx, &state, struct setautomntent_state);
    if (!req) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Could not create tevent request for setautomntent\n"));
        return NULL;
    }
    state->cmdctx = cmdctx;

    dctx = talloc_zero(state, struct autofs_dom_ctx);
    if (!dctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Out of memory\n"));
        ret = ENOMEM;
        goto fail;
    }
    dctx->cmd_ctx = state->cmdctx;
    state->dctx = dctx;

    ret = sss_parse_name_for_domains(state, client->rctx->domains,
                                     client->rctx->default_domain, rawname,
                                     &domname, &state->mapname);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Invalid name received [%s]\n", rawname));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
         ("Requesting info for automount map [%s] from [%s]\n",
         state->mapname, domname?domname:"<ALL>"));

    if (domname) {
        dctx->domain = responder_get_domain(dctx, client->rctx, domname);
        if (!dctx->domain) {
            ret = EINVAL;
            goto fail;
        }

        client->automntmap_name = talloc_strdup(client, rawname);
        if (!client->automntmap_name) {
            ret = ENOMEM;
            goto fail;
        }
    } else {
        /* this is a multidomain search */
        dctx->domain = client->rctx->domains;
        cmdctx->check_next = true;

        client->automntmap_name = talloc_strdup(client, state->mapname);
        if (!client->automntmap_name) {
            ret = ENOMEM;
            goto fail;
        }
    }

    dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
    /* Is the result context already available?
     * Check for existing lookups for this map
     */
    ret = get_autofs_map(actx, state->mapname, &state->map);
    if (ret == EOK) {
        /* Another process already requested this map
         * Check whether it's ready for processing.
         */
        if (state->map->ready) {
            if (state->map->found) {
                DEBUG(SSSDBG_TRACE_LIBS,
                      ("Map %s is ready to be processed\n", state->mapname));
                tevent_req_done(req);
                tevent_req_post(req, actx->rctx->ev);
                return req;
            } else {
                DEBUG(SSSDBG_TRACE_LIBS,
                      ("Map %s was marked as nonexistent\n", state->mapname));
                tevent_req_error(req, ENOENT);
                tevent_req_post(req, actx->rctx->ev);
                return req;
            }
        }

        /* Result object is still being constructed
         * Register for notification when it's ready
         */
        DEBUG(SSSDBG_TRACE_LIBS,
              ("Map %s is being looked up, registering for notification\n",
               state->mapname));
        ret = autofs_setent_add_ref(state, state->map, req);
        if (ret != EOK) {
            goto fail;
        }
        /* Will return control below */
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_LIBS,
              ("Map %s needs to be looked up\n", state->mapname));

        state->map = talloc_zero(actx, struct autofs_map_ctx);
        if (!state->map) {
            ret = ENOMEM;
            goto fail;
        }
        dctx->map_ctx = state->map;

        state->map->mapname = talloc_strdup(state->map, state->mapname);
        if (!state->map->mapname) {
            talloc_free(state->map);
            ret = ENOMEM;
            goto fail;
        }
        state->map->map_table = actx->maps;

        ret = autofs_setent_add_ref(state, state->map, req);
        if (ret != EOK) {
            talloc_free(state->map);
            goto fail;
        }

        ret = set_autofs_map(actx, state->map);
        if (ret != EOK) {
            talloc_free(state->map);
            goto fail;
        }

        /* Perform lookup */
        lookup_ctx = talloc_zero(state->map, struct setautomntent_lookup_ctx);
        if (!lookup_ctx) {
            talloc_free(state->map);
            ret = ENOMEM;
            goto fail;
        }

        /* Steal the dom_ctx onto the lookup_ctx so it doesn't go out of scope if
        * this request is canceled while other requests are in-progress.
        */
        lookup_ctx->dctx = talloc_steal(lookup_ctx, state->dctx);
        lookup_ctx->actx = actx;
        lookup_ctx->map = state->map;
        lookup_ctx->rctx = client->rctx;
        lookup_ctx->mapname =
                    talloc_strdup(lookup_ctx, state->mapname);
        if (!lookup_ctx->mapname) {
            talloc_free(state->map);
            ret = ENOMEM;
            goto fail;
        }

        ret = lookup_automntmap_step(lookup_ctx);
        if (ret == EAGAIN) {
            DEBUG(SSSDBG_TRACE_INTERNAL, ("lookup_automntmap_step "
                  "is refreshing the cache, re-entering the mainloop\n"));
            return req;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not get data from cache\n"));
            talloc_free(state->map);
            ret = ENOMEM;
            goto fail;
        }

        tevent_req_done(req);
        tevent_req_post(req, cmdctx->cctx->ev);
        return req;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unexpected error from get_autofs_map [%d]: %s\n",
               ret, strerror(ret)));
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, actx->rctx->ev);
    return req;
}

static errno_t
lookup_automntmap_update_cache(struct setautomntent_lookup_ctx *lookup_ctx);

static errno_t
lookup_automntmap_step(struct setautomntent_lookup_ctx *lookup_ctx)
{
    errno_t ret;
    struct sss_domain_info *dom = lookup_ctx->dctx->domain;
    struct autofs_dom_ctx *dctx = lookup_ctx->dctx;
    struct sysdb_ctx *sysdb;
    struct autofs_map_ctx *map;

    /* Check each domain for this map name */
    while (dom) {
        /* if it is a domainless search, skip domains that require fully
         * qualified names instead */
        while (dom && dctx->cmd_ctx->check_next && dom->fqnames) {
            dom = dom->next;
        }

        /* No domains left to search */
        if (!dom) break;

        if (dom != dctx->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            dctx->check_provider =
                    NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the dctx if we changed domain */
        dctx->domain = dom;

        DEBUG(SSSDBG_TRACE_FUNC, ("Requesting info for [%s@%s]\n",
              lookup_ctx->mapname, dom->name));
        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("Fatal: Sysdb CTX not found for this domain!\n"));
            return EIO;
        }

        /* Look into the cache */
        talloc_free(dctx->map);
        ret = sysdb_get_map_byname(dctx, sysdb, lookup_ctx->mapname,
                                   &dctx->map);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not check cache\n"));
            return ret;
        } else if (ret == ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("No automount map [%s] in cache for domain [%s]\n",
                   lookup_ctx->mapname, dom->name));
            if (!dctx->check_provider) {
                if (dctx->cmd_ctx->check_next) {
                    DEBUG(SSSDBG_TRACE_INTERNAL, ("Moving on to next domain\n"));
                    dom = dom->next;
                    continue;
                }
                else break;
            }
        }

        ret = get_autofs_map(lookup_ctx->actx, lookup_ctx->mapname, &map);
        if (ret != EOK) {
            /* Something really bad happened! */
            DEBUG(SSSDBG_CRIT_FAILURE, ("Autofs map entry was lost!\n"));
            return ret;
        }

        if (dctx->map == NULL && !dctx->check_provider) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Autofs map not found, setting negative cache\n"));
            map->ready = true;
            map->found = false;
            set_autofs_map_lifetime(lookup_ctx->actx->neg_timeout, lookup_ctx, map);
            return ENOENT;
        }

        if (dctx->check_provider) {
            ret = lookup_automntmap_update_cache(lookup_ctx);
            if (ret == EAGAIN) {
                DEBUG(SSSDBG_TRACE_INTERNAL,
                      ("Looking up automount maps from the DP\n"));
                return EAGAIN;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("Error looking up automount maps [%d]: %s\n",
                       ret, strerror(ret)));
                return ret;
            }
        }

        /* OK, the map is in cache and valid.
         * Let's get all members and return it
         */
        ret = sysdb_autofs_entries_by_map(map, sysdb, map->mapname,
                                          &map->entry_count,
                                          &map->entries);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Error looking automount map entries [%d]: %s\n",
                  ret, strerror(ret)));
            map->ready = true;
            map->found = false;
            set_autofs_map_lifetime(lookup_ctx->actx->neg_timeout, lookup_ctx, map);
            return EIO;
        }

        map->map = talloc_steal(map, dctx->map);

        DEBUG(SSSDBG_TRACE_FUNC,
              ("setautomntent done for map %s\n", lookup_ctx->mapname));
        map->ready = true;
        map->found = true;
        set_autofs_map_lifetime(dom->autofsmap_timeout, lookup_ctx, map);
        return EOK;
    }

    map = talloc_zero(lookup_ctx->actx, struct autofs_map_ctx);
    if (!map) {
        return ENOMEM;
    }

    map->ready = true;
    map->found = false;
    map->map_table = lookup_ctx->actx->maps;

    map->mapname = talloc_strdup(map, lookup_ctx->mapname);
    if (!map->mapname) {
        talloc_free(map);
        return ENOMEM;
    }

    ret = set_autofs_map(lookup_ctx->actx, map);
    if (ret != EOK) {
        talloc_free(map);
        return ENOMEM;
    }

    set_autofs_map_lifetime(lookup_ctx->actx->neg_timeout, lookup_ctx, map);

    /* If we've gotten here, then no domain contained this map */
    return ENOENT;
}

static void lookup_automntmap_cache_updated(uint16_t err_maj, uint32_t err_min,
                                            const char *err_msg, void *ptr);
static void autofs_dp_send_map_req_done(struct tevent_req *req);

static errno_t
lookup_automntmap_update_cache(struct setautomntent_lookup_ctx *lookup_ctx)
{
    errno_t ret;
    uint64_t cache_expire = 0;
    struct autofs_dom_ctx *dctx = lookup_ctx->dctx;
    struct tevent_req *req = NULL;
    struct dp_callback_ctx *cb_ctx = NULL;

    if (dctx->map != NULL) {
        cache_expire = ldb_msg_find_attr_as_uint64(dctx->map,
                                                   SYSDB_CACHE_EXPIRE, 0);

        /* if we have any reply let's check cache validity */
        ret = sss_cmd_check_cache(dctx->map, 0, cache_expire);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, ("Cached entry is valid, returning..\n"));
            return EOK;
        } else if (ret != EAGAIN && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error checking cache: %d\n", ret));
            goto error;
        }
    }

    /* dont loop forever :-) */
    dctx->check_provider = false;

    /* keep around current data in case backend is offline */
    /* FIXME - do this by default */
#if 0
    if (dctx->res->count) {
        dctx->res = talloc_steal(dctx, dctx->res);
    }
#endif

    req = sss_dp_get_autofs_send(lookup_ctx->cctx, lookup_ctx->rctx,
                                 lookup_ctx->dctx->domain, true,
                                 SSS_DP_AUTOFS, lookup_ctx->mapname);
    if (!req) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Out of memory sending data provider request\n"));
        ret = ENOMEM;
        goto error;
    }

    cb_ctx = talloc_zero(lookup_ctx->dctx, struct dp_callback_ctx);
    if(!cb_ctx) {
        talloc_zfree(req);
        ret = ENOMEM;
        goto error;
    }
    cb_ctx->callback = lookup_automntmap_cache_updated;
    cb_ctx->ptr = lookup_ctx;
    cb_ctx->cctx = lookup_ctx->dctx->cmd_ctx->cctx;
    cb_ctx->mem_ctx = lookup_ctx->dctx;

    tevent_req_set_callback(req, autofs_dp_send_map_req_done, cb_ctx);

    return EAGAIN;

error:
    ret = autofs_cmd_send_error(lookup_ctx->dctx->cmd_ctx, ret);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Fatal error, killing connection!\n"));
        talloc_free(lookup_ctx->cctx);
        return ret;
    }
    autofs_cmd_done(lookup_ctx->dctx->cmd_ctx, ret);
    return EOK;
}

static void autofs_dp_send_map_req_done(struct tevent_req *req)
{
    struct dp_callback_ctx *cb_ctx =
            tevent_req_callback_data(req, struct dp_callback_ctx);
    struct setautomntent_lookup_ctx *lookup_ctx =
            talloc_get_type(cb_ctx->ptr, struct setautomntent_lookup_ctx);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_autofs_recv(cb_ctx->mem_ctx, req,
                                 &err_maj, &err_min,
                                 &err_msg);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Fatal error, killing connection!\n"));
        talloc_free(lookup_ctx->cctx);
        return;
    }

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}

static void lookup_automntmap_cache_updated(uint16_t err_maj, uint32_t err_min,
                                            const char *err_msg, void *ptr)
{
    struct setautomntent_lookup_ctx *lookup_ctx =
            talloc_get_type(ptr, struct setautomntent_lookup_ctx);
    struct autofs_dom_ctx *dctx = lookup_ctx->dctx;
    errno_t ret;

    if (err_maj) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to get information from Data Provider\n"
               "Error: %u, %u, %s\n"
               "Will try to return what we have in cache\n",
               (unsigned int)err_maj, (unsigned int)err_min, err_msg));
        /* Loop to the next domain if possible */
        if (dctx->domain->next && dctx->cmd_ctx->check_next) {
            dctx->domain = dctx->domain->next;
            dctx->check_provider = NEED_CHECK_PROVIDER(dctx->domain->provider);
        }
    }

    /* ok the backend returned, search to see if we have updated results */
    ret = lookup_automntmap_step(lookup_ctx);
    if (ret != EOK) {
        if (ret == EAGAIN) {
            return;
        }
    }

    /* We have results to return */
    autofs_setent_notify(lookup_ctx->map, ret);
}

static errno_t
setautomntent_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static errno_t
getautomntent_process(struct autofs_cmd_ctx *cmdctx,
                      struct autofs_map_ctx *map,
                      uint32_t cursor, uint32_t max_entries);
static void
getautomntent_implicit_done(struct tevent_req *req);
static errno_t
fill_autofs_entry(struct ldb_message *entry, struct sss_packet *packet, size_t *rp);


static int
sss_autofs_cmd_getautomntent(struct cli_ctx *client)
{
    struct autofs_cmd_ctx *cmdctx;
    struct autofs_map_ctx *map;
    struct autofs_ctx *actx;
    uint8_t *body;
    size_t blen;
    errno_t ret;
    uint32_t namelen;
    size_t c = 0;
    struct tevent_req *req;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("sss_autofs_cmd_getautomntent\n"));

    cmdctx = talloc_zero(client, struct autofs_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = client;

    actx = talloc_get_type(client->rctx->pvt_ctx, struct autofs_ctx);
    if (!actx) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Missing autofs context\n"));
        return EIO;
    }

    /* get autofs map name and index to query */
    sss_packet_get_body(client->creq->in, &body, &blen);

    SAFEALIGN_COPY_UINT32_CHECK(&namelen, body+c, blen, &c);

    if (namelen == 0) {
        ret = EINVAL;
        goto done;
    }

    cmdctx->mapname = (char *) body+c;

    /* if not null-terminated fail */
    if (cmdctx->mapname[namelen] != '\0') {
        ret = EINVAL;
        goto done;
    }

    /* If the name isn't valid UTF-8, fail */
    if (!sss_utf8_check((const uint8_t *) cmdctx->mapname, namelen -1)) {
        ret = EINVAL;
        goto done;
    }

    SAFEALIGN_COPY_UINT32_CHECK(&cmdctx->cursor, body+c+namelen+1, blen, &c);
    SAFEALIGN_COPY_UINT32_CHECK(&cmdctx->max_entries, body+c+namelen+1, blen, &c);

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requested data of map %s cursor %d max entries %d\n",
           cmdctx->mapname, cmdctx->cursor, cmdctx->max_entries));

    ret = get_autofs_map(actx, cmdctx->mapname, &map);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Performing implicit setautomntent\n"));
        req = setautomntent_send(cmdctx, cmdctx->mapname, cmdctx);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("setautomntent_send failed\n"));
            ret = EIO;
            goto done;
        }

        tevent_req_set_callback(req, getautomntent_implicit_done, cmdctx);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("An unexpected error occurred: [%d][%s]\n",
              ret, strerror(ret)));
        goto done;
    }

    if (map->ready == false) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Performing implicit setautomntent\n"));
        req = setautomntent_send(cmdctx, cmdctx->mapname, cmdctx);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("setautomntent_send failed\n"));
            ret = EIO;
            goto done;
        }

        tevent_req_set_callback(req, getautomntent_implicit_done, cmdctx);
        ret = EOK;
        goto done;
    } else if (map->found == false) {
        DEBUG(SSSDBG_TRACE_FUNC, ("negative cache hit\n"));
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          ("returning entries for [%s]\n", map->mapname));

    ret = getautomntent_process(cmdctx, map, cmdctx->cursor, cmdctx->max_entries);

done:
    return autofs_cmd_done(cmdctx, ret);
}

static void
getautomntent_implicit_done(struct tevent_req *req)
{
    errno_t ret;
    struct autofs_map_ctx *map;
    struct autofs_cmd_ctx *cmdctx =
        tevent_req_callback_data(req, struct autofs_cmd_ctx);
    struct autofs_ctx *actx =
        talloc_get_type(cmdctx->cctx->rctx->pvt_ctx, struct autofs_ctx);

    ret = setautomntent_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("setautomntent_recv failed\n"));
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, ("No such map\n"));
        }
        goto done;
    }

    ret = get_autofs_map(actx, cmdctx->mapname, &map);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot get map after setautomntent succeeded?\n"));
        goto done;
    }

    if (map->ready == false) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Map not ready after setautomntent succeeded\n"));
        goto done;
    }

    ret = getautomntent_process(cmdctx, map,
                                cmdctx->cursor, cmdctx->max_entries);
done:
    autofs_cmd_done(cmdctx, ret);
    return;
}

static errno_t
getautomntent_process(struct autofs_cmd_ctx *cmdctx,
                      struct autofs_map_ctx *map,
                      uint32_t cursor, uint32_t max_entries)
{
    struct cli_ctx *client = cmdctx->cctx;
    errno_t ret;
    struct ldb_message *entry;
    size_t rp;
    uint32_t i, stop, left, nentries;
    uint8_t *body;
    size_t blen;

    /* create response packet */
    ret = sss_packet_new(client->creq, 0,
                         sss_packet_get_cmd(client->creq->in),
                         &client->creq->out);
    if (ret != EOK) {
        return ret;
    }

    if (!map->map || !map->entries || !map->entries[0] ||
        cursor >= map->entry_count) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("No entries found\n"));
        ret = sss_cmd_empty_packet(client->creq->out);
        if (ret != EOK) {
            return autofs_cmd_done(cmdctx, ret);
        }
        goto done;
    }

    ret = sss_packet_grow(client->creq->out, sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot grow packet\n"));
        goto done;
    }

    sss_packet_get_body(client->creq->out, &body, &blen);
    rp = sizeof(uint32_t);  /* We'll write the number of entries here */

    left = map->entry_count - cursor;
    stop = max_entries < left ? max_entries : left;

    nentries = 0;
    for (i=0; i < stop; i++) {
        entry = map->entries[cursor];
        cursor++;

        ret = fill_autofs_entry(entry, client->creq->out, &rp);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Cannot fill entry %d/%d, skipping\n", i, stop));
            continue;
        }
        nentries++;
    }

    rp = 0;
    SAFEALIGN_SET_UINT32(&body[rp], nentries, &rp);

    ret = EOK;
done:
    sss_packet_set_error(client->creq->out, ret);
    sss_cmd_done(client, cmdctx);

    return EOK;
}

static errno_t
fill_autofs_entry(struct ldb_message *entry, struct sss_packet *packet, size_t *rp)
{
    errno_t ret;
    const char *key;
    size_t keylen;
    const char *value;
    size_t valuelen;
    uint8_t *body;
    size_t blen;
    size_t len;

    key = ldb_msg_find_attr_as_string(entry, SYSDB_AUTOFS_ENTRY_KEY, NULL);
    value = ldb_msg_find_attr_as_string(entry, SYSDB_AUTOFS_ENTRY_VALUE, NULL);
    if (!key || !value) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Incomplete entry\n"));
        return EINVAL;
    }

    keylen = 1 + strlen(key);
    valuelen = 1 + strlen(value);
    len = sizeof(uint32_t) + sizeof(uint32_t) + keylen + sizeof(uint32_t) + valuelen;

    ret = sss_packet_grow(packet, len);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot grow packet\n"));
        return ret;
    }

    sss_packet_get_body(packet, &body, &blen);

    SAFEALIGN_SET_UINT32(&body[*rp], len, rp);
    SAFEALIGN_SET_UINT32(&body[*rp], keylen, rp);

    if (keylen == 1) {
        body[*rp] = '\0';
    } else {
        memcpy(&body[*rp], key, keylen);
    }
    *rp += keylen;

    SAFEALIGN_SET_UINT32(&body[*rp], valuelen, rp);
    if (valuelen == 1) {
        body[*rp] = '\0';
    } else {
        memcpy(&body[*rp], value, valuelen);
    }
    *rp += valuelen;

    return EOK;
}

static errno_t
getautomntbyname_process(struct autofs_cmd_ctx *cmdctx,
                         struct autofs_map_ctx *map,
                         const char *key);
static void
getautomntbyname_implicit_done(struct tevent_req *req);

static int
sss_autofs_cmd_getautomntbyname(struct cli_ctx *client)
{
    errno_t ret;
    struct autofs_cmd_ctx *cmdctx;
    struct autofs_map_ctx *map;
    struct autofs_ctx *actx;
    uint8_t *body;
    size_t blen;
    uint32_t namelen;
    uint32_t keylen;
    size_t c = 0;
    struct tevent_req *req;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("sss_autofs_cmd_getautomntbyname\n"));

    cmdctx = talloc_zero(client, struct autofs_cmd_ctx);
    if (!cmdctx) {
        return ENOMEM;
    }
    cmdctx->cctx = client;

    actx = talloc_get_type(client->rctx->pvt_ctx, struct autofs_ctx);
    if (!actx) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Missing autofs context\n"));
        return EIO;
    }

    /* get autofs map name and index to query */
    sss_packet_get_body(client->creq->in, &body, &blen);

    /* FIXME - split out a function to get string from <len><str>\0 */
    SAFEALIGN_COPY_UINT32_CHECK(&namelen, body+c, blen, &c);

    if (namelen == 0) {
        ret = EINVAL;
        goto done;
    }

    cmdctx->mapname = (char *) body+c;

    /* if not null-terminated fail */
    if (cmdctx->mapname[namelen] != '\0') {
        ret = EINVAL;
        goto done;
    }

    /* If the name isn't valid UTF-8, fail */
    if (!sss_utf8_check((const uint8_t *) cmdctx->mapname, namelen -1)) {
        ret = EINVAL;
        goto done;
    }

    c += namelen + 1;

    /* FIXME - split out a function to get string from <len><str>\0 */
    SAFEALIGN_COPY_UINT32_CHECK(&keylen, body+c, blen, &c);

    if (keylen == 0) {
        ret = EINVAL;
        goto done;
    }

    cmdctx->key = (char *) body+c;

    /* if not null-terminated fail */
    if (cmdctx->key[keylen] != '\0') {
        ret = EINVAL;
        goto done;
    }

    /* If the key isn't valid UTF-8, fail */
    if (!sss_utf8_check((const uint8_t *) cmdctx->key, keylen -1)) {
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requested data of map %s key %s\n", cmdctx->mapname, cmdctx->key));

    ret = get_autofs_map(actx, cmdctx->mapname, &map);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Performing implicit setautomntent\n"));
        req = setautomntent_send(cmdctx, cmdctx->mapname, cmdctx);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("setautomntent_send failed\n"));
            ret = EIO;
            goto done;
        }

        tevent_req_set_callback(req, getautomntbyname_implicit_done, cmdctx);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("An unexpected error occurred: [%d][%s]\n",
              ret, strerror(ret)));
        goto done;
    }

    if (map->ready == false) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Performing implicit setautomntent\n"));
        req = setautomntent_send(cmdctx, cmdctx->mapname, cmdctx);
        if (req == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("setautomntent_send failed\n"));
            ret = EIO;
            goto done;
        }

        tevent_req_set_callback(req, getautomntbyname_implicit_done, cmdctx);
        ret = EOK;
        goto done;
    } else if (map->found == false) {
        DEBUG(SSSDBG_TRACE_FUNC, ("negative cache hit\n"));
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          ("Looking up value for [%s] in [%s]\n", cmdctx->key, map->mapname));

    ret = getautomntbyname_process(cmdctx, map, cmdctx->key);

done:
    return autofs_cmd_done(cmdctx, ret);
}

static void
getautomntbyname_implicit_done(struct tevent_req *req)
{
    errno_t ret;
    struct autofs_map_ctx *map;
    struct autofs_cmd_ctx *cmdctx =
        tevent_req_callback_data(req, struct autofs_cmd_ctx);
    struct autofs_ctx *actx =
        talloc_get_type(cmdctx->cctx->rctx->pvt_ctx, struct autofs_ctx);

    ret = setautomntent_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("setautomntent_recv failed\n"));
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, ("No such map\n"));
        }
        goto done;
    }

    ret = get_autofs_map(actx, cmdctx->mapname, &map);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Cannot get map after setautomntent succeeded?\n"));
        goto done;
    }

    if (map->ready == false) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Map not ready after setautomntent succeeded\n"));
        goto done;
    }

    ret = getautomntbyname_process(cmdctx, map, cmdctx->key);
done:
    autofs_cmd_done(cmdctx, ret);
    return;
}

static errno_t
getautomntbyname_process(struct autofs_cmd_ctx *cmdctx,
                         struct autofs_map_ctx *map,
                         const char *key)
{
    struct cli_ctx *client = cmdctx->cctx;
    errno_t ret;
    size_t i;
    const char *k;
    const char *value;
    size_t valuelen;
    size_t len;
    uint8_t *body;
    size_t blen, rp;

    /* create response packet */
    ret = sss_packet_new(client->creq, 0,
                         sss_packet_get_cmd(client->creq->in),
                         &client->creq->out);
    if (ret != EOK) {
        return ret;
    }

    if (!map->map || !map->entries || !map->entries[0]) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("No entries found\n"));
        ret = sss_cmd_empty_packet(client->creq->out);
        if (ret != EOK) {
            return autofs_cmd_done(cmdctx, ret);
        }
        goto done;
    }

    for (i=0; i < map->entry_count; i++) {
        k = ldb_msg_find_attr_as_string(map->entries[i],
                                        SYSDB_AUTOFS_ENTRY_KEY, NULL);
        if (!k) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Skipping incomplete entry\n"));
            continue;
        }

        if (strcmp(k, key) == 0) {
            DEBUG(SSSDBG_TRACE_INTERNAL, ("Found key [%s]\n", key));
            break;
        }
    }

    if (i >= map->entry_count) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("No key named [%s] found\n", key));
        ret = sss_cmd_empty_packet(client->creq->out);
        if (ret != EOK) {
            return autofs_cmd_done(cmdctx, ret);
        }
        goto done;
    }

    value = ldb_msg_find_attr_as_string(map->entries[i],
                                        SYSDB_AUTOFS_ENTRY_VALUE, NULL);

    valuelen = 1 + strlen(value);
    len = sizeof(uint32_t) + sizeof(uint32_t) + valuelen;

    ret = sss_packet_grow(client->creq->out, len);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_get_body(client->creq->out, &body, &blen);

    rp = 0;
    SAFEALIGN_SET_UINT32(&body[rp], len, &rp);

    SAFEALIGN_SET_UINT32(&body[rp], valuelen, &rp);
    if (valuelen == 1) {
        body[rp] = '\0';
    } else {
        memcpy(&body[rp], value, valuelen);
    }
    rp += valuelen;

    ret = EOK;
done:
    sss_packet_set_error(client->creq->out, ret);
    sss_cmd_done(client, cmdctx);

    return EOK;
}

static int
sss_autofs_cmd_endautomntent(struct cli_ctx *client)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, ("endautomntent called\n"));

    /* create response packet */
    ret = sss_packet_new(client->creq, 0,
                         sss_packet_get_cmd(client->creq->in),
                         &client->creq->out);

    if (ret != EOK) {
        return ret;
    }

    sss_cmd_done(client, NULL);
    return EOK;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version autofs_cli_protocol_version[] = {
        { SSS_AUTOFS_PROTO_VERSION, NULL, NULL }
    };

    return autofs_cli_protocol_version;
}

struct sss_cmd_table *get_autofs_cmds(void)
{
    static struct sss_cmd_table autofs_cmds[] = {
        { SSS_GET_VERSION, sss_cmd_get_version },
        { SSS_AUTOFS_SETAUTOMNTENT, sss_autofs_cmd_setautomntent },
        { SSS_AUTOFS_GETAUTOMNTENT, sss_autofs_cmd_getautomntent },
        { SSS_AUTOFS_GETAUTOMNTBYNAME, sss_autofs_cmd_getautomntbyname },
        { SSS_AUTOFS_ENDAUTOMNTENT, sss_autofs_cmd_endautomntent },
        { SSS_CLI_NULL, NULL}
    };

    return autofs_cmds;
}
