/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <tevent.h>
#include <talloc.h>

#include "util/util.h"
#include "responder/nss/nss_private.h"
#include "responder/nss/nsssrv_mmap_cache.h"

static errno_t
memcache_delete_entry_by_name(struct nss_ctx *nss_ctx,
                              struct sized_string *name,
                              enum sss_mc_type type)
{
    errno_t ret;

    switch (type) {
    case SSS_MC_PASSWD:
        ret = sss_mmap_cache_pw_invalidate(nss_ctx->pwd_mc_ctx, name);
        break;
    case SSS_MC_GROUP:
        ret = sss_mmap_cache_gr_invalidate(nss_ctx->grp_mc_ctx, name);
        break;
    case SSS_MC_INITGROUPS:
        ret = sss_mmap_cache_initgr_invalidate(nss_ctx->initgr_mc_ctx, name);
        break;
    default:
        return EINVAL;
    }

    if (ret == EOK || ret == ENOENT) {
        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE,
          "Internal failure in memory cache code: %d [%s]\n",
          ret, sss_strerror(ret));

    return ret;
}

static errno_t
memcache_delete_entry_by_id(struct nss_ctx *nss_ctx,
                            uint32_t id,
                            enum sss_mc_type type)
{
    errno_t ret;

    switch (type) {
    case SSS_MC_PASSWD:
        ret = sss_mmap_cache_pw_invalidate_uid(nss_ctx->pwd_mc_ctx, (uid_t)id);
        break;
    case SSS_MC_GROUP:
        ret = sss_mmap_cache_gr_invalidate_gid(nss_ctx->grp_mc_ctx, (gid_t)id);
        break;
    default:
        return EINVAL;
    }

    if (ret == EOK || ret == ENOENT) {
        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE,
          "Internal failure in memory cache code: %d [%s]\n",
          ret, sss_strerror(ret));

    return ret;
}

static errno_t
memcache_delete_entry(struct nss_ctx *nss_ctx,
                      struct resp_ctx *rctx,
                      struct sss_domain_info *domain,
                      const char *name,
                      uint32_t id,
                      enum sss_mc_type type)
{
    struct sss_domain_info *dom;
    struct sized_string *sized_name;
    errno_t ret;

    for (dom = rctx->domains;
         dom != NULL;
         dom = get_next_domain(dom, SSS_GND_DESCEND)) {

        if (domain == dom) {
            /* We found entry in this domain so we don't
             * wont to invalidate it here. */
            continue;
        }

        if (name != NULL) {
            ret = sized_output_name(NULL, rctx, name, dom, &sized_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Unable to create sized name [%d]: %s\n",
                      ret, sss_strerror(ret));
                return ret;
            }

            ret = memcache_delete_entry_by_name(nss_ctx, sized_name, type);
            talloc_zfree(sized_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Unable to delete '%s' from domain '%s' memory cache!\n",
                      name, dom->name);
                continue;
            }
        } else if (id != 0) {
            ret = memcache_delete_entry_by_id(nss_ctx, id, type);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Unable to delete '%u' from domain '%s' memory cache!\n",
                      id, dom->name);
                continue;
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Bug: invalid input!");
            return ERR_INTERNAL;
        }
    }

    return EOK;
}

struct nss_get_object_state {
    struct nss_ctx *nss_ctx;
    struct resp_ctx *rctx;

    /* We delete object from memory cache if it is not found */
    enum sss_mc_type memcache;
    const char *input_name;
    uint32_t input_id;

    struct cache_req_result *result;
};

static void nss_get_object_done(struct tevent_req *subreq);

/* Cache request data memory context is stolen to internal state. */
struct tevent_req *
nss_get_object_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct cli_ctx *cli_ctx,
                    struct cache_req_data *data,
                    enum sss_mc_type memcache,
                    const char *input_name,
                    uint32_t input_id)
{
    struct nss_get_object_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct nss_get_object_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    talloc_steal(state, data);

    state->rctx = cli_ctx->rctx;
    state->nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    state->memcache = memcache;
    state->input_id = input_id;
    state->input_name = talloc_strdup(state, input_name);
    if (input_name != NULL && state->input_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = cache_req_send(req, ev, cli_ctx->rctx, cli_ctx->rctx->ncache,
                            state->nss_ctx->cache_refresh_percent,
                            CACHE_REQ_POSIX_DOM, NULL, data);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send cache request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, nss_get_object_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void nss_get_object_done(struct tevent_req *subreq)
{
    struct nss_get_object_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct nss_get_object_state);

    ret = cache_req_single_domain_recv(state, subreq, &state->result);
    talloc_zfree(subreq);

    switch (ret) {
    case EOK:
        if (state->memcache != SSS_MC_NONE) {
            /* Delete entry from all domains but the one that was found. */
            memcache_delete_entry(state->nss_ctx, state->rctx,
                                  state->result->domain,
                                  state->input_name,
                                  state->input_id,
                                  state->memcache);
        }

        tevent_req_done(req);
        break;
    case ENOENT:
        if (state->memcache != SSS_MC_NONE) {
            /* Delete entry from all domains. */
            memcache_delete_entry(state->nss_ctx, state->rctx, NULL,
                                  state->input_name, state->input_id,
                                  state->memcache);
        }

        tevent_req_error(req, ENOENT);
        break;
    default:
        tevent_req_error(req, ret);
        break;
    }

    return;
}

errno_t
nss_get_object_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    struct cache_req_result **_result,
                    const char **_rawname)
{
    struct nss_get_object_state *state;
    state = tevent_req_data(req, struct nss_get_object_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_result != NULL) {
        *_result = talloc_steal(mem_ctx, state->result);
    }

    if (_rawname != NULL) {
        *_rawname = talloc_steal(mem_ctx, state->input_name);
    }

    return EOK;
}
