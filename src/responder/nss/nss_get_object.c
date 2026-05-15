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
memcache_delete_entry_by_name(struct sss_nss_ctx *nss_ctx,
                              struct sized_string *name,
                              enum sss_mc_type type)
{
    errno_t ret;

    switch (type) {
    case SSS_MC_PASSWD:
        if (nss_ctx->pwd_mc_ctx == NULL) { /* mem-cache disabled */
            return EOK;
        }
        ret = sss_mmap_cache_pw_invalidate(&nss_ctx->pwd_mc_ctx, name);
        break;
    case SSS_MC_GROUP:
        if (nss_ctx->grp_mc_ctx == NULL) { /* mem-cache disabled */
            return EOK;
        }
        ret = sss_mmap_cache_gr_invalidate(&nss_ctx->grp_mc_ctx, name);
        break;
    case SSS_MC_INITGROUPS:
        if (nss_ctx->initgr_mc_ctx == NULL) { /* mem-cache disabled */
            return EOK;
        }
        ret = sss_mmap_cache_initgr_invalidate(&nss_ctx->initgr_mc_ctx, name);
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
memcache_delete_entry_by_id(struct sss_nss_ctx *nss_ctx,
                            uint32_t id,
                            enum sss_mc_type type)
{
    errno_t ret;

    switch (type) {
    case SSS_MC_PASSWD:
        if (nss_ctx->pwd_mc_ctx == NULL) { /* mem-cache disabled */
            return EOK;
        }
        ret = sss_mmap_cache_pw_invalidate_uid(&nss_ctx->pwd_mc_ctx, (uid_t)id);
        break;
    case SSS_MC_GROUP:
        if (nss_ctx->grp_mc_ctx == NULL) { /* mem-cache disabled */
            return EOK;
        }
        ret = sss_mmap_cache_gr_invalidate_gid(&nss_ctx->grp_mc_ctx, (gid_t)id);
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

errno_t
memcache_delete_entry(struct sss_nss_ctx *nss_ctx,
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
        } else if (id == 0) {
            /*
             * As "root" is not handled by SSSD, let's just return EOK here
             * instead of erroring out.
             */
            return EOK;
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

static struct cache_req_data *
hybrid_domain_retry_data(TALLOC_CTX *mem_ctx,
                         struct cache_req_data *orig,
                         const char *input_name,
                         uint32_t input_id)
{
    enum cache_req_type cr_type = cache_req_data_get_type(orig);
    struct cache_req_data *hybrid_data = NULL;

    if (cr_type == CACHE_REQ_GROUP_BY_ID) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Retrying group-by-ID lookup in user space\n");
        hybrid_data = cache_req_data_id(mem_ctx,
                                        CACHE_REQ_USER_BY_ID,
                                        input_id);
    } else if (cr_type == CACHE_REQ_GROUP_BY_NAME) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Retrying group-by-name lookup in user space\n");
        hybrid_data = cache_req_data_name(mem_ctx,
                                          CACHE_REQ_USER_BY_NAME,
                                          input_name);
    }

    if (hybrid_data != NULL) {
        cache_req_data_set_hybrid_lookup(hybrid_data, true);
    }

    return hybrid_data;
}

static struct cache_req_data *
hybrid_domain_verify_gid_data(TALLOC_CTX *mem_ctx,
                              struct cache_req_result *user_group)
{
    gid_t gid;

    /* read the GID of this 'group' and use it to construct
     * a cache_req_data struct
     */
    gid = sss_view_ldb_msg_find_attr_as_uint64(user_group->domain,
                                               user_group->msgs[0],
                                               SYSDB_GIDNUM,
                                               0);
    if (gid == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "A user with no GID?\n");
        return NULL;
    }

    return cache_req_data_id(mem_ctx,
                             CACHE_REQ_GROUP_BY_ID,
                             gid);
}

static int
hybrid_domain_user_to_group(struct cache_req_result *result)
{
    errno_t ret;
    uid_t uid;
    gid_t gid;

    /* There must be exactly one entry.. */
    if (result == NULL || result->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No result or wrong number of entries, expected 1 entry\n");
        return ENOENT;
    }

    /* ...which has uidNumber equal to gidNumber */
    uid = sss_view_ldb_msg_find_attr_as_uint64(result->domain,
                                               result->msgs[0],
                                               SYSDB_UIDNUM,
                                               0);

    gid = sss_view_ldb_msg_find_attr_as_uint64(result->domain,
                                               result->msgs[0],
                                               SYSDB_GIDNUM,
                                               0);

    if (uid == 0 || uid != gid) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "UID and GID differ\n");
        return ENOENT;
    }

    /* OK, we have a user with uid == gid; let's pretend this is a group */
    ret = ldb_msg_add_string(result->msgs[0],
                             SYSDB_OBJECTCATEGORY,
                             SYSDB_GROUP_CLASS);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot add group class\n");
        return ret;
    }

    return EOK;
}

struct sss_nss_get_object_state {
    struct sss_nss_ctx *nss_ctx;
    struct resp_ctx *rctx;
    struct tevent_context *ev;
    struct cli_ctx *cli_ctx;
    struct cache_req_data *data;

    /* We delete object from memory cache if it is not found */
    enum sss_mc_type memcache;
    const char *input_name;
    uint32_t input_id;

    struct cache_req_result *result;
};

static void sss_nss_get_object_done(struct tevent_req *subreq);
static bool sss_nss_is_hybrid_object_enabled(struct sss_domain_info *domains);
static errno_t sss_nss_get_hybrid_object_step(struct tevent_req *req);
static void sss_nss_get_hybrid_object_done(struct tevent_req *subreq);
static void sss_nss_get_hybrid_gid_verify_done(struct tevent_req *subreq);
static void sss_nss_get_object_finish_req(struct tevent_req *req,
                                          errno_t ret);

/* Cache request data memory context is stolen to internal state. */
struct tevent_req *
sss_nss_get_object_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct cli_ctx *cli_ctx,
                        struct cache_req_data *data,
                        enum sss_mc_type memcache,
                        const char *input_name,
                        uint32_t input_id)
{
    struct sss_nss_get_object_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sss_nss_get_object_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }
    state->ev = ev;
    state->cli_ctx = cli_ctx;
    state->data = talloc_steal(state, data);

    state->rctx = cli_ctx->rctx;
    state->nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct sss_nss_ctx);
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
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Client [%p][%d]: unable to send cache request!\n",
              cli_ctx, cli_ctx->cfd);
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Client [%p][%d]: sent cache request #%u\n",
          cli_ctx, cli_ctx->cfd, cache_req_get_reqid(subreq));

    tevent_req_set_callback(subreq, sss_nss_get_object_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sss_nss_get_object_done(struct tevent_req *subreq)
{
    struct sss_nss_get_object_state *state;
    struct tevent_req *req;
    errno_t ret;
    errno_t retry_ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_nss_get_object_state);

    ret = cache_req_single_domain_recv(state, subreq, &state->result);
    talloc_zfree(subreq);

    /* Try to process hybrid object if any domain enables it. This will issue a
     * cache_req that will iterate only over domains with MPG_HYBRID. */
    if (ret == ENOENT
            && sss_nss_is_hybrid_object_enabled(state->nss_ctx->rctx->domains)) {
        retry_ret = sss_nss_get_hybrid_object_step(req);
        if (retry_ret == EAGAIN) {
            /* Retrying hybrid search */
            return;
        }
        /* Otherwise return the value of ret as returned from
         * cache_req_single_domain_recv
         */
    }

    sss_nss_get_object_finish_req(req, ret);
    return;
}

static void sss_nss_get_object_finish_req(struct tevent_req *req,
                                      errno_t ret)
{
    struct sss_nss_get_object_state *state;

    state = tevent_req_data(req, struct sss_nss_get_object_state);

    switch (ret) {
    case EOK:
        tevent_req_done(req);
        break;
    case ENOENT:
        if ((state->memcache != SSS_MC_NONE) && (state->memcache != SSS_MC_SID)) {
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
}

static bool sss_nss_is_hybrid_object_enabled(struct sss_domain_info *domains)
{
    struct sss_domain_info *dom;

    for (dom = domains; dom != NULL;
             dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        if (dom->mpg_mode == MPG_HYBRID) {
            return true;
        }
    }

    return false;
}

static errno_t sss_nss_get_hybrid_object_step(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sss_nss_get_object_state *state;

    state = tevent_req_data(req, struct sss_nss_get_object_state);

    state->data = hybrid_domain_retry_data(state,
                                            state->data,
                                            state->input_name,
                                            state->input_id);
    if (state->data == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "This request cannot be retried\n");
        return EOK;
    }

    subreq = cache_req_send(req,
                            state->ev,
                            state->cli_ctx->rctx,
                            state->cli_ctx->rctx->ncache,
                            state->nss_ctx->cache_refresh_percent,
                            CACHE_REQ_POSIX_DOM,
                            NULL,
                            state->data);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send cache request!\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, sss_nss_get_hybrid_object_done, req);

    return EAGAIN;
}

static void sss_nss_get_hybrid_object_done(struct tevent_req *subreq)
{
    struct sss_nss_get_object_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_nss_get_object_state);

    ret = cache_req_single_domain_recv(state, subreq, &state->result);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Converting user object to a group\n");
    ret = hybrid_domain_user_to_group(state->result);
    if (ret != EOK) {
        goto done;
    }

    /* If the "group" was requested by name, we also must verify that
     * no other group with this ID exists in any domain, otherwise
     * we would have returned a private group that should be shadowed,
     * this record would have been inserted into the memcache and then
     * even getgrgid() would return this unexpected group
     */
    if (cache_req_data_get_type(state->data) == CACHE_REQ_USER_BY_NAME) {
        DEBUG(SSSDBG_TRACE_FUNC, "Will verify if MPG group is shadowed\n");
        talloc_zfree(state->data);
        state->data = hybrid_domain_verify_gid_data(state, state->result);
        if (state->data == NULL) {
            sss_nss_get_object_finish_req(req, EINVAL);
            return;
        }

        subreq = cache_req_send(req,
                                state->ev,
                                state->cli_ctx->rctx,
                                state->cli_ctx->rctx->ncache,
                                state->nss_ctx->cache_refresh_percent,
                                CACHE_REQ_POSIX_DOM,
                                NULL,
                                state->data);
        if (subreq == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send cache request!\n");
            tevent_req_error(req, ENOENT);
            return;
        }
        tevent_req_set_callback(subreq, sss_nss_get_hybrid_gid_verify_done, req);
        return;
    }

done:
    sss_nss_get_object_finish_req(req, ret);
    return;
}

static void sss_nss_get_hybrid_gid_verify_done(struct tevent_req *subreq)
{
    struct sss_nss_get_object_state *state;
    struct cache_req_result *real_gr_result;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sss_nss_get_object_state);

    ret = cache_req_single_domain_recv(state, subreq, &real_gr_result);
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        /* There is no real group with the same GID as the autogenerated
         * one we were checking, so let's return the autogenerated one
         */
        ret = EOK;
        goto done;
    } else if (ret == EOK) {
        /* The autogenerated group is shadowed by a real one. Don't return
         * anything.
         */
        DEBUG(SSSDBG_TRACE_FUNC,
              "A real entry would be shadowed by MPG entry\n");
        ret = ENOENT;
        goto done;
    }

done:
    sss_nss_get_object_finish_req(req, ret);
    return;
}

errno_t
sss_nss_get_object_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    struct cache_req_result **_result,
                    const char **_rawname)
{
    struct sss_nss_get_object_state *state;
    state = tevent_req_data(req, struct sss_nss_get_object_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_result != NULL) {
        *_result = talloc_steal(mem_ctx, state->result);
    }

    if (_rawname != NULL) {
        *_rawname = talloc_steal(mem_ctx, state->input_name);
    }

    return EOK;
}
