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

#include "responder/nss/nss_protocol.h"
#include "util/sss_format.h"

static errno_t
sss_nss_get_grent(TALLOC_CTX *mem_ctx,
                  struct sss_nss_ctx *nss_ctx,
                  struct sss_domain_info *domain,
                  struct ldb_message *msg,
                  uint32_t *_gid,
                  struct sized_string **_name)
{
    const char *name;
    uint32_t gid;
    errno_t ret;

    /* Check object class. */
    if (!ldb_msg_check_string_attribute(msg, SYSDB_OBJECTCATEGORY,
                                        SYSDB_GROUP_CLASS)) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Wrong object (%s) found on stack!\n",
              ldb_dn_get_linearized(msg->dn));
        return ERR_INTERNAL;
    }

    /* Get fields. */
    name = sss_get_name_from_msg(domain, msg);
    gid = sss_view_ldb_msg_find_attr_as_uint64(domain, msg, SYSDB_GIDNUM, 0);

    if (name == NULL || gid == 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Incomplete group object for %s[%u]! Skipping\n",
              name ? name : "<NULL>", gid);
        return EINVAL;
    }

    /* Convert to sized strings. */
    ret = sized_output_name(mem_ctx, nss_ctx->rctx, name, domain, _name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sized_output_name failed, skipping [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    *_gid = gid;

    return EOK;
}

static struct ldb_message_element *
sss_nss_get_group_members(struct sss_domain_info *domain,
                          struct ldb_message *msg)
{
    struct ldb_message_element *el;

    if (domain->ignore_group_members) {
        return NULL;
    }

    /* Unconditionally prefer OVERRIDE_PREFIX SYSDB_MEMBERUID, it
     * might contain override names from the default view. */
    el = ldb_msg_find_element(msg, OVERRIDE_PREFIX SYSDB_MEMBERUID);
    if (el == NULL) {
        el = ldb_msg_find_element(msg, SYSDB_MEMBERUID);
    }

    return el;
}

static struct ldb_message_element *
sss_nss_get_group_ghosts(struct sss_domain_info *domain,
                         struct ldb_message *msg,
                         const char *group_name)
{
    struct ldb_message_element *el;

    if (domain->ignore_group_members) {
        return NULL;
    }

    el = ldb_msg_find_element(msg, SYSDB_GHOST);
    if (el == NULL) {
        return NULL;
    }

    if (DOM_HAS_VIEWS(domain) && !is_local_view(domain->view_name)
            && el->num_values != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Domain has a view [%s] but group [%s] still has "
              "ghost members.\n", domain->view_name, group_name);
        return NULL;
    }

    return el;
}

static errno_t
sss_nss_protocol_fill_members(struct sss_packet *packet,
                              struct sss_nss_ctx *nss_ctx,
                              struct sss_domain_info *domain,
                              struct ldb_message *msg,
                              const char *group_name,
                              size_t *_rp,
                              uint32_t *_num_members)
{
    TALLOC_CTX *tmp_ctx;
    struct resp_ctx *rctx = nss_ctx->rctx;
    struct ldb_message_element *members[2];
    struct ldb_message_element *el;
    struct sized_string *name;
    const char *member_name;
    uint32_t num_members = 0;
    size_t body_len;
    uint8_t *body;
    errno_t ret;
    int i, j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    members[0] = sss_nss_get_group_members(domain, msg);
    members[1] = sss_nss_get_group_ghosts(domain, msg, group_name);

    sss_packet_get_body(packet, &body, &body_len);

    for (i = 0; i < sizeof(members) / sizeof(members[0]); i++) {
        el = members[i];
        if (el == NULL) {
            continue;
        }

        for (j = 0; j < el->num_values; j++) {
            member_name = (const char *)el->values[j].data;

            if (nss_ctx->filter_users_in_groups) {
                ret = sss_ncache_check_user(rctx->ncache, domain, member_name);
                if (ret == EEXIST) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "Group [%s] member [%s] filtered out! "
                          "(negative cache)\n", group_name, member_name);
                    continue;
                }
            }

            ret = sized_domain_name(tmp_ctx, rctx, member_name, &name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Unable to get sized name [%d]: %s\n",
                      ret, sss_strerror(ret));
                goto done;
            }

            ret = sss_packet_grow(packet, name->len);
            if (ret != EOK) {
                goto done;
            }

            sss_packet_get_body(packet, &body, &body_len);
            SAFEALIGN_SET_STRING(&body[*_rp], name->str, name->len, _rp);

            num_members++;
        }
    }

    ret = EOK;

done:
    *_num_members = num_members;
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
sss_nss_protocol_fill_grent(struct sss_nss_ctx *nss_ctx,
                            struct sss_nss_cmd_ctx *cmd_ctx,
                            struct sss_packet *packet,
                            struct cache_req_result *result)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct sized_string *name;
    struct sized_string pwfield;
    uint32_t gid;
    uint32_t num_results;
    uint32_t num_members;
    char *members;
    size_t members_size;
    size_t rp;
    size_t rp_members;
    size_t rp_num_members;
    size_t body_len;
    uint8_t *body;
    int i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* First two fields (length and reserved), filled up later. */
    ret = sss_packet_grow(packet, 2 * sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }

    rp = 2 * sizeof(uint32_t);

    num_results = 0;
    for (i = 0; i < result->count; i++) {
        talloc_free_children(tmp_ctx);
        msg = result->msgs[i];

        /* Password field content. */
        to_sized_string(&pwfield, sss_nss_get_pwfield(nss_ctx, result->domain));

        ret = sss_nss_get_grent(tmp_ctx, nss_ctx, result->domain, msg,
                            &gid, &name);
        if (ret != EOK) {
            continue;
        }

        /* Adjust packet size: gid, num_members + string fields. */

        ret = sss_packet_grow(packet, 2 * sizeof(uint32_t)
                                          + name->len + pwfield.len);
        if (ret != EOK) {
            goto done;
        }

        sss_packet_get_body(packet, &body, &body_len);

        /* Fill packet. */

        SAFEALIGN_SET_UINT32(&body[rp], gid, &rp);

        /* Remember pointer to number of members field. */
        rp_num_members = rp;
        SAFEALIGN_SET_UINT32(&body[rp], 0, &rp);
        SAFEALIGN_SET_STRING(&body[rp], name->str, name->len, &rp);
        SAFEALIGN_SET_STRING(&body[rp], pwfield.str, pwfield.len, &rp);
        rp_members = rp;

        /* Fill members. */
        ret = sss_nss_protocol_fill_members(packet, nss_ctx, result->domain, msg,
                                        name->str, &rp, &num_members);
        if (ret != EOK) {
            goto done;
        }

        sss_packet_get_body(packet, &body, &body_len);
        SAFEALIGN_SET_UINT32(&body[rp_num_members], num_members, NULL);

        num_results++;

        /* Do not store entry in memory cache during enumeration or when
         * requested or if cache explicitly disabled. */
        if (!cmd_ctx->enumeration
                && ((cmd_ctx->flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) == 0)
                && (nss_ctx->grp_mc_ctx != NULL)) {
            members = (char *)&body[rp_members];
            members_size = body_len - rp_members;
            ret = sss_mmap_cache_gr_store(&nss_ctx->grp_mc_ctx, name, &pwfield,
                                          gid, num_members, members,
                                          members_size);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to store group %s (%s) in mem-cache [%d]: %s!\n",
                      name->str, result->domain->name, ret, sss_strerror(ret));
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        sss_packet_set_size(packet, 0);
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);
    SAFEALIGN_COPY_UINT32(body, &num_results, NULL);
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL); /* reserved */

    return EOK;
}

static bool is_group_filtered(struct sss_nc_ctx *ncache,
                              struct sss_domain_info *domain,
                              const char *grp_name, gid_t gid)
{
    int ret;

    if (grp_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Group with gid [%"SPRIgid"] has no name, this should never "
              "happen, trying to continue without.\n", gid);
    } else {
        ret = sss_ncache_check_group(ncache, domain, grp_name);
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC, "Group [%s] is filtered out! "
                                     "(negative cache)", grp_name);
            return true;
        }
    }
    ret = sss_ncache_check_gid(ncache, domain, gid);
    if (ret == EEXIST) {
        DEBUG(SSSDBG_TRACE_FUNC, "Group [%"SPRIgid"] is filtered out! "
                                 "(negative cache)", gid);
        return true;
    }

    return false;
}

errno_t
sss_nss_protocol_fill_initgr(struct sss_nss_ctx *nss_ctx,
                             struct sss_nss_cmd_ctx *cmd_ctx,
                             struct sss_packet *packet,
                             struct cache_req_result *result)
{
    struct sss_domain_info *domain;
    struct sss_domain_info *grp_dom;
    struct ldb_message *user;
    struct ldb_message *msg;
    struct ldb_message *primary_group_msg;
    const char *posix;
    struct sized_string rawname;
    struct sized_string canonical_name;
    uint32_t num_results;
    uint8_t *body;
    size_t body_len;
    size_t rp;
    gid_t gid;
    const char *grp_name;
    gid_t orig_gid;
    errno_t ret;
    int i;

    if (result->count == 0) {
        return ENOENT;
    }

    domain = result->domain;

    /* num_results, reserved + gids */
    ret = sss_packet_grow(packet, (2 + result->count) * sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }
    sss_packet_get_body(packet, &body, &body_len);
    rp = 2 * sizeof(uint32_t);

    user = result->msgs[0];
    gid = sss_view_ldb_msg_find_attr_as_uint64(domain, user, SYSDB_GIDNUM, 0);
    orig_gid = sss_view_ldb_msg_find_attr_as_uint64(domain, user,
                                                    SYSDB_PRIMARY_GROUP_GIDNUM,
                                                    0);

    /* Try to get the real gid in case the primary group's gid was overridden. */
    ret = sysdb_search_group_by_origgid(NULL, domain, orig_gid, NULL,
                                        &primary_group_msg);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "There is no override for group %" SPRIgid "\n",
                  orig_gid);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unable to find the original group id attribute for %" SPRIgid
                  ". Assuming there is none. [%d] %s\n",
                  orig_gid, ret, sss_strerror(ret));
        }
        /* Just continue with what we have. */
    } else {
        orig_gid = ldb_msg_find_attr_as_uint64(primary_group_msg, SYSDB_GIDNUM,
                                               orig_gid);
        talloc_free(primary_group_msg);
    }

    /* If the GID of the original primary group is available but equal to the
     * current primary GID it must not be added. */
    orig_gid = orig_gid == gid ? 0 : orig_gid;

    /* First message is user, skip it. */
    num_results = 0;
    for (i = 1; i < result->count; i++) {
        msg = result->msgs[i];
        grp_dom = find_domain_by_msg(domain, msg);
        gid = sss_view_ldb_msg_find_attr_as_uint64(grp_dom, msg, SYSDB_GIDNUM,
                                                   0);
        posix = ldb_msg_find_attr_as_string(msg, SYSDB_POSIX, NULL);
        grp_name = sss_view_ldb_msg_find_attr_as_string(grp_dom, msg, SYSDB_NAME,
                                                        NULL);

        if (gid == 0) {
            if (posix != NULL && strcmp(posix, "FALSE") == 0) {
                continue;
            } else {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Incomplete group object [%s] for initgroups! "
                      "Skipping.\n", ldb_dn_get_linearized(msg->dn));
                continue;
            }
        }

        if (is_group_filtered(nss_ctx->rctx->ncache, grp_dom, grp_name, gid)) {
            continue;
        }

        SAFEALIGN_COPY_UINT32(&body[rp], &gid, &rp);
        num_results++;

        /* Do not add the GID of the original primary group if the user is
         * already an explicit member of the group. */
        if (orig_gid == gid) {
            orig_gid = 0;
        }
    }

    if (orig_gid == 0) {
        /* Initialize allocated memory to be safe and make Valgrind happy. */
        SAFEALIGN_SET_UINT32(&body[rp], 0, &rp);
    } else {
        /* Insert original primary group into the result. */
        SAFEALIGN_COPY_UINT32(&body[rp], &orig_gid, &rp);
        num_results++;
    }

    if (nss_ctx->initgr_mc_ctx
                && ((cmd_ctx->flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) == 0)
                && (nss_ctx->initgr_mc_ctx != NULL)) {
        to_sized_string(&rawname, cmd_ctx->rawname);
        to_sized_string(&canonical_name, sss_get_name_from_msg(domain, user));

        ret = sss_mmap_cache_initgr_store(&nss_ctx->initgr_mc_ctx, &rawname,
                                          &canonical_name, num_results,
                                          body + 2 * sizeof(uint32_t));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store initgroups %s (%s) in mem-cache [%d]: %s!\n",
                  rawname.str, domain->name, ret, sss_strerror(ret));
            sss_packet_set_size(packet, 0);
            return ret;
        }
    }

    sss_packet_get_body(packet, &body, &body_len);
    SAFEALIGN_COPY_UINT32(body, &num_results, NULL);
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL); /* reserved */

    return EOK;
}
