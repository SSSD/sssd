/*
    SSSD

    ID-mapping library

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "lib/idmap/sss_idmap.h"
#include "lib/idmap/sss_idmap_private.h"
#include "util/murmurhash3.h"

#define SID_FMT "%s-%d"
#define SID_STR_MAX_LEN 1024

struct idmap_domain_info {
    char *name;
    char *sid;
    struct sss_idmap_range *range;
    struct idmap_domain_info *next;
    uint32_t first_rid;
    char *range_id;
    bool external_mapping;
};

static void *default_alloc(size_t size, void *pvt)
{
    return malloc(size);
}

static void default_free(void *ptr, void *pvt)
{
    free(ptr);
}

static char *idmap_strdup(struct sss_idmap_ctx *ctx, const char *str)
{
    char *new = NULL;
    size_t len;

    CHECK_IDMAP_CTX(ctx, NULL);

    len = strlen(str) + 1;

    new = ctx->alloc_func(len, ctx->alloc_pvt);
    if (new == NULL) {
        return NULL;
    }

    memcpy(new, str, len);

    return new;
}

static struct sss_idmap_range *idmap_range_dup(struct sss_idmap_ctx *ctx,
                                               struct sss_idmap_range *range)
{
    struct sss_idmap_range *new = NULL;

    CHECK_IDMAP_CTX(ctx, NULL);


    new = ctx->alloc_func(sizeof(struct sss_idmap_range), ctx->alloc_pvt);
    if (new == NULL) {
        return NULL;
    }

    memset(new, 0, sizeof(struct sss_idmap_range));

    new->min = range->min;
    new->max = range->max;

    return new;
}

static bool id_is_in_range(uint32_t id, struct idmap_domain_info *dom,
                           uint32_t *rid)
{
    if (id == 0 || dom == NULL || dom->range == NULL) {
        return false;
    }

    if (id >= dom->range->min && id <= dom->range->max) {
        if (rid != NULL) {
            *rid = dom->first_rid + (id - dom->range->min);
        }

        return true;
    }

    return false;
}

const char *idmap_error_string(enum idmap_error_code err)
{
    switch (err) {
        case IDMAP_SUCCESS:
            return "IDMAP operation successful";
            break;
        case IDMAP_NOT_IMPLEMENTED:
            return "IDMAP Function is not yet implemented";
            break;
        case IDMAP_ERROR:
            return "IDMAP general error";
            break;
        case IDMAP_OUT_OF_MEMORY:
            return "IDMAP operation ran out of memory";
            break;
        case IDMAP_NO_DOMAIN:
            return "IDMAP domain not found";
            break;
        case IDMAP_CONTEXT_INVALID:
            return "IDMAP context is invalid";
            break;
        case IDMAP_SID_INVALID:
            return "IDMAP SID is invalid";
            break;
        case IDMAP_SID_UNKNOWN:
            return "IDMAP SID not found";
            break;
        case IDMAP_NO_RANGE:
            return "IDMAP range not found";
        default:
            return "IDMAP unknown error code";
    }
}

bool is_domain_sid(const char *sid)
{
    const char *p;
    long long a;
    char *endptr;
    size_t c;

    if (sid == NULL || strncmp(sid, DOM_SID_PREFIX, DOM_SID_PREFIX_LEN) != 0) {
        return false;
    }

    p = sid + DOM_SID_PREFIX_LEN;
    c = 0;

    do {
        errno = 0;
        a = strtoull(p, &endptr, 10);
        if (errno != 0 || a > UINT32_MAX) {
            return false;
        }

        if (*endptr == '-') {
            p = endptr + 1;
        } else if (*endptr != '\0') {
            return false;
        }
        c++;
    } while(c < 3 && *endptr != '\0');

    if (c != 3 || *endptr != '\0') {
        return false;
    }

    return true;
}

enum idmap_error_code sss_idmap_init(idmap_alloc_func *alloc_func,
                                     void *alloc_pvt,
                                     idmap_free_func *free_func,
                                     struct sss_idmap_ctx **_ctx)
{
    struct sss_idmap_ctx *ctx;

    if (alloc_func == NULL) {
        alloc_func = default_alloc;
    }

    ctx = alloc_func(sizeof(struct sss_idmap_ctx), alloc_pvt);
    if (ctx == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(ctx, 0, sizeof(struct sss_idmap_ctx));

    ctx->alloc_func = alloc_func;
    ctx->alloc_pvt = alloc_pvt;
    ctx->free_func = (free_func == NULL) ? default_free : free_func;

    /* Set default values. */
    ctx->idmap_opts.autorid_mode = SSS_IDMAP_DEFAULT_AUTORID;
    ctx->idmap_opts.idmap_lower = SSS_IDMAP_DEFAULT_LOWER;
    ctx->idmap_opts.idmap_upper = SSS_IDMAP_DEFAULT_UPPER;
    ctx->idmap_opts.rangesize = SSS_IDMAP_DEFAULT_RANGESIZE;

    *_ctx = ctx;

    return IDMAP_SUCCESS;
}

static void sss_idmap_free_domain(struct sss_idmap_ctx *ctx,
                                  struct idmap_domain_info *dom)
{
    if (ctx == NULL || dom == NULL) {
        return;
    }

    ctx->free_func(dom->range_id, ctx->alloc_pvt);
    ctx->free_func(dom->range, ctx->alloc_pvt);
    ctx->free_func(dom->name, ctx->alloc_pvt);
    ctx->free_func(dom->sid, ctx->alloc_pvt);
    ctx->free_func(dom, ctx->alloc_pvt);
}

enum idmap_error_code sss_idmap_free(struct sss_idmap_ctx *ctx)
{
    struct idmap_domain_info *dom;
    struct idmap_domain_info *next;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    next = ctx->idmap_domain_info;
    while (next) {
        dom = next;
        next = dom->next;
        sss_idmap_free_domain(ctx, dom);
    }

    ctx->free_func(ctx, ctx->alloc_pvt);

    return IDMAP_SUCCESS;
}

static enum idmap_error_code sss_idmap_free_ptr(struct sss_idmap_ctx *ctx,
                                                void *ptr)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (ptr != NULL) {
        ctx->free_func(ptr, ctx->alloc_pvt);
    }

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_free_sid(struct sss_idmap_ctx *ctx,
                                         char *sid)
{
    return sss_idmap_free_ptr(ctx, sid);
}

enum idmap_error_code sss_idmap_free_dom_sid(struct sss_idmap_ctx *ctx,
                                             struct sss_dom_sid *dom_sid)
{
    return sss_idmap_free_ptr(ctx, dom_sid);
}

enum idmap_error_code sss_idmap_free_smb_sid(struct sss_idmap_ctx *ctx,
                                             struct dom_sid *smb_sid)
{
    return sss_idmap_free_ptr(ctx, smb_sid);
}

enum idmap_error_code sss_idmap_free_bin_sid(struct sss_idmap_ctx *ctx,
                                             uint8_t *bin_sid)
{
    return sss_idmap_free_ptr(ctx, bin_sid);
}

enum idmap_error_code sss_idmap_calculate_range(struct sss_idmap_ctx *ctx,
                                                const char *dom_sid,
                                                id_t *slice_num,
                                                struct sss_idmap_range *_range)
{
    id_t max_slices;
    id_t orig_slice;
    id_t new_slice = 0;
    id_t min;
    id_t max;
    id_t idmap_lower;
    id_t idmap_upper;
    id_t rangesize;
    bool autorid_mode;
    uint32_t hash_val;
    struct idmap_domain_info *dom;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_lower = ctx->idmap_opts.idmap_lower;
    idmap_upper = ctx->idmap_opts.idmap_upper;
    rangesize = ctx->idmap_opts.rangesize;
    autorid_mode = ctx->idmap_opts.autorid_mode;

    max_slices = (idmap_upper - idmap_lower) / rangesize;

    if (slice_num && *slice_num != -1) {
        /* The slice is being set explicitly.
         * This may happen at system startup when we're loading
         * previously-determined slices. In the future, we may also
         * permit configuration to select the slice for a domain
         * explicitly.
         */
        new_slice = *slice_num;
    } else {
        /* If slice is -1, we're being asked to pick a new slice */

        if (autorid_mode) {
            /* In autorid compatibility mode, always start at 0 and find the
             * first free value.
             */
            orig_slice = 0;
        } else {
            /* Hash the domain sid string */
            hash_val = murmurhash3(dom_sid, strlen(dom_sid), 0xdeadbeef);

            /* Now get take the modulus of the hash val and the max_slices
             * to determine its optimal position in the range.
             */
            new_slice = hash_val % max_slices;
            orig_slice = new_slice;
        }

        min = (rangesize * new_slice) + idmap_lower;
        max = min + rangesize;
        /* Verify that this slice is not already in use */
        do {
            for (dom = ctx->idmap_domain_info; dom != NULL; dom = dom->next) {
                if ((dom->range->min <= min && dom->range->max >= max) ||
                    (dom->range->min >= min && dom->range->min <= max) ||
                    (dom->range->max >= min && dom->range->max <= max)) {
                    /* This range overlaps one already registered
                     * We'll try the next available slot
                     */
                    new_slice++;
                    if (new_slice >= max_slices) {
                        /* loop around to the beginning if necessary */
                        new_slice = 0;
                    }

                    min = (rangesize * new_slice) + idmap_lower;
                    max = min + rangesize;
                    break;
                }
            }

            /* Keep trying until dom is NULL (meaning we got to the end
             * without matching) or we have run out of slices and gotten
             * back to the first one we tried.
             */
        } while (dom && new_slice != orig_slice);

        if (dom) {
            /* We looped all the way through and found no empty slots */
            return IDMAP_OUT_OF_SLICES;
        }
    }

    _range->min = (rangesize * new_slice) + idmap_lower;
    _range->max = _range->min + rangesize;

    if (slice_num) {
        *slice_num = new_slice;
    }

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_check_collision_ex(const char *o_name,
                                                const char *o_sid,
                                                struct sss_idmap_range *o_range,
                                                uint32_t o_first_rid,
                                                const char *o_range_id,
                                                bool o_external_mapping,
                                                const char *n_name,
                                                const char *n_sid,
                                                struct sss_idmap_range *n_range,
                                                uint32_t n_first_rid,
                                                const char *n_range_id,
                                                bool n_external_mapping)
{
    bool names_equal;
    bool sids_equal;

    /* TODO: if both ranges have the same ID check if an update is
     * needed. */

    /* Check if ID ranges overlap.
     * ID ranges with external mapping may overlap. */
    if ((!n_external_mapping && !o_external_mapping)
        && ((n_range->min >= o_range->min
                && n_range->min <= o_range->max)
            || (n_range->max >= o_range->min
                && n_range->max <= o_range->max))) {
        return IDMAP_COLLISION;
    }

    names_equal = (strcasecmp(n_name, o_name) == 0);
    sids_equal = ((n_sid == NULL && o_sid == NULL)
                    || (n_sid != NULL && o_sid != NULL
                        && strcasecmp(n_sid, o_sid) == 0));

    /* check if domain name and SID are consistent */
    if ((names_equal && !sids_equal) || (!names_equal && sids_equal)) {
        return IDMAP_COLLISION;
    }

    /* check if external_mapping is consistent */
    if (names_equal && sids_equal
            && n_external_mapping != o_external_mapping) {
        return IDMAP_COLLISION;
    }

    /* check if RID ranges overlap */
    if (names_equal && sids_equal
            && n_external_mapping == false
            && n_first_rid >= o_first_rid
            && n_first_rid <= o_first_rid + (o_range->max - o_range->min)) {
        return IDMAP_COLLISION;
    }

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_check_collision(struct sss_idmap_ctx *ctx,
                                                char *n_name, char *n_sid,
                                                struct sss_idmap_range *n_range,
                                                uint32_t n_first_rid,
                                                char *n_range_id,
                                                bool n_external_mapping)
{
    struct idmap_domain_info *dom;
    enum idmap_error_code err;

    for (dom = ctx->idmap_domain_info; dom != NULL; dom = dom->next) {
        err = sss_idmap_check_collision_ex(dom->name, dom->sid, dom->range,
                                           dom->first_rid, dom->range_id,
                                           dom->external_mapping,
                                           n_name, n_sid, n_range, n_first_rid,
                                           n_range_id, n_external_mapping);
        if (err != IDMAP_SUCCESS) {
            return err;
        }
    }
    return IDMAP_SUCCESS;
}

static enum idmap_error_code dom_check_collision(
                                             struct idmap_domain_info *dom_list,
                                             struct idmap_domain_info *new_dom)
{
    struct idmap_domain_info *dom;
    enum idmap_error_code err;

    for (dom = dom_list; dom != NULL; dom = dom->next) {
        err = sss_idmap_check_collision_ex(dom->name, dom->sid, dom->range,
                                           dom->first_rid, dom->range_id,
                                           dom->external_mapping,
                                           new_dom->name, new_dom->sid,
                                           new_dom->range, new_dom->first_rid,
                                           new_dom->range_id,
                                           new_dom->external_mapping);
        if (err != IDMAP_SUCCESS) {
            return err;
        }
    }
    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_add_domain_ex(struct sss_idmap_ctx *ctx,
                                              const char *domain_name,
                                              const char *domain_sid,
                                              struct sss_idmap_range *range,
                                              const char *range_id,
                                              uint32_t rid,
                                              bool external_mapping)
{
    struct idmap_domain_info *dom = NULL;
    enum idmap_error_code err;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (domain_name == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    if (range == NULL) {
        return IDMAP_NO_RANGE;
    }

    /* For algorithmic mapping a valid domain SID is required, for external
     * mapping it may be NULL, but if set it should be valid. */
    if ((!external_mapping && !is_domain_sid(domain_sid))
            || (external_mapping
                && domain_sid != NULL
                && !is_domain_sid(domain_sid))) {
        return IDMAP_SID_INVALID;
    }

    dom = ctx->alloc_func(sizeof(struct idmap_domain_info), ctx->alloc_pvt);
    if (dom == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(dom, 0, sizeof(struct idmap_domain_info));

    dom->name = idmap_strdup(ctx, domain_name);
    if (dom->name == NULL) {
        err = IDMAP_OUT_OF_MEMORY;
        goto fail;
    }

    if (domain_sid != NULL) {
        dom->sid = idmap_strdup(ctx, domain_sid);
        if (dom->sid == NULL) {
            err = IDMAP_OUT_OF_MEMORY;
            goto fail;
        }
    }

    dom->range = idmap_range_dup(ctx, range);
    if (dom->range == NULL) {
        err = IDMAP_OUT_OF_MEMORY;
        goto fail;
    }

    if (range_id != NULL) {
        dom->range_id = idmap_strdup(ctx, range_id);
        if (dom->range_id == NULL) {
            err = IDMAP_OUT_OF_MEMORY;
            goto fail;
        }
    }

    dom->first_rid = rid;
    dom->external_mapping = external_mapping;

    err = dom_check_collision(ctx->idmap_domain_info, dom);
    if (err != IDMAP_SUCCESS) {
        goto fail;
    }

    dom->next = ctx->idmap_domain_info;
    ctx->idmap_domain_info = dom;

    return IDMAP_SUCCESS;

fail:
    sss_idmap_free_domain(ctx, dom);

    return err;
}

enum idmap_error_code sss_idmap_add_domain(struct sss_idmap_ctx *ctx,
                                           const char *domain_name,
                                           const char *domain_sid,
                                           struct sss_idmap_range *range)
{
    return sss_idmap_add_domain_ex(ctx, domain_name, domain_sid, range, NULL,
                                   0, false);
}

static bool sss_idmap_sid_is_builtin(const char *sid)
{
    if (strncmp(sid, "S-1-5-32-", 9) == 0) {
        return true;
    }

    return false;
}

enum idmap_error_code sss_idmap_sid_to_unix(struct sss_idmap_ctx *ctx,
                                            const char *sid,
                                            uint32_t *_id)
{
    struct idmap_domain_info *idmap_domain_info;
    size_t dom_len;
    long long rid;
    char *endptr;
    uint32_t id;
    bool no_range = false;

    if (sid == NULL || _id == NULL) {
        return IDMAP_ERROR;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_domain_info = ctx->idmap_domain_info;

    if (sss_idmap_sid_is_builtin(sid)) {
        return IDMAP_BUILTIN_SID;
    }

    while (idmap_domain_info != NULL) {
        if (idmap_domain_info->sid != NULL) {
            dom_len = strlen(idmap_domain_info->sid);
            if (strlen(sid) > dom_len && sid[dom_len] == '-'
                    && strncmp(sid, idmap_domain_info->sid, dom_len) == 0) {

                if (idmap_domain_info->external_mapping == true) {
                    return IDMAP_EXTERNAL;
                }

                errno = 0;
                rid = strtoull(sid + dom_len + 1, &endptr, 10);
                if (errno != 0 || rid > UINT32_MAX || *endptr != '\0') {
                    return IDMAP_SID_INVALID;
                }

                if (rid >= idmap_domain_info->first_rid) {
                    id = idmap_domain_info->range->min
                            + (rid - idmap_domain_info->first_rid);
                    if (id <= idmap_domain_info->range->max) {
                        *_id = id;
                        return IDMAP_SUCCESS;
                    }
                }

                no_range = true;
            }
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return no_range ? IDMAP_NO_RANGE : IDMAP_NO_DOMAIN;
}

enum idmap_error_code sss_idmap_check_sid_unix(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               uint32_t id)
{
    struct idmap_domain_info *idmap_domain_info;
    size_t dom_len;
    bool no_range = false;

    if (sid == NULL) {
        return IDMAP_ERROR;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (ctx->idmap_domain_info == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    idmap_domain_info = ctx->idmap_domain_info;

    if (sss_idmap_sid_is_builtin(sid)) {
        return IDMAP_BUILTIN_SID;
    }

    while (idmap_domain_info != NULL) {
        if (idmap_domain_info->sid != NULL) {
            dom_len = strlen(idmap_domain_info->sid);
            if (strlen(sid) > dom_len && sid[dom_len] == '-'
                    && strncmp(sid, idmap_domain_info->sid, dom_len) == 0) {

                if (id >= idmap_domain_info->range->min
                    && id <= idmap_domain_info->range->max) {
                    return IDMAP_SUCCESS;
                }

                no_range = true;
            }
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return no_range ? IDMAP_NO_RANGE : IDMAP_SID_UNKNOWN;
}

enum idmap_error_code sss_idmap_unix_to_sid(struct sss_idmap_ctx *ctx,
                                            uint32_t id,
                                            char **_sid)
{
    struct idmap_domain_info *idmap_domain_info;
    int len;
    int ret;
    uint32_t rid;
    char *sid = NULL;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_domain_info = ctx->idmap_domain_info;

    while (idmap_domain_info != NULL) {
        if (id_is_in_range(id, idmap_domain_info, &rid)) {

            if (idmap_domain_info->external_mapping == true
                    || idmap_domain_info->sid == NULL) {
                return IDMAP_EXTERNAL;
            }

            len = snprintf(NULL, 0, SID_FMT, idmap_domain_info->sid, rid);
            if (len <= 0 || len > SID_STR_MAX_LEN) {
                return IDMAP_ERROR;
            }

            sid = ctx->alloc_func(len + 1, ctx->alloc_pvt);
            if (sid == NULL) {
                return IDMAP_OUT_OF_MEMORY;
            }

            ret = snprintf(sid, len + 1, SID_FMT, idmap_domain_info->sid, rid);
            if (ret != len) {
                ctx->free_func(sid, ctx->alloc_pvt);
                return IDMAP_ERROR;
            }

            *_sid = sid;
            return IDMAP_SUCCESS;
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return IDMAP_NO_DOMAIN;
}

enum idmap_error_code sss_idmap_dom_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                struct sss_dom_sid *dom_sid,
                                                uint32_t *id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_dom_sid_to_sid(ctx, dom_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_bin_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                uint8_t *bin_sid,
                                                size_t length,
                                                uint32_t *id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_bin_sid_to_sid(ctx, bin_sid, length, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_smb_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                struct dom_sid *smb_sid,
                                                uint32_t *id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_smb_sid_to_sid(ctx, smb_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_check_dom_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                    struct sss_dom_sid *dom_sid,
                                                    uint32_t id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_dom_sid_to_sid(ctx, dom_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_check_sid_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_check_bin_sid_unix(struct sss_idmap_ctx *ctx,
                                                   uint8_t *bin_sid,
                                                   size_t length,
                                                   uint32_t id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_bin_sid_to_sid(ctx, bin_sid, length, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_check_sid_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}

enum idmap_error_code sss_idmap_check_smb_sid_unix(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   uint32_t id)
{
    enum idmap_error_code err;
    char *sid;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_smb_sid_to_sid(ctx, smb_sid, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_check_sid_unix(ctx, sid, id);

done:
    ctx->free_func(sid, ctx->alloc_pvt);

    return err;
}
enum idmap_error_code sss_idmap_unix_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                uint32_t id,
                                                struct sss_dom_sid **_dom_sid)
{
    enum idmap_error_code err;
    char *sid = NULL;
    struct sss_dom_sid *dom_sid = NULL;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_unix_to_sid(ctx, id, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_dom_sid(ctx, sid, &dom_sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_dom_sid = dom_sid;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(dom_sid, ctx->alloc_pvt);
    }

    return err;
}

enum idmap_error_code sss_idmap_unix_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                uint32_t id,
                                                uint8_t **_bin_sid,
                                                size_t *_length)
{
    enum idmap_error_code err;
    char *sid = NULL;
    uint8_t *bin_sid = NULL;
    size_t length;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_unix_to_sid(ctx, id, &sid);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    err = sss_idmap_sid_to_bin_sid(ctx, sid, &bin_sid, &length);
    if (err != IDMAP_SUCCESS) {
        goto done;
    }

    *_bin_sid = bin_sid;
    *_length = length;
    err = IDMAP_SUCCESS;

done:
    ctx->free_func(sid, ctx->alloc_pvt);
    if (err != IDMAP_SUCCESS) {
        ctx->free_func(bin_sid, ctx->alloc_pvt);
    }

    return err;

}

enum idmap_error_code
sss_idmap_ctx_set_autorid(struct sss_idmap_ctx *ctx, bool use_autorid)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.autorid_mode = use_autorid;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_set_lower(struct sss_idmap_ctx *ctx, id_t lower)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.idmap_lower = lower;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_set_upper(struct sss_idmap_ctx *ctx, id_t upper)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.idmap_upper = upper;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_set_rangesize(struct sss_idmap_ctx *ctx, id_t rangesize)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    ctx->idmap_opts.rangesize = rangesize;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_get_autorid(struct sss_idmap_ctx *ctx, bool *_autorid)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
     *_autorid = ctx->idmap_opts.autorid_mode;
     return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_get_lower(struct sss_idmap_ctx *ctx, id_t *_lower)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    *_lower = ctx->idmap_opts.idmap_lower;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_get_upper(struct sss_idmap_ctx *ctx, id_t *_upper)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    *_upper = ctx->idmap_opts.idmap_upper;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_ctx_get_rangesize(struct sss_idmap_ctx *ctx, id_t *_rangesize)
{
    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);
    *_rangesize =  ctx->idmap_opts.rangesize;
    return IDMAP_SUCCESS;
}

enum idmap_error_code
sss_idmap_domain_has_algorithmic_mapping(struct sss_idmap_ctx *ctx,
                                         const char *dom_sid,
                                         bool *has_algorithmic_mapping)
{
    struct idmap_domain_info *idmap_domain_info;
    size_t len;
    size_t dom_sid_len;

    if (dom_sid == NULL) {
        return IDMAP_SID_INVALID;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (ctx->idmap_domain_info == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    idmap_domain_info = ctx->idmap_domain_info;

    while (idmap_domain_info != NULL) {
        if (idmap_domain_info->sid != NULL) {
            len = strlen(idmap_domain_info->sid);
            dom_sid_len = strlen(dom_sid);
            if (((dom_sid_len > len && dom_sid[len] == '-')
                        || dom_sid_len == len)
                    && strncmp(dom_sid, idmap_domain_info->sid, len) == 0) {

                *has_algorithmic_mapping = !idmap_domain_info->external_mapping;
                return IDMAP_SUCCESS;

            }
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return IDMAP_SID_UNKNOWN;
}

enum idmap_error_code
sss_idmap_domain_by_name_has_algorithmic_mapping(struct sss_idmap_ctx *ctx,
                                                 const char *dom_name,
                                                 bool *has_algorithmic_mapping)
{
    struct idmap_domain_info *idmap_domain_info;

    if (dom_name == NULL) {
        return IDMAP_ERROR;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (ctx->idmap_domain_info == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    idmap_domain_info = ctx->idmap_domain_info;

    while (idmap_domain_info != NULL) {
        if (idmap_domain_info->name != NULL
                && strcmp(dom_name, idmap_domain_info->name) == 0) {

            *has_algorithmic_mapping = !idmap_domain_info->external_mapping;
            return IDMAP_SUCCESS;
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return IDMAP_NAME_UNKNOWN;
}
