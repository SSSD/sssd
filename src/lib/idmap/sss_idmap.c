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

#define SID_FMT "%s-%d"
#define SID_STR_MAX_LEN 1024

struct idmap_domain_info {
    char *name;
    char *sid;
    struct sss_idmap_range *range;
    struct idmap_domain_info *next;
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

static bool id_is_in_range(uint32_t id, struct sss_idmap_range *range,
                           uint32_t *rid)
{
    if (id == 0 || range == NULL) {
        return false;
    }

    if (id >= range->min && id <= range->max) {
        if (rid != NULL) {
            *rid = id - range->min;
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

    *_ctx = ctx;

    return IDMAP_SUCCESS;
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
        ctx->free_func(dom->range, ctx->alloc_pvt);
        ctx->free_func(dom->name, ctx->alloc_pvt);
        ctx->free_func(dom->sid, ctx->alloc_pvt);
        ctx->free_func(dom, ctx->alloc_pvt);
    }

    ctx->free_func(ctx, ctx->alloc_pvt);

    return IDMAP_SUCCESS;
}

enum idmap_error_code sss_idmap_add_domain(struct sss_idmap_ctx *ctx,
                                           const char *domain_name,
                                           const char *domain_sid,
                                           struct sss_idmap_range *range)
{
    struct idmap_domain_info *dom = NULL;

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    if (domain_name == NULL) {
        return IDMAP_NO_DOMAIN;
    }

    if (range == NULL) {
        return IDMAP_NO_RANGE;
    }

    if (!is_domain_sid(domain_sid)) {
        return IDMAP_SID_INVALID;
    }

    dom = ctx->alloc_func(sizeof(struct idmap_domain_info), ctx->alloc_pvt);
    if (dom == NULL) {
        return IDMAP_OUT_OF_MEMORY;
    }
    memset(dom, 0, sizeof(struct idmap_domain_info));

    dom->name = idmap_strdup(ctx, domain_name);
    if (dom->name == NULL) {
        goto fail;
    }

    dom->sid = idmap_strdup(ctx, domain_sid);
    if (dom->sid == NULL) {
        goto fail;
    }

    dom->range = idmap_range_dup(ctx, range);
    if (dom->range == NULL) {
        goto fail;
    }

    dom->next = ctx->idmap_domain_info;
    ctx->idmap_domain_info = dom;

    return IDMAP_SUCCESS;

fail:
    ctx->free_func(dom->sid, ctx->alloc_pvt);
    ctx->free_func(dom->name, ctx->alloc_pvt);
    ctx->free_func(dom, ctx->alloc_pvt);

    return IDMAP_OUT_OF_MEMORY;
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
                                            uint32_t *id)
{
    struct idmap_domain_info *idmap_domain_info;
    size_t dom_len;
    long long rid;
    char *endptr;

    if (sid == NULL || id == NULL) {
        return IDMAP_ERROR;
    }

    CHECK_IDMAP_CTX(ctx, IDMAP_CONTEXT_INVALID);

    idmap_domain_info = ctx->idmap_domain_info;

    if (sss_idmap_sid_is_builtin(sid)) {
        return IDMAP_BUILTIN_SID;
    }

    while (idmap_domain_info != NULL) {
        dom_len = strlen(idmap_domain_info->sid);
        if (strlen(sid) > dom_len && sid[dom_len] == '-' &&
            strncmp(sid, idmap_domain_info->sid, dom_len) == 0) {
            errno = 0;
            rid = strtoull(sid + dom_len + 1, &endptr, 10);
            if (errno != 0 || rid > UINT32_MAX || *endptr != '\0') {
                return IDMAP_SID_INVALID;
            }

            if (rid + idmap_domain_info->range->min >
                                                idmap_domain_info->range->max) {
                return IDMAP_NO_RANGE;
            }

            *id = rid + idmap_domain_info->range->min;
            return IDMAP_SUCCESS;
        }

        idmap_domain_info = idmap_domain_info->next;
    }

    return IDMAP_NO_DOMAIN;
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
        if (id_is_in_range(id, idmap_domain_info->range, &rid)) {
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
