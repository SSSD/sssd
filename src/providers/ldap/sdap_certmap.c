
/*
    SSSD

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include "util/util.h"
#include "lib/certmap/sss_certmap.h"
#include "providers/ldap/ldap_common.h"

struct sdap_certmap_ctx {
    struct sss_certmap_ctx *certmap_ctx;
};

struct priv_sss_debug {
    int level;
};

static void ext_debug(void *private, const char *file, long line,
                      const char *function, const char *format, ...)
{
    va_list ap;
    struct priv_sss_debug *data = private;
    int level = SSSDBG_OP_FAILURE;

    if (data != NULL) {
        level = data->level;
    }

    va_start(ap, format);
    sss_vdebug_fn(file, line, function, level, APPEND_LINE_FEED,
                  format, ap);
    va_end(ap);
}

struct sss_certmap_ctx *sdap_get_sss_certmap(struct sdap_certmap_ctx *ctx)
{
    return ctx == NULL ? NULL : ctx->certmap_ctx;
}

errno_t sdap_setup_certmap(struct sdap_certmap_ctx *sdap_certmap_ctx,
                           struct certmap_info **certmap_list)
{
    int ret;
    struct sss_certmap_ctx *sss_certmap_ctx = NULL;
    size_t c;

    if (sdap_certmap_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing sdap_certmap_ctx.\n");
        return EINVAL;
    }

    if (certmap_list == NULL || *certmap_list == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "No certmap data, nothing to do.\n");
        ret = EOK;
        goto done;
    }

    ret = sss_certmap_init(sdap_certmap_ctx, ext_debug, NULL, &sss_certmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_certmap_init failed.\n");
        goto done;
    }

    for (c = 0; certmap_list[c] != NULL; c++) {
        DEBUG(SSSDBG_TRACE_ALL, "Trying to add rule [%s][%d][%s][%s].\n",
                                certmap_list[c]->name,
                                certmap_list[c]->priority,
                                certmap_list[c]->match_rule,
                                certmap_list[c]->map_rule);

        ret = sss_certmap_add_rule(sss_certmap_ctx, certmap_list[c]->priority,
                                   certmap_list[c]->match_rule,
                                   certmap_list[c]->map_rule,
                                   certmap_list[c]->domains);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_certmap_add_rule failed for rule [%s] "
                  "with error [%d][%s], skipping. "
                  "Please check for typos and if rule syntax is supported.\n",
                  certmap_list[c]->name, ret, sss_strerror(ret));
            continue;
        }
    }

    ret = EOK;

done:
    if (ret == EOK) {
        sss_certmap_free_ctx(sdap_certmap_ctx->certmap_ctx);
        sdap_certmap_ctx->certmap_ctx = sss_certmap_ctx;
    } else {
        sss_certmap_free_ctx(sss_certmap_ctx);
    }

    return ret;
}

errno_t sdap_init_certmap(TALLOC_CTX *mem_ctx, struct sdap_id_ctx *id_ctx)
{
    int ret;
    bool hint;
    struct certmap_info **certmap_list = NULL;

    if (id_ctx->opts->sdap_certmap_ctx == NULL) {
        id_ctx->opts->sdap_certmap_ctx = talloc_zero(mem_ctx,
                                                     struct sdap_certmap_ctx);
        if (id_ctx->opts->sdap_certmap_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            return ENOMEM;
        }
    }

    ret = sysdb_get_certmap(mem_ctx, id_ctx->be->domain->sysdb,
                            &certmap_list, &hint);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_certmap failed.\n");
        goto done;
    }

    ret = sdap_setup_certmap(id_ctx->opts->sdap_certmap_ctx, certmap_list);
    if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_setup_certmap failed.\n");
            goto done;
    }

    ret = EOK;

done:
    talloc_free(certmap_list);

    return ret;
}
