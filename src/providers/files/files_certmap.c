/*
    SSSD

    files_init.c - Initialization of the files provider

    Copyright (C) 2018 Red Hat

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

#include "providers/files/files_private.h"
#include "util/util.h"
#include "util/cert.h"
#include "lib/certmap/sss_certmap.h"

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
    sss_vdebug_fn(file, line, function, level, APPEND_LINE_FEED, format, ap);
    va_end(ap);
}

errno_t files_init_certmap(TALLOC_CTX *mem_ctx, struct files_id_ctx *id_ctx)
{
    int ret;
    bool hint;
    struct certmap_info **certmap_list = NULL;
    size_t c;

    ret = sysdb_get_certmap(mem_ctx, id_ctx->be->domain->sysdb,
                            &certmap_list, &hint);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_certmap failed.\n");
        goto done;
    }

    if (certmap_list == NULL || *certmap_list == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "No certmap data, nothing to do.\n");
        ret = EOK;
        goto done;
    }

    ret = sss_certmap_init(mem_ctx, ext_debug, NULL, &id_ctx->sss_certmap_ctx);
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

        ret = sss_certmap_add_rule(id_ctx->sss_certmap_ctx,
                                   certmap_list[c]->priority,
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
    talloc_free(certmap_list);

    return ret;
}

errno_t files_map_cert_to_user(struct files_id_ctx *id_ctx,
                               struct dp_id_data *data)
{
    errno_t ret;
    char *filter;
    char *user;
    struct ldb_message *msg = NULL;
    struct sysdb_attrs *attrs = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sss_cert_derb64_to_ldap_filter(tmp_ctx, data->filter_value, "",
                                         id_ctx->sss_certmap_ctx,
                                         id_ctx->domain, &filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_cert_derb64_to_ldap_filter failed.\n");
        goto done;
    }
    if (filter == NULL || filter[0] != '('
                       || filter[strlen(filter) - 1] != ')') {
        DEBUG(SSSDBG_OP_FAILURE,
              "sss_cert_derb64_to_ldap_filter returned bad filter [%s].\n",
              filter);
        ret = EINVAL;
        goto done;
    }

    filter[strlen(filter) - 1] = '\0';
    user = sss_create_internal_fqname(tmp_ctx, &filter[1],
                                      id_ctx->domain->name);
    if (user == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_create_internal_fqname failed.\n");
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL, "Certificate mapped to user: [%s].\n", user);

    ret = sysdb_search_user_by_name(tmp_ctx, id_ctx->domain, user, NULL, &msg);
    if (ret == EOK) {
        attrs = sysdb_new_attrs(tmp_ctx);
        if (attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_MAPPED_CERT,
                                          data->filter_value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_base64_blob failed.\n");
            goto done;
        }

        ret = sysdb_set_entry_attr(id_ctx->domain->sysdb, msg->dn, attrs,
                                   SYSDB_MOD_ADD);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_entry_attr failed.\n");
            goto done;
        }
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "Mapped user [%s] not found.\n", user);
        ret = EOK;
        goto done;
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_name failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
