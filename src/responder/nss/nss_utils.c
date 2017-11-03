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

#include <talloc.h>
#include <ldb.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include "responder/nss/nss_private.h"

const char *
nss_get_pwfield(struct nss_ctx *nctx,
               struct sss_domain_info *dom)
{
    if (dom->pwfield != NULL) {
        return dom->pwfield;
    }

    return nctx->pwfield;
}

errno_t get_extra_data(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char override_space,
                       struct ldb_message *msg,
                       struct sized_data *extra_data)
{
    const char *name;
    char *short_name;
    size_t len = 0;
    size_t pos = 0;
    uint8_t *data;
    const char *flat_name;
    const char *sid_str;

    if (domain == NULL || domain->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing domain name.");
        return EINVAL;
    }

    /* Use domain->name if domain->flat_name is undefined */
    /* FIXME: or should it be better "" ? */
    flat_name = domain->flat_name != NULL ? domain->flat_name : domain->name;

    name = sss_get_name_from_msg(domain, msg);
    if (name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Object has no name.\n");
        return EINVAL;
    }

    short_name = sss_output_name(mem_ctx, name, domain->case_preserve,
                                 override_space);
    if (short_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_output_name failed.\n");
        return ENOMEM;
    }

    /* If a SID cannot be found add an empty string */
    sid_str = ldb_msg_find_attr_as_string(msg, SYSDB_SID_STR, "");

    len = strlen(short_name) + strlen(domain->name) + strlen(flat_name)
                             + strlen(sid_str) + 4 +  2 * sizeof(uint32_t);
    data = talloc_size(mem_ctx, len);
    if (data == NULL) {
        talloc_free(short_name);
        DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    /* overall length of the extra data including the length itself */
    SAFEALIGN_COPY_UINT32(data + pos, &len, &pos);
    /* 4 0-terminated strings will follow */
    SAFEALIGN_SET_UINT32(data + pos, 4, &pos);

    memcpy(data + pos, short_name, strlen(short_name) + 1);
    pos += strlen(short_name) + 1;
    talloc_free(short_name);

    memcpy(data + pos, domain->name, strlen(domain->name) + 1);
    pos += strlen(domain->name) + 1;

    memcpy(data + pos, flat_name, strlen(flat_name) + 1);
    pos += strlen(flat_name) + 1;

    memcpy(data + pos, sid_str, strlen(sid_str) + 1);
    pos += strlen(sid_str) + 1;

    extra_data->data = data;
    extra_data->len = len;

    return EOK;
}

