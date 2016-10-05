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

const char *
nss_get_name_from_msg(struct sss_domain_info *domain,
                      struct ldb_message *msg)
{
    const char *name;

    /* If domain has a view associated we return overridden name
     * if possible. */
    if (DOM_HAS_VIEWS(domain)) {
        name = ldb_msg_find_attr_as_string(msg, OVERRIDE_PREFIX SYSDB_NAME,
                                           NULL);
        if (name != NULL) {
            return name;
        }
    }

    /* Otherwise we try to return name override from
     * Default Truest View for trusted users. */
    name = ldb_msg_find_attr_as_string(msg, SYSDB_DEFAULT_OVERRIDE_NAME, NULL);
    if (name != NULL) {
        return name;
    }

    /* If no override is found we return the original name. */
    return ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
}

int sized_output_name(TALLOC_CTX *mem_ctx,
                      struct resp_ctx *rctx,
                      const char *orig_name,
                      struct sss_domain_info *name_dom,
                      struct sized_string **_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *username;
    struct sized_string *name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    username = sss_output_name(tmp_ctx, orig_name, name_dom->case_preserve,
                               rctx->override_space);
    if (username == NULL) {
        ret = EIO;
        goto done;
    }

    if (name_dom->fqnames) {
        username = sss_tc_fqname(tmp_ctx, name_dom->names, name_dom, username);
        if (username == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_replace_space failed\n");
            ret = EIO;
            goto done;
        }
    }

    name = talloc_zero(tmp_ctx, struct sized_string);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    to_sized_string(name, username);
    name->str = talloc_steal(name, username);
    *_name = talloc_steal(mem_ctx, name);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sized_member_name(TALLOC_CTX *mem_ctx,
                      struct resp_ctx *rctx,
                      const char *member_name,
                      struct sized_string **_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *domname;
    struct sss_domain_info *member_dom;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, member_name, NULL, &domname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_parse_internal_fqname failed\n");
        goto done;
    }

    if (domname == NULL) {
        ret = ERR_WRONG_NAME_FORMAT;
        goto done;
    }

    member_dom = find_domain_by_name(get_domains_head(rctx->domains),
                                     domname, true);
    if (member_dom == NULL) {
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    ret = sized_output_name(mem_ctx, rctx, member_name,
                            member_dom, _name);
done:
    talloc_free(tmp_ctx);
    return ret;
}
