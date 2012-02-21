/*
    SSSD

    Proxy netgroup handler

    Authors:

        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "providers/proxy/proxy.h"
#include "util/util.h"

#define BUFLEN  1024

static errno_t make_netgroup_attr(struct __netgrent netgrent,
                                  struct sysdb_attrs *attrs)
{
    int ret;
    char *dummy;

    if (netgrent.type == group_val) {
        ret =sysdb_attrs_add_string(attrs, SYSDB_NETGROUP_MEMBER,
                                    netgrent.val.group);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
            return ret;
        }
    } else if (netgrent.type == triple_val) {
        dummy = talloc_asprintf(attrs, "(%s,%s,%s)", netgrent.val.triple.host,
                                netgrent.val.triple.user,
                                netgrent.val.triple.domain);
        if (dummy == NULL) {
            DEBUG(1, ("talloc_asprintf failed.\n"));
            return ENOMEM;
        }

        ret = sysdb_attrs_add_string(attrs, SYSDB_NETGROUP_TRIPLE, dummy);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_attrs_add_string failed.\n"));
            return ret;
        }
    } else {
        DEBUG(1, ("Unknown netgrent entry type [%d].\n", netgrent.type));
        return EINVAL;
    }

    return EOK;
}

static errno_t save_netgroup(struct sysdb_ctx *sysdb,
                             const char *name,
                             struct sysdb_attrs *attrs,
                             bool lowercase,
                             uint64_t cache_timeout)
{
    errno_t ret;
    char *lower;

    if (lowercase) {
        lower = sss_tc_utf8_str_tolower(NULL, name);
        if (!lower) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot convert name to lowercase\n"));
            return ENOMEM;
        }

        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, lower);
        talloc_free(lower);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not add name alias\n"));
            return ret;
        }
    }

    ret = sysdb_add_netgroup(sysdb, name, NULL, attrs, NULL, cache_timeout, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_add_netgroup failed.\n"));
        return ret;
    }

    return EOK;
}

errno_t get_netgroup(struct proxy_id_ctx *ctx,
                     struct sysdb_ctx *sysdb,
                     struct sss_domain_info *dom,
                     const char *name)
{
    struct __netgrent result;
    enum nss_status status;
    char buffer[BUFLEN];
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *attrs;

    memset(&result, 0 ,sizeof(result));
    status = ctx->ops.setnetgrent(name, &result);
    if (status != NSS_STATUS_SUCCESS) {
        DEBUG(5, ("setnetgrent failed for netgroup [%s].\n", name));
        return EIO;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        DEBUG(1, ("sysdb_new_attrs failed.\n"));
        return ENOMEM;
    }

    do {
        status = ctx->ops.getnetgrent_r(&result, buffer, BUFLEN, &ret);
        if (status != NSS_STATUS_SUCCESS && status != NSS_STATUS_RETURN) {
            DEBUG(1, ("getnetgrent_r failed for netgroup [%s]: [%d][%s].\n",
                      name, ret, strerror(ret)));
            goto done;
        }

        if (status == NSS_STATUS_SUCCESS) {
            ret = make_netgroup_attr(result, attrs);
            if (ret != EOK) {
                DEBUG(1, ("make_netgroup_attr failed.\n"));
                goto done;
            }
        }
    } while (status != NSS_STATUS_RETURN);

    status = ctx->ops.endnetgrent(&result);
    if (status != NSS_STATUS_SUCCESS) {
        DEBUG(1, ("endnetgrent failed.\n"));
        ret = EIO;
        goto done;
    }

    ret = save_netgroup(sysdb, name, attrs,
                        !dom->case_sensitive,
                        dom->netgroup_timeout);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_add_netgroup failed.\n"));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
