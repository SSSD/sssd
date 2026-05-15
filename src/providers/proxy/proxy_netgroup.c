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

#define get_triple_el(s) ((s) ? (s) : "")

static errno_t make_netgroup_attr(struct __netgrent netgrent,
                                  struct sysdb_attrs *attrs)
{
    int ret;
    char *dummy;

    if (netgrent.type == group_val) {
        ret =sysdb_attrs_add_string(attrs, SYSDB_NETGROUP_MEMBER,
                                    netgrent.val.group);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_add_string failed.\n");
            return ret;
        }
    } else if (netgrent.type == triple_val) {
        dummy = talloc_asprintf(attrs, "(%s,%s,%s)",
                                get_triple_el(netgrent.val.triple.host),
                                get_triple_el(netgrent.val.triple.user),
                                get_triple_el(netgrent.val.triple.domain));
        if (dummy == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
            return ENOMEM;
        }

        ret = sysdb_attrs_add_string(attrs, SYSDB_NETGROUP_TRIPLE, dummy);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_add_string failed.\n");
            return ret;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown netgrent entry type [%d].\n", netgrent.type);
        return EINVAL;
    }

    return EOK;
}

static errno_t save_netgroup(struct sss_domain_info *domain,
                             const char *name,
                             struct sysdb_attrs *attrs,
                             bool lowercase,
                             uint64_t cache_timeout)
{
    errno_t ret;

    if (lowercase) {
        ret = sysdb_attrs_add_lc_name_alias(attrs, name);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add name alias\n");
            return ret;
        }
    }

    ret = sysdb_add_netgroup(domain, name, NULL, attrs, NULL,
                             cache_timeout, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_netgroup failed.\n");
        return ret;
    }

    return EOK;
}

static errno_t handle_error(enum nss_status status,
                            struct sss_domain_info *domain, const char *name)
{
    errno_t ret;

    switch (status) {
    case NSS_STATUS_SUCCESS:
        DEBUG(SSSDBG_TRACE_INTERNAL, "Netgroup lookup succeeded\n");
        ret = EOK;
        break;

    case NSS_STATUS_NOTFOUND:
        DEBUG(SSSDBG_MINOR_FAILURE, "The netgroup was not found\n");
        ret = sysdb_delete_netgroup(domain, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot delete netgroup: %d\n", ret);
            ret = EIO;
        }
        break;

    case NSS_STATUS_UNAVAIL:
        DEBUG(SSSDBG_TRACE_LIBS,
              "The proxy target did not respond, going offline\n");
        ret = ENXIO;
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected error looking up netgroup\n");
        ret = EIO;
        break;
    }

    return ret;
}

errno_t get_netgroup(struct proxy_id_ctx *ctx,
                     struct sss_domain_info *dom,
                     const char *name)
{
    struct __netgrent result;
    enum nss_status status;
    char buffer[BUFLEN];
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct sysdb_attrs *attrs;

    memset(&result, 0, sizeof(result));
    status = ctx->ops.setnetgrent(name, &result);
    if (status != NSS_STATUS_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "setnetgrent failed for netgroup [%s].\n", name);
        ret = handle_error(status, dom, name);
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_new_attrs failed.\n");
        ret = ENOMEM;
        goto done;
    }

    do {
        status = ctx->ops.getnetgrent_r(&result, buffer, BUFLEN, &ret);
        if (status != NSS_STATUS_SUCCESS &&
            status != NSS_STATUS_RETURN &&
            status != NSS_STATUS_NOTFOUND) {
            ret = handle_error(status, dom, name);
            DEBUG(SSSDBG_OP_FAILURE,
                  "getnetgrent_r failed for netgroup [%s]: [%d][%s].\n",
                   name, ret, strerror(ret));
            goto done;
        }

        if (status == NSS_STATUS_SUCCESS) {
            ret = make_netgroup_attr(result, attrs);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "make_netgroup_attr failed.\n");
                goto done;
            }
        }
    } while (status != NSS_STATUS_RETURN && status != NSS_STATUS_NOTFOUND);

    status = ctx->ops.endnetgrent(&result);
    if (status != NSS_STATUS_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "endnetgrent failed.\n");
        ret = handle_error(status, dom, name);
        goto done;
    }

    ret = save_netgroup(dom, name, attrs,
                        !dom->case_sensitive,
                        dom->netgroup_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "save_netgroup failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
