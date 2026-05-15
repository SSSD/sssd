/*
    SSSD

    AD groups helper routines

    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include "db/sysdb.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async_private.h"

/* ==Group-Parsing Routines=============================================== */

errno_t sdap_check_ad_group_type(struct sss_domain_info *dom,
                                 struct sdap_options *opts,
                                 struct sysdb_attrs *group_attrs,
                                 const char *group_name,
                                 bool *_need_filter)
{
    int32_t ad_group_type;
    errno_t ret = EOK;
    *_need_filter = false;

    if (opts->schema_type == SDAP_SCHEMA_AD
                && !opts->allow_remote_domain_local_groups) {
        ret = sysdb_attrs_get_int32_t(group_attrs, SYSDB_GROUP_TYPE,
                                      &ad_group_type);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_int32_t failed.\n");
            return ret;
        }

        DEBUG(SSSDBG_TRACE_ALL,
              "AD group [%s] has type flags %#x.\n",
              group_name, ad_group_type);

        /* Only security groups from AD are considered for POSIX groups.
         * Additionally only global and universal group are taken to account
         * for trusted domains. */
        if (!(ad_group_type & SDAP_AD_GROUP_TYPE_SECURITY)
            || (IS_SUBDOMAIN(dom)
                && (!((ad_group_type & SDAP_AD_GROUP_TYPE_GLOBAL)
                      || (ad_group_type & SDAP_AD_GROUP_TYPE_UNIVERSAL))))) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Filtering AD group [%s].\n", group_name);

            *_need_filter = true;
        }
    }

    return ret;
}
