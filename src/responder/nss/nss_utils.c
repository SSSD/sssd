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

const char *
nss_get_pwfield(struct nss_ctx *nctx,
               struct sss_domain_info *dom)
{
    if (dom->pwfield != NULL) {
        return dom->pwfield;
    }

    return nctx->pwfield;
}
