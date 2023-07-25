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
sss_nss_get_pwfield(struct sss_nss_ctx *nctx,
               struct sss_domain_info *dom)
{
    if (dom->pwfield != NULL) {
        return dom->pwfield;
    }

    return nctx->pwfield;
}
