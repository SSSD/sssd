/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#ifndef COMMON_MOCK_SDAP_H_
#define COMMON_MOCK_SDAP_H_

#include <talloc.h>

#include "util/util.h"
#include "providers/ldap/sdap.h"

struct sdap_options *mock_sdap_options_ldap(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            struct confdb_ctx *confdb_ctx,
                                            const char *conf_path);

struct sdap_id_ctx *mock_sdap_id_ctx(TALLOC_CTX *mem_ctx,
                                     struct be_ctx *be_ctx,
                                     struct sdap_options *sdap_opts);

struct sdap_handle *mock_sdap_handle(TALLOC_CTX *mem_ctx);

#endif /* COMMON_MOCK_SDAP_H_ */
