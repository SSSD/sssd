/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef SDAP_IDMAP_H_
#define SDAP_IDMAP_H_

#include "src/providers/ldap/sdap.h"
#include "src/providers/ldap/ldap_common.h"

typedef errno_t (find_new_domain_fn_t)(struct sdap_idmap_ctx *idmap_ctx,
                                       const char *dom_name,
                                       const char *dom_sid_str);
struct sdap_idmap_ctx {
    struct sss_idmap_ctx *map;

    struct sdap_id_ctx *id_ctx;
    find_new_domain_fn_t *find_new_domain;
};

errno_t sdap_idmap_init(TALLOC_CTX *mem_ctx,
                        struct sdap_id_ctx *id_ctx,
                        struct sdap_idmap_ctx **_idmap_ctx);

errno_t
sdap_idmap_add_domain(struct sdap_idmap_ctx *idmap_ctx,
                      const char *dom_name,
                      const char *dom_sid,
                      id_t slice);

errno_t
sdap_idmap_get_dom_sid_from_object(TALLOC_CTX *mem_ctx,
                                   const char *object_sid,
                                   char **dom_sid_str);

errno_t
sdap_idmap_sid_to_unix(struct sdap_idmap_ctx *idmap_ctx,
                       const char *sid_str,
                       id_t *id);

bool sdap_idmap_domain_has_algorithmic_mapping(struct sdap_idmap_ctx *ctx,
                                               const char *name,
                                               const char *dom_sid);

#endif /* SDAP_IDMAP_H_ */
