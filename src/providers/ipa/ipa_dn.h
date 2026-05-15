/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#ifndef IPA_DN_H_
#define IPA_DN_H_

#include <talloc.h>
#include "db/sysdb.h"

errno_t _ipa_get_rdn(TALLOC_CTX *mem_ctx,
                      struct sysdb_ctx *sysdb,
                      const char *obj_dn,
                      char **_rdn_val,
                      const char *rdn_attr,
                      ...);

#define ipa_get_rdn(mem_ctx, sysdb, dn, _rdn_val, rdn_attr, ...) \
    _ipa_get_rdn(mem_ctx, sysdb, dn, _rdn_val, rdn_attr, ##__VA_ARGS__, NULL)

#define ipa_check_rdn(sysdb, dn, rdn_attr, ...) \
    _ipa_get_rdn(NULL, sysdb, dn, NULL, rdn_attr, ##__VA_ARGS__, NULL)

#define ipa_check_rdn_bool(sysdb, dn, rdn_attr, ...) \
    ((bool)(ipa_check_rdn(sysdb, dn, rdn_attr, ##__VA_ARGS__) == EOK))

#endif /* IPA_DN_H_ */
