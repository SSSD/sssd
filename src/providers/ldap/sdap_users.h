/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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

#ifndef _SDAP_USERS_H_
#define _SDAP_USERS_H_

#include "config.h"

/* shared non-async user functions */

errno_t sdap_fallback_local_user(TALLOC_CTX *memctx,
                                 const char *name, uid_t uid,
                                 struct sysdb_attrs ***reply);

int sdap_save_user(TALLOC_CTX *memctx,
                   struct sdap_options *opts,
                   struct sss_domain_info *dom,
                   struct sysdb_attrs *attrs,
                   struct sysdb_attrs *mapped_attrs,
                   char **_usn_value,
                   time_t now);

#endif /* _SDAP_USERS_H_ */
