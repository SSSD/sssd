/*
    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2022 Red Hat

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

#ifndef _SYSDB_PASSKEY_USER_VERIFICATION_H_
#define _SYSDB_PASSKEY_USER_VERIFICATION_H_

#include "db/sysdb.h"

/* Retrieve passkey user verification value from sysdb */
errno_t sysdb_get_passkey_user_verification(TALLOC_CTX *mem_ctx,
                                            struct sysdb_ctx *sysdb,
                                            struct ldb_dn *dn,
                                            const char **_user_verification);

/* Replace passkey user verification value in sysdb with
 * user_verification argument value */
errno_t sysdb_update_passkey_user_verification(struct sysdb_ctx *sysdb,
                                               struct ldb_dn *dn,
                                               const char *user_verification);

/* For a given domain, retrieve passkey user verification value from sysdb */
errno_t sysdb_domain_get_passkey_user_verification(TALLOC_CTX *mem_ctx,
                                                   struct sysdb_ctx *sysdb,
                                                   const char *domain_name,
                                                   const char **_user_verification);

/* For a given domain, replace passkey user verification value from sysdb
 * with user_verification argument value */
errno_t sysdb_domain_update_passkey_user_verification(struct sysdb_ctx *sysdb,
                                                      const char *domain_name,
                                                      const char *user_verification);
#endif /* _SYSDB_PASSKEY_USER_VERIFICATION_H_ */
