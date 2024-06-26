/*
    SSSD

    Copyright (C) Pavel Reichl <preichl@redhat.com> 2015

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

#ifndef _LDAP_AUTH_H_
#define _LDAP_AUTH_H_

#include "config.h"

#include "providers/ldap/sdap_access.h"

enum pwexpire {
    PWEXPIRE_NONE = 0,
    PWEXPIRE_LDAP_PASSWORD_POLICY,
    PWEXPIRE_KERBEROS,
    PWEXPIRE_SHADOW
};

int get_user_dn(TALLOC_CTX *memctx,
                struct sss_domain_info *domain,
                enum sdap_access_type access_type,
                struct sdap_options *opts,
                const char *username,
                char **user_dn,
                enum pwexpire *user_pw_expire_type,
                void **user_pw_expire_data);

errno_t check_pwexpire_policy(enum pwexpire pw_expire_type,
                              void *pw_expire_data,
                              struct pam_data *pd,
                              int pwd_expiration_warning,
                              struct sdap_options *opts);


#endif /* _LDAP_AUTH_H_ */
