/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#ifndef __SSS_LDAP_H__
#define __SSS_LDAP_H__

#include <ldap.h>
#include <talloc.h>

#ifdef LDAP_OPT_DIAGNOSTIC_MESSAGE
#define SDAP_DIAGNOSTIC_MESSAGE LDAP_OPT_DIAGNOSTIC_MESSAGE
#else
#ifdef LDAP_OPT_ERROR_STRING
#define SDAP_DIAGNOSTIC_MESSAGE LDAP_OPT_ERROR_STRING
#else
#error No extended diagnostic message available
#endif
#endif

int sss_ldap_get_diagnostic_msg(TALLOC_CTX *mem_ctx,
                                LDAP *ld,
                                char **_errmsg);

#ifndef LDAP_SERVER_ASQ_OID
#define LDAP_SERVER_ASQ_OID "1.2.840.113556.1.4.1504"
#endif /* LDAP_SERVER_ASQ_OID */

int sss_ldap_control_create(const char *oid, int iscritical,
                            struct berval *value, int dupval,
                            LDAPControl **ctrlp);

inline const char *
sss_ldap_escape_ip_address(TALLOC_CTX *mem_ctx, int family, const char *addr);

#endif /* __SSS_LDAP_H__ */
