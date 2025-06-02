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

#include <sys/types.h>
#include <sys/socket.h>
#include <ldap.h>
#include <talloc.h>
#include <tevent.h>

#ifndef LDAP_CONTROL_PWEXPIRED
#define LDAP_CONTROL_PWEXPIRED "2.16.840.1.113730.3.4.4"
#endif

#ifndef LDAP_CONTROL_PWEXPIRING
#define LDAP_CONTROL_PWEXPIRING "2.16.840.1.113730.3.4.5"
#endif

#ifdef LDAP_OPT_DIAGNOSTIC_MESSAGE
#define SDAP_DIAGNOSTIC_MESSAGE LDAP_OPT_DIAGNOSTIC_MESSAGE
#else
#ifdef LDAP_OPT_ERROR_STRING
#define SDAP_DIAGNOSTIC_MESSAGE LDAP_OPT_ERROR_STRING
#else
#error No extended diagnostic message available
#endif
#endif

const char* sss_ldap_err2string(int err);

void sss_ldap_error_debug(int level, const char *msg, LDAP *ld, int error_code);

#ifndef LDAP_SERVER_ASQ_OID
#define LDAP_SERVER_ASQ_OID "1.2.840.113556.1.4.1504"
#endif /* LDAP_SERVER_ASQ_OID */

#ifndef LDAP_SERVER_SD_OID
#define LDAP_SERVER_SD_OID "1.2.840.113556.1.4.801"
#endif /* LDAP_SERVER_SD_OID */


/*
 * The following four flags specify which security descriptor parts to retrieve
 * during sd_search (see  http://msdn.microsoft.com/en-us/library/aa366987.aspx)
 */
#define SECINFO_OWNER ( 0x00000001 )
#define SECINFO_GROUP ( 0x00000002 )
#define SECINFO_DACL ( 0x00000004 )
#define SECINFO_SACL ( 0x00000008 )

int sss_ldap_control_create(const char *oid, int iscritical,
                            struct berval *value, int dupval,
                            LDAPControl **ctrlp);

struct tevent_req *sss_ldap_init_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      const char *uri,
                                      struct sockaddr *addr,
                                      int addr_len, int timeout);

int sss_ldap_init_recv(struct tevent_req *req, LDAP **ldap, int *sd);

struct sdap_options;
struct sdap_search_base;
bool sss_ldap_dn_in_search_bases(TALLOC_CTX *mem_ctx,
                                 const char *dn,
                                 struct sdap_search_base **search_bases,
                                 char **_filter);

bool sss_ldap_dn_in_search_bases_len(TALLOC_CTX *mem_ctx,
                                     const char *dn,
                                     struct sdap_search_base **search_bases,
                                     char **_filter,
                                     int *_match_len);

char *sss_ldap_encode_ndr_uint32(TALLOC_CTX *mem_ctx, uint32_t flags);

#endif /* __SSS_LDAP_H__ */
