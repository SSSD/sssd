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

int sss_ldap_control_create(const char *oid, int iscritical,
                            struct berval *value, int dupval,
                            LDAPControl **ctrlp);

inline const char *
sss_ldap_escape_ip_address(TALLOC_CTX *mem_ctx, int family, const char *addr);

struct tevent_req *sss_ldap_init_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      const char *uri,
                                      struct sockaddr_storage *addr,
                                      int addr_len);

int sss_ldap_init_recv(struct tevent_req *req, LDAP **ldap, int *sd);
#endif /* __SSS_LDAP_H__ */
