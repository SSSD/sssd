/*
    SSSD

    LDAP tevent_req wrappers

    Authors:
        Martin Nagy <mnagy@redhat.com>

    Copyright (C) 2010 Red Hat

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

#ifndef _LDAP_REQ_WRAP_H_
#define _LDAP_REQ_WRAP_H_

#include <talloc.h>
#include <tevent.h>

#include "providers/ldap/sdap.h"

struct tevent_req *ldap_sasl_bind_send(void *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sdap_handle *sh,
                                       const char *dn,
                                       const char *mechanism,
                                       struct berval *cred,
                                       LDAPControl **sctrls,
                                       LDAPControl **cctrls);

int ldap_sasl_bind_recv(struct tevent_req *req,
                        int *ret,
                        int *msgidp);


struct tevent_req *ldap_search_ext_send(void *mem_ctx,
                                        struct tevent_context *ev,
                                        struct sdap_handle *sh,
                                        const char *base,
                                        int scope,
                                        const char *filter,
                                        const char **attrs,
                                        int attrsonly,
                                        LDAPControl **sctrls,
                                        LDAPControl **cctrls,
                                        const struct timeval *timeout,
                                        int sizelimit);

int ldap_search_ext_recv(struct tevent_req *req,
                         int *retp,
                         int *msgidp);


struct tevent_req *ldap_extended_operation_send(void *mem_ctx,
                                                struct tevent_context *ev,
                                                struct sdap_handle *sh,
                                                const char *requestoid,
                                                struct berval *requestdata,
                                                LDAPControl **sctrls,
                                                LDAPControl **cctrls);

int ldap_extended_operation_recv(struct tevent_req *req,
                                 int *retp,
                                 int *msgidp);


struct tevent_req *ldap_start_tls_send(void *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sdap_handle *sh,
                                       LDAPControl **sctrls,
                                       LDAPControl **cctrls);

int ldap_start_tls_recv(struct tevent_req *req,
                        int *retp,
                        int *msgidp);


struct tevent_req *
ldap_sasl_interactive_bind_send(void *mem_ctx,
                                struct tevent_context *ev,
                                struct sdap_handle *sh,
                                const char *dn,
                                const char *mechanism,
                                LDAPControl **sctrls,
                                LDAPControl **cctrls,
                                unsigned flags,
                                LDAP_SASL_INTERACT_PROC *interact,
                                void *defaults);

int ldap_sasl_interactive_bind_recv(struct tevent_req *req);

#endif /* !_LDAP_REQ_WRAP_H_ */
