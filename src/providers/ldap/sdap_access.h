/*
    SSSD

    sdap_access.h

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#ifndef SDAP_ACCESS_H_
#define SDAP_ACCESS_H_

#include "providers/dp_backend.h"

#define SYSDB_LDAP_ACCESS "ldap_access_allow"

struct sdap_access_ctx {
    struct sdap_id_ctx *id_ctx;
    const char *filter;
};

void ldap_pam_access_handler(struct be_req *breq);

#endif /* SDAP_ACCESS_H_ */
