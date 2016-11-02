/*
    Copyright (C) 2016 Red Hat

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

#ifndef _RESPONDER_IFACE_H_
#define _RESPONDER_IFACE_H_

#include "responder/common/iface/responder_iface_generated.h"

#define RESPONDER_PATH "/org/freedesktop/sssd/responder"

struct sbus_iface_map *responder_get_sbus_interface(void);

/* org.freedesktop.sssd.Responder.Domain */

int sss_resp_domain_active(struct sbus_request *req,
                           void *data,
                           const char *domain_name);

int sss_resp_domain_inconsistent(struct sbus_request *req,
                                 void *data,
                                 const char *domain_name);

/* org.freedesktop.sssd.Responder.NegativeCache */

int sss_resp_reset_ncache_users(struct sbus_request *req, void *data);
int sss_resp_reset_ncache_groups(struct sbus_request *req, void *data);

#endif /* _RESPONDER_IFACE_H_ */
