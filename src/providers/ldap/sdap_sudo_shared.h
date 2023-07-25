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

#ifndef _SDAP_SUDO_SHARED_H_
#define _SDAP_SUDO_SHARED_H_

#include "providers/backend.h"
#include "providers/be_ptask.h"

errno_t
sdap_sudo_ptask_setup_generic(struct be_ctx *be_ctx,
                              struct dp_option *opts,
                              be_ptask_send_t full_send_fn,
                              be_ptask_recv_t full_recv_fn,
                              be_ptask_send_t smart_send_fn,
                              be_ptask_recv_t smart_recv_fn,
                              void *pvt,
                              struct be_ptask **_full_refresh,
                              struct be_ptask **_smart_refresh);

void
sdap_sudo_set_usn(struct sdap_server_opts *srv_opts,
                  const char *usn);

#endif /* _SDAP_SUDO_SHARED_H_ */
