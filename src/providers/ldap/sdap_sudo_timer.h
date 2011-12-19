/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#ifndef _SDAP_SUDO_TIMER_H_
#define _SDAP_SUDO_TIMER_H_

#include <time.h>

#include "providers/dp_backend.h"
#include "providers/ldap/ldap_common.h"

struct sdap_sudo_refresh_ctx;

int sdap_sudo_refresh_set_timer(struct sdap_sudo_refresh_ctx *ctx,
                                struct timeval tv);

struct sdap_sudo_refresh_ctx *
sdap_sudo_refresh_ctx_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           struct sdap_id_ctx *id_ctx,
                           struct sdap_options *opts,
                           struct timeval last_refresh);

#endif /* _SDAP_SUDO_TIMER_H_ */
