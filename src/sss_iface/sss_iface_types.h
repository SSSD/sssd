/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef _SSS_IFACE_CUSTOM_TYPES_H_
#define _SSS_IFACE_CUSTOM_TYPES_H_

#include <talloc.h>
#include <dbus/dbus.h>

#include "util/sss_pam_data.h"

errno_t sbus_iterator_read_pam_data(TALLOC_CTX *mem_ctx,
                                    DBusMessageIter *iterator,
                                    struct pam_data **_pd);

errno_t sbus_iterator_write_pam_data(DBusMessageIter *iterator,
                                     struct pam_data *pd);

errno_t sbus_iterator_read_pam_response(TALLOC_CTX *mem_ctx,
                                        DBusMessageIter *iterator,
                                        struct pam_data **_pd);

errno_t sbus_iterator_write_pam_response(DBusMessageIter *iterator,
                                         struct pam_data *pd);

#endif /* _SSS_IFACE_CUSTOM_TYPES_H_ */
