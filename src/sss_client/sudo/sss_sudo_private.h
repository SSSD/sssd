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

#ifndef SSS_SUDO_PRIVATE_H_
#define SSS_SUDO_PRIVATE_H_

#include <stdint.h>
#include "sss_client/sudo/sss_sudo.h"

int sss_sudo_parse_response(const char *message,
                            size_t message_len,
                            char **_domainname,
                            struct sss_sudo_result **_result,
                            uint32_t *_error);

#endif /* SSS_SUDO_PRIVATE_H_ */
