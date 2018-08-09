/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2018 Red Hat

    Helper to make dlopen-tests pass for libsss_nss_idmap_tests.so.

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

#include <stdint.h>
#include <unistd.h>
#include <nss.h>

#include "sss_client/sss_cli.h"

enum nss_status __wrap_sss_nss_make_request_timeout(enum sss_cli_command cmd,
                                                    struct sss_cli_req_data *rd,
                                                    int timeout,
                                                    uint8_t **repbuf,
                                                    size_t *replen,
                                                    int *errnop)
{
    return NSS_STATUS_SUCCESS;
}
