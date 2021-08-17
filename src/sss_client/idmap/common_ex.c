/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

    SSSD's enhanced NSS API

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

#include <time.h>
#include <errno.h>

#include "sss_cli.h"
#include "common_private.h"

int sss_nss_timedlock(unsigned int timeout_ms, int *time_left_ms)
{
    if (time_left_ms != NULL) {
        *time_left_ms = (int)timeout_ms;
    }

    return 0;
}
