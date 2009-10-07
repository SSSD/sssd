/*
    ELAPI

    Header file for the ELAPI handling of network interfaces.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

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

#ifndef ELAPI_IOCTL_H
#define ELAPI_IOCTL_H

#include "config.h"

#ifndef HAVE_GETIFADDRS

#include "elapi_defines.h"
#include <net/if.h>

/* Function prototypes */
int elapi_get_addrlist(struct ifconf *ifc);
struct ifreq *elapi_get_next_addr(struct ifconf *ifc, struct ifreq *current);

#define INTERFACE_NUM_GUESS 3
#define INTERFACE_NUM_INC 1

#endif /* HAVE_GETIFADDRS */

#endif
