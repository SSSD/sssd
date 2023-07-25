/*
    SSSD

    Data Provider -- backend request

    Copyright (C) Petr Cech <pcech@redhat.com> 2015

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

#ifndef __DATA_PROVIDER_REQ__
#define __DATA_PROVIDER_REQ__

#include <dbus/dbus.h>

/* When changing these constants, also please change sssd_functions.stp
 */
#define BE_REQ_USER           0x0001
#define BE_REQ_GROUP          0x0002
#define BE_REQ_INITGROUPS     0x0003
#define BE_REQ_NETGROUP       0x0004
#define BE_REQ_SERVICES       0x0005
#define BE_REQ_SUDO_FULL      0x0006
#define BE_REQ_SUDO_RULES     0x0007
#define BE_REQ_HOST           0x0008
#define BE_REQ_IP_NETWORK     0x0009
#define BE_REQ_SUBID_RANGES   0x0010
#define BE_REQ_BY_SECID       0x0011
#define BE_REQ_USER_AND_GROUP 0x0012
#define BE_REQ_BY_UUID        0x0013
#define BE_REQ_BY_CERT        0x0014
#define BE_REQ__LAST          BE_REQ_BY_CERT /* must be equal to max REQ number */
#define BE_REQ_TYPE_MASK      0x00FF

/**
 * @brief Convert request type to string for logging purpose.
 *
 * @param[in] req_type Type of request.
 * @return Pointer to string with request type. There could be 'fast' flag.
 */
const char *be_req2str(dbus_uint32_t req_type);

#endif /* __DATA_PROVIDER_REQ__ */
