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

#include "providers/data_provider_req.h"

#define be_req_to_str(be_req_t) #be_req_t

const char *be_req2str(dbus_uint32_t req_type)
{
    switch (req_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER:
        return be_req_to_str(BE_REQ_USER);
    case BE_REQ_GROUP:
        return be_req_to_str(BE_REQ_GROUP);
    case BE_REQ_INITGROUPS:
        return be_req_to_str(BE_REQ_INITGROUPS);
    case BE_REQ_NETGROUP:
        return be_req_to_str(BE_REQ_NETGROUP);
    case BE_REQ_SERVICES:
        return be_req_to_str(BE_REQ_SERVICES);
    case BE_REQ_SUDO_FULL:
        return be_req_to_str(BE_REQ_SUDO_FULL);
    case BE_REQ_SUDO_RULES:
        return be_req_to_str(BE_REQ_SUDO_RULES);
    case BE_REQ_HOST:
        return be_req_to_str(BE_REQ_HOST);
    case BE_REQ_IP_NETWORK:
        return be_req_to_str(BE_REQ_IP_NETWORK);
    case BE_REQ_SUBID_RANGES:
        return be_req_to_str(BE_REQ_SUBID_RANGES);
    case BE_REQ_BY_SECID:
        return be_req_to_str(BE_REQ_BY_SECID);
    case BE_REQ_USER_AND_GROUP:
        return be_req_to_str(BE_REQ_USER_AND_GROUP);
    case BE_REQ_BY_UUID:
        return be_req_to_str(BE_REQ_BY_UUID);
    case BE_REQ_BY_CERT:
        return be_req_to_str(BE_REQ_BY_CERT);
    }
    return "UNKNOWN_REQ";
}
