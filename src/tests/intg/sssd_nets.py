#
# Module for simulation of utility "getent networks -s sss" from coreutils
#
#   Authors:
#       Samuel Cabrero <scabrero@suse.com>
#
#   Copyright (C) 2020 SUSE LINUX GmbH, Nuernberg, Germany.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ctypes import (c_int, c_char_p, c_ulong, c_uint32, POINTER,
                    Structure, create_string_buffer)
from sssd_nss import NssReturnCode, SssdNssError, nss_sss_ctypes_loader
import socket
from ipaddress import IPv4Address
from struct import unpack

IP_NETWORK_BUFLEN = 1024


class Netent(Structure):
    _fields_ = [("n_name", c_char_p),
                ("n_aliases", POINTER(c_char_p)),
                ("n_addrtype", c_int),
                ("n_net", c_uint32)]


def getnetbyname_r(name, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getnetbyname_r(const char *name,
                                                struct netent *result,
                                                char *buffer, size_t buflen,
                                                int *errnop, int *h_errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getnetbyname_r")
    func.restype = c_int
    func.argtypes = [c_char_p, POINTER(Netent),
                     c_char_p, c_ulong, POINTER(c_int), POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))
    h_errno = POINTER(c_int)(c_int(0))

    name = name.encode('utf-8')
    res = func(c_char_p(name), result_p, buffer_p, buflen, errno, h_errno)

    return (int(res), int(errno[0]), int(h_errno[0]), result_p)


def getnetbyaddr_r(addr, af, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getnetbyaddr_r(uint32_t addr, int type,
                                                struct netent *result,
                                                char *buffer, size_t buflen,
                                                int *errnop, int *h_errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getnetbyaddr_r")
    func.restype = c_int
    func.argtypes = [c_uint32, c_int, POINTER(Netent),
                     c_char_p, c_ulong, POINTER(c_int), POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))
    h_errno = POINTER(c_int)(c_int(0))

    res = func(addr, af, result_p, buffer_p, buflen, errno, h_errno)

    return (int(res), int(errno[0]), int(h_errno[0]), result_p)


def set_netent_dict(res, result_p):
    if res != NssReturnCode.SUCCESS:
        return dict()

    netent_dict = dict()
    netent_dict['name'] = result_p[0].n_name.decode('utf-8')
    netent_dict['aliases'] = list()
    netent_dict['addrtype'] = result_p[0].n_addrtype
    netent_dict['address'] = result_p[0].n_net

    i = 0
    while result_p[0].n_aliases[i] is not None:
        alias = result_p[0].n_aliases[i].decode('utf-8')
        netent_dict['aliases'].append(alias)
        i = i + 1

    return netent_dict


def call_sssd_getnetbyname(name):
    """
    A Python wrapper to retrieve an IP network by name. Returns:
        (res, netent_dict)
    if res is NssReturnCode.SUCCESS, then netent_dict contains the keys
    corresponding to the C netent structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Netent()
    result_p = POINTER(Netent)(result)
    buff = create_string_buffer(IP_NETWORK_BUFLEN)

    (res, errno, h_errno, result_p) = getnetbyname_r(name, result_p,
                                                     buff, IP_NETWORK_BUFLEN)
    if errno != 0:
        raise SssdNssError(errno, "getnetbyname_r")

    netent_dict = set_netent_dict(res, result_p)
    return (res, h_errno, netent_dict)


def call_sssd_getnetbyaddr(addrstr, af):
    """
    A Python wrapper to retrieve an IP network by address. Returns:
        (res, netent_dict)
    if res is NssReturnCode.SUCCESS, then netent_dict contains the keys
    corresponding to the C netent structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Netent()
    result_p = POINTER(Netent)(result)
    buff = create_string_buffer(IP_NETWORK_BUFLEN)

    if isinstance(addrstr, bytes):
        addrstr = addrstr.decode('utf-8')
    addr = IPv4Address(addrstr)
    binaddr = unpack('<I', addr.packed)[0]
    binaddr = socket.ntohl(binaddr)

    (res, errno, h_errno, result_p) = getnetbyaddr_r(binaddr, af,
                                                     result_p, buff,
                                                     IP_NETWORK_BUFLEN)
    if errno != 0:
        raise SssdNssError(errno, "getnetbyaddr_r")

    netent_dict = set_netent_dict(res, result_p)
    return (res, h_errno, netent_dict)
