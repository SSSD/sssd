#
# Module for simulation of utility "getent hosts -s sss" from coreutils
#
#   Authors:
#       Samuel Cabrero <scabrero@suse.com>
#
#   Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.
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

from ctypes import (c_int, c_char_p, c_ulong, POINTER,
                    Structure, create_string_buffer)
from sssd_nss import NssReturnCode, SssdNssError, nss_sss_ctypes_loader
import socket
from ipaddress import IPv4Address, IPv6Address

HOST_BUFLEN = 1024


class Hostent(Structure):
    _fields_ = [("h_name", c_char_p),
                ("h_aliases", POINTER(c_char_p)),
                ("h_addrtype", c_int),
                ("h_length", c_int),
                ("h_addr_list", POINTER(c_char_p))]


def gethostbyname_r(name, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_gethostbyname_r(const char *name,
                                                 struct hostent *result,
                                                 char *buffer,
                                                 size_t buflen,
                                                 int *errnop,
                                                 int *h_errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_gethostbyname_r")
    func.restype = c_int
    func.argtypes = [c_char_p, POINTER(Hostent),
                     c_char_p, c_ulong, POINTER(c_int), POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))
    h_errno = POINTER(c_int)(c_int(0))

    name = name.encode('utf-8')
    res = func(c_char_p(name), result_p, buffer_p, buflen, errno, h_errno)

    return (int(res), int(errno[0]), int(h_errno[0]), result_p)


def gethostbyname2_r(name, af, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_gethostbyname2_r(const char *name,
                                                  int af,
                                                  struct hostent *result,
                                                  char *buffer,
                                                  size_t buflen,
                                                  int *errnop,
                                                  int *h_errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_gethostbyname2_r")
    func.restype = c_int
    func.argtypes = [c_char_p, c_int, POINTER(Hostent),
                     c_char_p, c_ulong, POINTER(c_int), POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))
    h_errno = POINTER(c_int)(c_int(0))

    name = name.encode('utf-8')
    res = func(c_char_p(name), af, result_p, buffer_p, buflen, errno, h_errno)

    return (int(res), int(errno[0]), int(h_errno[0]), result_p)


def set_hostent_dict(res, result_p):
    if res != NssReturnCode.SUCCESS:
        return dict()

    hostent_dict = dict()
    hostent_dict['name'] = result_p[0].h_name.decode('utf-8')
    hostent_dict['aliases'] = list()
    hostent_dict['addrtype'] = result_p[0].h_addrtype
    hostent_dict['length'] = result_p[0].h_length
    hostent_dict['addresses'] = list()

    i = 0
    while result_p[0].h_aliases[i] is not None:
        alias = result_p[0].h_aliases[i].decode('utf-8')
        hostent_dict['aliases'].append(alias)
        i = i + 1

    i = 0
    while result_p[0].h_addr_list[i] is not None:
        length = result_p[0].h_length
        binaddr = result_p[0].h_addr_list[i][:length]
        if result_p[0].h_addrtype == socket.AF_INET:
            addr = IPv4Address(binaddr)
            addr = socket.inet_ntop(socket.AF_INET, addr.packed)
        elif result_p[0].h_addrtype == socket.AF_INET6:
            addr = IPv6Address(binaddr)
            addr = socket.inet_ntop(socket.AF_INET, addr.packed)
        else:
            raise Exception("Failed to parse IP address")

        hostent_dict['addresses'].append(addr)
        i = i + 1

    return hostent_dict


def call_sssd_gethostbyname(name):
    """
    A Python wrapper to retrieve a host by name. Returns:
        (res, hostent_dict)
    if res is NssReturnCode.SUCCESS, then hostent_dict contains the keys
    corresponding to the C hostent structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Hostent()
    result_p = POINTER(Hostent)(result)
    buff = create_string_buffer(HOST_BUFLEN)

    (res, errno, h_errno, result_p) = gethostbyname_r(name, result_p,
                                                      buff, HOST_BUFLEN)
    if errno != 0:
        raise SssdNssError(errno, "gethostbyname_r")

    hostent_dict = set_hostent_dict(res, result_p)
    return (res, h_errno, hostent_dict)
