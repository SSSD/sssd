#
# Module for simulation of utility "getent services -s sss" from coreutils
#
#   Authors:
#       Samuel Cabrero <scabrero@suse.com>
#
#   Copyright (C) 2025 SUSE LINUX GmbH, Nuernberg, Germany.
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

from ctypes import (
    c_int,
    c_char_p,
    c_ulong,
    POINTER,
    Structure,
    create_string_buffer,
)
from sssd_nss import NssReturnCode, SssdNssError, nss_sss_ctypes_loader
import socket

SERVICE_BUFLEN = 1024


# struct servent from netdb.h
class Servent(Structure):
    _fields_ = [
        ("s_name", c_char_p),
        ("s_aliases", POINTER(c_char_p)),
        ("s_port", c_int),
        ("s_proto", c_char_p),
    ]


def getservbyname_r(name, proto, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getservbyname_r(const char *name,
                                                 const char *protocol,
                                                 struct servent *result,
                                                 char *buffer, size_t buflen,
                                                 int *errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getservbyname_r")
    func.restype = c_int
    func.argtypes = [
        c_char_p,
        c_char_p,
        POINTER(Servent),
        c_char_p,
        c_ulong,
        POINTER(c_int),
    ]

    errno = POINTER(c_int)(c_int(0))

    name = name.encode("utf-8")
    proto = proto.encode("utf-8")
    res = func(c_char_p(name), c_char_p(proto), result_p, buffer_p, buflen, errno)

    return (int(res), int(errno[0]), result_p)


def getservbyport_r(port, proto, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getservbyport_r(int port, const char *protocol,
                                                 struct servent *result,
                                                 char *buffer, size_t buflen,
                                                 int *errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getservbyport_r")
    func.restype = c_int
    func.argtypes = [
        c_int,
        c_char_p,
        POINTER(Servent),
        c_char_p,
        c_ulong,
        POINTER(c_int),
    ]

    errno = POINTER(c_int)(c_int(0))

    port = socket.htons(port)
    proto = proto.encode("utf-8")
    res = func(port, c_char_p(proto), result_p, buffer_p, buflen, errno)

    return (int(res), int(errno[0]), result_p)


def set_servent_dict(res, result_p):
    if res != NssReturnCode.SUCCESS:
        return dict()

    servent_dict = dict()
    servent_dict["name"] = result_p[0].s_name.decode("utf-8")
    servent_dict["aliases"] = list()
    servent_dict["port"] = result_p[0].s_port
    servent_dict["proto"] = result_p[0].s_proto

    i = 0
    while result_p[0].s_aliases[i] is not None:
        alias = result_p[0].s_aliases[i].decode("utf-8")
        servent_dict["aliases"].append(alias)
        i = i + 1

    return servent_dict


def call_sssd_getservbyname(name, proto):
    """
    A Python wrapper to retrieve a service by name and protocol. Returns:
        (res, servent_dict)
    if res is NssReturnCode.SUCCESS, then servent_dict contains the keys
    corresponding to the C servent structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Servent()
    result_p = POINTER(Servent)(result)
    buff = create_string_buffer(SERVICE_BUFLEN)

    (res, errno, result_p) = getservbyname_r(
        name, proto, result_p, buff, SERVICE_BUFLEN
    )
    if errno != 0:
        raise SssdNssError(errno, "getservbyname_r")

    servent_dict = set_servent_dict(res, result_p)
    return (res, servent_dict)


def call_sssd_getservbyport(port, proto):
    """
    A Python wrapper to retrieve a service by port and protocol. Returns:
        (res, servent_dict)
    if res is NssReturnCode.SUCCESS, then servent_dict contains the keys
    corresponding to the C servent structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Servent()
    result_p = POINTER(Servent)(result)
    buff = create_string_buffer(SERVICE_BUFLEN)

    (res, errno, result_p) = getservbyport_r(
        port, proto, result_p, buff, SERVICE_BUFLEN
    )
    if errno != 0:
        raise SssdNssError(errno, "getservbyport_r")

    servent_dict = set_servent_dict(res, result_p)
    return (res, servent_dict)
