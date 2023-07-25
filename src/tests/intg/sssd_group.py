#
# Module for simulation of utility "getent group -s sss" from coreutils
#
# Copyright (c) 2016 Red Hat, Inc.
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
#

from ctypes import (c_int, c_char_p, c_ulong, POINTER, Structure,
                    create_string_buffer)
from sssd_nss import NssReturnCode, SssdNssError, nss_sss_ctypes_loader

GROUP_BUFLEN = 1024


class Group(Structure):
    _fields_ = [("gr_name", c_char_p),
                ("gr_passwd", c_char_p),
                ("gr_gid", c_int),
                ("gr_mem", POINTER(c_char_p))]


def getgrnam_r(name, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getgrnam_r(const char *name,
                                            struct group *result,
                                            char *buffer,
                                            size_t buflen,
                                            int *errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getgrnam_r")
    func.restype = c_int
    func.argtypes = [c_char_p, POINTER(Group),
                     c_char_p, c_ulong, POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))

    name = name.encode('utf-8')
    res = func(c_char_p(name), result_p, buffer_p, buflen, errno)

    return (int(res), int(errno[0]), result_p)


def getgrgid_r(gid, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getgrgid_r(gid_t gid,
                                            struct passwd *result,
                                            char *buffer,
                                            size_t buflen,
                                            int *errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getgrgid_r")
    func.restype = c_int
    func.argtypes = [c_ulong, POINTER(Group),
                     c_char_p, c_ulong, POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))

    res = func(gid, result_p, buffer_p, buflen, errno)

    return (int(res), int(errno[0]), result_p)


def set_group_dict(res, result_p):
    if res != NssReturnCode.SUCCESS:
        return dict()

    group_dict = dict()
    group_dict['name'] = result_p[0].gr_name.decode('utf-8')
    group_dict['gid'] = result_p[0].gr_gid
    group_dict['mem'] = list()

    i = 0
    while result_p[0].gr_mem[i] is not None:
        grp_name = result_p[0].gr_mem[i].decode('utf-8')
        group_dict['mem'].append(grp_name)
        i = i + 1

    return group_dict


def call_sssd_getgrnam(name):
    """
    A Python wrapper to retrieve a group by name. Returns:
        (res, group_dict)
    if res is NssReturnCode.SUCCESS, then group_dict contains the keys
    corresponding to the C passwd structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Group()
    result_p = POINTER(Group)(result)
    buff = create_string_buffer(GROUP_BUFLEN)

    res, errno, result_p = getgrnam_r(name, result_p, buff, GROUP_BUFLEN)
    if errno != 0:
        raise SssdNssError(errno, "getgrnam_r")

    group_dict = set_group_dict(res, result_p)
    return res, group_dict


def call_sssd_getgrgid(gid):
    """
    A Python wrapper to retrieve a group by GID. Returns:
        (res, group_dict)
    if res is NssReturnCode.SUCCESS, then group_dict contains the keys
    corresponding to the C passwd structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Group()
    result_p = POINTER(Group)(result)
    buff = create_string_buffer(GROUP_BUFLEN)

    res, errno, result_p = getgrgid_r(gid, result_p, buff, GROUP_BUFLEN)
    if errno != 0:
        raise SssdNssError(errno, "getgrgid_r")

    group_dict = set_group_dict(res, result_p)
    return res, group_dict
