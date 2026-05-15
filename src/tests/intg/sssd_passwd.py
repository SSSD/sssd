#
# Module for simulation of utility "getent passwd -s sss" from coreutils
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

from ctypes import (c_int, c_char_p, c_ulong, POINTER,
                    Structure, create_string_buffer, get_errno)
from sssd_nss import NssReturnCode, SssdNssError, nss_sss_ctypes_loader

PASSWD_BUFLEN = 1024


class Passwd(Structure):
    _fields_ = [("pw_name", c_char_p),
                ("pw_passwd", c_char_p),
                ("pw_uid", c_int),
                ("pw_gid", c_int),
                ("pw_gecos", c_char_p),
                ("pw_dir", c_char_p),
                ("pw_shell", c_char_p)]


def set_user_dict(res, result_p):
    if res != NssReturnCode.SUCCESS:
        return dict()

    user_dict = dict()
    user_dict['name'] = result_p[0].pw_name.decode('utf-8')
    user_dict['passwd'] = result_p[0].pw_passwd.decode('utf-8')
    user_dict['uid'] = result_p[0].pw_uid
    user_dict['gid'] = result_p[0].pw_gid
    user_dict['gecos'] = result_p[0].pw_gecos.decode('utf-8')
    user_dict['dir'] = result_p[0].pw_dir.decode('utf-8')
    user_dict['shell'] = result_p[0].pw_shell.decode('utf-8')
    return user_dict


def getpwnam_r(name, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getpwnam_r(const char *name,
                                            struct passwd *result,
                                            char *buffer,
                                            size_t buflen,
                                            int *errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getpwnam_r")
    func.restype = c_int
    func.argtypes = [c_char_p, POINTER(Passwd),
                     c_char_p, c_ulong, POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))

    name = name.encode('utf-8')
    res = func(c_char_p(name), result_p, buffer_p, buflen, errno)

    return (int(res), int(errno[0]), result_p)


def getpwuid_r(uid, result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getpwuid_r(uid_t uid,
                                            struct passwd *result,
                                            char *buffer,
                                            size_t buflen,
                                            int *errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getpwuid_r")
    func.restype = c_int
    func.argtypes = [c_ulong, POINTER(Passwd),
                     c_char_p, c_ulong, POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))

    res = func(uid, result_p, buffer_p, buflen, errno)

    return (int(res), int(errno[0]), result_p)


def setpwent():
    """
    ctypes wrapper for:
        void setpwent(void)
    """
    func = nss_sss_ctypes_loader("_nss_sss_setpwent")
    func.argtypes = []

    res = func()
    assert res == NssReturnCode.SUCCESS

    errno = get_errno()
    if errno != 0:
        raise SssdNssError(errno, "setpwent")


def endpwent():
    """
    ctypes wrapper for:
        void endpwent(void)
    """
    func = nss_sss_ctypes_loader("_nss_sss_endpwent")
    func.argtypes = []

    res = func()
    assert res == NssReturnCode.SUCCESS

    errno = get_errno()
    if errno != 0:
        raise SssdNssError(errno, "endpwent")


def getpwent_r(result_p, buffer_p, buflen):
    """
    ctypes wrapper for:
        enum nss_status _nss_sss_getpwent_r(struct passwd *result,
                                            char *buffer, size_t buflen,
                                            int *errnop)
    """
    func = nss_sss_ctypes_loader("_nss_sss_getpwent_r")
    func.restype = c_int
    func.argtypes = [POINTER(Passwd), c_char_p, c_ulong, POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))

    res = func(result_p, buffer_p, buflen, errno)
    return (int(res), int(errno[0]), result_p)


def getpwent():
    result = Passwd()
    result_p = POINTER(Passwd)(result)
    buff = create_string_buffer(PASSWD_BUFLEN)

    res, errno, result_p = getpwent_r(result_p, buff, PASSWD_BUFLEN)
    if errno != 0:
        raise SssdNssError(errno, "getpwent_r")

    user_dict = set_user_dict(res, result_p)
    return res, user_dict


def call_sssd_getpwnam(name):
    """
    A Python wrapper to retrieve a user by name. Returns:
        (res, user_dict)
    if res is NssReturnCode.SUCCESS, then user_dict contains the keys
    corresponding to the C passwd structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Passwd()
    result_p = POINTER(Passwd)(result)
    buff = create_string_buffer(PASSWD_BUFLEN)

    res, errno, result_p = getpwnam_r(name, result_p, buff, PASSWD_BUFLEN)
    if errno != 0:
        raise SssdNssError(errno, "getpwnam_r")

    user_dict = set_user_dict(res, result_p)
    return res, user_dict


def call_sssd_getpwuid(uid):
    """
    A Python wrapper to retrieve a user by UID. Returns:
        (res, user_dict)
    if res is NssReturnCode.SUCCESS, then user_dict contains the keys
    corresponding to the C passwd structure fields. Otherwise, the dictionary
    is empty and errno indicates the error code
    """
    result = Passwd()
    result_p = POINTER(Passwd)(result)
    buff = create_string_buffer(PASSWD_BUFLEN)

    res, errno, result_p = getpwuid_r(uid, result_p, buff, PASSWD_BUFLEN)
    if errno != 0:
        raise SssdNssError(errno, "getpwuid_r")

    user_dict = set_user_dict(res, result_p)
    return res, user_dict


def call_sssd_enumeration():
    """
    enumerate users from sssd module only
    """
    setpwent()
    user_list = []

    res, user = getpwent()
    while res == NssReturnCode.SUCCESS:
        user_list.append(user)
        res, user = getpwent()

    endpwent()
    return user_list
