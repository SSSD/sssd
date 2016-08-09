#
# Module for simulation of utility "getent netgroup -s sss" from coreutils
#
# Copyright (c) 2016 Red Hat, Inc.
# Author: Lukas Slebodnik <lslebodn@redhat.com>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
from ctypes import (cdll, c_int, c_char, c_char_p, c_size_t, c_void_p, c_ulong,
                    POINTER, Structure, Union, create_string_buffer, get_errno)
import config


class NetgroupType(object):
    """ 'enum' class for type of netgroup """
    TRIPLE_VAL = 0
    GROUP_VAL = 1


class Triple(Structure):
    _fields_ = [("host", c_char_p),
                ("user", c_char_p),
                ("domain", c_char_p)]


class Val(Union):
    _fields_ = [("triple", Triple),
                ("group", c_char_p)]


class Idx(Union):
    _fields_ = [("cursor", POINTER(c_char)),
                ("position", c_ulong)]


class NameList(Structure):
    pass

NameList._fields_ = [("next", POINTER(NameList)),
                     ("name", POINTER(c_char))]


class NssReturnCode(object):
    """ 'enum' class for name service switch return code """
    TRYAGAIN = -2,
    UNAVAIL = -1
    NOTFOUND = 0
    SUCCESS = 1
    RETURN = 2


class Netgrent(Structure):
    _fields_ = [("type", c_int),
                ("val", Val),
                ("data", POINTER(c_char)),
                ("data_size", c_size_t),
                ("idx", Idx),
                ("first", c_int),
                ("known_groups", POINTER(NameList)),
                ("needed_groups", POINTER(NameList)),
                ("nip", c_void_p)]


def call_sssd_setnetgrent(netgroup):
    libnss_sss_path = config.NSS_MODULE_DIR + "/libnss_sss.so.2"
    libnss_sss = cdll.LoadLibrary(libnss_sss_path)

    func = libnss_sss._nss_sss_setnetgrent
    func.restype = c_int
    func.argtypes = [c_char_p, POINTER(Netgrent)]

    result = Netgrent()
    result_p = POINTER(Netgrent)(result)

    res = func(c_char_p(netgroup), result_p)

    return (int(res), result_p)


def call_sssd_getnetgrent_r(result_p, buff, buff_len):
    libnss_sss_path = config.NSS_MODULE_DIR + "/libnss_sss.so.2"
    libnss_sss = cdll.LoadLibrary(libnss_sss_path)

    func = libnss_sss._nss_sss_getnetgrent_r
    func.restype = c_int
    func.argtypes = [POINTER(Netgrent), POINTER(c_char), c_size_t,
                     POINTER(c_int)]

    errno = POINTER(c_int)(c_int(0))

    res = func(result_p, buff, buff_len, errno)

    return (int(res), int(errno[0]), result_p)


def call_sssd_endnetgrent(result_p):
    libnss_sss_path = config.NSS_MODULE_DIR + "/libnss_sss.so.2"
    libnss_sss = cdll.LoadLibrary(libnss_sss_path)

    func = libnss_sss._nss_sss_endnetgrent
    func.restype = c_int
    func.argtypes = [POINTER(Netgrent)]

    res = func(result_p)

    return int(res)


def get_sssd_netgroups(name):
    """
    Function will return netgroup triplets for given user. It will gather
    netgroups only provided by sssd.
    The equivalent of "getent netgroup -s sss user"

    @param string name name of netgroup

    @return (int, int, List[(string, string, string]) (err, errno, netgroups)
        if err is NssReturnCode.SUCCESS netgroups will contain list of touples.
        Each touple will consist of 3 elemets either string or None
        (host, user, domain).
    """
    buff_len = 1024 * 1024
    buff = create_string_buffer(buff_len)

    result = []

    res, result_p = call_sssd_setnetgrent(name)
    if res != NssReturnCode.SUCCESS:
        return (res, get_errno(), result)

    res, errno, result_p = call_sssd_getnetgrent_r(result_p, buff, buff_len)
    while res == NssReturnCode.SUCCESS:
        assert result_p[0].type == NetgroupType.TRIPLE_VAL
        result.append((result_p[0].val.triple.host,
                       result_p[0].val.triple.user,
                       result_p[0].val.triple.domain))
        res, errno, result_p = call_sssd_getnetgrent_r(result_p, buff,
                                                       buff_len)

    if res != NssReturnCode.RETURN:
        return (res, errno, result)

    res = call_sssd_endnetgrent(result_p)

    return (res, errno, result)
