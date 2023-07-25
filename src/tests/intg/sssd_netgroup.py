#
# Module for simulation of utility "getent netgroup -s sss" from coreutils
#
# Copyright (c) 2016 Red Hat, Inc.
# Author: Lukas Slebodnik <lslebodn@redhat.com>
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
from ctypes import (c_int, c_char, c_char_p, c_size_t, c_void_p, c_ulong,
                    POINTER, Structure, Union, create_string_buffer, get_errno)
from sssd_nss import NssReturnCode, nss_sss_ctypes_loader


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


class NetgroupRetriever(object):
    def __init__(self, name):
        self.name = name.encode('utf-8')
        self.needed_groups = []
        self.known_groups = []
        self.netgroups = []

    @staticmethod
    def _setnetgrent(netgroup):
        """
        This private method is ctypes wrapper for
        enum nss_status _nss_sss_setnetgrent(const char *netgroup,
                                             struct __netgrent *result)

        @param string name name of netgroup

        @return (int, POINTER(Netgrent)) (err, result_p)
            err is a constant from class NssReturnCode and in case of SUCCESS
            result_p will contain POINTER(Netgrent) which can be used in
            _getnetgrent_r or _getnetgrent_r.
        """
        func = nss_sss_ctypes_loader('_nss_sss_setnetgrent')
        func.restype = c_int
        func.argtypes = [c_char_p, POINTER(Netgrent)]

        result = Netgrent()
        result_p = POINTER(Netgrent)(result)

        res = func(c_char_p(netgroup), result_p)

        return (int(res), result_p)

    @staticmethod
    def _getnetgrent_r(result_p, buff, buff_len):
        """
        This private method is ctypes wrapper for
        enum nss_status _nss_sss_getnetgrent_r(struct __netgrent *result,
                                               char *buffer, size_t buflen,
                                               int *errnop)
        @param POINTER(Netgrent) result_p pointer to initialized C structure
               struct __netgrent
        @param ctypes.c_char_Array buff buffer used by C functions
        @param int buff_len size of c_char_Array passed as a parameter buff

        @return (int, int, List[(string, string, string])
                (err, errno, netgroups)
            if err is NssReturnCode.SUCCESS netgroups will contain list of
            touples. Each touple will consist of 3 elements either string or
        """
        func = nss_sss_ctypes_loader('_nss_sss_getnetgrent_r')
        func.restype = c_int
        func.argtypes = [POINTER(Netgrent), POINTER(c_char), c_size_t,
                         POINTER(c_int)]

        errno = POINTER(c_int)(c_int(0))

        res = func(result_p, buff, buff_len, errno)

        return (int(res), int(errno[0]), result_p)

    @staticmethod
    def _endnetgrent(result_p):
        """
        This private method is ctypes wrapper for
        enum nss_status _nss_sss_endnetgrent(struct __netgrent *result)

        @param POINTER(Netgrent) result_p pointer to initialized C structure
               struct __netgrent

        @return int a constant from class NssReturnCode
        """
        func = nss_sss_ctypes_loader('_nss_sss_endnetgrent')
        func.restype = c_int
        func.argtypes = [POINTER(Netgrent)]

        res = func(result_p)

        return int(res)

    def get_netgroups(self):
        """
        Function will return netgroup triplets for given user. All nested
        netgroups will be retrieved as part of executions and will content
        will be merged with direct triplets.
        Missing nested netgroups will not cause failure and are considered
        as an empty netgroup without triplets.

        @param string name name of netgroup

        @return (int, int, List[(string, string, string])
                (err, errno, netgroups)
            if err is NssReturnCode.SUCCESS netgroups will contain list of
            touples. Each touple will consist of 3 elements either string or
            None (host, user, domain).
        """
        res, errno, result = self._flat_fetch_netgroups(self.name)
        if res != NssReturnCode.SUCCESS:
            return (res, errno, self.netgroups)

        self.netgroups += result

        while self.needed_groups:
            name = self.needed_groups.pop(0)

            nest_res, nest_errno, result = self._flat_fetch_netgroups(name)
            # do not fail for missing nested netgroup
            if nest_res not in (NssReturnCode.SUCCESS, NssReturnCode.NOTFOUND):
                return (nest_res, nest_errno, self.netgroups)

            self.netgroups = result + self.netgroups

        return (res, errno, self.netgroups)

    def _flat_fetch_netgroups(self, name):
        """
        Function will return netgroup triplets for given user. The nested
        netgroups will not be returned. Missing nested netgroups will be
        appended to the array needed_groups

        @param string name name of netgroup

        @return (int, int, List[(string, string, string])
                (err, errno, netgroups)
            if err is NssReturnCode.SUCCESS netgroups will contain list of
            touples. Each touple will consist of 3 elements either string or
            None (host, user, domain).
        """
        buff_len = 1024 * 1024
        buff = create_string_buffer(buff_len)

        result = []

        res, result_p = self._setnetgrent(name)
        if res != NssReturnCode.SUCCESS:
            return (res, get_errno(), result)

        res, errno, result_p = self._getnetgrent_r(result_p, buff, buff_len)
        while res == NssReturnCode.SUCCESS:
            if result_p[0].type == NetgroupType.GROUP_VAL:
                nested_netgroup = result_p[0].val.group
                if nested_netgroup not in self.known_groups:
                    self.needed_groups.append(nested_netgroup)
                    self.known_groups.append(nested_netgroup)

            if result_p[0].type == NetgroupType.TRIPLE_VAL:
                triple = result_p[0].val.triple
                result.append((triple.host and triple.host.decode('utf-8')
                               or "",
                               triple.user and triple.user.decode('utf-8')
                               or "",
                               triple.domain and triple.domain.decode('utf-8')
                               or ""))

            res, errno, result_p = self._getnetgrent_r(result_p, buff,
                                                       buff_len)

        if res != NssReturnCode.RETURN:
            return (res, errno, result)

        res = self._endnetgrent(result_p)

        return (res, errno, result)


def get_sssd_netgroups(name):
    """
    Function will return netgroup triplets for given user. It will gather
    netgroups only provided by sssd.
    The equivalent of "getent netgroup -s sss user"

    @param string name name of netgroup

    @return (int, int, List[(string, string, string]) (err, errno, netgroups)
        if err is NssReturnCode.SUCCESS netgroups will contain list of touples.
        Each touple will consist of 3 elements either string or None
        (host, user, domain).
    """

    retriever = NetgroupRetriever(name)

    return retriever.get_netgroups()
