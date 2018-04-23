#
# Shared module for integration tests that need to access the sssd_nss_ex
# interface directly
#
# Copyright (c) 2018 Red Hat, Inc.
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

import config
import errno
from ctypes import (cdll, c_int, c_char_p, c_char,
                    c_uint32, c_uint, POINTER, pointer)


def nss_sss_ex_ctypes_loader(func_name):
    libnss_idmap_path = config.NSS_MODULE_DIR + "/libsss_nss_idmap.so"
    libnss_idmap = cdll.LoadLibrary(libnss_idmap_path)
    func = getattr(libnss_idmap, func_name)
    return func


class NssExFlags(object):
    """ 'enum' class for name the flags the sssd_nss_ex calls accept """
    NONE = 0,
    SSS_NSS_EX_FLAG_NO_CACHE = 1,
    SSS_NSS_EX_FLAG_INVALIDATE_CACHE = 2,


class SssNssGetgrouplistResult:
    def __init__(self, errno, ngroups, groups):
        self.errno = errno
        self.ngroups = ngroups
        self.groups = groups


def sss_nss_getgrouplist_timeout(name,
                                 gid,
                                 num_groups,
                                 flags=NssExFlags.NONE,
                                 timeout=5000):
    """
    A python wrapper for:

    int sss_nss_getgrouplist_timeout(const char *name, gid_t group,
                                    gid_t *groups, int *ngroups,
                                    uint32_t flags, unsigned int timeout)
    """
    func = nss_sss_ex_ctypes_loader("sss_nss_getgrouplist_timeout")

    func.restype = c_int
    func.argtypes = [POINTER(c_char), c_uint32, POINTER(c_uint32),
                     POINTER(c_int), c_uint32, c_uint]

    group_array = (c_uint32 * num_groups)()
    p_num_groups = pointer(c_int(num_groups))

    res = func(c_char_p(name.encode('utf-8')),
               c_uint32(gid),
               group_array,
               p_num_groups,
               c_uint32(int(flags[0])),
               c_uint(timeout))

    groups = []
    group_num = 0

    if res == 0:
        group_num = p_num_groups[0]
    elif res == errno.ERANGE:
        group_num = num_groups
    # else group_num == 0 and the loop will fall through

    for i in range(0, group_num):
        groups.append(int(group_array[i]))

    return SssNssGetgrouplistResult(res, group_num, groups)
