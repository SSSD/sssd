#
# Module for simulation of utility "id" from coreutils
#
# Copyright (c) 2015 Red Hat, Inc.
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
import config
import pwd
import grp
from ctypes import (cdll, c_int, c_char, c_uint32, c_long, c_char_p,
                    POINTER, pointer)


class NssReturnCode(object):
    """ 'enum' class for name service switch retrn code """
    TRYAGAIN = -2,
    UNAVAIL = -1
    NOTFOUND = 0
    SUCCESS = 1
    RETURN = 2


def call_sssd_initgroups(user, gid):
    """
    Function will initialize the supplementary group access list
    for given user. It will gather groups only provided by sssd.

    Arguments are the same as for C function initgroups
    @param string user name of user
    @param int gid the additional gid will be also added to the list.

    @return (int, int, List[int]) (err, errno, gids)
        gids shoudl contain user group IDs if err is NssReturnCode.SUCCESS
        otherwise errno will contain non-zero vlaue.
    """
    libnss_sss_path = config.PREFIX + "/lib/libnss_sss.so.2"
    libnss_sss = cdll.LoadLibrary(libnss_sss_path)

    func = libnss_sss._nss_sss_initgroups_dyn
    func.restype = c_int
    func.argtypes = [POINTER(c_char), c_uint32, POINTER(c_long),
                     POINTER(c_long), POINTER(POINTER(c_uint32)), c_long,
                     POINTER(c_int)]

    start = POINTER(c_long)(c_long(0))
    size = POINTER(c_long)(c_long(0))
    groups = POINTER(c_uint32)()
    p_groups = pointer(groups)
    limit = c_long(-1)
    errno = POINTER(c_int)(c_int(0))

    res = func(c_char_p(user), c_uint32(gid), start, size, p_groups, limit,
               errno)

    gids = []
    if res == NssReturnCode.SUCCESS:
        gids_count = size[0]
        assert gids_count > 0, "_nss_sss_initgroups_dyn shoulld return " \
                               "one gid"

        for i in range(0, gids_count):
            gids.append(int(p_groups.contents[i]))

    return (int(res), errno[0], gids)


def get_user_gids(user):
    """
    Function will initialize the supplementary group access list
    for given user. It will gather groups only provided by sssd.

    Arguments are the same as for C function initgroups
    @param string user name of user

    @return (int, int, List[int]) (err, errno, gids)
        gids shoudl contain user group IDs if err is NssReturnCode.SUCCESS
        otherwise errno will contain non-zero vlaue.
    """
    pwd_user = pwd.getpwnam(user)
    uid = pwd_user.pw_uid
    gid = pwd_user.pw_gid

    user = pwd.getpwuid(uid).pw_name

    return call_sssd_initgroups(user, gid)


def get_user_groups(user):
    """
    Function will initialize the supplementary group access list
    for given user. It will gather groups only provided by sssd.

    Arguments are the same as for C function initgroups
    @param string user name of user

    @return (int, int, List[string]) (err, errno, groups)
        roups shoudl contain names of user groups
        if err is NssReturnCode.SUCCESS
        otherwise errno will contain non-zero vlaue.
    """
    (res, errno, gids) = get_user_gids(user)
    groups = []

    if res == NssReturnCode.SUCCESS:
        groups = [grp.getgrgid(gid).gr_name for gid in gids]

    return (res, errno, groups)
