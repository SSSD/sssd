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
    """ 'enum' class for name service switch return code """
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
        gids should contain user group IDs if err is NssReturnCode.SUCCESS
        otherwise errno will contain non-zero value.
    """
    libnss_sss_path = config.NSS_MODULE_DIR + "/libnss_sss.so.2"
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

    res = func(c_char_p(user.encode('utf-8)')), c_uint32(gid), start, size,
               p_groups, limit, errno)

    gids = []
    if res == NssReturnCode.SUCCESS:
        gids_count = size[0]
        assert gids_count > 0, "_nss_sss_initgroups_dyn should return " \
                               "one gid"

        for i in range(0, gids_count):
            gids.append(int(p_groups.contents[i]))

        # add primary group if missing
        if gid not in gids:
            gids.append(gid)

    return (int(res), errno[0], gids)


def get_user_gids(user):
    """
    Function will initialize the supplementary group access list
    for given user. It will gather groups only provided by sssd.

    Arguments are the same as for C function initgroups
    @param string user name of user

    @return (int, int, List[int]) (err, errno, gids)
        gids should contain user group IDs if err is NssReturnCode.SUCCESS
        otherwise errno will contain non-zero value.
    """
    pwd_user = pwd.getpwnam(user)
    uid = pwd_user.pw_uid
    gid = pwd_user.pw_gid

    user = pwd.getpwuid(uid).pw_name

    return call_sssd_initgroups(user, gid)


def gid_to_str(gid):
    """
    Function will map numeric GID into names.
    If there isn't a group for GID (getgrgid failed)
    then the function will return decimal representation of ID.

    @param int gid ID of groups which should be converted to string.
    @return string name of group with requested ID or decimal
                   representation of ID
    """
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def get_user_groups(user):
    """
    Function will initialize the supplementary group access list
    for given user. It will gather groups only provided by sssd.

    Arguments are the same as for C function initgroups
    @param string user name of user

    @return (int, int, List[string]) (err, errno, groups)
        groups should contain names of user groups
        if err is NssReturnCode.SUCCESS
        otherwise errno will contain non-zero value.
    """
    (res, errno, gids) = get_user_gids(user)
    groups = []

    if res == NssReturnCode.SUCCESS:
        groups = [gid_to_str(gid) for gid in gids]

    return (res, errno, groups)
