#
# Shared module for integration tests that need to access the sssd_nss
# module directly
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
import config
import ctypes


class NssReturnCode(object):
    """ 'enum' class for name service switch return code """
    TRYAGAIN = -2,
    UNAVAIL = -1
    NOTFOUND = 0
    SUCCESS = 1
    RETURN = 2


class SssdNssError(Exception):
    """ Raised when one of the NSS operations fail """
    def __init__(self, errno, nssop):
        self.errno = errno
        self.nssop = nssop

    def __str__(self):
        return "NSS operation %s failed %d" % (nssop, errno)


def nss_sss_ctypes_loader(func_name):
    libnss_sss_path = config.NSS_MODULE_DIR + "/libnss_sss.so.2"
    libnss_sss = ctypes.cdll.LoadLibrary(libnss_sss_path)
    func = getattr(libnss_sss, func_name)
    return func
