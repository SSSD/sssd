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


class HostError(object):
    """ 'enum' class for h_errno (glibc >= 2.19) """
    HOST_NOT_FOUND = 1
    TRY_AGAIN = 2
    NO_RECOVERY = 3
    NO_DATA = 4

    @classmethod
    def tostring(cls, val):
        if (val == 1):
            return "HOST_NOT_FOUND"
        if (val == 2):
            return "TRY_AGAIN"
        if (val == 3):
            return "NO_RECOVERY"
        if (val == 4):
            return "NO_DATA"
        return "UNKNOWN"


class SssdNssError(Exception):
    """ Raised when one of the NSS operations fail """
    def __init__(self, errno, nssop):
        self.errno = errno
        self.nssop = nssop

    def __str__(self):
        return "NSS operation %s failed %d" % (self.nssop, self.errno)


class SssdNssHostError(Exception):
    """ Raised when one of the NSS hosts operations fail """
    def __init__(self, h_errno, nssop):
        self.h_errno = h_errno
        self.nssop = nssop

    def __str__(self):
        str_herr = HostError.tostring(self.h_errno)
        return "NSS host operation %s failed: %s" % (self.nssop, str_herr)


def nss_sss_ctypes_loader(func_name):
    libnss_sss_path = config.NSS_MODULE_DIR + "/libnss_sss.so.2"
    libnss_sss = ctypes.cdll.LoadLibrary(libnss_sss_path)
    func = getattr(libnss_sss, func_name)
    return func
