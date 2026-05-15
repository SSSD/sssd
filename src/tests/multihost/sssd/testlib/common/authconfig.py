# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#          Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2007-2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
""" Authconfig Module """
from __future__ import print_function
from subprocess import CalledProcessError
import os

FILES_TO_NOT_BACKUP = ['passwd', 'group', 'shadow', 'gshadow']


class RedHatAuthConfig(object):
    """
    AuthConfig class implements a system-independent interface to configure
    system authentication resources. In Red Hat systems this is done with
    authconfig(8) utility.

    AuthConfig class is nothing more than a tool to gather configuration
    options and execute their processing. These options are then converted by
    an actual implementation to a series of system calls to appropriate
    utilities performing real configuration.

    If you need to re-use existing AuthConfig instance for multiple runs,
    make sure to call 'AuthConfig.reset()' between the runs.
    """

    def __init__(self, host):
        """ Initialize host
        :param str host: hostname
        """
        self.host = host
        self.parameters = {}

    def enable(self, option):
        """
        Option to be passed to authconfig
        :param str option: authconfig options
        """
        self.parameters[option] = True
        return self

    def disable(self, option):
        """
        Disable options
        :param str option: authconfig options
        """
        self.parameters[option] = False
        return self

    def add_option(self, option):
        """
        Add option
        :param str option: authconfig options
        """
        self.parameters[option] = None
        return self

    def add_parameter(self, option, value):
        """
        Add parameters
        :param str option: authconfig options
        :param str values: values
        """
        self.parameters[option] = [value]
        return self

    def reset(self):
        """
        Reset to the default
        """
        self.parameters = {}
        return self

    def build_args(self):
        """
        Build argument list from options provided
        """
        args = []
        print("parameters passed: ", self.parameters)
        for (option, value) in self.parameters.items():
            if type(value) is bool:
                if value:
                    args.append("--enable%s" % (option))
                else:
                    args.append("--disable%s" % (option))
            elif type(value) in (tuple, list):
                args.append("--%s" % (option))
                args.append("%s" % (value[0]))
            elif value is None:
                args.append("--%s" % (option))
            else:
                args.append("--%s%s" % (option, value))
        return args

    def execute(self, update=True):
        """ Execute authconfig command """
        if update:
            self.add_option("update")

        args = self.build_args()
        auth_cmd = ['/usr/sbin/authconfig'] + args
        cmd = self.host.run_command(auth_cmd, set_env=False, raiseonerr=False)
        if cmd.returncode != 0:
            raise Exception("Failed to run Authconfig")

    def backup(self, path):
        """ Backup existing authconfig options
        :param str path: path where existing files are backed
        """
        cmd = self.host.run_command(['/usr/sbin/authconfig', '--savebackup',
                                     path], set_env=False, raiseonerr=False)
        if cmd.returncode != 0:
            raise Exception("Unable to save backup")
        # do not backup these files since we don't want to mess with
        # users/groups during restore. Authconfig doesn't seem to mind about
        # having them deleted from backup dir
        files_to_remove = [os.path.join(path, f) for f in FILES_TO_NOT_BACKUP]
        for filename in files_to_remove:
            try:
                self.host.run_command(['rm', '-f', filename], set_env=False)
            except CalledProcessError:
                pass

    def restore(self, path):
        """ Restore from backup
        :param str path: backup path
        """
        self.host.run_command(["/usr/sbin/authconfig", "--restorebackup",
                               path], set_env=False, raiseonerr=False)
