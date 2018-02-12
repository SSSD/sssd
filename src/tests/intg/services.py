#
# LDAP integration test
#
# Copyright (c) 2017 Red Hat, Inc.
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
import os
import os.path
import signal
import subprocess
import time

import config


class SSSD(object):
    def __init__(self):
        self.pid = 0

    def start(self):
        """Start the SSSD process"""
        assert self.pid == 0

        if subprocess.call(["sssd", "-D", "-f"]) != 0:
            raise Exception("sssd start failed")

        # wait 2 seconds for pidfile
        wait_time = 2
        for _ in range(wait_time * 10):
            if os.path.isfile(config.PIDFILE_PATH):
                break
            time.sleep(.1)

        assert os.path.isfile(config.PIDFILE_PATH)
        with open(config.PIDFILE_PATH, "r") as pid_file:
            self.pid = int(pid_file.read())

    def stop(self):
        """Stop the SSSD process and remove its state"""

        # stop process only if running
        if self.pid != 0:
            try:
                os.kill(self.pid, signal.SIGTERM)
                while True:
                    try:
                        os.kill(self.pid, signal.SIGCONT)
                    except:
                        break
                    time.sleep(.1)
            except:
                pass

        # clean pid so we can start service one more time
        self.pid = 0

    def restart(self):
        self.stop()
        self.start()

    def go_offline(self):
        os.kill(self.pid, signal.SIGUSR1)

    @staticmethod
    def clean_cache():
        """Remove SSSD cache files"""
        for path in os.listdir(config.DB_PATH):
            os.unlink(config.DB_PATH + "/" + path)
        for path in os.listdir(config.MCACHE_PATH):
            os.unlink(config.MCACHE_PATH + "/" + path)
