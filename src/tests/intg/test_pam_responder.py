#
# Test for the PAM responder
#
# Copyright (c) 2018 Red Hat, Inc.
# Author: Sumit Bose <sbose@redhat.com>
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

"""
Tests for the PAM responder
"""
import os
import stat
import signal
import errno
import subprocess
import time
import pytest

import config

from util import unindent


def format_pam_cert_auth_conf():
    """Format a basic SSSD configuration"""
    return unindent("""\
        [sssd]
        domains = auth_only
        services = pam

        [nss]

        [pam]
        pam_cert_auth = True
        debug_level = 10

        [domain/auth_only]
        id_provider = ldap
        auth_provider = ldap
        chpass_provider = ldap
        access_provider = ldap
    """).format(**locals())


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)


def create_conf_fixture(request, contents):
    """
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)

    def cleanup_conf_file():
        """Remove sssd.conf, if it exists"""
        if os.path.lexists(config.CONF_PATH):
            os.unlink(config.CONF_PATH)

    request.addfinalizer(cleanup_conf_file)


def create_sssd_process():
    """Start the SSSD process"""
    if subprocess.call(["sssd", "-D", "-f"]) != 0:
        raise Exception("sssd start failed")


def cleanup_sssd_process():
    """Stop the SSSD process and remove its state"""
    try:
        with open(config.PIDFILE_PATH, "r") as pid_file:
            pid = int(pid_file.read())
        os.kill(pid, signal.SIGTERM)
        while True:
            try:
                os.kill(pid, signal.SIGCONT)
            except OSError as ex:
                break
            time.sleep(1)
    except OSError as ex:
        pass
    for path in os.listdir(config.DB_PATH):
        os.unlink(config.DB_PATH + "/" + path)
    for path in os.listdir(config.MCACHE_PATH):
        os.unlink(config.MCACHE_PATH + "/" + path)

    # make sure that the indicator file is removed during shutdown
    try:
        assert not os.stat(config.PUBCONF_PATH + "/pam_preauth_available")
    except OSError as ex:
        if ex.errno != errno.ENOENT:
            raise ex


def create_sssd_fixture(request):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process()
    request.addfinalizer(cleanup_sssd_process)


@pytest.fixture
def simple_pam_cert_auth(request):
    """Setup SSSD with pam_cert_auth=True"""
    conf = format_pam_cert_auth_conf()
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_preauth_indicator(simple_pam_cert_auth):
    """Check if preauth indicator file is created"""
    statinfo = os.stat(config.PUBCONF_PATH + "/pam_preauth_available")
    assert stat.S_ISREG(statinfo.st_mode)
