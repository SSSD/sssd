#
# Test for the PAM responder
#
# Copyright (c) 2018 Red Hat, Inc.
# Author: Sumit Bose <sbose@redhat.com>
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

"""
Tests for the PAM responder
"""
import os
import stat
import signal
import errno
import subprocess
import time
import shutil

import config

import pytest

from intg.util import unindent
from intg.files_ops import passwd_ops_setup

USER1 = dict(name='user1', passwd='x', uid=10001, gid=20001,
             gecos='User for tests',
             dir='/home/user1',
             shell='/bin/bash')


def format_pam_cert_auth_conf(config):
    """Format a basic SSSD configuration"""
    return unindent("""\
        [sssd]
        debug_level = 10
        domains = auth_only
        services = pam, nss

        [nss]
        debug_level = 10

        [pam]
        pam_cert_auth = True
        pam_p11_allowed_services = +pam_sss_service
        pam_cert_db_path = {config.PAM_CERT_DB_PATH}
        debug_level = 10

        [domain/auth_only]
        debug_level = 10
        id_provider = files

        [certmap/auth_only/user1]
        matchrule = <SUBJECT>.*CN=SSSD test cert 0001.*
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
    os.environ["SSS_FILES_PASSWD"] = os.environ["NSS_WRAPPER_PASSWD"]
    os.environ["SSS_FILES_GROUP"] = os.environ["NSS_WRAPPER_GROUP"]
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


def create_nssdb():
    os.mkdir(config.SYSCONFDIR + "/pki")
    os.mkdir(config.SYSCONFDIR + "/pki/nssdb")
    if subprocess.call(["certutil", "-N", "-d",
                        "sql:" + config.SYSCONFDIR + "/pki/nssdb/",
                        "--empty-password"]) != 0:
        raise Exception("certutil failed")

    pkcs11_txt = open(config.SYSCONFDIR + "/pki/nssdb/pkcs11.txt", "w")
    pkcs11_txt.write("library=libsoftokn3.so\nname=soft\n" +
                     "parameters=configdir='sql:" + config.ABS_BUILDDIR +
                     "/../test_CA/p11_nssdb' " +
                     "dbSlotDescription='SSSD Test Slot' " +
                     "dbTokenDescription='SSSD Test Token' " +
                     "secmod='secmod.db' flags=readOnly)\n\n")
    pkcs11_txt.close()


def cleanup_nssdb():
    shutil.rmtree(config.SYSCONFDIR + "/pki")


def create_nssdb_fixture(request):
    create_nssdb()
    request.addfinalizer(cleanup_nssdb)


@pytest.fixture
def simple_pam_cert_auth(request):
    """Setup SSSD with pam_cert_auth=True"""
    config.PAM_CERT_DB_PATH = os.environ['PAM_CERT_DB_PATH']
    conf = format_pam_cert_auth_conf(config)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    create_nssdb_fixture(request)
    return None


def test_preauth_indicator(simple_pam_cert_auth):
    """Check if preauth indicator file is created"""
    statinfo = os.stat(config.PUBCONF_PATH + "/pam_preauth_available")
    assert stat.S_ISREG(statinfo.st_mode)


@pytest.fixture
def pam_wrapper_setup(request):
    pwrap_runtimedir = os.getenv("PAM_WRAPPER_SERVICE_DIR")
    if pwrap_runtimedir is None:
        raise ValueError("The PAM_WRAPPER_SERVICE_DIR variable is unset\n")


def test_sc_auth_wrong_pin(simple_pam_cert_auth, pam_wrapper_setup,
                           passwd_ops_setup):

    passwd_ops_setup.useradd(**USER1)
    current_env = os.environ.copy()
    current_env['PAM_WRAPPER'] = "1"
    current_env['SSSD_INTG_PEER_UID'] = "0"
    current_env['SSSD_INTG_PEER_GID'] = "0"
    current_env['LD_PRELOAD'] += ':' + os.environ['PAM_WRAPPER_PATH']

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth", "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=current_env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="111")
    except:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: " +
                    "Authentication failure") != -1


def test_sc_auth(simple_pam_cert_auth, pam_wrapper_setup, passwd_ops_setup):

    passwd_ops_setup.useradd(**USER1)
    current_env = os.environ.copy()
    current_env['PAM_WRAPPER'] = "1"
    current_env['SSSD_INTG_PEER_UID'] = "0"
    current_env['SSSD_INTG_PEER_GID'] = "0"
    current_env['LD_PRELOAD'] += ':' + os.environ['PAM_WRAPPER_PATH']

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth", "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=current_env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: Success") != -1
