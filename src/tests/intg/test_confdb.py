#
# Confdb integration tests
#
# Copyright (c) 2022 Red Hat, Inc.
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

import os
import stat
import signal
import subprocess
import time
import pytest

import config
from util import unindent


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    with open(config.CONF_PATH, "w") as conf:
        conf.write(contents)
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)


def cleanup_conf_file():
    """Remove sssd.conf, if it exists"""
    if os.path.lexists(config.CONF_PATH):
        os.unlink(config.CONF_PATH)


def create_conf_cleanup(request):
    """Add teardown for removing sssd.conf"""
    request.addfinalizer(cleanup_conf_file)


def create_conf_fixture(request, contents):
    """
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)
    create_conf_cleanup(request)


def create_sssd_process():
    """Start the SSSD process"""
    if subprocess.call(["sssd", "-D", "--logger=files"]) != 0:
        raise Exception("sssd start failed")


def get_sssd_pid():
    with open(config.PIDFILE_PATH, "r") as pid_file:
        pid = int(pid_file.read())
    return pid


def cleanup_sssd_process():
    """Stop the SSSD process and remove its state"""
    try:
        pid = get_sssd_pid()
        os.kill(pid, signal.SIGTERM)
        while True:
            try:
                os.kill(pid, signal.SIGCONT)
            except OSError:
                break
            time.sleep(1)
    except OSError:
        # Ignore the error.
        pass
    for path in os.listdir(config.DB_PATH):
        os.unlink(config.DB_PATH + "/" + path)
    for path in os.listdir(config.MCACHE_PATH):
        os.unlink(config.MCACHE_PATH + "/" + path)


def test_domains__domains(request):
    """
    Test that SSSD starts with explicitly configured domain.
    """
    conf = unindent("""\
        [sssd]
        services = nss, sudo
        domains = test

        [domain/test]
        id_provider = proxy
        proxy_lib_name = files
        auth_provider = none
    """)

    create_conf_fixture(request, conf)

    try:
        create_sssd_process()
    except Exception:
        assert False
    finally:
        cleanup_sssd_process()


def test_domains__enabled(request):
    """
    Test that SSSD starts without domains option.
    """
    conf = unindent("""\
        [sssd]
        services = nss, sudo

        [domain/test]
        enabled = true
        id_provider = proxy
        proxy_lib_name = files
        auth_provider = none
    """)

    create_conf_fixture(request, conf)

    try:
        create_sssd_process()
    except Exception:
        assert False
    finally:
        cleanup_sssd_process()


def test_domains__empty(request):
    """
    Test that SSSD fails without any domain enabled.
    """
    conf = unindent("""\
        [sssd]
        services = nss, sudo
        enable_files_domain = false

        [domain/test]
        id_provider = proxy
        proxy_lib_name = files
        auth_provider = none
    """)

    create_conf_fixture(request, conf)
    with pytest.raises(Exception):
        create_sssd_process()

    cleanup_sssd_process()
