#
# SSSD PAC responder tests
#
# Copyright (c) 2017 Red Hat, Inc.
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
import os
import stat
import time
import config
import signal
import subprocess
import pytest
from util import unindent


def have_sssd_responder(responder_name):
    responder_path = os.path.join(config.LIBEXEC_PATH, "sssd", responder_name)

    return os.access(responder_path, os.X_OK)


def stop_sssd():
    with open(config.PIDFILE_PATH, "r") as pid_file:
        pid = int(pid_file.read())
    os.kill(pid, signal.SIGTERM)
    while True:
        try:
            os.kill(pid, signal.SIGCONT)
        except:
            break
        time.sleep(1)


def create_conf_fixture(request, contents):
    """Generate sssd.conf and add teardown for removing it"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)
    request.addfinalizer(lambda: os.unlink(config.CONF_PATH))


def create_sssd_fixture(request):
    """Start sssd and add teardown for stopping it and removing state"""
    if subprocess.call(["sssd", "-D", "-f"]) != 0:
        raise Exception("sssd start failed")

    def teardown():
        try:
            stop_sssd()
        except:
            pass
        for path in os.listdir(config.DB_PATH):
            os.unlink(config.DB_PATH + "/" + path)
        for path in os.listdir(config.MCACHE_PATH):
            os.unlink(config.MCACHE_PATH + "/" + path)
    request.addfinalizer(teardown)


@pytest.fixture
def local_domain_only(request):
    conf = unindent("""\
        [sssd]
        domains = LOCAL
        services = nss, pac

        [nss]
        memcache_timeout = 0

        [domain/LOCAL]
        id_provider = local
        min_id = 10000
        max_id = 20000
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def sssd_pac_test_client(request):
    path = os.path.join(config.ABS_BUILDDIR,
                        "..", "..", "..", "sssd_pac_test_client")
    if os.access(path, os.X_OK):
        return path

    return None


def timeout_handler(signum, frame):
    raise Exception("Timeout")


@pytest.mark.skipif(not have_sssd_responder("sssd_pac"),
                    reason="No PAC responder, skipping")
def test_multithreaded_pac_client(local_domain_only, sssd_pac_test_client):
    """
    Test for ticket
    https://pagure.io/SSSD/sssd/issue/3518
    """

    if not sssd_pac_test_client:
        pytest.skip("The sssd_pac_test_client is not available, skipping test")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(10)

    try:
        subprocess.check_call(sssd_pac_test_client)
    except:
        # cancel alarm
        signal.alarm(0)
        raise Exception("sssd_pac_test_client failed")

    signal.alarm(0)
