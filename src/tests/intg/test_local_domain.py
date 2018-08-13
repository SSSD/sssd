#
# SSSD LOCAL domain tests
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Michal Zidek <mzidek@redhat.com>
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
import pwd
import grp
import time
import config
import signal
import subprocess
import pytest
import ent
from util import unindent


def stop_sssd():
    pid_file = open(config.PIDFILE_PATH, "r")
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
        domains             = LOCAL
        services            = nss

        [nss]
        memcache_timeout = 0

        [domain/LOCAL]
        id_provider         = local
        min_id = 10000
        max_id = 20000
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def local_domain_only_fqdn(request):
    conf = unindent("""\
        [sssd]
        domains = LOCAL
        services = nss

        [nss]
        memcache_timeout = 0

        [domain/LOCAL]
        id_provider = local
        min_id = 10000
        max_id = 20000
        use_fully_qualified_names = True
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def assert_nonexistent_user(name):
    with pytest.raises(KeyError):
        pwd.getpwnam(name)


def assert_nonexistent_group(name):
    with pytest.raises(KeyError):
        grp.getgrnam(name)


def test_groupshow_mpg(local_domain_only):
    """
    Regression test for ticket
    https://fedorahosted.org/sssd/ticket/3184
    """
    subprocess.check_call(["sss_useradd", "foo", "-M"])

    # The user's mpg has to be found (should return 0)
    subprocess.check_call(["sss_groupshow", "foo"])


def test_groupshow_mpg_fqdn(local_domain_only_fqdn):
    """
    Regression test for ticket (fq variant)
    https://fedorahosted.org/sssd/ticket/3184
    """
    subprocess.check_call(["sss_useradd", "foo@LOCAL", "-M"])

    # The user's mpg has to be found (should return 0)
    subprocess.check_call(["sss_groupshow", "foo@LOCAL"])


def test_wrong_LC_ALL(local_domain_only):
    """
    Regression test for ticket
    https://fedorahosted.org/sssd/ticket/2785

    """
    subprocess.check_call(["sss_useradd", "foo", "-M"])
    pwd.getpwnam("foo")

    # Change the LC_ALL variable to nonexistent locale
    oldvalue = os.environ.get("LC_ALL", "")
    os.environ["LC_ALL"] = "nonexistent_locale"

    # sss_userdel must remove the user despite wrong LC_ALL
    subprocess.check_call(["sss_userdel", "foo", "-R"])
    assert_nonexistent_user("foo")
    os.environ["LC_ALL"] = oldvalue


def test_sss_group_add_show_del(local_domain_only):
    """
    Regression test for tickets
    https://fedorahosted.org/sssd/ticket/3173
    https://fedorahosted.org/sssd/ticket/3175
    """

    subprocess.check_call(["sss_groupadd", "foo", "-g", "10001"])

    "This should not raise KeyError"
    ent.assert_group_by_name("foo", dict(name="foo", gid=10001))

    "sss_grupshow should return 0 with existing group name"
    subprocess.check_call(["sss_groupshow", "foo"])

    subprocess.check_call(["sss_groupdel", "foo"])
    assert_nonexistent_group("foo")


def test_add_local_user_to_local_group(local_domain_only):
    """
    Regression test for ticket
    https://fedorahosted.org/sssd/ticket/3178
    """
    subprocess.check_call(["sss_groupadd", "-g", "10009", "group10009"])
    subprocess.check_call(["sss_useradd", "-u", "10009", "-M", "user10009"])
    subprocess.check_call(["sss_usermod", "-a", "group10009", "user10009"])

    ent.assert_group_by_name(
        "group10009",
        dict(name="group10009", passwd="*", gid=10009,
             mem=ent.contains_only("user10009")))


def test_add_local_group_to_local_group(local_domain_only):
    """
    Regression test for tickets
    https://fedorahosted.org/sssd/ticket/3178
    """
    subprocess.check_call(["sss_groupadd", "-g", "10009", "group_child"])
    subprocess.check_call(["sss_useradd", "-u", "10009", "-M", "user_child"])
    subprocess.check_call(["sss_usermod", "-a", "group_child", "user_child"])

    subprocess.check_call(["sss_groupadd", "-g", "10008", "group_parent"])
    subprocess.check_call(
        ["sss_groupmod", "-a", "group_parent", "group_child"])

    # User from child_group is member of parent_group, so child_group's
    # member must be also parent_group's member
    ent.assert_group_by_name(
        "group_parent",
        dict(name="group_parent", passwd="*", gid=10008,
             mem=ent.contains_only("user_child")))


def test_sss_group_add_show_del_fqdn(local_domain_only_fqdn):
    """
    Regression test for tickets
    https://fedorahosted.org/sssd/ticket/3173
    https://fedorahosted.org/sssd/ticket/3175
    """

    subprocess.check_call(["sss_groupadd", "foo@LOCAL", "-g", "10001"])

    "This should not raise KeyError"
    ent.assert_group_by_name("foo@LOCAL", dict(name="foo@LOCAL", gid=10001))

    "sss_grupshow should return 0 with existing group name"
    subprocess.check_call(["sss_groupshow", "foo@LOCAL"])

    subprocess.check_call(["sss_groupdel", "foo@LOCAL"])
    assert_nonexistent_group("foo@LOCAL")


def test_add_local_user_to_local_group_fqdn(local_domain_only_fqdn):
    """
    Regression test for ticket
    https://fedorahosted.org/sssd/ticket/3178
    """
    subprocess.check_call(
        ["sss_groupadd", "-g", "10009", "group10009@LOCAL"])
    subprocess.check_call(
        ["sss_useradd", "-u", "10009", "-M", "user10009@LOCAL"])
    subprocess.check_call(
        ["sss_usermod", "-a", "group10009@LOCAL", "user10009@LOCAL"])

    ent.assert_group_by_name(
        "group10009@LOCAL",
        dict(name="group10009@LOCAL", passwd="*", gid=10009,
             mem=ent.contains_only("user10009@LOCAL")))


def test_add_local_group_to_local_group_fqdn(local_domain_only_fqdn):
    """
    Regression test for tickets
    https://fedorahosted.org/sssd/ticket/3178
    """
    subprocess.check_call(
        ["sss_groupadd", "-g", "10009", "group_child@LOCAL"])
    subprocess.check_call(
        ["sss_useradd", "-u", "10009", "-M", "user_child@LOCAL"])
    subprocess.check_call(
        ["sss_usermod", "-a", "group_child@LOCAL", "user_child@LOCAL"])

    subprocess.check_call(
        ["sss_groupadd", "-g", "10008", "group_parent@LOCAL"])
    subprocess.check_call(
        ["sss_groupmod", "-a", "group_parent@LOCAL", "group_child@LOCAL"])

    # User from child_group is member of parent_group, so child_group's
    # member must be also parent_group's member
    ent.assert_group_by_name(
        "group_parent@LOCAL",
        dict(name="group_parent@LOCAL", passwd="*", gid=10008,
             mem=ent.contains_only("user_child@LOCAL")))
