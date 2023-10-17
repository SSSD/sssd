#
# integration test for sss_override tool
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Pavel Reichl  <preichl@redhat.com>
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
import ent
import pwd
import config
import signal
import subprocess
import time
import pytest
import ds_openldap
import ldap_ent
import sssd_id
from util import unindent

try:
    from subprocess import check_output
except ImportError:
    # In Python 2.6, the module subprocess does not have the function
    # check_output. This is a fallback implementation.
    def check_output(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be '
                             'overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs,
                                   **kwargs)
        output, _ = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise subprocess.CalledProcessError(retcode, cmd, output=output)
        return output


@pytest.fixture(scope="module")
def ds_inst(request):
    """LDAP server instance fixture"""
    ds_inst = ds_openldap.DSOpenLDAP(
        config.PREFIX, 10389, 'dc=example,dc=com',
        "cn=admin", "Secret123")
    try:
        ds_inst.setup()
    except Exception:
        ds_inst.teardown()
        raise
    request.addfinalizer(lambda: ds_inst.teardown())
    return ds_inst


@pytest.fixture(scope="module")
def ldap_conn(request, ds_inst):
    """LDAP server connection fixture"""
    ldap_conn = ds_inst.bind()
    ldap_conn.ds_inst = ds_inst
    request.addfinalizer(lambda: ldap_conn.unbind_s())
    return ldap_conn


def create_ldap_fixture(request, ldap_conn, ent_list):
    """Add LDAP entries and add teardown for removing them"""
    for entry in ent_list:
        ldap_conn.add_s(entry[0], entry[1])

    def teardown():
        for entry in ent_list:
            ldap_conn.delete_s(entry[0])
    request.addfinalizer(teardown)


def create_conf_fixture(request, contents):
    """Generate sssd.conf and add teardown for removing it"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)
    request.addfinalizer(lambda: os.unlink(config.CONF_PATH))


def stop_sssd():
    pid_file = open(config.PIDFILE_PATH, "r")
    pid = int(pid_file.read())
    os.kill(pid, signal.SIGTERM)
    while True:
        try:
            os.kill(pid, signal.SIGCONT)
        except OSError:
            break
        time.sleep(1)


def start_sssd():
    """Start sssd"""
    if subprocess.call(["sssd", "-D", "--logger=files"]) != 0:
        raise Exception("sssd start failed")


def restart_sssd():
    stop_sssd()
    start_sssd()


def create_sssd_fixture(request):
    """Start sssd and add teardown for stopping it and removing state"""
    if subprocess.call(["sssd", "-D", "--logger=files"]) != 0:
        raise Exception("sssd start failed")

    def teardown():
        try:
            stop_sssd()
        except Exception:
            pass
        for path in os.listdir(config.DB_PATH):
            os.unlink(config.DB_PATH + "/" + path)
        for path in os.listdir(config.MCACHE_PATH):
            os.unlink(config.MCACHE_PATH + "/" + path)
    request.addfinalizer(teardown)


OVERRIDE_FILENAME = "export_file"


def prepare_sssd(request, ldap_conn, use_fully_qualified_names=False,
                 case_sensitive=True, override_homedir_option=False):
    """Prepare SSSD with defaults"""
    conf_override_homedir_option = ""
    if override_homedir_option:
        conf_override_homedir_option = "override_homedir = /home/ov_option/%u"

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        memcache_timeout = 1
        {conf_override_homedir_option}

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_id_use_start_tls = false
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
        use_fully_qualified_names = {use_fully_qualified_names}
        case_sensitive      = {case_sensitive}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)

    def teardown():
        # remove user export file
        try:
            os.unlink(OVERRIDE_FILENAME)
        except OSError:
            pass
    request.addfinalizer(teardown)


#
# Common asserts for users
#

def assert_user_default():

    # Assert entries are not overriden
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user1')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user1@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user2')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user2@LDAP')

    user1 = dict(name='user1', passwd='*', uid=10001, gid=20001,
                 gecos='User Number 1',
                 dir='/home/user1',
                 shell='/bin/user1_shell')
    user2 = dict(name='user2', passwd='*', uid=10002, gid=20001,
                 gecos='User Number 2',
                 dir='/home/user2',
                 shell='/bin/user2_shell')

    ent.assert_passwd_by_name('user1', user1)
    ent.assert_passwd_by_name('user1@LDAP', user1)

    ent.assert_passwd_by_name('user2', user2)
    ent.assert_passwd_by_name('user2@LDAP', user2)


def assert_user_overriden(override_name=True):

    if override_name:
        name1 = "ov_user1"
        name2 = "ov_user2"
    else:
        name1 = "user1"
        name2 = "user2"

    user1 = dict(name=name1, passwd='*', uid=10010, gid=20010,
                 gecos='Overriden User 1',
                 dir='/home/ov/user1',
                 shell='/bin/ov_user1_shell')

    user2 = dict(name=name2, passwd='*', uid=10020, gid=20020,
                 gecos='Overriden User 2',
                 dir='/home/ov/user2',
                 shell='/bin/ov_user2_shell')

    ent.assert_passwd_by_name('user1', user1)
    ent.assert_passwd_by_name('user1@LDAP', user1)

    if override_name:
        ent.assert_passwd_by_name('ov_user1', user1)
        ent.assert_passwd_by_name('ov_user1@LDAP', user1)

    ent.assert_passwd_by_name('user2', user2)
    ent.assert_passwd_by_name('user2@LDAP', user2)

    if override_name:
        ent.assert_passwd_by_name('ov_user2', user2)
        ent.assert_passwd_by_name('ov_user2@LDAP', user2)


#
# Common fixtures for users
#


@pytest.fixture
def env_two_users_and_group(request, ldap_conn):

    prepare_sssd(request, ldap_conn)

    # Add entries
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 10001, 20001,
                      gecos='User Number 1',
                      loginShell='/bin/user1_shell',
                      homeDirectory='/home/user1')

    ent_list.add_user("user2", 10002, 20001,
                      gecos='User Number 2',
                      loginShell='/bin/user2_shell',
                      homeDirectory='/home/user2')

    ent_list.add_group("group", 2001,
                       ["user2", "user1"])

    create_ldap_fixture(request, ldap_conn, ent_list)

    # Assert entries are not overriden
    assert_user_default()


@pytest.fixture
def env_two_users_and_group_overriden(request, ldap_conn,
                                      env_two_users_and_group):

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-u", "10010",
                           "-g", "20010",
                           "-n", "ov_user1",
                           "-c", "Overriden User 1",
                           "-h", "/home/ov/user1",
                           "-s", "/bin/ov_user1_shell"])

    subprocess.check_call(["sss_override", "user-add", "user2@LDAP",
                           "-u", "10020",
                           "-g", "20020",
                           "-n", "ov_user2",
                           "-c", "Overriden User 2",
                           "-h", "/home/ov/user2",
                           "-s", "/bin/ov_user2_shell"])

    # Restart SSSD so the override might take effect
    restart_sssd()

    # Assert entries are overriden
    assert_user_overriden()


#
# Simple user override
#


@pytest.fixture
def env_simple_user_override(request, ldap_conn, env_two_users_and_group):

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-u", "10010",
                           "-g", "20010",
                           "-n", "ov_user1",
                           "-c", "Overriden User 1",
                           "-h", "/home/ov/user1",
                           "-s", "/bin/ov_user1_shell"])

    subprocess.check_call(["sss_override", "user-add", "user2@LDAP",
                           "-u", "10020",
                           "-g", "20020",
                           "-n", "ov_user2",
                           "-c", "Overriden User 2",
                           "-h", "/home/ov/user2",
                           "-s", "/bin/ov_user2_shell"])

    # Restart SSSD so the override might take effect
    restart_sssd()


def test_simple_user_override(ldap_conn, env_simple_user_override):
    """Test entries are overriden"""

    assert_user_overriden()


#
# Root user override
#


@pytest.fixture
def env_root_user_override(request, ldap_conn, env_two_users_and_group):

    # Assert entries are not overriden
    ent.assert_passwd_by_name(
        'root',
        dict(name='root', uid=0, gid=0))

    ent.assert_passwd_by_uid(0, dict(name="root"))

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-u", "0",
                           "-g", "0",
                           "-n", "ov_user1",
                           "-c", "Overriden User 1",
                           "-h", "/home/ov/user1",
                           "-s", "/bin/ov_user1_shell"])

    subprocess.check_call(["sss_override", "user-add", "user2",
                           "-u", "10020",
                           "-g", "20020",
                           "-n", "root",
                           "-c", "Overriden User 2",
                           "-h", "/home/ov/user2",
                           "-s", "/bin/ov_user2_shell"])

    # Restart SSSD so the override might take effect
    restart_sssd()


def test_root_user_override(ldap_conn, env_root_user_override):
    """Test entries are not overriden to root"""

    # Override does not have to happen completly, trying to set uid or gid
    # to 0 is simply ignored.
    ent.assert_passwd_by_name(
        'ov_user1',
        dict(name='ov_user1', passwd='*', uid=10001, gid=20001,
             gecos='Overriden User 1',
             dir='/home/ov/user1',
             shell='/bin/ov_user1_shell'))

    # We can create override with name root. This test is just for tracking
    # that this particular behavior won't change.
    ent.assert_passwd_by_name(
        'user2',
        dict(name='root', passwd='*', uid=10020, gid=20020,
             gecos='Overriden User 2',
             dir='/home/ov/user2',
             shell='/bin/ov_user2_shell'))

    ent.assert_passwd_by_uid(0, dict(name="root"))


#
# Override replaces previous override
#


@pytest.fixture
def env_replace_user_override(request, ldap_conn):

    prepare_sssd(request, ldap_conn)

    # Add entries
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 10001, 20001,
                      gecos='User Number 1',
                      loginShell='/bin/user1_shell',
                      homeDirectory='/home/user1')

    create_ldap_fixture(request, ldap_conn, ent_list)

    # Assert entries are not overriden
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=10001, gid=20001,
             gecos='User Number 1',
             dir='/home/user1',
             shell='/bin/user1_shell'))

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-u", "10010",
                           "-g", "20010",
                           "-n", "ov_user1",
                           "-c", "Overriden User 1",
                           "-h", "/home/ov/user1",
                           "-s", "/bin/ov_user1_shell"])

    # Restart SSSD so the override might take effect
    restart_sssd()

    # Assert entries are overriden
    ent.assert_passwd_by_name(
        'user1',
        dict(name='ov_user1', passwd='*', uid=10010, gid=20010,
             gecos='Overriden User 1',
             dir='/home/ov/user1',
             shell='/bin/ov_user1_shell'))

    # Override of override
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-u", "10100",
                           "-g", "20100",
                           "-n", "ov2_user1",
                           "-c", "Overriden2 User 1",
                           "-h", "/home/ov2/user1",
                           "-s", "/bin/ov2_user1_shell"])

    # Restart SSSD so the override might take effect
    restart_sssd()


def test_replace_user_override(ldap_conn, env_replace_user_override):

    user = dict(name='ov2_user1', passwd='*', uid=10100, gid=20100,
                gecos='Overriden2 User 1',
                dir='/home/ov2/user1',
                shell='/bin/ov2_user1_shell')

    ent.assert_passwd_by_name('ov2_user1', user)
    ent.assert_passwd_by_name('ov2_user1@LDAP', user)

    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user1')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user1@LDAP')


#
# Override removal
#


@pytest.fixture
def env_remove_user_override(request, ldap_conn,
                             env_two_users_and_group_overriden):

    # Drop all overrides
    subprocess.check_call(["sss_override", "user-del", "user1"])
    subprocess.check_call(["sss_override", "user-del", "user2@LDAP"])

    # Avoid hitting memory cache
    time.sleep(2)


def test_remove_user_override(ldap_conn, env_remove_user_override):

    # Test entries are not overriden
    assert_user_default()


#
# Override import/export
#


@pytest.fixture
def env_imp_exp_user_override(request, ldap_conn,
                              env_two_users_and_group_overriden):

    # Export overrides
    subprocess.check_call(["sss_override", "user-export", OVERRIDE_FILENAME])

    # Drop all overrides
    subprocess.check_call(["sss_override", "user-del", "user1"])
    subprocess.check_call(["sss_override", "user-del", "user2@LDAP"])

    # Avoid hitting memory cache
    time.sleep(2)

    # Assert entries are not overridden
    assert_user_default()

    # Import overrides
    subprocess.check_call(["sss_override", "user-import",
                           OVERRIDE_FILENAME])
    restart_sssd()


def test_imp_exp_user_override(ldap_conn, env_imp_exp_user_override):

    assert_user_overriden()


# Regression test for bug 3179


def test_imp_exp_user_override_noname(ldap_conn,
                                      env_two_users_and_group):

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-u", "10010",
                           "-g", "20010",
                           "-c", "Overriden User 1",
                           "-h", "/home/ov/user1",
                           "-s", "/bin/ov_user1_shell"])

    subprocess.check_call(["sss_override", "user-add", "user2@LDAP",
                           "-u", "10020",
                           "-g", "20020",
                           "-c", "Overriden User 2",
                           "-h", "/home/ov/user2",
                           "-s", "/bin/ov_user2_shell"])

    # Restart SSSD so the override might take effect
    restart_sssd()

    # Assert entries are overriden
    assert_user_overriden(override_name=False)

    # Export overrides
    subprocess.check_call(["sss_override", "user-export", OVERRIDE_FILENAME])

    # Drop all overrides
    subprocess.check_call(["sss_override", "user-del", "user1"])
    subprocess.check_call(["sss_override", "user-del", "user2@LDAP"])

    # Avoid hitting memory cache
    time.sleep(2)

    # Assert entries are not overridden
    assert_user_default()

    # Import overrides
    subprocess.check_call(["sss_override", "user-import",
                           OVERRIDE_FILENAME])
    restart_sssd()

    assert_user_overriden(override_name=False)


#
# Override user-show
#


@pytest.fixture
def env_show_user_override(request, ldap_conn,
                           env_two_users_and_group_overriden):
    pass


def test_show_user_override(ldap_conn, env_show_user_override):

    out = check_output(['sss_override', 'user-show', 'user1']).decode('utf-8')
    assert out == "user1@LDAP:ov_user1:10010:20010:Overriden User 1:"\
                  "/home/ov/user1:/bin/ov_user1_shell:\n"

    out = check_output(['sss_override', 'user-show',
                        'user2@LDAP']).decode('utf-8')
    assert out == "user2@LDAP:ov_user2:10020:20020:Overriden User 2:"\
                  "/home/ov/user2:/bin/ov_user2_shell:\n"

    # Return error on non-existing user
    ret = subprocess.call(['sss_override', 'user-show', 'nonexisting_user'])
    assert ret == 1


#
# Override user-find
#


@pytest.fixture
def env_find_user_override(request, ldap_conn,
                           env_two_users_and_group_overriden):
    pass


def test_find_user_override(ldap_conn, env_find_user_override):

    out = check_output(['sss_override', 'user-find']).decode('utf-8')

    # Expected override of users
    exp_usr_ovrd = ['user1@LDAP:ov_user1:10010:20010:Overriden User 1:'
                    '/home/ov/user1:/bin/ov_user1_shell:',
                    'user2@LDAP:ov_user2:10020:20020:Overriden User 2:'
                    '/home/ov/user2:/bin/ov_user2_shell:']

    assert set(out.splitlines()) == set(exp_usr_ovrd)

    out = check_output(['sss_override', 'user-find', '--domain=LDAP'])

    assert set(out.decode('utf-8').splitlines()) == set(exp_usr_ovrd)

    # Unexpected parameter is reported
    ret = subprocess.call(['sss_override', 'user-find', 'PARAM'])
    assert ret == 1


#
# Group tests
#


#
# Common group asserts
#

def assert_group_overriden(override_name=True):

    # Assert entries are overridden
    empty_group = dict(gid=3002, mem=ent.contains_only())
    group = dict(gid=3001, mem=ent.contains_only("user1", "user2"))

    ent.assert_group_by_name("group", group)
    ent.assert_group_by_name("group@LDAP", group)

    if override_name:
        ent.assert_group_by_name("ov_group", group)
        ent.assert_group_by_name("ov_group@LDAP", group)

    ent.assert_group_by_name("empty_group", empty_group)
    ent.assert_group_by_name("empty_group@LDAP", empty_group)

    if override_name:
        ent.assert_group_by_name("ov_empty_group", empty_group)
        ent.assert_group_by_name("ov_empty_group@LDAP", empty_group)


def assert_group_default():

    # Assert entries are not overridden
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_group')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_group@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_empty_group')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_empty_group@LDAP')

    empty_group = dict(gid=2002, mem=ent.contains_only())
    group = dict(gid=2001, mem=ent.contains_only("user1", "user2"))

    ent.assert_group_by_name("group", group)
    ent.assert_group_by_name("group@LDAP", group)
    ent.assert_group_by_name("empty_group", empty_group)
    ent.assert_group_by_name("empty_group@LDAP", empty_group)


#
# Common fixtures for groups
#


@pytest.fixture
def env_group_basic(request, ldap_conn):
    prepare_sssd(request, ldap_conn)

    # Add entries
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 10001, 20001,
                      gecos='User Number 1',
                      loginShell='/bin/user1_shell',
                      homeDirectory='/home/user1')

    ent_list.add_user("user2", 10002, 20001,
                      gecos='User Number 2',
                      loginShell='/bin/user2_shell',
                      homeDirectory='/home/user2')

    ent_list.add_group("group", 2001,
                       ["user2", "user1"])
    ent_list.add_group("empty_group", 2002, [])

    create_ldap_fixture(request, ldap_conn, ent_list)

    # Assert entries are not overriden
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_group')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_group@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_empty_group')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_empty_group@LDAP')


@pytest.fixture
def env_group_override(request, ldap_conn, env_group_basic):

    # Override
    subprocess.check_call(["sss_override", "group-add", "group",
                           "-n", "ov_group",
                           "-g", "3001"])

    subprocess.check_call(["sss_override", "group-add", "empty_group@LDAP",
                           "--name", "ov_empty_group",
                           "--gid", "3002"])

    # Restart SSSD so the override might take effect
    restart_sssd()

    # Assert entries are overridden
    assert_group_overriden()


#
# Simple group override
#


@pytest.fixture
def env_simple_group_override(request, ldap_conn, env_group_basic):

    # Override
    subprocess.check_call(["sss_override", "group-add", "group",
                           "-n", "ov_group",
                           "-g", "3001"])

    subprocess.check_call(["sss_override", "group-add", "empty_group@LDAP",
                           "--name", "ov_empty_group",
                           "--gid", "3002"])

    # Restart SSSD so the override might take effect
    restart_sssd()


def test_simple_group_override(ldap_conn, env_simple_group_override):
    """Test entries are overriden"""

    assert_group_overriden()


#
# Root group override
#


@pytest.fixture
def env_root_group_override(request, ldap_conn, env_group_basic):

    # Override
    subprocess.check_call(["sss_override", "group-add", "group",
                           "-n", "ov_group",
                           "-g", "0"])

    subprocess.check_call(["sss_override", "group-add", "empty_group@LDAP",
                           "--name", "ov_empty_group",
                           "--gid", "0"])

    # Restart SSSD so the override might take effect
    restart_sssd()


def test_root_group_override(ldap_conn, env_root_group_override):
    """Test entries are overriden"""

    group = dict(gid=2001, mem=ent.contains_only("user1", "user2"))
    empty_group = dict(gid=2002, mem=ent.contains_only())

    ent.assert_group_by_name("group", group)
    ent.assert_group_by_name("ov_group", group)
    ent.assert_group_by_name("group@LDAP", group)
    ent.assert_group_by_name("ov_group@LDAP", group)
    ent.assert_group_by_name("empty_group", empty_group)
    ent.assert_group_by_name("ov_empty_group", empty_group)
    ent.assert_group_by_name("empty_group@LDAP", empty_group)
    ent.assert_group_by_name("ov_empty_group@LDAP", empty_group)


#
# Replace group override
#


@pytest.fixture
def env_replace_group_override(request, ldap_conn, env_group_override):

    # Override of override
    subprocess.check_call(["sss_override", "group-add", "group",
                           "-n", "ov2_group",
                           "-g", "4001"])

    subprocess.check_call(["sss_override", "group-add", "empty_group@LDAP",
                           "--name", "ov2_empty_group",
                           "--gid", "4002"])

    # Restart SSSD so the override might take effect
    restart_sssd()


def test_replace_group_override(ldap_conn, env_replace_group_override):

    # Test overrides are overridden
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_group')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_group@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_empty_group')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_empty_group@LDAP')

    group = dict(gid=4001, mem=ent.contains_only("user1", "user2"))
    empty_group = dict(gid=4002, mem=ent.contains_only())

    ent.assert_group_by_name("group", group)
    ent.assert_group_by_name("ov2_group", group)
    ent.assert_group_by_name("group@LDAP", group)
    ent.assert_group_by_name("ov2_group@LDAP", group)

    ent.assert_group_by_name("empty_group", empty_group)
    ent.assert_group_by_name("empty_group@LDAP", empty_group)
    ent.assert_group_by_name("ov2_empty_group", empty_group)
    ent.assert_group_by_name("ov2_empty_group@LDAP", empty_group)


#
# Remove group override
#


@pytest.fixture
def env_remove_group_override(request, ldap_conn, env_group_override):

    # Drop all overrides
    subprocess.check_call(["sss_override", "group-del", "group"])
    subprocess.check_call(["sss_override", "group-del", "empty_group@LDAP"])

    # Avoid hitting memory cache
    time.sleep(2)


def test_remove_group_override(ldap_conn, env_remove_group_override):

    # Test overrides were dropped
    assert_group_default()


#
# Override group import/export
#


@pytest.fixture
def env_imp_exp_group_override(request, ldap_conn, env_group_override):

    # Export overrides
    subprocess.check_call(["sss_override", "group-export",
                           OVERRIDE_FILENAME])

    # Drop all overrides
    subprocess.check_call(["sss_override", "group-del", "group"])
    subprocess.check_call(["sss_override", "group-del", "empty_group@LDAP"])

    # Avoid hitting memory cache
    time.sleep(2)

    assert_group_default()

    # Import overrides
    subprocess.check_call(["sss_override", "group-import",
                           OVERRIDE_FILENAME])
    restart_sssd()


def test_imp_exp_group_override(ldap_conn, env_imp_exp_group_override):

    assert_group_overriden()


# Regression test for bug 3179


def test_imp_exp_group_override_noname(ldap_conn, env_group_basic):

    # Override - do not use -n here)
    subprocess.check_call(["sss_override", "group-add", "group",
                           "-g", "3001"])

    subprocess.check_call(["sss_override", "group-add", "empty_group@LDAP",
                           "--gid", "3002"])

    # Restart SSSD so the override might take effect
    restart_sssd()

    # Assert entries are overridden
    assert_group_overriden(override_name=False)

    # Export overrides
    subprocess.check_call(["sss_override", "group-export",
                           OVERRIDE_FILENAME])

    # Drop all overrides
    subprocess.check_call(["sss_override", "group-del", "group"])
    subprocess.check_call(["sss_override", "group-del", "empty_group@LDAP"])

    # Avoid hitting memory cache
    time.sleep(2)

    assert_group_default()

    # Import overrides
    subprocess.check_call(["sss_override", "group-import",
                           OVERRIDE_FILENAME])
    restart_sssd()

    assert_group_overriden(override_name=False)


# Regression test for bug #2802
# sss_override segfaults when accidentally adding --help flag to some commands


@pytest.fixture
def env_regr_2802_override(request, ldap_conn):

    prepare_sssd(request, ldap_conn)


def test_regr_2802_override(ldap_conn, env_regr_2802_override):

    subprocess.check_call(["sss_override", "user-del", "--help"])


# Regression test for bug #2757
# sss_override does not work correctly when 'use_fully_qualified_names = True'


@pytest.fixture
def env_regr_2757_override(request, ldap_conn):

    prepare_sssd(request, ldap_conn, use_fully_qualified_names=True)

    # Add entries
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 10001, 20001)

    create_ldap_fixture(request, ldap_conn, ent_list)

    # Assert entries are not overridden
    ent.assert_passwd_by_name(
        'user1@LDAP',
        dict(name='user1@LDAP', passwd='*', uid=10001, gid=20001))
    with pytest.raises(KeyError):
        pwd.getpwnam('alias1')
    with pytest.raises(KeyError):
        pwd.getpwnam('alias1@LDAP')

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1@LDAP",
                           "-n", "alias1"])
    restart_sssd()


def test_regr_2757_override(ldap_conn, env_regr_2757_override):

    # Assert entries are overridden
    ent.assert_passwd_by_name(
        'user1@LDAP',
        dict(name='alias1@LDAP', passwd='*', uid=10001, gid=20001))
    ent.assert_passwd_by_name(
        'alias1@LDAP',
        dict(name='alias1@LDAP', passwd='*', uid=10001, gid=20001))

    with pytest.raises(KeyError):
        pwd.getpwnam('user1')
    with pytest.raises(KeyError):
        pwd.getpwnam('alias1')


# Regression test for bug #2790
# sss_override --name doesn't work with RFC2307 and ghost users


@pytest.fixture
def env_regr_2790_override(request, ldap_conn):

    prepare_sssd(request, ldap_conn)

    # Add entries
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 10001, 20001)
    ent_list.add_user("user2", 10002, 20002)
    ent_list.add_group("group1", 2001,
                       ["user1", "user2"])
    ent_list.add_group("group2", 2002,
                       ["user2"])

    create_ldap_fixture(request, ldap_conn, ent_list)

    # Assert entries are not overridden
    with pytest.raises(KeyError):
        pwd.getpwnam('alias1')
    with pytest.raises(KeyError):
        pwd.getpwnam('alias1@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('alias2')
    with pytest.raises(KeyError):
        pwd.getpwnam('alias2@LDAP')

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-n", "alias1"])
    subprocess.check_call(["sss_override", "user-add", "user2",
                           "-n", "alias2"])

    restart_sssd()


def test_regr_2790_override(ldap_conn, env_regr_2790_override):

    # Assert entries are overridden
    (res, errno, grp_list) = sssd_id.get_user_groups("alias1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1 %d" % errno
    assert sorted(grp_list) == sorted(["20001", "group1"])

    (res, errno, grp_list) = sssd_id.get_user_groups("alias2")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user2 %d" % errno
    assert sorted(grp_list) == sorted(["20002", "group1", "group2"])


# Test fully qualified and case-insensitive names
@pytest.fixture
def env_mix_cased_name_override(request, ldap_conn):
    """Setup test for mixed case names"""

    prepare_sssd(request, ldap_conn, True, False)

    # Add entries
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 10001, 20001)
    ent_list.add_user("uSeR2", 10002, 20002)

    create_ldap_fixture(request, ldap_conn, ent_list)

    pwd.getpwnam('user1@LDAP')
    pwd.getpwnam('user2@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user1@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user2@LDAP')

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1@LDAP",
                           "-u", "10010",
                           "-g", "20010",
                           "-n", "ov_user1",
                           "-c", "Overriden User 1",
                           "-h", "/home/ov/user1",
                           "-s", "/bin/ov_user1_shell"])

    subprocess.check_call(["sss_override", "user-add", "user2@LDAP",
                           "-u", "10020",
                           "-g", "20020",
                           "-n", "ov_user2",
                           "-c", "Overriden User 2",
                           "-h", "/home/ov/user2",
                           "-s", "/bin/ov_user2_shell"])

    restart_sssd()


def test_mix_cased_name_override(ldap_conn, env_mix_cased_name_override):
    """Test if names with upper and lower case letter are overridden"""

    # Assert entries are overridden
    user1 = dict(name='ov_user1@LDAP', passwd='*', uid=10010, gid=20010,
                 gecos='Overriden User 1',
                 dir='/home/ov/user1',
                 shell='/bin/ov_user1_shell')

    user2 = dict(name='ov_user2@LDAP', passwd='*', uid=10020, gid=20020,
                 gecos='Overriden User 2',
                 dir='/home/ov/user2',
                 shell='/bin/ov_user2_shell')

    ent.assert_passwd_by_name('user1@LDAP', user1)
    ent.assert_passwd_by_name('ov_user1@LDAP', user1)

    ent.assert_passwd_by_name('user2@LDAP', user2)
    ent.assert_passwd_by_name('ov_user2@LDAP', user2)


# Test with override_homedir option
@pytest.fixture
def env_override_homedir_option(request, ldap_conn):
    """Setup test for override_homedir option and overrides"""

    prepare_sssd(request, ldap_conn, override_homedir_option=True)

    # Add entries
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 10001, 20001)
    ent_list.add_user("user2", 10002, 20002)

    create_ldap_fixture(request, ldap_conn, ent_list)

    pwd.getpwnam('user1@LDAP')
    pwd.getpwnam('user2@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user1@LDAP')
    with pytest.raises(KeyError):
        pwd.getpwnam('ov_user2@LDAP')

    # Override
    subprocess.check_call(["sss_override", "user-add", "user1@LDAP",
                           "-u", "10010",
                           "-g", "20010",
                           "-n", "ov_user1",
                           "-c", "Overriden User 1",
                           # no homedir override
                           "-s", "/bin/ov_user1_shell"])

    subprocess.check_call(["sss_override", "user-add", "user2@LDAP",
                           "-u", "10020",
                           "-g", "20020",
                           "-n", "ov_user2",
                           "-c", "Overriden User 2",
                           "-h", "/home/ov/user2",
                           "-s", "/bin/ov_user2_shell"])

    restart_sssd()


def test_override_homedir_option(ldap_conn, env_override_homedir_option):
    """Test if overrides will overwrite override_homedir option"""

    # Assert entries are overridden, user1 has no homedir override and
    # override_homedir option should be used, user2 has a homedir override
    # which should be used.
    user1 = dict(name='ov_user1', passwd='*', uid=10010, gid=20010,
                 gecos='Overriden User 1',
                 dir='/home/ov_option/ov_user1',
                 shell='/bin/ov_user1_shell')

    user2 = dict(name='ov_user2', passwd='*', uid=10020, gid=20020,
                 gecos='Overriden User 2',
                 dir='/home/ov/user2',
                 shell='/bin/ov_user2_shell')

    ent.assert_passwd_by_name('user1@LDAP', user1)
    ent.assert_passwd_by_name('ov_user1@LDAP', user1)
    ent.assert_passwd_by_name('user1', user1)
    ent.assert_passwd_by_name('ov_user1', user1)

    ent.assert_passwd_by_name('user2@LDAP', user2)
    ent.assert_passwd_by_name('ov_user2@LDAP', user2)
    ent.assert_passwd_by_name('user2', user2)
    ent.assert_passwd_by_name('ov_user2', user2)
