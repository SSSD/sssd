#
# Infopipe integration test
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

from __future__ import print_function

import os
import stat
import pwd
import signal
import subprocess
import errno
import time
import ldap
import ldap.modlist
import pytest
import dbus

import config
import ds_openldap
import ldap_ent
from util import unindent, get_call_output

LDAP_BASE_DN = "dc=example,dc=com"
INTERACTIVE_TIMEOUT = 4


class DbusDaemon(object):
    def __init__(self):
        self.pid = 0

    def start(self):
        """Start the SSSD process"""
        assert self.pid == 0

        dbus_config_path = config.SYSCONFDIR + "/dbus-1/cwrap-dbus-system.conf"
        dbus_commands = [
            ["dbus-daemon", "--config-file", dbus_config_path,
             "--nosyslog", "--fork"],
            ["dbus-daemon", "--config-file", dbus_config_path, "--fork"],
        ]
        dbus_started = False
        for dbus_command in dbus_commands:
            try:
                if subprocess.call(dbus_command) == 0:
                    dbus_started = True
                    break
                else:
                    print("start failed for %s" % " ".join(dbus_command))
            except OSError as ex:
                if ex.errno == errno.ENOENT:
                    print("%s does not exist" % (dbus_command[0]))
                    pass

        if not dbus_started:
            raise Exception("dbus-daemon start failed")
        dbus_pid_path = config.RUNSTATEDIR + "/dbus/messagebus.pid"
        # wait 10 seconds for pidfile
        wait_time = 10
        for _ in range(wait_time * 10):
            if os.path.isfile(dbus_pid_path):
                break
            time.sleep(.1)

        assert os.path.isfile(dbus_pid_path)
        with open(dbus_pid_path, "r") as pid_file:
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

        # dbus-daemon 1.2.24 does not clean pid file after itself
        try:
            os.unlink(config.RUNSTATEDIR + "/dbus/messagebus.pid")
        except OSError as ex:
            if ex.errno != errno.ENOENT:
                raise


@pytest.fixture(scope="module")
def dbus_system_bus(request):
    dbus_daemon = DbusDaemon()
    dbus_daemon.start()

    def cleanup_dbus_process():
        dbus_daemon.stop()
    request.addfinalizer(cleanup_dbus_process)

    return dbus.SystemBus()


@pytest.fixture(scope="module")
def ds_inst(request):
    """LDAP server instance fixture"""
    ds_inst = ds_openldap.DSOpenLDAP(
        config.PREFIX, 10389, LDAP_BASE_DN,
        "cn=admin", "Secret123"
    )

    try:
        ds_inst.setup()
    except:
        ds_inst.teardown()
        raise
    request.addfinalizer(ds_inst.teardown)

    return ds_inst


@pytest.fixture(scope="module")
def ldap_conn(request, ds_inst):
    """LDAP server connection fixture"""
    ldap_conn = ds_inst.bind()
    ldap_conn.ds_inst = ds_inst
    request.addfinalizer(ldap_conn.unbind_s)
    return ldap_conn


def create_ldap_entries(ldap_conn, ent_list=None):
    """Add LDAP entries from ent_list"""
    if ent_list is not None:
        for entry in ent_list:
            ldap_conn.add_s(entry[0], entry[1])


def cleanup_ldap_entries(ldap_conn, ent_list=None):
    """Remove LDAP entries added by create_ldap_entries"""
    if ent_list is None:
        for ou in ("Users", "Groups", "Netgroups", "Services", "Policies"):
            for entry in ldap_conn.search_s("ou=" + ou + "," +
                                            ldap_conn.ds_inst.base_dn,
                                            ldap.SCOPE_ONELEVEL,
                                            attrlist=[]):
                ldap_conn.delete_s(entry[0])
    else:
        for entry in ent_list:
            ldap_conn.delete_s(entry[0])


def create_ldap_cleanup(request, ldap_conn, ent_list=None):
    """Add teardown for removing all user/group LDAP entries"""
    request.addfinalizer(lambda: cleanup_ldap_entries(ldap_conn, ent_list))


def create_ldap_fixture(request, ldap_conn, ent_list=None):
    """Add LDAP entries and add teardown for removing them"""
    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, ent_list)


SCHEMA_RFC2307 = "rfc2307"
SCHEMA_RFC2307_BIS = "rfc2307bis"


def format_basic_conf(ldap_conn, schema):
    """Format a basic SSSD configuration"""
    schema_conf = "ldap_schema         = " + schema + "\n"
    if schema == SCHEMA_RFC2307_BIS:
        schema_conf += "ldap_group_object_class = groupOfNames\n"

    valgrind_cmd = "valgrind --log-file=%s/valgrind_ifp.log" % config.LOG_PATH
    ifp_command = "%s %s/sssd/sssd_ifp " % (valgrind_cmd, config.LIBEXEC_PATH)
    return unindent("""\
        [sssd]
        debug_level         = 0xffff
        domains             = LDAP, app
        services            = nss, ifp
        enable_files_domain = false

        [nss]
        memcache_timeout    = 0

        [ifp]
        # it need to be executed with valgrind because there is a problem
        # problem with "ifp" + client regristration in monitor
        # There is not such problem in 1st test. Just in following tests.
        command = {ifp_command} --uid 0 --gid 0 --debug-to-files

        [domain/LDAP]
        {schema_conf}
        id_provider         = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}

        [application/app]
        inherit_from = LDAP
    """).format(**locals())


def format_interactive_conf(ldap_conn, schema):
    """Format an SSSD configuration with all caches refreshing in 4 seconds"""
    return \
        format_basic_conf(ldap_conn, schema) + \
        unindent("""
            [nss]
            memcache_timeout                    = 0
            entry_negative_timeout              = 0

            [domain/LDAP]
            ldap_purge_cache_timeout            = 1
            entry_cache_timeout                 = {0}
        """).format(INTERACTIVE_TIMEOUT)


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
            except:
                break
            time.sleep(1)
    except:
        pass
    for path in os.listdir(config.DB_PATH):
        os.unlink(config.DB_PATH + "/" + path)
    for path in os.listdir(config.MCACHE_PATH):
        os.unlink(config.MCACHE_PATH + "/" + path)


def create_sssd_cleanup(request):
    """Add teardown for stopping SSSD and removing its state"""
    request.addfinalizer(cleanup_sssd_process)


def create_sssd_fixture(request):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process()
    create_sssd_cleanup(request)


@pytest.fixture
def sanity_rfc2307(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)

    ent_list.add_group("group1", 2001)
    ent_list.add_group("group2", 2002)
    ent_list.add_group("group3", 2003)

    ent_list.add_group("empty_group", 2010)

    ent_list.add_group("single_user_group", 2011, ["user1"])
    ent_list.add_group("two_user_group", 2012, ["user1", "user2"])

    create_ldap_fixture(request, ldap_conn, ent_list)

    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def simple_rfc2307(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user('usr\\\\001', 181818, 181818)
    ent_list.add_group("group1", 181818)
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_ping_raw(dbus_system_bus, ldap_conn, simple_rfc2307):
    # test with disabled introspection
    sssd_obj = dbus_system_bus.get_object('org.freedesktop.sssd.infopipe',
                                          '/org/freedesktop/sssd/infopipe',
                                          introspect=False)
    sssd_interface = dbus.Interface(sssd_obj, 'org.freedesktop.sssd.infopipe')

    # test missing parameter
    with pytest.raises(dbus.exceptions.DBusException) as exc_info:
        sssd_interface.Ping()
    assert exc_info.errisinstance(dbus.exceptions.DBusException)

    ex = exc_info.value
    assert ex.get_dbus_name() == 'org.freedesktop.DBus.Error.InvalidArgs'
    assert ex.get_dbus_message() == 'Argument 0 is specified to be of type ' \
                                    '"string", but is actually of type ' \
                                    '"invalid"\n'

    # test wrong parameter type
    with pytest.raises(dbus.exceptions.DBusException) as exc_info:
        sssd_interface.Ping(1)
    assert exc_info.errisinstance(dbus.exceptions.DBusException)

    ex = exc_info.value
    assert ex.get_dbus_name() == 'org.freedesktop.DBus.Error.InvalidArgs'
    assert ex.get_dbus_message() == 'Argument 0 is specified to be of type ' \
                                    '"string", but is actually of type ' \
                                    '"int32"\n'

    # test wrong parameter value
    with pytest.raises(dbus.exceptions.DBusException) as exc_info:
        sssd_interface.Ping('test')
    assert exc_info.errisinstance(dbus.exceptions.DBusException)

    ex = exc_info.value
    assert ex.get_dbus_name() == 'org.freedesktop.DBus.Error.InvalidArgs'
    assert ex.get_dbus_message() == 'Ping() only accepts "ping" as a param\n'

    # positive test
    ret = sssd_interface.Ping('ping')
    assert ret == "PONG"

    # test case insensitive input
    ret = sssd_interface.Ping('PinG')
    assert ret == "PONG"

    ret = sssd_interface.Ping('PING')
    assert ret == "PONG"


def test_ping_introspection(dbus_system_bus, ldap_conn, simple_rfc2307):
    sssd_obj = dbus_system_bus.get_object('org.freedesktop.sssd.infopipe',
                                          '/org/freedesktop/sssd/infopipe')
    sssd_interface = dbus.Interface(sssd_obj, 'org.freedesktop.sssd.infopipe')

    # test missing parameter
    with pytest.raises(TypeError) as exc_info:
        sssd_interface.Ping()
    assert exc_info.errisinstance(TypeError)

    ex = exc_info.value
    assert str(ex) == 'More items found in D-Bus signature than in Python ' \
                      'arguments'

    # test wrong parameter type
    with pytest.raises(TypeError) as exc_info:
        sssd_interface.Ping(1)
    assert exc_info.errisinstance(TypeError)

    ex = exc_info.value
    assert str(ex) == 'Expected a string or unicode object'

    # test wrong parameter value
    with pytest.raises(dbus.exceptions.DBusException) as exc_info:
        sssd_interface.Ping('test')
    assert exc_info.errisinstance(dbus.exceptions.DBusException)

    ex = exc_info.value
    assert ex.get_dbus_name() == 'org.freedesktop.DBus.Error.InvalidArgs'
    assert ex.get_dbus_message() == 'Ping() only accepts "ping" as a param\n'

    # positive test
    ret = sssd_interface.Ping('ping')
    assert ret == "PONG"

    # test case insensitive input
    ret = sssd_interface.Ping('PinG')
    assert ret == "PONG"

    ret = sssd_interface.Ping('PING')
    assert ret == "PONG"


def test_special_characters(dbus_system_bus, ldap_conn, simple_rfc2307):
    sssd_obj = dbus_system_bus.get_object('org.freedesktop.sssd.infopipe',
                                          '/org/freedesktop/sssd/infopipe')
    sssd_interface = dbus.Interface(sssd_obj, 'org.freedesktop.sssd.infopipe')

    attributes = ['name', 'uidNumber', 'gidNumber', 'gecos', 'homeDirectory',
                  'loginShell']
    expected = dict(name='usr\\001', uidNumber='181818', gidNumber='181818',
                    gecos='181818', homeDirectory='/home/usr\\\\001',
                    loginShell='/bin/bash')

    user_attrs = sssd_interface.GetUserAttr('usr\\001', attributes)
    assert user_attrs.signature == 'sv'
    assert user_attrs.variant_level == 0

    assert len(attributes) == len(user_attrs)
    assert sorted(attributes) == sorted(user_attrs.keys())

    # check values of attributes
    for attr in user_attrs:
        assert user_attrs[attr].signature == 's'
        assert user_attrs[attr].variant_level == 1
        assert user_attrs[attr][0] == expected[attr]


def test_get_user_attr(dbus_system_bus, ldap_conn, sanity_rfc2307):
    sssd_obj = dbus_system_bus.get_object('org.freedesktop.sssd.infopipe',
                                          '/org/freedesktop/sssd/infopipe')
    sssd_interface = dbus.Interface(sssd_obj, 'org.freedesktop.sssd.infopipe')

    # negative test
    with pytest.raises(dbus.exceptions.DBusException) as exc_info:
        sssd_interface.GetUserAttr('non_existent_user', ['name'])
    assert exc_info.errisinstance(dbus.exceptions.DBusException)

    ex = exc_info.value
    assert ex.get_dbus_name() == 'org.freedesktop.DBus.Error.Failed'
    assert ex.get_dbus_message() == 'No such user\n'

    # test 0 attributes
    user_attrs = sssd_interface.GetUserAttr('user1', [])

    assert user_attrs.signature == 'sv'
    assert user_attrs.variant_level == 0

    # expect empty sequence; len(user_attrs) == 0
    assert not user_attrs

    # positive test
    attributes = ['name', 'uidNumber', 'gidNumber', 'gecos', 'homeDirectory',
                  'loginShell']
    expected = dict(name='user1', uidNumber='1001', gidNumber='2001',
                    gecos='1001', homeDirectory='/home/user1',
                    loginShell='/bin/bash')
    user_attrs = sssd_interface.GetUserAttr('user1', attributes)

    assert user_attrs.signature == 'sv'
    assert user_attrs.variant_level == 0

    assert len(attributes) == len(user_attrs)
    assert sorted(attributes) == sorted(user_attrs.keys())

    # check values of attributes
    for attr in user_attrs:
        assert user_attrs[attr].signature == 's'
        assert user_attrs[attr].variant_level == 1
        assert user_attrs[attr][0] == expected[attr]


def test_get_user_groups(dbus_system_bus, ldap_conn, sanity_rfc2307):
    sssd_obj = dbus_system_bus.get_object('org.freedesktop.sssd.infopipe',
                                          '/org/freedesktop/sssd/infopipe')
    sssd_interface = dbus.Interface(sssd_obj, 'org.freedesktop.sssd.infopipe')

    # negative test
    with pytest.raises(dbus.exceptions.DBusException) as exc_info:
        sssd_interface.GetUserGroups('non_existent_user')
    assert exc_info.errisinstance(dbus.exceptions.DBusException)

    ex = exc_info.value
    assert ex.get_dbus_name() == 'org.freedesktop.DBus.Error.Failed'
    assert ex.get_dbus_message() == 'No such user\n'

    # the same test via nss responder
    with pytest.raises(KeyError):
        pwd.getpwnam("non_existent_user")

    # 0 groups
    res = sssd_interface.GetUserGroups('user3')
    assert res.signature == 's'
    assert res.variant_level == 0

    # expect empty sequence; len(res) == 0
    assert not res

    # single group
    res = sssd_interface.GetUserGroups('user2')
    assert res.signature == 's'
    assert res.variant_level == 0

    assert len(res) == 1
    assert res[0] == 'two_user_group'

    # more groups
    res = sssd_interface.GetUserGroups('user1')
    assert res.signature == 's'
    assert res.variant_level == 0

    assert len(res) == 2
    assert sorted(res) == ['single_user_group', 'two_user_group']


def test_sssctl_domain_list_app_domain(dbus_system_bus,
                                       ldap_conn,
                                       sanity_rfc2307):
    output = get_call_output(["sssctl", "domain-list"], subprocess.STDOUT)

    assert "Error" not in output
    assert output.find("LDAP") != -1
    assert output.find("app") != -1
