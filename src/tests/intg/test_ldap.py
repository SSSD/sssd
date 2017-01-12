#
# LDAP integration test
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
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
import stat
import pwd
import grp
import signal
import subprocess
import time
import ldap
import ldap.modlist
import pytest

import config
import ds_openldap
import ent
import ldap_ent
import sssd_id
import sssd_ldb
from util import unindent

LDAP_BASE_DN = "dc=example,dc=com"
INTERACTIVE_TIMEOUT = 4


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
    return unindent("""\
        [sssd]
        debug_level         = 0xffff
        domains             = LDAP
        services            = nss, pam

        [nss]
        debug_level         = 0xffff
        memcache_timeout    = 0
        entry_negative_timeout = 1

        [pam]
        debug_level         = 0xffff

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        debug_level         = 0xffff
        {schema_conf}
        id_provider         = ldap
        auth_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
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


def format_rfc2307bis_deref_conf(ldap_conn, schema):
    """Format an SSSD configuration with all caches refreshing in 4 seconds"""
    return \
        format_basic_conf(ldap_conn, schema) + \
        unindent("""
            [nss]
            memcache_timeout                    = 0
            entry_negative_timeout              = 0

            [domain/LDAP]
            entry_cache_timeout                 = {0}
            ldap_deref_threshold                = 1
        """).format(INTERACTIVE_TIMEOUT)


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
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
        pid_file = open(config.PIDFILE_PATH, "r")
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

    ent_list.add_group("two_user_group", 2012, ["user1", "user2"])

    ent_list.add_user("t(u)ser", 5000, 5001)
    ent_list.add_group("group(_u)ser1", 5001, ["t(u)ser"])
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


@pytest.fixture
def sanity_rfc2307_bis(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)

    ent_list.add_group_bis("group1", 2001)
    ent_list.add_group_bis("group2", 2002)
    ent_list.add_group_bis("group3", 2003)

    ent_list.add_group_bis("empty_group1", 2010)
    ent_list.add_group_bis("empty_group2", 2011)

    ent_list.add_group_bis("two_user_group", 2012, ["user1", "user2"])
    ent_list.add_group_bis("group_empty_group", 2013, [], ["empty_group1"])
    ent_list.add_group_bis("group_two_empty_groups", 2014,
                           [], ["empty_group1", "empty_group2"])
    ent_list.add_group_bis("one_user_group1", 2015, ["user1"])
    ent_list.add_group_bis("one_user_group2", 2016, ["user2"])
    ent_list.add_group_bis("group_one_user_group", 2017,
                           [], ["one_user_group1"])
    ent_list.add_group_bis("group_two_user_group", 2018,
                           [], ["two_user_group"])
    ent_list.add_group_bis("group_two_one_user_groups", 2019,
                           [], ["one_user_group1", "one_user_group2"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def expected_list_to_name_dict(entries):
    return dict((u["name"], u) for u in entries)


def test_regression_ticket2163(ldap_conn, simple_rfc2307):
    ent.assert_passwd_by_name(
        'usr\\001',
        dict(name='usr\\001', passwd='*', uid=181818, gid=181818,
             gecos='181818', shell='/bin/bash'))


def test_sanity_rfc2307(ldap_conn, sanity_rfc2307):
    passwd_pattern = expected_list_to_name_dict([
        dict(name='user1', passwd='*', uid=1001, gid=2001, gecos='1001',
             dir='/home/user1', shell='/bin/bash'),
        dict(name='user2', passwd='*', uid=1002, gid=2002, gecos='1002',
             dir='/home/user2', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=2003, gecos='1003',
             dir='/home/user3', shell='/bin/bash')
    ])
    ent.assert_each_passwd_by_name(passwd_pattern)

    group_pattern = expected_list_to_name_dict([
        dict(name='group1', passwd='*', gid=2001, mem=ent.contains_only()),
        dict(name='group2', passwd='*', gid=2002, mem=ent.contains_only()),
        dict(name='group3', passwd='*', gid=2003, mem=ent.contains_only()),
        dict(name='empty_group', passwd='*', gid=2010,
             mem=ent.contains_only()),
        dict(name='two_user_group', passwd='*', gid=2012,
             mem=ent.contains_only("user1", "user2"))
    ])
    ent.assert_each_group_by_name(group_pattern)

    with pytest.raises(KeyError):
        pwd.getpwnam("non_existent_user")
    with pytest.raises(KeyError):
        pwd.getpwuid(1)
    with pytest.raises(KeyError):
        grp.getgrnam("non_existent_group")
    with pytest.raises(KeyError):
        grp.getgrgid(1)


def test_sanity_rfc2307_bis(ldap_conn, sanity_rfc2307_bis):
    passwd_pattern = expected_list_to_name_dict([
        dict(name='user1', passwd='*', uid=1001, gid=2001, gecos='1001',
             dir='/home/user1', shell='/bin/bash'),
        dict(name='user2', passwd='*', uid=1002, gid=2002, gecos='1002',
             dir='/home/user2', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=2003, gecos='1003',
             dir='/home/user3', shell='/bin/bash')
    ])
    ent.assert_each_passwd_by_name(passwd_pattern)

    group_pattern = expected_list_to_name_dict([
        dict(name='group1', passwd='*', gid=2001, mem=ent.contains_only()),
        dict(name='group2', passwd='*', gid=2002, mem=ent.contains_only()),
        dict(name='group3', passwd='*', gid=2003, mem=ent.contains_only()),
        dict(name='empty_group1', passwd='*', gid=2010,
             mem=ent.contains_only()),
        dict(name='empty_group2', passwd='*', gid=2011,
             mem=ent.contains_only()),
        dict(name='two_user_group', passwd='*', gid=2012,
             mem=ent.contains_only("user1", "user2")),
        dict(name='group_empty_group', passwd='*', gid=2013,
             mem=ent.contains_only()),
        dict(name='group_two_empty_groups', passwd='*', gid=2014,
             mem=ent.contains_only()),
        dict(name='one_user_group1', passwd='*', gid=2015,
             mem=ent.contains_only("user1")),
        dict(name='one_user_group2', passwd='*', gid=2016,
             mem=ent.contains_only("user2")),
        dict(name='group_one_user_group', passwd='*', gid=2017,
             mem=ent.contains_only("user1")),
        dict(name='group_two_user_group', passwd='*', gid=2018,
             mem=ent.contains_only("user1", "user2")),
        dict(name='group_two_one_user_groups', passwd='*', gid=2019,
             mem=ent.contains_only("user1", "user2"))
    ])
    ent.assert_each_group_by_name(group_pattern)

    with pytest.raises(KeyError):
        pwd.getpwnam("non_existent_user")
    with pytest.raises(KeyError):
        pwd.getpwuid(1)
    with pytest.raises(KeyError):
        grp.getgrnam("non_existent_group")
    with pytest.raises(KeyError):
        grp.getgrgid(1)


@pytest.fixture
def refresh_after_cleanup_task(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)

    ent_list.add_group_bis("group1", 2001, ["user1"])
    ent_list.add_group_bis("group2", 2002, [], ["group1"])

    create_ldap_fixture(request, ldap_conn, ent_list)

    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [domain/LDAP]
            entry_cache_user_timeout = 1
            entry_cache_group_timeout = 5000
            ldap_purge_cache_timeout = 3
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_refresh_after_cleanup_task(ldap_conn, refresh_after_cleanup_task):
    """
    Regression test for ticket:
    https://fedorahosted.org/sssd/ticket/2676
    """
    ent.assert_group_by_name(
        "group2",
        dict(mem=ent.contains_only("user1")))

    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    time.sleep(15)

    ent.assert_group_by_name(
        "group2",
        dict(mem=ent.contains_only("user1")))


@pytest.fixture
def blank_rfc2307(request, ldap_conn):
    """Create blank RFC2307 directory fixture with interactive SSSD conf"""
    create_ldap_cleanup(request, ldap_conn)
    create_conf_fixture(request,
                        format_interactive_conf(ldap_conn, SCHEMA_RFC2307))
    create_sssd_fixture(request)


@pytest.fixture
def blank_rfc2307_bis(request, ldap_conn):
    """Create blank RFC2307bis directory fixture with interactive SSSD conf"""
    create_ldap_cleanup(request, ldap_conn)
    create_conf_fixture(request,
                        format_interactive_conf(ldap_conn, SCHEMA_RFC2307_BIS))
    create_sssd_fixture(request)


@pytest.fixture
def user_and_group_rfc2307(request, ldap_conn):
    """
    Create an RFC2307 directory fixture with interactive SSSD conf,
    one user and one group
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user", 1001, 2000)
    ent_list.add_group("group", 2001)
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request,
                        format_interactive_conf(ldap_conn, SCHEMA_RFC2307))
    create_sssd_fixture(request)
    return None


@pytest.fixture
def user_and_groups_rfc2307_bis(request, ldap_conn):
    """
    Create an RFC2307bis directory fixture with interactive SSSD conf,
    one user and two groups
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user", 1001, 2000)
    ent_list.add_group_bis("group1", 2001)
    ent_list.add_group_bis("group2", 2002)
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request,
                        format_interactive_conf(ldap_conn, SCHEMA_RFC2307_BIS))
    create_sssd_fixture(request)
    return None


@pytest.fixture
def rfc2307bis_deref_group_with_users(request, ldap_conn):
    """
    Create an RFC2307bis directory fixture with interactive SSSD conf,
    one user and two groups
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2000)
    ent_list.add_user("user2", 1001, 2000)
    ent_list.add_user("user3", 1001, 2000)
    ent_list.add_group_bis("group1", 20000, member_uids=("user1", "user2"))
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request,
                        format_rfc2307bis_deref_conf(
                            ldap_conn,
                            SCHEMA_RFC2307_BIS))
    create_sssd_fixture(request)
    return None


def test_ldap_group_dereference(ldap_conn, rfc2307bis_deref_group_with_users):
    ent.assert_group_by_name("group1",
                             dict(mem=ent.contains_only("user1", "user2")))


@pytest.fixture
def override_homedir(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_homedir_A", 1001, 2001,
                      homeDirectory="/home/A")
    ent_list.add_user("user_with_homedir_B", 1002, 2002,
                      homeDirectory="/home/B")
    ent_list.add_user("user_with_empty_homedir", 1003, 2003,
                      homeDirectory="")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [nss]
            override_homedir    = /home/B
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_override_homedir(override_homedir):
    """Test the effect of the "override_homedir" option"""
    passwd_pattern = expected_list_to_name_dict([
        dict(name="user_with_homedir_A", uid=1001, dir="/home/B"),
        dict(name="user_with_homedir_B", uid=1002, dir="/home/B"),
        dict(name="user_with_empty_homedir", uid=1003, dir="/home/B")
    ])

    ent.assert_each_passwd_by_name(passwd_pattern)


@pytest.fixture
def fallback_homedir(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_homedir_A", 1001, 2001,
                      homeDirectory="/home/A")
    ent_list.add_user("user_with_homedir_B", 1002, 2002,
                      homeDirectory="/home/B")
    ent_list.add_user("user_with_empty_homedir", 1003, 2003,
                      homeDirectory="")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [nss]
            fallback_homedir    = /home/B
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_fallback_homedir(fallback_homedir):
    """Test the effect of the "fallback_homedir" option"""
    passwd_pattern = expected_list_to_name_dict([
        dict(name="user_with_homedir_A", uid=1001, dir="/home/A"),
        dict(name="user_with_homedir_B", uid=1002, dir="/home/B"),
        dict(name="user_with_empty_homedir", uid=1003, dir="/home/B")
    ])

    ent.assert_each_passwd_by_name(passwd_pattern)


@pytest.fixture
def override_shell(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_shell_A", 1001, 2001,
                      loginShell="/bin/A")
    ent_list.add_user("user_with_shell_B", 1002, 2002,
                      loginShell="/bin/B")
    ent_list.add_user("user_with_empty_shell", 1003, 2003,
                      loginShell="")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [nss]
            override_shell      = /bin/B
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_override_shell(override_shell):
    """Test the effect of the "override_shell" option"""
    passwd_pattern = expected_list_to_name_dict([
        dict(name="user_with_shell_A", uid=1001, shell="/bin/B"),
        dict(name="user_with_shell_B", uid=1002, shell="/bin/B"),
        dict(name="user_with_empty_shell", uid=1003, shell="/bin/B")
    ])

    ent.assert_each_passwd_by_name(passwd_pattern)


@pytest.fixture
def shell_fallback(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_sh_shell", 1001, 2001,
                      loginShell="/bin/sh")
    ent_list.add_user("user_with_not_installed_shell", 1002, 2002,
                      loginShell="/bin/not_installed")
    ent_list.add_user("user_with_empty_shell", 1003, 2003,
                      loginShell="")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [nss]
            shell_fallback      = /bin/fallback
            allowed_shells      = /bin/not_installed
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_shell_fallback(shell_fallback):
    """Test the effect of the "shell_fallback" option"""
    passwd_pattern = expected_list_to_name_dict([
        dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
        dict(name="user_with_not_installed_shell", uid=1002,
             shell="/bin/fallback"),
        dict(name="user_with_empty_shell", uid=1003, shell="")
    ])

    ent.assert_each_passwd_by_name(passwd_pattern)


@pytest.fixture
def default_shell(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_sh_shell", 1001, 2001,
                      loginShell="/bin/sh")
    ent_list.add_user("user_with_not_installed_shell", 1002, 2002,
                      loginShell="/bin/not_installed")
    ent_list.add_user("user_with_empty_shell", 1003, 2003,
                      loginShell="")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [nss]
            default_shell       = /bin/default
            allowed_shells      = /bin/default, /bin/not_installed
            shell_fallback      = /bin/fallback
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_default_shell(default_shell):
    """Test the effect of the "default_shell" option"""
    passwd_pattern = expected_list_to_name_dict([
        dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
        dict(name="user_with_not_installed_shell", uid=1002,
             shell="/bin/fallback"),
        dict(name="user_with_empty_shell", uid=1003,
             shell="/bin/default")
    ])

    ent.assert_each_passwd_by_name(passwd_pattern)


@pytest.fixture
def vetoed_shells(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user_with_sh_shell", 1001, 2001,
                      loginShell="/bin/sh")
    ent_list.add_user("user_with_vetoed_shell", 1002, 2002,
                      loginShell="/bin/vetoed")
    ent_list.add_user("user_with_empty_shell", 1003, 2003,
                      loginShell="")
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [nss]
            default_shell       = /bin/default
            vetoed_shells       = /bin/vetoed
            shell_fallback      = /bin/fallback
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_vetoed_shells(vetoed_shells):
    """Test the effect of the "vetoed_shells" option"""
    passwd_pattern = expected_list_to_name_dict([
        dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
        dict(name="user_with_vetoed_shell", uid=1002,
             shell="/bin/fallback"),
        dict(name="user_with_empty_shell", uid=1003,
             shell="/bin/default")
    ])

    ent.assert_each_passwd_by_name(passwd_pattern)


def test_user_2307bis_nested_groups(ldap_conn,
                                    sanity_rfc2307_bis):
    """
    Test nested groups.

    Regression test for ticket:
    https://fedorahosted.org/sssd/ticket/3093
    """
    primary_gid = 2001
    # group1, two_user_group, one_user_group1, group_one_user_group,
    # group_two_user_group, group_two_one_user_groups
    expected_gids = [2001, 2012, 2015, 2017, 2018, 2019]

    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001,
                                            gid=primary_gid))

    (res, errno, gids) = sssd_id.call_sssd_initgroups("user1", primary_gid)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(expected_gids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(expected_gids)])
        )


def test_special_characters_in_names(ldap_conn, sanity_rfc2307):
    """
    Test special characters which could cause malformed filter
    in ldb_seach.

    Regression test for ticket:
    https://fedorahosted.org/sssd/ticket/3121
    """
    ent.assert_passwd_by_name(
        "t(u)ser",
        dict(name="t(u)ser", passwd="*", uid=5000, gid=5001,
             gecos="5000", shell="/bin/bash"))

    ent.assert_group_by_name(
        "group(_u)ser1",
        dict(name="group(_u)ser1", passwd="*", gid=5001,
             mem=ent.contains_only("t(u)ser")))


@pytest.fixture
def extra_attributes(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user", 2001, 2000)
    ent_list.add_group("group", 2000)
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [domain/LDAP]
            ldap_user_extra_attrs = mail, name:uid, givenName
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_extra_attribute_already_exists(ldap_conn, extra_attributes):
    """Test the effect of the "vetoed_shells" option"""

    user = 'user'
    extra_attribute = 'givenName'
    given_name = b'unix_user'

    user_dn = "uid=" + user + ",ou=Users," + ldap_conn.ds_inst.base_dn

    old = {'objectClass': [b'top', b'inetOrgPerson', b'posixAccount']}
    new = {'objectClass': [b'top', b'inetOrgPerson', b'posixAccount',
                           b'extensibleObject']}
    ldif = ldap.modlist.modifyModlist(old, new)

    ldap_conn.modify_s(user_dn, ldif)
    ldap_conn.modify_s(user_dn, [(ldap.MOD_ADD, extra_attribute, given_name)])

    ent.assert_passwd_by_name(
        user,
        dict(name="user", uid=2001, gid=2000, shell="/bin/bash"),
    )

    domain = 'LDAP'
    ldb_conn = sssd_ldb.SssdLdb('LDAP')
    val = ldb_conn.get_entry_attr(sssd_ldb.CacheType.sysdb,
                                  sssd_ldb.TsCacheEntry.user,
                                  user, domain, extra_attribute)

    assert val == given_name


@pytest.fixture
def add_user_to_group(request, ldap_conn):
    """
    Adding user to group
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_group_bis("group1", 20001, member_uids=["user1"])
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request,
                        format_rfc2307bis_deref_conf(
                            ldap_conn,
                            SCHEMA_RFC2307_BIS))
    create_sssd_fixture(request)
    return None


def test_add_user_to_group(ldap_conn, add_user_to_group):
    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=2001))
    ent.assert_group_by_name("group1", dict(mem=ent.contains_only("user1")))


@pytest.fixture
def remove_user_from_group(request, ldap_conn):
    """
    Adding user to group
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_group_bis("group1", 20001, member_uids=["user1", "user2"])
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request,
                        format_rfc2307bis_deref_conf(
                            ldap_conn,
                            SCHEMA_RFC2307_BIS))
    create_sssd_fixture(request)
    return None


def test_remove_user_from_group(ldap_conn, remove_user_from_group):
    """
    Removing two users from group, step by step
    """
    group1_dn = 'cn=group1,ou=Groups,' + ldap_conn.ds_inst.base_dn

    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=2001))
    ent.assert_passwd_by_name("user2", dict(name="user2", uid=1002, gid=2002))
    ent.assert_group_by_name("group1",
                             dict(mem=ent.contains_only("user1", "user2")))

    # removing of user2 from group1
    old = {'member': [b"uid=user1,ou=Users,dc=example,dc=com",
                      b"uid=user2,ou=Users,dc=example,dc=com"]}
    new = {'member': [b"uid=user1,ou=Users,dc=example,dc=com"]}

    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(group1_dn, ldif)

    if subprocess.call(["sss_cache", "-GU"]) != 0:
        raise Exception("sssd_cache failed")

    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=2001))
    ent.assert_passwd_by_name("user2", dict(name="user2", uid=1002, gid=2002))
    ent.assert_group_by_name("group1", dict(mem=ent.contains_only("user1")))

    # removing of user1 from group1
    old = {'member': [b"uid=user1,ou=Users,dc=example,dc=com"]}
    new = {'member': []}

    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(group1_dn, ldif)

    if subprocess.call(["sss_cache", "-GU"]) != 0:
        raise Exception("sssd_cache failed")

    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=2001))
    ent.assert_passwd_by_name("user2", dict(name="user2", uid=1002, gid=2002))
    ent.assert_group_by_name("group1", dict(mem=ent.contains_only()))


@pytest.fixture
def remove_user_from_nested_group(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_group_bis("group1", 20001, member_uids=["user1"])
    ent_list.add_group_bis("group2", 20002, member_uids=["user2"])
    ent_list.add_group_bis("group3", 20003, member_gids=["group1", "group2"])
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request,
                        format_rfc2307bis_deref_conf(
                            ldap_conn,
                            SCHEMA_RFC2307_BIS))
    create_sssd_fixture(request)
    return None


def test_remove_user_from_nested_group(ldap_conn,
                                       remove_user_from_nested_group):

    group3_dn = 'cn=group3,ou=Groups,' + ldap_conn.ds_inst.base_dn

    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=2001))
    ent.assert_passwd_by_name("user2", dict(name="user2", uid=1002, gid=2002))

    ent.assert_group_by_name("group1",
                             dict(mem=ent.contains_only("user1")))
    ent.assert_group_by_name("group2",
                             dict(mem=ent.contains_only("user2")))

    ent.assert_group_by_name("group3",
                             dict(mem=ent.contains_only("user1",
                                                        "user2")))

    # removing of group2 from group3
    old = {'member': [b"cn=group1,ou=Groups,dc=example,dc=com",
                      b"cn=group2,ou=Groups,dc=example,dc=com"]}
    new = {'member': [b"cn=group1,ou=Groups,dc=example,dc=com"]}

    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(group3_dn, ldif)

    if subprocess.call(["sss_cache", "-GU"]) != 0:
        raise Exception("sssd_cache failed")

    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=2001))
    ent.assert_passwd_by_name("user2", dict(name="user2", uid=1002, gid=2002))

    ent.assert_group_by_name("group1",
                             dict(mem=ent.contains_only("user1")))
    ent.assert_group_by_name("group2",
                             dict(mem=ent.contains_only("user2")))
    ent.assert_group_by_name("group3",
                             dict(mem=ent.contains_only("user1")))

    # removing of group1 from group3
    old = {'member': [b"cn=group1,ou=Groups,dc=example,dc=com"]}
    new = {'member': []}

    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(group3_dn, ldif)

    if subprocess.call(["sss_cache", "-GU"]) != 0:
        raise Exception("sssd_cache failed")

    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=2001))
    ent.assert_passwd_by_name("user2", dict(name="user2", uid=1002, gid=2002))

    ent.assert_group_by_name("group1",
                             dict(mem=ent.contains_only("user1")))
    ent.assert_group_by_name("group2",
                             dict(mem=ent.contains_only("user2")))
    ent.assert_group_by_name("group3",
                             dict(mem=ent.contains_only()))


def zero_nesting_sssd_conf(ldap_conn, schema):
    """Format an SSSD configuration with group nesting disabled"""
    return \
        format_basic_conf(ldap_conn, schema) + \
        unindent("""
            [domain/LDAP]
            ldap_group_nesting_level                = 0
        """).format(INTERACTIVE_TIMEOUT)


@pytest.fixture
def rfc2307bis_no_nesting(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_group_bis("group1", 20001, member_uids=["user1"])
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request,
                        zero_nesting_sssd_conf(
                            ldap_conn,
                            SCHEMA_RFC2307_BIS))
    create_sssd_fixture(request)
    return None


def test_zero_nesting_level(ldap_conn, rfc2307bis_no_nesting):
    ent.assert_group_by_name("group1",
                             dict(mem=ent.contains_only("user1")))
