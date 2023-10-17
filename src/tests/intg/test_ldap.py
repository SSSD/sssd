#
# LDAP integration test
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
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
from sssd_nss import NssReturnCode
from sssd_passwd import call_sssd_getpwnam, call_sssd_getpwuid
from sssd_group import call_sssd_getgrnam, call_sssd_getgrgid

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
    except Exception:
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
            for entry in ldap_conn.search_s(f"ou={ou},"
                                            f"{ldap_conn.ds_inst.base_dn}",
                                            ldap.SCOPE_ONELEVEL,
                                            attrlist=[]):
                ldap_conn.delete_s(entry[0])
    else:
        for entry in ent_list:
            ldap_conn.delete_s(entry[0])


def create_ldap_cleanup(request, ldap_conn, ent_list=None):
    """Add teardown for removing all user/group LDAP entries"""
    request.addfinalizer(lambda: cleanup_ldap_entries(ldap_conn, ent_list))


def create_ldap_fixture(request, ldap_conn, ent_list=None, cleanup=True):
    """Add LDAP entries and add teardown for removing them"""
    create_ldap_entries(ldap_conn, ent_list)
    if cleanup:
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
        enable_files_domain = false

        [nss]
        debug_level         = 0xffff
        memcache_timeout    = 0
        entry_negative_timeout = 1

        [pam]
        debug_level         = 0xffff

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_id_use_start_tls = false
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
    if subprocess.call(["sssd", "-D", "--logger=files"]) != 0:
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
            except OSError:
                break
            time.sleep(1)
    except OSError:
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


@pytest.fixture
def member_with_different_cases_rfc2307_bis(request, ldap_conn):
    """
    Create a group where the user DN values of the RFC2307bis member attribute
    differ in case from the original DN of the user object.
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)

    ent_list.add_group_bis("two_user_group", 2012, ["USER1", "uSeR2"])

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


def test_member_with_different_cases_rfc2307_bis(
        ldap_conn,
        member_with_different_cases_rfc2307_bis):
    """
    Regression test for https://bugzilla.redhat.com/show_bug.cgi?id=1817122
    Make sure that group members are added properly to the group even if the
    user DN in the RFC2307bis member attribute differs in case from the
    original DN of the user object.
    """
    group_pattern = expected_list_to_name_dict([
        dict(name='two_user_group', passwd='*', gid=2012,
             mem=ent.contains_only("user1", "user2")),
    ])
    ent.assert_each_group_by_name(group_pattern)


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
def update_ts_after_cleanup_task(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2001)

    ent_list.add_group_bis("group1", 2001, ["user1", "user2"])

    create_ldap_fixture(request, ldap_conn, ent_list)

    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [domain/LDAP]
            ldap_purge_cache_timeout = 3
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_update_ts_cache_after_cleanup_task(ldap_conn,
                                            update_ts_after_cleanup_task):
    """
    Regression test for ticket:
    https://fedorahosted.org/sssd/ticket/2676
    """
    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user2")))

    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user2',
        dict(name='user2', passwd='*', uid=1002, gid=2001,
             gecos='1002', shell='/bin/bash'))

    if subprocess.call(["sss_cache", "-u", "user1"]) != 0:
        raise Exception("sssd_cache failed")

    # The cleanup task runs every 3 seconds, so sleep for 6
    # so that we know the cleanup task ran at least once
    # even if we start sleeping during the first one
    time.sleep(6)

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user2")))


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
    ent_list.add_group_bis("primarygroup", 2001)
    ent_list.add_group_bis("parentgroup", 2010, member_uids=["user1"])
    ent_list.add_group_bis("nestedgroup", 2011, member_gids=["parentgroup"])
    create_ldap_fixture(request, ldap_conn, ent_list)
    create_conf_fixture(request,
                        zero_nesting_sssd_conf(
                            ldap_conn,
                            SCHEMA_RFC2307_BIS))
    create_sssd_fixture(request)
    return None


def test_zero_nesting_level(ldap_conn, rfc2307bis_no_nesting):
    """
    Test initgroups operation with rfc2307bis schema asserting
    only primary group and parent groups are included in group
    list. No parent groups of groups should be returned with zero
    group nesting level.
    """
    ent.assert_group_by_name("parentgroup",
                             dict(mem=ent.contains_only("user1")))
    ent.assert_group_by_name("nestedgroup",
                             dict(mem=ent.contains_only()))

    (res, errno, grp_list) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno

    # test nestedgroup is not returned in group list
    assert sorted(grp_list) == sorted(["primarygroup", "parentgroup"])


@pytest.fixture
def sanity_nss_filter(request, ldap_conn):
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
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [nss]
            filter_users = user2
            filter_groups = group_two_one_user_groups
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_nss_filters(ldap_conn, sanity_nss_filter):
    passwd_pattern = expected_list_to_name_dict([
        dict(name='user1', passwd='*', uid=1001, gid=2001, gecos='1001',
             dir='/home/user1', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=2003, gecos='1003',
             dir='/home/user3', shell='/bin/bash')
    ])

    # test filtered user
    ent.assert_each_passwd_by_name(passwd_pattern)
    with pytest.raises(KeyError):
        pwd.getpwnam("user2")
    with pytest.raises(KeyError):
        pwd.getpwuid(1002)

    group_pattern = expected_list_to_name_dict([
        dict(name='group1', passwd='*', gid=2001, mem=ent.contains_only()),
        dict(name='group2', passwd='*', gid=2002, mem=ent.contains_only()),
        dict(name='group3', passwd='*', gid=2003, mem=ent.contains_only()),
        dict(name='empty_group1', passwd='*', gid=2010,
             mem=ent.contains_only()),
        dict(name='empty_group2', passwd='*', gid=2011,
             mem=ent.contains_only()),
        dict(name='two_user_group', passwd='*', gid=2012,
             mem=ent.contains_only("user1")),
        dict(name='group_empty_group', passwd='*', gid=2013,
             mem=ent.contains_only()),
        dict(name='group_two_empty_groups', passwd='*', gid=2014,
             mem=ent.contains_only()),
        dict(name='one_user_group1', passwd='*', gid=2015,
             mem=ent.contains_only("user1")),
        dict(name='one_user_group2', passwd='*', gid=2016,
             mem=ent.contains_only()),
        dict(name='group_one_user_group', passwd='*', gid=2017,
             mem=ent.contains_only("user1")),
        dict(name='group_two_user_group', passwd='*', gid=2018,
             mem=ent.contains_only("user1")),
    ])

    # test filtered group
    ent.assert_each_group_by_name(group_pattern)
    with pytest.raises(KeyError):
        grp.getgrnam("group_two_one_user_groups")
    with pytest.raises(KeyError):
        grp.getgrgid(2019)

    # test non-existing user/group
    with pytest.raises(KeyError):
        pwd.getpwnam("non_existent_user")
    with pytest.raises(KeyError):
        pwd.getpwuid(9)
    with pytest.raises(KeyError):
        grp.getgrnam("non_existent_group")
    with pytest.raises(KeyError):
        grp.getgrgid(14)

    # test initgroups - user1 is member of group_two_one_user_groups (2019)
    # which is filtered out
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user1", 2001)
    assert res == sssd_id.NssReturnCode.SUCCESS

    user_with_group_ids = [2001, 2012, 2015, 2017, 2018]
    assert sorted(gids) == sorted(user_with_group_ids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user_with_group_ids)])
    )


@pytest.fixture
def sanity_nss_filter_cached(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)
    ent_list.add_user("root", 1004, 2004)
    ent_list.add_user("zerouid", 0, 0)

    ent_list.add_group_bis("group1", 2001)
    ent_list.add_group_bis("group2", 2002)
    ent_list.add_group_bis("group3", 2003)
    ent_list.add_group_bis("root", 2004)
    ent_list.add_group_bis("zerogid", 0)

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [nss]
            filter_users = user2
            filter_groups = group2
            entry_negative_timeout = 1
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_nss_filters_cached(ldap_conn, sanity_nss_filter_cached):
    passwd_pattern = expected_list_to_name_dict([
        dict(name='user1', passwd='*', uid=1001, gid=2001, gecos='1001',
             dir='/home/user1', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=2003, gecos='1003',
             dir='/home/user3', shell='/bin/bash')
    ])
    ent.assert_each_passwd_by_name(passwd_pattern)

    # test filtered user
    with pytest.raises(KeyError):
        pwd.getpwuid(1002)
    time.sleep(2)
    with pytest.raises(KeyError):
        pwd.getpwuid(1002)

    group_pattern = expected_list_to_name_dict([
        dict(name='group1', passwd='*', gid=2001, mem=ent.contains_only()),
        dict(name='group3', passwd='*', gid=2003, mem=ent.contains_only()),
    ])
    ent.assert_each_group_by_name(group_pattern)

    # test filtered group
    with pytest.raises(KeyError):
        grp.getgrgid(2002)
    time.sleep(2)
    with pytest.raises(KeyError):
        grp.getgrgid(2002)

    # test that root is always filtered even if filter_users contains other
    # entries. This is a regression test for upstream ticket #3460
    res, _ = call_sssd_getpwnam("root")
    assert res == NssReturnCode.NOTFOUND

    res, _ = call_sssd_getgrnam("root")
    assert res == NssReturnCode.NOTFOUND

    res, _ = call_sssd_getpwuid(0)
    assert res == NssReturnCode.NOTFOUND

    res, _ = call_sssd_getgrgid(0)
    assert res == NssReturnCode.NOTFOUND


@pytest.fixture
def mpg_setup(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)

    ent_list.add_group_bis("group1", 2001)
    ent_list.add_group_bis("group2", 2002)
    ent_list.add_group_bis("group3", 2003)

    ent_list.add_group_bis("two_user_group", 2012, ["user1", "user2"])
    ent_list.add_group_bis("one_user_group1", 2015, ["user1"])
    ent_list.add_group_bis("one_user_group2", 2016, ["user2"])

    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, None)

    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [domain/LDAP]
            auto_private_groups = True
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_ldap_auto_private_groups_direct(ldap_conn, mpg_setup):
    """
    Integration test for auto_private_groups

    See also ticket https://github.com/SSSD/sssd/issues/2914
    """
    # Make sure the user's GID is taken from their uidNumber
    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=1001))
    # Make sure the private group is resolvable by name and by GID
    ent.assert_group_by_name("user1", dict(gid=1001, mem=ent.contains_only()))
    ent.assert_group_by_gid(1001, dict(name="user1", mem=ent.contains_only()))

    # The group referenced in user's gidNumber attribute should be still
    # visible, but it's fine that it doesn't contain the user as a member
    # as the group is currently added during the initgroups operation only
    ent.assert_group_by_name("group1", dict(gid=2001, mem=ent.contains_only()))
    ent.assert_group_by_gid(2001, dict(name="group1", mem=ent.contains_only()))

    # The user's secondary groups list must be correct as well
    # Note that the original GID is listed as well -- this is correct and
    # expected because we save the original GID in the
    # SYSDB_PRIMARY_GROUP_GIDNUM attribute
    user1_expected_gids = [1001, 2001, 2012, 2015]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user1", 1001)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(user1_expected_gids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user1_expected_gids)])
    )

    # Request user2's private group by GID without resolving the user first.
    # This must trigger user resolution through by-GID resolution, since the
    # GID doesn't exist on its own in LDAP
    ent.assert_group_by_gid(1002, dict(name="user2", mem=ent.contains_only()))

    # Test supplementary groups for user2 as well
    user1_expected_gids = [1002, 2002, 2012, 2016]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user2", 1002)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(user1_expected_gids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user1_expected_gids)])
    )

    # Request user3's private group by name without resolving the user first
    # This must trigger user resolution through by-name resolution, since the
    # name doesn't exist on its own in LDAP
    ent.assert_group_by_name("user3", dict(gid=1003, mem=ent.contains_only()))

    # Remove entries and request them again to make sure they are not
    # resolvable anymore
    cleanup_ldap_entries(ldap_conn, None)

    if subprocess.call(["sss_cache", "-GU"]) != 0:
        raise Exception("sssd_cache failed")

    with pytest.raises(KeyError):
        pwd.getpwnam("user1")
    with pytest.raises(KeyError):
        grp.getgrnam("user1")
    with pytest.raises(KeyError):
        grp.getgrgid(1002)
    with pytest.raises(KeyError):
        grp.getgrnam("user3")


@pytest.fixture
def mpg_setup_conflict(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 1003)
    ent_list.add_group_bis("group1", 1001)
    ent_list.add_group_bis("group2", 1002)
    ent_list.add_group_bis("group3", 1003)
    ent_list.add_group_bis("supp_group", 2015, ["user3"])
    create_ldap_fixture(request, ldap_conn, ent_list)

    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [domain/LDAP]
            auto_private_groups = True
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_ldap_auto_private_groups_conflict(ldap_conn, mpg_setup_conflict):
    """
    Make sure that conflicts between groups that are auto-created with the
    help of the auto_private_groups option and between 'real' LDAP groups
    are handled in a predictable manner.
    """
    # Make sure the user's GID is taken from their uidNumber
    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=1001))
    # Make sure the private group is resolvable by name and by GID
    ent.assert_group_by_name("user1", dict(gid=1001, mem=ent.contains_only()))
    ent.assert_group_by_gid(1001, dict(name="user1", mem=ent.contains_only()))

    # Let's request the group with the same ID as user2's private group
    # The request should match the 'real' group
    ent.assert_group_by_gid(1002, dict(name="group2", mem=ent.contains_only()))
    # But because of the GID conflict, the user cannot be resolved
    with pytest.raises(KeyError):
        pwd.getpwnam("user2")

    # This user's GID is the same as the UID in this entry. The most important
    # thing here is that the supplementary groups are correct and the GID
    # resolves to the private group (as long as the user was requested first)
    user3_expected_gids = [1003, 2015]
    ent.assert_passwd_by_name("user3", dict(name="user3", uid=1003, gid=1003))
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user3", 1003)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(user3_expected_gids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user3_expected_gids)])
    )
    # Make sure the private group is resolvable by name and by GID
    ent.assert_group_by_gid(1003, dict(name="user3", mem=ent.contains_only()))
    ent.assert_group_by_name("user3", dict(gid=1003, mem=ent.contains_only()))


@pytest.fixture
def mpg_setup_no_gid(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)

    ent_list.add_group_bis("group1", 2001)
    ent_list.add_group_bis("one_user_group1", 2015, ["user1"])

    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, None)

    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [domain/LDAP]
            auto_private_groups = True
            ldap_user_gid_number = no_such_attribute
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_ldap_auto_private_groups_direct_no_gid(ldap_conn, mpg_setup_no_gid):
    """
    Integration test for auto_private_groups - test that even a user with
    no GID assigned at all can be resolved including their autogenerated
    primary group.

    See also ticket https://github.com/SSSD/sssd/issues/2914
    """
    # Make sure the user's GID is taken from their uidNumber
    ent.assert_passwd_by_name("user1", dict(name="user1", uid=1001, gid=1001))
    # Make sure the private group is resolvable by name and by GID
    ent.assert_group_by_name("user1", dict(gid=1001, mem=ent.contains_only()))
    ent.assert_group_by_gid(1001, dict(name="user1", mem=ent.contains_only()))

    # The group referenced in user's gidNumber attribute should be still
    # visible, but shouldn't have any relation to the user
    ent.assert_group_by_name("group1", dict(gid=2001, mem=ent.contains_only()))
    ent.assert_group_by_gid(2001, dict(name="group1", mem=ent.contains_only()))

    # The user's secondary groups list must be correct as well. This time only
    # the generated group and the explicit secondary group are added, since
    # there is no original GID
    user1_expected_gids = [1001, 2015]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user1", 1001)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(user1_expected_gids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user1_expected_gids)])
    )


@pytest.fixture
def mpg_setup_hybrid(request, ldap_conn):
    """
    This setup creates two users - one with a GID that corresponds to
    a group and another with GID that does not.
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_user("user_with_group", 1001, 2001)
    ent_list.add_group_bis("user_with_group_pvt", 2001)
    ent_list.add_group_bis("with_group_group1", 10010, ["user_with_group"])
    ent_list.add_group_bis("with_group_group2", 10011, ["user_with_group"])

    ent_list.add_user("user_with_no_group", 1002, 1002)
    # Note - there is no group for the GID 1002
    ent_list.add_group_bis("no_group_group1", 10020, ["user_with_no_group"])
    ent_list.add_group_bis("no_group_group2", 10021, ["user_with_no_group"])

    # This user has their gid different from the UID, but there is
    # no group with gid 2003
    ent_list.add_user("user_with_unresolvable_gid", 1003, 2003)
    ent_list.add_group_bis("unresolvable_group1",
                           10030,
                           ["user_with_unresolvable_gid"])
    ent_list.add_group_bis("unresolvable_group2",
                           10031,
                           ["user_with_unresolvable_gid"])

    # This user's autogenerated private group should be shadowed
    # by the real one
    ent_list.add_user("user_with_real_group", 1004, 1004)
    ent_list.add_user("user_in_pvt_group", 1005, 1005)
    ent_list.add_group_bis("user_with_real_group_pvt",
                           1004,
                           ['user_in_pvt_group'])
    ent_list.add_group_bis("with_real_group_group1",
                           10040,
                           ["user_with_real_group"])
    ent_list.add_group_bis("with_real_group_group2",
                           10041,
                           ["user_with_real_group"])

    # Test shadowing again, but this time with the same name
    ent_list.add_user("u_g_same_name", 1006, 1006)
    ent_list.add_group_bis("u_g_same_name",
                           1006,
                           ['user_in_pvt_group'])
    ent_list.add_group_bis("u_g_same_g1",
                           10060,
                           ["u_g_same_name"])
    ent_list.add_group_bis("u_g_same_g2",
                           10061,
                           ["u_g_same_name"])

    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, None)

    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [domain/LDAP]
            auto_private_groups = hybrid
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_ldap_auto_private_groups_hybrid_direct(ldap_conn, mpg_setup_hybrid):
    """
    Integration test for auto_private_groups=hybrid. This test checks the
    resolution of the users and their groups.

    See also ticket https://github.com/SSSD/sssd/issues/2914
    """
    # Make sure the user's GID is taken from their gidNumber, if available
    ent.assert_passwd_by_name("user_with_group",
                              dict(name="user_with_group", uid=1001, gid=2001))

    # The user's secondary groups list must be correct as well and include
    # the primary gid, too
    user_with_group_ids = [2001, 10010, 10011]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user_with_group", 2001)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(user_with_group_ids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user_with_group_ids)])
    )

    # On the other hand, if the gidNumber is the same as UID, SSSD should
    # just autogenerate the private group on its own
    ent.assert_passwd_by_name("user_with_no_group",
                              dict(name="user_with_no_group",
                                   uid=1002, gid=1002))

    # The user's secondary groups list must be correct as well. Since there was
    # no original GID, it is not added to the list
    user_without_group_ids = [1002, 10020, 10021]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user_with_no_group",
                                                      1002)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(user_without_group_ids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user_without_group_ids)])
    )

    ent.assert_passwd_by_name("user_with_unresolvable_gid",
                              dict(name="user_with_unresolvable_gid",
                                   uid=1003, gid=2003))
    unresolvable_group_ids = [2003, 10030, 10031]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user_with_unresolvable_gid", 2003)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(unresolvable_group_ids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(unresolvable_group_ids)])
    )

    ent.assert_passwd_by_name("user_with_real_group",
                              dict(name="user_with_real_group",
                                   uid=1004, gid=1004))
    with_real_group_ids = [1004, 10040, 10041]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user_with_real_group", 1004)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(with_real_group_ids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(with_real_group_ids)])
    )


def test_ldap_auto_private_groups_hybrid_priv_group_byname(ldap_conn,
                                                           mpg_setup_hybrid):
    """
    Integration test for auto_private_groups=hybrid. This test checks the
    resolution of user private groups by name.

    See also ticket https://github.com/SSSD/sssd/issues/2914
    """
    # gidNumber is resolvable by name..
    ent.assert_group_by_name("user_with_group_pvt",
                             dict(gid=2001,
                                  mem=ent.contains_only()))

    # ..but since this user /has/ a gidNumber set, their autogenerated group
    # should not be resolvable
    with pytest.raises(KeyError):
        grp.getgrnam("user_with_group")

    # Finally, the autogenerated group for the user with
    # uidNumber==gidNumber must be resolvable
    ent.assert_group_by_name("user_with_no_group",
                             dict(gid=1002,
                                  mem=ent.contains_only()))

    # A gid that is different from an UID must not resolve to a private
    # group even if the private group does not exist
    with pytest.raises(KeyError):
        grp.getgrnam("user_with_unresolvable_gid")

    # If there is a user with the same UID and GID but there is a real
    # group corresponding to the primary GID, the real group should take
    # precedence and the automatic group should not be resolvable
    ent.assert_group_by_name("user_with_real_group_pvt",
                             dict(gid=1004,
                                  mem=ent.contains_only('user_in_pvt_group',)))

    # getgrnam should not return
    with pytest.raises(KeyError):
        grp.getgrnam("user_with_real_group")


def test_ldap_auto_private_groups_hybrid_priv_group_byid(ldap_conn,
                                                         mpg_setup_hybrid):
    """
    Integration test for auto_private_groups=hybrid. This test checks the
    resolution of user private groups by name.

    See also ticket https://github.com/SSSD/sssd/issues/2914
    """
    # Make sure the private group of user who has this group set in their
    # gidNumber is resolvable by ID
    ent.assert_group_by_gid(2001,
                            dict(name="user_with_group_pvt",
                                 mem=ent.contains_only()))

    # ..but since this user /has/ a gidNumber set different from the uidNumber,
    # their autogenerated group
    # should not be resolvable
    with pytest.raises(KeyError):
        grp.getgrgid(1001)

    # Finally, the autogenerated group for the user with
    # uidNumber==gidNumber must be resolvable
    ent.assert_group_by_gid(1002,
                            dict(name="user_with_no_group",
                                 mem=ent.contains_only()))

    # A gid that is different from an UID must not resolve to a private
    # group even if the private group does not exist
    with pytest.raises(KeyError):
        grp.getgrgid(2003)

    # Conversely, a GID that corresponds to a group must not resolve to
    # the autogenerated group (IOW, the autogenerated group should not
    # shadow the real one
    ent.assert_group_by_gid(1004,
                            dict(name="user_with_real_group_pvt",
                                 mem=ent.contains_only('user_in_pvt_group')))


def test_ldap_auto_private_groups_hybrid_name_gid_identical(ldap_conn,
                                                            mpg_setup_hybrid):
    """
    See also ticket https://github.com/SSSD/sssd/issues/2914
    """
    ent.assert_passwd_by_name("u_g_same_name",
                              dict(name="u_g_same_name",
                                   uid=1006, gid=1006))
    user_without_group_ids = [1006, 10060, 10061]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("u_g_same_name",
                                                      1006)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(user_without_group_ids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user_without_group_ids)])
    )
    ent.assert_group_by_gid(1006,
                            dict(name="u_g_same_name",
                                 mem=ent.contains_only('user_in_pvt_group')))


def test_ldap_auto_private_groups_hybrid_initgr(ldap_conn, mpg_setup_hybrid):
    """
    See also ticket https://github.com/SSSD/sssd/issues/2914
    """
    user_without_group_ids = [1004, 10040, 10041]
    (res, errno, gids) = sssd_id.call_sssd_initgroups("user_with_real_group",
                                                      1004)
    assert res == sssd_id.NssReturnCode.SUCCESS

    assert sorted(gids) == sorted(user_without_group_ids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(user_without_group_ids)])
    )

    ent.assert_group_by_gid(1004,
                            dict(name="user_with_real_group_pvt",
                                 mem=ent.contains_only('user_in_pvt_group')))


def rename_setup_no_cleanup(request, ldap_conn, cleanup_ent=None):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_group_bis("user1_private", 2001)

    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_group_bis("user2_private", 2002)

    ent_list.add_group_bis("group1", 2015, ["user1", "user2"])

    if cleanup_ent is None:
        create_ldap_fixture(request, ldap_conn, ent_list)
    else:
        # Since the entries were renamed, we need to clean up
        # the renamed entries..
        create_ldap_fixture(request, ldap_conn, ent_list, cleanup=False)
        create_ldap_cleanup(request, ldap_conn, None)


@pytest.fixture
def rename_setup_cleanup(request, ldap_conn):
    cleanup_ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    cleanup_ent_list.add_user("user1", 1001, 2001)
    cleanup_ent_list.add_group_bis("new_user1_private", 2001)

    cleanup_ent_list.add_user("user2", 1002, 2002)
    cleanup_ent_list.add_group_bis("new_user2_private", 2002)

    cleanup_ent_list.add_group_bis("new_group1", 2015, ["user1", "user2"])

    rename_setup_no_cleanup(request, ldap_conn, cleanup_ent_list)

    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def rename_setup_with_name(request, ldap_conn):
    rename_setup_no_cleanup(request, ldap_conn)

    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS) + \
        unindent("""
            [nss]
            [domain/LDAP]
            ldap_group_name                = name
            timeout = 3000
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_rename_incomplete_group_same_dn(ldap_conn, rename_setup_with_name):
    """
    Test that if a group's name attribute changes, but the DN stays the same,
    the incomplete group object will be renamed.

    Because the RDN attribute must be present in the entry, we add another
    attribute "name" that is purposefully different from the CN and make
    sure the group names are reflected in name

    Regression test for https://github.com/SSSD/sssd/issues/4315
    """
    pvt_dn1 = 'cn=user1_private,ou=Groups,' + ldap_conn.ds_inst.base_dn
    pvt_dn2 = 'cn=user2_private,ou=Groups,' + ldap_conn.ds_inst.base_dn
    group1_dn = 'cn=group1,ou=Groups,' + ldap_conn.ds_inst.base_dn

    # Add the name we want for both private and secondary group
    old = {'name': []}
    new = {'name': [b"user1_group1"]}
    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(group1_dn, ldif)

    new = {'name': [b"pvt_user1"]}
    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(pvt_dn1, ldif)

    new = {'name': [b"pvt_user2"]}
    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(pvt_dn2, ldif)

    # Make sure the old name shows up in the id output
    (res, errno, grp_list) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno

    assert sorted(grp_list) == sorted(["pvt_user1", "user1_group1"])

    # Rename the group by changing the cn attribute, but keep the DN the same
    old = {'name': [b"user1_group1"]}
    new = {'name': [b"new_user1_group1"]}
    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(group1_dn, ldif)

    (res, errno, grp_list) = sssd_id.get_user_groups("user2")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user2, %d" % errno

    assert sorted(grp_list) == sorted(["pvt_user2", "new_user1_group1"])

    (res, errno, grp_list) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno

    assert sorted(grp_list) == sorted(["pvt_user1", "new_user1_group1"])


def test_rename_incomplete_group_rdn_changed(ldap_conn, rename_setup_cleanup):
    """
    If a group is renamed and also some attributes changed and gid remains the
    same then existing group in the cache is overridden with the new attributes
    and name.
    """
    pvt_dn = 'cn=user1_private,ou=Groups,' + ldap_conn.ds_inst.base_dn
    group1_dn = 'cn=group1,ou=Groups,' + ldap_conn.ds_inst.base_dn

    # Make sure the old name shows up in the id output
    (res, errno, grp_list) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno

    assert sorted(grp_list) == sorted(["user1_private", "group1"])

    # Rename the groups, changing the RDN
    ldap_conn.rename_s(group1_dn, "cn=new_group1")
    ldap_conn.rename_s(pvt_dn, "cn=new_user1_private")

    (res, errno, grp_list) = sssd_id.get_user_groups("user2")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user2, %d" % errno

    # The initgroups succeeds, but because saving the new group fails,
    # SSSD will revert to the cache contents and return what's in the cache
    assert sorted(grp_list) == sorted(["user2_private", "new_group1"])


@pytest.fixture
def find_local_user_and_group():
    f = open("/etc/passwd")
    for line in f:
        passwd_user = line.split(':')
        passwd_user[2] = int(passwd_user[2])
        if passwd_user[2] != 0:
            break
    f.close()
    assert passwd_user[2] != 0

    f = open("/etc/group")
    for line in f:
        passwd_group = line.split(':')
        passwd_group[2] = int(passwd_group[2])
        if passwd_group[2] != 0:
            break
    f.close()
    assert passwd_group[2] != 0

    return (passwd_user, passwd_group)


@pytest.fixture
def user_and_group_rfc2307_lcl(find_local_user_and_group,
                               user_and_group_rfc2307):
    return find_local_user_and_group


def test_local_negative_timeout_enabled_by_default(ldap_conn,
                                                   user_and_group_rfc2307_lcl):
    """
    Test that with the default local_negative_timeout value, a user who can't
    be resolved through SSSD but can be resolved in LDAP is negatively cached
    """
    # sanity check - try resolving an LDAP user
    ent.assert_passwd_by_name("user", dict(name="user", uid=1001, gid=2000))

    passwd_user, passwd_group = user_and_group_rfc2307_lcl

    # resolve a user who is not in LDAP, but exists locally
    res, _ = call_sssd_getpwnam(passwd_user[0])
    assert res == NssReturnCode.NOTFOUND
    # Do the same by UID
    res, _ = call_sssd_getpwuid(passwd_user[2])
    assert res == NssReturnCode.NOTFOUND

    # Do the same for a group both by name and by ID
    res, _ = call_sssd_getgrnam(passwd_group[0])
    assert res == NssReturnCode.NOTFOUND
    res, _ = call_sssd_getgrgid(passwd_group[2])
    assert res == NssReturnCode.NOTFOUND

    # add the user and the group to LDAP
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user(passwd_user[0], passwd_user[2], 2000)
    ent_list.add_group(passwd_group[0], passwd_group[2])
    create_ldap_entries(ldap_conn, ent_list)

    # Make sure the negative cache would expire if global timeout was used
    time.sleep(2)

    # The user is now negatively cached and can't be resolved by either
    # name or UID
    res, _ = call_sssd_getpwnam(passwd_group[0])
    assert res == NssReturnCode.NOTFOUND
    res, _ = call_sssd_getpwuid(passwd_group[2])
    assert res == NssReturnCode.NOTFOUND

    res, _ = call_sssd_getgrnam(passwd_group[0])
    assert res == NssReturnCode.NOTFOUND
    res, _ = call_sssd_getgrgid(passwd_group[2])
    assert res == NssReturnCode.NOTFOUND

    cleanup_ldap_entries(ldap_conn, ent_list)


@pytest.fixture
def usr_and_grp_rfc2307_no_local_ncache(request, find_local_user_and_group,
                                        ldap_conn):
    """
    Create an RFC2307 directory fixture with interactive SSSD conf,
    one user and one group but with the local negative timeout
    disabled
    """
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user", 1001, 2000)
    ent_list.add_group("group", 2001)
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_interactive_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""
        [nss]
        local_negative_timeout              = 0
        """)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return find_local_user_and_group


def test_local_negative_timeout_disabled(ldap_conn,
                                         usr_and_grp_rfc2307_no_local_ncache):
    """
    Test that with the local negative cache disabled, a user who is in both
    LDAP and files can be resolved once the negative cache expires
    """
    # sanity check - try resolving an LDAP user
    ent.assert_passwd_by_name("user", dict(name="user", uid=1001, gid=2000))

    passwd_user, passwd_group = usr_and_grp_rfc2307_no_local_ncache

    # resolve a user who is not in LDAP, but exists locally
    res, _ = call_sssd_getpwnam(passwd_user[0])
    assert res == NssReturnCode.NOTFOUND
    # Do the same by UID
    res, _ = call_sssd_getpwuid(passwd_user[2])
    assert res == NssReturnCode.NOTFOUND

    # Do the same for a group both by name and by ID
    res, _ = call_sssd_getgrnam(passwd_group[0])
    assert res == NssReturnCode.NOTFOUND
    res, _ = call_sssd_getgrgid(passwd_group[2])
    assert res == NssReturnCode.NOTFOUND

    # add the user and the group to LDAP
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user(passwd_user[0], passwd_user[2], 2000)
    ent_list.add_group(passwd_group[0], passwd_group[2])
    create_ldap_entries(ldap_conn, ent_list)

    # Make sure the negative cache expired
    time.sleep(2)

    # The user can now be resolved
    res, _ = call_sssd_getpwnam(passwd_user[0])
    assert res == NssReturnCode.SUCCESS
    # Do the same by UID
    res, _ = call_sssd_getpwuid(passwd_user[2])
    assert res == NssReturnCode.SUCCESS

    res, _ = call_sssd_getgrnam(passwd_group[0])
    assert res == NssReturnCode.SUCCESS
    res, _ = call_sssd_getgrgid(passwd_group[2])
    assert res == NssReturnCode.SUCCESS

    cleanup_ldap_entries(ldap_conn, ent_list)


def users_with_email_setup(request, ldap_conn, cache_first):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001, mail="user1.email@LDAP")

    ent_list.add_user("emailuser", 1002, 2002)
    ent_list.add_user("emailuser2", 1003, 2003, mail="emailuser@LDAP")

    ent_list.add_user("userx", 1004, 2004, mail="userxy@LDAP")
    ent_list.add_user("usery", 1005, 2005, mail="userxy@LDAP")

    create_ldap_fixture(request, ldap_conn, ent_list)

    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)

    conf += unindent("""
        [nss]
        cache_first = {0}
    """).format(str(cache_first))

    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


@pytest.mark.parametrize('cache_first', [True, False])
def test_lookup_by_email(request, ldap_conn, cache_first):
    """
    Test the simple case of looking up a user by e-mail
    """
    users_with_email_setup(request, ldap_conn, cache_first)
    ent.assert_passwd_by_name("user1.email@LDAP",
                              dict(name="user1", uid=1001, gid=2001))


@pytest.mark.parametrize('cache_first', [True, False])
def test_conflicting_mail_addresses_and_fqdn(request, ldap_conn, cache_first):
    """
    Test that we handle the case where one user's mail address is the
    same as another user's FQDN

    This is a regression test for https://github.com/SSSD/sssd/issues/4630
    """
    users_with_email_setup(request, ldap_conn, cache_first)
    # With #3607 unfixed, these two lookups would prime the cache with
    # nameAlias: emailuser@LDAP for both entries..
    ent.assert_passwd_by_name("emailuser@LDAP",
                              dict(name="emailuser", uid=1002, gid=2002))
    ent.assert_passwd_by_name("emailuser2@LDAP",
                              dict(name="emailuser2", uid=1003, gid=2003))

    # ..and subsequently, emailuser would not be returned because the cache
    # lookup would have had returned two entries which is an error
    ent.assert_passwd_by_name("emailuser@LDAP",
                              dict(name="emailuser", uid=1002, gid=2002))
    ent.assert_passwd_by_name("emailuser2@LDAP",
                              dict(name="emailuser2", uid=1003, gid=2003))


@pytest.mark.parametrize('cache_first', [True, False])
def test_conflicting_mail_addresses(request, ldap_conn, cache_first):
    """
    Negative test: looking up a user by e-mail which belongs to more than
    one account fails in the back end.
    """
    users_with_email_setup(request, ldap_conn, cache_first)
    with pytest.raises(KeyError):
        pwd.getpwnam("userxy@LDAP")

    # However resolving the users on their own must work
    ent.assert_passwd_by_name("userx", dict(name="userx", uid=1004, gid=2004))
    ent.assert_passwd_by_name("usery", dict(name="usery", uid=1005, gid=2005))
