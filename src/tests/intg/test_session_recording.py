#
# Session Recording tests
#
# Copyright (c) 2016 Red Hat, Inc.
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
import ent
import config
import signal
import subprocess
import time
import ldap
import pytest
import ds_openldap
import ldap_ent
from util import unindent

LDAP_BASE_DN = "dc=example,dc=com"
INTERACTIVE_TIMEOUT = 4


def stop_sssd():
    """Stop sssd"""
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
    """Restart sssd"""
    stop_sssd()
    start_sssd()


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
    request.addfinalizer(lambda: ds_inst.teardown())
    return ds_inst


@pytest.fixture(scope="module")
def ldap_conn(request, ds_inst):
    """LDAP server connection fixture"""
    ldap_conn = ds_inst.bind()
    ldap_conn.ds_inst = ds_inst
    request.addfinalizer(lambda: ldap_conn.unbind_s())
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


def create_ldap_fixture(request, ldap_conn, ent_list=None):
    """Add LDAP entries and add teardown for removing them"""
    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, ent_list)


SCHEMA_RFC2307 = "rfc2307"
SCHEMA_RFC2307_BIS = "rfc2307bis"


def format_basic_conf(ldap_conn, schema):
    """
    Format a basic SSSD configuration.

    The files domain is defined but not enabled in order to avoid enumerating
    users from the files domain that would otherwise by implicitly enabled.
    """
    schema_conf = "ldap_schema         = " + schema + "\n"
    if schema == SCHEMA_RFC2307_BIS:
        schema_conf += "ldap_group_object_class = groupOfNames\n"
    return unindent("""\
        [sssd]
        debug_level                      = 0xffff
        domains                          = LDAP
        services                         = nss, pam

        [nss]
        debug_level                      = 0xffff
        memcache_timeout                 = 0

        [pam]
        debug_level                      = 0xffff

        [domain/files]
        id_provider                      = files

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_id_use_start_tls = false
        debug_level                      = 0xffff
        enumerate                        = true
        {schema_conf}
        id_provider                      = ldap
        auth_provider                    = ldap
        ldap_uri                         = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base                 = {ldap_conn.ds_inst.base_dn}
        ldap_enumeration_refresh_offset  = 0
    """).format(**locals())


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
    Create sssd.conf with specified contents and add teardown for removing it.
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
def users_and_groups(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001, loginShell="/bin/sh1")
    ent_list.add_user("user2", 1002, 2002, loginShell="/bin/sh2")
    ent_list.add_user("user3", 1003, 2003, loginShell="/bin/sh3")
    # User without primary group
    ent_list.add_user("user4", 1004, 2004, loginShell="/bin/sh4")
    ent_list.add_group("group1", 2001)
    ent_list.add_group("group2", 2002)
    ent_list.add_group("group3", 2003)
    ent_list.add_group("empty_group", 2010)
    ent_list.add_group("one_user_group", 2011, ["user1"])
    ent_list.add_group("two_user_group", 2012, ["user1", "user2"])
    ent_list.add_group("three_user_group", 2013, ["user1", "user2", "user3"])
    # Supplementary group for a user without primary group
    ent_list.add_group("groupless_user_group", 2014, ["user4"])
    create_ldap_fixture(request, ldap_conn, ent_list)


@pytest.fixture
def none(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "none".
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = none
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_none(none):
    """Test "none" scope"""
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user1", uid=1001, shell="/bin/sh1"),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def all(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "all".
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = all
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_all_nam(all):
    """Test "all" scope with getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        user3=dict(name="user3", uid=1003,
                   shell=config.SESSION_RECORDING_SHELL),
        user4=dict(name="user4", uid=1004,
                   shell=config.SESSION_RECORDING_SHELL),
    ))


def test_all_uid(all):
    """Test "all" scope with getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        1003: dict(name="user3", uid=1003,
                   shell=config.SESSION_RECORDING_SHELL),
        1004: dict(name="user4", uid=1004,
                   shell=config.SESSION_RECORDING_SHELL),
    })


def test_all_ent(all):
    """Test "all" scope with getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user3", uid=1003, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user4", uid=1004, shell=config.SESSION_RECORDING_SHELL),
        )
    )


@pytest.fixture
def some_empty(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", but no users or groups listed.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_some_empty(some_empty):
    """Test "some" scope with no users or groups"""
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user1", uid=1001, shell="/bin/sh1"),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def some_users(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", and some users listed.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            users = user1, user2
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_some_users_nam(some_users):
    """Test "some" scope with user list and getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_users_uid(some_users):
    """Test "some" scope with user list and getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_users_ent(some_users):
    """Test "some" scope with user list and getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def some_users_overridden(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", specifying two users with
    overridden names, but one listed with the original name.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            users = overridden_user1, user2
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-n", "overridden_user1"])
    subprocess.check_call(["sss_override", "user-add", "user2",
                           "-n", "overridden_user2"])
    restart_sssd()


def test_some_users_overridden_nam(some_users_overridden):
    """
    Test "some" scope with user list containing some
    overridden users, requested with getpwnam.
    """
    ent.assert_each_passwd_by_name(dict(
        overridden_user1=dict(name="overridden_user1", uid=1001,
                              shell=config.SESSION_RECORDING_SHELL),
        overridden_user2=dict(name="overridden_user2", uid=1002,
                              shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_users_overridden_uid(some_users_overridden):
    """
    Test "some" scope with user list containing some
    overridden users, requested with getpwuid.
    """
    ent.assert_each_passwd_by_uid({
        1001: dict(name="overridden_user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="overridden_user2", uid=1002,
                   shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_users_overridden_ent(some_users_overridden):
    """
    Test "some" scope with user list containing some
    overridden users, requested with getpwent.
    """
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="overridden_user1", uid=1001,
                 shell=config.SESSION_RECORDING_SHELL),
            dict(name="overridden_user2", uid=1002,
                 shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def some_groups1(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", specifying a single-user supplementary group,
    and a two-user supplementary group intersecting with the first one.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            groups = one_user_group, two_user_group
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


@pytest.fixture
def some_groups2(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", specifying a three-user supplementary group.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            groups = three_user_group
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


@pytest.fixture
def some_groups3(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", specifying a group with a user with
    non-existent primary group.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            groups = groupless_user_group
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


@pytest.fixture
def some_groups4(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", specifying two primary groups.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            groups = group1, group3
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_some_groups1_nam(some_groups1):
    """Test "some" scope with group list and getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_groups1_uid(some_groups1):
    """Test "some" scope with group list and getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_groups1_ent(some_groups1):
    """Test "some" scope with group list and getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


def test_some_groups2_nam(some_groups2):
    """Test "some" scope with group list and getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        user3=dict(name="user3", uid=1003,
                   shell=config.SESSION_RECORDING_SHELL),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_groups2_uid(some_groups2):
    """Test "some" scope with group list and getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        1003: dict(name="user3", uid=1003,
                   shell=config.SESSION_RECORDING_SHELL),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_groups2_ent(some_groups2):
    """Test "some" scope with group list and getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user3", uid=1003, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


def test_some_groups3_nam(some_groups3):
    """Test "some" scope with group list and getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001, shell="/bin/sh1"),
        user2=dict(name="user2", uid=1002, shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004,
                   shell=config.SESSION_RECORDING_SHELL),
    ))


def test_some_groups3_uid(some_groups3):
    """Test "some" scope with group list and getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001, shell="/bin/sh1"),
        1002: dict(name="user2", uid=1002, shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004,
                   shell=config.SESSION_RECORDING_SHELL),
    })


def test_some_groups3_ent(some_groups3):
    """Test "some" scope with group list and getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell="/bin/sh1"),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell=config.SESSION_RECORDING_SHELL),
        )
    )


def test_some_groups4_nam(some_groups4):
    """Test "some" scope with group list and getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002, shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003,
                   shell=config.SESSION_RECORDING_SHELL),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_groups4_uid(some_groups4):
    """Test "some" scope with group list and getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002, shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003,
                   shell=config.SESSION_RECORDING_SHELL),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_groups4_ent(some_groups4):
    """Test "some" scope with group list and getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def some_groups_overridden1(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", specifying two primary groups with
    overridden names, but one listed with the original name.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            groups = overridden_group1, group2
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    subprocess.check_call(["sss_override", "group-add", "group1",
                           "-n", "overridden_group1"])
    subprocess.check_call(["sss_override", "group-add", "group2",
                           "-n", "overridden_group2"])
    restart_sssd()


def test_some_groups_overridden1_nam(some_groups_overridden1):
    """
    Test "some" scope with group list containing some
    overridden groups, and users requested with getpwnam.
    """
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002, shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_groups_overridden1_uid(some_groups_overridden1):
    """
    Test "some" scope with group list containing some
    overridden groups, and users requested with getpwuid.
    """
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002, shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_groups_overridden1_ent(some_groups_overridden1):
    """
    Test "some" scope with group list containing some
    overridden groups, and users requested with getpwent.
    """
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def some_groups_overridden2(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", specifying two supplementary groups with
    overridden names, but one listed with the original name.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            groups = one_user_group_overridden, two_user_group
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    subprocess.check_call(["sss_override", "group-add", "one_user_group",
                           "-n", "one_user_group_overridden"])
    subprocess.check_call(["sss_override", "group-add", "two_user_group",
                           "-n", "two_user_group_overridden"])
    restart_sssd()


def test_some_groups_overridden2_nam(some_groups_overridden2):
    """
    Test "some" scope with group list containing some
    overridden groups, and users requested with getpwnam.
    """
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002, shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_groups_overridden2_uid(some_groups_overridden2):
    """
    Test "some" scope with group list containing some
    overridden groups, and users requested with getpwuid.
    """
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002, shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_groups_overridden2_ent(some_groups_overridden2):
    """
    Test "some" scope with group list containing some
    overridden groups, and users requested with getpwent.
    """
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def some_groups_overridden3(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", having two primary groups with
    IDs swapped via overriding, but only one of them listed.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            groups = group2
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    subprocess.check_call(["sss_override", "group-add", "group1",
                           "-g", "2002"])
    subprocess.check_call(["sss_override", "group-add", "group2",
                           "-g", "2001"])
    restart_sssd()


def test_some_groups_overridden3_nam(some_groups_overridden3):
    """
    Test "some" scope with group list containing some
    overridden group, and users requested with getpwnam.
    """
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002, shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_groups_overridden3_uid(some_groups_overridden3):
    """
    Test "some" scope with group list containing some
    overridden group, and users requested with getpwuid.
    """
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002, shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_groups_overridden3_ent(some_groups_overridden3):
    """
    Test "some" scope with group list containing some
    overridden group, and users requested with getpwent.
    """
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def some_groups_overridden4(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", two users with GIDs swapped via overridding,
    and one of their primary groups listed.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            groups = group2
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    subprocess.check_call(["sss_override", "user-add", "user1",
                           "-g", "2002"])
    subprocess.check_call(["sss_override", "user-add", "user2",
                           "-g", "2001"])
    restart_sssd()


def test_some_groups_overridden4_nam(some_groups_overridden3):
    """
    Test "some" scope with group list containing some
    overridden group, and users requested with getpwnam.
    """
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002, shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_groups_overridden4_uid(some_groups_overridden3):
    """
    Test "some" scope with group list containing some
    overridden group, and users requested with getpwuid.
    """
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002, shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_groups_overridden4_ent(some_groups_overridden3):
    """
    Test "some" scope with group list containing some
    overridden group, and users requested with getpwent.
    """
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def some_users_and_groups(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some", listing some users and groups.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            users = user3
            groups = one_user_group
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_some_users_and_groups_nam(some_users_and_groups):
    """
    Test "some" scope with user and group lists and getpwnam.
    """
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002, shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003,
                   shell=config.SESSION_RECORDING_SHELL),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_users_and_groups_uid(some_users_and_groups):
    """
    Test "some" scope with user and group lists and getpwuid.
    """
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002, shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003,
                   shell=config.SESSION_RECORDING_SHELL),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_users_and_groups_ent(some_users_and_groups):
    """
    Test "some" scope with user and group lists and getpwent.
    """
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )


@pytest.fixture
def all_exclude_users(request, ldap_conn, users_and_groups):
    """
    Test "all" scope with a simple excludes user list
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = all
            exclude_users = user1, user3
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_all_exclude_users_nam(all_exclude_users):
    """Test "all" scope with exclude users list and getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001, shell="/bin/sh1"),
        user2=dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004,
                   shell=config.SESSION_RECORDING_SHELL),
    ))


def test_all_exclude_users_uid(all_exclude_users):
    """Test "all" scope with exclude users list and getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001, shell="/bin/sh1"),
        1002: dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004,
                   shell=config.SESSION_RECORDING_SHELL),
    })


def test_all_exclude_users_ent(all_exclude_users):
    """Test "all" scope with exclude users list and getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell="/bin/sh1"),
            dict(name="user2", uid=1002, shell=config.SESSION_RECORDING_SHELL),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell=config.SESSION_RECORDING_SHELL),
        )
    )


@pytest.fixture
def all_exclude_groups(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "all", specifying two primary exclude
    groups and one supplementary exclude group.
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = all
            exclude_groups = group1, group3, two_user_group
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_all_exclude_groups_nam(all_exclude_groups):
    """Test "all" scope with exclude groups list and getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001, shell="/bin/sh1"),
        user2=dict(name="user2", uid=1002, shell="/bin/sh2"),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004,
                   shell=config.SESSION_RECORDING_SHELL),
    ))


def test_all_exclude_groups_uid(all_exclude_groups):
    """Test "all" scope with group list and getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001, shell="/bin/sh1"),
        1002: dict(name="user2", uid=1002, shell="/bin/sh2"),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004,
                   shell=config.SESSION_RECORDING_SHELL),
    })


def test_all_exclude_groups_ent(all_exclude_groups):
    """Test "all" scope with group list and getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001, shell="/bin/sh1"),
            dict(name="user2", uid=1002, shell="/bin/sh2"),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004,
                 shell=config.SESSION_RECORDING_SHELL),
        )
    )


@pytest.fixture
def some_users_and_exclude_groups(request, ldap_conn, users_and_groups):
    """
    Fixture with scope "some" containing users to
    enable recording, and exclude_* options to be ignored
    intentionally
    """
    conf = \
        format_basic_conf(ldap_conn, SCHEMA_RFC2307) + \
        unindent("""\
            [session_recording]
            scope = some
            users = user1, user2
            exclude_users = user1, user2, user3
            exclude_groups = group1, group3, two_user_group
        """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)


def test_some_users_and_exclude_groups_nam(some_users_and_exclude_groups):
    """Test "some" scope with exclude users and groups list and getpwnam"""
    ent.assert_each_passwd_by_name(dict(
        user1=dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        user2=dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        user3=dict(name="user3", uid=1003, shell="/bin/sh3"),
        user4=dict(name="user4", uid=1004, shell="/bin/sh4"),
    ))


def test_some_users_and_exclude_groups_uid(some_users_and_exclude_groups):
    """Test "some" scope with exclude users and groups list and getpwuid"""
    ent.assert_each_passwd_by_uid({
        1001: dict(name="user1", uid=1001,
                   shell=config.SESSION_RECORDING_SHELL),
        1002: dict(name="user2", uid=1002,
                   shell=config.SESSION_RECORDING_SHELL),
        1003: dict(name="user3", uid=1003, shell="/bin/sh3"),
        1004: dict(name="user4", uid=1004, shell="/bin/sh4"),
    })


def test_some_users_and_exclude_groups_ent(some_users_and_exclude_groups):
    """Test "some" scope with exclude users and group list and getpwent"""
    ent.assert_passwd_list(
        ent.contains_only(
            dict(name="user1", uid=1001,
                 shell=config.SESSION_RECORDING_SHELL),
            dict(name="user2", uid=1002,
                 shell=config.SESSION_RECORDING_SHELL),
            dict(name="user3", uid=1003, shell="/bin/sh3"),
            dict(name="user4", uid=1004, shell="/bin/sh4"),
        )
    )
