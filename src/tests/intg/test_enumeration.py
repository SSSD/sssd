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

# Enumeration is run periodically. It is scheduled during SSSD startup
# and then it runs every four seconds. We do not know precisely when
# the enumeration refresh is triggered so sleeping for four seconds is
# not enough, we have to sleep longer time to adapt for delays (it is
# not scheduled on precise time because of other sssd operation, it
# takes some time to finish so each run moves it further away from
# exact 4 seconds period, cpu scheduler, context switches, ...).
# The random offset is set to 0 to prevent it from being applied to the
# periodic tasks, but mainly to the initial delay.
# I agree that just little bit longer timeout may work as well.
# However we can be sure when using twice the period because we know
# that enumeration was indeed run at least once.
ENUMERATION_TIMEOUT = 4
INTERACTIVE_TIMEOUT = ENUMERATION_TIMEOUT * 2


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
    Format a basic SSSD configuration

    The files domain is defined but not enabled in order to avoid enumerating
    users from the files domain that would otherwise by implicitly enabled
    """
    schema_conf = "ldap_schema         = " + schema + "\n"
    if schema == SCHEMA_RFC2307_BIS:
        schema_conf += "ldap_group_object_class = groupOfNames\n"
    return unindent("""\
        [sssd]
        debug_level                     = 0xffff
        domains                         = LDAP
        services                        = nss, pam
        enable_files_domain             = false

        [nss]
        debug_level                     = 0xffff
        memcache_timeout                = 0

        [pam]
        debug_level                     = 0xffff

        [domain/files]
        id_provider                     = proxy
        proxy_lib_name                  = files
        auth_provider                   = none

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_id_use_start_tls           = false
        debug_level                     = 0xffff
        enumerate                       = true
        {schema_conf}
        id_provider                     = ldap
        auth_provider                   = ldap
        ldap_enumeration_refresh_offset = 0
        ldap_uri                        = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base                = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())


def format_interactive_conf(ldap_conn, schema):
    """Format an SSSD configuration with all caches refreshing in 4 seconds"""
    return \
        format_basic_conf(ldap_conn, schema) + \
        unindent("""
            [nss]
            memcache_timeout                    = 0
            enum_cache_timeout                  = {0}
            entry_negative_timeout              = 0

            [domain/LDAP]
            ldap_enumeration_refresh_timeout    = {0}
            ldap_purge_cache_timeout            = 1
            entry_cache_timeout                 = {0}
        """).format(ENUMERATION_TIMEOUT)


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
    create_ldap_fixture(request, ldap_conn, ent_list)

    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def populate_rfc2307bis(request, ldap_conn):
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


@pytest.fixture
def sanity_rfc2307_bis(request, ldap_conn):
    populate_rfc2307bis(request, ldap_conn)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_sanity_rfc2307(ldap_conn, sanity_rfc2307):
    time.sleep(INTERACTIVE_TIMEOUT)
    passwd_pattern = ent.contains_only(
        dict(name='user1', passwd='*', uid=1001, gid=2001, gecos='1001',
             dir='/home/user1', shell='/bin/bash'),
        dict(name='user2', passwd='*', uid=1002, gid=2002, gecos='1002',
             dir='/home/user2', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=2003, gecos='1003',
             dir='/home/user3', shell='/bin/bash')
    )
    ent.assert_passwd(passwd_pattern)

    group_pattern = ent.contains_only(
        dict(name='group1', passwd='*', gid=2001, mem=ent.contains_only()),
        dict(name='group2', passwd='*', gid=2002, mem=ent.contains_only()),
        dict(name='group3', passwd='*', gid=2003, mem=ent.contains_only()),
        dict(name='empty_group', passwd='*', gid=2010,
             mem=ent.contains_only()),
        dict(name='two_user_group', passwd='*', gid=2012,
             mem=ent.contains_only("user1", "user2"))
    )
    ent.assert_group(group_pattern)

    with pytest.raises(KeyError):
        pwd.getpwnam("non_existent_user")
    with pytest.raises(KeyError):
        pwd.getpwuid(1)
    with pytest.raises(KeyError):
        grp.getgrnam("non_existent_group")
    with pytest.raises(KeyError):
        grp.getgrgid(1)


def test_sanity_rfc2307_bis(ldap_conn, sanity_rfc2307_bis):
    time.sleep(INTERACTIVE_TIMEOUT)
    passwd_pattern = ent.contains_only(
        dict(name='user1', passwd='*', uid=1001, gid=2001, gecos='1001',
             dir='/home/user1', shell='/bin/bash'),
        dict(name='user2', passwd='*', uid=1002, gid=2002, gecos='1002',
             dir='/home/user2', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=2003, gecos='1003',
             dir='/home/user3', shell='/bin/bash')
    )
    ent.assert_passwd(passwd_pattern)

    group_pattern = ent.contains_only(
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
    )
    ent.assert_group(group_pattern)

    with pytest.raises(KeyError):
        pwd.getpwnam("non_existent_user")
    with pytest.raises(KeyError):
        pwd.getpwuid(1)
    with pytest.raises(KeyError):
        grp.getgrnam("non_existent_group")
    with pytest.raises(KeyError):
        grp.getgrgid(1)


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


def test_add_remove_user(ldap_conn, blank_rfc2307):
    """Test user addition and removal are reflected by SSSD"""
    e = ldap_ent.user(ldap_conn.ds_inst.base_dn, "user", 2001, 2000)
    time.sleep(INTERACTIVE_TIMEOUT)
    # Add the user
    ent.assert_passwd(ent.contains_only())
    ldap_conn.add_s(*e)
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_passwd(ent.contains_only(dict(name="user", uid=2001)))
    # Remove the user
    ldap_conn.delete_s(e[0])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_passwd(ent.contains_only())


def test_add_remove_group_rfc2307(ldap_conn, blank_rfc2307):
    """Test RFC2307 group addition and removal are reflected by SSSD"""
    e = ldap_ent.group(ldap_conn.ds_inst.base_dn, "group", 2001)
    time.sleep(INTERACTIVE_TIMEOUT)
    # Add the group
    ent.assert_group(ent.contains_only())
    ldap_conn.add_s(*e)
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group(ent.contains_only(dict(name="group", gid=2001)))
    # Remove the group
    ldap_conn.delete_s(e[0])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group(ent.contains_only())


def test_add_remove_group_rfc2307_bis(ldap_conn, blank_rfc2307_bis):
    """Test RFC2307bis group addition and removal are reflected by SSSD"""
    e = ldap_ent.group_bis(ldap_conn.ds_inst.base_dn, "group", 2001)
    time.sleep(INTERACTIVE_TIMEOUT)
    # Add the group
    ent.assert_group(ent.contains_only())
    ldap_conn.add_s(*e)
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group(ent.contains_only(dict(name="group", gid=2001)))
    # Remove the group
    ldap_conn.delete_s(e[0])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group(ent.contains_only())


def test_add_remove_membership_rfc2307(ldap_conn, user_and_group_rfc2307):
    """Test user membership addition and removal are reflected by SSSD"""
    time.sleep(INTERACTIVE_TIMEOUT)
    # Add user to group
    ent.assert_group_by_name("group", dict(mem=ent.contains_only()))
    ldap_conn.modify_s("cn=group,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_REPLACE, "memberUid", b"user")])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group_by_name("group", dict(mem=ent.contains_only("user")))
    # Remove user from group
    ldap_conn.modify_s("cn=group,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_DELETE, "memberUid", None)])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group_by_name("group", dict(mem=ent.contains_only()))


def test_add_remove_membership_rfc2307_bis(ldap_conn,
                                           user_and_groups_rfc2307_bis):
    """
    Test user and group membership addition and removal are reflected by SSSD,
    with RFC2307bis schema
    """
    base_dn_bytes = ldap_conn.ds_inst.base_dn.encode('utf-8')

    time.sleep(INTERACTIVE_TIMEOUT)
    # Add user to group1
    ent.assert_group_by_name("group1", dict(mem=ent.contains_only()))
    ldap_conn.modify_s("cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_REPLACE, "member",
                         b"uid=user,ou=Users," + base_dn_bytes)])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group_by_name("group1", dict(mem=ent.contains_only("user")))

    # Add group1 to group2
    ldap_conn.modify_s("cn=group2,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_REPLACE, "member",
                         b"cn=group1,ou=Groups," + base_dn_bytes)])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group_by_name("group2", dict(mem=ent.contains_only("user")))

    # Remove group1 from group2
    ldap_conn.modify_s("cn=group2,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_DELETE, "member", None)])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group_by_name("group2", dict(mem=ent.contains_only()))

    # Remove user from group1
    ldap_conn.modify_s("cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_DELETE, "member", None)])
    time.sleep(INTERACTIVE_TIMEOUT)
    ent.assert_group_by_name("group1", dict(mem=ent.contains_only()))


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
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_homedir_A", uid=1001, dir="/home/B"),
            dict(name="user_with_homedir_B", uid=1002, dir="/home/B"),
            dict(name="user_with_empty_homedir", uid=1003, dir="/home/B")
        )
    )


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
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_homedir_A", uid=1001, dir="/home/A"),
            dict(name="user_with_homedir_B", uid=1002, dir="/home/B"),
            dict(name="user_with_empty_homedir", uid=1003, dir="/home/B")
        )
    )


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
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_shell_A", uid=1001, shell="/bin/B"),
            dict(name="user_with_shell_B", uid=1002, shell="/bin/B"),
            dict(name="user_with_empty_shell", uid=1003, shell="/bin/B")
        )
    )


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
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
            dict(name="user_with_not_installed_shell", uid=1002,
                 shell="/bin/fallback"),
            dict(name="user_with_empty_shell", uid=1003, shell="")
        )
    )


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
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
            dict(name="user_with_not_installed_shell", uid=1002,
                 shell="/bin/fallback"),
            dict(name="user_with_empty_shell", uid=1003,
                 shell="/bin/default")
        )
    )


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
    ent.assert_passwd(
        ent.contains_only(
            dict(name="user_with_sh_shell", uid=1001, shell="/bin/sh"),
            dict(name="user_with_vetoed_shell", uid=1002,
                 shell="/bin/fallback"),
            dict(name="user_with_empty_shell", uid=1003,
                 shell="/bin/default")
        )
    )


@pytest.fixture
def sanity_rfc2307_bis_mpg(request, ldap_conn):
    populate_rfc2307bis(request, ldap_conn)

    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_group_bis("conflict1", 1001)
    ent_list.add_group_bis("conflict2", 1002)
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


def test_ldap_auto_private_groups_enumerate(ldap_conn,
                                            sanity_rfc2307_bis_mpg):
    """
    Test the auto_private_groups together with enumeration
    """
    passwd_pattern = ent.contains_only(
        dict(name='user1', passwd='*', uid=1001, gid=1001, gecos='1001',
             dir='/home/user1', shell='/bin/bash'),
        dict(name='user2', passwd='*', uid=1002, gid=1002, gecos='1002',
             dir='/home/user2', shell='/bin/bash'),
        dict(name='user3', passwd='*', uid=1003, gid=1003, gecos='1003',
             dir='/home/user3', shell='/bin/bash')
    )
    ent.assert_passwd(passwd_pattern)

    group_pattern = ent.contains_only(
        dict(name='user1', passwd='*', gid=1001, mem=ent.contains_only()),
        dict(name='user2', passwd='*', gid=1002, mem=ent.contains_only()),
        dict(name='user3', passwd='*', gid=1003, mem=ent.contains_only()),
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
    )
    ent.assert_group(group_pattern)

    with pytest.raises(KeyError):
        grp.getgrnam("conflict1")
    ent.assert_group_by_gid(1002, dict(name="user2", mem=ent.contains_only()))
