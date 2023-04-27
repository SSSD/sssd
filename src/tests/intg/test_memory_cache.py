#
# LDAP integration test
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Lukas Slebodnik <lslebodn@redhat.com>
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
import grp
import pwd
import config
import random
import signal
import string
import struct
import subprocess
import time
import pytest
import pysss_murmur

import ds_openldap
import ldap_ent
import sssd_id
from util import unindent

LDAP_BASE_DN = "dc=example,dc=com"


@pytest.fixture(scope="module")
def ds_inst(request):
    """LDAP server instance fixture"""
    ds_inst = ds_openldap.DSOpenLDAP(
        config.PREFIX, 10389, LDAP_BASE_DN,
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
        # force sss_client libs to realize mem-cache files were deleted
        try:
            sssd_id.call_sssd_initgroups("user1", 2001)
        except Exception:
            pass
        try:
            grp.getgrnam("group1")
        except Exception:
            pass
        try:
            pwd.getpwnam("user1")
        except Exception:
            pass
    request.addfinalizer(teardown)


def load_data_to_ldap(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)
    ent_list.add_user("user11", 1011, 2001)
    ent_list.add_user("user12", 1012, 2002)
    ent_list.add_user("user13", 1013, 2003)
    ent_list.add_user("user21", 1021, 2001)
    ent_list.add_user("user22", 1022, 2002)
    ent_list.add_user("user23", 1023, 2003)

    ent_list.add_group("group1", 2001, ["user1", "user11", "user21"])
    ent_list.add_group("group2", 2002, ["user2", "user12", "user22"])
    ent_list.add_group("group3", 2003, ["user3", "user13", "user23"])

    ent_list.add_group("group0x", 2000, ["user1", "user2", "user3"])
    ent_list.add_group("group1x", 2010, ["user11", "user12", "user13"])
    ent_list.add_group("group2x", 2020, ["user21", "user22", "user23"])
    create_ldap_fixture(request, ldap_conn, ent_list)


@pytest.fixture
def disable_memcache_rfc2307(request, ldap_conn):
    load_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        memcache_size_group = 0
        memcache_size_passwd = 0
        memcache_size_initgroups = 0

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def disable_pwd_mc_rfc2307(request, ldap_conn):
    load_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        memcache_size_passwd = 0

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def disable_grp_mc_rfc2307(request, ldap_conn):
    load_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        memcache_size_group = 0

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def disable_initgr_mc_rfc2307(request, ldap_conn):
    load_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        memcache_size_initgroups = 0

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def sanity_rfc2307(request, ldap_conn):
    load_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def fqname_rfc2307(request, ldap_conn):
    load_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
        use_fully_qualified_names = true
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def fqname_case_insensitive_rfc2307(request, ldap_conn):
    load_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
        use_fully_qualified_names = true
        case_sensitive = false
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def zero_timeout_rfc2307(request, ldap_conn):
    load_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        memcache_timeout = 0

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        ldap_schema         = rfc2307
        id_provider         = ldap
        auth_provider       = ldap
        sudo_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.mark.converted('test_id.py', 'test_id__getpwuid')
@pytest.mark.converted('test_id.py', 'test_id__getpwnam')
def test_getpwnam(ldap_conn, sanity_rfc2307):
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user2',
        dict(name='user2', passwd='*', uid=1002, gid=2002,
             gecos='1002', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1002,
        dict(name='user2', passwd='*', uid=1002, gid=2002,
             gecos='1002', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user3',
        dict(name='user3', passwd='*', uid=1003, gid=2003,
             gecos='1003', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1003,
        dict(name='user3', passwd='*', uid=1003, gid=2003,
             gecos='1003', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user11',
        dict(name='user11', passwd='*', uid=1011, gid=2001,
             gecos='1011', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1011,
        dict(name='user11', passwd='*', uid=1011, gid=2001,
             gecos='1011', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user12',
        dict(name='user12', passwd='*', uid=1012, gid=2002,
             gecos='1012', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1012,
        dict(name='user12', passwd='*', uid=1012, gid=2002,
             gecos='1012', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user13',
        dict(name='user13', passwd='*', uid=1013, gid=2003,
             gecos='1013', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1013,
        dict(name='user13', passwd='*', uid=1013, gid=2003,
             gecos='1013', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user21',
        dict(name='user21', passwd='*', uid=1021, gid=2001,
             gecos='1021', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1021,
        dict(name='user21', passwd='*', uid=1021, gid=2001,
             gecos='1021', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user22',
        dict(name='user22', passwd='*', uid=1022, gid=2002,
             gecos='1022', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1022,
        dict(name='user22', passwd='*', uid=1022, gid=2002,
             gecos='1022', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        'user23',
        dict(name='user23', passwd='*', uid=1023, gid=2003,
             gecos='1023', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1023,
        dict(name='user23', passwd='*', uid=1023, gid=2003,
             gecos='1023', shell='/bin/bash'))


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__getpwnam')
def test_getpwnam_with_mc(ldap_conn, sanity_rfc2307):
    test_getpwnam(ldap_conn, sanity_rfc2307)
    stop_sssd()
    test_getpwnam(ldap_conn, sanity_rfc2307)


@pytest.mark.converted('test_id.py', 'test_id__getgrgid')
@pytest.mark.converted('test_id.py', 'test_id__getgrnam')
def test_getgrnam_simple(ldap_conn, sanity_rfc2307):
    ent.assert_group_by_name("group1", dict(name="group1", gid=2001))
    ent.assert_group_by_gid(2001, dict(name="group1", gid=2001))

    ent.assert_group_by_name("group2", dict(name="group2", gid=2002))
    ent.assert_group_by_gid(2002, dict(name="group2", gid=2002))

    ent.assert_group_by_name("group3", dict(name="group3", gid=2003))
    ent.assert_group_by_gid(2003, dict(name="group3", gid=2003))

    ent.assert_group_by_name("group0x", dict(name="group0x", gid=2000))
    ent.assert_group_by_gid(2000, dict(name="group0x", gid=2000))

    ent.assert_group_by_name("group1x", dict(name="group1x", gid=2010))
    ent.assert_group_by_gid(2010, dict(name="group1x", gid=2010))

    ent.assert_group_by_name("group2x", dict(name="group2x", gid=2020))
    ent.assert_group_by_gid(2020, dict(name="group2x", gid=2020))


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__getgrnam')
def test_getgrnam_simple_with_mc(ldap_conn, sanity_rfc2307):
    test_getgrnam_simple(ldap_conn, sanity_rfc2307)
    stop_sssd()
    test_getgrnam_simple(ldap_conn, sanity_rfc2307)


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__disabled_passwd_getgrnam')
def test_getgrnam_simple_disabled_pwd_mc(ldap_conn, disable_pwd_mc_rfc2307):
    test_getgrnam_simple(ldap_conn, disable_pwd_mc_rfc2307)
    stop_sssd()
    test_getgrnam_simple(ldap_conn, disable_pwd_mc_rfc2307)


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__disabled_intitgroups_getgrnam')
def test_getgrnam_simple_disabled_intitgr_mc(ldap_conn,
                                             disable_initgr_mc_rfc2307):
    test_getgrnam_simple(ldap_conn, disable_initgr_mc_rfc2307)
    stop_sssd()
    test_getgrnam_simple(ldap_conn, disable_initgr_mc_rfc2307)


@pytest.mark.converted('test_id.py', 'test_id__membership_by_group_id')
@pytest.mark.converted('test_id.py', 'test_id__membership_by_group_name')
def test_getgrnam_membership(ldap_conn, sanity_rfc2307):
    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user11", "user21")))
    ent.assert_group_by_gid(
        2001,
        dict(mem=ent.contains_only("user1", "user11", "user21")))

    ent.assert_group_by_name(
        "group2",
        dict(mem=ent.contains_only("user2", "user12", "user22")))
    ent.assert_group_by_gid(
        2002,
        dict(mem=ent.contains_only("user2", "user12", "user22")))

    ent.assert_group_by_name(
        "group3",
        dict(mem=ent.contains_only("user3", "user13", "user23")))
    ent.assert_group_by_gid(
        2003,
        dict(mem=ent.contains_only("user3", "user13", "user23")))

    ent.assert_group_by_name(
        "group0x",
        dict(mem=ent.contains_only("user1", "user2", "user3")))
    ent.assert_group_by_gid(
        2000,
        dict(mem=ent.contains_only("user1", "user2", "user3")))

    ent.assert_group_by_name(
        "group1x",
        dict(mem=ent.contains_only("user11", "user12", "user13")))
    ent.assert_group_by_gid(
        2010,
        dict(mem=ent.contains_only("user11", "user12", "user13")))

    ent.assert_group_by_name(
        "group2x",
        dict(mem=ent.contains_only("user21", "user22", "user23")))
    ent.assert_group_by_gid(
        2020,
        dict(mem=ent.contains_only("user21", "user22", "user23")))


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__membership_by_group_id')
@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__membership_by_group_name')
def test_getgrnam_membership_with_mc(ldap_conn, sanity_rfc2307):
    test_getgrnam_membership(ldap_conn, sanity_rfc2307)
    stop_sssd()
    test_getgrnam_membership(ldap_conn, sanity_rfc2307)


def assert_user_gids_equal(user, expected_gids):
    (res, errno, gids) = sssd_id.get_user_gids(user)
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user %s, %d" % (user, errno)

    assert sorted(gids) == sorted(expected_gids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(expected_gids)])
    )


@pytest.mark.converted('test_id.py', 'test_id__initgroups')
def test_initgroups(ldap_conn, sanity_rfc2307):
    assert_user_gids_equal('user1', [2000, 2001])
    assert_user_gids_equal('user2', [2000, 2002])
    assert_user_gids_equal('user3', [2000, 2003])

    assert_user_gids_equal('user11', [2010, 2001])
    assert_user_gids_equal('user12', [2010, 2002])
    assert_user_gids_equal('user13', [2010, 2003])

    assert_user_gids_equal('user21', [2020, 2001])
    assert_user_gids_equal('user22', [2020, 2002])
    assert_user_gids_equal('user23', [2020, 2003])


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__user_gids')
def test_initgroups_with_mc(ldap_conn, sanity_rfc2307):
    test_initgroups(ldap_conn, sanity_rfc2307)
    stop_sssd()
    test_initgroups(ldap_conn, sanity_rfc2307)


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__getpwnam_fully_qualified_names')
@pytest.mark.converted('test_id.py', 'test_id__getpwnam_fully_qualified_names')
def test_initgroups_fqname_with_mc(ldap_conn, fqname_rfc2307):
    assert_user_gids_equal('user1@LDAP', [2000, 2001])
    stop_sssd()
    assert_user_gids_equal('user1@LDAP', [2000, 2001])


def assert_initgroups_equal(user, primary_gid, expected_gids):
    (res, errno, gids) = sssd_id.call_sssd_initgroups(user, primary_gid)
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user %s, %d" % (user, errno)

    assert sorted(gids) == sorted(expected_gids), \
        "result: %s\n expected %s" % (
            ", ".join(["%s" % s for s in sorted(gids)]),
            ", ".join(["%s" % s for s in sorted(expected_gids)])
    )


def assert_stored_last_initgroups(user1_case1, user1_case2, user1_case_last,
                                  primary_gid, expected_gids):

    assert_initgroups_equal(user1_case1, primary_gid, expected_gids)
    assert_initgroups_equal(user1_case2, primary_gid, expected_gids)
    assert_initgroups_equal(user1_case_last, primary_gid, expected_gids)
    stop_sssd()

    user = user1_case1
    (res, errno, _) = sssd_id.call_sssd_initgroups(user, primary_gid)
    assert res == sssd_id.NssReturnCode.UNAVAIL, \
        "Initgroups for user should fail user %s, %d, %d" % (user, res, errno)

    user = user1_case2
    (res, errno, _) = sssd_id.call_sssd_initgroups(user, primary_gid)
    assert res == sssd_id.NssReturnCode.UNAVAIL, \
        "Initgroups for user should fail user %s, %d, %d" % (user, res, errno)

    # Just last invocation of initgroups should PASS
    # Otherwise, we would not be able to invalidate it
    assert_initgroups_equal(user1_case_last, primary_gid, expected_gids)


@pytest.mark.converted('test_id.py', 'test_id__fq_names_case_insensitive')
@pytest.mark.converted('test_id.py', 'test_id__case_insensitive')
@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__fq_names_case_insensitive')
@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__case_insensitive')
def test_initgroups_case_insensitive_with_mc1(ldap_conn,
                                              fqname_case_insensitive_rfc2307):
    user1_case1 = 'User1@LDAP'
    user1_case2 = 'uSer1@LDAP'
    user1_case_last = 'usEr1@LDAP'
    primary_gid = 2001
    expected_gids = [2000, 2001]

    assert_stored_last_initgroups(user1_case1, user1_case2, user1_case_last,
                                  primary_gid, expected_gids)


@pytest.mark.converted('test_id.py', 'test_id__fq_names_case_insensitive')
@pytest.mark.converted('test_id.py', 'test_id__case_insensitive')
@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__fq_names_case_insensitive')
@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__case_insensitive')
def test_initgroups_case_insensitive_with_mc2(ldap_conn,
                                              fqname_case_insensitive_rfc2307):
    user1_case1 = 'usEr1@LDAP'
    user1_case2 = 'User1@LDAP'
    user1_case_last = 'uSer1@LDAP'
    primary_gid = 2001
    expected_gids = [2000, 2001]

    assert_stored_last_initgroups(user1_case1, user1_case2, user1_case_last,
                                  primary_gid, expected_gids)


@pytest.mark.converted('test_id.py', 'test_id__fq_names_case_insensitive')
@pytest.mark.converted('test_id.py', 'test_id__case_insensitive')
@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__fq_names_case_insensitive')
@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__case_insensitive')
def test_initgroups_case_insensitive_with_mc3(ldap_conn,
                                              fqname_case_insensitive_rfc2307):
    user1_case1 = 'uSer1@LDAP'
    user1_case2 = 'usEr1@LDAP'
    user1_case_last = 'User1@LDAP'
    primary_gid = 2001
    expected_gids = [2000, 2001]

    assert_stored_last_initgroups(user1_case1, user1_case2, user1_case_last,
                                  primary_gid, expected_gids)


def run_simple_test_with_initgroups():
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user11", "user21")))
    ent.assert_group_by_gid(
        2001,
        dict(mem=ent.contains_only("user1", "user11", "user21")))

    # unrelated group to user1
    ent.assert_group_by_name(
        "group2",
        dict(mem=ent.contains_only("user2", "user12", "user22")))
    ent.assert_group_by_gid(
        2002,
        dict(mem=ent.contains_only("user2", "user12", "user22")))

    assert_initgroups_equal("user1", 2001, [2000, 2001])


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidatation_of_gids_after_initgroups')
def test_invalidation_of_gids_after_initgroups(ldap_conn, sanity_rfc2307):

    # the sssd cache was empty and not all user's group were
    # resolved with getgr{nm,gid}. Therefore there is a change in
    # group membership => user groups should be invalidated
    run_simple_test_with_initgroups()
    assert_initgroups_equal("user1", 2001, [2000, 2001])

    stop_sssd()

    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    # unrelated group to user1 must be returned
    ent.assert_group_by_name(
        "group2",
        dict(mem=ent.contains_only("user2", "user12", "user22")))
    ent.assert_group_by_gid(
        2002,
        dict(mem=ent.contains_only("user2", "user12", "user22")))

    assert_initgroups_equal("user1", 2001, [2000, 2001])

    # user groups must be invalidated
    for group in ["group1", "group0x"]:
        with pytest.raises(KeyError):
            grp.getgrnam(group)

    for gid in [2000, 2001]:
        with pytest.raises(KeyError):
            grp.getgrgid(gid)


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__initgroups_without_change_in_membership')
def test_initgroups_without_change_in_membership(ldap_conn, sanity_rfc2307):

    # the sssd cache was empty and not all user's group were
    # resolved with getgr{nm,gid}. Therefore there is a change in
    # group membership => user groups should be invalidated
    run_simple_test_with_initgroups()

    # invalidate cache
    subprocess.call(["sss_cache", "-E"])

    # all users and groups will be just refreshed from LDAP
    # but there will not be a change in group membership
    # user groups should not be invlaidated
    run_simple_test_with_initgroups()

    stop_sssd()

    # everything should be in memory cache
    run_simple_test_with_initgroups()


def assert_mc_records_for_user1():
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user11", "user21")))
    ent.assert_group_by_gid(
        2001,
        dict(mem=ent.contains_only("user1", "user11", "user21")))
    ent.assert_group_by_name(
        "group0x",
        dict(mem=ent.contains_only("user1", "user2", "user3")))
    ent.assert_group_by_gid(
        2000,
        dict(mem=ent.contains_only("user1", "user2", "user3")))

    assert_initgroups_equal("user1", 2001, [2000, 2001])


def assert_missing_mc_records_for_user1():
    with pytest.raises(KeyError):
        pwd.getpwnam("user1")
    with pytest.raises(KeyError):
        pwd.getpwuid(1001)

    for gid in [2000, 2001]:
        with pytest.raises(KeyError):
            grp.getgrgid(gid)
    for group in ["group0x", "group1"]:
        with pytest.raises(KeyError):
            grp.getgrnam(group)

    (res, err, _) = sssd_id.call_sssd_initgroups("user1", 2001)
    assert res == sssd_id.NssReturnCode.UNAVAIL, \
        "Initgroups should not find anything after invalidation of mc.\n" \
        "User user1, errno:%d" % err


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_user_before_stop')
def test_invalidate_user_before_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    subprocess.call(["sss_cache", "-u", "user1"])
    stop_sssd()

    assert_missing_mc_records_for_user1()


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_user_after_stop')
def test_invalidate_user_after_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    stop_sssd()
    subprocess.call(["sss_cache", "-u", "user1"])

    assert_missing_mc_records_for_user1()


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_users_before_stop')
def test_invalidate_users_before_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    subprocess.call(["sss_cache", "-U"])
    stop_sssd()

    assert_missing_mc_records_for_user1()


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_users_after_stop')
def test_invalidate_users_after_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    stop_sssd()
    subprocess.call(["sss_cache", "-U"])

    assert_missing_mc_records_for_user1()


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_group_before_stop')
def test_invalidate_group_before_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    subprocess.call(["sss_cache", "-g", "group1"])
    stop_sssd()

    assert_missing_mc_records_for_user1()


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_group_after_stop')
def test_invalidate_group_after_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    stop_sssd()
    subprocess.call(["sss_cache", "-g", "group1"])

    assert_missing_mc_records_for_user1()


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_groups_before_stop')
def test_invalidate_groups_before_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    subprocess.call(["sss_cache", "-G"])
    stop_sssd()

    assert_missing_mc_records_for_user1()


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_groups_after_stop')
def test_invalidate_groups_after_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    stop_sssd()
    subprocess.call(["sss_cache", "-G"])

    assert_missing_mc_records_for_user1()

@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_everything_before_stop')
def test_invalidate_everything_before_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    subprocess.call(["sss_cache", "-E"])
    stop_sssd()

    assert_missing_mc_records_for_user1()


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__invalidate_everything_after_stop')
def test_invalidate_everything_after_stop(ldap_conn, sanity_rfc2307):
    # initialize cache with full ID
    (res, errno, _) = sssd_id.get_user_groups("user1")
    assert res == sssd_id.NssReturnCode.SUCCESS, \
        "Could not find groups for user1, %d" % errno
    assert_mc_records_for_user1()

    stop_sssd()
    subprocess.call(["sss_cache", "-E"])

    assert_missing_mc_records_for_user1()


def get_random_string(length):
    return ''.join([random.choice(string.ascii_letters + string.digits)
                    for n in range(length)])


class MemoryCache(object):
    SIZEOF_UINT32_T = 4

    def __init__(self, path):
        with open(path, "rb") as fin:
            fin.seek(4 * self.SIZEOF_UINT32_T)
            self.seed = struct.unpack('i', fin.read(4))[0]
            self.data_size = struct.unpack('i', fin.read(4))[0]
            self.ft_size = struct.unpack('i', fin.read(4))[0]
            hash_len = struct.unpack('i', fin.read(4))[0]
            self.hash_size = hash_len / self.SIZEOF_UINT32_T

    def sss_nss_mc_hash(self, key):
        input_key = key + '\0'
        input_len = len(key) + 1

        murmur_hash = pysss_murmur.murmurhash3(input_key, input_len, self.seed)
        return murmur_hash % self.hash_size


def test_colliding_hashes(ldap_conn, sanity_rfc2307):
    """
    Regression test for ticket:
    https://github.com/SSSD/sssd/issues/4595
    """

    first_user = 'user1'

    # initialize data in memcache
    ent.assert_passwd_by_name(
        first_user,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    mem_cache = MemoryCache(config.MCACHE_PATH + '/passwd')

    colliding_hash = mem_cache.sss_nss_mc_hash(first_user)

    while True:
        # string for colliding hash need to be longer then data for user1
        # stored in memory cache (almost equivalent to:
        #   `getent passwd user1 | wc -c` ==> 45
        second_user = get_random_string(80)
        val = mem_cache.sss_nss_mc_hash(second_user)
        if val == colliding_hash:
            break

    # add new user to LDAP
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user(second_user, 5001, 5001)
    ldap_conn.add_s(ent_list[0][0], ent_list[0][1])

    ent.assert_passwd_by_name(
        second_user,
        dict(name=second_user, passwd='*', uid=5001, gid=5001,
             gecos='5001', shell='/bin/bash'))

    stop_sssd()

    # check that both users are stored in cache
    ent.assert_passwd_by_name(
        first_user,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_passwd_by_name(
        second_user,
        dict(name=second_user, passwd='*', uid=5001, gid=5001,
             gecos='5001', shell='/bin/bash'))


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__removed_cache_without_invalidation')
def test_removed_mc(ldap_conn, sanity_rfc2307):
    """
    Regression test for ticket:
    https://fedorahosted.org/sssd/ticket/2726
    """

    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_group_by_name("group1", dict(name="group1", gid=2001))
    ent.assert_group_by_gid(2001, dict(name="group1", gid=2001))
    stop_sssd()

    # remove cache without invalidation
    for path in os.listdir(config.MCACHE_PATH):
        os.unlink(config.MCACHE_PATH + "/" + path)

    # sssd is stopped; so the memory cache should not be used
    # in long living clients (py.test in this case)
    with pytest.raises(KeyError):
        pwd.getpwnam('user1')
    with pytest.raises(KeyError):
        pwd.getpwuid(1001)

    with pytest.raises(KeyError):
        grp.getgrnam('group1')
    with pytest.raises(KeyError):
        grp.getgrgid(2001)


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__memcache_timeout_zero')
def test_mc_zero_timeout(ldap_conn, zero_timeout_rfc2307):
    """
    Test that the memory cache is not created at all with memcache_timeout=0
    """
    # No memory cache files must be created
    assert len(os.listdir(config.MCACHE_PATH)) == 0

    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_group_by_name("group1", dict(name="group1", gid=2001))
    ent.assert_group_by_gid(2001, dict(name="group1", gid=2001))
    stop_sssd()

    # sssd is stopped; so the memory cache should not be used
    # in long living clients (py.test in this case)
    with pytest.raises(KeyError):
        pwd.getpwnam('user1')
    with pytest.raises(KeyError):
        pwd.getpwuid(1001)

    with pytest.raises(KeyError):
        grp.getgrnam('group1')
    with pytest.raises(KeyError):
        grp.getgrgid(2001)


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__disabled_cache')
def test_disabled_mc(ldap_conn, disable_memcache_rfc2307):
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_group_by_name("group1", dict(name="group1", gid=2001))
    ent.assert_group_by_gid(2001, dict(name="group1", gid=2001))

    assert_user_gids_equal('user1', [2000, 2001])

    stop_sssd()

    # sssd is stopped and the memory cache is disabled;
    # so pytest should not be able to find anything
    with pytest.raises(KeyError):
        pwd.getpwnam('user1')
    with pytest.raises(KeyError):
        pwd.getpwuid(1001)

    with pytest.raises(KeyError):
        grp.getgrnam('group1')
    with pytest.raises(KeyError):
        grp.getgrgid(2001)

    with pytest.raises(KeyError):
        (res, errno, gids) = sssd_id.get_user_gids('user1')


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__disabled_passwd_getpwnam')
def test_disabled_passwd_mc(ldap_conn, disable_pwd_mc_rfc2307):
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    assert_user_gids_equal('user1', [2000, 2001])

    stop_sssd()

    # passwd cache is disabled
    with pytest.raises(KeyError):
        pwd.getpwnam('user1')
    with pytest.raises(KeyError):
        pwd.getpwuid(1001)

    # Initgroups looks up the user first, hence KeyError from the
    # passwd database even if the initgroups cache is active.
    with pytest.raises(KeyError):
        (res, errno, gids) = sssd_id.get_user_gids('user1')


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__disabled_group')
def test_disabled_group_mc(ldap_conn, disable_grp_mc_rfc2307):
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    ent.assert_group_by_name("group1", dict(name="group1", gid=2001))
    ent.assert_group_by_gid(2001, dict(name="group1", gid=2001))

    assert_user_gids_equal('user1', [2000, 2001])

    stop_sssd()

    # group cache is disabled, other caches should work
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    with pytest.raises(KeyError):
        grp.getgrnam('group1')
    with pytest.raises(KeyError):
        grp.getgrgid(2001)

    assert_user_gids_equal('user1', [2000, 2001])


@pytest.mark.converted('test_memory_cache.py', 'test_memory_cache__disabled_intitgroups_getpwnam')
def test_disabled_initgr_mc(ldap_conn, disable_initgr_mc_rfc2307):
    # Even if initgroups is disabled, passwd should work
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))

    stop_sssd()

    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_uid(
        1001,
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
