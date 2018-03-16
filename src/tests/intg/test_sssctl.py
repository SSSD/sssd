#
# sssctl tool integration test
#
# Copyright (c) 2016 Red Hat, Inc.
# Author: Michal Zidek <mzidek@redhat.com>
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
import ent
import grp
import pwd
import subprocess
import pytest
import stat
import time
import signal
import ds_openldap
import ldap_ent
import config
from util import unindent, get_call_output
import sssd_netgroup

LDAP_BASE_DN = "dc=example,dc=com"


@pytest.fixture(scope="module")
def ds_inst(request):
    """LDAP server instance fixture"""
    ds_inst = ds_openldap.DSOpenLDAP(
        config.PREFIX, 10389, LDAP_BASE_DN,
        "cn=admin", "Secret123")
    try:
        ds_inst.setup()
    except:
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
        except:
            break
        time.sleep(1)


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
def portable_LC_ALL(request):
    os.environ["LC_ALL"] = "C"
    return None


def load_data_to_ldap(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("CamelCaseUser1", 1002, 2002)

    ent_list.add_group("group1", 2001, ["user1"])
    ent_list.add_group("CamelCaseGroup1", 2002, ["CamelCaseUser1"])

    create_ldap_fixture(request, ldap_conn, ent_list)


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
        ldap_netgroup_search_base = ou=Netgroups,{ldap_conn.ds_inst.base_dn}
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


def test_user_show_basic_sanity(ldap_conn, sanity_rfc2307, portable_LC_ALL):
    # Fill the cache first
    ent.assert_passwd_by_name(
        'user1',
        dict(name='user1', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_name(
        'CamelCaseUser1',
        dict(name='CamelCaseUser1', passwd='*', uid=1002, gid=2002,
             gecos='1002', shell='/bin/bash'))

    output = get_call_output(["sssctl", "user-show", "user1"])
    assert output.find("Name: user1") != -1
    assert output.find("Initgroups expiration time: Initgroups were not yet "
                       "performed") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "user-show",
                              "CamelCaseUser1"])
    assert output.find("Name: CamelCaseUser1") != -1
    assert output.find("Initgroups expiration time: Initgroups were not yet "
                       "performed") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "user-show", "camelcaseuser1"])
    assert output.find("User camelcaseuser1 is not present in cache.") != -1


def test_user_show_basic_fqname(ldap_conn, fqname_rfc2307, portable_LC_ALL):
    # Fill the cache first
    ent.assert_passwd_by_name(
        'user1@LDAP',
        dict(name='user1@LDAP', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_name(
        'CamelCaseUser1@LDAP',
        dict(name='CamelCaseUser1@LDAP', passwd='*', uid=1002, gid=2002,
             gecos='1002', shell='/bin/bash'))

    output = get_call_output(["sssctl", "user-show", "user1@LDAP"])
    assert output.find("Name: user1@LDAP") != -1
    assert output.find("Initgroups expiration time: Initgroups were not yet "
                       "performed") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "user-show", "CamelCaseUser1@LDAP"])
    assert output.find("Name: CamelCaseUser1@LDAP") != -1
    assert output.find("Initgroups expiration time: Initgroups were not yet "
                       "performed") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "user-show", "camelcaseuser1@LDAP"])
    assert output.find("User camelcaseuser1 is not present in cache.") != -1


def test_user_show_basic_fqname_insensitive(ldap_conn,
                                            fqname_case_insensitive_rfc2307,
                                            portable_LC_ALL):
    # Fill the cache first
    ent.assert_passwd_by_name(
        'user1@LDAP',
        dict(name='user1@LDAP', passwd='*', uid=1001, gid=2001,
             gecos='1001', shell='/bin/bash'))
    ent.assert_passwd_by_name(
        'CamelCaseUser1@LDAP',
        dict(name='camelcaseuser1@LDAP', passwd='*', uid=1002, gid=2002,
             gecos='1002', shell='/bin/bash'))

    output = get_call_output(["sssctl", "user-show", "user1@LDAP"])
    assert output.find("Name: user1@LDAP") != -1
    assert output.find("Initgroups expiration time: Initgroups were not yet "
                       "performed") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "user-show", "CamelCaseUser1@LDAP"])
    assert output.find("Name: camelcaseuser1@LDAP") != -1
    assert output.find("Initgroups expiration time: Initgroups were not yet "
                       "performed") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "user-show", "camelcaseuser1@LDAP"])
    assert output.find("Name: camelcaseuser1@LDAP") != -1
    assert output.find("Initgroups expiration time: Initgroups were not yet "
                       "performed") != -1
    assert output.find("Cached in InfoPipe: No") != -1


def test_group_show_basic_sanity(ldap_conn, sanity_rfc2307, portable_LC_ALL):
    # Fill the cache first
    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1")))
    ent.assert_group_by_name(
        "CamelCaseGroup1",
        dict(mem=ent.contains_only("CamelCaseUser1")))

    output = get_call_output(["sssctl", "group-show", "group1"])
    assert output.find("Name: group1") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "group-show", "CamelCaseGroup1"])
    assert output.find("Name: CamelCaseGroup1") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "group-show", "camelcasegroup1"])
    assert output.find("Group camelcasegroup1 is not present in cache.") != -1


def test_group_show_basic_fqname(ldap_conn, fqname_rfc2307, portable_LC_ALL):
    # Fill the cache first
    ent.assert_group_by_name(
        "group1@LDAP",
        dict(mem=ent.contains_only("user1@LDAP")))
    ent.assert_group_by_name(
        "CamelCaseGroup1@LDAP",
        dict(mem=ent.contains_only("CamelCaseUser1@LDAP")))

    output = get_call_output(["sssctl", "group-show", "group1@LDAP"])
    assert output.find("Name: group1@LDAP") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "group-show", "CamelCaseGroup1@LDAP"])
    assert output.find("Name: CamelCaseGroup1@LDAP") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "group-show", "camelcasegroup1@LDAP"])
    assert output.find("Group camelcasegroup1 is not present in cache.") != -1


def test_group_show_basic_fqname_insensitive(ldap_conn,
                                             fqname_case_insensitive_rfc2307,
                                             portable_LC_ALL):
    # Fill the cache first
    ent.assert_group_by_name(
        "group1@LDAP",
        dict(mem=ent.contains_only("user1@LDAP")))
    ent.assert_group_by_name(
        "camelcasegroup1@LDAP",
        dict(mem=ent.contains_only("camelcaseuser1@LDAP")))

    output = get_call_output(["sssctl", "group-show", "group1@LDAP"])
    assert output.find("Name: group1@LDAP") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "group-show", "CamelCaseGroup1@LDAP"])
    assert output.find("Name: camelcasegroup1@LDAP") != -1
    assert output.find("Cached in InfoPipe: No") != -1

    output = get_call_output(["sssctl", "group-show", "camelcasegroup1@LDAP"])
    assert output.find("Name: camelcasegroup1@LDAP") != -1
    assert output.find("Cached in InfoPipe: No") != -1


@pytest.fixture
def add_tripled_netgroup(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_netgroup("tripled_netgroup", ["(host,user,domain)"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    return None


def test_netgroup_show(ldap_conn,
                       sanity_rfc2307,
                       portable_LC_ALL,
                       add_tripled_netgroup):
    output = get_call_output(["sssctl", "netgroup-show", "tripled_netgroup"])
    assert "Name: tripled_netgroup" not in output

    res, _, netgrps = sssd_netgroup.get_sssd_netgroups("tripled_netgroup")
    assert res == sssd_netgroup.NssReturnCode.SUCCESS
    assert netgrps == [("host", "user", "domain")]

    output = get_call_output(["sssctl", "netgroup-show", "tripled_netgroup"])
    assert "Name: tripled_netgroup" in output
