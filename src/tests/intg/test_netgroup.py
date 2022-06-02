#
# Netgroup integration test
#
# Copyright (c) 2016 Red Hat, Inc.
# Author: Petr Cech <pcech@redhat.com>
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
import signal
import subprocess
import time
import ldap
import ldap.modlist
import pytest

import config
import ds_openldap
import ldap_ent
from util import unindent
from sssd_nss import NssReturnCode
from sssd_netgroup import get_sssd_netgroups

LDAP_BASE_DN = "dc=example,dc=com"


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


def create_ldap_fixture(request, ldap_conn, ent_list=None):
    """Add LDAP entries and add teardown for removing them"""
    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, ent_list)


SCHEMA_RFC2307_BIS = "rfc2307bis"


def format_basic_conf(ldap_conn, schema):
    """Format a basic SSSD configuration"""
    schema_conf = "ldap_schema         = " + schema + "\n"
    schema_conf += "ldap_group_object_class = groupOfNames\n"
    return unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss
        disable_netlink     = true

        [nss]

        [domain/LDAP]
        {schema_conf}
        id_provider         = ldap
        auth_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
        ldap_netgroup_search_base = ou=Netgroups,{ldap_conn.ds_inst.base_dn}
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
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)
    create_conf_cleanup(request)


def create_sssd_process():
    """Start the SSSD process"""
    if subprocess.call(["sssd", "-D", "--logger=files"]) != 0:
        raise Exception("sssd start failed")


def get_sssd_pid():
    pid_file = open(config.PIDFILE_PATH, "r")
    pid = int(pid_file.read())
    return pid


def cleanup_sssd_process():
    """Stop the SSSD process and remove its state"""
    try:
        pid = get_sssd_pid()
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


def simulate_offline():
    pid = get_sssd_pid()
    os.kill(pid, signal.SIGUSR1)


def create_sssd_fixture(request):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process()
    create_sssd_cleanup(request)


@pytest.fixture
def add_empty_netgroup(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_netgroup("empty_netgroup")

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_add_empty_netgroup(add_empty_netgroup):
    """
    Adding empty netgroup.
    """

    res, _, netgroups = get_sssd_netgroups("empty_netgroup")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == []


@pytest.fixture
def add_tripled_netgroup(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_netgroup("tripled_netgroup", ["(host,user,domain)"])

    ent_list.add_netgroup("adv_tripled_netgroup", ["(host1,user1,domain1)",
                                                   "(host2,user2,domain2)"])

    ent_list.add_netgroup("tripled_netgroup_no_domain", ["(host,user,)"])

    ent_list.add_netgroup("tripled_netgroup_no_user", ["(host,,domain)"])

    ent_list.add_netgroup("tripled_netgroup_no_host", ["(,user,domain)"])

    ent_list.add_netgroup("tripled_netgroup_none", ["(,,)"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_add_tripled_netgroup(add_tripled_netgroup):
    """
    Adding netgroup with triplet.
    """

    res, _, netgrps = get_sssd_netgroups("tripled_netgroup")
    assert res == NssReturnCode.SUCCESS
    assert netgrps == [("host", "user", "domain")]

    res, _, netgrps = get_sssd_netgroups("adv_tripled_netgroup")
    assert res == NssReturnCode.SUCCESS
    assert sorted(netgrps) == sorted([("host1", "user1", "domain1"),
                                      ("host2", "user2", "domain2")])

    res, _, netgrps = get_sssd_netgroups("tripled_netgroup_no_domain")
    assert res == NssReturnCode.SUCCESS
    assert netgrps == [("host", "user", "")]

    res, _, netgrps = get_sssd_netgroups("tripled_netgroup_no_user")
    assert res == NssReturnCode.SUCCESS
    assert netgrps == [("host", "", "domain")]

    res, _, netgrps = get_sssd_netgroups("tripled_netgroup_no_host")
    assert res == NssReturnCode.SUCCESS
    assert netgrps == [("", "user", "domain")]

    res, _, netgrps = get_sssd_netgroups("tripled_netgroup_none")
    assert res == NssReturnCode.SUCCESS
    assert netgrps == [("", "", "")]


@pytest.fixture
def add_mixed_netgroup(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_netgroup("mixed_netgroup1")
    ent_list.add_netgroup("mixed_netgroup2", members=["mixed_netgroup1"])

    ent_list.add_netgroup("mixed_netgroup3", ["(host1,user1,domain1)"])
    ent_list.add_netgroup("mixed_netgroup4",
                          ["(host2,user2,domain2)", "(host3,user3,domain3)"])

    ent_list.add_netgroup("mixed_netgroup5",
                          ["(host4,user4,domain4)"],
                          ["mixed_netgroup1"])
    ent_list.add_netgroup("mixed_netgroup6",
                          ["(host5,user5,domain5)"],
                          ["mixed_netgroup2"])

    ent_list.add_netgroup("mixed_netgroup7", members=["mixed_netgroup3"])
    ent_list.add_netgroup("mixed_netgroup8",
                          members=["mixed_netgroup3", "mixed_netgroup4"])

    ent_list.add_netgroup("mixed_netgroup9",
                          ["(host6,user6,domain6)"],
                          ["mixed_netgroup3", "mixed_netgroup4"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_add_mixed_netgroup(add_mixed_netgroup):
    """
    Adding many netgroups of different type.
    """

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup1")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == []

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup2")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == []

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup3")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [("host1", "user1", "domain1")]

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup4")
    assert res == NssReturnCode.SUCCESS
    assert sorted(netgroups) == sorted([("host2", "user2", "domain2"),
                                        ("host3", "user3", "domain3")])

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup5")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [("host4", "user4", "domain4")]

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup6")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [("host5", "user5", "domain5")]

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup7")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [("host1", "user1", "domain1")]

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup8")
    assert res == NssReturnCode.SUCCESS
    assert sorted(netgroups) == sorted([("host1", "user1", "domain1"),
                                        ("host2", "user2", "domain2"),
                                        ("host3", "user3", "domain3")])

    res, _, netgroups = get_sssd_netgroups("mixed_netgroup9")
    assert res == NssReturnCode.SUCCESS
    assert sorted(netgroups) == sorted([("host1", "user1", "domain1"),
                                        ("host2", "user2", "domain2"),
                                        ("host3", "user3", "domain3"),
                                        ("host6", "user6", "domain6")])


@pytest.fixture
def remove_step_by_step(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_netgroup("rm_empty_netgroup1", ["(host1,user1,domain1)"])
    ent_list.add_netgroup("rm_empty_netgroup2",
                          ["(host2,user2,domain2)"],
                          ["rm_empty_netgroup1"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return ent_list


def test_remove_step_by_step(remove_step_by_step, ldap_conn):
    """
    Removing netgroups step by step.
    """

    ent_list = remove_step_by_step

    res, _, netgroups = get_sssd_netgroups("rm_empty_netgroup1")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host1', 'user1', 'domain1')]

    res, _, netgroups = get_sssd_netgroups("rm_empty_netgroup2")
    assert res == NssReturnCode.SUCCESS
    assert sorted(netgroups) == sorted([('host1', 'user1', 'domain1'),
                                        ('host2', 'user2', 'domain2')])

    # removing of rm_empty_netgroup1
    ldap_conn.delete_s(ent_list[0][0])
    ent_list.remove(ent_list[0])

    if subprocess.call(["sss_cache", "-N"]) != 0:
        raise Exception("sssd_cache failed")

    res, _, netgroups = get_sssd_netgroups("rm_empty_netgroup1")
    assert res == NssReturnCode.NOTFOUND
    assert netgroups == []

    res, _, netgroups = get_sssd_netgroups("rm_empty_netgroup2")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host2', 'user2', 'domain2')]

    # removing of rm_empty_netgroup2
    ldap_conn.delete_s(ent_list[0][0])
    ent_list.remove(ent_list[0])

    if subprocess.call(["sss_cache", "-N"]) != 0:
        raise Exception("sssd_cache failed")

    res, _, netgroups = get_sssd_netgroups("rm_empty_netgroup1")
    assert res == NssReturnCode.NOTFOUND
    assert netgroups == []

    res, _, netgroups = get_sssd_netgroups("rm_empty_netgroup2")
    assert res == NssReturnCode.NOTFOUND
    assert netgroups == []


@pytest.fixture
def removing_nested_netgroups(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_netgroup("t2841_netgroup1", ["(host1,user1,domain1)"])
    ent_list.add_netgroup("t2841_netgroup2", ["(host2,user2,domain2)"])
    ent_list.add_netgroup("t2841_netgroup3",
                          members=["t2841_netgroup1", "t2841_netgroup2"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_removing_nested_netgroups(removing_nested_netgroups, ldap_conn):
    """
    Regression test for ticket 2841.
    https://fedorahosted.org/sssd/ticket/2841
    """

    netgrp_dn = 'cn=t2841_netgroup3,ou=Netgroups,' + ldap_conn.ds_inst.base_dn

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup1")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host1', 'user1', 'domain1')]

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup2")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host2', 'user2', 'domain2')]

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup3")
    assert res == NssReturnCode.SUCCESS
    assert sorted(netgroups) == sorted([('host1', 'user1', 'domain1'),
                                        ('host2', 'user2', 'domain2')])

    # removing of t2841_netgroup1 from t2841_netgroup3
    old = {'memberNisNetgroup': [b"t2841_netgroup1", b"t2841_netgroup2"]}
    new = {'memberNisNetgroup': [b"t2841_netgroup2"]}

    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(netgrp_dn, ldif)

    if subprocess.call(["sss_cache", "-N"]) != 0:
        raise Exception("sssd_cache failed")

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup1")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host1', 'user1', 'domain1')]

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup2")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host2', 'user2', 'domain2')]

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup3")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host2', 'user2', 'domain2')]

    # removing of t2841_netgroup2 from t2841_netgroup3
    old = {'memberNisNetgroup': [b"t2841_netgroup2"]}
    new = {'memberNisNetgroup': []}

    ldif = ldap.modlist.modifyModlist(old, new)
    ldap_conn.modify_s(netgrp_dn, ldif)

    if subprocess.call(["sss_cache", "-N"]) != 0:
        raise Exception("sssd_cache failed")

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup1")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host1', 'user1', 'domain1')]

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup2")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == [('host2', 'user2', 'domain2')]

    res, _, netgroups = get_sssd_netgroups("t2841_netgroup3")
    assert res == NssReturnCode.SUCCESS
    assert netgroups == []


def test_offline_netgroups(add_tripled_netgroup):
    res, _, netgrps = get_sssd_netgroups("tripled_netgroup")
    assert res == NssReturnCode.SUCCESS
    assert netgrps == [("host", "user", "domain")]

    subprocess.check_call(["sss_cache", "-N"])

    simulate_offline()

    res, _, netgrps = get_sssd_netgroups("tripled_netgroup")
    assert res == NssReturnCode.SUCCESS
    assert netgrps == [("host", "user", "domain")]


@pytest.fixture
def add_thread_test_netgroup(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    triple_list = []
    for i in range(1, 999):
        triple_list.append("(host1,user" + str(i) + ",domain1)")
    ent_list.add_netgroup("ng1", triple_list)

    triple_list = []
    for i in range(1, 999):
        triple_list.append("(host2,user" + str(i) + ",domain2)")
    ent_list.add_netgroup("ng2", triple_list)

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_innetgr_with_threads(add_thread_test_netgroup):

    subprocess.check_call(["sss_netgroup_thread_test"])
