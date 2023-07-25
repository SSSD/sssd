#
# Resolver integration test
#
#   Authors:
#       Samuel Cabrero <scabrero@suse.com>
#
#   Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.
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

import os
import stat
import signal
import subprocess
import time
import ldap
import pytest
import socket
import config
import ds_openldap
import ldap_ent
from util import unindent
from sssd_nss import NssReturnCode, HostError
from sssd_hosts import call_sssd_gethostbyname
from sssd_nets import call_sssd_getnetbyname, call_sssd_getnetbyaddr

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
        for ou in ("Users", "Groups", "Netgroups", "Services", "Policies",
                   "Hosts", "Networks"):
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
    """Format a basic SSSD configuration"""
    schema_conf = "ldap_schema         = " + schema + "\n"
    if schema == SCHEMA_RFC2307_BIS:
        schema_conf += "ldap_group_object_class = groupOfNames\n"
    iphost_search_base = "ou=Hosts," + ldap_conn.ds_inst.base_dn
    ipnetwork_search_base = "ou=Networks," + ldap_conn.ds_inst.base_dn
    return unindent("""\
        [sssd]
        debug_level         = 0xffff
        domains             = LDAP
        services            = nss

        [nss]
        debug_level         = 0xffff
        memcache_timeout    = 0
        entry_negative_timeout = 1

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        debug_level         = 0xffff
        {schema_conf}
        id_provider         = ldap
        auth_provider       = ldap
        resolver_provider   = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
        ldap_iphost_search_base = {iphost_search_base}
        ldap_ipnetwork_search_base = {ipnetwork_search_base}
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


def create_sssd_fixture(request):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process()
    create_sssd_cleanup(request)


def create_sssd_cleanup(request):
    """Add teardown for stopping SSSD and removing its state"""
    request.addfinalizer(cleanup_sssd_process)


@pytest.fixture
def add_hosts(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_host("host1",
                      aliases=["host1_alias1", "host1_alias2"],
                      addresses=["192.168.1.1", "192.168.1.2",
                                 "2001:db8:1::1", "2001:db8:1::2"])
    ent_list.add_host("host2.example.com",
                      aliases=["host2_alias1.example.com",
                               "host2_alias2.example.com"],
                      addresses=["192.168.2.1", "192.168.2.2",
                                 "2001:db8:2::1", "2001:db8:2::2"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def add_nets(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_ipnet("net1", "192.168.1.1",
                       aliases=["net1_alias1", "net1_alias2"])
    ent_list.add_ipnet("net2", "10.2.2.2",
                       aliases=["net2_alias1", "net2_alias2"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_hostbyname(add_hosts):
    (res, hres, _) = call_sssd_gethostbyname("invalid")

    assert res == NssReturnCode.NOTFOUND
    assert hres == HostError.HOST_NOT_FOUND

    (res, hres, _) = call_sssd_gethostbyname("example.com")
    assert res == NssReturnCode.NOTFOUND
    assert hres == HostError.HOST_NOT_FOUND

    (res, hres, _) = call_sssd_gethostbyname("invalid.example.com")
    assert res == NssReturnCode.NOTFOUND
    assert hres == HostError.HOST_NOT_FOUND

    (res, hres, _) = call_sssd_gethostbyname("host1")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_gethostbyname("host1_alias1")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_gethostbyname("host1_alias2")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_gethostbyname("host2.example.com")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_gethostbyname("host2_alias1.example.com")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_gethostbyname("host2_alias2.example.com")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0


def test_netbyname(add_nets):
    (res, hres, _) = call_sssd_getnetbyname("invalid")
    assert res == NssReturnCode.NOTFOUND
    assert hres == HostError.HOST_NOT_FOUND

    (res, hres, _) = call_sssd_getnetbyname("net1")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_getnetbyname("net1_alias1")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_getnetbyname("net1_alias2")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_getnetbyname("net2")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_getnetbyname("net2_alias1")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_getnetbyname("net2_alias2")
    assert res == NssReturnCode.SUCCESS
    assert hres == 0


def test_netbyaddr(add_nets):
    (res, hres, _) = call_sssd_getnetbyaddr("10.2.2.1", socket.AF_INET)
    assert res == NssReturnCode.NOTFOUND
    assert hres == HostError.HOST_NOT_FOUND

    (res, hres, _) = call_sssd_getnetbyaddr("10.2.2.1", socket.AF_UNSPEC)
    assert res == NssReturnCode.NOTFOUND
    assert hres == HostError.HOST_NOT_FOUND

    (res, hres, _) = call_sssd_getnetbyaddr("10.2.2.2", socket.AF_INET)
    assert res == NssReturnCode.SUCCESS
    assert hres == 0

    (res, hres, _) = call_sssd_getnetbyaddr("10.2.2.2", socket.AF_UNSPEC)
    assert res == NssReturnCode.SUCCESS
    assert hres == 0
