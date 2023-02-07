#
# LDAP integration test
#
# Copyright (c) 2017 Red Hat, Inc.
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
import pwd
import grp
import signal
import subprocess
import time
import pytest
import ldb
import pysss_nss_idmap

import config
import ds_openldap

from .util import unindent

LDAP_BASE_DN = "dc=example,dc=com"


@pytest.fixture(scope="module")
def ad_inst(request):
    """Fake AD server instance fixture"""
    instance = ds_openldap.FakeAD(
        config.PREFIX, 10389, LDAP_BASE_DN,
        "cn=admin", "Secret123"
    )

    try:
        instance.setup()
    except Exception:
        instance.teardown()
        raise
    request.addfinalizer(instance.teardown)
    return instance


@pytest.fixture(scope="module")
def ldap_conn(request, ad_inst):
    """LDAP server connection fixture"""
    ldap_conn = ad_inst.bind()
    ldap_conn.ad_inst = ad_inst
    request.addfinalizer(ldap_conn.unbind_s)
    return ldap_conn


def format_basic_conf(ldap_conn, ignore_unreadable_refs):
    """Format a basic SSSD configuration"""

    ignore_unreadable_refs_conf = "false"
    if ignore_unreadable_refs:
        ignore_unreadable_refs_conf = "true"

    return unindent("""\
        [sssd]
        domains = FakeAD
        services = nss

        [nss]

        [pam]

        [domain/FakeAD]
        ldap_search_base = {ldap_conn.ad_inst.base_dn}
        ldap_referrals = false

        id_provider = ldap
        auth_provider = ldap
        chpass_provider = ldap
        access_provider = ldap

        ldap_uri = {ldap_conn.ad_inst.ldap_url}
        ldap_default_bind_dn = {ldap_conn.ad_inst.admin_dn}
        ldap_default_authtok_type = password
        ldap_default_authtok = {ldap_conn.ad_inst.admin_pw}

        ldap_schema = ad
        ldap_id_mapping = true
        ldap_idmap_default_domain_sid = S-1-5-21-1305200397-2901131868-73388776
        case_sensitive = False

        ldap_ignore_unreadable_references = {ignore_unreadable_refs_conf}
    """).format(**locals())


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)


def create_conf_fixture(request, contents):
    """
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)

    def cleanup_conf_file():
        """Remove sssd.conf, if it exists"""
        if os.path.lexists(config.CONF_PATH):
            os.unlink(config.CONF_PATH)

    request.addfinalizer(cleanup_conf_file)


def create_sssd_process():
    """Start the SSSD process"""
    if subprocess.call(["sssd", "-D", "--logger=files"]) != 0:
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
    request.addfinalizer(cleanup_sssd_process)


def sysdb_sed_domainid(domain_name, domain_id):
    sssd_cache = "{0}/cache_{1}.ldb".format(config.DB_PATH, domain_name)
    domain_ldb = ldb.Ldb(sssd_cache)

    msg = ldb.Message()
    msg.dn = ldb.Dn(domain_ldb, "cn=sysdb")
    msg["cn"] = "sysdb"
    msg["description"] = "base object"
    msg["version"] = "0.17"
    domain_ldb.add(msg)

    # Set domainID for fake AD domain
    msg = ldb.Message()
    msg.dn = ldb.Dn(domain_ldb, "cn={0},cn=sysdb".format(domain_name))
    msg["cn"] = domain_name
    msg["domainID"] = domain_id
    msg["distinguishedName"] = "cn={0},cn=sysdb".format(domain_name)
    domain_ldb.add(msg)

    msg = ldb.Message()
    msg.dn = ldb.Dn(domain_ldb, "@ATTRIBUTES")
    msg["distinguishedName"] = "@ATTRIBUTES"
    for attr in ['cn', 'dc', 'dn', 'objectclass', 'originalDN',
                 'userPrincipalName']:
        msg[attr] = "CASE_INSENSITIVE"
    domain_ldb.add(msg)

    msg = ldb.Message()
    msg.dn = ldb.Dn(domain_ldb, "@INDEXLIST")
    msg["distinguishedName"] = "@INDEXLIST"
    msg["@IDXONE"] = "1"
    for attr in ['cn', 'objectclass', 'member', 'memberof', 'name',
                 'uidNumber', 'gidNumber', 'lastUpdate', 'dataExpireTimestamp',
                 'originalDN', 'nameAlias', 'servicePort', 'serviceProtocol',
                 'sudoUser', 'sshKnownHostsExpire', 'objectSIDString']:
        msg["@IDXATTR"] = attr
    domain_ldb.add(msg)

    msg = ldb.Message()
    msg.dn = ldb.Dn(domain_ldb, "@MODULES")
    msg["distinguishedName"] = "@MODULES"
    msg["@LIST"] = "asq,memberof"
    domain_ldb.add(msg)


@pytest.fixture
def simple_ad(request, ldap_conn):
    conf = format_basic_conf(ldap_conn, ignore_unreadable_refs=False)
    sysdb_sed_domainid("FakeAD", "S-1-5-21-1305200397-2901131868-73388776")

    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_user_operations(ldap_conn, simple_ad):
    user = 'user1_dom1-19661'
    user_id = pwd.getpwnam(user).pw_uid
    user_sid = 'S-1-5-21-1305200397-2901131868-73388776-82809'

    output = pysss_nss_idmap.getsidbyname(user)[user]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.SID_KEY] == user_sid

    output = pysss_nss_idmap.getsidbyusername(user)[user]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.SID_KEY] == user_sid

    output = pysss_nss_idmap.getsidbygroupname(user)
    assert len(output) == 0

    output = pysss_nss_idmap.getsidbyid(user_id)[user_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.SID_KEY] == user_sid

    output = pysss_nss_idmap.getsidbyuid(user_id)[user_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.SID_KEY] == user_sid

    output = pysss_nss_idmap.getsidbygid(user_id)
    assert len(output) == 0

    output = pysss_nss_idmap.getidbysid(user_sid)[user_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.ID_KEY] == user_id

    output = pysss_nss_idmap.getnamebysid(user_sid)[user_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.NAME_KEY] == user


def test_group_operations(ldap_conn, simple_ad):
    group = 'group1_dom1-19661'
    group_id = grp.getgrnam(group).gr_gid
    group_sid = 'S-1-5-21-1305200397-2901131868-73388776-82810'

    output = pysss_nss_idmap.getsidbyname(group)[group]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbygroupname(group)[group]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbyusername(group)
    assert len(output) == 0

    output = pysss_nss_idmap.getsidbyid(group_id)[group_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbygid(group_id)[group_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbyuid(group_id)
    assert len(output) == 0

    output = pysss_nss_idmap.getidbysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.ID_KEY] == group_id

    output = pysss_nss_idmap.getnamebysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.NAME_KEY] == group


def test_case_insensitive(ldap_conn, simple_ad):
    # resolve group and also member of this group
    group = 'Domain Users'
    group_id = grp.getgrnam(group).gr_gid
    group_sid = 'S-1-5-21-1305200397-2901131868-73388776-513'

    output = pysss_nss_idmap.getsidbyname(group)[group]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbyid(group_id)[group_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbygid(group_id)[group_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbyuid(group_id)
    assert len(output) == 0

    output = pysss_nss_idmap.getidbysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.ID_KEY] == group_id

    output = pysss_nss_idmap.getnamebysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.NAME_KEY] == group.lower()


@pytest.fixture
def simple_ad_ignore_unrdbl_refs(request, ldap_conn):
    conf = format_basic_conf(ldap_conn, ignore_unreadable_refs=True)
    sysdb_sed_domainid("FakeAD", "S-1-5-21-1305200397-2901131868-73388776")

    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_ignore_unreadable_references(ldap_conn, simple_ad_ignore_unrdbl_refs):
    group = 'group3_dom1-17775'
    group_id = grp.getgrnam(group).gr_gid
    group_sid = 'S-1-5-21-1305200397-2901131868-73388776-82764'

    output = pysss_nss_idmap.getsidbyname(group)[group]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbyid(group_id)[group_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbygid(group_id)[group_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbyuid(group_id)
    assert len(output) == 0

    output = pysss_nss_idmap.getidbysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.ID_KEY] == group_id

    output = pysss_nss_idmap.getnamebysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.NAME_KEY] == group


def test_no_ignore_unreadable_references(ldap_conn, simple_ad):
    group = 'group3_dom1-17775'

    # This group has a member attribute referencing to a user in other
    # domain
    with pytest.raises(KeyError):
        grp.getgrnam(group)
