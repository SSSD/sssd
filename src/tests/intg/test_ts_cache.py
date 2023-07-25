#
# LDAP integration test - test updating the sysdb and timestamp
#                         cache
#
# Copyright (c) 2016 Red Hat, Inc.
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
import signal
import subprocess
import time
import ldap
import pytest
import ds_openldap
import ldap_ent
import sssd_ldb
import sssd_id
from util import unindent

LDAP_BASE_DN = "dc=example,dc=com"
SSSD_DOMAIN = "LDAP"

SCHEMA_RFC2307 = "rfc2307"
SCHEMA_RFC2307_BIS = "rfc2307bis"

TS_ATTRLIST = ("dataExpireTimestamp", "originalModifyTimestamp")


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
            try:
                ldap_conn.delete_s(entry[0])
            except ldap.NO_SUCH_OBJECT:
                # if the test already removed an object, it's fine
                # to not care in the teardown
                pass
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
    request.addfinalizer(teardown)


def load_data_to_ldap(request, ldap_conn, schema):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user11", 1011, 2001)
    ent_list.add_user("user21", 1021, 2001)

    if schema == SCHEMA_RFC2307_BIS:
        ent_list.add_group_bis("group1", 2001, ("user1", "user11", "user21"))
    elif schema == SCHEMA_RFC2307:
        ent_list.add_group("group1", 2001, ("user1", "user11", "user21"))
    create_ldap_fixture(request, ldap_conn, ent_list)


def load_2307bis_data_to_ldap(request, ldap_conn):
    return load_data_to_ldap(request, ldap_conn, SCHEMA_RFC2307_BIS)


def load_2307_data_to_ldap(request, ldap_conn):
    return load_data_to_ldap(request, ldap_conn, SCHEMA_RFC2307)


@pytest.fixture
def setup_rfc2307bis(request, ldap_conn):
    load_2307bis_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        memcache_timeout    = 1

        [domain/LDAP]
        ldap_schema             = rfc2307bis
        id_provider             = ldap
        auth_provider           = ldap
        sudo_provider           = ldap
        ldap_group_object_class = groupOfNames
        ldap_uri                = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base        = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def setup_rfc2307(request, ldap_conn):
    load_2307_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        memcache_timeout    = 1

        [domain/LDAP]
        ldap_schema             = rfc2307
        id_provider             = ldap
        auth_provider           = ldap
        sudo_provider           = ldap
        ldap_uri                = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base        = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def ldb_examine(request):
    ldb_conn = sssd_ldb.SssdLdb('LDAP')
    return ldb_conn


def invalidate_group(ldb_conn, name):
    ldb_conn.invalidate_entry(name, sssd_ldb.TsCacheEntry.group, SSSD_DOMAIN)


def invalidate_user(ldb_conn, name):
    ldb_conn.invalidate_entry(name, sssd_ldb.TsCacheEntry.user, SSSD_DOMAIN)


def get_attrs(ldb_conn, type, name, domain, attr_list):
    sysdb_attrs = dict()
    ts_attrs = dict()

    for attr in attr_list:
        val = ldb_conn.get_entry_attr(sssd_ldb.CacheType.sysdb,
                                      type, name, domain, attr)
        if val:
            val = val.decode('utf-8')
        sysdb_attrs[attr] = val

        val = ldb_conn.get_entry_attr(sssd_ldb.CacheType.timestamps,
                                      type, name, domain, attr)
        if val:
            val = val.decode('utf-8')
        ts_attrs[attr] = val
    return (sysdb_attrs, ts_attrs)


def get_group_attrs(ldb_conn, name, domain, attr_list):
    return get_attrs(ldb_conn, sssd_ldb.TsCacheEntry.group,
                     name, domain, attr_list)


def get_user_attrs(ldb_conn, name, domain, attr_list):
    return get_attrs(ldb_conn, sssd_ldb.TsCacheEntry.user,
                     name, domain, attr_list)


def assert_same_attrval(adict1, adict2, attr_name):
    assert adict1.get(attr_name) is not None and \
        adict1.get(attr_name) == adict2.get(attr_name)


def assert_diff_attrval(adict1, adict2, attr_name):
    assert adict1.get(attr_name) is not None and \
        adict1.get(attr_name) != adict2.get(attr_name)


def prime_cache_group(ldb_conn, name, members):
    ent.assert_group_by_name(
        name,
        dict(mem=ent.contains_only(*members)))
    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, name,
                                            SSSD_DOMAIN, TS_ATTRLIST)
    assert_same_attrval(sysdb_attrs, ts_attrs, "dataExpireTimestamp")
    assert_same_attrval(sysdb_attrs, ts_attrs, "originalModifyTimestamp")

    # just to force different stamps and make sure memcache is gone
    time.sleep(1)
    invalidate_group(ldb_conn, name)

    return sysdb_attrs, ts_attrs


def prime_cache_user(ldb_conn, name, primary_gid):
    # calling initgroups would add the initgExpire timestamp attribute and
    # make sure that sss_cache doesn't add it with a value of 1,
    # triggering a sysdb update
    (res, errno, gids) = sssd_id.call_sssd_initgroups(name, primary_gid)
    assert res == sssd_id.NssReturnCode.SUCCESS

    sysdb_attrs, ts_attrs = get_user_attrs(ldb_conn, name,
                                           SSSD_DOMAIN, TS_ATTRLIST)
    assert_same_attrval(sysdb_attrs, ts_attrs, "dataExpireTimestamp")
    assert_same_attrval(sysdb_attrs, ts_attrs, "originalModifyTimestamp")

    # just to force different stamps and make sure memcache is gone
    time.sleep(1)
    invalidate_user(ldb_conn, name)

    return sysdb_attrs, ts_attrs


def test_group_2307bis_update_same_modstamp(ldap_conn,
                                            ldb_examine,
                                            setup_rfc2307bis):
    """
    Test that a group update with the same modifyTimestamp does not trigger
    sysdb cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user11", "user21")))
    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)

    assert_same_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_same_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_same_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_group_2307bis_update_same_attrs(ldap_conn,
                                         ldb_examine,
                                         setup_rfc2307bis):
    """
    Test that a group update with a different modifyTimestamp but the same
    attrs does not trigger sysdb cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    # modify an argument we don't save to the cache. This will bump the
    # modifyTimestamp attribute, but the attributes themselves will be the same
    # from sssd's point of view
    ldap_conn.modify_s("cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_ADD, "description", b"group one")])
    # wait for slapd to change its database
    time.sleep(1)

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user11", "user21")))
    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)

    assert_same_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_same_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_diff_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_group_2307bis_update_diff_attrs(ldap_conn,
                                         ldb_examine,
                                         setup_rfc2307bis):
    """
    Test that a group update with different attribute triggers cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    user_dn = "uid=user1,ou=Users," + ldap_conn.ds_inst.base_dn
    ldap_conn.modify_s("cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_DELETE, "member", user_dn.encode('utf-8'))])
    # wait for slapd to change its database
    time.sleep(1)

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user11", "user21")))
    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)

    assert_diff_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_diff_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_diff_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_group_2307bis_delete_group(ldap_conn,
                                    ldb_examine,
                                    setup_rfc2307bis):
    """
    Test that deleting a group removes it from both caches
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    e = ldap_ent.group_bis(ldap_conn.ds_inst.base_dn, "group1", 2001)
    ldap_conn.delete_s(e[0])
    # wait for slapd to change its database
    time.sleep(1)

    with pytest.raises(KeyError):
        grp.getgrnam("group1")

    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)
    assert sysdb_attrs.get("dataExpireTimestamp") is None
    assert sysdb_attrs.get("originalModifyTimestamp") is None
    assert ts_attrs.get("dataExpireTimestamp") is None
    assert ts_attrs.get("originalModifyTimestamp") is None


def test_group_2307_update_same_modstamp(ldap_conn,
                                         ldb_examine,
                                         setup_rfc2307):
    """
    Test that a group update with the same modifyTimestamp does not trigger
    sysdb cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user11", "user21")))
    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)

    assert_same_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_same_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_same_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_group_2307_update_same_attrs(ldap_conn,
                                      ldb_examine,
                                      setup_rfc2307):
    """
    Test that a group update with a different modifyTimestamp but the same
    attrs does not trigger sysdb cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    # modify an argument we don't save to the cache. This will bump the
    # modifyTimestamp attribute, but the attributes themselves will be the same
    # from sssd's point of view
    ldap_conn.modify_s("cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_ADD, "description", b"group one")])
    # wait for slapd to change its database
    time.sleep(1)

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user1", "user11", "user21")))
    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)

    assert_same_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_same_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_diff_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_group_2307_update_diff_attrs(ldap_conn,
                                      ldb_examine,
                                      setup_rfc2307):
    """
    Test that a group update with different attribute triggers cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    ldap_conn.modify_s("cn=group1,ou=Groups," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_DELETE, "memberUid", b"user1")])
    # wait for slapd to change its database
    time.sleep(1)

    ent.assert_group_by_name(
        "group1",
        dict(mem=ent.contains_only("user11", "user21")))
    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)

    assert_diff_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_diff_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_diff_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_group_2307_delete_group(ldap_conn,
                                 ldb_examine,
                                 setup_rfc2307):
    """
    Test that deleting a group removes it from both caches
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    e = ldap_ent.group_bis(ldap_conn.ds_inst.base_dn, "group1", 2001)
    ldap_conn.delete_s(e[0])
    # wait for slapd to change its database
    time.sleep(1)

    with pytest.raises(KeyError):
        grp.getgrnam("group1")

    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)
    assert sysdb_attrs.get("dataExpireTimestamp") is None
    assert sysdb_attrs.get("originalModifyTimestamp") is None
    assert ts_attrs.get("dataExpireTimestamp") is None
    assert ts_attrs.get("originalModifyTimestamp") is None


def test_user_update_same_modstamp(ldap_conn,
                                   ldb_examine,
                                   setup_rfc2307bis):
    """
    Test that a user update with the same modifyTimestamp does not trigger
    sysdb cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_user(ldb_conn, "user1", 2001)

    ent.assert_passwd_by_name("user1", dict(name="user1"))

    sysdb_attrs, ts_attrs = get_user_attrs(ldb_conn, "user1",
                                           SSSD_DOMAIN, TS_ATTRLIST)
    assert_same_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_same_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_same_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_user_update_same_attrs(ldap_conn,
                                ldb_examine,
                                setup_rfc2307bis):
    """
    Test that a user update with the same modifyTimestamp does not trigger
    sysdb cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_user(ldb_conn, "user1", 2001)

    # modify an argument we don't save to the cache. This will bump the
    # modifyTimestamp attribute, but the attributes themselves will be the same
    # from sssd's point of view
    ldap_conn.modify_s("uid=user1,ou=Users," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_ADD, "description", b"user one")])
    # wait for slapd to change its database
    time.sleep(1)

    ent.assert_passwd_by_name("user1", dict(name="user1"))

    sysdb_attrs, ts_attrs = get_user_attrs(ldb_conn, "user1",
                                           SSSD_DOMAIN, TS_ATTRLIST)
    assert_same_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_same_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_diff_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_user_update_diff_attrs(ldap_conn,
                                ldb_examine,
                                setup_rfc2307bis):
    """
    Test that a user update with the same modifyTimestamp does not trigger
    sysdb cache update
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_user(ldb_conn, "user1", 2001)

    # modify an argument we don't save to the cache. This will bump the
    # modifyTimestamp attribute, but the attributes themselves will be the same
    # from sssd's point of view
    ldap_conn.modify_s("uid=user1,ou=Users," + ldap_conn.ds_inst.base_dn,
                       [(ldap.MOD_REPLACE, "loginShell", b"/bin/zsh")])
    # wait for slapd to change its database
    time.sleep(1)

    ent.assert_passwd_by_name("user1", dict(name="user1"))
    sysdb_attrs, ts_attrs = get_user_attrs(ldb_conn, "user1",
                                           SSSD_DOMAIN, TS_ATTRLIST)
    assert_diff_attrval(sysdb_attrs, old_sysdb_attrs, "dataExpireTimestamp")
    assert_diff_attrval(sysdb_attrs, old_sysdb_attrs,
                        "originalModifyTimestamp")

    assert_diff_attrval(ts_attrs, old_ts_attrs, "dataExpireTimestamp")
    assert_diff_attrval(ts_attrs, old_ts_attrs, "originalModifyTimestamp")


def test_user_2307bis_delete_user(ldap_conn,
                                  ldb_examine,
                                  setup_rfc2307bis):
    """
    Test that deleting a user removes it from both caches
    """
    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_user(ldb_conn, "user1", 2001)

    e = ldap_ent.user(ldap_conn.ds_inst.base_dn, "user1", 1001, 2001)

    ldap_conn.delete_s(e[0])
    # wait for slapd to change its database
    time.sleep(1)

    with pytest.raises(KeyError):
        pwd.getpwnam("user1")
    sysdb_attrs, ts_attrs = get_user_attrs(ldb_conn, "user1",
                                           SSSD_DOMAIN, TS_ATTRLIST)
    assert sysdb_attrs.get("dataExpireTimestamp") is None
    assert sysdb_attrs.get("originalModifyTimestamp") is None
    assert ts_attrs.get("dataExpireTimestamp") is None
    assert ts_attrs.get("originalModifyTimestamp") is None


def test_sss_cache_invalidate_user(ldap_conn,
                                   ldb_examine,
                                   setup_rfc2307bis):
    """
    Test that sss_cache invalidate user in both caches
    """

    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_user(ldb_conn, "user1", 2001)

    subprocess.call(["sss_cache", "-u", "user1"])

    sysdb_attrs, ts_attrs = get_user_attrs(ldb_conn, "user1",
                                           SSSD_DOMAIN, TS_ATTRLIST)

    assert sysdb_attrs.get("dataExpireTimestamp") == '1'
    assert ts_attrs.get("dataExpireTimestamp") == '1'

    time.sleep(1)
    pwd.getpwnam("user1")
    sysdb_attrs, ts_attrs = get_user_attrs(ldb_conn, "user1",
                                           SSSD_DOMAIN, TS_ATTRLIST)

    assert sysdb_attrs.get("dataExpireTimestamp") == '1'
    assert_diff_attrval(ts_attrs, sysdb_attrs, "dataExpireTimestamp")


def test_sss_cache_invalidate_group(ldap_conn,
                                    ldb_examine,
                                    setup_rfc2307bis):
    """
    Test that sss_cache invalidate group in both caches
    """

    ldb_conn = ldb_examine
    old_sysdb_attrs, old_ts_attrs = prime_cache_group(
        ldb_conn, "group1",
        ("user1", "user11", "user21"))

    subprocess.call(["sss_cache", "-g", "group1"])

    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)

    assert sysdb_attrs.get("dataExpireTimestamp") == '1'
    assert ts_attrs.get("dataExpireTimestamp") == '1'

    time.sleep(1)
    grp.getgrnam("group1")
    sysdb_attrs, ts_attrs = get_group_attrs(ldb_conn, "group1",
                                            SSSD_DOMAIN, TS_ATTRLIST)

    assert sysdb_attrs.get("dataExpireTimestamp") == '1'
    assert_diff_attrval(ts_attrs, sysdb_attrs, "dataExpireTimestamp")
