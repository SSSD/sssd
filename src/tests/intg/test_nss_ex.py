#
# Integration test for the nss_ex interface
#
# Copyright (c) 2016 Red Hat, Inc.
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
import errno
import stat
import signal
import subprocess
import time
import ldap
import pytest
import ds_openldap
import ldap_ent
import config
from util import unindent
from sssd_nss_ex import sss_nss_getgrouplist_timeout, NssExFlags


LDAP_BASE_DN = "dc=example,dc=com"
SSSD_DOMAIN = "LDAP"
SCHEMA_RFC2307_BIS = "rfc2307bis"


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


def load_data_to_ldap(request, ldap_conn, schema):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)

    for gid in range(20000, 20010):
        groupname = "group%d" % gid
        ent_list.add_group_bis(groupname, gid, ("user1",))

    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_group_bis("user2_group", 3001, member_uids=("user2",))
    create_ldap_fixture(request, ldap_conn, ent_list)


def load_2307bis_data_to_ldap(request, ldap_conn):
    return load_data_to_ldap(request, ldap_conn, SCHEMA_RFC2307_BIS)


@pytest.fixture
def setup_rfc2307bis(request, ldap_conn):
    load_2307bis_data_to_ldap(request, ldap_conn)

    conf = unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss

        [nss]
        debug_level = 10

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


def run_getgrouplist_timeout(username,
                             pgid,
                             exp_groups,
                             flags=NssExFlags.NONE):
    res = sss_nss_getgrouplist_timeout(username, pgid, 100, flags=flags)
    assert res.errno == 0
    assert sorted(res.groups) == sorted(exp_groups)
    assert res.ngroups == len(exp_groups)


def user1_grouplist_ok_and_erange():
    pgid = 2001
    exp_groups = [g for g in range(20000, 20010)]
    exp_groups.append(pgid)

    # Positive test -- a large enough array
    run_getgrouplist_timeout("user1", pgid, exp_groups)

    # Pass in an array too small, just make sure we don't crash
    res = sss_nss_getgrouplist_timeout("user1", pgid, 5)
    assert res.errno == errno.ERANGE
    assert res.ngroups == 5
    # It is not reliable between successive runs /which/ groups
    # will be returned, so we don't check a slice of the exp_groups


def test_sss_nss_getgrouplist_timeout(ldap_conn,
                                      setup_rfc2307bis):
    """
    Test calling the sss_nss_getgrouplist_timeout function
    """
    user1_grouplist_ok_and_erange()

    # Test that the same case works fine just replying from the
    # memory cache
    stop_sssd()
    user1_grouplist_ok_and_erange()


def test_sss_nss_getgrouplist_timeout_etime(ldap_conn,
                                            setup_rfc2307bis):
    """
    Test that the function does time out with a ridiculously low timeout
    """
    res = sss_nss_getgrouplist_timeout("user1", 2001, 100, timeout=1)
    assert res.errno == errno.ETIME


def test_sss_nss_getgrouplist_timeout_no_cache(ldap_conn,
                                               setup_rfc2307bis):
    """
    Test that the NssExFlags.SSS_NSS_EX_FLAG_NO_CACHE flag works well
    with the getgrouplist_timeout function
    """
    pgid = 2002
    exp_groups = [3001, pgid]

    # Cache the user first
    run_getgrouplist_timeout("user2", pgid, exp_groups)

    # Modify the user group memberships
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_group_bis("addtl_group", 3002, member_uids=("user2",))
    for entry in ent_list:
        ldap_conn.add_s(entry[0], entry[1])

    # Still the same results since normally we get results from the cache
    run_getgrouplist_timeout("user2", pgid, exp_groups)

    # Bypassing the cache should now return the extra group
    exp_groups.append(3002)
    run_getgrouplist_timeout("user2", pgid, exp_groups,
                             NssExFlags.SSS_NSS_EX_FLAG_NO_CACHE)


def test_sss_nss_getgrouplist_timeout_invalidate_cache(ldap_conn,
                                                       setup_rfc2307bis):
    """
    Test that the NssExFlags.SSS_NSS_EX_FLAG_INVALIDATE_CACHE flag works well
    with the getgrouplist_timeout function
    """
    pgid = 2002
    exp_groups = [3001, pgid]

    # Cache the user first
    run_getgrouplist_timeout("user2", pgid, exp_groups)

    # Modify the user group memberships
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)

    ent_list.add_group_bis("addtl_group", 3002, member_uids=("user2",))
    for entry in ent_list:
        ldap_conn.add_s(entry[0], entry[1])

    # Still the same results since normally we get results from the cache
    run_getgrouplist_timeout("user2", pgid, exp_groups,
                             NssExFlags.SSS_NSS_EX_FLAG_INVALIDATE_CACHE)

    # Bypassing the cache should now return the extra group
    exp_groups.append(3002)
    run_getgrouplist_timeout("user2", pgid, exp_groups)
