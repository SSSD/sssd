#
# Sudo integration test
#
# Copyright (c) 2018 Red Hat, Inc.
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
import pytest
import json

import config
import ds_openldap
import ldap_ent
from util import unindent, get_call_output

LDAP_BASE_DN = "dc=example,dc=com"


class SudoReplyElement:
    def __init__(self, retval, rules):
        self.retval = retval
        self.rules = rules


class SudoReply:
    def __init__(self, json_string):
        self.jres = json.loads(json_string)
        for reply_elem in self.jres:
            el = SudoReplyElement(reply_elem['retval'],
                                  reply_elem['result']['rules'])
            if reply_elem['type'] == 'default':
                self.defaults = el
            if reply_elem['type'] == 'rules':
                self.sudo_rules = el


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
        services            = nss, sudo

        [nss]

        [sudo]
        debug_level=10

        [domain/LDAP]
        {schema_conf}
        id_provider         = ldap
        auth_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
        ldap_sudo_use_host_filter = false
        ldap_sudo_random_offset = 0
        ldap_id_use_start_tls = false
        debug_level=10
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
    my_env = os.environ.copy()
    my_env['SSSD_INTG_PEER_UID'] = "0"
    my_env['SSSD_INTG_PEER_GID'] = "0"
    if subprocess.call(["sssd", "-D", "--logger=files"], env=my_env) != 0:
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


@pytest.fixture()
def sudocli_tool(request):
    sudocli_path = os.path.join(config.ABS_BUILDDIR,
                                "..", "..", "..", "sss_sudo_cli")
    assert os.access(sudocli_path, os.X_OK)
    return sudocli_path


@pytest.fixture
def add_common_rules(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1001, 2001)
    ent_list.add_sudo_rule("user1_allow_less_shadow",
                           users=("user1",),
                           hosts=("ALL",),
                           commands=("/usr/bin/less /etc/shadow", "/bin/ls"))
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.mark.converted('test_sudo.py', 'test_sudo__user_allowed')
def test_sudo_rule_for_user(add_common_rules, sudocli_tool):
    """
    Test that user1 is allowed in the rule but user2 is not
    """
    my_env = os.environ.copy()
    my_env['SSSD_INTG_PEER_UID'] = "0"
    my_env['SSSD_INTG_PEER_GID'] = "0"
    user1_rules = get_call_output([sudocli_tool, "user1"], custom_env=my_env)
    print(user1_rules)
    reply = SudoReply(user1_rules)
    assert len(reply.sudo_rules.rules) == 1
    assert reply.sudo_rules.rules[0]['cn'] == 'user1_allow_less_shadow'

    user2_rules = get_call_output([sudocli_tool, "user2"], custom_env=my_env)
    reply = SudoReply(user2_rules)
    assert len(reply.sudo_rules.rules) == 0


@pytest.fixture
def add_double_qualified_rules(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2001)
    ent_list.add_user("user3", 1003, 2001)
    ent_list.add_user("user4", 1004, 2001)
    ent_list.add_sudo_rule("user1_allow_less_shadow",
                           users=("user1", "user2", "user2@LDAP", "user3"),
                           hosts=("ALL",),
                           commands=("/usr/bin/less /etc/shadow", "/bin/ls"))
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.mark.converted('test_sudo.py', 'test_sudo__duplicate_sudo_user')
def test_sudo_rule_duplicate_sudo_user(add_double_qualified_rules,
                                       sudocli_tool):
    """
    Test that despite user1 and user1@LDAP meaning the same user,
    the rule is still usable
    """
    my_env = os.environ.copy()
    my_env['SSSD_INTG_PEER_UID'] = "0"
    my_env['SSSD_INTG_PEER_GID'] = "0"
    # Try several users to make sure we don't mangle the list
    for u in ["user1", "user2", "user3"]:
        user_rules = get_call_output([sudocli_tool, u], custom_env=my_env)
        reply = SudoReply(user_rules)
        assert len(reply.sudo_rules.rules) == 1
        assert reply.sudo_rules.rules[0]['cn'] == 'user1_allow_less_shadow'

    user4_rules = get_call_output([sudocli_tool, "user4"], custom_env=my_env)
    reply = SudoReply(user4_rules)
    assert len(reply.sudo_rules.rules) == 0
