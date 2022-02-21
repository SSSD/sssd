""" Automation of nsaccount lock

:subsystemteam: sst_idm_sssd
:upstream: yes
:requirement: ns_account_lock
:casecomponent: sssd
"""

from __future__ import print_function
import re
import pytest
import threading
import time
import paramiko
import subprocess
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.exceptions import SSHLoginException
from sssd.testlib.common.utils import sssdTools, LdapOperations
from sssd.testlib.common.utils import SSHClient
import ldap


def execute_cmd(multihost, command):
    """ Execute command on client """
    cmd = multihost.client[0].run_command(command)
    return cmd


def lock_check(multihost, user):
    "Check if user is locked"
    out_put = execute_cmd(multihost,
                          'grep "Performing RHDS access '
                          'check for user" /var/log/sssd/'
                          'sssd_example1.log').stdout_text
    assert f"Performing RHDS access check " \
           f"for user [{user}@example1]" in out_put
    assert "pam_sss(sshd:account): system info:" \
           " [The user account is locked on the server]" \
           in execute_cmd(multihost,
                          'grep "pam_sss(sshd:account): '
                          'system info" /var/log/secure').stdout_text
    assert f"pam_sss(sshd:account):" \
           f" Access denied for user" \
           f" {user}@example1: 6 (Permission denied)"\
           in execute_cmd(multihost, 'grep '
                                     '"Access denied '
                                     'for user" '
                                     '/var/log/secure').stdout_text


def unlock_check(multihost, user):
    "Check if user is unlocked"
    assert f"Performing RHDS access " \
           f"check for user [{user}@example1]" \
           in execute_cmd(multihost,
                          'grep "Performing RHDS '
                          'access check for user"'
                          ' /var/log/sssd/sssd_example1.log').stdout_text
    assert f"{user}@example1" in \
           execute_cmd(multihost,
                       'grep "is not locked." '
                       '/var/log/sssd/sssd_example1.log').stdout_text


def manage_user_roles(multihost, user, lock, type1):
    "Manage users and roles"
    master_e = multihost.master[0].ip
    assert f"Entry {user},ou=people," \
           f"dc=example,dc=test is {lock}" in \
           execute_cmd(multihost, f"dsidm "
                                  f"ldap://{master_e}:389 -D"
                                  f" 'cn=Directory Manager'"
                                  f" -w Secret123 -b dc=example,"
                                  f"dc=test {type1}"
                                  f" {lock} {user},ou=people,"
                                  f"dc=example,dc=test").stdout_text


def clean_sys(multihost):
    "Clean logs and restart"
    execute_cmd(multihost, "rm -vf /var/log/sssd/*")
    execute_cmd(multihost, "> /var/log/secure")
    execute_cmd(multihost, "systemctl restart sssd")


@pytest.mark.tier1_2
@pytest.mark.usefixtures('setup_sssd_krb',
                         'create_posix_usersgroups',
                         'ns_account_lock')
@pytest.mark.nsaccountlock
class TestNsAccountLock(object):
    """
    This is for ns_account automation
    """
    def test_user_inactivated_locked(self, multihost):
        """
        :title: User is inactivated or locked
        :id: 5787bb3e-3045-11ec-8da7-845cf3eff344
        :steps:
            1. Check user is present
            2. Lock user, check user is really locked.
            3. Unlock user, check user is really unlocked.
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        clean_sys(multihost)
        client_e = multihost.client[0].ip
        assert "foo1@example1" in \
               execute_cmd(multihost, "getent -s sss passwd"
                                      " foo1@example1").stdout_text
        assert "ldapusers@example1" in \
               execute_cmd(multihost, "getent -s sss group "
                                      "ldapusers@example1").stdout_text
        manage_user_roles(multihost, "uid=foo1", "lock", "account")
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(client_e,
                      username="foo1@example1",
                      password="Secret123")
        time.sleep(3)
        lock_check(multihost, "foo1")
        # User is activated or unlocked
        clean_sys(multihost)
        manage_user_roles(multihost, "uid=foo1", "unlock", "account")
        ssh1 = SSHClient(client_e,
                         username="foo1@example1",
                         password="Secret123")
        ssh1.close()
        time.sleep(3)
        unlock_check(multihost, "foo1")

    def test_inactive_managed_roles(self, multihost):
        """
        title: Inactive managed roles
        :id: 4f685ee0-3045-11ec-b3f8-845cf3eff344
        :steps:
            1. Make managed role it inactive
            2. User added to the above inactive managed role
            3. User removed from the above inactive managed role
            4. Activate managed role
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
        """
        clean_sys(multihost)
        client_e = multihost.client[0].ip
        master_e = multihost.master[0].ip
        ldap_uri = f'ldap://{master_e}'
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        manage_user_roles(multihost, "cn=managed", "lock", "role")
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(client_e,
                      username="foo1@example1",
                      password="Secret123")
        time.sleep(3)
        lock_check(multihost, "foo1")
        # User added to the above inactive managed role
        clean_sys(multihost)
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_dn = 'uid=foo2,ou=People,dc=example,dc=test'
        role_dn = "cn=managed,ou=people,dc=example,dc=test"
        add_member = [(ldap.MOD_ADD, 'nsRoleDN', role_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(user_dn, add_member)
        assert ret == 'Success'
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(client_e,
                      username="foo2@example1",
                      password="Secret123")
        time.sleep(3)
        lock_check(multihost, "foo2")
        # User removed from the above inactive managed role
        clean_sys(multihost)
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_dn = 'uid=foo2,ou=People,dc=example,dc=test'
        role_dn = "cn=managed,ou=people,dc=example,dc=test"
        add_member = [(ldap.MOD_DELETE, 'nsRoleDN', role_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(user_dn, add_member)
        assert ret == 'Success'
        ssh1 = SSHClient(client_e,
                         username="foo2@example1",
                         password="Secret123")
        ssh1.close()
        time.sleep(3)
        unlock_check(multihost, "foo2")
        # Activate managed role
        clean_sys(multihost)
        manage_user_roles(multihost, "cn=managed", "unlock", "role")
        ssh1 = SSHClient(client_e,
                         username="foo1@example1",
                         password="Secret123")
        ssh1.close()
        time.sleep(3)
        unlock_check(multihost, "foo1")

    def test_inactivated_filtered_roles(self, multihost):
        """
        title: Inactivated filtered roles
        :id: 4286dac6-3045-11ec-8fd0-845cf3eff344
        :steps:
            1. Make filter role inactive
            2. User added to the above inactive filtered role
            3. User removed from the above inactive filtered role
            4. Activate filtered role
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
            4. Should succeed
        """
        clean_sys(multihost)
        client_e = multihost.client[0].ip
        master_e = multihost.master[0].ip
        ldap_uri = f'ldap://{master_e}'
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_dn = 'uid=foo3,ou=People,dc=example,dc=test'
        role_dn = "filtered"
        add_member = [(ldap.MOD_ADD, 'o', role_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(user_dn, add_member)
        assert ret == 'Success'
        manage_user_roles(multihost, "cn=filtered", "lock", "role")
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(client_e,
                      username="foo3@example1",
                      password="Secret123")
        time.sleep(3)
        lock_check(multihost, "foo3")
        # User added to the above inactive filtered role
        clean_sys(multihost)
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(client_e,
                      username="foo4@example1",
                      password="Secret123")
        time.sleep(3)
        lock_check(multihost, "foo4")
        # User removed from the above inactive filtered role
        clean_sys(multihost)
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_dn = 'uid=foo3,ou=People,dc=example,dc=test'
        role_dn = "filtered"
        add_member = [(ldap.MOD_DELETE, 'o', role_dn.encode('utf-8'))]
        (ret, _) = ldap_inst.modify_ldap(user_dn, add_member)
        assert ret == 'Success'
        ssh1 = SSHClient(client_e,
                         username="foo3@example1",
                         password="Secret123")
        ssh1.close()
        time.sleep(3)
        unlock_check(multihost, "foo3")
        # Activate filtered role
        clean_sys(multihost)
        manage_user_roles(multihost, "cn=filtered", "unlock", "role")
        ssh1 = SSHClient(client_e,
                         username="foo4@example1",
                         password="Secret123")
        ssh1.close()
        time.sleep(3)
        unlock_check(multihost, "foo4")

    def test_nested_role_inactivated(self, multihost):
        """
        title: Nested role has both the above roles and inactivated
        :id: 312e42c8-3045-11ec-88d4-845cf3eff344
        :steps:
            1. Add nasted role and make it inactive
            2. Nested role has the managed role
            3. Nested role has the filtered role
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        clean_sys(multihost)
        client_e = multihost.client[0].ip
        master_e = multihost.master[0].ip
        ldap_uri = f'ldap://{master_e}'
        ds_rootdn = 'cn=Directory Manager'
        ds_rootpw = 'Secret123'
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        user_info = {'cn': 'nested'.encode('utf-8'),
                     'objectClass': [b'top',
                                     b'LdapSubEntry',
                                     b'nsRoleDefinition',
                                     b'nsComplexRoleDefinition',
                                     b'nsNestedRoleDefinition'],
                     'nsRoleDN': [b'cn=filtered,ou=people,' +
                                  b'dc=example,dc=test',
                                  b'cn=managed,ou=people,' +
                                  b'dc=example,dc=test']}
        user_dn = 'cn=nested,ou=People,dc=example,dc=test'
        (_, _) = ldap_inst.add_entry(user_info, user_dn)
        manage_user_roles(multihost, "cn=nested", "lock", "role")
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(client_e,
                      username="foo1@example1",
                      password="Secret123")
        time.sleep(3)
        lock_check(multihost, "foo1")
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            SSHClient(client_e,
                      username="foo4@example1",
                      password="Secret123")
        time.sleep(3)
        lock_check(multihost, "foo4")
        # Nested role has both the above roles and activated
        clean_sys(multihost)
        ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
        manage_user_roles(multihost, "cn=nested", "unlock", "role")
        ssh1 = SSHClient(client_e,
                         username="foo1@example1",
                         password="Secret123")
        ssh1.close()
        ssh1 = SSHClient(client_e,
                         username="foo4@example1",
                         password="Secret123")
        ssh1.close()
        time.sleep(3)
        unlock_check(multihost, "foo1")
        unlock_check(multihost, "foo4")
