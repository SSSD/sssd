""" Automation of pam_pwd_expiration warning
:requirement: pam_pwd_expiration_warning
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import time
import pytest
import ldap
import os
from sssd.testlib.common.utils import sssdTools, LdapOperations
from constants import ds_instance_name, ds_rootpw, ds_rootdn


def ldap_modify_ds(multihost, ldap_mode, dn_dn, element, value):
    """This funciton will do modification on master elements
    ldap_mode: Mode of ldap operation.
    dn_dn: Dn to operate.
    element: Attribute of Dn which needs to change
    value: New Attribute value.
    """
    ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    modify_gid = [(ldap_mode, element, value)]
    ldap_inst.modify_ldap(dn_dn, modify_gid)


@pytest.fixture(scope='class')
def create_users_groups(multihost, request):
    """ Create user and restore """
    client = multihost.client[0]
    ldap_uri = f'ldap://{multihost.master[0].sys_hostname}'
    ldap_inst = LdapOperations(ldap_uri, ds_rootdn, ds_rootpw)
    user_dn = 'uid=pp_user,ou=People,dc=example,dc=test'
    user_info = {'cn': 'pp_user'.encode('utf-8'),
                 'sn': 'pp_user'.encode('utf-8'),
                 'uid': 'pp_user'.encode('utf-8'),
                 'loginshell': '/bin/bash'.encode('utf-8'),
                 'uidNumber': '23571'.encode('utf-8'),
                 'gidNumber': '23571'.encode('utf-8'),
                 'objectClass': ['top'.encode('utf-8'),
                                 'inetuser'.encode('utf-8'),
                                 'posixAccount'.encode('utf-8'),
                                 'person'.encode('utf-8'),
                                 'inetorgperson'.encode('utf-8')],
                 'homeDirectory': '/home/pp_user'.encode('utf-8'),
                 'userPassword': 'Secret123'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    file_location = '/script/change_user_password_while_expired.sh'
    client.transport.put_file(os.path.dirname(os.path.abspath(__file__))
                              + file_location, '/tmp/change_user_password_while_expired.sh')

    def restore():
        "Delete user after test finish"
        ldap_inst.del_dn(user_dn)
    request.addfinalizer(restore)


@pytest.mark.tier1_4
@pytest.mark.usefixtures('setup_sssd',
                         'create_users_groups')
@pytest.mark.pam_pwd_expr_warn
class TestPamPwdExpWarn():
    """
    This is test case class for PAM Password Expiry Warning suite
    """
    @staticmethod
    def test_default_behavior_without_expiry_warning(multihost, backupsssdconf):
        """
        :title: Default behaviour when pam pwd expiration warning is not added to sssd conf
        :id: d2992b21-15be-4c12-8ef9-ae37f48126a9
        :setup:
            1. setup 389-ds w/server-side pw controls
            2. create an account and set the password
            3. clear secure log
            4. clear sssd logs and cache
        :steps:
            1. The user is able to authenticate using SSH password by asserting the
                output of the tools.auth_client_ssh_password() function.
            2. Searches for specific log messages in two log files (/var/log/secure and
                /var/log/sssd/sssd_{ds_instance_name}.log)
                using the find_logs() function, and raises an assertion error if
                the specified log message is not found in the log file.
        :expectedresults:
            1. Authentication should succeed
            2. Corresponding logs should be generated
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        # setup 389-ds w/server-side pw controls
        cn_config = 'cn=config'
        for element, value in [('passwordExp', [b'on']),
                               ('passwordMaxAge', [b'266400']),
                               ('passwordWarning', [b'266400'])]:
            ldap_modify_ds(multihost, ldap.MOD_REPLACE, "cn=config", element, value)
        user_dn = 'uid=ppuser1,ou=People,dc=example,dc=test'
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, user_dn, 'userPassword', [b'Secret123'])
        client.run_command('> /var/log/secure')
        tools.clear_sssd_cache()
        assert tools.auth_client_ssh_password('pp_user', 'Secret123')
        time.sleep(3)
        file_scure = '/var/log/secure'
        file_ssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        find_logs(multihost, '/var/log/secure', "Your password will expire in 3 day")
        find_logs(multihost, f"/var/log/sssd/sssd_{ds_instance_name}.log", "Server returned control [1.3.6.1.4.1.42.2.27.8.5.1]")
        find_logs(multihost, f"/var/log/sssd/sssd_{ds_instance_name}.log", "Password will expire in")
        with pytest.raises(AssertionError):
            find_logs(multihost, file_ssd,
                      "Server does not support the requested "
                      "control [1.3.6.1.4.1.42.2.27.8.5.1]")
