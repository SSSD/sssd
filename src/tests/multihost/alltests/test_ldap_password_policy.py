""" Automation of password Policy suite
:requirement: ldap_id_ldap_auth
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


def find_logs(multihost, log_name, string_name):
    """This function will find strings in a log file
    log_name: Absolute path of log where the search will happen.
    string_name: String to search in the log file.
    """
    log_str = multihost.client[0].get_file_contents(log_name).decode('utf-8')
    assert string_name in log_str


@pytest.fixture(scope='function')
def common_sssd_setup(multihost):
    """
    This is common sssd setup used in this test suit.
    """
    tools = sssdTools(multihost.client[0])
    tools.sssd_conf("nss", {'filter_groups': 'root',
                            'filter_users': 'root',
                            'debug_level': '9'}, action='update')
    ldap_params = {'use_fully_qualified_names': False}
    tools.sssd_conf(f'domain/{ds_instance_name}', ldap_params)
    tools.clear_sssd_cache()


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
    user_dn = 'uid=ppuser1,ou=People,dc=example,dc=test'
    user_info = {'cn': 'ppuser1'.encode('utf-8'),
                 'sn': 'ppuser1'.encode('utf-8'),
                 'uid': 'ppuser1'.encode('utf-8'),
                 'loginshell': '/bin/bash'.encode('utf-8'),
                 'uidNumber': '23579'.encode('utf-8'),
                 'gidNumber': '23579'.encode('utf-8'),
                 'objectClass': ['top'.encode('utf-8'),
                                 'inetuser'.encode('utf-8'),
                                 'posixAccount'.encode('utf-8'),
                                 'person'.encode('utf-8'),
                                 'inetorgperson'.encode('utf-8')],
                 'homeDirectory': '/home/ppuser1'.encode('utf-8'),
                 'userPassword': 'Secret123'.encode('utf-8')}
    ldap_inst.add_entry(user_info, user_dn)
    ldap_modify_ds(multihost, ldap.MOD_REPLACE, 'cn=config', 'nsslapd-allowed-to-delete-attrs',
                   [b'passwordExp passwordMaxAge passwordWarning passwordGraceLimit passwordMustChange'])
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
@pytest.mark.passwordcheck
class TestPasswordPolicy():
    """
    This is test case class for ldap Password Policy suite
    """
    @staticmethod
    def test_bz748856(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: Set passwordMaxAge to 24 hours bz748856
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=748856
        :id: b0200b74-9675-11ed-b874-845cf3eff344
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
                               ('passwordMaxAge', [b'86400']),
                               ('passwordWarning', [b'86400'])]:
            ldap_modify_ds(multihost, ldap.MOD_REPLACE, cn_config, element, value)
        # set the password
        user_dn = 'uid=ppuser1,ou=People,dc=example,dc=test'
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, user_dn, 'userPassword', [b'Secret123'])
        client.run_command('> /var/log/secure')
        tools.clear_sssd_cache()
        assert tools.auth_client_ssh_password('ppuser1', 'Secret123')
        time.sleep(3)
        file_scure = '/var/log/secure'
        file_ssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        find_logs(multihost, file_scure, "Your password will expire in ")
        find_logs(multihost, file_ssd, "Server returned control [1.3.6.1.4.1.42.2.27.8.5.1]")
        find_logs(multihost, file_ssd, "Password will expire in [86")
        with pytest.raises(AssertionError):
            find_logs(multihost, file_ssd,
                      "Server does not support the requested "
                      "control [1.3.6.1.4.1.42.2.27.8.5.1]")

    @staticmethod
    def test_maxage(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: "Set passwordMaxAge to 1"
        :id: fc68293e-9676-11ed-9808-845cf3eff344
        :setup:
            1. setup 389-ds w/server-side passwordMaxAge to 1.
            2. sets the password for a user.
            3. clears the SSSD cache for the selected client.
        :steps:
            1. Runs a shell script (/tmp/change_user_password_while_expired.sh) on the selected
                client to simulate a password change attempt after the user's password has expired.
            2. Searches for specific log messages in two log files (/var/log/secure and
                /var/log/sssd/sssd_{ds_instance_name}.log) using the find_logs() function to verify that
                the expected log messages have been generated.
            3. Sets the passwordExp configuration in the cn=config section of the
                389-ds directory server to off using the ldap_modify_ds() function.
            4. Tests that the user is able to authenticate using SSH password by calling
                the tools.auth_client_ssh_password() function with the new password (NewPass_123).
            5. Sets the user's password back to the original password (Secret123) using the ldap_modify_ds() function.
        :expectedresults:
            1. User should be able to reset expired password
            2. Corresponding logs should be generated
            3. PasswordExp configuration in the cn=config section should success
            4. Authenticate using SSH password by user should success
            5. Changing user's password back to the original password should success
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        cn_config = 'cn=config'
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, cn_config, 'passwordMaxAge', [b'1'])
        user_dn = 'uid=ppuser1,ou=People,dc=example,dc=test'
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, user_dn, 'userPassword', [b'Secret123'])
        client.run_command('> /var/log/secure')
        tools.clear_sssd_cache()
        client.run_command('sh /tmp/change_user_password_while_expired.sh', raiseonerr=False)
        time.sleep(3)
        file_scure = '/var/log/secure'
        file_ssd = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        find_logs(multihost, file_scure, "Password expired. Change your password now.")
        find_logs(multihost, file_ssd, "Server returned control [1.3.6.1.4.1.42.2.27.8.5.1]")
        find_logs(multihost, file_ssd, "Password expired user must set a new password")
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, cn_config, 'passwordExp', [b'off'])
        time.sleep(3)
        assert tools.auth_client_ssh_password('ppuser1', 'Secret123')
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, user_dn, 'userPassword', [b'Secret123'])

    @staticmethod
    def test_bz954323(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: Display last grace login bz954323
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=954323
        :id: f6e2511a-9676-11ed-a446-845cf3eff344
        :setup:
            1. Enable password policy in Directory Server.
            2. Set the number of grace login in password policy to 3
            3. Expire a user password ( by setting password Expiration Time)
            4. Clear the secure log
        :steps:
            1. Calling tools.auth_client_ssh_password to authenticate
                the user 'ppuser1' with a password on the client.
            2. Calling find_logs to search for a specific message in a log file on the server.
            3. Repeating steps 1-2 two more times, with different log search messages each time.
            4. Calling ldap_modify_ds two more times with different arguments to
                delete the configuration settings modified earlier.
        :expectedresults:
            1. Authentication should succeed
            2. Corresponding logs should be generated
            3. Corresponding logs should be generated
            4. Configuration settings should changed to modified earlier
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        cn_config = 'cn=config'
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, cn_config, 'passwordExp', [b'on'])
        ldap_modify_ds(multihost, ldap.MOD_ADD, cn_config, 'passwordGraceLimit', [b'3'])
        client.run_command("> /var/log/secure")
        time.sleep(3)
        assert tools.auth_client_ssh_password('ppuser1', 'Secret123')
        time.sleep(3)
        find_logs(multihost, "/var/log/secure", "You have 2 grace login(s) remaining")
        client.run_command("> /var/log/secure")
        assert tools.auth_client_ssh_password('ppuser1', 'Secret123')
        time.sleep(3)
        find_logs(multihost, "/var/log/secure", "You have 1 grace login(s) remaining")
        client.run_command("> /var/log/secure")
        assert tools.auth_client_ssh_password('ppuser1', 'Secret123')
        time.sleep(3)
        find_logs(multihost, "/var/log/secure", "You have 0 grace login(s) remaining")
        for element, value in [('passwordGraceLimit', []),
                               ('passwordMaxAge', [])]:
            ldap_modify_ds(multihost, ldap.MOD_DELETE, cn_config, element, value)

    @staticmethod
    def test_bz1146198_bz1144011(multihost, backupsssdconf, common_sssd_setup):
        """
        :title: Password expiration policies are not being enforced by SSSD bz1146198 bz1144011
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1146198
                   https://bugzilla.redhat.com/show_bug.cgi?id=1144011
        :id: f6e2511a-9676-11ed-a446-845cf3eff344
        :setup:
            1. Add passwordMustChange to config.
            2. Set the password for the user to 'Secret123'
            3. Clear secure logs
        :steps:
            1. Run a script to simulate an expired password.
            2. Calling find_logs to search for specific messages in log files on the server.
            3. Calling tools.auth_client_ssh_password to authenticate the user with a new password.
            4. Calling ldap_modify_ds three times to delete some configuration settings related to
                password expiration for the directory
        :expectedresults:
            1. User should be forced to change the password.
            2. Corresponding logs should be generated
            3. User authentication should success
            4. New setting related to password change should success
        """
        client = multihost.client[0]
        tools = sssdTools(multihost.client[0])
        cn_config = 'cn=config'
        ldap_modify_ds(multihost, ldap.MOD_ADD, cn_config, 'passwordMustChange', [b'on'])
        user_dn = 'uid=ppuser1,ou=People,dc=example,dc=test'
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, user_dn, 'userPassword', [b'Secret123'])
        client.run_command("> /var/log/secure")
        client.run_command(f"> '/var/log/sssd/sssd_{ds_instance_name}.log'")
        client.run_command("sh /tmp/change_user_password_while_expired.sh")
        time.sleep(3)
        find_logs(multihost, "/var/log/secure", "Password expired. Change your password now")
        find_logs(multihost, f'/var/log/sssd/sssd_{ds_instance_name}.log',
                  "Password was reset. User must set a new password")
        time.sleep(3)
        assert tools.auth_client_ssh_password('ppuser1', 'NewPass_123')
        for element, value in [('passwordMustChange', []),
                               ('passwordWarning', []),
                               ('passwordExp', [b'on'])]:
            ldap_modify_ds(multihost, ldap.MOD_DELETE, cn_config, element, value)
        ldap_modify_ds(multihost, ldap.MOD_REPLACE, user_dn, 'userPassword', [b'Secret123'])
