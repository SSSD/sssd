"""Automation for Krb access provider tests ported from bash

:requirement: krb_access_provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest
import time
from constants import ds_instance_name
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.ssh2_python import check_login_client, \
    check_login_client_bool, run_command_client, SSHClient


@pytest.fixture(scope='class')
def custom_setup(session_multihost, setup_sssd_krb, create_posix_usersgroups, krb_connection_timeout):
    """ Added neccessary sssd domain parameters """
    tools = sssdTools(session_multihost.client[0])
    sssd_params = {'sbus_timeout': 30,
                   'services': "nss, pam"}
    tools.sssd_conf('sssd', sssd_params)
    domain_section = f'domain/{ds_instance_name}'
    domain_params = {'access_provider': 'krb5',
                     'use_fully_qualified_names': 'False',
                     'override_homedir': '/home/%u'}
    tools.sssd_conf(domain_section, domain_params)
    tools.clear_sssd_cache()

    cmds = ["mkdir -p /home/foo3",
            "chown foo3: /home/foo3",
            "chmod 700 /home/foo3",
            "truncate -s 0 /home/foo3/.k5login",
            "chown foo3: /home/foo3/.k5login",
            "restorecon -v /home/foo3/.k5login"]
    for command in cmds:
        cmd = session_multihost.client[0].run_command(command, raiseonerr=False)
        assert cmd.returncode == 0, f'{command} did not execute successfully'


@pytest.mark.tier2
@pytest.mark.krbaccessprovider
@pytest.mark.usefixtures('custom_setup')
class TestKrbAccessProvider():
    """
    This is test case class for krb_access_provider suite

    Test access provision by kerberos on the basis of .k5login file.
    Test for empty k5login file and test for presence of single or
    multiple kerberos principal in the file, test for deleted user with
    principals present in the file.
    """
    @staticmethod
    def test_0001_k5login_empty(multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_access_provider: k5login is an empty file
        :id: e84bd024-669f-40d0-8833-edbc1be48e8e
        :setup:
          1. Clear the secure log, clear cache and restart sssd.
        :steps:
          1. Authenticate the user foo3 and foo4 from the client
          2. Check the secure log for expected messages.
          3. Check the sssd domain log for expected messages.
        :expectedresults:
          1. User foo3 should be able to successfully login
             User foo4 should not able to login
          2. Secure Log contains the expected lines:
             pam_sss(sshd:auth): authentication success for foo3
             pam_sss(sshd:account): Access denied for user foo3
             pam_sss(sshd:auth): authentication success for foo4
             Accepted password for foo4
          3. SSSD Domain Log contains the expected lines:
             Access denied for user [foo3
             Access allowed for user [foo4
        :teardown:
          1. Clear the .k5login file.
        """
        multihost.client[0].run_command("truncate -s 0 /var/log/secure", raiseonerr=False)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        with pytest.raises(Exception):
            check_login_client(multihost, "foo3", "Secret123")
        ssh = check_login_client_bool(multihost, "foo4", "Secret123")
        time.sleep(3)
        secure_log_str = multihost.client[0].get_file_contents("/var/log/secure").decode('utf-8')
        file = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        sssd_log_str = multihost.client[0].get_file_contents(file).decode('utf-8')

        multihost.client[0].run_command("truncate -s 0 /home/foo3/.k5login", raiseonerr=False)
        assert ssh, 'foo4 is not able to login.'
        assert "pam_sss(sshd:auth): authentication success" in secure_log_str, \
               "authentication success not found in /var/log/secure"
        assert "pam_sss(sshd:account): Access denied for user foo3" in secure_log_str, \
               "Access denied not found in /var/log/secure"

        assert "pam_sss(sshd:auth): authentication success" in secure_log_str, \
               "authentication success not found in /var/log/secure"
        assert "Accepted password for foo4" in secure_log_str, "Accepted password not found in /var/log/secure"

        assert f"Access denied for user [foo3@{ds_instance_name}]" in sssd_log_str, \
               "Access denied not found in /var/log/sssd/sssd_example1.log"
        assert f"Access allowed for user [foo4@{ds_instance_name}]" in sssd_log_str, \
               "Access allowed not found in /var/log/sssd/sssd_example1.log"

    @staticmethod
    def test_0002_k5login_user3(multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_access_provider: k5login has testuser3
        :id: decede10-c500-4b56-8037-7f2e325009b6
        :setup:
          1. Clear the secure log, clear cache and restart sssd.
          2. Add the foo3 user principal in the k5login file
        :steps:
          1. Authenticate the user foo3 from the client
          2. Check the secure log for expected messages.
          3. Check the sssd domain log for expected messages.
        :expectedresults:
          1. User foo3 should be able to successfully login
          2. Secure Log contains the expected lines:
             pam_sss(sshd:auth): authentication success for foo3
             Accepted password for foo3
          3. SSSD Domain Log contains the expected lines:
             Access allowed for user [foo3
        :teardown:
          1. Clear the .k5login file.
        """
        multihost.client[0].run_command("truncate -s 0 /var/log/secure", raiseonerr=False)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        cmds = ['echo "foo3@EXAMPLE.TEST" > /home/foo3/.k5login',
                "restorecon -v /home/foo3/.k5login"]
        for command in cmds:
            cmd = multihost.client[0].run_command(command, raiseonerr=False)

        ssh = check_login_client_bool(multihost, "foo3", "Secret123")
        time.sleep(3)
        secure_log_str = multihost.client[0].get_file_contents("/var/log/secure").decode('utf-8')

        file = f'/var/log/sssd/sssd_{ds_instance_name}.log'
        sssd_log_str = multihost.client[0].get_file_contents(file).decode('utf-8')

        multihost.client[0].run_command("truncate -s 0 /home/foo3/.k5login", raiseonerr=False)
        assert ssh, 'foo3 is not able to login.'
        assert cmd.returncode == 0, f"{command} did not execute successfully"
        assert "pam_sss(sshd:auth): authentication success" in secure_log_str, \
               "authentication success not found in /var/log/secure"
        assert "Accepted password for foo3" in secure_log_str, \
               "Accepted password not found in /var/log/secure"
        assert f"Access allowed for user [foo3@{ds_instance_name}]" in sssd_log_str, \
               "Access allowed not found in /var/log/sssd/sssd_example1.log"

    @staticmethod
    def test_0003_k5login_user3_with_user4(multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_access_provider: k5login has testuser3 and testuser4
        :id: 3ddb4948-6b5a-4e82-85f7-c896bce14dda
        :setup:
          1. Clear the secure log, clear cache and restart sssd.
          2. Add both the user principal in the k5login file
        :steps:
          1. Authenticate the user foo3 from the client
          2. Check the /tmp/accessprovider.out file for expected messages.
        :expectedresults:
          1. User foo3 should be able to successfully login
          2. /tmp/accessprovider.out file contains the expected output:
             'foo3' username should be present in the file.
        :teardown:
          1. Clear the .k5login file.
          2. Remove the /tmp/accessProvider.out file
        """
        multihost.client[0].run_command("truncate -s 0 /var/log/secure", raiseonerr=False)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        echo_cmds = ['echo "foo3@EXAMPLE.TEST" > /home/foo3/.k5login',
                     'echo "foo4@EXAMPLE.TEST" >> /home/foo3/.k5login',
                     'restorecon -v /home/foo3/.k5login']

        for command in echo_cmds:
            cmd = multihost.client[0].run_command(command, raiseonerr=False)

        ssh = check_login_client_bool(multihost, "foo3", "Secret123")
        client_hostname = multihost.client[0].sys_hostname
        try:
            run_command_client(multihost, "foo4", "Secret123",
                               f"ssh -o StrictHostKeyChecking=no -o "
                               f"PasswordAuthentication=no foo3@{client_hostname} "
                               f"id > /tmp/accessProvider_id_krb5_003.out 2>&1")
        except Exception:
            pytest.fail("Error in connection via ssh as foo4")
        finally:
            multihost.client[0].run_command("truncate -s 0 /home/foo3/.k5login", raiseonerr=False)
        logfile = multihost.client[0].get_file_contents("/tmp/accessProvider_id_krb5_003.out").decode('utf-8')
        multihost.client[0].run_command("rm -rf /tmp/accessProvider_id_krb5_003.out", raiseonerr=False)
        assert ssh, 'foo3 is not able to login.'
        assert cmd.returncode == 0, f"{command} did not execute successfully"
        assert "foo3" in logfile, "foo3 not found in /tmp/accessProvider_id_krb5_003.out"

    @staticmethod
    def test_0004_k5login_user4_with_deleted_user3(multihost):
        """
        :title: IDM-SSSD-TC: krb_provider: krb_access_provider: k5login has testuser3 and testuser4\
           and testuser3 is deleted
        :id: ff46741d-cab8-4217-840a-fcd72857b0a6
        :setup:
          1. Clear the secure log, clear cache and restart sssd.
          2. Add both the user principal in the k5login file
        :steps:
          1. Authenticate the user foo3 from the client
          2. Delete the ldapuser foo3
          3. Check the /tmp/accessprovider.out file for expected messages.
        :expectedresults:
          1. User foo3 should be able to successfully login
          2. ldapuser foo3 should be successfully deleted
          3. /tmp/accessprovider.out file contains the expected output:
             'foo4' username should be present in the file.
             'foo3' username should not be present in the file.
        :teardown:
          1. Clear the .k5login file.
          2. Remove the /tmp/accessProvider.out file
        """
        multihost.client[0].run_command("truncate -s 0 /var/log/secure", raiseonerr=False)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()

        echo_cmds = ['echo "foo3@EXAMPLE.TEST" > /home/foo3/.k5login',
                     'echo "foo4@EXAMPLE.TEST" >> /home/foo3/.k5login',
                     'restorecon -v /home/foo3/.k5login']
        for command in echo_cmds:
            cmd1 = multihost.client[0].run_command(command, raiseonerr=False)

        ssh1 = check_login_client_bool(multihost, "foo3", "Secret123")

        ldap_cmd = f'ldapdelete -x -H ldap://{multihost.master[0].sys_hostname} \
                   -D "cn=Directory Manager" -w "Secret123" uid=foo3,ou=People,dc=example,dc=test'
        cmd2 = multihost.client[0].run_command(ldap_cmd, raiseonerr=False)
        time.sleep(10)
        client_hostname = multihost.client[0].sys_hostname
        try:
            ssh = SSHClient(client_hostname, "foo4", "Secret123")
            ssh.connect()
            ssh.execute_command("id > /tmp/accessProvider_id_krb5_004.out 2>&1")
            ssh.execute_command(f"ssh -o StrictHostKeyChecking=no -o "
                                f"PasswordAuthentication=no foo3@{client_hostname} id >> "
                                f"/tmp/accessProvider_id_krb5_004.out 2>&1")
            ssh.close()
        except Exception:
            pytest.fail("Error in connection via ssh as foo4")
        finally:
            multihost.client[0].run_command("truncate -s 0 /home/foo3/.k5login", raiseonerr=False)
        logfile = multihost.client[0].get_file_contents("/tmp/accessProvider_id_krb5_004.out").decode('utf-8')
        multihost.client[0].run_command("rm -rf /tmp/accessProvider_id_krb5_004.out", raiseonerr=False)
        assert ssh1, 'foo1 is not able to login.'
        assert cmd1.returncode == 0, f'{command} did not execute successfully'
        assert cmd2.returncode == 0, f'{ldap_cmd} did not execute successfully'
        assert "foo3" not in logfile, "foo3 found in /tmp/accessProvider_id_krb5_004.out"
        assert "foo4" in logfile, "foo4 not found in /tmp/accessProvider_id_krb5_004.out"
